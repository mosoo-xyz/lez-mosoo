use alloy_primitives::{keccak256, U256};
use mosoo_core::predicate::derive_eth_deposit_subject_key;
use mosoo_core::types::{
    StatementBinding, VerifiedStatement, ETH_MAINNET_CHAIN_ID, MOSOO_PROGRAM_ID,
    PROOF_TYPE_ETH_DEPOSIT,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum EtherReceiverError {
    #[error("predicate did not hold - Ethereum account balance verification failed")]
    PredicateFailed,

    #[error("unauthenticated attester: statement was not signed by authentic Mosoo program ID")]
    UnauthenticatedAttester,

    #[error("statement has already been claimed (replay attempt)")]
    AlreadyClaimed,

    #[error("statement is for chain {0}, but this receiver only accepts Ethereum Mainnet (1)")]
    WrongChain(u64),

    #[error("verified balance {actual} wei is less than required {required} wei")]
    BalanceTooLow { actual: u64, required: u64 },

    #[error("invalid statement type: expected native ETH deposit proof (tag 3), got tag {0}")]
    InvalidStatementType(u8),

    #[error("deposit contract mismatch: expected {expected:?}, got {actual:?}")]
    ContractMismatch {
        expected: [u8; 20],
        actual: [u8; 20],
    },

    #[error("sender mismatch: expected {expected:?}, got {actual:?}")]
    SenderMismatch {
        expected: [u8; 20],
        actual: [u8; 20],
    },

    #[error("recipient mismatch: expected {expected:?}, got {actual:?}")]
    RecipientMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },

    #[error("subject key cryptographic tampering detected: statement subject_key does not match canonical parameters")]
    SubjectKeyMismatch,

    #[error("state attestation failed: {0}")]
    AttestationFailed(String),

    #[error("insufficient mETH balance: available {available} wei, requested {requested} wei")]
    InsufficientBalance { available: u128, requested: u128 },

    #[error("account not found: {0:?}")]
    AccountNotFound([u8; 32]),

    #[error("arithmetic overflow in token operation")]
    Overflow,
}

/// In-memory nullifier store mapping verified statement IDs to spent state.
#[derive(Default)]
pub struct EtherNullifierSet {
    used: HashMap<[u8; 32], bool>,
}

impl EtherNullifierSet {
    pub fn new() -> Self {
        Self {
            used: HashMap::new(),
        }
    }

    pub fn is_used(&self, id: &[u8; 32]) -> bool {
        self.used.contains_key(id)
    }

    pub fn mark_used(&mut self, id: [u8; 32]) {
        self.used.insert(id, true);
    }
}

/// Process a verified native Ethereum balance statement and credit LEZ-side ether.
///
/// Ensures:
/// 1. Attester origin authentication (`statement.attester_program_id == MOSOO_PROGRAM_ID`).
/// 2. Settlement binding: credited wei derives strictly from `statement.value_as_u64()`.
/// 3. Replay protection: atomic marking in `EtherNullifierSet`.
///
/// # Examples
///
/// ```
/// use ether_receiver::{claim_ether, EtherNullifierSet};
/// use mosoo_core::types::{VerifiedStatement, ETH_MAINNET_CHAIN_ID, MOSOO_PROGRAM_ID};
///
/// let mut nullifiers = EtherNullifierSet::new();
/// let mut verified_value = [0u8; 32];
/// verified_value[24..32].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());
///
/// let statement = VerifiedStatement {
///     chain_id: ETH_MAINNET_CHAIN_ID,
///     attester_program_id: MOSOO_PROGRAM_ID,
///     statement_id: [0x55; 32],
///     predicate_holds: true,
///     verified_value,
///     subject_key: [0u8; 32],
///     proof_type_tag: 0,
///     binding: Default::default(),
/// };
///
/// let wei = claim_ether(&statement, &mut nullifiers, 1_000_000_000_000_000_000)
///     .expect("valid ether claim succeeds");
/// assert_eq!(wei, 1_000_000_000_000_000_000);
/// ```
pub fn claim_ether(
    statement: &VerifiedStatement,
    nullifiers: &mut EtherNullifierSet,
    min_wei: u64,
) -> Result<u64, EtherReceiverError> {
    if statement.chain_id != ETH_MAINNET_CHAIN_ID {
        return Err(EtherReceiverError::WrongChain(statement.chain_id));
    }

    // Authenticate the attester program identity
    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(EtherReceiverError::UnauthenticatedAttester);
    }

    if !statement.predicate_holds {
        return Err(EtherReceiverError::PredicateFailed);
    }

    // Derive credited amount strictly from verified statement value (with overflow check)
    let verified_wei = statement
        .value_as_u64_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_wei < min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei,
            required: min_wei,
        });
    }

    if nullifiers.is_used(&statement.statement_id)
        || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
    {
        return Err(EtherReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    if statement.subject_key != [0u8; 32] {
        nullifiers.mark_used(statement.subject_key);
    }

    Ok(verified_wei)
}

/// Detailed parameters for claiming a verified Native ETH transfer or deposit to a specific contract.
///
/// In accordance with Logos RFP-021 reference consumer specifications, this proves that
/// a specific `sender` transferred a specific `amount` of native ETH to a designated
/// Ethereum deposit contract for the benefit of a `recipient` on LEZ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NativeEthDepositClaim {
    /// The verified statement emitted by the Mosoo attestation module.
    pub statement: VerifiedStatement,
    /// The expected Ethereum deposit/vault contract address.
    pub expected_deposit_contract: [u8; 20],
    /// The Ethereum sender / depositor address.
    pub sender: [u8; 20],
    /// The designated LEZ recipient address.
    pub recipient: [u8; 32],
    /// Minimum wei acceptable to the claimant.
    pub min_wei: u64,
}

/// Process a verified native ETH deposit or transfer event to a specific contract,
/// proving sender, recipient, and amount in accordance with RFP-021 reference consumer semantics.
pub fn claim_native_eth_deposit(
    claim: &NativeEthDepositClaim,
    nullifiers: &mut EtherNullifierSet,
) -> Result<u64, EtherReceiverError> {
    if claim.statement.chain_id != ETH_MAINNET_CHAIN_ID {
        return Err(EtherReceiverError::WrongChain(claim.statement.chain_id));
    }

    // Authenticate the attester program identity
    if claim.statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(EtherReceiverError::UnauthenticatedAttester);
    }

    if !claim.statement.predicate_holds {
        return Err(EtherReceiverError::PredicateFailed);
    }

    // Verify statement proof type is NativeEthDeposit
    if claim.statement.proof_type_tag != PROOF_TYPE_ETH_DEPOSIT {
        return Err(EtherReceiverError::InvalidStatementType(
            claim.statement.proof_type_tag,
        ));
    }

    // Match statement binding against caller's expected parameters
    let (block_hash, slot, tx_index, log_index) = match &claim.statement.binding {
        StatementBinding::NativeEthDeposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        } => {
            if *deposit_contract != claim.expected_deposit_contract {
                return Err(EtherReceiverError::ContractMismatch {
                    expected: claim.expected_deposit_contract,
                    actual: *deposit_contract,
                });
            }
            if *sender != claim.sender {
                return Err(EtherReceiverError::SenderMismatch {
                    expected: claim.sender,
                    actual: *sender,
                });
            }
            if *recipient != claim.recipient {
                return Err(EtherReceiverError::RecipientMismatch {
                    expected: claim.recipient,
                    actual: *recipient,
                });
            }
            (*execution_block_hash, *slot, *tx_index, *log_index)
        }
        _ => {
            return Err(EtherReceiverError::InvalidStatementType(
                claim.statement.proof_type_tag,
            ));
        }
    };

    // Verify canonical subject key cryptographic derivation
    let expected_subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &claim.expected_deposit_contract,
        &claim.sender,
        &claim.recipient,
    );
    if claim.statement.subject_key != expected_subject_key {
        return Err(EtherReceiverError::SubjectKeyMismatch);
    }

    // Derive credited amount strictly from verified statement value (with overflow check)
    let verified_wei = claim
        .statement
        .value_as_u64_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_wei < claim.min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei,
            required: claim.min_wei,
        });
    }

    if nullifiers.is_used(&expected_subject_key)
        || nullifiers.is_used(&claim.statement.statement_id)
    {
        return Err(EtherReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(expected_subject_key);
    nullifiers.mark_used(claim.statement.statement_id);

    // Verified wei credited to recipient on LEZ
    Ok(verified_wei)
}

/// Execution parameters for atomic same-transaction Native Ether claim.
///
/// In compliance with Logos RFP-021 Functionality requirements, state inclusion verification
/// and predicate evaluation execute within the consuming transaction itself against the
/// authenticated light client instance and header record. This ensures caller-supplied
/// statements cannot be fabricated or accepted out-of-band.
#[derive(Debug, Clone)]
pub struct AtomicEtherClaimArgs {
    /// Active authenticated light client instance account
    pub instance: mosoo_core::types::InstanceAccount,
    /// Authenticated header record for the target block
    pub header: mosoo_core::types::HeaderRecord,
    /// Optional historical branch if proving against past block in weak-subjectivity window
    pub header_history_branch: Option<Vec<[u8; 32]>>,
    /// State inclusion proof (MPT proof for account balance or deposit contract)
    pub proof: mosoo_core::inclusion::StateProof,
    /// Predicate evaluated against verified state
    pub predicate: mosoo_core::types::Predicate,
    /// Expected Ethereum account or deposit contract address
    pub expected_address: [u8; 20],
    /// Expected recipient identifier on LEZ
    pub recipient: [u8; 32],
    /// Minimum required wei
    pub min_wei: u64,
}

/// Execute atomic same-transaction Native Ether claim.
///
/// Directly invokes `mosoo_core::verifier::handle_attest_state` in-guest, verifies the MPT inclusion
/// proof against the authenticated `HeaderRecord`, evaluates the predicate, asserts account identity,
/// derives the deterministic statement nullifier, checks for replay, and credits wei.
pub fn claim_ether_atomic(
    args: AtomicEtherClaimArgs,
    nullifiers: &mut EtherNullifierSet,
) -> Result<u64, EtherReceiverError> {
    if args.instance.chain_id != ETH_MAINNET_CHAIN_ID {
        return Err(EtherReceiverError::WrongChain(args.instance.chain_id));
    }

    let attest_args = mosoo_core::verifier::AttestStateArgs {
        instance: args.instance,
        header: args.header,
        header_history_branch: args.header_history_branch,
        proof: args.proof,
        predicate: args.predicate,
    };

    let output = mosoo_core::verifier::handle_attest_state(attest_args)
        .map_err(|e| EtherReceiverError::AttestationFailed(e.to_string()))?;

    let statement = match output {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => {
            return Err(EtherReceiverError::AttestationFailed(
                "unexpected instruction output from handle_attest_state".into(),
            ))
        }
    };

    if !statement.predicate_holds {
        return Err(EtherReceiverError::PredicateFailed);
    }

    match &statement.binding {
        StatementBinding::Account { address } => {
            if *address != args.expected_address {
                return Err(EtherReceiverError::ContractMismatch {
                    expected: args.expected_address,
                    actual: *address,
                });
            }
        }
        StatementBinding::NativeEthDeposit {
            deposit_contract, ..
        } => {
            if *deposit_contract != args.expected_address {
                return Err(EtherReceiverError::ContractMismatch {
                    expected: args.expected_address,
                    actual: *deposit_contract,
                });
            }
        }
        _ => {
            return Err(EtherReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ));
        }
    }

    let verified_wei = statement
        .value_as_u64_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_wei < args.min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei,
            required: args.min_wei,
        });
    }

    if nullifiers.is_used(&statement.statement_id)
        || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
    {
        return Err(EtherReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    if statement.subject_key != [0u8; 32] {
        nullifiers.mark_used(statement.subject_key);
    }

    Ok(verified_wei)
}

/// Derives the canonical 32-byte burn identifier matching `MosooLocker.sol`:
/// `keccak256(abi.encodePacked("mosoo_burn_v1", block.chainid, lezOwner, recipient, amount, burnNonce, lezSlot))`
pub fn derive_burn_id(
    chain_id: u64,
    lez_owner: &[u8; 32],
    eth_recipient: &[u8; 20],
    amount_wei: u128,
    burn_nonce: u64,
    lez_slot: u64,
) -> [u8; 32] {
    let mut packed = Vec::with_capacity(145);
    packed.extend_from_slice(b"mosoo_burn_v1");
    packed.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    packed.extend_from_slice(lez_owner);
    packed.extend_from_slice(eth_recipient);
    packed.extend_from_slice(&U256::from(amount_wei).to_be_bytes::<32>());
    packed.extend_from_slice(&burn_nonce.to_be_bytes());
    packed.extend_from_slice(&lez_slot.to_be_bytes());
    keccak256(&packed).0
}

/// An on-chain account holding synthetic `mETH` on Logos Execution Zone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MethAccount {
    /// Owner address on LEZ (32-byte account ID / PDA)
    pub owner: [u8; 32],
    /// Active mETH token balance in wei
    pub balance_wei: u128,
    /// Number of successful deposits / mints credited
    pub deposit_count: u64,
    /// Number of burns executed
    pub burn_count: u64,
}

/// An immutable, cryptographically verifiable Burn Receipt generated on LEZ.
/// This receipt is presented to the Ethereum `MosooLocker.sol` contract to release real locked ETH.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnReceipt {
    /// Canonical burn identifier: keccak256("mosoo_burn_v1" || chain_id || lez_owner || eth_recipient || amount_wei || burn_nonce || slot)
    pub burn_id: [u8; 32],
    /// Target Ethereum chain ID (e.g., 1 for Mainnet, 11155111 for Sepolia)
    pub chain_id: u64,
    /// LEZ account that initiated the burn
    pub lez_owner: [u8; 32],
    /// Destination Ethereum recipient address
    pub eth_recipient: [u8; 20],
    /// Amount of mETH burned (in wei)
    pub amount_wei: u128,
    /// Sequential burn nonce of this user
    pub burn_nonce: u64,
    /// LEZ block / slot height at which the burn was finalized
    pub lez_slot: u64,
}

/// The state ledger for `mETH` synthetic ether on LEZ, tracking user balances,
/// total supply, and emitted burn receipts.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MethLedger {
    accounts: HashMap<[u8; 32], MethAccount>,
    pub total_supply_wei: u128,
    pub total_burned_wei: u128,
    burn_receipts: HashMap<[u8; 32], BurnReceipt>,
}

impl MethLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_balance(&self, owner: &[u8; 32]) -> u128 {
        self.accounts.get(owner).map_or(0, |a| a.balance_wei)
    }

    pub fn get_account(&self, owner: &[u8; 32]) -> Option<&MethAccount> {
        self.accounts.get(owner)
    }

    /// Mint synthetic `mETH` upon verification of a native ETH deposit to `MosooLocker.sol`.
    pub fn mint_meth(
        &mut self,
        claim: &NativeEthDepositClaim,
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<u128, EtherReceiverError> {
        let verified_wei = claim_native_eth_deposit(claim, nullifiers)?;
        let amount = verified_wei as u128;

        let entry = self
            .accounts
            .entry(claim.recipient)
            .or_insert_with(|| MethAccount {
                owner: claim.recipient,
                balance_wei: 0,
                deposit_count: 0,
                burn_count: 0,
            });

        entry.balance_wei = entry
            .balance_wei
            .checked_add(amount)
            .ok_or(EtherReceiverError::Overflow)?;
        entry.deposit_count += 1;

        self.total_supply_wei = self
            .total_supply_wei
            .checked_add(amount)
            .ok_or(EtherReceiverError::Overflow)?;

        Ok(entry.balance_wei)
    }

    /// Mint synthetic `mETH` via atomic same-transaction verification.
    pub fn mint_meth_atomic(
        &mut self,
        args: AtomicEtherClaimArgs,
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<u128, EtherReceiverError> {
        let recipient = args.recipient;
        let verified_wei = claim_ether_atomic(args, nullifiers)?;
        let amount = verified_wei as u128;

        let entry = self
            .accounts
            .entry(recipient)
            .or_insert_with(|| MethAccount {
                owner: recipient,
                balance_wei: 0,
                deposit_count: 0,
                burn_count: 0,
            });

        entry.balance_wei = entry
            .balance_wei
            .checked_add(amount)
            .ok_or(EtherReceiverError::Overflow)?;
        entry.deposit_count += 1;

        self.total_supply_wei = self
            .total_supply_wei
            .checked_add(amount)
            .ok_or(EtherReceiverError::Overflow)?;

        Ok(entry.balance_wei)
    }

    /// Transfer synthetic `mETH` between LEZ accounts.
    pub fn transfer_meth(
        &mut self,
        from: &[u8; 32],
        to: &[u8; 32],
        amount_wei: u128,
    ) -> Result<(), EtherReceiverError> {
        if amount_wei == 0 {
            return Ok(());
        }
        if from == to {
            let from_account = self
                .accounts
                .get(from)
                .ok_or(EtherReceiverError::AccountNotFound(*from))?;
            if from_account.balance_wei < amount_wei {
                return Err(EtherReceiverError::InsufficientBalance {
                    available: from_account.balance_wei,
                    requested: amount_wei,
                });
            }
            return Ok(());
        }
        let from_account = self
            .accounts
            .get_mut(from)
            .ok_or(EtherReceiverError::AccountNotFound(*from))?;

        if from_account.balance_wei < amount_wei {
            return Err(EtherReceiverError::InsufficientBalance {
                available: from_account.balance_wei,
                requested: amount_wei,
            });
        }
        from_account.balance_wei -= amount_wei;

        let to_account = self.accounts.entry(*to).or_insert_with(|| MethAccount {
            owner: *to,
            balance_wei: 0,
            deposit_count: 0,
            burn_count: 0,
        });
        to_account.balance_wei = to_account
            .balance_wei
            .checked_add(amount_wei)
            .ok_or(EtherReceiverError::Overflow)?;

        Ok(())
    }

    /// Burn synthetic `mETH` on LEZ to unlock real ETH on Ethereum.
    /// Emits a canonical `BurnReceipt` cryptographically bound to the Ethereum recipient.
    pub fn burn_meth(
        &mut self,
        chain_id: u64,
        owner: &[u8; 32],
        amount_wei: u128,
        eth_recipient: &[u8; 20],
        lez_slot: u64,
    ) -> Result<BurnReceipt, EtherReceiverError> {
        if amount_wei == 0 {
            return Err(EtherReceiverError::BalanceTooLow {
                actual: 0,
                required: 1,
            });
        }
        let user = self
            .accounts
            .get_mut(owner)
            .ok_or(EtherReceiverError::AccountNotFound(*owner))?;

        if user.balance_wei < amount_wei {
            return Err(EtherReceiverError::InsufficientBalance {
                available: user.balance_wei,
                requested: amount_wei,
            });
        }

        user.balance_wei -= amount_wei;
        user.burn_count += 1;
        let burn_nonce = user.burn_count;

        self.total_supply_wei -= amount_wei;
        self.total_burned_wei = self
            .total_burned_wei
            .checked_add(amount_wei)
            .ok_or(EtherReceiverError::Overflow)?;

        let burn_id = derive_burn_id(
            chain_id,
            owner,
            eth_recipient,
            amount_wei,
            burn_nonce,
            lez_slot,
        );

        let receipt = BurnReceipt {
            burn_id,
            chain_id,
            lez_owner: *owner,
            eth_recipient: *eth_recipient,
            amount_wei,
            burn_nonce,
            lez_slot,
        };

        self.burn_receipts.insert(burn_id, receipt.clone());
        Ok(receipt)
    }

    /// Retrieve an emitted burn receipt by its canonical 32-byte burn ID.
    pub fn get_burn_receipt(&self, burn_id: &[u8; 32]) -> Option<&BurnReceipt> {
        self.burn_receipts.get(burn_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn min_32(v: u64) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[24..32].copy_from_slice(&v.to_be_bytes());
        out
    }

    fn make_statement(
        chain_id: u64,
        holds: bool,
        id_seed: u8,
        wei: u64,
        attester: [u8; 32],
    ) -> VerifiedStatement {
        let mut verified_value = [0u8; 32];
        verified_value[24..32].copy_from_slice(&wei.to_be_bytes());
        VerifiedStatement {
            chain_id,
            attester_program_id: attester,
            statement_id: [id_seed; 32],
            predicate_holds: holds,
            verified_value,
            subject_key: [0u8; 32],
            proof_type_tag: 0,
            binding: StatementBinding::Account { address: [0u8; 20] },
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn make_deposit_statement(
        chain_id: u64,
        holds: bool,
        id_seed: u8,
        wei: u64,
        attester: [u8; 32],
        deposit_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    ) -> VerifiedStatement {
        let mut verified_value = [0u8; 32];
        verified_value[24..32].copy_from_slice(&wei.to_be_bytes());
        let block_hash = [0x22; 32];
        let slot = 200u64;
        let tx_index = 1u64;
        let log_index = 0usize;
        let subject_key = derive_eth_deposit_subject_key(
            &block_hash,
            slot,
            tx_index,
            log_index,
            &deposit_contract,
            &sender,
            &recipient,
        );
        VerifiedStatement {
            chain_id,
            attester_program_id: attester,
            statement_id: [id_seed; 32],
            predicate_holds: holds,
            verified_value,
            subject_key,
            proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
            binding: StatementBinding::NativeEthDeposit {
                execution_block_hash: block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            },
        }
    }

    #[test]
    fn valid_ether_claim_succeeds() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x10,
            1_000_000_000_000_000_000,
            MOSOO_PROGRAM_ID,
        );
        let result = claim_ether(&statement, &mut nullifiers, 1_000_000_000_000_000_000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1_000_000_000_000_000_000);
    }

    #[test]
    fn duplicate_ether_claim_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x20, 100, MOSOO_PROGRAM_ID);
        claim_ether(&statement, &mut nullifiers, 100).unwrap();
        let result = claim_ether(&statement, &mut nullifiers, 100);
        assert!(matches!(result, Err(EtherReceiverError::AlreadyClaimed)));
    }

    #[test]
    fn wrong_chain_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_statement(11_155_111, true, 0x30, 100, MOSOO_PROGRAM_ID);
        let result = claim_ether(&statement, &mut nullifiers, 100);
        assert!(matches!(result, Err(EtherReceiverError::WrongChain(_))));
    }

    #[test]
    fn failed_predicate_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, false, 0x40, 100, MOSOO_PROGRAM_ID);
        let result = claim_ether(&statement, &mut nullifiers, 100);
        assert!(matches!(result, Err(EtherReceiverError::PredicateFailed)));
    }

    #[test]
    fn unauthenticated_attester_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let bogus_attester = [0xef; 32];
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x45, 100, bogus_attester);
        let result = claim_ether(&statement, &mut nullifiers, 100);
        assert_eq!(result, Err(EtherReceiverError::UnauthenticatedAttester));
    }

    #[test]
    fn balance_too_low_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x46, 50, MOSOO_PROGRAM_ID);
        let result = claim_ether(&statement, &mut nullifiers, 100);
        assert_eq!(
            result,
            Err(EtherReceiverError::BalanceTooLow {
                actual: 50,
                required: 100
            })
        );
    }

    #[test]
    fn test_native_eth_deposit_with_sender_recipient_and_amount_succeeds() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x50,
            2_500_000_000_000_000_000,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1_000_000_000_000_000_000,
        };
        let credited = claim_native_eth_deposit(&deposit_claim, &mut nullifiers)
            .expect("Valid deposit claim should succeed");
        assert_eq!(credited, 2_500_000_000_000_000_000);
    }

    #[test]
    fn test_native_eth_deposit_wrong_contract_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x51,
            2_000_000,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0x99; 20], // wrong deposit contract
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1_000_000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(EtherReceiverError::ContractMismatch {
                expected: [0x99; 20],
                actual: [0xaa; 20],
            })
        );
    }

    #[test]
    fn test_native_eth_deposit_wrong_sender_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x52,
            2_000_000,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0x77; 20], // wrong sender
            recipient: [0xcc; 32],
            min_wei: 1_000_000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(EtherReceiverError::SenderMismatch {
                expected: [0x77; 20],
                actual: [0xbb; 20],
            })
        );
    }

    #[test]
    fn test_native_eth_deposit_wrong_recipient_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x53,
            2_000_000,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0x33; 32], // wrong recipient
            min_wei: 1_000_000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(EtherReceiverError::RecipientMismatch {
                expected: [0x33; 32],
                actual: [0xcc; 32],
            })
        );
    }

    #[test]
    fn test_native_eth_deposit_wrong_statement_type_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        // Raw account balance statement instead of NativeEthDeposit
        let statement = make_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x54,
            2_000_000,
            MOSOO_PROGRAM_ID,
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1_000_000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(result, Err(EtherReceiverError::InvalidStatementType(0)));
    }

    #[test]
    fn test_native_eth_deposit_subject_key_tamper_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let mut statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x55,
            2_000_000,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        // Tamper with subject_key
        statement.subject_key[0] ^= 0xff;
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1_000_000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(result, Err(EtherReceiverError::SubjectKeyMismatch));
    }

    #[test]
    fn test_native_eth_deposit_duplicate_replay_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x56,
            1_000_000_000_000_000_000,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1_000_000_000_000_000_000,
        };
        claim_native_eth_deposit(&deposit_claim, &mut nullifiers).unwrap();
        let replay_result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(replay_result, Err(EtherReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_native_eth_deposit_insufficient_wei_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x57,
            500,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(EtherReceiverError::BalanceTooLow {
                actual: 500,
                required: 1000
            })
        );
    }

    #[test]
    fn test_native_eth_deposit_unauthenticated_attester_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let bogus_attester = [0x99; 32];
        let statement = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x58,
            1000,
            bogus_attester,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(result, Err(EtherReceiverError::UnauthenticatedAttester));
    }

    #[test]
    fn test_native_eth_deposit_wrong_chain_rejected() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            11_155_111, // Sepolia instead of Mainnet
            true,
            0x59,
            1000,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            [0xbb; 20],
            [0xcc; 32],
        );
        let deposit_claim = NativeEthDepositClaim {
            statement,
            expected_deposit_contract: [0xaa; 20],
            sender: [0xbb; 20],
            recipient: [0xcc; 32],
            min_wei: 1000,
        };
        let result = claim_native_eth_deposit(&deposit_claim, &mut nullifiers);
        assert_eq!(result, Err(EtherReceiverError::WrongChain(11_155_111)));
    }

    #[test]
    fn test_claim_ether_atomic_account_balance_succeeds() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = EtherNullifierSet::new();
        let user_addr = [0x42; 20];
        let balance_u64: u64 = 5_000_000_000_000_000_000; // 5 ETH
        let balance = U256::from(balance_u64);

        let (state_root, proof_nodes, account_rlp) =
            build_test_account_balance_proof(Address::from(user_addr), balance);

        let instance = InstanceAccount {
            chain_id: ETH_MAINNET_CHAIN_ID,
            current_header_hash: [0x55; 32],
            current_state_root: [0x66; 32],
            current_slot: 10_000_000,
            current_sync_committee: SyncCommittee {
                pubkeys: vec![vec![0u8; 48]; 512],
                aggregate_pubkey: vec![0u8; 48],
            },
            next_sync_committee: None,
            bootstrap_slot: 10_000_000,
            initialized: true,
            current_execution_block_hash: [0u8; 32],
            current_execution_state_root: [0u8; 32],
            current_receipts_root: [0u8; 32],
        };

        let header = HeaderRecord {
            chain_id: ETH_MAINNET_CHAIN_ID,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x77; 32],
            execution_state_root: state_root.0,
            receipts_root: [0x88; 32],
        };

        let proof = StateProof {
            target: ProofTarget::AccountBalance {
                address: Address::from(user_addr),
            },
            account_proof: proof_nodes,
            storage_proof: None,
            receipt_proof: None,
            account_value: Some(account_rlp),
            storage_value: None,
            receipt_value: None,
        };

        let args = AtomicEtherClaimArgs {
            instance,
            header,
            header_history_branch: None,
            proof,
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000_000_000_000_000),
            },
            expected_address: user_addr,
            recipient: [0x33; 32],
            min_wei: 1_000_000_000_000_000_000,
        };

        let credited = claim_ether_atomic(args.clone(), &mut nullifiers)
            .expect("Atomic ether claim must succeed");
        assert_eq!(credited, balance_u64);

        // Replay rejection
        let replay = claim_ether_atomic(args, &mut nullifiers);
        assert_eq!(replay, Err(EtherReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_claim_ether_atomic_rejects_unauthenticated_header() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = EtherNullifierSet::new();
        let user_addr = [0x42; 20];
        let balance = U256::from(5_000_000_000_000_000_000u64);

        let (state_root, proof_nodes, account_rlp) =
            build_test_account_balance_proof(Address::from(user_addr), balance);

        let instance = InstanceAccount {
            chain_id: ETH_MAINNET_CHAIN_ID,
            current_header_hash: [0x55; 32],
            current_state_root: [0x66; 32],
            current_slot: 10_000_000,
            current_sync_committee: SyncCommittee {
                pubkeys: vec![vec![0u8; 48]; 512],
                aggregate_pubkey: vec![0u8; 48],
            },
            next_sync_committee: None,
            bootstrap_slot: 10_000_000,
            initialized: true,
            current_execution_block_hash: [0u8; 32],
            current_execution_state_root: [0u8; 32],
            current_receipts_root: [0u8; 32],
        };

        // Forged beacon block root
        let forged_header = HeaderRecord {
            chain_id: ETH_MAINNET_CHAIN_ID,
            slot: 10_000_000,
            beacon_block_root: [0xba; 32],
            execution_block_hash: [0x77; 32],
            execution_state_root: state_root.0,
            receipts_root: [0x88; 32],
        };

        let proof = StateProof {
            target: ProofTarget::AccountBalance {
                address: Address::from(user_addr),
            },
            account_proof: proof_nodes,
            storage_proof: None,
            receipt_proof: None,
            account_value: Some(account_rlp),
            storage_value: None,
            receipt_value: None,
        };

        let args = AtomicEtherClaimArgs {
            instance,
            header: forged_header,
            header_history_branch: None,
            proof,
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000_000_000_000_000),
            },
            expected_address: user_addr,
            recipient: [0x33; 32],
            min_wei: 1_000_000_000_000_000_000,
        };

        let res = claim_ether_atomic(args, &mut nullifiers);
        assert!(matches!(res, Err(EtherReceiverError::AttestationFailed(_))));
    }

    #[test]
    fn test_claim_ether_atomic_rejects_address_mismatch() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = EtherNullifierSet::new();
        let user_addr = [0x42; 20];
        let balance = U256::from(5_000_000_000_000_000_000u64);

        let (state_root, proof_nodes, account_rlp) =
            build_test_account_balance_proof(Address::from(user_addr), balance);

        let instance = InstanceAccount {
            chain_id: ETH_MAINNET_CHAIN_ID,
            current_header_hash: [0x55; 32],
            current_state_root: [0x66; 32],
            current_slot: 10_000_000,
            current_sync_committee: SyncCommittee {
                pubkeys: vec![vec![0u8; 48]; 512],
                aggregate_pubkey: vec![0u8; 48],
            },
            next_sync_committee: None,
            bootstrap_slot: 10_000_000,
            initialized: true,
            current_execution_block_hash: [0u8; 32],
            current_execution_state_root: [0u8; 32],
            current_receipts_root: [0u8; 32],
        };

        let header = HeaderRecord {
            chain_id: ETH_MAINNET_CHAIN_ID,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x77; 32],
            execution_state_root: state_root.0,
            receipts_root: [0x88; 32],
        };

        let proof = StateProof {
            target: ProofTarget::AccountBalance {
                address: Address::from(user_addr),
            },
            account_proof: proof_nodes,
            storage_proof: None,
            receipt_proof: None,
            account_value: Some(account_rlp),
            storage_value: None,
            receipt_value: None,
        };

        let args = AtomicEtherClaimArgs {
            instance,
            header,
            header_history_branch: None,
            proof,
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000_000_000_000_000),
            },
            expected_address: [0x99; 20], // mismatched address
            recipient: [0x33; 32],
            min_wei: 1_000_000_000_000_000_000,
        };

        let res = claim_ether_atomic(args, &mut nullifiers);
        assert!(matches!(
            res,
            Err(EtherReceiverError::ContractMismatch { .. })
        ));
    }

    #[test]
    fn test_meth_ledger_deposit_mint_and_balance() {
        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();

        let recipient = [0x55; 32];
        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];
        let wei = 2_000_000_000_000_000_000u64; // 2 ETH

        let stmt = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x10,
            wei,
            MOSOO_PROGRAM_ID,
            deposit_contract,
            sender,
            recipient,
        );

        let claim = NativeEthDepositClaim {
            statement: stmt,
            expected_deposit_contract: deposit_contract,
            sender,
            recipient,
            min_wei: 1_000_000_000_000_000_000,
        };

        let new_balance = ledger.mint_meth(&claim, &mut nullifiers).unwrap();
        assert_eq!(new_balance, 2_000_000_000_000_000_000);
        assert_eq!(ledger.get_balance(&recipient), 2_000_000_000_000_000_000);
        assert_eq!(ledger.total_supply_wei, 2_000_000_000_000_000_000);

        let account = ledger.get_account(&recipient).unwrap();
        assert_eq!(account.deposit_count, 1);
        assert_eq!(account.burn_count, 0);
    }

    #[test]
    fn test_meth_ledger_transfer_between_lez_accounts() {
        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();

        let alice = [0xAA; 32];
        let bob = [0xBB; 32];
        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];

        let stmt = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x20,
            5_000_000_000_000_000_000,
            MOSOO_PROGRAM_ID,
            deposit_contract,
            sender,
            alice,
        );

        let claim = NativeEthDepositClaim {
            statement: stmt,
            expected_deposit_contract: deposit_contract,
            sender,
            recipient: alice,
            min_wei: 1_000_000_000_000_000_000,
        };

        ledger.mint_meth(&claim, &mut nullifiers).unwrap();
        assert_eq!(ledger.get_balance(&alice), 5_000_000_000_000_000_000);

        // Alice transfers 2 ETH of mETH to Bob
        ledger
            .transfer_meth(&alice, &bob, 2_000_000_000_000_000_000)
            .unwrap();
        assert_eq!(ledger.get_balance(&alice), 3_000_000_000_000_000_000);
        assert_eq!(ledger.get_balance(&bob), 2_000_000_000_000_000_000);
        assert_eq!(ledger.total_supply_wei, 5_000_000_000_000_000_000);
    }

    #[test]
    fn test_meth_ledger_transfer_insufficient_balance_rejected() {
        let mut ledger = MethLedger::new();
        let alice = [0xAA; 32];
        let bob = [0xBB; 32];

        // Transfer with zero/non-existent account
        let res = ledger.transfer_meth(&alice, &bob, 1_000_000_000);
        assert!(matches!(res, Err(EtherReceiverError::AccountNotFound(_))));
    }

    #[test]
    fn test_meth_ledger_burn_produces_valid_burn_receipt() {
        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();

        let alice = [0xAA; 32];
        let eth_recipient = [0x77; 20];
        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];

        let stmt = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x30,
            10_000_000_000_000_000_000, // 10 ETH
            MOSOO_PROGRAM_ID,
            deposit_contract,
            sender,
            alice,
        );

        let claim = NativeEthDepositClaim {
            statement: stmt,
            expected_deposit_contract: deposit_contract,
            sender,
            recipient: alice,
            min_wei: 1_000_000_000_000_000_000,
        };

        ledger.mint_meth(&claim, &mut nullifiers).unwrap();

        // Alice burns 4 ETH of mETH to unlock on Ethereum
        let burn_receipt = ledger
            .burn_meth(
                ETH_MAINNET_CHAIN_ID,
                &alice,
                4_000_000_000_000_000_000,
                &eth_recipient,
                62180,
            )
            .unwrap();

        assert_eq!(burn_receipt.amount_wei, 4_000_000_000_000_000_000);
        assert_eq!(burn_receipt.eth_recipient, eth_recipient);
        assert_eq!(burn_receipt.lez_owner, alice);
        assert_eq!(burn_receipt.burn_nonce, 1);
        assert_eq!(burn_receipt.lez_slot, 62180);

        // Check balances and invariants
        assert_eq!(ledger.get_balance(&alice), 6_000_000_000_000_000_000);
        assert_eq!(ledger.total_supply_wei, 6_000_000_000_000_000_000);
        assert_eq!(ledger.total_burned_wei, 4_000_000_000_000_000_000);

        // Verify receipt retrievability
        let retrieved = ledger.get_burn_receipt(&burn_receipt.burn_id).unwrap();
        assert_eq!(retrieved.burn_id, burn_receipt.burn_id);
    }

    #[test]
    fn test_meth_ledger_burn_insufficient_balance_rejected() {
        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();

        let alice = [0xAA; 32];
        let eth_recipient = [0x77; 20];
        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];

        let stmt = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x40,
            1_000_000_000_000_000_000, // 1 ETH
            MOSOO_PROGRAM_ID,
            deposit_contract,
            sender,
            alice,
        );

        let claim = NativeEthDepositClaim {
            statement: stmt,
            expected_deposit_contract: deposit_contract,
            sender,
            recipient: alice,
            min_wei: 1_000_000_000_000_000_000,
        };

        ledger.mint_meth(&claim, &mut nullifiers).unwrap();

        // Alice tries to burn 2 ETH when she only has 1 ETH
        let res = ledger.burn_meth(
            ETH_MAINNET_CHAIN_ID,
            &alice,
            2_000_000_000_000_000_000,
            &eth_recipient,
            62180,
        );
        assert!(matches!(
            res,
            Err(EtherReceiverError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn test_meth_ledger_double_deposit_mint_rejected_by_nullifier() {
        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();

        let alice = [0xAA; 32];
        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];

        let stmt = make_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x50,
            3_000_000_000_000_000_000,
            MOSOO_PROGRAM_ID,
            deposit_contract,
            sender,
            alice,
        );

        let claim = NativeEthDepositClaim {
            statement: stmt.clone(),
            expected_deposit_contract: deposit_contract,
            sender,
            recipient: alice,
            min_wei: 1_000_000_000_000_000_000,
        };

        // First mint succeeds
        ledger.mint_meth(&claim, &mut nullifiers).unwrap();

        // Second mint attempt with the same claim fails due to nullifier
        let err = ledger.mint_meth(&claim, &mut nullifiers).unwrap_err();
        assert_eq!(err, EtherReceiverError::AlreadyClaimed);
        assert_eq!(ledger.get_balance(&alice), 3_000_000_000_000_000_000);
    }

    #[test]
    fn test_derive_burn_id_deterministic() {
        let id1 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_000, 1, 100);
        let id2 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_000, 1, 100);
        assert_eq!(id1, id2);

        let id3 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_001, 1, 100);
        assert_ne!(id1, id3);
    }
}
