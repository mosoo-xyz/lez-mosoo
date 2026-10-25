use alloy_primitives::{keccak256, U256};
pub use mosoo_core::predicate::derive_eth_deposit_subject_key;
pub use mosoo_core::types::derive_statement_pda;
pub use mosoo_core::types::StatementAccount as EtherStatementAccount;
pub use mosoo_core::types::{
    get_canonical_trusted_locker, is_supported_chain_id, AccountStore, RuntimeAccount,
    StatementAccount, StatementBinding, TrustedBridgeConfig, VerifiedStatement,
    ETH_HOLESKY_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    PROOF_TYPE_ACCOUNT_BALANCE, PROOF_TYPE_ETH_DEPOSIT,
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
    BalanceTooLow { actual: u128, required: u128 },

    #[error("verified balance {actual} wei (U256) is less than required {required} wei")]
    BalanceTooLowU256 { actual: U256, required: U256 },

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

    #[error(
        "statement ID mismatch: supplied statement_id does not match canonical state derivation"
    )]
    StatementIdMismatch,

    #[error("deposit backing required: ordinary Ethereum account balance cannot be credited as bridge-minted tokens without escrow lock in MosooLocker")]
    DepositBackingRequired,

    #[error("untrusted chain or locker: chain {0} has no authenticated locker vault configured")]
    UntrustedLocker(u64),

    #[error(
        "untrusted light-client instance {0:?}: instance is not approved in TrustedBridgeConfig"
    )]
    UntrustedInstanceAccount([u8; 32]),
}

/// A persistent Program-Derived Account (PDA) nullifier record for Native ETH on Logos Execution Zone.
/// Seed derivation: `[b"ether_nullifier", statement_id]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtherNullifierAccount {
    /// Deterministic statement ID marked as spent.
    pub statement_id: [u8; 32],
    /// Associated canonical subject key.
    pub subject_key: [u8; 32],
    /// Timestamp or slot when this nullifier account was initialized/spent.
    pub spent_slot: u64,
    /// Whether this nullifier account is spent.
    pub is_spent: bool,
}

/// Derives the unique PDA address for an Ether statement nullifier account on LEZ.
pub fn derive_ether_nullifier_pda(program_id: &[u8; 32], statement_id: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut h = sha2::Sha256::new();
    h.update(program_id);
    h.update(b"ether_nullifier");
    h.update(statement_id);
    h.finalize().into()
}

/// Persistent nullifier store mapping verified statement IDs to spent state on LEZ.
#[derive(Default, Clone, Debug)]
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

    /// Export active nullifier state to persistent PDA account representations.
    pub fn export_pda_records(&self, current_slot: u64) -> Vec<EtherNullifierAccount> {
        self.used
            .keys()
            .map(|id| EtherNullifierAccount {
                statement_id: *id,
                subject_key: *id,
                spent_slot: current_slot,
                is_spent: true,
            })
            .collect()
    }

    /// Restore in-memory nullifier state from persistent PDA account representations across restarts.
    pub fn restore_pda_records(&mut self, records: &[EtherNullifierAccount]) {
        for rec in records {
            if rec.is_spent {
                self.used.insert(rec.statement_id, true);
                self.used.insert(rec.subject_key, true);
            }
        }
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
/// # #[allow(deprecated)]
/// use ether_receiver::{claim_ether, EtherNullifierSet};
/// use mosoo_core::types::{VerifiedStatement, StatementBinding, ETH_MAINNET_CHAIN_ID, MOSOO_PROGRAM_ID, PROOF_TYPE_ACCOUNT_BALANCE};
/// use mosoo_core::predicate::derive_statement_id_from_raw;
/// use sha2::Digest;
///
/// let mut nullifiers = EtherNullifierSet::new();
/// let mut verified_value = [0u8; 32];
/// verified_value[24..32].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());
///
/// let user_addr = [0x42; 20];
/// let subject_key: [u8; 32] = sha2::Sha256::digest(user_addr).into();
/// let statement_id = derive_statement_id_from_raw(
///     ETH_MAINNET_CHAIN_ID,
///     &subject_key,
///     PROOF_TYPE_ACCOUNT_BALANCE,
///     &verified_value,
/// );
///
/// let statement = VerifiedStatement {
///     chain_id: ETH_MAINNET_CHAIN_ID,
///     attester_program_id: MOSOO_PROGRAM_ID,
///     statement_id,
///     predicate_holds: true,
///     verified_value,
///     subject_key,
///     proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
///     binding: StatementBinding::Account { address: user_addr },
/// };
///
/// let wei = claim_ether(&statement, &mut nullifiers, 1_000_000_000_000_000_000)
///     .expect("valid ether claim succeeds");
/// assert_eq!(wei, 1_000_000_000_000_000_000);
/// ```
#[deprecated(
    note = "Use `claim_ether_atomic_u256` for in-guest atomic execution or `claim_ether_authenticated_pda_u256` for on-chain PDA account provenance"
)]
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

    // Strict statement proof type and binding validation
    let (block_hash, slot, tx_index, log_index, deposit_contract, sender, recipient) =
        match &statement.binding {
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => {
                if *deposit_contract == [0u8; 20] || *recipient == [0u8; 32] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                (
                    *execution_block_hash,
                    *slot,
                    *tx_index,
                    *log_index,
                    *deposit_contract,
                    *sender,
                    *recipient,
                )
            }
            StatementBinding::Account { address } => {
                if statement.proof_type_tag != PROOF_TYPE_ACCOUNT_BALANCE || *address == [0u8; 20] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                use sha2::Digest;
                let expected_key: [u8; 32] = sha2::Sha256::digest(address.as_slice()).into();
                if statement.subject_key != expected_key || statement.subject_key == [0u8; 32] {
                    return Err(EtherReceiverError::SubjectKeyMismatch);
                }
                // Canonical statement ID verification
                let expected_statement_id = statement.derive_canonical_id();
                if statement.statement_id != expected_statement_id {
                    return Err(EtherReceiverError::StatementIdMismatch);
                }
                // Valid account balance claim
                let verified_wei = statement.value_as_u64_checked().map_err(|e| {
                    EtherReceiverError::AttestationFailed(format!("value overflow: {e}"))
                })?;
                if verified_wei < min_wei {
                    return Err(EtherReceiverError::BalanceTooLow {
                        actual: verified_wei as u128,
                        required: min_wei as u128,
                    });
                }
                if nullifiers.is_used(&statement.statement_id)
                    || nullifiers.is_used(&statement.subject_key)
                {
                    return Err(EtherReceiverError::AlreadyClaimed);
                }
                nullifiers.mark_used(statement.statement_id);
                nullifiers.mark_used(statement.subject_key);
                return Ok(verified_wei);
            }
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ))
            }
        };

    if statement.proof_type_tag != PROOF_TYPE_ETH_DEPOSIT {
        return Err(EtherReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let expected_subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(EtherReceiverError::SubjectKeyMismatch);
    }

    // Canonical statement ID cryptographic verification
    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(EtherReceiverError::StatementIdMismatch);
    }

    // Derive credited amount strictly from verified statement value (with overflow check)
    let verified_wei = statement
        .value_as_u64_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_wei < min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei as u128,
            required: min_wei as u128,
        });
    }

    if nullifiers.is_used(&statement.statement_id) || nullifiers.is_used(&statement.subject_key) {
        return Err(EtherReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    nullifiers.mark_used(statement.subject_key);

    Ok(verified_wei)
}

/// Claim native Ether / mETH from an authentic on-chain Statement Account committed by `MOSOO_PROGRAM_ID`.
///
/// Cryptographically verifies on-chain provenance:
/// 1. Account owner is strictly `MOSOO_PROGRAM_ID` (enforced on-chain by LEZ VM).
/// 2. PDA address matches `derive_statement_pda(chain_id, statement_id)`.
/// 3. Re-derives canonical statement ID and subject key.
/// 4. Enforces nullifier replay protection with full U256 precision.
pub fn claim_ether_authenticated_pda_u256(
    statement_account: &StatementAccount,
    nullifiers: &mut EtherNullifierSet,
    min_wei: U256,
) -> Result<U256, EtherReceiverError> {
    if statement_account.owner != MOSOO_PROGRAM_ID {
        return Err(EtherReceiverError::UnauthenticatedAttester);
    }
    let expected_pda = derive_statement_pda(
        statement_account.statement.chain_id,
        &statement_account.statement.statement_id,
    );
    if statement_account.pda_address != expected_pda {
        return Err(EtherReceiverError::UnauthenticatedAttester);
    }
    #[allow(deprecated)]
    claim_ether_u256(&statement_account.statement, nullifiers, min_wei)
}

/// Authenticate host runtime account metadata and claim Ether statement with full U256 precision.
/// Asserts host sequencer owner authentication and canonical PDA derivation.
pub fn claim_ether_runtime_account_u256(
    runtime_account: &RuntimeAccount,
    nullifiers: &mut EtherNullifierSet,
    min_wei: U256,
) -> Result<U256, EtherReceiverError> {
    let statement_account = StatementAccount::try_from_runtime_account(runtime_account)
        .map_err(|e| EtherReceiverError::AttestationFailed(e.to_string()))?;
    claim_ether_authenticated_pda_u256(&statement_account, nullifiers, min_wei)
}

/// Verify an Ether statement with full 256-bit (U256) precision and credit LEZ-side ether.
///
/// Prevents truncation or rejection for high-value transfers > u64::MAX (e.g. >18.45 ETH in wei).
#[deprecated(
    note = "Use `claim_ether_atomic_u256` for in-guest atomic execution or `claim_ether_authenticated_pda_u256` for on-chain PDA account provenance"
)]
pub fn claim_ether_u256(
    statement: &VerifiedStatement,
    nullifiers: &mut EtherNullifierSet,
    min_wei: U256,
) -> Result<U256, EtherReceiverError> {
    if !is_supported_chain_id(statement.chain_id) {
        return Err(EtherReceiverError::WrongChain(statement.chain_id));
    }
    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(EtherReceiverError::UnauthenticatedAttester);
    }
    if !statement.predicate_holds {
        return Err(EtherReceiverError::PredicateFailed);
    }

    let (block_hash, slot, tx_index, log_index, deposit_contract, sender, recipient) =
        match &statement.binding {
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => {
                if *deposit_contract == [0u8; 20] || *recipient == [0u8; 32] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                (
                    *execution_block_hash,
                    *slot,
                    *tx_index,
                    *log_index,
                    *deposit_contract,
                    *sender,
                    *recipient,
                )
            }
            StatementBinding::Account { address } => {
                if statement.proof_type_tag != PROOF_TYPE_ACCOUNT_BALANCE || *address == [0u8; 20] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                use sha2::Digest;
                let expected_key: [u8; 32] = sha2::Sha256::digest(address.as_slice()).into();
                if statement.subject_key != expected_key || statement.subject_key == [0u8; 32] {
                    return Err(EtherReceiverError::SubjectKeyMismatch);
                }
                let expected_statement_id = statement.derive_canonical_id();
                if statement.statement_id != expected_statement_id {
                    return Err(EtherReceiverError::StatementIdMismatch);
                }
                let verified_wei = statement.value_as_u256();
                if verified_wei < min_wei {
                    return Err(EtherReceiverError::BalanceTooLowU256 {
                        actual: verified_wei,
                        required: min_wei,
                    });
                }
                if nullifiers.is_used(&statement.statement_id)
                    || nullifiers.is_used(&statement.subject_key)
                {
                    return Err(EtherReceiverError::AlreadyClaimed);
                }
                nullifiers.mark_used(statement.statement_id);
                nullifiers.mark_used(statement.subject_key);
                return Ok(verified_wei);
            }
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ))
            }
        };

    if statement.proof_type_tag != PROOF_TYPE_ETH_DEPOSIT {
        return Err(EtherReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let expected_subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(EtherReceiverError::SubjectKeyMismatch);
    }

    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(EtherReceiverError::StatementIdMismatch);
    }

    let verified_wei = statement.value_as_u256();
    if verified_wei < min_wei {
        return Err(EtherReceiverError::BalanceTooLowU256 {
            actual: verified_wei,
            required: min_wei,
        });
    }

    if nullifiers.is_used(&statement.statement_id) || nullifiers.is_used(&statement.subject_key) {
        return Err(EtherReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    nullifiers.mark_used(statement.subject_key);

    Ok(verified_wei)
}

/// Verify an Ether statement with u128 precision.
#[deprecated(note = "Use `claim_ether_atomic_u256` or `claim_ether_authenticated_pda_u256`")]
pub fn claim_ether_u128(
    statement: &VerifiedStatement,
    nullifiers: &mut EtherNullifierSet,
    min_wei: u128,
) -> Result<u128, EtherReceiverError> {
    #[allow(deprecated)]
    claim_ether_u256(statement, nullifiers, U256::from(min_wei))?;
    statement
        .value_as_u128_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow u128: {e}")))
}

/// Atomically verifies statement, loads/asserts persistent PDA nullifier account state,
/// writes the spent nullifier PDA record into `store`, and returns the credited amount.
#[deprecated(note = "Use `claim_ether_atomic_u256` or `claim_ether_authenticated_pda_u256`")]
pub fn claim_ether_with_store<S: AccountStore>(
    statement: &VerifiedStatement,
    store: &mut S,
    min_wei: u64,
    current_slot: u64,
) -> Result<u64, EtherReceiverError> {
    if !is_supported_chain_id(statement.chain_id) {
        return Err(EtherReceiverError::WrongChain(statement.chain_id));
    }

    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(EtherReceiverError::UnauthenticatedAttester);
    }

    if !statement.predicate_holds {
        return Err(EtherReceiverError::PredicateFailed);
    }

    // Strict statement proof type and binding validation
    let (block_hash, slot, tx_index, log_index, deposit_contract, sender, recipient) =
        match &statement.binding {
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => {
                if *deposit_contract == [0u8; 20] || *recipient == [0u8; 32] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                (
                    *execution_block_hash,
                    *slot,
                    *tx_index,
                    *log_index,
                    *deposit_contract,
                    *sender,
                    *recipient,
                )
            }
            StatementBinding::Account { address } => {
                if statement.proof_type_tag != PROOF_TYPE_ACCOUNT_BALANCE || *address == [0u8; 20] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                use sha2::Digest;
                let expected_key: [u8; 32] = sha2::Sha256::digest(address.as_slice()).into();
                if statement.subject_key != expected_key || statement.subject_key == [0u8; 32] {
                    return Err(EtherReceiverError::SubjectKeyMismatch);
                }
                let expected_statement_id = statement.derive_canonical_id();
                if statement.statement_id != expected_statement_id {
                    return Err(EtherReceiverError::StatementIdMismatch);
                }
                let verified_wei = statement.value_as_u64_checked().map_err(|e| {
                    EtherReceiverError::AttestationFailed(format!("value overflow: {e}"))
                })?;
                if verified_wei < min_wei {
                    return Err(EtherReceiverError::BalanceTooLow {
                        actual: verified_wei as u128,
                        required: min_wei as u128,
                    });
                }

                let statement_pda =
                    derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
                let subject_pda =
                    derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);
                if store.has_account(&statement_pda) || store.has_account(&subject_pda) {
                    return Err(EtherReceiverError::AlreadyClaimed);
                }

                let record = EtherNullifierAccount {
                    statement_id: statement.statement_id,
                    subject_key: statement.subject_key,
                    spent_slot: current_slot,
                    is_spent: true,
                };
                let encoded = serde_json::to_vec(&record).map_err(|e| {
                    EtherReceiverError::AttestationFailed(format!("serialization failure: {e}"))
                })?;
                store.set_account(&statement_pda, encoded.clone());
                store.set_account(&subject_pda, encoded);

                return Ok(verified_wei);
            }
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ))
            }
        };

    if statement.proof_type_tag != PROOF_TYPE_ETH_DEPOSIT {
        return Err(EtherReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let expected_subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(EtherReceiverError::SubjectKeyMismatch);
    }

    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(EtherReceiverError::StatementIdMismatch);
    }

    let verified_wei = statement
        .value_as_u64_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_wei < min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei as u128,
            required: min_wei as u128,
        });
    }

    let statement_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);
    if store.has_account(&statement_pda) || store.has_account(&subject_pda) {
        return Err(EtherReceiverError::AlreadyClaimed);
    }

    let record = EtherNullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: current_slot,
        is_spent: true,
    };
    let encoded = serde_json::to_vec(&record).map_err(|e| {
        EtherReceiverError::AttestationFailed(format!("serialization failure: {e}"))
    })?;
    store.set_account(&statement_pda, encoded.clone());
    store.set_account(&subject_pda, encoded);

    Ok(verified_wei)
}

/// Atomically verifies an Ether statement with full 256-bit (U256) precision against persistent PDA nullifiers in AccountStore.
#[deprecated(note = "Use `claim_ether_atomic_u256` or `claim_ether_authenticated_pda_u256`")]
pub fn claim_ether_with_store_u256<S: AccountStore>(
    statement: &VerifiedStatement,
    store: &mut S,
    min_wei: U256,
    current_slot: u64,
) -> Result<U256, EtherReceiverError> {
    if !is_supported_chain_id(statement.chain_id) {
        return Err(EtherReceiverError::WrongChain(statement.chain_id));
    }
    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(EtherReceiverError::UnauthenticatedAttester);
    }
    if !statement.predicate_holds {
        return Err(EtherReceiverError::PredicateFailed);
    }

    let (block_hash, slot, tx_index, log_index, deposit_contract, sender, recipient) =
        match &statement.binding {
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => {
                if *deposit_contract == [0u8; 20] || *recipient == [0u8; 32] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                (
                    *execution_block_hash,
                    *slot,
                    *tx_index,
                    *log_index,
                    *deposit_contract,
                    *sender,
                    *recipient,
                )
            }
            StatementBinding::Account { address } => {
                if statement.proof_type_tag != PROOF_TYPE_ACCOUNT_BALANCE || *address == [0u8; 20] {
                    return Err(EtherReceiverError::InvalidStatementType(
                        statement.proof_type_tag,
                    ));
                }
                use sha2::Digest;
                let expected_key: [u8; 32] = sha2::Sha256::digest(address.as_slice()).into();
                if statement.subject_key != expected_key || statement.subject_key == [0u8; 32] {
                    return Err(EtherReceiverError::SubjectKeyMismatch);
                }
                let expected_statement_id = statement.derive_canonical_id();
                if statement.statement_id != expected_statement_id {
                    return Err(EtherReceiverError::StatementIdMismatch);
                }
                let verified_wei = statement.value_as_u256();
                if verified_wei < min_wei {
                    return Err(EtherReceiverError::BalanceTooLowU256 {
                        actual: verified_wei,
                        required: min_wei,
                    });
                }
                let statement_pda =
                    derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
                let subject_pda =
                    derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);
                if store.has_account(&statement_pda) || store.has_account(&subject_pda) {
                    return Err(EtherReceiverError::AlreadyClaimed);
                }
                let record = EtherNullifierAccount {
                    statement_id: statement.statement_id,
                    subject_key: statement.subject_key,
                    spent_slot: current_slot,
                    is_spent: true,
                };
                let encoded = serde_json::to_vec(&record).map_err(|e| {
                    EtherReceiverError::AttestationFailed(format!("serialization failure: {e}"))
                })?;
                store.set_account(&statement_pda, encoded.clone());
                store.set_account(&subject_pda, encoded);
                return Ok(verified_wei);
            }
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ))
            }
        };

    if statement.proof_type_tag != PROOF_TYPE_ETH_DEPOSIT {
        return Err(EtherReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let expected_subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );
    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(EtherReceiverError::SubjectKeyMismatch);
    }

    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(EtherReceiverError::StatementIdMismatch);
    }

    let verified_wei = statement.value_as_u256();
    if verified_wei < min_wei {
        return Err(EtherReceiverError::BalanceTooLowU256 {
            actual: verified_wei,
            required: min_wei,
        });
    }

    let statement_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);
    if store.has_account(&statement_pda) || store.has_account(&subject_pda) {
        return Err(EtherReceiverError::AlreadyClaimed);
    }

    let record = EtherNullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: current_slot,
        is_spent: true,
    };
    let encoded = serde_json::to_vec(&record).map_err(|e| {
        EtherReceiverError::AttestationFailed(format!("serialization failure: {e}"))
    })?;
    store.set_account(&statement_pda, encoded.clone());
    store.set_account(&subject_pda, encoded);

    Ok(verified_wei)
}

/// Atomically verifies an Ether statement with u128 precision against persistent PDA nullifiers in AccountStore.
#[deprecated(note = "Use `claim_ether_atomic_u256` or `claim_ether_authenticated_pda_u256`")]
pub fn claim_ether_with_store_u128<S: AccountStore>(
    statement: &VerifiedStatement,
    store: &mut S,
    min_wei: u128,
    current_slot: u64,
) -> Result<u128, EtherReceiverError> {
    #[allow(deprecated)]
    claim_ether_with_store_u256(statement, store, U256::from(min_wei), current_slot)?;
    statement
        .value_as_u128_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow u128: {e}")))
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
    if !is_supported_chain_id(claim.statement.chain_id) {
        return Err(EtherReceiverError::WrongChain(claim.statement.chain_id));
    }

    if claim.expected_deposit_contract == [0u8; 20] {
        return Err(EtherReceiverError::DepositBackingRequired);
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

    // Canonical statement ID cryptographic verification
    let expected_statement_id = claim.statement.derive_canonical_id();
    if claim.statement.statement_id != expected_statement_id {
        return Err(EtherReceiverError::StatementIdMismatch);
    }

    // Derive credited amount strictly from verified statement value (with overflow check)
    let verified_wei = claim
        .statement
        .value_as_u64_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_wei < claim.min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei as u128,
            required: claim.min_wei as u128,
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
    /// Complete cryptographic proof binding historical execution roots to beacon state
    pub historical_execution_proof: Option<mosoo_core::types::HistoricalHeaderProof>,
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

/// Arguments for executing an atomic same-transaction Native Ether claim with 256-bit representation.
#[derive(Debug, Clone)]
pub struct AtomicEtherClaimArgsU256 {
    /// Active authenticated light client instance account
    pub instance: mosoo_core::types::InstanceAccount,
    /// Authenticated header record for the target block
    pub header: mosoo_core::types::HeaderRecord,
    /// Optional historical branch if proving against past block in weak-subjectivity window
    pub header_history_branch: Option<Vec<[u8; 32]>>,
    /// Complete cryptographic proof binding historical execution roots to beacon state
    pub historical_execution_proof: Option<mosoo_core::types::HistoricalHeaderProof>,
    /// State inclusion proof (MPT proof for account balance or deposit contract)
    pub proof: mosoo_core::inclusion::StateProof,
    /// Predicate evaluated against verified state
    pub predicate: mosoo_core::types::Predicate,
    /// Expected Ethereum account or deposit contract address
    pub expected_address: [u8; 20],
    /// Expected recipient identifier on LEZ
    pub recipient: [u8; 32],
    /// Minimum required wei as U256
    pub min_wei: U256,
}

/// Execute atomic same-transaction Native Ether claim with full 256-bit amount preservation.
pub fn claim_ether_atomic_u256(
    args: AtomicEtherClaimArgsU256,
    nullifiers: &mut EtherNullifierSet,
) -> Result<U256, EtherReceiverError> {
    if !is_supported_chain_id(args.instance.chain_id) {
        return Err(EtherReceiverError::WrongChain(args.instance.chain_id));
    }

    // Provenance & Authenticity verification on instance account
    if let Err(why) = args.instance.validate_authenticity() {
        return Err(EtherReceiverError::AttestationFailed(format!(
            "unauthenticated instance account: {why}"
        )));
    }

    let attest_args = mosoo_core::verifier::AttestStateArgs {
        instance: args.instance,
        header: args.header,
        header_history_branch: args.header_history_branch,
        historical_execution_proof: args.historical_execution_proof,
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

    let verified_wei = statement.value_as_u256();
    if verified_wei < args.min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei.to::<u128>(),
            required: args.min_wei.to::<u128>(),
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

/// Execute atomic same-transaction Native Ether claim.
///
/// Directly invokes `mosoo_core::verifier::handle_attest_state` in-guest, verifies the MPT inclusion
/// proof against the authenticated `HeaderRecord`, evaluates the predicate, asserts account identity,
/// derives the deterministic statement nullifier, checks for replay, and credits wei.
#[deprecated(
    note = "Use `claim_ether_atomic_u256` for full U256 precision to prevent overflow/truncation of amounts > u64::MAX"
)]
pub fn claim_ether_atomic(
    args: AtomicEtherClaimArgs,
    nullifiers: &mut EtherNullifierSet,
) -> Result<u64, EtherReceiverError> {
    let u256_args = AtomicEtherClaimArgsU256 {
        instance: args.instance,
        header: args.header,
        header_history_branch: args.header_history_branch,
        historical_execution_proof: args.historical_execution_proof,
        proof: args.proof,
        predicate: args.predicate,
        expected_address: args.expected_address,
        recipient: args.recipient,
        min_wei: U256::from(args.min_wei),
    };
    let val_u256 = claim_ether_atomic_u256(u256_args, nullifiers)?;
    let val_u64: u64 = val_u256.try_into().map_err(|_| {
        EtherReceiverError::AttestationFailed(
            "verified wei exceeds u64 bounds; use claim_ether_atomic_u256".into(),
        )
    })?;
    Ok(val_u64)
}

/// Strongly-typed cryptographic receipt proving a verified native ETH deposit or vault escrow lock event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthDepositReceipt {
    pub statement_id: [u8; 32],
    pub deposit_contract: [u8; 20],
    pub sender: [u8; 20],
    pub recipient: [u8; 32],
    pub amount_wei: U256,
    pub execution_block_hash: [u8; 32],
    pub slot: u64,
    pub tx_index: u64,
    pub log_index: u64,
}

/// Strongly-typed attestation proving an Ethereum account balance at a verified execution state root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountBalanceAttestation {
    pub statement_id: [u8; 32],
    pub account_address: [u8; 20],
    pub verified_balance_wei: u64,
    pub execution_block_hash: [u8; 32],
    pub slot: u64,
}

/// Execute atomic same-transaction verification of an Ethereum Account Balance attestation.
///
/// Returns a strongly-typed `AccountBalanceAttestation` strictly binding the account address
/// and verified balance. Ordinary account balance attestations cannot be used to mint bridge tokens.
pub fn claim_account_balance_atomic(
    args: AtomicEtherClaimArgs,
    nullifiers: &mut EtherNullifierSet,
) -> Result<AccountBalanceAttestation, EtherReceiverError> {
    if !is_supported_chain_id(args.instance.chain_id) {
        return Err(EtherReceiverError::WrongChain(args.instance.chain_id));
    }

    // Provenance & Authenticity verification on instance account
    if let Err(why) = args.instance.validate_authenticity() {
        return Err(EtherReceiverError::AttestationFailed(format!(
            "unauthenticated instance account: {why}"
        )));
    }

    let header_slot = args.header.slot;
    let header_exec_hash = args.header.execution_block_hash;

    let attest_args = mosoo_core::verifier::AttestStateArgs {
        instance: args.instance,
        header: args.header,
        header_history_branch: args.header_history_branch,
        historical_execution_proof: args.historical_execution_proof,
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

    let account_address = match &statement.binding {
        StatementBinding::Account { address } => {
            if *address != args.expected_address {
                return Err(EtherReceiverError::ContractMismatch {
                    expected: args.expected_address,
                    actual: *address,
                });
            }
            *address
        }
        _ => {
            return Err(EtherReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ));
        }
    };

    let verified_wei = statement
        .value_as_u64_checked()
        .map_err(|e| EtherReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_wei < args.min_wei {
        return Err(EtherReceiverError::BalanceTooLow {
            actual: verified_wei as u128,
            required: args.min_wei as u128,
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

    Ok(AccountBalanceAttestation {
        statement_id: statement.statement_id,
        account_address,
        verified_balance_wei: verified_wei,
        execution_block_hash: header_exec_hash,
        slot: header_slot,
    })
}

/// Execute atomic same-transaction verification of an escrow-backed Native ETH deposit.
/// Strictly enforces that the deposit was locked in the canonical trusted vault contract
/// ([`get_canonical_trusted_locker`]) for the benefit of `args.recipient`.
#[deprecated(
    note = "In-memory test harness entrypoint. Production LEZ contract calls MUST use claim_native_eth_deposit_authenticated_store_with_config with pinned TrustedBridgeConfig."
)]
#[allow(deprecated)]
pub fn claim_native_eth_deposit_atomic(
    args: AtomicEtherClaimArgs,
    nullifiers: &mut EtherNullifierSet,
) -> Result<EthDepositReceipt, EtherReceiverError> {
    claim_native_eth_deposit_atomic_with_config(args, nullifiers, &TrustedBridgeConfig::canonical())
}

/// Execute atomic same-transaction verification of an escrow-backed Native ETH deposit with custom bridge configuration.
///
/// Returns a strongly-typed `EthDepositReceipt` proving that the deposit was locked in
/// the configured trusted vault contract for the benefit of `args.recipient`.
#[deprecated(
    note = "In-memory test harness entrypoint. Production LEZ contract calls MUST use claim_native_eth_deposit_authenticated_store_with_config with pinned TrustedBridgeConfig."
)]
pub fn claim_native_eth_deposit_atomic_with_config(
    args: AtomicEtherClaimArgs,
    nullifiers: &mut EtherNullifierSet,
    config: &TrustedBridgeConfig,
) -> Result<EthDepositReceipt, EtherReceiverError> {
    if !is_supported_chain_id(args.instance.chain_id) {
        return Err(EtherReceiverError::WrongChain(args.instance.chain_id));
    }

    // Provenance & Authenticity verification on instance account
    if let Err(why) = args.instance.validate_authenticity() {
        return Err(EtherReceiverError::AttestationFailed(format!(
            "unauthenticated instance account: {why}"
        )));
    }
    if args.expected_address == [0u8; 20] {
        return Err(EtherReceiverError::DepositBackingRequired);
    }
    let trusted_locker = config
        .get_trusted_locker(args.instance.chain_id)
        .ok_or(EtherReceiverError::UntrustedLocker(args.instance.chain_id))?;
    if args.expected_address != trusted_locker {
        return Err(EtherReceiverError::ContractMismatch {
            expected: trusted_locker,
            actual: args.expected_address,
        });
    }

    let attest_args = mosoo_core::verifier::AttestStateArgs {
        instance: args.instance,
        header: args.header,
        header_history_branch: args.header_history_branch,
        historical_execution_proof: args.historical_execution_proof,
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

    let (deposit_contract, sender, recipient, execution_block_hash, slot, tx_index, log_index) =
        match &statement.binding {
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => {
                if *deposit_contract != trusted_locker {
                    return Err(EtherReceiverError::ContractMismatch {
                        expected: trusted_locker,
                        actual: *deposit_contract,
                    });
                }
                if *recipient != args.recipient {
                    return Err(EtherReceiverError::RecipientMismatch {
                        expected: args.recipient,
                        actual: *recipient,
                    });
                }
                (
                    *deposit_contract,
                    *sender,
                    *recipient,
                    *execution_block_hash,
                    *slot,
                    *tx_index,
                    *log_index as u64,
                )
            }
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
        };

    let verified_wei = statement.value_as_u256();
    if verified_wei < U256::from(args.min_wei) {
        return Err(EtherReceiverError::BalanceTooLowU256 {
            actual: verified_wei,
            required: U256::from(args.min_wei),
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

    Ok(EthDepositReceipt {
        statement_id: statement.statement_id,
        deposit_contract,
        sender,
        recipient,
        amount_wei: verified_wei,
        execution_block_hash,
        slot,
        tx_index,
        log_index,
    })
}

/// Execute atomic same-transaction verification of an escrow-backed Native ETH deposit backed by an
/// authenticated InstanceAccount loaded directly from the persistent LEZ AccountStore.
pub fn claim_native_eth_deposit_authenticated_store_with_config<
    S: mosoo_core::types::AccountStore,
>(
    store: &mut S,
    instance_pda: &[u8; 32],
    header_pda: Option<&[u8; 32]>,
    args: AtomicEtherClaimArgs,
    nullifiers: &mut EtherNullifierSet,
    config: &TrustedBridgeConfig,
) -> Result<EthDepositReceipt, EtherReceiverError> {
    // 1. Strictly load authentic InstanceAccount from persistent store first (Finding P0)
    let authentic_instance =
        mosoo_core::verifier::verify_instance_account_authenticity(store, instance_pda)
            .map_err(|e| EtherReceiverError::AttestationFailed(e.to_string()))?;

    if !is_supported_chain_id(authentic_instance.chain_id) {
        return Err(EtherReceiverError::WrongChain(authentic_instance.chain_id));
    }

    // 2. Guard: Light-client instance must be pinned in TrustedBridgeConfig (Finding M-01)
    let loaded_config = TrustedBridgeConfig::load_or_canonical(store);
    if !config.is_trusted_instance(authentic_instance.chain_id, instance_pda)
        && !loaded_config.is_trusted_instance(authentic_instance.chain_id, instance_pda)
    {
        return Err(EtherReceiverError::UntrustedInstanceAccount(*instance_pda));
    }

    // 3. Guard: Verify authentic stored instance's bootstrap root matches pinned trusted checkpoint (Finding P0 / Chat 19)
    let expected_checkpoint = config
        .get_trusted_checkpoint(authentic_instance.chain_id)
        .or_else(|| loaded_config.get_trusted_checkpoint(authentic_instance.chain_id))
        .ok_or_else(|| {
            EtherReceiverError::AttestationFailed(
                "trusted checkpoint root absent from configuration for target chain".into(),
            )
        })?;

    if authentic_instance.bootstrap_header_hash != expected_checkpoint {
        return Err(EtherReceiverError::AttestationFailed(
            "authenticated instance bootstrap root does not match pinned trusted checkpoint".into(),
        ));
    }

    if args.expected_address == [0u8; 20] {
        return Err(EtherReceiverError::DepositBackingRequired);
    }
    let trusted_locker = config
        .get_trusted_locker(authentic_instance.chain_id)
        .ok_or(EtherReceiverError::UntrustedLocker(
            authentic_instance.chain_id,
        ))?;
    if args.expected_address != trusted_locker {
        return Err(EtherReceiverError::ContractMismatch {
            expected: trusted_locker,
            actual: args.expected_address,
        });
    }

    let attest_args = mosoo_core::verifier::AttestStateArgs {
        instance: authentic_instance,
        header: args.header,
        header_history_branch: args.header_history_branch,
        historical_execution_proof: args.historical_execution_proof,
        proof: args.proof,
        predicate: args.predicate,
    };

    let output = mosoo_core::verifier::handle_attest_state_authenticated(
        store,
        instance_pda,
        header_pda,
        attest_args,
    )
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

    let (deposit_contract, sender, recipient, execution_block_hash, slot, tx_index, log_index) =
        match &statement.binding {
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => {
                if *deposit_contract != trusted_locker {
                    return Err(EtherReceiverError::ContractMismatch {
                        expected: trusted_locker,
                        actual: *deposit_contract,
                    });
                }
                if *recipient != args.recipient {
                    return Err(EtherReceiverError::RecipientMismatch {
                        expected: args.recipient,
                        actual: *recipient,
                    });
                }
                (
                    *deposit_contract,
                    *sender,
                    *recipient,
                    *execution_block_hash,
                    *slot,
                    *tx_index,
                    *log_index as u64,
                )
            }
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
        };

    let verified_wei = statement.value_as_u256();
    if verified_wei < U256::from(args.min_wei) {
        return Err(EtherReceiverError::BalanceTooLowU256 {
            actual: verified_wei,
            required: U256::from(args.min_wei),
        });
    }

    let nullifier_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_pda = if statement.subject_key != [0u8; 32] {
        Some(derive_ether_nullifier_pda(
            &MOSOO_PROGRAM_ID,
            &statement.subject_key,
        ))
    } else {
        None
    };

    if nullifiers.is_used(&statement.statement_id)
        || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
        || store.get_account(&nullifier_pda).is_some()
        || subject_pda
            .as_ref()
            .is_some_and(|p| store.get_account(p).is_some())
    {
        return Err(EtherReceiverError::AlreadyClaimed);
    }

    // Atomically persist nullifier PDA to LEZ AccountStore (Finding P1)
    let nullifier_rec = EtherNullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: slot,
        is_spent: true,
    };
    if let Ok(encoded) = serde_json::to_vec(&nullifier_rec) {
        store.set_account_with_owner(&nullifier_pda, encoded.clone(), MOSOO_PROGRAM_ID);
        if let Some(sub_pda) = subject_pda {
            store.set_account_with_owner(&sub_pda, encoded, MOSOO_PROGRAM_ID);
        }
    }

    nullifiers.mark_used(statement.statement_id);
    if statement.subject_key != [0u8; 32] {
        nullifiers.mark_used(statement.subject_key);
    }

    Ok(EthDepositReceipt {
        statement_id: statement.statement_id,
        deposit_contract,
        sender,
        recipient,
        amount_wei: verified_wei,
        execution_block_hash,
        slot,
        tx_index,
        log_index,
    })
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MethLedger {
    accounts: HashMap<[u8; 32], MethAccount>,
    pub total_supply_wei: u128,
    pub total_burned_wei: u128,
    burn_receipts: HashMap<[u8; 32], BurnReceipt>,
    /// Authenticated program-owned bridge configuration (trusted lockers per chain)
    pub config: TrustedBridgeConfig,
}

impl Default for MethLedger {
    fn default() -> Self {
        Self {
            accounts: HashMap::new(),
            total_supply_wei: 0,
            total_burned_wei: 0,
            burn_receipts: HashMap::new(),
            config: TrustedBridgeConfig::canonical(),
        }
    }
}

impl MethLedger {
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers or updates the trusted locker contract for a given chain ID in the ledger's configuration.
    pub fn register_trusted_locker(&mut self, chain_id: u64, locker: [u8; 20]) -> bool {
        self.config.register_trusted_locker(chain_id, locker)
    }

    /// Returns the trusted locker contract for a given chain ID from the ledger's configuration.
    pub fn get_trusted_locker(&self, chain_id: u64) -> Option<[u8; 20]> {
        self.config.get_trusted_locker(chain_id)
    }

    /// Checks if candidate address matches the configured trusted locker contract for a chain ID.
    pub fn is_trusted_locker(&self, chain_id: u64, candidate: &[u8; 20]) -> bool {
        self.config.is_trusted_locker(chain_id, candidate)
    }

    pub fn get_balance(&self, owner: &[u8; 32]) -> u128 {
        self.accounts.get(owner).map_or(0, |a| a.balance_wei)
    }

    pub fn get_account(&self, owner: &[u8; 32]) -> Option<&MethAccount> {
        self.accounts.get(owner)
    }

    /// Mint synthetic `mETH` upon verification of a native ETH deposit to `MosooLocker.sol`.
    ///
    /// # Security Warning
    /// This is a legacy helper that processes an in-memory `VerifiedStatement`. In-memory statements
    /// can be fabricated by callers if exposed as an unauthenticated entrypoint.
    /// For production LEZ bridging, always invoke [`MethLedger::mint_meth_atomic`] (atomic in-guest verification)
    /// or [`MethLedger::mint_deposit_authenticated_pda_u256`] (on-chain StatementAccount PDA verification).
    #[deprecated(
        note = "Legacy test helper: In-memory VerifiedStatement can be forged. Use `mint_meth_atomic` or `mint_deposit_authenticated_pda_u256` in production"
    )]
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
    /// Strictly validates escrow deposit backing from MosooLocker, converts U256 to u128 with
    /// checked arithmetic, and verifies balance additions BEFORE consuming nullifiers.
    pub fn mint_meth_atomic(
        &mut self,
        args: AtomicEtherClaimArgs,
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<u128, EtherReceiverError> {
        // Enforce that bridge-minted mETH strictly requires authentic escrow deposit backing!
        // Unbacked Ethereum account balance proofs cannot mint bridge tokens.
        if matches!(
            args.proof.target,
            mosoo_core::inclusion::ProofTarget::AccountBalance { .. }
        ) {
            return Err(EtherReceiverError::DepositBackingRequired);
        }

        if !is_supported_chain_id(args.instance.chain_id) {
            return Err(EtherReceiverError::WrongChain(args.instance.chain_id));
        }

        if args.expected_address == [0u8; 20] {
            return Err(EtherReceiverError::DepositBackingRequired);
        }

        let trusted_locker = self
            .config
            .get_trusted_locker(args.instance.chain_id)
            .ok_or(EtherReceiverError::UntrustedLocker(args.instance.chain_id))?;

        if args.expected_address != trusted_locker {
            return Err(EtherReceiverError::ContractMismatch {
                expected: trusted_locker,
                actual: args.expected_address,
            });
        }

        let attest_args = mosoo_core::verifier::AttestStateArgs {
            instance: args.instance,
            header: args.header,
            header_history_branch: args.header_history_branch,
            historical_execution_proof: args.historical_execution_proof,
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

        let (deposit_contract, recipient) = match &statement.binding {
            StatementBinding::NativeEthDeposit {
                deposit_contract,
                recipient,
                ..
            } => (*deposit_contract, *recipient),
            _ => {
                return Err(EtherReceiverError::DepositBackingRequired);
            }
        };

        if deposit_contract != trusted_locker {
            return Err(EtherReceiverError::ContractMismatch {
                expected: trusted_locker,
                actual: deposit_contract,
            });
        }
        if recipient != args.recipient {
            return Err(EtherReceiverError::RecipientMismatch {
                expected: args.recipient,
                actual: recipient,
            });
        }

        let verified_wei = statement.value_as_u256();
        if verified_wei < U256::from(args.min_wei) {
            return Err(EtherReceiverError::BalanceTooLowU256 {
                actual: verified_wei,
                required: U256::from(args.min_wei),
            });
        }

        let amount_u128: u128 = verified_wei
            .try_into()
            .map_err(|_| EtherReceiverError::Overflow)?;

        let current_balance = self.get_balance(&recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;

        let new_supply = self
            .total_supply_wei
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;

        if nullifiers.is_used(&statement.statement_id)
            || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
        {
            return Err(EtherReceiverError::AlreadyClaimed);
        }

        nullifiers.mark_used(statement.statement_id);
        if statement.subject_key != [0u8; 32] {
            nullifiers.mark_used(statement.subject_key);
        }

        let entry = self
            .accounts
            .entry(recipient)
            .or_insert_with(|| MethAccount {
                owner: recipient,
                balance_wei: 0,
                deposit_count: 0,
                burn_count: 0,
            });

        entry.balance_wei = new_balance;
        entry.deposit_count += 1;

        self.total_supply_wei = new_supply;

        Ok(new_balance)
    }

    /// Mint synthetic `mETH` from an authentic on-chain StatementAccount PDA.
    /// Strictly verifies PDA provenance from Mosoo program ID, validates deposit vault address,
    /// performs checked U256-to-u128 conversion, and verifies balance additions before nullifier consumption.
    pub fn mint_deposit_authenticated_pda_u256(
        &mut self,
        statement_account: &StatementAccount,
        expected_deposit_contract: [u8; 20],
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<U256, EtherReceiverError> {
        if statement_account.owner != MOSOO_PROGRAM_ID {
            return Err(EtherReceiverError::UnauthenticatedAttester);
        }
        let expected_pda = derive_statement_pda(
            statement_account.statement.chain_id,
            &statement_account.statement.statement_id,
        );
        if statement_account.pda_address != expected_pda {
            return Err(EtherReceiverError::UnauthenticatedAttester);
        }

        if expected_deposit_contract == [0u8; 20] {
            return Err(EtherReceiverError::DepositBackingRequired);
        }

        let chain_id = statement_account.statement.chain_id;
        let trusted_locker = self
            .config
            .get_trusted_locker(chain_id)
            .ok_or(EtherReceiverError::UntrustedLocker(chain_id))?;

        if expected_deposit_contract != trusted_locker {
            return Err(EtherReceiverError::ContractMismatch {
                expected: trusted_locker,
                actual: expected_deposit_contract,
            });
        }

        let (deposit_contract, recipient) = match &statement_account.statement.binding {
            StatementBinding::NativeEthDeposit {
                deposit_contract,
                recipient,
                ..
            } => (*deposit_contract, *recipient),
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement_account.statement.proof_type_tag,
                ));
            }
        };

        if deposit_contract != trusted_locker {
            return Err(EtherReceiverError::ContractMismatch {
                expected: trusted_locker,
                actual: deposit_contract,
            });
        }

        let amount_u256 = statement_account.statement.value_as_u256();
        let amount_u128: u128 = amount_u256
            .try_into()
            .map_err(|_| EtherReceiverError::Overflow)?;

        let current_balance = self.get_balance(&recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;

        let new_supply = self
            .total_supply_wei
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;

        claim_ether_authenticated_pda_u256(statement_account, nullifiers, U256::ZERO)?;

        let entry = self
            .accounts
            .entry(recipient)
            .or_insert_with(|| MethAccount {
                owner: recipient,
                balance_wei: 0,
                deposit_count: 0,
                burn_count: 0,
            });

        entry.balance_wei = new_balance;
        entry.deposit_count += 1;

        self.total_supply_wei = new_supply;

        Ok(amount_u256)
    }

    /// Mint synthetic `mETH` from a host-authenticated runtime account metadata object.
    /// Strictly verifies that the host runtime owner is `MOSOO_PROGRAM_ID` and that the
    /// address matches the canonical statement PDA before minting tokens.
    pub fn mint_deposit_runtime_account_u256(
        &mut self,
        runtime_account: &RuntimeAccount,
        expected_deposit_contract: [u8; 20],
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<U256, EtherReceiverError> {
        let statement_account = StatementAccount::try_from_runtime_account(runtime_account)
            .map_err(|e| EtherReceiverError::AttestationFailed(e.to_string()))?;
        self.mint_deposit_authenticated_pda_u256(
            &statement_account,
            expected_deposit_contract,
            nullifiers,
        )
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
#[allow(deprecated)]
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
        let user_addr = [0x42; 20];
        use sha2::Digest;
        let subject_key: [u8; 32] = sha2::Sha256::digest(user_addr).into();
        let mut verified_value = [0u8; 32];
        verified_value[24..32].copy_from_slice(&wei.to_be_bytes());
        let mut stmt = VerifiedStatement {
            chain_id,
            attester_program_id: attester,
            statement_id: [0u8; 32],
            predicate_holds: holds,
            verified_value,
            subject_key,
            proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
            binding: StatementBinding::Account { address: user_addr },
        };
        stmt.statement_id = if id_seed != 0 {
            stmt.derive_canonical_id()
        } else {
            [0u8; 32]
        };
        stmt
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
        let mut stmt = VerifiedStatement {
            chain_id,
            attester_program_id: attester,
            statement_id: [0u8; 32],
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
        };
        stmt.statement_id = if id_seed != 0 {
            stmt.derive_canonical_id()
        } else {
            [0u8; 32]
        };
        stmt
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
    fn test_sepolia_chain_claim_succeeds() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_statement(ETH_SEPOLIA_CHAIN_ID, true, 0x30, 100, MOSOO_PROGRAM_ID);
        let account = StatementAccount::new_authentic(statement);
        let result =
            claim_ether_authenticated_pda_u256(&account, &mut nullifiers, U256::from(100u64));
        assert_eq!(result, Ok(U256::from(100u64)));
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
            999_999, // Unsupported chain ID
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
        assert_eq!(result, Err(EtherReceiverError::WrongChain(999_999)));
    }

    #[test]
    fn test_native_eth_deposit_sepolia_succeeds() {
        let mut nullifiers = EtherNullifierSet::new();
        let statement = make_deposit_statement(
            ETH_SEPOLIA_CHAIN_ID, // Sepolia testnet
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
        assert_eq!(result, Ok(1000));
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
            instance_id: [0u8; 32],
            network_config: None,
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
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: state_root.0,
            current_receipts_root: [0x88; 32],
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
            historical_execution_proof: None,
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
    fn test_claim_ether_atomic_u256_large_amount_succeeds() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = EtherNullifierSet::new();
        let user_addr = [0x42; 20];
        // 50 ETH = 50 * 10^18 wei >> u64::MAX (18.44 * 10^18)
        let large_wei = U256::from(50_000_000_000_000_000_000u128);

        let (state_root, proof_nodes, account_rlp) =
            build_test_account_balance_proof(user_addr.into(), large_wei);

        let instance = InstanceAccount {
            instance_id: [0u8; 32],
            network_config: None,
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
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: state_root.0,
            current_receipts_root: [0x88; 32],
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

        let mut min_32 = [0u8; 32];
        min_32[24..32].copy_from_slice(&1_000u64.to_be_bytes());

        let args = AtomicEtherClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: min_32 },
            expected_address: user_addr,
            recipient: [0x33; 32],
            min_wei: U256::from(10_000_000_000_000_000_000u128), // 10 ETH
        };

        let credited = claim_ether_atomic_u256(args.clone(), &mut nullifiers)
            .expect("Atomic U256 ether claim for 50 ETH MUST succeed");
        assert_eq!(credited, large_wei);

        // Replay rejection
        let replay = claim_ether_atomic_u256(args, &mut nullifiers);
        assert_eq!(replay, Err(EtherReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_claim_account_balance_atomic_typed_receipt() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = EtherNullifierSet::new();
        let user_addr = [0x42; 20];
        let balance_u64 = 7_000_000_000_000_000_000u64;
        let balance = U256::from(balance_u64);

        let (state_root, proof_nodes, account_rlp) =
            build_test_account_balance_proof(Address::from(user_addr), balance);

        let instance = InstanceAccount {
            instance_id: [0u8; 32],
            network_config: None,
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
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: state_root.0,
            current_receipts_root: [0x88; 32],
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
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000_000_000_000_000),
            },
            expected_address: user_addr,
            recipient: [0x33; 32],
            min_wei: 1_000_000_000_000_000_000,
        };

        let attestation = claim_account_balance_atomic(args.clone(), &mut nullifiers)
            .expect("Atomic account balance attestation must succeed");
        assert_eq!(attestation.account_address, user_addr);
        assert_eq!(attestation.verified_balance_wei, balance_u64);
        assert_eq!(attestation.slot, 10_000_000);

        // Replay rejection
        let replay = claim_account_balance_atomic(args, &mut nullifiers);
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
            instance_id: [0u8; 32],
            network_config: None,
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
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: state_root.0,
            current_receipts_root: [0x88; 32],
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
            historical_execution_proof: None,
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
            instance_id: [0u8; 32],
            network_config: None,
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
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: state_root.0,
            current_receipts_root: [0x88; 32],
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
            historical_execution_proof: None,
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
    fn test_claim_ether_rejects_statement_id_tampering() {
        let mut nullifiers = EtherNullifierSet::new();
        let mut stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x10, 100, MOSOO_PROGRAM_ID);
        // Attacker mutates statement_id to bypass nullifier tracking
        stmt.statement_id = [0xfe; 32];
        let res = claim_ether(&stmt, &mut nullifiers, 100);
        assert_eq!(res.unwrap_err(), EtherReceiverError::StatementIdMismatch);
    }

    #[test]
    fn test_ether_nullifier_pda_derivation_and_restart_persistence() {
        let mut nullifiers = EtherNullifierSet::new();
        let stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x30, 500, MOSOO_PROGRAM_ID);

        let pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &stmt.statement_id);
        assert_ne!(pda, [0u8; 32]);

        // First claim succeeds on runtime instance 1
        claim_ether(&stmt, &mut nullifiers, 100).expect("claim succeeds");

        // Export PDA records (simulating LEZ account storage persistence)
        let records = nullifiers.export_pda_records(10_000_000);
        assert!(!records.is_empty());

        // Simulate runtime restart with fresh memory state
        let mut restarted = EtherNullifierSet::new();
        assert!(!restarted.is_used(&stmt.statement_id));

        // Restore state from persistent LEZ PDA accounts
        restarted.restore_pda_records(&records);
        assert!(restarted.is_used(&stmt.statement_id));

        // Replay attempt across restart cycle MUST BE REJECTED!
        let replay_res = claim_ether(&stmt, &mut restarted, 100);
        assert_eq!(replay_res.unwrap_err(), EtherReceiverError::AlreadyClaimed);
    }

    #[test]
    fn test_meth_ledger_mint_atomic_rejects_unbacked_account_balance() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_account_balance_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();
        let user_addr = [0x42; 20];
        let balance = U256::from(5_000_000_000_000_000_000u64);

        let (state_root, proof_nodes, account_rlp) =
            build_test_account_balance_proof(Address::from(user_addr), balance);

        let instance = InstanceAccount {
            instance_id: [0u8; 32],
            network_config: None,
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
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: state_root.0,
            current_receipts_root: [0x88; 32],
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
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000_000_000_000_000),
            },
            expected_address: user_addr,
            recipient: [0x33; 32],
            min_wei: 1_000_000_000_000_000_000,
        };

        // Attempting to mint bridge mETH from an ordinary Ethereum account balance MUST FAIL!
        let res = ledger.mint_meth_atomic(args, &mut nullifiers);
        assert_eq!(res.unwrap_err(), EtherReceiverError::DepositBackingRequired);
    }

    #[test]
    fn test_meth_ledger_mint_atomic_rejects_zero_address_and_untrusted_locker() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_deposit_eth_canonical_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();

        let authentic_locker = [0xaa; 20]; // Registered test locker
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
        let fake_locker = [0x77; 20];
        let sender = [0x22; 20];
        let recipient = [0x33; 32];
        let amount_wei = U256::from(5_000_000_000_000_000_000u64); // 5 ETH
        let nonce = 1u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_eth_canonical_proof(
            Address::from(authentic_locker),
            Address::from(sender),
            recipient,
            amount_wei,
            nonce,
        );

        let instance = InstanceAccount {
            instance_id: [0u8; 32],
            network_config: None,
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
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: [0x88; 32],
            current_receipts_root: receipts_root.0,
        };

        let header = HeaderRecord {
            chain_id: ETH_MAINNET_CHAIN_ID,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x77; 32],
            execution_state_root: [0x88; 32],
            receipts_root: receipts_root.0,
        };

        let proof = StateProof {
            target: ProofTarget::NativeEthDeposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract: Address::from(authentic_locker),
                sender: Address::from(sender),
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        // 1. Zero address expected_address strictly rejected (no bypass)
        let zero_args = AtomicEtherClaimArgs {
            instance: instance.clone(),
            header: header.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: proof.clone(),
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_address: [0u8; 20],
            recipient,
            min_wei: 1_000_000,
        };
        let err_zero = ledger.mint_meth_atomic(zero_args, &mut nullifiers);
        assert_eq!(err_zero, Err(EtherReceiverError::DepositBackingRequired));

        // 2. Caller-supplied fake expected locker rejected against program-owned configuration
        let fake_args = AtomicEtherClaimArgs {
            instance: instance.clone(),
            header: header.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: proof.clone(),
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_address: fake_locker,
            recipient,
            min_wei: 1_000_000,
        };
        let err_fake = ledger.mint_meth_atomic(fake_args, &mut nullifiers);
        assert_eq!(
            err_fake,
            Err(EtherReceiverError::ContractMismatch {
                expected: authentic_locker,
                actual: fake_locker,
            })
        );
    }

    #[test]
    fn test_claim_native_eth_deposit_atomic_rejects_untrusted_vault_and_zero_address() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_deposit_eth_canonical_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = EtherNullifierSet::new();
        let canonical_sepolia = mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_LOCKER;
        let fake_vault = [0x55; 20];
        let sender = [0x22; 20];
        let recipient = [0x33; 32];
        let amount_wei = U256::from(2_000_000_000_000_000_000u64);
        let nonce = 1u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_eth_canonical_proof(
            Address::from(canonical_sepolia),
            Address::from(sender),
            recipient,
            amount_wei,
            nonce,
        );

        let instance = InstanceAccount {
            instance_id: [0u8; 32],
            network_config: None,
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            current_header_hash: [0x55; 32],
            current_state_root: [0x66; 32],
            current_slot: 10_000_000,
            current_sync_committee: SyncCommittee {
                pubkeys: vec![vec![0u8; 48]; 512],
                aggregate_pubkey: vec![0u8; 48],
            },
            next_sync_committee: None,
            bootstrap_slot: 10_000_000,
            bootstrap_header_hash: [0x55; 32],
            initialized: true,
            current_execution_block_hash: [0x77; 32],
            current_execution_state_root: [0x88; 32],
            current_receipts_root: receipts_root.0,
        };

        let header = HeaderRecord {
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x77; 32],
            execution_state_root: [0x88; 32],
            receipts_root: receipts_root.0,
        };

        let proof = StateProof {
            target: ProofTarget::NativeEthDeposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract: Address::from(canonical_sepolia),
                sender: Address::from(sender),
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        // 1. Zero address rejected
        let zero_args = AtomicEtherClaimArgs {
            instance: instance.clone(),
            header: header.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: proof.clone(),
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_address: [0u8; 20],
            recipient,
            min_wei: 1_000_000,
        };
        let err_zero = claim_native_eth_deposit_atomic(zero_args, &mut nullifiers);
        assert_eq!(err_zero, Err(EtherReceiverError::DepositBackingRequired));

        // 2. Fake vault rejected against canonical locker
        let fake_args = AtomicEtherClaimArgs {
            instance: instance.clone(),
            header: header.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: proof.clone(),
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_address: fake_vault,
            recipient,
            min_wei: 1_000_000,
        };
        let err_fake = claim_native_eth_deposit_atomic(fake_args, &mut nullifiers);
        assert_eq!(
            err_fake,
            Err(EtherReceiverError::ContractMismatch {
                expected: canonical_sepolia,
                actual: fake_vault,
            })
        );

        // 3. Authentic canonical vault succeeds
        let valid_args = AtomicEtherClaimArgs {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_address: canonical_sepolia,
            recipient,
            min_wei: 1_000_000,
        };
        let receipt = claim_native_eth_deposit_atomic(valid_args, &mut nullifiers)
            .expect("Authentic canonical Sepolia deposit claim must succeed");
        assert_eq!(receipt.deposit_contract, canonical_sepolia);
        assert_eq!(receipt.amount_wei, amount_wei);
    }

    #[test]
    fn test_derive_burn_id_deterministic() {
        let id1 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_000, 1, 100);
        let id2 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_000, 1, 100);
        assert_eq!(id1, id2);

        let id3 = derive_burn_id(1, &[0x11; 32], &[0x22; 20], 1_000_001, 1, 100);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_claim_ether_u256_amounts_exceeding_u64_max_succeeds() {
        let mut nullifiers = EtherNullifierSet::new();
        // 50 ETH = 50 * 10^18 wei = 50_000_000_000_000_000_000 > u64::MAX (~18.44 ETH in wei)
        let large_wei: u128 = 50_000_000_000_000_000_000;
        assert!(large_wei > u64::MAX as u128);

        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];
        let recipient = [0x33; 32];
        let block_hash = [0x44; 32];
        let slot = 10_500_000;
        let tx_index = 1;
        let log_index = 0;

        let subject_key = derive_eth_deposit_subject_key(
            &block_hash,
            slot,
            tx_index,
            log_index,
            &deposit_contract,
            &sender,
            &recipient,
        );
        let mut verified_value = [0u8; 32];
        verified_value.copy_from_slice(&U256::from(large_wei).to_be_bytes::<32>());

        let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
            ETH_MAINNET_CHAIN_ID,
            &subject_key,
            PROOF_TYPE_ETH_DEPOSIT,
            &verified_value,
        );

        let statement = VerifiedStatement {
            chain_id: ETH_MAINNET_CHAIN_ID,
            attester_program_id: MOSOO_PROGRAM_ID,
            statement_id,
            predicate_holds: true,
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
        };

        // Standard u64 claim fails closed with overflow protection
        let u64_res = claim_ether(&statement, &mut nullifiers, 1_000_000_000);
        assert!(matches!(
            u64_res,
            Err(EtherReceiverError::AttestationFailed(_))
        ));

        // U256 claim succeeds
        let claimed = claim_ether_u256(&statement, &mut nullifiers, U256::from(large_wei))
            .expect("claim_ether_u256 for > u64::MAX wei must succeed");
        assert_eq!(claimed, U256::from(large_wei));

        // Replay rejected
        let replay = claim_ether_u256(&statement, &mut nullifiers, U256::from(large_wei));
        assert_eq!(replay.unwrap_err(), EtherReceiverError::AlreadyClaimed);
    }

    #[test]
    fn test_claim_ether_u128_amounts_exceeding_u64_max_succeeds() {
        let mut nullifiers = EtherNullifierSet::new();
        let large_wei: u128 = 25_000_000_000_000_000_000; // 25 ETH
        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];
        let recipient = [0x33; 32];
        let block_hash = [0x44; 32];
        let slot = 10_500_000;
        let tx_index = 1;
        let log_index = 0;

        let subject_key = derive_eth_deposit_subject_key(
            &block_hash,
            slot,
            tx_index,
            log_index,
            &deposit_contract,
            &sender,
            &recipient,
        );
        let mut verified_value = [0u8; 32];
        verified_value.copy_from_slice(&U256::from(large_wei).to_be_bytes::<32>());

        let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
            ETH_MAINNET_CHAIN_ID,
            &subject_key,
            PROOF_TYPE_ETH_DEPOSIT,
            &verified_value,
        );

        let statement = VerifiedStatement {
            chain_id: ETH_MAINNET_CHAIN_ID,
            attester_program_id: MOSOO_PROGRAM_ID,
            statement_id,
            predicate_holds: true,
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
        };

        #[allow(deprecated)]
        let claimed = claim_ether_u128(&statement, &mut nullifiers, large_wei)
            .expect("claim_ether_u128 for > u64::MAX wei must succeed");
        assert_eq!(claimed, large_wei);
    }

    #[test]
    fn test_claim_ether_authenticated_pda_u256_provenance_verification() {
        let mut nullifiers = EtherNullifierSet::new();
        let deposit_contract = [0x11; 20];
        let sender = [0x22; 20];
        let recipient = [0x33; 32];
        let block_hash = [0x44; 32];
        let slot = 10_500_000;
        let tx_index = 1;
        let log_index = 0;
        let wei = U256::from(50_000_000_000_000_000_000u128); // 50 ETH

        let subject_key = derive_eth_deposit_subject_key(
            &block_hash,
            slot,
            tx_index,
            log_index,
            &deposit_contract,
            &sender,
            &recipient,
        );
        let mut val_bytes = [0u8; 32];
        val_bytes.copy_from_slice(&wei.to_be_bytes::<32>());

        let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
            ETH_MAINNET_CHAIN_ID,
            &subject_key,
            PROOF_TYPE_ETH_DEPOSIT,
            &val_bytes,
        );

        let statement = VerifiedStatement {
            chain_id: ETH_MAINNET_CHAIN_ID,
            attester_program_id: MOSOO_PROGRAM_ID,
            statement_id,
            predicate_holds: true,
            verified_value: val_bytes,
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
        };

        // 1. Adversary fabricates statement account with fake owner program ID
        let fake_owner = [0x99; 32];
        let fabricated_account = StatementAccount {
            owner: fake_owner,
            pda_address: derive_statement_pda(statement.chain_id, &statement.statement_id),
            statement: statement.clone(),
        };
        let err = claim_ether_authenticated_pda_u256(
            &fabricated_account,
            &mut nullifiers,
            U256::from(100u64),
        )
        .expect_err("Fabricated account with fake owner must be rejected");
        assert_eq!(err, EtherReceiverError::UnauthenticatedAttester);

        // 2. Adversary fabricates statement account with mismatched PDA address
        let fake_pda = [0x88; 32];
        let tampered_pda_account = StatementAccount {
            owner: MOSOO_PROGRAM_ID,
            pda_address: fake_pda,
            statement: statement.clone(),
        };
        let err2 = claim_ether_authenticated_pda_u256(
            &tampered_pda_account,
            &mut nullifiers,
            U256::from(100u64),
        )
        .expect_err("Account with tampered PDA address must be rejected");
        assert_eq!(err2, EtherReceiverError::UnauthenticatedAttester);

        // 3. Authentic statement account succeeds
        let authentic_account = StatementAccount::new_authentic(statement);
        let claimed = claim_ether_authenticated_pda_u256(
            &authentic_account,
            &mut nullifiers,
            U256::from(100u64),
        )
        .expect("Authentic statement account must be accepted");
        assert_eq!(claimed, wei);

        // 4. Replay rejected
        let replay = claim_ether_authenticated_pda_u256(
            &authentic_account,
            &mut nullifiers,
            U256::from(100u64),
        )
        .expect_err("Replay claim on statement account must be rejected");
        assert_eq!(replay, EtherReceiverError::AlreadyClaimed);
    }

    #[test]
    fn test_meth_ledger_authenticated_pda_mint_succeeds_and_fabricated_rejected() {
        let mut ledger = MethLedger::new();
        let mut nullifiers = EtherNullifierSet::new();
        let deposit_contract = [0x11; 20];
        ledger.register_trusted_locker(ETH_SEPOLIA_CHAIN_ID, deposit_contract);

        let sender = [0x22; 20];
        let recipient = [0x33; 32];
        let block_hash = [0x44; 32];
        let slot = 10_500_000;
        let tx_index = 1;
        let log_index = 0;
        let amount_wei = U256::from(50_000_000_000_000_000_000u128); // 50 ETH

        let subject_key = derive_eth_deposit_subject_key(
            &block_hash,
            slot,
            tx_index,
            log_index,
            &deposit_contract,
            &sender,
            &recipient,
        );
        let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
            ETH_SEPOLIA_CHAIN_ID,
            &subject_key,
            PROOF_TYPE_ETH_DEPOSIT,
            &amount_wei.to_be_bytes::<32>(),
        );

        let statement = VerifiedStatement {
            chain_id: ETH_SEPOLIA_CHAIN_ID,
            attester_program_id: MOSOO_PROGRAM_ID,
            statement_id,
            predicate_holds: true,
            verified_value: amount_wei.to_be_bytes::<32>(),
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
        };

        // 1. Fabricated account rejected
        let fabricated = StatementAccount {
            owner: [0xfe; 32],
            pda_address: [0xdd; 32],
            statement: statement.clone(),
        };
        let err = ledger.mint_deposit_authenticated_pda_u256(
            &fabricated,
            deposit_contract,
            &mut nullifiers,
        );
        assert_eq!(err, Err(EtherReceiverError::UnauthenticatedAttester));

        // 2. Zero address bypass strictly rejected
        let authentic = StatementAccount::new_authentic(statement);
        let zero_err =
            ledger.mint_deposit_authenticated_pda_u256(&authentic, [0u8; 20], &mut nullifiers);
        assert_eq!(zero_err, Err(EtherReceiverError::DepositBackingRequired));

        // 3. Mismatched deposit vault rejected
        let mismatch =
            ledger.mint_deposit_authenticated_pda_u256(&authentic, [0xee; 20], &mut nullifiers);
        assert_eq!(
            mismatch,
            Err(EtherReceiverError::ContractMismatch {
                expected: deposit_contract,
                actual: [0xee; 20],
            })
        );

        // 3. Authentic account mints 50 ETH successfully
        let minted = ledger
            .mint_deposit_authenticated_pda_u256(&authentic, deposit_contract, &mut nullifiers)
            .expect("Authentic PDA mint must succeed");
        assert_eq!(minted, amount_wei);
        assert_eq!(ledger.get_balance(&recipient), amount_wei.to::<u128>());
        assert_eq!(ledger.total_supply_wei, amount_wei.to::<u128>());

        // 4. Double-mint replay rejected by nullifier
        let replay = ledger.mint_deposit_authenticated_pda_u256(
            &authentic,
            deposit_contract,
            &mut nullifiers,
        );
        assert_eq!(replay, Err(EtherReceiverError::AlreadyClaimed));
    }
}
