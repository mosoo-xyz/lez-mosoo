use alloy_primitives::{keccak256, U256};
pub use mosoo_core::predicate::derive_eth_deposit_subject_key;
pub use mosoo_core::types::derive_statement_pda;
pub use mosoo_core::types::StatementAccount as EtherStatementAccount;
pub use mosoo_core::types::{
    derive_claim_nullifier, derive_shielded_burn_nullifier, derive_shielded_commitment,
    derive_shielded_deposit_secrets, get_canonical_trusted_locker, is_supported_chain_id,
    AccountStore, RuntimeAccount, StatementAccount, StatementBinding, TrustedBridgeConfig,
    VerifiedStatement, ETH_HOLESKY_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
    MOSOO_PROGRAM_ID, PROOF_TYPE_ACCOUNT_BALANCE, PROOF_TYPE_ETH_DEPOSIT,
    PROOF_TYPE_SHIELDED_DEPOSIT,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
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

    #[error("unauthenticated source instance: zero instance PDA is not permitted in production")]
    UnauthenticatedSourceInstance,

    #[error("untrusted source instance: statement source_instance_pda does not match pinned trusted instance")]
    UntrustedSourceInstance,

    #[error("shielded commitment preimage verification failed: secret or nullifier preimage does not match attested commitment")]
    InvalidShieldedPreimage,
}

/// Claim parameters for an RFP-022 unlinkable shielded native ETH deposit claim (`DepositCommitted` with `token = Address::ZERO`).
#[derive(Debug, Clone)]
pub struct ShieldedEthClaimArgs {
    pub header: mosoo_core::types::HeaderRecord,
    pub header_history_branch: Option<Vec<[u8; 32]>>,
    pub historical_execution_proof: Option<mosoo_core::types::HistoricalHeaderProof>,
    pub proof: mosoo_core::inclusion::StateProof,
    pub predicate: mosoo_core::types::Predicate,
    pub expected_deposit_contract: [u8; 20],
    /// Fresh LEZ recipient specified strictly at claim time (never revealed on Ethereum L1).
    pub recipient: [u8; 32],
    /// User secret commitment preimage.
    pub secret: [u8; 32],
    /// User nullifier preimage (hashed on claim to prevent double-spend).
    pub nullifier_secret: [u8; 32],
    pub min_wei: u128,
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
#[derive(Default, Clone, Debug, PartialEq, Eq)]
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
///     genesis_validators_root: [0u8; 32],
///     source_instance_id: [0u8; 32],
///     source_instance_pda: [0u8; 32],
///     attester_program_id: MOSOO_PROGRAM_ID,
///     statement_id,
///     predicate_holds: true,
///     verified_value,
///     subject_key,
///     proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
///     binding: StatementBinding::Account { address: user_addr },
/// };
///
/// #[allow(deprecated)]
/// let wei = claim_ether(&statement, &mut nullifiers, 1_000_000_000_000_000_000)
///     .expect("valid ether claim succeeds");
/// assert_eq!(wei, 1_000_000_000_000_000_000);
/// ```
#[cfg(any(test, feature = "test-harness"))]
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
    if statement_account.statement.source_instance_pda == [0u8; 32] {
        return Err(EtherReceiverError::UnauthenticatedSourceInstance);
    }
    let pinned_pda = TrustedBridgeConfig::canonical()
        .get_trusted_instance(statement_account.statement.chain_id)
        .ok_or(EtherReceiverError::UntrustedSourceInstance)?;
    if statement_account.statement.source_instance_pda != pinned_pda {
        return Err(EtherReceiverError::UntrustedSourceInstance);
    }
    claim_ether_u256_internal(&statement_account.statement, nullifiers, min_wei)
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

pub(crate) fn claim_ether_u256_internal(
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

/// Opening witness parameters required to redeem a shielded Native ETH statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedEtherClaimWitness {
    /// The unshielded binding containing the underlying Ethereum transfer or deposit parameters.
    pub unshielded_binding: StatementBinding,
    /// The private 256-bit blinding salt used during statement issuance (if salted).
    pub privacy_salt: Option<[u8; 32]>,
}

/// Verifies and claims a privacy-shielded native ETH statement (where `statement.binding` is `StatementBinding::Shielded`),
/// verifying the commitment and blinded identifiers against the claimant's private witness preimage.
pub fn claim_shielded_ether_statement_u256(
    statement: &VerifiedStatement,
    witness: &ShieldedEtherClaimWitness,
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
    if statement.proof_type_tag != PROOF_TYPE_ETH_DEPOSIT {
        return Err(EtherReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let StatementBinding::Shielded { commitment } = &statement.binding else {
        return Err(EtherReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    };

    // 1. Verify commitment against unshielded binding witness
    let expected_commitment = match witness.privacy_salt {
        Some(ref salt) => witness.unshielded_binding.compute_salted_commitment(salt),
        None => witness.unshielded_binding.compute_commitment(),
    };
    if *commitment != expected_commitment {
        return Err(EtherReceiverError::SubjectKeyMismatch);
    }

    // 2. Derive unshielded subject key from the witness binding
    let (block_hash, slot, tx_index, log_index, deposit_contract, sender, recipient) =
        match &witness.unshielded_binding {
            StatementBinding::NativeEthDeposit {
                execution_block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                sender,
                recipient,
            } => (
                *execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                *deposit_contract,
                *sender,
                *recipient,
            ),
            _ => {
                return Err(EtherReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ))
            }
        };

    let unblinded_subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );

    // 3. Verify blinded subject key
    let expected_blinded_subject_key: [u8; 32] = match witness.privacy_salt {
        Some(ref salt) => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"mosoo_salted_subject_key_v1:");
            hasher.update(salt);
            hasher.update(unblinded_subject_key);
            hasher.finalize().into()
        }
        None => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"mosoo_shielded_subject_key_v1:");
            hasher.update(unblinded_subject_key);
            hasher.finalize().into()
        }
    };
    if statement.subject_key != expected_blinded_subject_key {
        return Err(EtherReceiverError::SubjectKeyMismatch);
    }

    // 4. Derive unblinded canonical statement ID
    let mut unblinded_stmt = statement.clone();
    unblinded_stmt.binding = witness.unshielded_binding.clone();
    unblinded_stmt.subject_key = unblinded_subject_key;
    let unblinded_id = unblinded_stmt.derive_canonical_id();

    // 5. Verify blinded statement ID
    let expected_blinded_id: [u8; 32] = match witness.privacy_salt {
        Some(ref salt) => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"mosoo_salted_statement_id_v1:");
            hasher.update(salt);
            hasher.update(unblinded_id);
            hasher.finalize().into()
        }
        None => {
            let mut hasher = sha2::Sha256::new();
            hasher.update(b"mosoo_shielded_statement_id_v1:");
            hasher.update(unblinded_id);
            hasher.finalize().into()
        }
    };
    if statement.statement_id != expected_blinded_id {
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

/// Verify an Ether statement with full 256-bit (U256) precision and credit LEZ-side ether.
///
/// Prevents truncation or rejection for high-value transfers > u64::MAX (e.g. >18.45 ETH in wei).
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(
    note = "Use `claim_ether_atomic_u256` for in-guest atomic execution or `claim_ether_authenticated_pda_u256` for on-chain PDA account provenance"
)]
pub fn claim_ether_u256(
    statement: &VerifiedStatement,
    nullifiers: &mut EtherNullifierSet,
    min_wei: U256,
) -> Result<U256, EtherReceiverError> {
    claim_ether_u256_internal(statement, nullifiers, min_wei)
}

/// Verify an Ether statement with u128 precision.
#[cfg(any(test, feature = "test-harness"))]
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
#[cfg(any(test, feature = "test-harness"))]
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
#[cfg(any(test, feature = "test-harness"))]
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
#[cfg(any(test, feature = "test-harness"))]
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
/// Proves that
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
/// verifying sender, recipient, and amount parameters.
#[cfg(any(test, feature = "test-harness"))]
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

#[cfg(any(test, feature = "test-harness"))]
#[deprecated(
    note = "In-memory test harness entrypoint. Production LEZ contract calls MUST use claim_ether_authenticated_store_u256 with pinned TrustedBridgeConfig."
)]
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
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
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
#[cfg(any(test, feature = "test-harness"))]
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
    #[allow(deprecated)]
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
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
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
#[cfg(any(test, feature = "test-harness"))]
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
#[cfg(any(test, feature = "test-harness"))]
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
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
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

/// Strictly verifies an atomic Native ETH deposit claim against persistent storage.
/// Returns the strongly-typed `EthDepositReceipt` and statement details WITHOUT consuming nullifiers.
pub fn verify_native_eth_deposit_authenticated_store_details<S: mosoo_core::types::AccountStore>(
    store: &S,
    instance_pda: &[u8; 32],
    header_pda: Option<&[u8; 32]>,
    args: AtomicEtherClaimArgs,
    nullifiers: &EtherNullifierSet,
    config: &TrustedBridgeConfig,
) -> Result<(EthDepositReceipt, VerifiedStatement), EtherReceiverError> {
    // 1. Load program-owned TrustedBridgeConfig from persistent storage.
    let loaded_config = TrustedBridgeConfig::load_strict(store).map_err(|e| {
        EtherReceiverError::AttestationFailed(format!(
            "program-owned config verification failed: {e}"
        ))
    })?;

    if config != &loaded_config {
        return Err(EtherReceiverError::AttestationFailed(
            "caller-supplied configuration does not match persistent program-owned configuration"
                .into(),
        ));
    }

    // 2. Load InstanceAccount from program-owned storage.
    let authentic_instance =
        mosoo_core::verifier::verify_instance_account_authenticity(store, instance_pda)
            .map_err(|e| EtherReceiverError::AttestationFailed(e.to_string()))?;

    if !is_supported_chain_id(authentic_instance.chain_id) {
        return Err(EtherReceiverError::WrongChain(authentic_instance.chain_id));
    }

    // 3. Guard: Light-client instance must be pinned in program-owned TrustedBridgeConfig
    if !loaded_config.is_trusted_instance(authentic_instance.chain_id, instance_pda) {
        return Err(EtherReceiverError::UntrustedInstanceAccount(*instance_pda));
    }

    // 4. Guard: Verify authentic stored instance's bootstrap root matches pinned trusted checkpoint
    let expected_checkpoint = loaded_config
        .get_trusted_checkpoint(authentic_instance.chain_id)
        .ok_or_else(|| {
            EtherReceiverError::AttestationFailed(
                "trusted checkpoint root absent from stored configuration for target chain".into(),
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

    let trusted_locker = loaded_config
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
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
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

    let receipt = EthDepositReceipt {
        statement_id: statement.statement_id,
        deposit_contract,
        sender,
        recipient,
        amount_wei: verified_wei,
        execution_block_hash,
        slot,
        tx_index,
        log_index,
    };

    Ok((receipt, statement))
}

/// Atomically persists nullifier records to persistent storage and marks them in memory.
pub fn commit_ether_nullifiers<S: mosoo_core::types::AccountStore>(
    store: &mut S,
    nullifiers: &mut EtherNullifierSet,
    statement: &VerifiedStatement,
    slot: u64,
) -> Result<(), EtherReceiverError> {
    let nullifier_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_pda = if statement.subject_key != [0u8; 32] {
        Some(derive_ether_nullifier_pda(
            &MOSOO_PROGRAM_ID,
            &statement.subject_key,
        ))
    } else {
        None
    };

    let nullifier_rec = EtherNullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: slot,
        is_spent: true,
    };
    let encoded = serde_json::to_vec(&nullifier_rec).map_err(|e| {
        EtherReceiverError::AttestationFailed(format!("failed to serialize nullifier PDA: {e}"))
    })?;
    let mut batch = vec![(nullifier_pda, encoded.clone(), MOSOO_PROGRAM_ID)];
    if let Some(sub_pda) = subject_pda {
        batch.push((sub_pda, encoded, MOSOO_PROGRAM_ID));
    }
    store
        .try_set_accounts_batch_with_owner(&batch)
        .map_err(|e| {
            EtherReceiverError::AttestationFailed(format!(
                "failed to atomically store nullifier PDA batch: {e}"
            ))
        })?;

    nullifiers.mark_used(statement.statement_id);
    if statement.subject_key != [0u8; 32] {
        nullifiers.mark_used(statement.subject_key);
    }

    Ok(())
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
    let (receipt, statement) = verify_native_eth_deposit_authenticated_store_details(
        store,
        instance_pda,
        header_pda,
        args,
        nullifiers,
        config,
    )?;
    commit_ether_nullifiers(store, nullifiers, &statement, receipt.slot)?;
    Ok(receipt)
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

/// Derives the canonical 32-byte burn identifier matching `MosooLocker.sol` V2 with cross-instance domain separation:
/// `keccak256(abi.encodePacked("mosoo_burn_v2", block.chainid, sourceInstance, lezOwner, recipient, amount, burnNonce, lezSlot))`
pub fn derive_burn_id_v2(
    chain_id: u64,
    source_instance: &[u8; 32],
    lez_owner: &[u8; 32],
    eth_recipient: &[u8; 20],
    amount_wei: u128,
    burn_nonce: u64,
    lez_slot: u64,
) -> [u8; 32] {
    let mut packed = Vec::with_capacity(177);
    packed.extend_from_slice(b"mosoo_burn_v2");
    packed.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    packed.extend_from_slice(source_instance);
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
    #[cfg(any(test, feature = "test-harness"))]
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

    /// Mint synthetic `mETH` backed by an authentic on-chain light client instance in persistent `AccountStore`.
    /// Strictly loads authentic InstanceAccount and TrustedBridgeConfig from storage,
    /// verifies instance pinning and vault contracts, performs atomic in-guest verification,
    /// and ensures balance additions precede nullifier consumption.
    pub fn mint_deposit_authenticated_store_u256<S: mosoo_core::types::AccountStore>(
        &mut self,
        store: &mut S,
        instance_pda: &[u8; 32],
        header_pda: Option<&[u8; 32]>,
        args: AtomicEtherClaimArgs,
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<u128, EtherReceiverError> {
        let (receipt, statement) = verify_native_eth_deposit_authenticated_store_details(
            store,
            instance_pda,
            header_pda,
            args,
            nullifiers,
            &self.config,
        )?;

        // Arithmetic Pre-Check: conversion, balance addition, and supply addition must succeed BEFORE consuming nullifiers!
        let amount_u128: u128 = receipt
            .amount_wei
            .try_into()
            .map_err(|_| EtherReceiverError::Overflow)?;

        let current_balance = self.get_balance(&receipt.recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;

        let new_supply = self
            .total_supply_wei
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;

        // All arithmetic checks passed without overflow: now consume nullifiers atomically.
        commit_ether_nullifiers(store, nullifiers, &statement, receipt.slot)?;

        let entry = self
            .accounts
            .entry(receipt.recipient)
            .or_insert_with(|| MethAccount {
                owner: receipt.recipient,
                balance_wei: 0,
                deposit_count: 0,
                burn_count: 0,
            });

        entry.balance_wei = new_balance;
        entry.deposit_count += 1;
        self.total_supply_wei = new_supply;

        Ok(new_balance)
    }

    /// Execute an unlinkable RFP-022 shielded ETH claim backed by an authenticated `InstanceAccount`
    /// and a verified `DepositCommitted(token = address(0))` receipt log from `MosooLocker.depositShieldedETH`.
    ///
    /// Neither Ethereum depositor address nor LEZ `recipient` appears anywhere on Ethereum L1.
    pub fn claim_shielded_eth_deposit_authenticated_store<S: mosoo_core::types::AccountStore>(
        &mut self,
        store: &mut S,
        instance_pda: &[u8; 32],
        header_pda: Option<&[u8; 32]>,
        args: ShieldedEthClaimArgs,
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<u128, EtherReceiverError> {
        let loaded_config = TrustedBridgeConfig::load_strict(store).map_err(|e| {
            EtherReceiverError::AttestationFailed(format!(
                "program-owned config verification failed: {e}"
            ))
        })?;
        if self.config != loaded_config {
            return Err(EtherReceiverError::AttestationFailed(
                "caller-supplied configuration does not match persistent program-owned configuration".into(),
            ));
        }

        let authentic_instance =
            mosoo_core::verifier::verify_instance_account_authenticity(store, instance_pda)
                .map_err(|e| EtherReceiverError::AttestationFailed(e.to_string()))?;

        if !is_supported_chain_id(authentic_instance.chain_id) {
            return Err(EtherReceiverError::WrongChain(authentic_instance.chain_id));
        }
        if !loaded_config.is_trusted_instance(authentic_instance.chain_id, instance_pda) {
            return Err(EtherReceiverError::UntrustedInstanceAccount(*instance_pda));
        }

        let expected_checkpoint = loaded_config
            .get_trusted_checkpoint(authentic_instance.chain_id)
            .ok_or_else(|| {
                EtherReceiverError::AttestationFailed(
                    "trusted checkpoint root absent from stored configuration for target chain"
                        .into(),
                )
            })?;
        if authentic_instance.bootstrap_header_hash != expected_checkpoint {
            return Err(EtherReceiverError::AttestationFailed(
                "authenticated instance bootstrap root does not match pinned trusted checkpoint"
                    .into(),
            ));
        }

        if args.expected_deposit_contract == [0u8; 20] {
            return Err(EtherReceiverError::DepositBackingRequired);
        }

        let chain_id = authentic_instance.chain_id;
        let trusted_locker = loaded_config
            .get_trusted_locker(chain_id)
            .ok_or(EtherReceiverError::UntrustedLocker(chain_id))?;
        if !loaded_config.is_trusted_shielded_locker(chain_id, &args.expected_deposit_contract) {
            return Err(EtherReceiverError::ContractMismatch {
                expected: trusted_locker,
                actual: args.expected_deposit_contract,
            });
        }

        let attest_args = mosoo_core::verifier::AttestStateArgs {
            instance: authentic_instance,
            header: args.header,
            header_history_branch: args.header_history_branch,
            historical_execution_proof: args.historical_execution_proof,
            proof: args.proof,
            predicate: args.predicate,
            privacy_salt: None,
            trusted_head_slot: None,
            privacy_mode: None,
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
        if statement.proof_type_tag != PROOF_TYPE_SHIELDED_DEPOSIT {
            return Err(EtherReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ));
        }

        let (locker_contract, token_contract, commitment, slot) = match &statement.binding {
            StatementBinding::ShieldedCommitment {
                locker_contract,
                token_contract,
                commitment,
                slot,
                ..
            } => (*locker_contract, *token_contract, *commitment, *slot),
            _ => return Err(EtherReceiverError::DepositBackingRequired),
        };

        if locker_contract != args.expected_deposit_contract
            || !loaded_config.is_trusted_shielded_locker(chain_id, &locker_contract)
        {
            return Err(EtherReceiverError::ContractMismatch {
                expected: args.expected_deposit_contract,
                actual: locker_contract,
            });
        }
        // Native ETH shielded deposit pool requires token_contract == Address::ZERO
        if token_contract != [0u8; 20] {
            return Err(EtherReceiverError::DepositBackingRequired);
        }

        let verified_wei = statement.value_as_u256();
        if verified_wei < U256::from(args.min_wei) {
            return Err(EtherReceiverError::BalanceTooLowU256 {
                actual: verified_wei,
                required: U256::from(args.min_wei),
            });
        }

        let expected_commitment = derive_shielded_commitment(
            &[0u8; 20],
            &verified_wei.to_be_bytes::<32>(),
            &args.secret,
            &args.nullifier_secret,
        );
        if expected_commitment != commitment {
            return Err(EtherReceiverError::InvalidShieldedPreimage);
        }

        let claim_nullifier = derive_claim_nullifier(&args.nullifier_secret);
        let claim_nullifier_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &claim_nullifier);
        let stmt_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
        let subj_pda = derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);
        if nullifiers.is_used(&claim_nullifier)
            || nullifiers.is_used(&statement.statement_id)
            || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
            || store.get_account(&claim_nullifier_pda).is_some()
            || store.get_account(&stmt_pda).is_some()
            || (statement.subject_key != [0u8; 32] && store.get_account(&subj_pda).is_some())
        {
            return Err(EtherReceiverError::AlreadyClaimed);
        }

        let amount_u128: u128 = verified_wei
            .try_into()
            .map_err(|_| EtherReceiverError::Overflow)?;
        let current_balance = self.get_balance(&args.recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;
        let new_supply = self
            .total_supply_wei
            .checked_add(amount_u128)
            .ok_or(EtherReceiverError::Overflow)?;

        let claim_rec = EtherNullifierAccount {
            statement_id: claim_nullifier,
            subject_key: commitment,
            spent_slot: slot,
            is_spent: true,
        };
        let encoded_claim = serde_json::to_vec(&claim_rec).map_err(|e| {
            EtherReceiverError::AttestationFailed(format!(
                "failed to serialize claim nullifier PDA: {e}"
            ))
        })?;
        store
            .try_set_accounts_batch_with_owner(&[(
                claim_nullifier_pda,
                encoded_claim,
                MOSOO_PROGRAM_ID,
            )])
            .map_err(|e| {
                EtherReceiverError::AttestationFailed(format!(
                    "failed to persist shielded ETH claim nullifier PDA: {e}"
                ))
            })?;
        commit_ether_nullifiers(store, nullifiers, &statement, slot)?;
        nullifiers.mark_used(claim_nullifier);

        let entry = self
            .accounts
            .entry(args.recipient)
            .or_insert_with(|| MethAccount {
                owner: args.recipient,
                balance_wei: 0,
                deposit_count: 0,
                burn_count: 0,
            });
        entry.balance_wei = new_balance;
        entry.deposit_count += 1;
        self.total_supply_wei = new_supply;

        Ok(new_balance)
    }

    /// Burn synthetic `mETH` on LEZ and emit a privacy-preserving `burnNullifier` for
    /// `MosooLocker.unlockShieldedETH` without leaking `lez_owner`, `burn_nonce`, or `lez_slot` on Ethereum L1.
    pub fn burn_shielded_meth(
        &mut self,
        chain_id: u64,
        source_instance: &[u8; 32],
        owner: &[u8; 32],
        amount_wei: u128,
        burn_secret: &[u8; 32],
    ) -> Result<[u8; 32], EtherReceiverError> {
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
        self.total_supply_wei -= amount_wei;
        self.total_burned_wei = self
            .total_burned_wei
            .checked_add(amount_wei)
            .ok_or(EtherReceiverError::Overflow)?;

        Ok(derive_shielded_burn_nullifier(
            chain_id,
            source_instance,
            &[0u8; 20],
            &U256::from(amount_wei).to_be_bytes::<32>(),
            burn_secret,
        ))
    }

    /// Convenience alias for `mint_deposit_authenticated_store_u256`.
    pub fn mint_deposit_authenticated_store<S: mosoo_core::types::AccountStore>(
        &mut self,
        store: &mut S,
        instance_pda: &[u8; 32],
        header_pda: Option<&[u8; 32]>,
        args: AtomicEtherClaimArgs,
        nullifiers: &mut EtherNullifierSet,
    ) -> Result<u128, EtherReceiverError> {
        self.mint_deposit_authenticated_store_u256(
            store,
            instance_pda,
            header_pda,
            args,
            nullifiers,
        )
    }

    /// Mint synthetic `mETH` via atomic same-transaction verification.
    /// Strictly validates escrow deposit backing from MosooLocker, converts U256 to u128 with
    /// checked arithmetic, and verifies balance additions BEFORE consuming nullifiers.
    #[cfg(any(test, feature = "test-harness"))]
    #[deprecated(
        note = "In-memory test harness entrypoint. Production LEZ contract calls MUST use mint_deposit_authenticated_store_u256 or mint_deposit_authenticated_pda_u256."
    )]
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
            privacy_salt: None,
            trusted_head_slot: None,
            privacy_mode: None,
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

        if statement_account.statement.source_instance_pda == [0u8; 32] {
            return Err(EtherReceiverError::UnauthenticatedSourceInstance);
        }
        let pinned_pda = self
            .config
            .get_trusted_instance(statement_account.statement.chain_id)
            .ok_or(EtherReceiverError::UntrustedSourceInstance)?;
        if statement_account.statement.source_instance_pda != pinned_pda {
            return Err(EtherReceiverError::UntrustedSourceInstance);
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

        claim_ether_u256_internal(&statement_account.statement, nullifiers, U256::ZERO)?;

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
mod tests;
