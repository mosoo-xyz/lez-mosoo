//! ERC-20 receiver â€” reference consumer for the Mosoo attestation module.
//!
//! This LEZ program shows how a dApp consumes a `VerifiedStatement` produced
//! by the `mosoo` attestation module to trustlessly mint LEZ tokens in exchange
//! for an on-chain Ethereum ERC-20 transfer, with no bridge or oracle.
//!
//! ## How it works
//!
//! 1. User transfers ERC-20 tokens on Ethereum mainnet to a designated vault.
//! 2. User (or relayer) calls `mosoo::attest_state` with an `eth_getProof`
//!    for the storage slot that records the transfer.
//! 3. Mosoo returns a `VerifiedStatement` with `predicate_holds = true`.
//! 4. User calls `erc20_receiver::claim` with the `VerifiedStatement`.
//! 5. This program checks the statement, stores the nullifier, and mints tokens.
//!
//! ## Replay protection
//!
//! `VerifiedStatement.statement_id` is a deterministic hash of the Ethereum
//! state that was verified.  The contract stores it as a nullifier â€” the same
//! statement cannot be claimed twice.

use alloy_primitives::{keccak256, U256};
pub use mosoo_core::predicate::{
    derive_erc20_deposit_subject_key, derive_erc20_transfer_subject_key,
};
pub use mosoo_core::types::derive_statement_pda;
pub use mosoo_core::types::{
    derive_claim_nullifier, derive_shielded_burn_nullifier, derive_shielded_commitment,
    derive_shielded_deposit_secrets, get_canonical_trusted_locker, is_supported_chain_id,
    AccountStore, RuntimeAccount, StatementAccount, StatementBinding, TrustedBridgeConfig,
    VerifiedStatement, ETH_HOLESKY_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
    MOSOO_PROGRAM_ID, PROOF_TYPE_ERC20_DEPOSIT, PROOF_TYPE_ERC20_TRANSFER,
    PROOF_TYPE_SHIELDED_DEPOSIT,
};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::HashMap;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReceiverError {
    #[error("predicate did not hold — the Ethereum transfer was not verified")]
    PredicateFailed,

    #[error("unauthenticated attester: statement was not signed by authentic Mosoo program ID")]
    UnauthenticatedAttester,

    #[error("this statement has already been claimed (replay attempt)")]
    AlreadyClaimed,

    #[error("statement is for chain {0}, but this receiver only accepts mainnet (chain 1)")]
    WrongChain(u64),

    #[error("expected at least {min_amount} tokens, verified statement value is {actual}")]
    AmountTooLow { min_amount: u128, actual: u128 },

    #[error("expected at least {min_amount} tokens (U256), verified statement value is {actual}")]
    AmountTooLowU256 { min_amount: U256, actual: U256 },

    #[error("invalid statement type: expected ERC-20 transfer or deposit proof, got tag {0}")]
    InvalidStatementType(u8),

    #[error("token contract mismatch: expected {expected:?}, got {actual:?}")]
    TokenContractMismatch {
        expected: [u8; 20],
        actual: [u8; 20],
    },

    #[error("deposit contract mismatch: expected {expected:?}, got {actual:?}")]
    DepositContractMismatch {
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

    #[error(
        "statement ID mismatch: supplied statement_id does not match canonical state derivation"
    )]
    StatementIdMismatch,

    #[error("state attestation failed: {0}")]
    AttestationFailed(String),

    #[error("insufficient token balance: available {available}, requested {requested}")]
    InsufficientBalance { available: u128, requested: u128 },

    #[error("account not found: {owner:?} for token {token:?}")]
    AccountNotFound { token: [u8; 20], owner: [u8; 32] },

    #[error("deposit backing required: deposit minting strictly requires authentic escrow deposit proof (DepositERC20)")]
    DepositBackingRequired,

    #[error("token contract {0:?} is not permitted on chain {1} by the authenticated bridge token allowlist")]
    TokenNotAllowed([u8; 20], u64),

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

    #[error("arithmetic overflow in token operation")]
    Overflow,
}

/// Claim parameters for an RFP-022 unlinkable shielded ERC-20 deposit claim (`DepositCommitted`).
#[derive(Debug, Clone)]
pub struct ShieldedErc20ClaimArgs {
    pub header: mosoo_core::types::HeaderRecord,
    pub header_history_branch: Option<Vec<[u8; 32]>>,
    pub historical_execution_proof: Option<mosoo_core::types::HistoricalHeaderProof>,
    pub proof: mosoo_core::inclusion::StateProof,
    pub predicate: mosoo_core::types::Predicate,
    pub expected_deposit_contract: [u8; 20],
    pub expected_token_contract: [u8; 20],
    /// Fresh LEZ recipient specified strictly at claim time (never revealed on Ethereum L1).
    pub recipient: [u8; 32],
    /// User secret commitment preimage.
    pub secret: [u8; 32],
    /// User nullifier preimage (hashed on claim to prevent double-spend).
    pub nullifier_secret: [u8; 32],
    pub min_amount: U256,
}

/// A persistent Program-Derived Account (PDA) nullifier record on Logos Execution Zone.
/// Seed derivation: `[b"nullifier", statement_id]`
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NullifierAccount {
    /// Deterministic statement ID marked as spent.
    pub statement_id: [u8; 32],
    /// Associated canonical subject key.
    pub subject_key: [u8; 32],
    /// Timestamp or slot when this nullifier account was initialized/spent.
    pub spent_slot: u64,
    /// Whether this nullifier account is spent.
    pub is_spent: bool,
}

/// Derives the unique PDA address for a statement nullifier account on LEZ.
pub fn derive_nullifier_pda(program_id: &[u8; 32], statement_id: &[u8; 32]) -> [u8; 32] {
    let mut h = sha2::Sha256::new();
    h.update(program_id);
    h.update(b"nullifier");
    h.update(statement_id);
    h.finalize().into()
}

/// Persistent nullifier store mapping verified statement IDs to spent state on LEZ.
/// On LEZ runtime, each nullifier maps to a distinct PDA account per statement_id.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct NullifierSet {
    used: HashMap<[u8; 32], bool>,
}

impl NullifierSet {
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
    pub fn export_pda_records(&self, current_slot: u64) -> Vec<NullifierAccount> {
        self.used
            .keys()
            .map(|id| NullifierAccount {
                statement_id: *id,
                subject_key: *id,
                spent_slot: current_slot,
                is_spent: true,
            })
            .collect()
    }

    /// Restore in-memory nullifier state from persistent PDA account representations across restarts.
    pub fn restore_pda_records(&mut self, records: &[NullifierAccount]) {
        for rec in records {
            if rec.is_spent {
                self.used.insert(rec.statement_id, true);
                self.used.insert(rec.subject_key, true);
            }
        }
    }
}

/// Verify a VerifiedStatement from Mosoo and mint LEZ-side tokens.
///
/// Ensures:
/// 1. Attester origin authentication (`statement.attester_program_id == MOSOO_PROGRAM_ID`).
/// 2. Settlement binding: minted tokens derive strictly from `statement.value_as_u64()` (cannot claim arbitrary amounts).
/// 3. Replay prevention: atomic marking in `NullifierSet`.
///
/// # Examples
///
/// ```
/// # #[allow(deprecated)]
/// use erc20_receiver::{claim, NullifierSet, derive_erc20_transfer_subject_key};
/// use mosoo_core::types::{VerifiedStatement, StatementBinding, ETH_MAINNET_CHAIN_ID, MOSOO_PROGRAM_ID, PROOF_TYPE_ERC20_TRANSFER};
/// use mosoo_core::predicate::derive_statement_id_from_raw;
///
/// let mut nullifiers = NullifierSet::new();
/// let mut verified_value = [0u8; 32];
/// verified_value[24..32].copy_from_slice(&100u64.to_be_bytes());
///
/// let token_contract = [0xaa; 20];
/// let sender = [0x11; 20];
/// let recipient = [0x22; 32];
/// let block_hash = [0x33; 32];
/// let slot = 10_000_000u64;
/// let tx_index = 0u64;
/// let log_index = 0usize;
///
/// let subject_key = derive_erc20_transfer_subject_key(
///     &block_hash, slot, tx_index, log_index, &token_contract, &sender, &recipient,
/// );
/// let statement_id = derive_statement_id_from_raw(
///     ETH_MAINNET_CHAIN_ID,
///     &subject_key,
///     PROOF_TYPE_ERC20_TRANSFER,
///     &verified_value,
/// );
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
///     proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
///     binding: StatementBinding::Erc20Transfer {
///         execution_block_hash: block_hash,
///         slot,
///         tx_index,
///         log_index,
///         token_contract,
///         sender,
///         recipient,
///     },
/// };
///
/// #[allow(deprecated)]
/// let minted = claim(&statement, &mut nullifiers, 100).expect("first claim succeeds");
/// assert_eq!(minted, 100);
/// ```
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(
    note = "Use `claim_atomic_u256` for in-guest atomic execution or `claim_authenticated_pda_u256` for on-chain PDA account provenance with full U256 precision"
)]
pub fn claim(
    statement: &VerifiedStatement,
    nullifiers: &mut NullifierSet,
    min_amount: u64,
) -> Result<u64, ReceiverError> {
    if statement.chain_id != ETH_MAINNET_CHAIN_ID {
        return Err(ReceiverError::WrongChain(statement.chain_id));
    }

    // Authenticate the attester program identity
    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }

    if !statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }

    if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER
        && statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT
    {
        return Err(ReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    // Strict statement binding validation: token, recipient, sender
    let expected_subject_key = match &statement.binding {
        StatementBinding::Erc20Transfer {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *token_contract == [0u8; 20] || *recipient == [0u8; 32] {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_transfer_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                token_contract,
                sender,
                recipient,
            )
        }
        StatementBinding::Erc20Deposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *deposit_contract == [0u8; 20]
                || *token_contract == [0u8; 20]
                || *recipient == [0u8; 32]
            {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_deposit_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            )
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ))
        }
    };

    // Canonical subject key cryptographic verification
    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(ReceiverError::SubjectKeyMismatch);
    }

    // Canonical statement ID cryptographic verification (recomputed from canonical state facts)
    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(ReceiverError::StatementIdMismatch);
    }

    // Derive credited amount strictly from the verified statement value (with overflow check)
    let verified_amount = statement
        .value_as_u64_checked()
        .map_err(|e| ReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_amount < min_amount {
        return Err(ReceiverError::AmountTooLow {
            min_amount: min_amount as u128,
            actual: verified_amount as u128,
        });
    }

    if nullifiers.is_used(&statement.statement_id) || nullifiers.is_used(&statement.subject_key) {
        return Err(ReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    nullifiers.mark_used(statement.subject_key);

    // Tokens credited 1:1 on LEZ matching the verified on-chain Ethereum value
    let minted_amount = verified_amount;
    Ok(minted_amount)
}

/// Claim tokens from an authentic on-chain Statement Account committed by `MOSOO_PROGRAM_ID`.
///
/// Cryptographically verifies on-chain provenance:
/// 1. Account owner is strictly `MOSOO_PROGRAM_ID` (enforced on-chain by LEZ VM).
/// 2. PDA address matches `derive_statement_pda(chain_id, statement_id)`.
/// 3. Re-derives canonical statement ID and subject key.
/// 4. Enforces nullifier replay protection with full U256 precision.
pub fn claim_authenticated_pda_u256(
    statement_account: &StatementAccount,
    nullifiers: &mut NullifierSet,
    min_amount: U256,
) -> Result<U256, ReceiverError> {
    if statement_account.owner != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }
    let expected_pda = derive_statement_pda(
        statement_account.statement.chain_id,
        &statement_account.statement.statement_id,
    );
    if statement_account.pda_address != expected_pda {
        return Err(ReceiverError::UnauthenticatedAttester);
    }
    if statement_account.statement.source_instance_pda == [0u8; 32] {
        return Err(ReceiverError::UnauthenticatedSourceInstance);
    }
    let pinned_pda = TrustedBridgeConfig::canonical()
        .get_trusted_instance(statement_account.statement.chain_id)
        .ok_or(ReceiverError::UntrustedSourceInstance)?;
    if statement_account.statement.source_instance_pda != pinned_pda {
        return Err(ReceiverError::UntrustedSourceInstance);
    }
    claim_u256_internal(&statement_account.statement, nullifiers, min_amount)
}

/// Authenticate host runtime account metadata and claim ERC-20 statement with full U256 precision.
/// Asserts host sequencer owner authentication and canonical PDA derivation.
pub fn claim_authenticated_runtime_account_u256(
    runtime_account: &RuntimeAccount,
    nullifiers: &mut NullifierSet,
    min_amount: U256,
) -> Result<U256, ReceiverError> {
    let statement_account = StatementAccount::try_from_runtime_account(runtime_account)
        .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;
    claim_authenticated_pda_u256(&statement_account, nullifiers, min_amount)
}

pub(crate) fn claim_u256_internal(
    statement: &VerifiedStatement,
    nullifiers: &mut NullifierSet,
    min_amount: U256,
) -> Result<U256, ReceiverError> {
    if !is_supported_chain_id(statement.chain_id) {
        return Err(ReceiverError::WrongChain(statement.chain_id));
    }
    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }
    if !statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }

    if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER
        && statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT
    {
        return Err(ReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let expected_subject_key = match &statement.binding {
        StatementBinding::Erc20Transfer {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *token_contract == [0u8; 20] || *recipient == [0u8; 32] {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_transfer_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                token_contract,
                sender,
                recipient,
            )
        }
        StatementBinding::Erc20Deposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *deposit_contract == [0u8; 20]
                || *token_contract == [0u8; 20]
                || *recipient == [0u8; 32]
            {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_deposit_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            )
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ))
        }
    };

    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(ReceiverError::SubjectKeyMismatch);
    }

    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(ReceiverError::StatementIdMismatch);
    }

    let verified_amount = statement.value_as_u256();
    if verified_amount < min_amount {
        return Err(ReceiverError::AmountTooLowU256 {
            min_amount,
            actual: verified_amount,
        });
    }

    if nullifiers.is_used(&statement.statement_id) || nullifiers.is_used(&statement.subject_key) {
        return Err(ReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    nullifiers.mark_used(statement.subject_key);

    Ok(verified_amount)
}

/// Opening witness parameters required to redeem a shielded ERC-20 statement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShieldedErc20ClaimWitness {
    /// The unshielded binding containing the underlying Ethereum transfer or deposit parameters.
    pub unshielded_binding: StatementBinding,
    /// The private 256-bit blinding salt used during statement issuance (if salted).
    pub privacy_salt: Option<[u8; 32]>,
}

/// Verifies and claims a privacy-shielded statement (where `statement.binding` is `StatementBinding::Shielded`),
/// verifying the commitment and blinded identifiers against the claimant's private witness preimage.
pub fn claim_shielded_statement_u256(
    statement: &VerifiedStatement,
    witness: &ShieldedErc20ClaimWitness,
    nullifiers: &mut NullifierSet,
    min_amount: U256,
) -> Result<U256, ReceiverError> {
    if !is_supported_chain_id(statement.chain_id) {
        return Err(ReceiverError::WrongChain(statement.chain_id));
    }
    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }
    if !statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }
    if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER
        && statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT
    {
        return Err(ReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let StatementBinding::Shielded { commitment } = &statement.binding else {
        return Err(ReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    };

    // 1. Verify commitment against unshielded binding witness
    let expected_commitment = match witness.privacy_salt {
        Some(ref salt) => witness.unshielded_binding.compute_salted_commitment(salt),
        None => witness.unshielded_binding.compute_commitment(),
    };
    if *commitment != expected_commitment {
        return Err(ReceiverError::SubjectKeyMismatch);
    }

    // 2. Derive unshielded subject key from the witness binding
    let unblinded_subject_key = match &witness.unshielded_binding {
        StatementBinding::Erc20Transfer {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_transfer_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                token_contract,
                sender,
                recipient,
            )
        }
        StatementBinding::Erc20Deposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_deposit_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            )
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ))
        }
    };

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
        return Err(ReceiverError::SubjectKeyMismatch);
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
        return Err(ReceiverError::StatementIdMismatch);
    }

    let verified_amount = statement.value_as_u256();
    if verified_amount < min_amount {
        return Err(ReceiverError::AmountTooLowU256 {
            min_amount,
            actual: verified_amount,
        });
    }

    if nullifiers.is_used(&statement.statement_id) || nullifiers.is_used(&statement.subject_key) {
        return Err(ReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    nullifiers.mark_used(statement.subject_key);

    Ok(verified_amount)
}

/// Verify a VerifiedStatement with full 256-bit (U256) precision and mint LEZ-side tokens.
///
/// Prevents truncation for amounts > u64::MAX (e.g. standard 18-decimal token transfers).
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(
    note = "Use `claim_atomic_u256` for in-guest atomic execution or `claim_authenticated_pda_u256` for on-chain PDA account provenance"
)]
pub fn claim_u256(
    statement: &VerifiedStatement,
    nullifiers: &mut NullifierSet,
    min_amount: U256,
) -> Result<U256, ReceiverError> {
    claim_u256_internal(statement, nullifiers, min_amount)
}

/// Verify a VerifiedStatement with u128 precision (safe for amounts up to 3.4e38 units).
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(note = "Use `claim_atomic_u256` or `claim_authenticated_pda_u256`")]
pub fn claim_u128(
    statement: &VerifiedStatement,
    nullifiers: &mut NullifierSet,
    min_amount: u128,
) -> Result<u128, ReceiverError> {
    #[allow(deprecated)]
    claim_u256(statement, nullifiers, U256::from(min_amount))?;
    statement
        .value_as_u128_checked()
        .map_err(|e| ReceiverError::AttestationFailed(format!("value overflow u128: {e}")))
}

/// Atomically verifies statement, loads/asserts persistent PDA nullifier account state,
/// writes the spent nullifier PDA record into `store`, and returns the credited amount.
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(note = "Use `claim_atomic_u256` or `claim_authenticated_pda_u256`")]
pub fn claim_with_store<S: AccountStore>(
    statement: &VerifiedStatement,
    store: &mut S,
    min_amount: u64,
    current_slot: u64,
) -> Result<u64, ReceiverError> {
    if !is_supported_chain_id(statement.chain_id) {
        return Err(ReceiverError::WrongChain(statement.chain_id));
    }

    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }

    if !statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }

    if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER
        && statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT
    {
        return Err(ReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let expected_subject_key = match &statement.binding {
        StatementBinding::Erc20Transfer {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *token_contract == [0u8; 20] || *recipient == [0u8; 32] {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_transfer_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                token_contract,
                sender,
                recipient,
            )
        }
        StatementBinding::Erc20Deposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *deposit_contract == [0u8; 20]
                || *token_contract == [0u8; 20]
                || *recipient == [0u8; 32]
            {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_deposit_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            )
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ))
        }
    };

    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(ReceiverError::SubjectKeyMismatch);
    }

    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(ReceiverError::StatementIdMismatch);
    }

    let verified_amount = statement
        .value_as_u64_checked()
        .map_err(|e| ReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_amount < min_amount {
        return Err(ReceiverError::AmountTooLow {
            min_amount: min_amount as u128,
            actual: verified_amount as u128,
        });
    }

    // 1. Check persistent PDA nullifiers in AccountStore
    let statement_nullifier_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_nullifier_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);

    if store.has_account(&statement_nullifier_pda) || store.has_account(&subject_nullifier_pda) {
        return Err(ReceiverError::AlreadyClaimed);
    }

    // 2. Write persistent spent nullifier accounts to AccountStore atomically
    let nullifier_record = NullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: current_slot,
        is_spent: true,
    };
    let encoded_record = serde_json::to_vec(&nullifier_record)
        .map_err(|e| ReceiverError::AttestationFailed(format!("serialization failure: {e}")))?;

    store.set_account(&statement_nullifier_pda, encoded_record.clone());
    store.set_account(&subject_nullifier_pda, encoded_record);

    Ok(verified_amount)
}

/// Atomically verifies statement with full 256-bit (U256) precision against persistent PDA nullifiers in AccountStore.
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(note = "Use `claim_atomic_u256` or `claim_authenticated_pda_u256`")]
pub fn claim_with_store_u256<S: AccountStore>(
    statement: &VerifiedStatement,
    store: &mut S,
    min_amount: U256,
    current_slot: u64,
) -> Result<U256, ReceiverError> {
    if !is_supported_chain_id(statement.chain_id) {
        return Err(ReceiverError::WrongChain(statement.chain_id));
    }

    if statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }

    if !statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }

    if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER
        && statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT
    {
        return Err(ReceiverError::InvalidStatementType(
            statement.proof_type_tag,
        ));
    }

    let expected_subject_key = match &statement.binding {
        StatementBinding::Erc20Transfer {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *token_contract == [0u8; 20] || *recipient == [0u8; 32] {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_transfer_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                token_contract,
                sender,
                recipient,
            )
        }
        StatementBinding::Erc20Deposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        } => {
            if statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            if *deposit_contract == [0u8; 20]
                || *token_contract == [0u8; 20]
                || *recipient == [0u8; 32]
            {
                return Err(ReceiverError::InvalidStatementType(
                    statement.proof_type_tag,
                ));
            }
            derive_erc20_deposit_subject_key(
                execution_block_hash,
                *slot,
                *tx_index,
                *log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            )
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ))
        }
    };

    if statement.subject_key != expected_subject_key || statement.subject_key == [0u8; 32] {
        return Err(ReceiverError::SubjectKeyMismatch);
    }

    let expected_statement_id = statement.derive_canonical_id();
    if statement.statement_id != expected_statement_id {
        return Err(ReceiverError::StatementIdMismatch);
    }

    let verified_amount = statement.value_as_u256();
    if verified_amount < min_amount {
        return Err(ReceiverError::AmountTooLowU256 {
            min_amount,
            actual: verified_amount,
        });
    }

    let statement_nullifier_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_nullifier_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);

    if store.has_account(&statement_nullifier_pda) || store.has_account(&subject_nullifier_pda) {
        return Err(ReceiverError::AlreadyClaimed);
    }

    let nullifier_record = NullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: current_slot,
        is_spent: true,
    };
    let encoded_record = serde_json::to_vec(&nullifier_record)
        .map_err(|e| ReceiverError::AttestationFailed(format!("serialization failure: {e}")))?;

    store.set_account(&statement_nullifier_pda, encoded_record.clone());
    store.set_account(&subject_nullifier_pda, encoded_record);

    Ok(verified_amount)
}

/// Atomically verifies statement with u128 precision against persistent PDA nullifiers in AccountStore.
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(note = "Use `claim_atomic_u256` or `claim_authenticated_pda_u256`")]
pub fn claim_with_store_u128<S: AccountStore>(
    statement: &VerifiedStatement,
    store: &mut S,
    min_amount: u128,
    current_slot: u64,
) -> Result<u128, ReceiverError> {
    #[allow(deprecated)]
    claim_with_store_u256(statement, store, U256::from(min_amount), current_slot)?;
    statement
        .value_as_u128_checked()
        .map_err(|e| ReceiverError::AttestationFailed(format!("value overflow u128: {e}")))
}

/// Detailed parameters for claiming a verified ERC-20 token transfer or vault deposit.
///
/// Proves that
/// a specific `sender` transferred a specific `min_amount` of `token_contract` tokens
/// for the benefit of a `recipient` on LEZ.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20TransferClaim {
    /// The verified statement emitted by the Mosoo attestation module.
    pub statement: VerifiedStatement,
    /// The intended ERC-20 token contract address on Ethereum (e.g., DAI, USDC).
    pub token_contract: [u8; 20],
    /// The Ethereum sender / depositor address.
    pub sender: [u8; 20],
    /// The designated LEZ recipient address.
    pub recipient: [u8; 32],
    /// Minimum tokens expected.
    pub min_amount: u64,
}

/// Process a verified ERC-20 token transfer event, proving token contract,
/// verifying token contract, sender, recipient, and amount parameters.
#[cfg(any(test, feature = "test-harness"))]
pub fn claim_erc20_transfer(
    claim: &Erc20TransferClaim,
    nullifiers: &mut NullifierSet,
) -> Result<u64, ReceiverError> {
    if !is_supported_chain_id(claim.statement.chain_id) {
        return Err(ReceiverError::WrongChain(claim.statement.chain_id));
    }

    // Authenticate the attester program identity
    if claim.statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }

    if !claim.statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }

    // Verify statement proof type tag is ERC-20 transfer
    if claim.statement.proof_type_tag != PROOF_TYPE_ERC20_TRANSFER {
        return Err(ReceiverError::InvalidStatementType(
            claim.statement.proof_type_tag,
        ));
    }

    // Match statement binding against caller's expected parameters
    let (block_hash, slot, tx_index, log_index) = match &claim.statement.binding {
        StatementBinding::Erc20Transfer {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        } => {
            if *token_contract != claim.token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: claim.token_contract,
                    actual: *token_contract,
                });
            }
            if *sender != claim.sender {
                return Err(ReceiverError::SenderMismatch {
                    expected: claim.sender,
                    actual: *sender,
                });
            }
            if *recipient != claim.recipient {
                return Err(ReceiverError::RecipientMismatch {
                    expected: claim.recipient,
                    actual: *recipient,
                });
            }
            (*execution_block_hash, *slot, *tx_index, *log_index)
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                claim.statement.proof_type_tag,
            ));
        }
    };

    // Verify canonical subject key cryptographic derivation
    let expected_subject_key = derive_erc20_transfer_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &claim.token_contract,
        &claim.sender,
        &claim.recipient,
    );
    if claim.statement.subject_key != expected_subject_key {
        return Err(ReceiverError::SubjectKeyMismatch);
    }

    // Canonical statement ID cryptographic verification (recomputed from canonical state facts)
    let expected_statement_id = claim.statement.derive_canonical_id();
    if claim.statement.statement_id != expected_statement_id {
        return Err(ReceiverError::StatementIdMismatch);
    }

    // Derive credited amount strictly from verified statement value (with overflow check)
    let verified_amount = claim
        .statement
        .value_as_u64_checked()
        .map_err(|e| ReceiverError::AttestationFailed(format!("value overflow: {e}")))?;
    if verified_amount < claim.min_amount {
        return Err(ReceiverError::AmountTooLow {
            min_amount: claim.min_amount as u128,
            actual: verified_amount as u128,
        });
    }

    if nullifiers.is_used(&expected_subject_key)
        || nullifiers.is_used(&claim.statement.statement_id)
    {
        return Err(ReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(expected_subject_key);
    nullifiers.mark_used(claim.statement.statement_id);

    Ok(verified_amount)
}

/// Parameters for claiming a verified ERC-20 vault deposit to MosooLocker.sol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Erc20DepositClaim {
    /// The verified statement emitted by the Mosoo attestation module.
    pub statement: VerifiedStatement,
    /// The canonical bridge vault contract address on Ethereum (e.g. MosooLocker).
    pub deposit_contract: [u8; 20],
    /// The deposited ERC-20 token contract address on Ethereum.
    pub token_contract: [u8; 20],
    /// The Ethereum sender / depositor address.
    pub sender: [u8; 20],
    /// The designated LEZ recipient address.
    pub recipient: [u8; 32],
    /// Minimum tokens expected (u128 precision).
    pub min_amount: u128,
}

/// Process a verified ERC-20 deposit event log from MosooLocker.sol:
/// DepositERC20(address indexed token, address indexed sender, bytes32 indexed lezRecipient, uint256 amount, uint64 nonce)
/// Strictly enforces that the deposit was locked in the canonical deployed vault ([`get_canonical_trusted_locker`]).
#[cfg(any(test, feature = "test-harness"))]
pub fn claim_erc20_deposit(
    claim: &Erc20DepositClaim,
    nullifiers: &mut NullifierSet,
) -> Result<u128, ReceiverError> {
    claim_erc20_deposit_with_config(claim, nullifiers, &TrustedBridgeConfig::canonical())
}

/// Process a verified ERC-20 deposit event log from MosooLocker.sol using a specified bridge configuration.
#[cfg(any(test, feature = "test-harness"))]
pub fn claim_erc20_deposit_with_config(
    claim: &Erc20DepositClaim,
    nullifiers: &mut NullifierSet,
    config: &TrustedBridgeConfig,
) -> Result<u128, ReceiverError> {
    if !is_supported_chain_id(claim.statement.chain_id) {
        return Err(ReceiverError::WrongChain(claim.statement.chain_id));
    }
    if claim.deposit_contract == [0u8; 20] {
        return Err(ReceiverError::DepositBackingRequired);
    }
    let trusted_locker = config
        .get_trusted_locker(claim.statement.chain_id)
        .ok_or(ReceiverError::UntrustedLocker(claim.statement.chain_id))?;
    if claim.deposit_contract != trusted_locker {
        return Err(ReceiverError::DepositContractMismatch {
            expected: trusted_locker,
            actual: claim.deposit_contract,
        });
    }
    if !config.is_token_allowed(claim.statement.chain_id, &claim.token_contract) {
        return Err(ReceiverError::TokenNotAllowed(
            claim.token_contract,
            claim.statement.chain_id,
        ));
    }
    if claim.statement.attester_program_id != MOSOO_PROGRAM_ID {
        return Err(ReceiverError::UnauthenticatedAttester);
    }
    if !claim.statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }
    if claim.statement.proof_type_tag != PROOF_TYPE_ERC20_DEPOSIT {
        return Err(ReceiverError::InvalidStatementType(
            claim.statement.proof_type_tag,
        ));
    }

    let (block_hash, slot, tx_index, log_index) = match &claim.statement.binding {
        StatementBinding::Erc20Deposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            token_contract,
            sender,
            recipient,
        } => {
            if *deposit_contract != trusted_locker {
                return Err(ReceiverError::DepositContractMismatch {
                    expected: trusted_locker,
                    actual: *deposit_contract,
                });
            }
            if *token_contract != claim.token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: claim.token_contract,
                    actual: *token_contract,
                });
            }
            if *sender != claim.sender {
                return Err(ReceiverError::SenderMismatch {
                    expected: claim.sender,
                    actual: *sender,
                });
            }
            if *recipient != claim.recipient {
                return Err(ReceiverError::RecipientMismatch {
                    expected: claim.recipient,
                    actual: *recipient,
                });
            }
            (*execution_block_hash, *slot, *tx_index, *log_index)
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                claim.statement.proof_type_tag,
            ));
        }
    };

    let expected_subject_key = derive_erc20_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &claim.deposit_contract,
        &claim.token_contract,
        &claim.sender,
        &claim.recipient,
    );
    if claim.statement.subject_key != expected_subject_key {
        return Err(ReceiverError::SubjectKeyMismatch);
    }

    let expected_statement_id = claim.statement.derive_canonical_id();
    if claim.statement.statement_id != expected_statement_id {
        return Err(ReceiverError::StatementIdMismatch);
    }

    let verified_amount = claim
        .statement
        .value_as_u128_checked()
        .map_err(|e| ReceiverError::AttestationFailed(format!("value overflow u128: {e}")))?;
    if verified_amount < claim.min_amount {
        return Err(ReceiverError::AmountTooLow {
            min_amount: claim.min_amount,
            actual: verified_amount,
        });
    }

    if nullifiers.is_used(&expected_subject_key)
        || nullifiers.is_used(&claim.statement.statement_id)
    {
        return Err(ReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(expected_subject_key);
    nullifiers.mark_used(claim.statement.statement_id);

    Ok(verified_amount)
}

/// Execution parameters for atomic same-transaction ERC-20 claim.
///
/// In compliance with Logos RFP-021 Functionality requirements, state inclusion verification
/// and predicate evaluation execute within the consuming transaction itself against the
/// authenticated light client instance and header record. This ensures caller-supplied
/// statements cannot be fabricated or accepted out-of-band.
#[derive(Debug, Clone)]
pub struct AtomicErc20ClaimArgs {
    /// Active authenticated light client instance account
    pub instance: mosoo_core::types::InstanceAccount,
    /// Authenticated header record for the target block
    pub header: mosoo_core::types::HeaderRecord,
    /// Optional historical branch if proving against past block in weak-subjectivity window
    pub header_history_branch: Option<Vec<[u8; 32]>>,
    /// Complete cryptographic proof binding historical execution roots to beacon state
    pub historical_execution_proof: Option<mosoo_core::types::HistoricalHeaderProof>,
    /// State inclusion proof (receipt log proof or storage proof)
    pub proof: mosoo_core::inclusion::StateProof,
    /// Predicate evaluated against verified state
    pub predicate: mosoo_core::types::Predicate,
    /// Expected ERC-20 token contract address on Ethereum
    pub expected_token_contract: [u8; 20],
    /// Expected sender address on Ethereum (optional for general storage slot claims)
    pub expected_sender: Option<[u8; 20]>,
    /// Expected recipient identifier on LEZ
    pub recipient: [u8; 32],
    /// Minimum required token amount
    pub min_amount: u64,
}

/// Arguments for executing an atomic same-transaction ERC-20 token claim with 256-bit amount representation.
#[derive(Debug, Clone)]
pub struct AtomicErc20ClaimArgsU256 {
    /// Active authenticated light client instance account
    pub instance: mosoo_core::types::InstanceAccount,
    /// Authenticated header record for the target block
    pub header: mosoo_core::types::HeaderRecord,
    /// Optional historical branch if proving against past block in weak-subjectivity window
    pub header_history_branch: Option<Vec<[u8; 32]>>,
    /// Complete cryptographic proof binding historical execution roots to beacon state
    pub historical_execution_proof: Option<mosoo_core::types::HistoricalHeaderProof>,
    /// State inclusion proof (receipt log proof or storage proof)
    pub proof: mosoo_core::inclusion::StateProof,
    /// Predicate evaluated against verified state
    pub predicate: mosoo_core::types::Predicate,
    /// Expected canonical bridge vault / locker contract address on Ethereum (e.g. MosooLocker)
    pub expected_deposit_contract: [u8; 20],
    /// Expected ERC-20 token contract address on Ethereum
    pub expected_token_contract: [u8; 20],
    /// Expected sender address on Ethereum (optional for general storage slot claims)
    pub expected_sender: Option<[u8; 20]>,
    /// Expected recipient identifier on LEZ
    pub recipient: [u8; 32],
    /// Minimum required token amount as U256
    pub min_amount: U256,
}

/// Execute atomic same-transaction ERC-20 token claim with full 256-bit amount preservation.
///
/// NOTE: In-memory test harness entrypoint for offline simulation.
/// Production LEZ contracts MUST invoke `claim_authenticated_store_u256` with persistent `AccountStore` and pinned `TrustedBridgeConfig`.
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(
    note = "In-memory test harness entrypoint. Production LEZ contract calls MUST use claim_authenticated_store_u256 with pinned TrustedBridgeConfig."
)]
pub fn claim_atomic_u256(
    args: AtomicErc20ClaimArgsU256,
    nullifiers: &mut NullifierSet,
) -> Result<U256, ReceiverError> {
    if !is_supported_chain_id(args.instance.chain_id) {
        return Err(ReceiverError::WrongChain(args.instance.chain_id));
    }

    // Provenance & Authenticity verification on instance account
    if let Err(why) = args.instance.validate_authenticity() {
        return Err(ReceiverError::AttestationFailed(format!(
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
        .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;

    let statement = match output {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => {
            return Err(ReceiverError::AttestationFailed(
                "unexpected instruction output from handle_attest_state".into(),
            ))
        }
    };

    if !statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }

    match &statement.binding {
        StatementBinding::Storage { contract, .. } => {
            if *contract != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *contract,
                });
            }
        }
        StatementBinding::ReceiptLog { emitter, .. } => {
            if *emitter != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *emitter,
                });
            }
        }
        StatementBinding::Erc20Transfer {
            token_contract,
            sender,
            recipient,
            ..
        } => {
            if *token_contract != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *token_contract,
                });
            }
            if let Some(expected_sender) = args.expected_sender {
                if *sender != expected_sender {
                    return Err(ReceiverError::SenderMismatch {
                        expected: expected_sender,
                        actual: *sender,
                    });
                }
            }
            if *recipient != args.recipient {
                return Err(ReceiverError::RecipientMismatch {
                    expected: args.recipient,
                    actual: *recipient,
                });
            }
        }
        StatementBinding::Erc20Deposit {
            deposit_contract,
            token_contract,
            sender,
            recipient,
            ..
        } => {
            if args.expected_deposit_contract == [0u8; 20] {
                return Err(ReceiverError::DepositBackingRequired);
            }
            if *deposit_contract != args.expected_deposit_contract {
                return Err(ReceiverError::DepositContractMismatch {
                    expected: args.expected_deposit_contract,
                    actual: *deposit_contract,
                });
            }
            if *token_contract != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *token_contract,
                });
            }
            if let Some(expected_sender) = args.expected_sender {
                if *sender != expected_sender {
                    return Err(ReceiverError::SenderMismatch {
                        expected: expected_sender,
                        actual: *sender,
                    });
                }
            }
            if *recipient != args.recipient {
                return Err(ReceiverError::RecipientMismatch {
                    expected: args.recipient,
                    actual: *recipient,
                });
            }
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ));
        }
    }

    let verified_amount = statement.value_as_u256();
    if verified_amount < args.min_amount {
        return Err(ReceiverError::AmountTooLow {
            min_amount: args.min_amount.to::<u128>(),
            actual: verified_amount.to::<u128>(),
        });
    }

    if nullifiers.is_used(&statement.statement_id)
        || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
    {
        return Err(ReceiverError::AlreadyClaimed);
    }
    nullifiers.mark_used(statement.statement_id);
    if statement.subject_key != [0u8; 32] {
        nullifiers.mark_used(statement.subject_key);
    }

    Ok(verified_amount)
}

/// Execute atomic same-transaction ERC-20 token claim.
///
/// Directly invokes `mosoo_core::verifier::handle_attest_state` in-guest, verifies the MPT inclusion
/// proof against the authenticated `HeaderRecord`, evaluates the predicate, asserts target contract
/// identity, derives the deterministic statement nullifier, checks for replay, and credits tokens.
#[cfg(any(test, feature = "test-harness"))]
#[deprecated(
    note = "In-memory test harness entrypoint. Production LEZ contract calls MUST use claim_authenticated_store_u256 with pinned TrustedBridgeConfig."
)]
#[allow(deprecated)]
pub fn claim_atomic(
    args: AtomicErc20ClaimArgs,
    nullifiers: &mut NullifierSet,
) -> Result<u64, ReceiverError> {
    let expected_deposit_contract =
        get_canonical_trusted_locker(args.instance.chain_id).unwrap_or([0u8; 20]);
    let u256_args = AtomicErc20ClaimArgsU256 {
        instance: args.instance,
        header: args.header,
        header_history_branch: args.header_history_branch,
        historical_execution_proof: args.historical_execution_proof,
        proof: args.proof,
        predicate: args.predicate,
        expected_deposit_contract,
        expected_token_contract: args.expected_token_contract,
        expected_sender: args.expected_sender,
        recipient: args.recipient,
        min_amount: U256::from(args.min_amount),
    };
    let val_u256 = claim_atomic_u256(u256_args, nullifiers)?;
    let val_u64: u64 = val_u256.try_into().map_err(|_| {
        ReceiverError::AttestationFailed(
            "verified value exceeds u64 bounds; use claim_atomic_u256".into(),
        )
    })?;
    Ok(val_u64)
}

/// Strictly verifies an atomic ERC-20 claim against an authenticated InstanceAccount in persistent storage.
/// Returns the verified statement and current slot WITHOUT consuming nullifiers.
pub fn verify_authenticated_store_erc20_claim_details<S: mosoo_core::types::AccountStore>(
    store: &S,
    instance_pda: &[u8; 32],
    header_pda: Option<&[u8; 32]>,
    args: AtomicErc20ClaimArgsU256,
    nullifiers: &NullifierSet,
    config: &TrustedBridgeConfig,
) -> Result<(VerifiedStatement, u64), ReceiverError> {
    // 1. Load program-owned TrustedBridgeConfig from persistent storage.
    let loaded_config = TrustedBridgeConfig::load_strict(store).map_err(|e| {
        ReceiverError::AttestationFailed(format!("program-owned config verification failed: {e}"))
    })?;

    if config != &loaded_config {
        return Err(ReceiverError::AttestationFailed(
            "caller-supplied configuration does not match persistent program-owned configuration"
                .into(),
        ));
    }

    // 2. Load InstanceAccount from program-owned storage.
    let authentic_instance =
        mosoo_core::verifier::verify_instance_account_authenticity(store, instance_pda)
            .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;

    // 3. Guard: Light-client instance must be pinned in program-owned TrustedBridgeConfig
    if !loaded_config.is_trusted_instance(authentic_instance.chain_id, instance_pda) {
        return Err(ReceiverError::UntrustedInstanceAccount(*instance_pda));
    }

    // 4. Guard: Verify authentic stored instance's bootstrap root matches pinned trusted checkpoint
    let expected_checkpoint = loaded_config
        .get_trusted_checkpoint(authentic_instance.chain_id)
        .ok_or_else(|| {
            ReceiverError::AttestationFailed(
                "trusted checkpoint root absent from stored configuration for target chain".into(),
            )
        })?;

    if authentic_instance.bootstrap_header_hash != expected_checkpoint {
        return Err(ReceiverError::AttestationFailed(
            "authenticated instance bootstrap root does not match pinned trusted checkpoint".into(),
        ));
    }

    let chain_id = authentic_instance.chain_id;
    let current_slot = authentic_instance.current_slot;
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
    .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;

    let statement = match output {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => {
            return Err(ReceiverError::AttestationFailed(
                "unexpected instruction output from handle_attest_state".into(),
            ))
        }
    };

    if !statement.predicate_holds {
        return Err(ReceiverError::PredicateFailed);
    }

    match &statement.binding {
        StatementBinding::Storage { contract, .. } => {
            if *contract != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *contract,
                });
            }
        }
        StatementBinding::ReceiptLog { emitter, .. } => {
            if *emitter != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *emitter,
                });
            }
        }
        StatementBinding::Erc20Transfer {
            token_contract,
            sender,
            recipient,
            ..
        } => {
            if *token_contract != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *token_contract,
                });
            }
            if let Some(expected_sender) = args.expected_sender {
                if *sender != expected_sender {
                    return Err(ReceiverError::SenderMismatch {
                        expected: expected_sender,
                        actual: *sender,
                    });
                }
            }
            if *recipient != args.recipient {
                return Err(ReceiverError::RecipientMismatch {
                    expected: args.recipient,
                    actual: *recipient,
                });
            }
        }
        StatementBinding::Erc20Deposit {
            deposit_contract,
            token_contract,
            sender,
            recipient,
            ..
        } => {
            let trusted_locker = loaded_config
                .get_trusted_locker(chain_id)
                .ok_or(ReceiverError::UntrustedLocker(chain_id))?;
            if args.expected_deposit_contract == [0u8; 20] {
                return Err(ReceiverError::DepositBackingRequired);
            }
            if *deposit_contract != trusted_locker
                || args.expected_deposit_contract != trusted_locker
            {
                return Err(ReceiverError::DepositContractMismatch {
                    expected: trusted_locker,
                    actual: *deposit_contract,
                });
            }
            if !loaded_config.is_token_allowed(chain_id, token_contract) {
                return Err(ReceiverError::TokenNotAllowed(*token_contract, chain_id));
            }
            if *token_contract != args.expected_token_contract {
                return Err(ReceiverError::TokenContractMismatch {
                    expected: args.expected_token_contract,
                    actual: *token_contract,
                });
            }
            if let Some(expected_sender) = args.expected_sender {
                if *sender != expected_sender {
                    return Err(ReceiverError::SenderMismatch {
                        expected: expected_sender,
                        actual: *sender,
                    });
                }
            }
            if *recipient != args.recipient {
                return Err(ReceiverError::RecipientMismatch {
                    expected: args.recipient,
                    actual: *recipient,
                });
            }
        }
        _ => {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ));
        }
    }

    let verified_val = statement.value_as_u256();

    if verified_val < args.min_amount {
        return Err(ReceiverError::AmountTooLow {
            min_amount: args.min_amount.to::<u128>(),
            actual: verified_val.to::<u128>(),
        });
    }

    let nullifier_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_pda = if statement.subject_key != [0u8; 32] {
        Some(derive_nullifier_pda(
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
        return Err(ReceiverError::AlreadyClaimed);
    }

    Ok((statement, current_slot))
}

/// Atomically persists nullifier records to persistent storage and marks them in memory.
pub fn commit_erc20_nullifiers<S: mosoo_core::types::AccountStore>(
    store: &mut S,
    nullifiers: &mut NullifierSet,
    statement: &VerifiedStatement,
    current_slot: u64,
) -> Result<(), ReceiverError> {
    let nullifier_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
    let subject_pda = if statement.subject_key != [0u8; 32] {
        Some(derive_nullifier_pda(
            &MOSOO_PROGRAM_ID,
            &statement.subject_key,
        ))
    } else {
        None
    };

    let nullifier_rec = NullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: current_slot,
        is_spent: true,
    };
    let encoded = serde_json::to_vec(&nullifier_rec).map_err(|e| {
        ReceiverError::AttestationFailed(format!("failed to serialize nullifier PDA: {e}"))
    })?;
    let mut batch = vec![(nullifier_pda, encoded.clone(), MOSOO_PROGRAM_ID)];
    if let Some(sub_pda) = subject_pda {
        batch.push((sub_pda, encoded, MOSOO_PROGRAM_ID));
    }
    store
        .try_set_accounts_batch_with_owner(&batch)
        .map_err(|e| {
            ReceiverError::AttestationFailed(format!(
                "failed to atomically store nullifier PDA batch: {e}"
            ))
        })?;

    nullifiers.mark_used(statement.statement_id);
    if statement.subject_key != [0u8; 32] {
        nullifiers.mark_used(statement.subject_key);
    }

    Ok(())
}

/// Execute atomic same-transaction ERC-20 token claim backed by an authenticated InstanceAccount
/// loaded directly from the persistent LEZ AccountStore and verified against pinned TrustedBridgeConfig.
pub fn claim_authenticated_store_u256<S: mosoo_core::types::AccountStore>(
    store: &mut S,
    instance_pda: &[u8; 32],
    header_pda: Option<&[u8; 32]>,
    args: AtomicErc20ClaimArgsU256,
    nullifiers: &mut NullifierSet,
    config: &TrustedBridgeConfig,
) -> Result<U256, ReceiverError> {
    let (statement, current_slot) = verify_authenticated_store_erc20_claim_details(
        store,
        instance_pda,
        header_pda,
        args,
        nullifiers,
        config,
    )?;
    let verified_val = statement.value_as_u256();
    commit_erc20_nullifiers(store, nullifiers, &statement, current_slot)?;
    Ok(verified_val)
}

/// Derives the canonical 32-byte burn identifier matching `MosooLocker.sol:unlockERC20`:
/// `keccak256(abi.encodePacked("mosoo_burn_erc20_v1", block.chainid, token, lezOwner, recipient, amount, burnNonce, lezSlot))`
pub fn derive_burn_erc20_id(
    chain_id: u64,
    token: &[u8; 20],
    lez_owner: &[u8; 32],
    eth_recipient: &[u8; 20],
    amount: u128,
    burn_nonce: u64,
    lez_slot: u64,
) -> [u8; 32] {
    let mut packed = Vec::with_capacity(171);
    packed.extend_from_slice(b"mosoo_burn_erc20_v1"); // 19 bytes
    packed.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>()); // 32 bytes
    packed.extend_from_slice(token); // 20 bytes
    packed.extend_from_slice(lez_owner); // 32 bytes
    packed.extend_from_slice(eth_recipient); // 20 bytes
    packed.extend_from_slice(&U256::from(amount).to_be_bytes::<32>()); // 32 bytes
    packed.extend_from_slice(&burn_nonce.to_be_bytes()); // 8 bytes
    packed.extend_from_slice(&lez_slot.to_be_bytes()); // 8 bytes
    keccak256(&packed).0
}

/// Derives the canonical 32-byte ERC-20 burn identifier matching `MosooLocker.sol` V2 with cross-instance domain separation:
/// `keccak256(abi.encodePacked("mosoo_burn_erc20_v2", block.chainid, sourceInstance, token, lezOwner, recipient, amount, burnNonce, lezSlot))`
#[allow(clippy::too_many_arguments)]
pub fn derive_burn_erc20_id_v2(
    chain_id: u64,
    source_instance: &[u8; 32],
    token: &[u8; 20],
    lez_owner: &[u8; 32],
    eth_recipient: &[u8; 20],
    amount: u128,
    burn_nonce: u64,
    lez_slot: u64,
) -> [u8; 32] {
    let mut packed = Vec::with_capacity(197);
    packed.extend_from_slice(b"mosoo_burn_erc20_v2");
    packed.extend_from_slice(&U256::from(chain_id).to_be_bytes::<32>());
    packed.extend_from_slice(source_instance);
    packed.extend_from_slice(token);
    packed.extend_from_slice(lez_owner);
    packed.extend_from_slice(eth_recipient);
    packed.extend_from_slice(&U256::from(amount).to_be_bytes::<32>());
    packed.extend_from_slice(&burn_nonce.to_be_bytes());
    packed.extend_from_slice(&lez_slot.to_be_bytes());
    keccak256(&packed).0
}

/// An on-chain account holding synthetic ERC-20 token balances on Logos Execution Zone.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Erc20Account {
    /// Token contract address on Ethereum
    pub token: [u8; 20],
    /// Owner address on LEZ (32-byte account ID / PDA)
    pub owner: [u8; 32],
    /// Active token balance
    pub balance: u128,
    /// Number of successful deposits / mints credited
    pub deposit_count: u64,
    /// Number of burns executed
    pub burn_count: u64,
}

/// An immutable, cryptographically verifiable Burn Receipt generated on LEZ for ERC-20 tokens.
/// This receipt is presented to Ethereum `MosooLocker.sol:unlockERC20` to release locked tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Erc20BurnReceipt {
    /// Canonical burn identifier: keccak256("mosoo_burn_erc20_v1" || chain_id || token || lez_owner || eth_recipient || amount || burn_nonce || slot)
    pub burn_id: [u8; 32],
    /// Target Ethereum chain ID (1 for Mainnet, 11155111 for Sepolia)
    pub chain_id: u64,
    /// Ethereum token contract address
    pub token: [u8; 20],
    /// LEZ account that initiated the burn
    pub lez_owner: [u8; 32],
    /// Destination Ethereum recipient address
    pub eth_recipient: [u8; 20],
    /// Amount of tokens burned
    pub amount: u128,
    /// Sequential burn nonce of this user for this token
    pub burn_nonce: u64,
    /// LEZ block / slot height at which the burn was finalized
    pub lez_slot: u64,
}

/// The multi-token state ledger for synthetic ERC-20 tokens on LEZ.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Erc20Ledger {
    accounts: HashMap<([u8; 20], [u8; 32]), Erc20Account>,
    total_supplies: HashMap<[u8; 20], u128>,
    total_burned: HashMap<[u8; 20], u128>,
    burn_receipts: HashMap<[u8; 32], Erc20BurnReceipt>,
    /// Authenticated program-owned bridge configuration (trusted lockers & token allowlist per chain)
    pub config: TrustedBridgeConfig,
}

impl Default for Erc20Ledger {
    fn default() -> Self {
        Self {
            accounts: HashMap::new(),
            total_supplies: HashMap::new(),
            total_burned: HashMap::new(),
            burn_receipts: HashMap::new(),
            config: TrustedBridgeConfig::canonical(),
        }
    }
}

impl Erc20Ledger {
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

    /// Whitelists an ERC-20 token contract for bridging on a given chain ID.
    pub fn allow_token(&mut self, chain_id: u64, token: [u8; 20]) -> bool {
        self.config.allow_token(chain_id, token)
    }

    /// Checks if a token is permitted on a given chain ID.
    pub fn is_token_allowed(&self, chain_id: u64, token: &[u8; 20]) -> bool {
        self.config.is_token_allowed(chain_id, token)
    }

    pub fn get_balance(&self, token: &[u8; 20], owner: &[u8; 32]) -> u128 {
        self.accounts
            .get(&(*token, *owner))
            .map_or(0, |a| a.balance)
    }

    pub fn get_total_supply(&self, token: &[u8; 20]) -> u128 {
        self.total_supplies.get(token).copied().unwrap_or(0)
    }

    pub fn get_total_burned(&self, token: &[u8; 20]) -> u128 {
        self.total_burned.get(token).copied().unwrap_or(0)
    }

    /// Mint synthetic tokens upon verification of an ERC-20 deposit to `MosooLocker.sol`.
    ///
    /// # Security Warning
    /// This is a legacy helper that processes an in-memory `VerifiedStatement`. In-memory statements
    /// can be fabricated by callers if exposed as an unauthenticated entrypoint.
    /// For production LEZ bridging, always invoke [`Erc20Ledger::mint_deposit_atomic_u256`] (atomic in-guest verification)
    /// or [`Erc20Ledger::mint_deposit_authenticated_pda_u256`] (on-chain StatementAccount PDA verification).
    #[cfg(any(test, feature = "test-harness"))]
    #[deprecated(
        note = "Legacy test helper: In-memory VerifiedStatement can be forged. Use `mint_deposit_atomic_u256` or `mint_deposit_authenticated_pda_u256` in production"
    )]
    pub fn mint_tokens(
        &mut self,
        claim: &Erc20TransferClaim,
        nullifiers: &mut NullifierSet,
    ) -> Result<u128, ReceiverError> {
        let verified_amount = claim_erc20_transfer(claim, nullifiers)?;
        let amount = verified_amount as u128;

        let key = (claim.token_contract, claim.recipient);
        let entry = self.accounts.entry(key).or_insert_with(|| Erc20Account {
            token: claim.token_contract,
            owner: claim.recipient,
            balance: 0,
            deposit_count: 0,
            burn_count: 0,
        });

        entry.balance = entry
            .balance
            .checked_add(amount)
            .ok_or(ReceiverError::Overflow)?;
        entry.deposit_count += 1;

        let supply = self.total_supplies.entry(claim.token_contract).or_insert(0);
        *supply = supply.checked_add(amount).ok_or(ReceiverError::Overflow)?;

        Ok(entry.balance)
    }

    /// Mint synthetic tokens backed by an authentic on-chain light client instance in persistent `AccountStore`.
    /// Strictly loads authentic InstanceAccount and TrustedBridgeConfig from storage,
    /// verifies instance pinning and vault contracts, performs atomic in-guest verification,
    /// and ensures balance additions precede nullifier consumption.
    pub fn mint_deposit_authenticated_store_u256<S: mosoo_core::types::AccountStore>(
        &mut self,
        store: &mut S,
        instance_pda: &[u8; 32],
        header_pda: Option<&[u8; 32]>,
        args: AtomicErc20ClaimArgsU256,
        nullifiers: &mut NullifierSet,
    ) -> Result<U256, ReceiverError> {
        let (statement, current_slot) = verify_authenticated_store_erc20_claim_details(
            store,
            instance_pda,
            header_pda,
            args.clone(),
            nullifiers,
            &self.config,
        )?;

        let verified_amount = statement.value_as_u256();

        // Arithmetic Pre-Check: conversion, balance addition, and supply addition must succeed BEFORE consuming nullifiers!
        let amount_u128: u128 = verified_amount
            .try_into()
            .map_err(|_| ReceiverError::Overflow)?;

        let token = args.expected_token_contract;
        let recipient = args.recipient;
        let current_balance = self.get_balance(&token, &recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;

        let current_supply = self.get_total_supply(&token);
        let new_supply = current_supply
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;

        // All arithmetic checks passed without overflow: now consume nullifiers atomically.
        commit_erc20_nullifiers(store, nullifiers, &statement, current_slot)?;

        let key = (token, recipient);
        let entry = self.accounts.entry(key).or_insert_with(|| Erc20Account {
            token,
            owner: recipient,
            balance: 0,
            deposit_count: 0,
            burn_count: 0,
        });

        entry.balance = new_balance;
        entry.deposit_count += 1;
        self.total_supplies.insert(token, new_supply);

        Ok(verified_amount)
    }

    /// Execute an unlinkable RFP-022 shielded ERC-20 claim backed by an authenticated `InstanceAccount`
    /// and a verified `DepositCommitted` receipt log from `MosooLocker.depositShieldedERC20`.
    ///
    /// Neither Ethereum depositor address nor LEZ `recipient` ever appears on Ethereum L1.
    /// Replay protection consumes the commitment-derived `claim_nullifier`, `statement_id`,
    /// and `subject_key` atomically in the persistent `AccountStore`.
    pub fn claim_shielded_deposit_authenticated_store<S: mosoo_core::types::AccountStore>(
        &mut self,
        store: &mut S,
        instance_pda: &[u8; 32],
        header_pda: Option<&[u8; 32]>,
        args: ShieldedErc20ClaimArgs,
        nullifiers: &mut NullifierSet,
    ) -> Result<U256, ReceiverError> {
        let loaded_config = TrustedBridgeConfig::load_strict(store).map_err(|e| {
            ReceiverError::AttestationFailed(format!(
                "program-owned config verification failed: {e}"
            ))
        })?;
        if self.config != loaded_config {
            return Err(ReceiverError::AttestationFailed(
                "caller-supplied configuration does not match persistent program-owned configuration".into(),
            ));
        }

        let authentic_instance =
            mosoo_core::verifier::verify_instance_account_authenticity(store, instance_pda)
                .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;

        if !loaded_config.is_trusted_instance(authentic_instance.chain_id, instance_pda) {
            return Err(ReceiverError::UntrustedInstanceAccount(*instance_pda));
        }

        let expected_checkpoint = loaded_config
            .get_trusted_checkpoint(authentic_instance.chain_id)
            .ok_or_else(|| {
                ReceiverError::AttestationFailed(
                    "trusted checkpoint root absent from stored configuration for target chain"
                        .into(),
                )
            })?;
        if authentic_instance.bootstrap_header_hash != expected_checkpoint {
            return Err(ReceiverError::AttestationFailed(
                "authenticated instance bootstrap root does not match pinned trusted checkpoint"
                    .into(),
            ));
        }

        if args.expected_deposit_contract == [0u8; 20] {
            return Err(ReceiverError::DepositBackingRequired);
        }
        if args.expected_token_contract == [0u8; 20] {
            return Err(ReceiverError::TokenNotAllowed(
                [0u8; 20],
                authentic_instance.chain_id,
            ));
        }

        let chain_id = authentic_instance.chain_id;
        let current_slot = authentic_instance.current_slot;
        let trusted_locker = loaded_config
            .get_trusted_locker(chain_id)
            .ok_or(ReceiverError::UntrustedLocker(chain_id))?;
        if !loaded_config.is_trusted_shielded_locker(chain_id, &args.expected_deposit_contract) {
            return Err(ReceiverError::DepositContractMismatch {
                expected: trusted_locker,
                actual: args.expected_deposit_contract,
            });
        }
        if !loaded_config.is_token_allowed(chain_id, &args.expected_token_contract) {
            return Err(ReceiverError::TokenNotAllowed(
                args.expected_token_contract,
                chain_id,
            ));
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
        .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;

        let statement = match output {
            mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
            _ => {
                return Err(ReceiverError::AttestationFailed(
                    "unexpected instruction output from handle_attest_state".into(),
                ))
            }
        };
        if !statement.predicate_holds {
            return Err(ReceiverError::PredicateFailed);
        }
        if statement.proof_type_tag != PROOF_TYPE_SHIELDED_DEPOSIT {
            return Err(ReceiverError::InvalidStatementType(
                statement.proof_type_tag,
            ));
        }

        let (locker_contract, token_contract, commitment) = match &statement.binding {
            StatementBinding::ShieldedCommitment {
                locker_contract,
                token_contract,
                commitment,
                ..
            } => (*locker_contract, *token_contract, *commitment),
            _ => return Err(ReceiverError::DepositBackingRequired),
        };

        if locker_contract != args.expected_deposit_contract
            || !loaded_config.is_trusted_shielded_locker(chain_id, &locker_contract)
        {
            return Err(ReceiverError::DepositContractMismatch {
                expected: args.expected_deposit_contract,
                actual: locker_contract,
            });
        }
        if token_contract != args.expected_token_contract || token_contract == [0u8; 20] {
            return Err(ReceiverError::TokenContractMismatch {
                expected: args.expected_token_contract,
                actual: token_contract,
            });
        }

        let verified_amount = statement.value_as_u256();
        if verified_amount < args.min_amount {
            return Err(ReceiverError::AmountTooLowU256 {
                min_amount: args.min_amount,
                actual: verified_amount,
            });
        }

        // Verify commitment preimage binds (token_contract, verified_amount, secret, nullifier_secret)
        let expected_commitment = derive_shielded_commitment(
            &token_contract,
            &verified_amount.to_be_bytes::<32>(),
            &args.secret,
            &args.nullifier_secret,
        );
        if expected_commitment != commitment {
            return Err(ReceiverError::InvalidShieldedPreimage);
        }

        let claim_nullifier = derive_claim_nullifier(&args.nullifier_secret);
        let claim_nullifier_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &claim_nullifier);
        if nullifiers.is_used(&claim_nullifier) || store.get_account(&claim_nullifier_pda).is_some()
        {
            return Err(ReceiverError::AlreadyClaimed);
        }
        let stmt_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.statement_id);
        let subj_pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement.subject_key);
        if nullifiers.is_used(&statement.statement_id)
            || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
            || store.get_account(&stmt_pda).is_some()
            || (statement.subject_key != [0u8; 32] && store.get_account(&subj_pda).is_some())
        {
            return Err(ReceiverError::AlreadyClaimed);
        }

        // Arithmetic Pre-Check before nullifier commit
        let amount_u128: u128 = verified_amount
            .try_into()
            .map_err(|_| ReceiverError::Overflow)?;
        let current_balance = self.get_balance(&token_contract, &args.recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;
        let current_supply = self.get_total_supply(&token_contract);
        let new_supply = current_supply
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;

        // Commit statement + subject PDAs and claim_nullifier PDA atomically
        let claim_rec = NullifierAccount {
            statement_id: claim_nullifier,
            subject_key: commitment,
            spent_slot: current_slot,
            is_spent: true,
        };
        let encoded_claim = serde_json::to_vec(&claim_rec).map_err(|e| {
            ReceiverError::AttestationFailed(format!(
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
                ReceiverError::AttestationFailed(format!(
                    "failed to persist shielded claim nullifier PDA: {e}"
                ))
            })?;
        commit_erc20_nullifiers(store, nullifiers, &statement, current_slot)?;
        nullifiers.mark_used(claim_nullifier);

        let key = (token_contract, args.recipient);
        let entry = self.accounts.entry(key).or_insert_with(|| Erc20Account {
            token: token_contract,
            owner: args.recipient,
            balance: 0,
            deposit_count: 0,
            burn_count: 0,
        });
        entry.balance = new_balance;
        entry.deposit_count += 1;
        self.total_supplies.insert(token_contract, new_supply);

        Ok(verified_amount)
    }

    /// Burn synthetic tokens on LEZ and emit a privacy-preserving `burnNullifier` for
    /// `MosooLocker.unlockShieldedERC20` without leaking `lez_owner`, `burn_nonce`, or `lez_slot` on Ethereum L1.
    pub fn burn_shielded_tokens(
        &mut self,
        chain_id: u64,
        source_instance: &[u8; 32],
        token: &[u8; 20],
        owner: &[u8; 32],
        amount: u128,
        burn_secret: &[u8; 32],
    ) -> Result<[u8; 32], ReceiverError> {
        if amount == 0 {
            return Err(ReceiverError::AmountTooLow {
                min_amount: 1,
                actual: 0,
            });
        }
        let user =
            self.accounts
                .get_mut(&(*token, *owner))
                .ok_or(ReceiverError::AccountNotFound {
                    token: *token,
                    owner: *owner,
                })?;
        if user.balance < amount {
            return Err(ReceiverError::InsufficientBalance {
                available: user.balance,
                requested: amount,
            });
        }
        user.balance -= amount;
        user.burn_count += 1;
        let supply = self.total_supplies.entry(*token).or_insert(0);
        *supply -= amount;
        let burned = self.total_burned.entry(*token).or_insert(0);
        *burned = burned.checked_add(amount).ok_or(ReceiverError::Overflow)?;

        Ok(derive_shielded_burn_nullifier(
            chain_id,
            source_instance,
            token,
            &U256::from(amount).to_be_bytes::<32>(),
            burn_secret,
        ))
    }

    /// Mint synthetic tokens from an in-guest atomic execution proof with full 256-bit validation.
    /// Strictly requires an authentic `StatementBinding::Erc20Deposit` binding and validates the
    /// trusted bridge locker address from program configuration, token contract allowlist, depositor,
    /// and recipient before state mutation.
    /// Validates checked U256-to-u128 conversion and balance additions BEFORE consuming nullifiers.
    #[cfg(any(test, feature = "test-harness"))]
    #[deprecated(
        note = "In-memory test harness entrypoint. Production LEZ contract calls MUST use mint_deposit_authenticated_store_u256 or mint_deposit_authenticated_pda_u256."
    )]
    pub fn mint_deposit_atomic_u256(
        &mut self,
        args: AtomicErc20ClaimArgsU256,
        nullifiers: &mut NullifierSet,
    ) -> Result<U256, ReceiverError> {
        if !is_supported_chain_id(args.instance.chain_id) {
            return Err(ReceiverError::WrongChain(args.instance.chain_id));
        }
        if args.expected_deposit_contract == [0u8; 20] {
            return Err(ReceiverError::DepositBackingRequired);
        }

        let trusted_locker = self
            .config
            .get_trusted_locker(args.instance.chain_id)
            .ok_or(ReceiverError::UntrustedLocker(args.instance.chain_id))?;

        if args.expected_deposit_contract != trusted_locker {
            return Err(ReceiverError::DepositContractMismatch {
                expected: trusted_locker,
                actual: args.expected_deposit_contract,
            });
        }

        let attest_args = mosoo_core::verifier::AttestStateArgs {
            instance: args.instance.clone(),
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
            .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;

        let statement = match output {
            mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
            _ => {
                return Err(ReceiverError::AttestationFailed(
                    "unexpected instruction output from handle_attest_state".into(),
                ))
            }
        };

        if !statement.predicate_holds {
            return Err(ReceiverError::PredicateFailed);
        }

        // Strict proof type binding: ONLY authentic DepositERC20 from MosooLocker is accepted
        let (deposit_contract, token_contract, sender, recipient) = match &statement.binding {
            StatementBinding::Erc20Deposit {
                deposit_contract,
                token_contract,
                sender,
                recipient,
                ..
            } => (*deposit_contract, *token_contract, *sender, *recipient),
            _ => {
                return Err(ReceiverError::DepositBackingRequired);
            }
        };

        if deposit_contract != trusted_locker {
            return Err(ReceiverError::DepositContractMismatch {
                expected: trusted_locker,
                actual: deposit_contract,
            });
        }
        if token_contract != args.expected_token_contract {
            return Err(ReceiverError::TokenContractMismatch {
                expected: args.expected_token_contract,
                actual: token_contract,
            });
        }
        if !self
            .config
            .is_token_allowed(args.instance.chain_id, &token_contract)
        {
            return Err(ReceiverError::TokenNotAllowed(
                token_contract,
                args.instance.chain_id,
            ));
        }
        if let Some(expected_sender) = args.expected_sender {
            if sender != expected_sender {
                return Err(ReceiverError::SenderMismatch {
                    expected: expected_sender,
                    actual: sender,
                });
            }
        }
        if recipient != args.recipient {
            return Err(ReceiverError::RecipientMismatch {
                expected: args.recipient,
                actual: recipient,
            });
        }

        let verified_amount = statement.value_as_u256();
        if verified_amount < args.min_amount {
            return Err(ReceiverError::AmountTooLowU256 {
                min_amount: args.min_amount,
                actual: verified_amount,
            });
        }

        let amount_u128: u128 = verified_amount
            .try_into()
            .map_err(|_| ReceiverError::Overflow)?;

        // Checked conversion and ledger balance/supply overflow checks MUST pass before nullifier mutation
        let current_balance = self.get_balance(&token_contract, &recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;

        let current_supply = self.get_total_supply(&token_contract);
        let new_supply = current_supply
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;

        if nullifiers.is_used(&statement.statement_id)
            || (statement.subject_key != [0u8; 32] && nullifiers.is_used(&statement.subject_key))
        {
            return Err(ReceiverError::AlreadyClaimed);
        }

        nullifiers.mark_used(statement.statement_id);
        if statement.subject_key != [0u8; 32] {
            nullifiers.mark_used(statement.subject_key);
        }

        let key = (token_contract, recipient);
        let entry = self.accounts.entry(key).or_insert_with(|| Erc20Account {
            token: token_contract,
            owner: recipient,
            balance: 0,
            deposit_count: 0,
            burn_count: 0,
        });
        entry.balance = new_balance;
        entry.deposit_count += 1;

        self.total_supplies.insert(token_contract, new_supply);

        Ok(verified_amount)
    }

    /// Mint synthetic tokens from an authentic on-chain StatementAccount PDA.
    /// Strictly verifies canonical PDA derivation from Mosoo program ID, enforces
    /// `StatementBinding::Erc20Deposit` proof type, validates expected locker contract
    /// against program-owned configuration, checks token allowlist, performs checked
    /// U256-to-u128 conversion, and guards against balance overflow before nullifier mutation.
    pub fn mint_deposit_authenticated_pda_u256(
        &mut self,
        statement_account: &StatementAccount,
        expected_deposit_contract: [u8; 20],
        nullifiers: &mut NullifierSet,
    ) -> Result<U256, ReceiverError> {
        if statement_account.owner != MOSOO_PROGRAM_ID {
            return Err(ReceiverError::UnauthenticatedAttester);
        }
        let expected_pda = derive_statement_pda(
            statement_account.statement.chain_id,
            &statement_account.statement.statement_id,
        );
        if statement_account.pda_address != expected_pda {
            return Err(ReceiverError::UnauthenticatedAttester);
        }

        if statement_account.statement.source_instance_pda == [0u8; 32] {
            return Err(ReceiverError::UnauthenticatedSourceInstance);
        }
        let pinned_pda = self
            .config
            .get_trusted_instance(statement_account.statement.chain_id)
            .ok_or(ReceiverError::UntrustedSourceInstance)?;
        if statement_account.statement.source_instance_pda != pinned_pda {
            return Err(ReceiverError::UntrustedSourceInstance);
        }

        if expected_deposit_contract == [0u8; 20] {
            return Err(ReceiverError::DepositBackingRequired);
        }

        let chain_id = statement_account.statement.chain_id;
        let trusted_locker = self
            .config
            .get_trusted_locker(chain_id)
            .ok_or(ReceiverError::UntrustedLocker(chain_id))?;

        if expected_deposit_contract != trusted_locker {
            return Err(ReceiverError::DepositContractMismatch {
                expected: trusted_locker,
                actual: expected_deposit_contract,
            });
        }

        let (deposit_contract, token, recipient) = match &statement_account.statement.binding {
            StatementBinding::Erc20Deposit {
                deposit_contract,
                token_contract,
                recipient,
                ..
            } => (*deposit_contract, *token_contract, *recipient),
            _ => {
                return Err(ReceiverError::DepositBackingRequired);
            }
        };

        if deposit_contract != trusted_locker {
            return Err(ReceiverError::DepositContractMismatch {
                expected: trusted_locker,
                actual: deposit_contract,
            });
        }

        if !self.config.is_token_allowed(chain_id, &token) {
            return Err(ReceiverError::TokenNotAllowed(token, chain_id));
        }

        let amount_u256 = statement_account.statement.value_as_u256();
        let amount_u128: u128 = amount_u256
            .try_into()
            .map_err(|_| ReceiverError::Overflow)?;

        let current_balance = self.get_balance(&token, &recipient);
        let new_balance = current_balance
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;

        let current_supply = self.get_total_supply(&token);
        let new_supply = current_supply
            .checked_add(amount_u128)
            .ok_or(ReceiverError::Overflow)?;

        claim_u256_internal(&statement_account.statement, nullifiers, U256::ZERO)?;

        let key = (token, recipient);
        let entry = self.accounts.entry(key).or_insert_with(|| Erc20Account {
            token,
            owner: recipient,
            balance: 0,
            deposit_count: 0,
            burn_count: 0,
        });
        entry.balance = new_balance;
        entry.deposit_count += 1;

        self.total_supplies.insert(token, new_supply);

        Ok(amount_u256)
    }

    /// Mint synthetic tokens from a host-authenticated runtime account metadata object.
    /// Strictly verifies that the host runtime owner is `MOSOO_PROGRAM_ID` and that the
    /// address matches the canonical statement PDA before minting tokens.
    pub fn mint_deposit_runtime_account_u256(
        &mut self,
        runtime_account: &RuntimeAccount,
        expected_deposit_contract: [u8; 20],
        nullifiers: &mut NullifierSet,
    ) -> Result<U256, ReceiverError> {
        let statement_account = StatementAccount::try_from_runtime_account(runtime_account)
            .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;
        self.mint_deposit_authenticated_pda_u256(
            &statement_account,
            expected_deposit_contract,
            nullifiers,
        )
    }

    /// Mint synthetic tokens upon verification of a canonical DepositERC20 log from MosooLocker.sol.
    #[cfg(any(test, feature = "test-harness"))]
    #[deprecated(
        note = "In-memory VerifiedStatement can be forged. Use `mint_deposit_atomic_u256` for in-guest atomic execution or `mint_deposit_authenticated_pda_u256` for on-chain StatementAccount PDA verification"
    )]
    pub fn mint_deposit_tokens(
        &mut self,
        claim: &Erc20DepositClaim,
        nullifiers: &mut NullifierSet,
    ) -> Result<u128, ReceiverError> {
        let amount = claim_erc20_deposit_with_config(claim, nullifiers, &self.config)?;

        let key = (claim.token_contract, claim.recipient);
        let entry = self.accounts.entry(key).or_insert_with(|| Erc20Account {
            token: claim.token_contract,
            owner: claim.recipient,
            balance: 0,
            deposit_count: 0,
            burn_count: 0,
        });

        entry.balance = entry
            .balance
            .checked_add(amount)
            .ok_or(ReceiverError::Overflow)?;
        entry.deposit_count += 1;

        let supply = self.total_supplies.entry(claim.token_contract).or_insert(0);
        *supply = supply.checked_add(amount).ok_or(ReceiverError::Overflow)?;

        Ok(entry.balance)
    }

    /// Transfer synthetic tokens between LEZ accounts.
    pub fn transfer_tokens(
        &mut self,
        token: &[u8; 20],
        from: &[u8; 32],
        to: &[u8; 32],
        amount: u128,
    ) -> Result<(), ReceiverError> {
        if amount == 0 {
            return Ok(());
        }
        if from == to {
            let from_entry =
                self.accounts
                    .get(&(*token, *from))
                    .ok_or(ReceiverError::AccountNotFound {
                        token: *token,
                        owner: *from,
                    })?;
            if from_entry.balance < amount {
                return Err(ReceiverError::InsufficientBalance {
                    available: from_entry.balance,
                    requested: amount,
                });
            }
            return Ok(());
        }
        let from_entry =
            self.accounts
                .get_mut(&(*token, *from))
                .ok_or(ReceiverError::AccountNotFound {
                    token: *token,
                    owner: *from,
                })?;

        if from_entry.balance < amount {
            return Err(ReceiverError::InsufficientBalance {
                available: from_entry.balance,
                requested: amount,
            });
        }
        from_entry.balance -= amount;

        let to_entry = self
            .accounts
            .entry((*token, *to))
            .or_insert_with(|| Erc20Account {
                token: *token,
                owner: *to,
                balance: 0,
                deposit_count: 0,
                burn_count: 0,
            });
        to_entry.balance = to_entry
            .balance
            .checked_add(amount)
            .ok_or(ReceiverError::Overflow)?;

        Ok(())
    }

    /// Burn synthetic tokens on LEZ to unlock real ERC-20 tokens on Ethereum.
    /// Emits a canonical `Erc20BurnReceipt` cryptographically bound to the Ethereum recipient.
    pub fn burn_tokens(
        &mut self,
        chain_id: u64,
        token: &[u8; 20],
        owner: &[u8; 32],
        amount: u128,
        eth_recipient: &[u8; 20],
        lez_slot: u64,
    ) -> Result<Erc20BurnReceipt, ReceiverError> {
        if amount == 0 {
            return Err(ReceiverError::AmountTooLow {
                min_amount: 1,
                actual: 0,
            });
        }

        let user =
            self.accounts
                .get_mut(&(*token, *owner))
                .ok_or(ReceiverError::AccountNotFound {
                    token: *token,
                    owner: *owner,
                })?;

        if user.balance < amount {
            return Err(ReceiverError::InsufficientBalance {
                available: user.balance,
                requested: amount,
            });
        }

        user.balance -= amount;
        user.burn_count += 1;
        let burn_nonce = user.burn_count;

        let supply = self.total_supplies.entry(*token).or_insert(0);
        *supply -= amount;

        let burned = self.total_burned.entry(*token).or_insert(0);
        *burned = burned.checked_add(amount).ok_or(ReceiverError::Overflow)?;

        let burn_id = derive_burn_erc20_id(
            chain_id,
            token,
            owner,
            eth_recipient,
            amount,
            burn_nonce,
            lez_slot,
        );

        let receipt = Erc20BurnReceipt {
            burn_id,
            chain_id,
            token: *token,
            lez_owner: *owner,
            eth_recipient: *eth_recipient,
            amount,
            burn_nonce,
            lez_slot,
        };

        self.burn_receipts.insert(burn_id, receipt.clone());
        Ok(receipt)
    }

    /// Retrieve an emitted burn receipt by its canonical 32-byte burn ID.
    pub fn get_burn_receipt(&self, burn_id: &[u8; 32]) -> Option<&Erc20BurnReceipt> {
        self.burn_receipts.get(burn_id)
    }
}

#[cfg(test)]
mod tests;
