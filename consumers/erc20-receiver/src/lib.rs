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
    get_canonical_trusted_locker, is_supported_chain_id, AccountStore, RuntimeAccount,
    StatementAccount, StatementBinding, TrustedBridgeConfig, VerifiedStatement,
    ETH_HOLESKY_CHAIN_ID, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    PROOF_TYPE_ERC20_DEPOSIT, PROOF_TYPE_ERC20_TRANSFER,
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

    #[error("arithmetic overflow in token operation")]
    Overflow,
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
#[derive(Default, Clone, Debug)]
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
/// let minted = claim(&statement, &mut nullifiers, 100).expect("first claim succeeds");
/// assert_eq!(minted, 100);
/// ```
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
    #[allow(deprecated)]
    claim_u256(&statement_account.statement, nullifiers, min_amount)
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

/// Verify a VerifiedStatement with full 256-bit (U256) precision and mint LEZ-side tokens.
///
/// Prevents truncation for amounts > u64::MAX (e.g. standard 18-decimal token transfers).
#[deprecated(
    note = "Use `claim_atomic_u256` for in-guest atomic execution or `claim_authenticated_pda_u256` for on-chain PDA account provenance"
)]
pub fn claim_u256(
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

/// Verify a VerifiedStatement with u128 precision (safe for amounts up to 3.4e38 units).
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
/// In accordance with Logos RFP-021 reference consumer specifications, this proves that
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
/// sender, recipient, and amount in accordance with RFP-021 reference consumer semantics.
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
pub fn claim_erc20_deposit(
    claim: &Erc20DepositClaim,
    nullifiers: &mut NullifierSet,
) -> Result<u128, ReceiverError> {
    claim_erc20_deposit_with_config(claim, nullifiers, &TrustedBridgeConfig::canonical())
}

/// Process a verified ERC-20 deposit event log from MosooLocker.sol using a specified bridge configuration.
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
#[deprecated(
    note = "Use `claim_atomic_u256` for full U256 precision to prevent overflow/truncation of amounts > u64::MAX"
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
    // 1. Strictly load authentic InstanceAccount from persistent store first (Finding P0)
    let authentic_instance =
        mosoo_core::verifier::verify_instance_account_authenticity(store, instance_pda)
            .map_err(|e| ReceiverError::AttestationFailed(e.to_string()))?;

    // 2. Guard: Light-client instance must be pinned in TrustedBridgeConfig (Finding M-01)
    if !config.is_trusted_instance(authentic_instance.chain_id, instance_pda) {
        return Err(ReceiverError::UntrustedInstanceAccount(*instance_pda));
    }

    // 3. Guard: Verify authentic stored instance's bootstrap root matches pinned trusted checkpoint (Finding P0)
    if let Some(expected_checkpoint) = config.get_trusted_checkpoint(authentic_instance.chain_id) {
        if authentic_instance.bootstrap_header_hash != expected_checkpoint {
            return Err(ReceiverError::AttestationFailed(
                "authenticated instance bootstrap root does not match pinned trusted checkpoint"
                    .into(),
            ));
        }
    }

    let current_slot = authentic_instance.current_slot;
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

    // Atomically persist nullifier PDA to LEZ AccountStore (Finding P1)
    let nullifier_rec = NullifierAccount {
        statement_id: statement.statement_id,
        subject_key: statement.subject_key,
        spent_slot: current_slot,
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

    /// Mint synthetic tokens from an in-guest atomic execution proof with full 256-bit validation.
    /// Strictly requires an authentic `StatementBinding::Erc20Deposit` binding and validates the
    /// trusted bridge locker address from program configuration, token contract allowlist, depositor,
    /// and recipient before state mutation.
    /// Validates checked U256-to-u128 conversion and balance additions BEFORE consuming nullifiers.
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

        claim_authenticated_pda_u256(statement_account, nullifiers, U256::ZERO)?;

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
        amount: u64,
        attester: [u8; 32],
    ) -> VerifiedStatement {
        make_erc20_statement(
            chain_id, holds, id_seed, amount, attester, [0xaa; 20], [0x11; 20], [0x22; 32],
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn make_erc20_statement(
        chain_id: u64,
        holds: bool,
        id_seed: u8,
        amount: u64,
        attester: [u8; 32],
        token_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    ) -> VerifiedStatement {
        let mut verified_value = [0u8; 32];
        verified_value[24..32].copy_from_slice(&amount.to_be_bytes());
        let block_hash = [0x11; 32];
        let slot = 100u64;
        let tx_index = 0u64;
        let log_index = 0usize;
        let subject_key = derive_erc20_transfer_subject_key(
            &block_hash,
            slot,
            tx_index,
            log_index,
            &token_contract,
            &sender,
            &recipient,
        );
        let statement_id = if id_seed != 0 {
            mosoo_core::predicate::derive_statement_id_from_raw(
                chain_id,
                &subject_key,
                PROOF_TYPE_ERC20_TRANSFER,
                &verified_value,
            )
        } else {
            [0u8; 32]
        };
        VerifiedStatement {
            chain_id,
            attester_program_id: attester,
            statement_id,
            predicate_holds: holds,
            verified_value,
            subject_key,
            proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
            binding: StatementBinding::Erc20Transfer {
                execution_block_hash: block_hash,
                slot,
                tx_index,
                log_index,
                token_contract,
                sender,
                recipient,
            },
        }
    }

    #[test]
    fn valid_claim_succeeds() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x01, 100, MOSOO_PROGRAM_ID);
        let result = claim(&statement, &mut nullifiers, 100);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 100);
    }

    #[test]
    fn duplicate_claim_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x02, 100, MOSOO_PROGRAM_ID);
        claim(&statement, &mut nullifiers, 100).unwrap();
        let result = claim(&statement, &mut nullifiers, 100);
        assert!(matches!(result, Err(ReceiverError::AlreadyClaimed)));
    }

    #[test]
    fn wrong_chain_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_statement(ETH_SEPOLIA_CHAIN_ID, true, 0x03, 100, MOSOO_PROGRAM_ID);
        let result = claim(&statement, &mut nullifiers, 100);
        assert!(matches!(result, Err(ReceiverError::WrongChain(_))));
    }

    #[test]
    fn test_sepolia_chain_claim_succeeds() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_statement(ETH_SEPOLIA_CHAIN_ID, true, 0x03, 100, MOSOO_PROGRAM_ID);
        let account = StatementAccount::new_authentic(statement);
        let result = claim_authenticated_pda_u256(&account, &mut nullifiers, U256::from(100u64));
        assert_eq!(result, Ok(U256::from(100u64)));
    }

    #[test]
    fn failed_predicate_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, false, 0x04, 100, MOSOO_PROGRAM_ID);
        let result = claim(&statement, &mut nullifiers, 100);
        assert!(matches!(result, Err(ReceiverError::PredicateFailed)));
    }

    #[test]
    fn unauthenticated_attester_rejected() {
        let mut nullifiers = NullifierSet::new();
        let bogus_attester = [0xde; 32];
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x05, 100, bogus_attester);
        let result = claim(&statement, &mut nullifiers, 100);
        assert_eq!(result, Err(ReceiverError::UnauthenticatedAttester));
    }

    #[test]
    fn claim_amount_too_low_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x06, 50, MOSOO_PROGRAM_ID);
        let result = claim(&statement, &mut nullifiers, 100);
        assert_eq!(
            result,
            Err(ReceiverError::AmountTooLow {
                min_amount: 100,
                actual: 50
            })
        );
    }

    #[test]
    fn test_erc20_transfer_claim_succeeds() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x07,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let minted = claim_erc20_transfer(&claim, &mut nullifiers)
            .expect("Valid ERC20 transfer claim should succeed");
        assert_eq!(minted, 500_000);
    }

    #[test]
    fn test_erc20_transfer_wrong_token_contract_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x08,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x99; 20], // wrong token contract
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(ReceiverError::TokenContractMismatch {
                expected: [0x99; 20],
                actual: [0x11; 20],
            })
        );
    }

    #[test]
    fn test_erc20_transfer_wrong_sender_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x09,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x88; 20], // wrong sender
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(ReceiverError::SenderMismatch {
                expected: [0x88; 20],
                actual: [0x22; 20],
            })
        );
    }

    #[test]
    fn test_erc20_transfer_wrong_recipient_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x0a,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x77; 32], // wrong recipient
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(ReceiverError::RecipientMismatch {
                expected: [0x77; 32],
                actual: [0x33; 32],
            })
        );
    }

    #[test]
    fn test_erc20_transfer_wrong_statement_type_rejected() {
        let mut nullifiers = NullifierSet::new();
        // Raw account balance statement instead of Erc20Transfer
        let mut statement =
            make_statement(ETH_MAINNET_CHAIN_ID, true, 0x0b, 500_000, MOSOO_PROGRAM_ID);
        statement.proof_type_tag = 0;
        statement.binding = StatementBinding::Account {
            address: [0x11; 20],
        };
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(result, Err(ReceiverError::InvalidStatementType(0)));
    }

    #[test]
    fn test_erc20_transfer_subject_key_tamper_rejected() {
        let mut nullifiers = NullifierSet::new();
        let mut statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x0c,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        // Tamper with subject_key
        statement.subject_key[0] ^= 0xff;
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(result, Err(ReceiverError::SubjectKeyMismatch));
    }

    #[test]
    fn test_erc20_transfer_insufficient_amount_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x0d,
            50,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(
            result,
            Err(ReceiverError::AmountTooLow {
                min_amount: 100,
                actual: 50
            })
        );
    }

    #[test]
    fn test_erc20_transfer_duplicate_replay_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x0e,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        claim_erc20_transfer(&claim, &mut nullifiers).unwrap();
        let replay_result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(replay_result, Err(ReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_erc20_transfer_unauthenticated_attester_rejected() {
        let mut nullifiers = NullifierSet::new();
        let bogus_attester = [0x55; 32];
        let statement = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x0f,
            500_000,
            bogus_attester,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(result, Err(ReceiverError::UnauthenticatedAttester));
    }

    #[test]
    fn test_erc20_transfer_wrong_chain_rejected() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            999_999, // Unsupported chain ID
            true,
            0x10,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(result, Err(ReceiverError::WrongChain(999_999)));
    }

    #[test]
    fn test_erc20_transfer_sepolia_succeeds() {
        let mut nullifiers = NullifierSet::new();
        let statement = make_erc20_statement(
            ETH_SEPOLIA_CHAIN_ID, // Sepolia testnet
            true,
            0x10,
            500_000,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 32],
        );
        let claim = Erc20TransferClaim {
            statement,
            token_contract: [0x11; 20],
            sender: [0x22; 20],
            recipient: [0x33; 32],
            min_amount: 100_000,
        };
        let result = claim_erc20_transfer(&claim, &mut nullifiers);
        assert_eq!(result, Ok(500_000));
    }

    #[test]
    fn test_claim_atomic_receipt_log_succeeds() {
        use alloy_primitives::{keccak256, Address, U256};
        use mosoo_core::inclusion::test_helpers::{
            build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
        };
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = NullifierSet::new();
        let emitter_addr = [0xaa; 20];
        let from_addr = [0x11; 20];
        let to_addr = [0x22; 20];
        let amount_u64: u64 = 42_000_000;
        let amount = U256::from(amount_u64);

        let receipt_rlp = build_test_eip1559_transfer_receipt(
            Address::from(emitter_addr),
            Address::from(from_addr),
            Address::from(to_addr),
            amount,
        );
        let tx_index: u64 = 0;
        let key_bytes = alloy_rlp::encode(tx_index);
        let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

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
            target: ProofTarget::ReceiptLog {
                tx_index,
                log_index: 0,
                emitter: Address::from(emitter_addr),
                topic0: keccak256("Transfer(address,address,uint256)"),
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let args = AtomicErc20ClaimArgs {
            instance: instance.clone(),
            header: header.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: proof.clone(),
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000),
            },
            expected_token_contract: emitter_addr,
            expected_sender: None,
            recipient: [0x33; 32],
            min_amount: 1_000_000,
        };

        let minted = claim_atomic(args.clone(), &mut nullifiers)
            .expect("Atomic receipt log claim must succeed");
        assert_eq!(minted, amount_u64);

        // Replay rejection in the same state
        let replay = claim_atomic(args, &mut nullifiers);
        assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_claim_atomic_u256_large_amount_succeeds() {
        use alloy_primitives::{keccak256, Address, U256};
        use mosoo_core::inclusion::test_helpers::{
            build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
        };
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = NullifierSet::new();
        let emitter_addr = [0xaa; 20];
        let from_addr = [0x11; 20];
        let to_addr = [0x22; 20];
        // 500,000 tokens (18 dec) >> u64::MAX
        let amount = U256::from(500_000_000_000_000_000_000_000u128);

        let receipt_rlp = build_test_eip1559_transfer_receipt(
            Address::from(emitter_addr),
            Address::from(from_addr),
            Address::from(to_addr),
            amount,
        );
        let tx_index: u64 = 0;
        let key_bytes = alloy_rlp::encode(tx_index);
        let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

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
            target: ProofTarget::ReceiptLog {
                tx_index,
                log_index: 0,
                emitter: Address::from(emitter_addr),
                topic0: keccak256("Transfer(address,address,uint256)"),
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let mut min_32 = [0u8; 32];
        min_32[24..32].copy_from_slice(&1_000u64.to_be_bytes());

        let args = AtomicErc20ClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: min_32 },
            expected_deposit_contract: [0u8; 20],
            expected_token_contract: emitter_addr,
            expected_sender: None,
            recipient: [0x33; 32],
            min_amount: U256::from(100_000_000_000_000_000_000u128),
        };

        let minted = claim_atomic_u256(args.clone(), &mut nullifiers)
            .expect("Atomic U256 claim for 500,000 tokens MUST succeed");
        assert_eq!(minted, amount);

        // Replay rejection
        let replay = claim_atomic_u256(args, &mut nullifiers);
        assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_claim_atomic_rejects_unauthenticated_header() {
        use alloy_primitives::{keccak256, Address, U256};
        use mosoo_core::inclusion::test_helpers::{
            build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
        };
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = NullifierSet::new();
        let emitter_addr = [0xaa; 20];
        let amount = U256::from(42_000_000u64);
        let receipt_rlp = build_test_eip1559_transfer_receipt(
            Address::from(emitter_addr),
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            amount,
        );
        let (receipts_root, proof_nodes) =
            build_leaf_mpt_proof(&alloy_rlp::encode(0u64), &receipt_rlp);

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

        // Forged beacon block root
        let forged_header = HeaderRecord {
            chain_id: ETH_MAINNET_CHAIN_ID,
            slot: 10_000_000,
            beacon_block_root: [0xba; 32],
            execution_block_hash: [0x77; 32],
            execution_state_root: [0x88; 32],
            receipts_root: receipts_root.0,
        };

        let proof = StateProof {
            target: ProofTarget::ReceiptLog {
                tx_index: 0,
                log_index: 0,
                emitter: Address::from(emitter_addr),
                topic0: keccak256("Transfer(address,address,uint256)"),
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let args = AtomicErc20ClaimArgs {
            instance,
            header: forged_header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000),
            },
            expected_token_contract: emitter_addr,
            expected_sender: None,
            recipient: [0x33; 32],
            min_amount: 1_000_000,
        };

        let res = claim_atomic(args, &mut nullifiers);
        assert!(matches!(res, Err(ReceiverError::AttestationFailed(_))));
    }

    #[test]
    fn test_claim_atomic_rejects_contract_mismatch() {
        use alloy_primitives::{keccak256, Address, U256};
        use mosoo_core::inclusion::test_helpers::{
            build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
        };
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut nullifiers = NullifierSet::new();
        let emitter_addr = [0xaa; 20];
        let amount = U256::from(42_000_000u64);
        let receipt_rlp = build_test_eip1559_transfer_receipt(
            Address::from(emitter_addr),
            Address::repeat_byte(0x11),
            Address::repeat_byte(0x22),
            amount,
        );
        let (receipts_root, proof_nodes) =
            build_leaf_mpt_proof(&alloy_rlp::encode(0u64), &receipt_rlp);

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
            target: ProofTarget::ReceiptLog {
                tx_index: 0,
                log_index: 0,
                emitter: Address::from(emitter_addr),
                topic0: keccak256("Transfer(address,address,uint256)"),
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let args = AtomicErc20ClaimArgs {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast {
                min: min_32(1_000_000),
            },
            expected_token_contract: [0xbb; 20], // mismatched contract
            expected_sender: None,
            recipient: [0x33; 32],
            min_amount: 1_000_000,
        };

        let res = claim_atomic(args, &mut nullifiers);
        assert!(matches!(
            res,
            Err(ReceiverError::TokenContractMismatch { .. })
        ));
    }

    #[test]
    fn test_erc20_ledger_mint_and_balance() {
        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let token = [0x55; 20];
        let recipient = [0xAA; 32];
        let sender = [0x11; 20];
        let amount = 500_000_000u64; // 500 USDC

        let stmt = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x10,
            amount,
            MOSOO_PROGRAM_ID,
            token,
            sender,
            recipient,
        );

        let claim = Erc20TransferClaim {
            statement: stmt,
            token_contract: token,
            sender,
            recipient,
            min_amount: 100_000_000,
        };

        let new_bal = ledger.mint_tokens(&claim, &mut nullifiers).unwrap();
        assert_eq!(new_bal, 500_000_000);
        assert_eq!(ledger.get_balance(&token, &recipient), 500_000_000);
        assert_eq!(ledger.get_total_supply(&token), 500_000_000);
    }

    #[test]
    fn test_erc20_ledger_transfer_between_accounts() {
        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let token = [0x55; 20];
        let alice = [0xAA; 32];
        let bob = [0xBB; 32];
        let sender = [0x11; 20];

        let stmt = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x20,
            1_000_000_000,
            MOSOO_PROGRAM_ID,
            token,
            sender,
            alice,
        );

        let claim = Erc20TransferClaim {
            statement: stmt,
            token_contract: token,
            sender,
            recipient: alice,
            min_amount: 1_000_000,
        };

        ledger.mint_tokens(&claim, &mut nullifiers).unwrap();

        // Alice transfers 400 tokens to Bob
        ledger
            .transfer_tokens(&token, &alice, &bob, 400_000_000)
            .unwrap();
        assert_eq!(ledger.get_balance(&token, &alice), 600_000_000);
        assert_eq!(ledger.get_balance(&token, &bob), 400_000_000);
        assert_eq!(ledger.get_total_supply(&token), 1_000_000_000);
    }

    #[test]
    fn test_erc20_ledger_transfer_insufficient_balance_rejected() {
        let mut ledger = Erc20Ledger::new();
        let token = [0x55; 20];
        let alice = [0xAA; 32];
        let bob = [0xBB; 32];

        let res = ledger.transfer_tokens(&token, &alice, &bob, 100);
        assert!(matches!(res, Err(ReceiverError::AccountNotFound { .. })));
    }

    #[test]
    fn test_erc20_ledger_burn_generates_burn_receipt() {
        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let token = [0x55; 20];
        let alice = [0xAA; 32];
        let eth_recipient = [0x99; 20];
        let sender = [0x11; 20];

        let stmt = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x30,
            800_000_000,
            MOSOO_PROGRAM_ID,
            token,
            sender,
            alice,
        );

        let claim = Erc20TransferClaim {
            statement: stmt,
            token_contract: token,
            sender,
            recipient: alice,
            min_amount: 1_000_000,
        };

        ledger.mint_tokens(&claim, &mut nullifiers).unwrap();

        // Alice burns 300 tokens
        let receipt = ledger
            .burn_tokens(
                ETH_MAINNET_CHAIN_ID,
                &token,
                &alice,
                300_000_000,
                &eth_recipient,
                62_200,
            )
            .unwrap();

        assert_eq!(receipt.amount, 300_000_000);
        assert_eq!(receipt.token, token);
        assert_eq!(receipt.eth_recipient, eth_recipient);
        assert_eq!(receipt.lez_owner, alice);
        assert_eq!(receipt.burn_nonce, 1);
        assert_eq!(receipt.lez_slot, 62_200);

        assert_eq!(ledger.get_balance(&token, &alice), 500_000_000);
        assert_eq!(ledger.get_total_supply(&token), 500_000_000);
        assert_eq!(ledger.get_total_burned(&token), 300_000_000);

        let retrieved = ledger.get_burn_receipt(&receipt.burn_id).unwrap();
        assert_eq!(retrieved.burn_id, receipt.burn_id);
    }

    #[test]
    fn test_erc20_ledger_double_deposit_mint_rejected_by_nullifier() {
        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let token = [0x55; 20];
        let alice = [0xAA; 32];
        let sender = [0x11; 20];

        let stmt = make_erc20_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            0x40,
            200_000_000,
            MOSOO_PROGRAM_ID,
            token,
            sender,
            alice,
        );

        let claim = Erc20TransferClaim {
            statement: stmt,
            token_contract: token,
            sender,
            recipient: alice,
            min_amount: 1_000_000,
        };

        // First mint succeeds
        ledger.mint_tokens(&claim, &mut nullifiers).unwrap();

        // Second mint fails
        let res = ledger.mint_tokens(&claim, &mut nullifiers);
        assert_eq!(res.unwrap_err(), ReceiverError::AlreadyClaimed);
        assert_eq!(ledger.get_balance(&token, &alice), 200_000_000);
    }

    #[test]
    fn test_derive_burn_erc20_id_deterministic() {
        let id1 = derive_burn_erc20_id(1, &[0x11; 20], &[0x22; 32], &[0x33; 20], 1_000, 1, 100);
        let id2 = derive_burn_erc20_id(1, &[0x11; 20], &[0x22; 32], &[0x33; 20], 1_000, 1, 100);
        assert_eq!(id1, id2);

        let id3 = derive_burn_erc20_id(1, &[0x11; 20], &[0x22; 32], &[0x33; 20], 1_001, 1, 100);
        assert_ne!(id1, id3);
    }

    #[test]
    fn test_erc20_claim_rejects_statement_id_tampering() {
        let mut nullifiers = NullifierSet::new();
        let mut stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x10, 100, MOSOO_PROGRAM_ID);
        // Attacker mutates statement_id to bypass nullifier
        stmt.statement_id = [0xfe; 32];
        let res = claim(&stmt, &mut nullifiers, 100);
        assert_eq!(res.unwrap_err(), ReceiverError::StatementIdMismatch);
    }

    #[test]
    fn test_erc20_nullifier_pda_derivation_and_restart_persistence() {
        let mut nullifiers = NullifierSet::new();
        let stmt = make_statement(ETH_MAINNET_CHAIN_ID, true, 0x25, 500, MOSOO_PROGRAM_ID);

        let pda = derive_nullifier_pda(&MOSOO_PROGRAM_ID, &stmt.statement_id);
        assert_ne!(pda, [0u8; 32]);

        // Process claim on original runtime instance
        claim(&stmt, &mut nullifiers, 100).expect("claim on instance 1 succeeds");

        // Export PDA records (simulating LEZ account storage checkpoint)
        let pda_records = nullifiers.export_pda_records(10_000_000);
        assert!(!pda_records.is_empty());

        // Simulate runtime restart with fresh in-memory process
        let mut restarted_nullifiers = NullifierSet::new();
        assert!(!restarted_nullifiers.is_used(&stmt.statement_id));

        // Restore state from persistent LEZ PDA accounts
        restarted_nullifiers.restore_pda_records(&pda_records);
        assert!(restarted_nullifiers.is_used(&stmt.statement_id));

        // Attempt replay after restart: MUST BE REJECTED!
        let replay_res = claim(&stmt, &mut restarted_nullifiers, 100);
        assert_eq!(replay_res.unwrap_err(), ReceiverError::AlreadyClaimed);
    }

    #[allow(clippy::too_many_arguments)]
    fn make_erc20_deposit_statement(
        chain_id: u64,
        holds: bool,
        amount_u128: u128,
        attester: [u8; 32],
        deposit_contract: [u8; 20],
        token_contract: [u8; 20],
        sender: [u8; 20],
        recipient: [u8; 32],
    ) -> VerifiedStatement {
        let mut verified_value = [0u8; 32];
        verified_value.copy_from_slice(&U256::from(amount_u128).to_be_bytes::<32>());
        let block_hash = [0x55; 32];
        let slot = 10_500_000;
        let tx_index = 2;
        let log_index = 1;

        let subject_key = derive_erc20_deposit_subject_key(
            &block_hash,
            slot,
            tx_index,
            log_index,
            &deposit_contract,
            &token_contract,
            &sender,
            &recipient,
        );
        let statement_id = mosoo_core::predicate::derive_statement_id_from_raw(
            chain_id,
            &subject_key,
            PROOF_TYPE_ERC20_DEPOSIT,
            &verified_value,
        );
        VerifiedStatement {
            chain_id,
            attester_program_id: attester,
            statement_id,
            predicate_holds: holds,
            verified_value,
            subject_key,
            proof_type_tag: PROOF_TYPE_ERC20_DEPOSIT,
            binding: StatementBinding::Erc20Deposit {
                execution_block_hash: block_hash,
                slot,
                tx_index,
                log_index,
                deposit_contract,
                token_contract,
                sender,
                recipient,
            },
        }
    }

    #[test]
    fn test_claim_u256_amounts_exceeding_u64_max_succeeds() {
        let mut nullifiers = NullifierSet::new();
        // 100 tokens with 18 decimals = 100 * 10^18 = 10^20, which is > u64::MAX (~1.84 * 10^19)
        let large_amount: u128 = 100_000_000_000_000_000_000;
        assert!(large_amount > u64::MAX as u128);

        let statement = make_erc20_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            large_amount,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 20],
            [0x44; 32],
        );

        // Standard u64 claim fails closed with overflow protection error
        let u64_res = claim(&statement, &mut nullifiers, 100);
        assert!(matches!(u64_res, Err(ReceiverError::AttestationFailed(_))));

        // U256 claim succeeds with full 256-bit fidelity
        let claimed_u256 = claim_u256(&statement, &mut nullifiers, U256::from(large_amount))
            .expect("U256 claim for amounts > u64::MAX MUST succeed");
        assert_eq!(claimed_u256, U256::from(large_amount));

        // Duplicate claim rejected
        let replay = claim_u256(&statement, &mut nullifiers, U256::from(large_amount));
        assert_eq!(replay.unwrap_err(), ReceiverError::AlreadyClaimed);
    }

    #[test]
    fn test_claim_u128_amounts_exceeding_u64_max_succeeds() {
        let mut nullifiers = NullifierSet::new();
        let large_amount: u128 = 50_000_000_000_000_000_000; // 50 tokens (18 decimals)
        let statement = make_erc20_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            large_amount,
            MOSOO_PROGRAM_ID,
            [0x11; 20],
            [0x22; 20],
            [0x33; 20],
            [0x44; 32],
        );

        let claimed = claim_u128(&statement, &mut nullifiers, large_amount)
            .expect("u128 claim for amounts > u64::MAX MUST succeed");
        assert_eq!(claimed, large_amount);
    }

    #[test]
    fn test_canonical_deposit_erc20_claim_and_mint_succeeds() {
        let mut nullifiers = NullifierSet::new();
        let mut ledger = Erc20Ledger::new();
        let token = [0x22; 20];
        let deposit_contract = [0x11; 20];
        let sender = [0x33; 20];
        let recipient = [0x44; 32];
        let amount: u128 = 250_000_000_000_000_000_000; // 250 tokens
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, deposit_contract);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, token);

        let statement = make_erc20_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            amount,
            MOSOO_PROGRAM_ID,
            deposit_contract,
            token,
            sender,
            recipient,
        );

        let claim = Erc20DepositClaim {
            statement,
            deposit_contract,
            token_contract: token,
            sender,
            recipient,
            min_amount: 100_000_000_000_000_000_000,
        };

        let new_bal = ledger
            .mint_deposit_tokens(&claim, &mut nullifiers)
            .expect("Minting from verified canonical DepositERC20 log must succeed");
        assert_eq!(new_bal, amount);
        assert_eq!(ledger.get_balance(&token, &recipient), amount);
        assert_eq!(ledger.get_total_supply(&token), amount);

        // Replay rejection
        let replay = ledger.mint_deposit_tokens(&claim, &mut nullifiers);
        assert_eq!(replay.unwrap_err(), ReceiverError::AlreadyClaimed);
    }

    #[test]
    fn test_claim_authenticated_pda_u256_provenance_verification() {
        let mut nullifiers = NullifierSet::new();
        let deposit_contract = [0x42; 20];
        let token = [0xaa; 20];
        let sender = [0x11; 20];
        let recipient = [0x22; 32];
        let amount = 500_000_000_000_000_000_000u128; // 500 tokens

        let statement = make_erc20_deposit_statement(
            ETH_MAINNET_CHAIN_ID,
            true,
            amount,
            MOSOO_PROGRAM_ID,
            deposit_contract,
            token,
            sender,
            recipient,
        );

        // 1. Adversary fabricates statement account with fake owner program ID
        let fake_owner = [0x99; 32];
        let fabricated_account = StatementAccount {
            owner: fake_owner,
            pda_address: derive_statement_pda(statement.chain_id, &statement.statement_id),
            statement: statement.clone(),
        };
        let err =
            claim_authenticated_pda_u256(&fabricated_account, &mut nullifiers, U256::from(100u64))
                .expect_err("Fabricated account with fake owner must be rejected");
        assert_eq!(err, ReceiverError::UnauthenticatedAttester);

        // 2. Adversary fabricates statement account with mismatched PDA address
        let fake_pda = [0x88; 32];
        let tampered_pda_account = StatementAccount {
            owner: MOSOO_PROGRAM_ID,
            pda_address: fake_pda,
            statement: statement.clone(),
        };
        let err2 = claim_authenticated_pda_u256(
            &tampered_pda_account,
            &mut nullifiers,
            U256::from(100u64),
        )
        .expect_err("Account with tampered PDA address must be rejected");
        assert_eq!(err2, ReceiverError::UnauthenticatedAttester);

        // 3. Authentic statement account succeeds
        let authentic_account = StatementAccount::new_authentic(statement);
        let minted =
            claim_authenticated_pda_u256(&authentic_account, &mut nullifiers, U256::from(100u64))
                .expect("Authentic statement account must be accepted");
        assert_eq!(minted, U256::from(amount));

        // 4. Replay rejected
        let replay =
            claim_authenticated_pda_u256(&authentic_account, &mut nullifiers, U256::from(100u64))
                .expect_err("Replay claim on statement account must be rejected");
        assert_eq!(replay, ReceiverError::AlreadyClaimed);
    }

    #[test]
    fn test_erc20_ledger_authenticated_pda_mint_succeeds_and_fabricated_rejected() {
        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();
        let token = [0x11; 20];
        let sender = [0x22; 20];
        let recipient = [0x33; 32];
        let amount = 1_000_000u128;

        ledger.register_trusted_locker(ETH_SEPOLIA_CHAIN_ID, [0xaa; 20]);
        ledger.allow_token(ETH_SEPOLIA_CHAIN_ID, token);

        let statement = make_erc20_deposit_statement(
            ETH_SEPOLIA_CHAIN_ID,
            true,
            amount,
            MOSOO_PROGRAM_ID,
            [0xaa; 20],
            token,
            sender,
            recipient,
        );

        // 1. Fabricated account rejected
        let fabricated = StatementAccount {
            owner: [0x55; 32],
            pda_address: derive_statement_pda(statement.chain_id, &statement.statement_id),
            statement: statement.clone(),
        };
        let err =
            ledger.mint_deposit_authenticated_pda_u256(&fabricated, [0xaa; 20], &mut nullifiers);
        assert_eq!(err, Err(ReceiverError::UnauthenticatedAttester));

        // 2. Zero address bypass strictly rejected
        let authentic = StatementAccount::new_authentic(statement);
        let zero_addr_err =
            ledger.mint_deposit_authenticated_pda_u256(&authentic, [0u8; 20], &mut nullifiers);
        assert_eq!(zero_addr_err, Err(ReceiverError::DepositBackingRequired));

        // 3. Mismatched expected deposit contract rejected
        let mismatch =
            ledger.mint_deposit_authenticated_pda_u256(&authentic, [0xee; 20], &mut nullifiers);
        assert_eq!(
            mismatch,
            Err(ReceiverError::DepositContractMismatch {
                expected: [0xaa; 20],
                actual: [0xee; 20],
            })
        );

        // 4. Authentic account mints tokens successfully
        let minted = ledger
            .mint_deposit_authenticated_pda_u256(&authentic, [0xaa; 20], &mut nullifiers)
            .expect("Authentic StatementAccount PDA mint must succeed");
        assert_eq!(minted, U256::from(amount));
        assert_eq!(ledger.get_balance(&token, &recipient), amount);
        assert_eq!(ledger.get_total_supply(&token), amount);

        // 5. Double-mint replay rejected
        let replay =
            ledger.mint_deposit_authenticated_pda_u256(&authentic, [0xaa; 20], &mut nullifiers);
        assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_erc20_mint_deposit_atomic_rejects_unbacked_transfer_proof() {
        use alloy_primitives::{keccak256, Address, U256};
        use mosoo_core::inclusion::test_helpers::{
            build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
        };
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();
        let token_addr = [0x11; 20];
        let depositor = [0x22; 20];
        let recipient = [0x33; 32];
        let locker_addr = [0xaa; 20];
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
        let amount = U256::from(100_000_000_000_000_000_000u128);

        // Ordinary Transfer event log (NOT DepositERC20 from MosooLocker)
        let receipt_rlp = build_test_eip1559_transfer_receipt(
            Address::from(token_addr),
            Address::from(depositor),
            Address::from([0x44; 20]),
            amount,
        );
        let tx_index: u64 = 0;
        let key_bytes = alloy_rlp::encode(tx_index);
        let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_rlp);

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
            target: ProofTarget::ReceiptLog {
                tx_index,
                log_index: 0,
                emitter: Address::from(token_addr),
                topic0: keccak256("Transfer(address,address,uint256)"),
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let mut min_32 = [0u8; 32];
        min_32[24..32].copy_from_slice(&1_000u64.to_be_bytes());

        let args = AtomicErc20ClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: min_32 },
            expected_deposit_contract: locker_addr,
            expected_token_contract: token_addr,
            expected_sender: Some(depositor),
            recipient,
            min_amount: U256::from(1_000u64),
        };

        // Minting deposit strictly rejects ordinary ERC-20 transfer logs!
        let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
        assert_eq!(err, Err(ReceiverError::DepositBackingRequired));
        assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
    }

    #[test]
    fn test_erc20_mint_deposit_atomic_rejects_storage_proof() {
        use alloy_primitives::{Address, B256, U256};
        use mosoo_core::inclusion::test_helpers::build_test_storage_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();
        let token_addr = [0x11; 20];
        let locker_addr = [0xaa; 20];
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
        let recipient = [0x33; 32];

        let contract = Address::from(token_addr);
        let slot = B256::repeat_byte(0x05);
        let mut expected_val = [0u8; 32];
        expected_val[31] = 42;

        let (state_root, account_proof, account_rlp, storage_proof, storage_rlp) =
            build_test_storage_proof(contract, slot, expected_val);

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
            current_receipts_root: [0x99; 32],
        };

        let header = HeaderRecord {
            chain_id: ETH_MAINNET_CHAIN_ID,
            slot: 10_000_000,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x77; 32],
            execution_state_root: state_root.0,
            receipts_root: [0x99; 32],
        };

        let proof = StateProof {
            target: ProofTarget::StorageSlot { contract, slot },
            account_proof,
            storage_proof: Some(storage_proof),
            receipt_proof: None,
            account_value: Some(account_rlp),
            storage_value: Some(storage_rlp),
            receipt_value: None,
        };

        let args = AtomicErc20ClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: locker_addr,
            expected_token_contract: token_addr,
            expected_sender: None,
            recipient,
            min_amount: U256::from(1_000u64),
        };

        // Minting deposit strictly rejects raw storage proofs
        let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
        assert_eq!(err, Err(ReceiverError::DepositBackingRequired));
        assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
    }

    #[test]
    fn test_erc20_mint_deposit_atomic_succeeds_with_authentic_locker() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let locker_addr = [0xaa; 20];
        let token_addr = [0x11; 20];
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
        let depositor = [0x22; 20];
        let recipient = [0x33; 32];
        let amount = U256::from(2_500_000_000_000_000_000u128); // 2.5 tokens
        let nonce = 1u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
            Address::from(locker_addr),
            Address::from(token_addr),
            Address::from(depositor),
            recipient,
            amount,
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
            target: ProofTarget::Erc20Deposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract: Address::from(locker_addr),
                token_contract: Address::from(token_addr),
                sender: Address::from(depositor),
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let args = AtomicErc20ClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: locker_addr,
            expected_token_contract: token_addr,
            expected_sender: Some(depositor),
            recipient,
            min_amount: U256::from(1_000u64),
        };

        // 1. Authentic deposit mint succeeds
        let minted = ledger
            .mint_deposit_atomic_u256(args.clone(), &mut nullifiers)
            .expect("Authentic atomic deposit mint must succeed");
        assert_eq!(minted, amount);
        assert_eq!(
            ledger.get_balance(&token_addr, &recipient),
            2_500_000_000_000_000_000u128
        );
        assert_eq!(
            ledger.get_total_supply(&token_addr),
            2_500_000_000_000_000_000u128
        );

        // 2. Replay rejected by nullifier
        let replay = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
        assert_eq!(replay, Err(ReceiverError::AlreadyClaimed));
    }

    #[test]
    fn test_erc20_mint_deposit_atomic_rejects_malicious_deposit_contract() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let authentic_locker = [0xaa; 20];
        let malicious_locker = [0x99; 20]; // Attacker contract emitting DepositERC20
        let token_addr = [0x11; 20];
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
        let depositor = [0x22; 20];
        let recipient = [0x33; 32];
        let amount = U256::from(1_000_000_000u64);
        let nonce = 1u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
            Address::from(malicious_locker),
            Address::from(token_addr),
            Address::from(depositor),
            recipient,
            amount,
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
            target: ProofTarget::Erc20Deposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract: Address::from(malicious_locker),
                token_contract: Address::from(token_addr),
                sender: Address::from(depositor),
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let args = AtomicErc20ClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: authentic_locker, // Expects canonical locker
            expected_token_contract: token_addr,
            expected_sender: Some(depositor),
            recipient,
            min_amount: U256::from(1_000u64),
        };

        // Rejected because deposit_contract does not match expected_deposit_contract!
        let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
        assert_eq!(
            err,
            Err(ReceiverError::DepositContractMismatch {
                expected: authentic_locker,
                actual: malicious_locker,
            })
        );
        assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
        assert_eq!(ledger.get_total_supply(&token_addr), 0);
    }

    #[test]
    fn test_erc20_mint_deposit_atomic_overflow_fails_without_consuming_nullifier() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let locker_addr = [0xaa; 20];
        let token_addr = [0x11; 20];
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, locker_addr);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
        let depositor = [0x22; 20];
        let recipient = [0x33; 32];
        // Amount exceeding u128::MAX (2^128)
        let amount = U256::from(u128::MAX) + U256::from(1u64);
        let nonce = 1u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
            Address::from(locker_addr),
            Address::from(token_addr),
            Address::from(depositor),
            recipient,
            amount,
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
            target: ProofTarget::Erc20Deposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract: Address::from(locker_addr),
                token_contract: Address::from(token_addr),
                sender: Address::from(depositor),
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let args = AtomicErc20ClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: locker_addr,
            expected_token_contract: token_addr,
            expected_sender: Some(depositor),
            recipient,
            min_amount: U256::from(1_000u64),
        };

        let err = ledger.mint_deposit_atomic_u256(args, &mut nullifiers);
        assert_eq!(err, Err(ReceiverError::Overflow));
        // Verify nullifiers remain clean (no burned or orphan nullifier state)
        assert!(!nullifiers.is_used(&[0u8; 32]));
        assert_eq!(ledger.get_balance(&token_addr, &recipient), 0);
    }

    #[test]
    fn test_erc20_mint_deposit_atomic_rejects_untrusted_locker_and_zero_address() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let authentic_locker = [0xaa; 20]; // Default Mainnet canonical locker
        let fake_locker = [0x77; 20];
        let token_addr = [0x11; 20];
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, token_addr);
        let depositor = [0x22; 20];
        let recipient = [0x33; 32];
        let amount = U256::from(500_000u64);
        let nonce = 1u64;

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
            Address::from(authentic_locker),
            Address::from(token_addr),
            Address::from(depositor),
            recipient,
            amount,
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
            target: ProofTarget::Erc20Deposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract: Address::from(authentic_locker),
                token_contract: Address::from(token_addr),
                sender: Address::from(depositor),
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        // 1. Zero address expected_deposit_contract strictly rejected (no bypass)
        let zero_addr_args = AtomicErc20ClaimArgsU256 {
            instance: instance.clone(),
            header: header.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: proof.clone(),
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: [0u8; 20],
            expected_token_contract: token_addr,
            expected_sender: Some(depositor),
            recipient,
            min_amount: U256::from(100u64),
        };
        let err_zero = ledger.mint_deposit_atomic_u256(zero_addr_args, &mut nullifiers);
        assert_eq!(err_zero, Err(ReceiverError::DepositBackingRequired));

        // 2. Caller-supplied fake expected locker rejected against program-owned configuration
        let fake_args = AtomicErc20ClaimArgsU256 {
            instance: instance.clone(),
            header: header.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: proof.clone(),
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: fake_locker,
            expected_token_contract: token_addr,
            expected_sender: Some(depositor),
            recipient,
            min_amount: U256::from(100u64),
        };
        let err_fake = ledger.mint_deposit_atomic_u256(fake_args, &mut nullifiers);
        assert_eq!(
            err_fake,
            Err(ReceiverError::DepositContractMismatch {
                expected: authentic_locker,
                actual: fake_locker,
            })
        );
    }

    #[test]
    fn test_erc20_mint_deposit_atomic_enforces_token_allowlist() {
        use alloy_primitives::{Address, U256};
        use mosoo_core::inclusion::test_helpers::build_test_deposit_erc20_proof;
        use mosoo_core::inclusion::{ProofTarget, StateProof};
        use mosoo_core::types::{HeaderRecord, InstanceAccount, Predicate, SyncCommittee};

        let mut ledger = Erc20Ledger::new();
        let mut nullifiers = NullifierSet::new();

        let authentic_locker = [0xaa; 20];
        let allowed_token = [0x11; 20];
        let forbidden_token = [0x99; 20];
        let depositor = [0x22; 20];
        let recipient = [0x33; 32];
        let amount = U256::from(500_000u64);
        let nonce = 1u64;

        // Configure allowlist: only allowed_token is permitted on Mainnet
        ledger.register_trusted_locker(ETH_MAINNET_CHAIN_ID, authentic_locker);
        ledger.allow_token(ETH_MAINNET_CHAIN_ID, allowed_token);

        let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
            Address::from(authentic_locker),
            Address::from(forbidden_token),
            Address::from(depositor),
            recipient,
            amount,
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
            target: ProofTarget::Erc20Deposit {
                tx_index: 0,
                log_index: 0,
                deposit_contract: Address::from(authentic_locker),
                token_contract: Address::from(forbidden_token),
                sender: Address::from(depositor),
                recipient,
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: Some(proof_nodes),
            account_value: None,
            storage_value: None,
            receipt_value: Some(receipt_rlp),
        };

        let forbidden_args = AtomicErc20ClaimArgsU256 {
            instance,
            header,
            header_history_branch: None,
            historical_execution_proof: None,
            proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: authentic_locker,
            expected_token_contract: forbidden_token,
            expected_sender: Some(depositor),
            recipient,
            min_amount: U256::from(100u64),
        };

        let err = ledger.mint_deposit_atomic_u256(forbidden_args, &mut nullifiers);
        assert_eq!(
            err,
            Err(ReceiverError::TokenNotAllowed(
                forbidden_token,
                ETH_MAINNET_CHAIN_ID
            ))
        );
        assert_eq!(ledger.get_balance(&forbidden_token, &recipient), 0);
    }
}
