//! Predicate engine for evaluating conditions over verified Ethereum state.

use sha2::{Digest, Sha256};

use crate::error::MosooError;
use crate::inclusion::VerifiedValue;
use crate::types::{Predicate, VerifiedStatement};

/// Evaluate a `Predicate` over a `VerifiedValue` and produce a `VerifiedStatement`.
///
/// The `statement_id` is derived deterministically from:
/// `sha256(chain_id LE || subject_key_32 || proof_type_tag || value_bytes || predicate_bytes)`.
/// Binding to the exact on-chain target (account address or contract+storage slot) ensures that
/// proving the same balance across different block slots still maps to the identical nullifier,
/// preventing duplicate cross-slot claim attacks.
///
/// # Examples
///
/// ```
/// use mosoo_core::predicate;
/// use mosoo_core::types::Predicate;
/// use mosoo_core::inclusion::VerifiedValue;
/// use alloy_primitives::U256;
///
/// let pred = Predicate::AtLeast { min: [0u8; 32] };
/// let val = VerifiedValue::EthBalance(U256::from(100u64));
/// let statement = predicate::evaluate(&pred, &val, 1, [0xaa; 32], 0).unwrap();
/// assert!(statement.predicate_holds);
/// ```
pub fn evaluate(
    predicate: &Predicate,
    value: &VerifiedValue,
    chain_id: u64,
    subject_key: [u8; 32],
    proof_type_tag: u8,
) -> Result<VerifiedStatement, MosooError> {
    let holds = check(predicate, value)?;
    let statement_id =
        derive_statement_id(chain_id, &subject_key, proof_type_tag, value, predicate);
    Ok(VerifiedStatement {
        chain_id,
        attester_program_id: crate::types::MOSOO_PROGRAM_ID,
        statement_id,
        predicate_holds: holds,
        verified_value: value.as_bytes32(),
        subject_key,
        proof_type_tag,
        binding: crate::types::StatementBinding::default(),
    })
}

/// Evaluate a `Predicate` over a `VerifiedValue` and produce a `VerifiedStatement`.
/// Fails with `MosooError::PredicateFailed` if the condition does not hold.
pub fn evaluate_checked(
    predicate: &Predicate,
    value: &VerifiedValue,
    chain_id: u64,
    subject_key: [u8; 32],
    proof_type_tag: u8,
) -> Result<VerifiedStatement, MosooError> {
    let stmt = evaluate(predicate, value, chain_id, subject_key, proof_type_tag)?;
    if !stmt.predicate_holds {
        return Err(MosooError::PredicateFailed);
    }
    Ok(stmt)
}

/// Evaluate a `Predicate` over a `VerifiedValue` with an explicit canonical provenance `StatementBinding`.
pub fn evaluate_with_binding(
    predicate: &Predicate,
    value: &VerifiedValue,
    chain_id: u64,
    subject_key: [u8; 32],
    proof_type_tag: u8,
    binding: crate::types::StatementBinding,
) -> Result<VerifiedStatement, MosooError> {
    let holds = check(predicate, value)?;
    let statement_id =
        derive_statement_id(chain_id, &subject_key, proof_type_tag, value, predicate);
    Ok(VerifiedStatement {
        chain_id,
        attester_program_id: crate::types::MOSOO_PROGRAM_ID,
        statement_id,
        predicate_holds: holds,
        verified_value: value.as_bytes32(),
        subject_key,
        proof_type_tag,
        binding,
    })
}

const MAX_PREDICATE_DEPTH: usize = 16;

fn check(predicate: &Predicate, value: &VerifiedValue) -> Result<bool, MosooError> {
    check_inner(predicate, value, 0)
}

fn check_inner(
    predicate: &Predicate,
    value: &VerifiedValue,
    depth: usize,
) -> Result<bool, MosooError> {
    if depth > MAX_PREDICATE_DEPTH {
        return Err(MosooError::Internal(
            "predicate recursion depth exceeded maximum limit (16)".into(),
        ));
    }
    let v = value.as_bytes32();
    match predicate {
        Predicate::Equal { expected } => Ok(v == *expected),
        Predicate::AtLeast { min } => Ok(v >= *min),
        Predicate::LessThan { max } => Ok(v < *max),
        Predicate::All(subs) => {
            for sub in subs {
                if !check_inner(sub, value, depth + 1)? {
                    return Ok(false);
                }
            }
            Ok(true)
        }
        Predicate::Any(subs) => {
            for sub in subs {
                if check_inner(sub, value, depth + 1)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
    }
}

/// Derives the canonical deterministic statement identifier for verified Ethereum state.
///
/// Cryptographically binds:
/// 1. Domain-separation tag (`"mosoo_statement_v1"`).
/// 2. Target Ethereum `chain_id`.
/// 3. Canonical `subject_key` (incorporating block hash, slot, indices, and emitter for events).
/// 4. Proof type tag.
/// 5. Verified state value.
///
/// NOTE: The statement identity represents the underlying verified Ethereum state fact.
/// It is strictly invariant to predicate variations, guaranteeing that an attacker cannot
/// construct alternative predicates (e.g. AtLeast(50) vs AtLeast(60)) for the same event
/// to derive distinct statement IDs and bypass single-use nullifier checks.
/// Derives the canonical 32-byte statement identifier directly from raw Ethereum state facts:
/// `sha256("mosoo_statement_v1" || chain_id_le8 || subject_key_32 || proof_type_tag_u8 || verified_value_32)`
pub fn derive_statement_id_from_raw(
    chain_id: u64,
    subject_key: &[u8; 32],
    proof_type_tag: u8,
    verified_value: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"mosoo_statement_v1");
    h.update(chain_id.to_le_bytes());
    h.update(subject_key);
    h.update([proof_type_tag]);
    h.update(verified_value);
    h.finalize().into()
}

pub fn derive_statement_id(
    chain_id: u64,
    subject_key: &[u8; 32],
    proof_type_tag: u8,
    value: &VerifiedValue,
    _predicate: &Predicate,
) -> [u8; 32] {
    derive_statement_id_from_raw(chain_id, subject_key, proof_type_tag, &value.as_bytes32())
}

/// Derives a globally unique, collision-resistant event subject key for transaction receipt logs.
/// Incorporates block hash, slot, transaction index, log index, emitter address, and event topic.
/// This prevents cross-block event nullifier collision attacks where identical transfers
/// in different blocks would otherwise collapse into the same statement identifier.
pub fn derive_receipt_log_subject_key(
    execution_block_hash: &[u8; 32],
    slot: u64,
    tx_index: u64,
    log_index: usize,
    emitter: &[u8; 20],
    topic0: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(execution_block_hash);
    hasher.update(slot.to_be_bytes());
    hasher.update(tx_index.to_be_bytes());
    hasher.update((log_index as u64).to_be_bytes());
    hasher.update(emitter);
    hasher.update(topic0);
    hasher.finalize().into()
}

/// Derives the canonical subject key for an Ethereum native ETH deposit to a vault/contract.
///
/// Binds the execution block hash, slot, transaction index, log index, deposit contract,
/// sender Ethereum address, and recipient LEZ address into a collision-resistant 32-byte identifier.
/// This prevents nullifier collision across multiple deposits between the same parties.
pub fn derive_eth_deposit_subject_key(
    execution_block_hash: &[u8; 32],
    slot: u64,
    tx_index: u64,
    log_index: usize,
    deposit_contract: &[u8; 20],
    sender: &[u8; 20],
    recipient: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"MOSOO_ETH_DEPOSIT_V2:");
    h.update(execution_block_hash);
    h.update(slot.to_be_bytes());
    h.update(tx_index.to_be_bytes());
    h.update((log_index as u64).to_be_bytes());
    h.update(deposit_contract);
    h.update(sender);
    h.update(recipient);
    h.finalize().into()
}

/// Derives the canonical subject key for an Ethereum ERC-20 transfer.
///
/// Binds the execution block hash, slot, transaction index, log index, token contract,
/// sender Ethereum address, and recipient LEZ address into a collision-resistant 32-byte identifier.
/// This guarantees distinct nullifiers for separate transfer events between the same parties.
pub fn derive_erc20_transfer_subject_key(
    execution_block_hash: &[u8; 32],
    slot: u64,
    tx_index: u64,
    log_index: usize,
    token_contract: &[u8; 20],
    sender: &[u8; 20],
    recipient: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"MOSOO_ERC20_TRANSFER_V2:");
    h.update(execution_block_hash);
    h.update(slot.to_be_bytes());
    h.update(tx_index.to_be_bytes());
    h.update((log_index as u64).to_be_bytes());
    h.update(token_contract);
    h.update(sender);
    h.update(recipient);
    h.finalize().into()
}

/// Derives the canonical subject key for an Ethereum ERC-20 vault deposit (MosooLocker.sol).
///
/// Binds execution block hash, slot, transaction index, log index, deposit contract,
/// token contract, sender address, and recipient LEZ address into a collision-resistant 32-byte identifier.
#[allow(clippy::too_many_arguments)]
pub fn derive_erc20_deposit_subject_key(
    execution_block_hash: &[u8; 32],
    slot: u64,
    tx_index: u64,
    log_index: usize,
    deposit_contract: &[u8; 20],
    token_contract: &[u8; 20],
    sender: &[u8; 20],
    recipient: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"MOSOO_ERC20_DEPOSIT_V1:");
    h.update(execution_block_hash);
    h.update(slot.to_be_bytes());
    h.update(tx_index.to_be_bytes());
    h.update((log_index as u64).to_be_bytes());
    h.update(deposit_contract);
    h.update(token_contract);
    h.update(sender);
    h.update(recipient);
    h.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inclusion::VerifiedValue;
    use alloy_primitives::U256;

    fn val(n: u64) -> VerifiedValue {
        VerifiedValue::EthBalance(U256::from(n))
    }

    #[test]
    fn equal_predicate_matches_exact_value() {
        let mut expected = [0u8; 32];
        expected[31] = 100;
        let p = Predicate::Equal { expected };
        let subject = [0xaa; 32];
        let stmt = evaluate(&p, &val(100), 1, subject, 0).unwrap();
        assert!(stmt.predicate_holds);
    }

    #[test]
    fn equal_predicate_rejects_different_value() {
        let mut expected = [0u8; 32];
        expected[31] = 100;
        let p = Predicate::Equal { expected };
        let subject = [0xaa; 32];
        let stmt = evaluate(&p, &val(99), 1, subject, 0).unwrap();
        assert!(!stmt.predicate_holds);
    }

    #[test]
    fn at_least_predicate() {
        let mut min = [0u8; 32];
        min[31] = 50;
        let p = Predicate::AtLeast { min };
        let subject = [0xbb; 32];
        assert!(
            evaluate(&p, &val(50), 1, subject, 0)
                .unwrap()
                .predicate_holds
        );
        assert!(
            evaluate(&p, &val(100), 1, subject, 0)
                .unwrap()
                .predicate_holds
        );
        assert!(
            !evaluate(&p, &val(49), 1, subject, 0)
                .unwrap()
                .predicate_holds
        );
    }

    #[test]
    fn all_predicate() {
        let mut min = [0u8; 32];
        min[31] = 10;
        let mut max = [0u8; 32];
        max[31] = 20;
        let p = Predicate::All(vec![
            Predicate::AtLeast { min },
            Predicate::LessThan { max },
        ]);
        let s = [0xcc; 32];
        assert!(evaluate(&p, &val(15), 1, s, 0).unwrap().predicate_holds);
        assert!(!evaluate(&p, &val(9), 1, s, 0).unwrap().predicate_holds);
        assert!(!evaluate(&p, &val(20), 1, s, 0).unwrap().predicate_holds);
    }

    #[test]
    fn statement_id_is_deterministic() {
        let mut exp = [0u8; 32];
        exp[31] = 1;
        let p = Predicate::Equal { expected: exp };
        let s1 = evaluate(&p, &val(1), 1, [0x11; 32], 0).unwrap();
        let s2 = evaluate(&p, &val(1), 1, [0x11; 32], 0).unwrap();
        assert_eq!(s1.statement_id, s2.statement_id);
    }

    #[test]
    fn statement_id_differs_by_chain() {
        let mut exp = [0u8; 32];
        exp[31] = 1;
        let p = Predicate::Equal { expected: exp };
        let s1 = evaluate(&p, &val(1), 1, [0x11; 32], 0).unwrap();
        let s2 = evaluate(&p, &val(1), 11155111, [0x11; 32], 0).unwrap();
        assert_ne!(s1.statement_id, s2.statement_id);
    }

    #[test]
    fn statement_id_differs_by_subject() {
        let mut exp = [0u8; 32];
        exp[31] = 1;
        let p = Predicate::Equal { expected: exp };
        let s1 = evaluate(&p, &val(1), 1, [0x11; 32], 0).unwrap();
        let s2 = evaluate(&p, &val(1), 1, [0x22; 32], 0).unwrap();
        assert_ne!(s1.statement_id, s2.statement_id);
    }

    #[test]
    fn test_cross_block_event_identity_prevents_nullifier_collision() {
        let block_hash_a = [0x11; 32];
        let block_hash_b = [0x22; 32]; // Different block!
        let slot_a = 15_433_728;
        let slot_b = 15_433_760;
        let tx_index = 0;
        let log_index = 0;
        let emitter = [0xaa; 20];
        let topic0 = [0xdd; 32];

        // Same tx_index and log_index in different blocks
        let key_a = derive_receipt_log_subject_key(
            &block_hash_a,
            slot_a,
            tx_index,
            log_index,
            &emitter,
            &topic0,
        );
        let key_b = derive_receipt_log_subject_key(
            &block_hash_b,
            slot_b,
            tx_index,
            log_index,
            &emitter,
            &topic0,
        );

        assert_ne!(
            key_a, key_b,
            "Events at identical tx/log index in different blocks MUST produce distinct subject keys"
        );

        let pred = Predicate::AtLeast { min: [0; 32] };
        let stmt_a = evaluate(&pred, &val(100), 1, key_a, 2).unwrap();
        let stmt_b = evaluate(&pred, &val(100), 1, key_b, 2).unwrap();

        assert_ne!(
            stmt_a.statement_id, stmt_b.statement_id,
            "Statement IDs for separate block occurrences MUST NOT collide"
        );
    }

    #[test]
    fn test_statement_id_invariant_under_predicate_variation_prevents_replay() {
        let subject = [0x55; 32];
        let val = val(100);
        let chain_id = 1;
        let proof_type = 4; // ERC20 transfer

        let pred_1 = Predicate::AtLeast { min: [0u8; 32] };
        let mut min_50 = [0u8; 32];
        min_50[31] = 50;
        let pred_2 = Predicate::AtLeast { min: min_50 };
        let mut min_80 = [0u8; 32];
        min_80[31] = 80;
        let pred_3 = Predicate::AtLeast { min: min_80 };

        let stmt_1 = evaluate(&pred_1, &val, chain_id, subject, proof_type).unwrap();
        let stmt_2 = evaluate(&pred_2, &val, chain_id, subject, proof_type).unwrap();
        let stmt_3 = evaluate(&pred_3, &val, chain_id, subject, proof_type).unwrap();

        assert!(stmt_1.predicate_holds);
        assert!(stmt_2.predicate_holds);
        assert!(stmt_3.predicate_holds);

        // All three statements verify the same underlying Ethereum fact with different predicates.
        // Their statement_ids MUST be identical so an attacker cannot replay claims using varying predicates!
        assert_eq!(
            stmt_1.statement_id, stmt_2.statement_id,
            "Statement ID must be invariant to predicate changes on identical state"
        );
        assert_eq!(
            stmt_2.statement_id, stmt_3.statement_id,
            "Statement ID must be invariant to predicate changes on identical state"
        );
    }
}
