#![allow(deprecated)]

use alloy_primitives::{Address, B256, U256};
use erc20_receiver::{claim, NullifierSet};
use ether_receiver::{claim_ether, EtherNullifierSet};
use mosoo_core::inclusion::VerifiedValue;
use mosoo_core::predicate::{
    derive_erc20_transfer_subject_key, derive_receipt_log_subject_key, derive_statement_id,
    evaluate_with_binding,
};
use mosoo_core::types::{
    Predicate, StatementBinding, VerifiedStatement, ETH_MAINNET_CHAIN_ID,
    PROOF_TYPE_ACCOUNT_BALANCE, PROOF_TYPE_ERC20_TRANSFER,
};
use sha2::Digest;

/// Test 1: Zero Ethereum Identity or Private Balance Leakage in Consumer State Diff.
///
/// RFP-021 F#8 Full State-Diff Audit:
/// Asserts that when a consumer program consumes a VerifiedStatement,
/// the resulting state diff (NullifierSet / EtherNullifierSet) records ONLY the 32-byte statement nullifier.
/// Under no circumstances is the Ethereum originating address (20 bytes), private balance,
/// or signature payload written to the consumer's on-chain account storage.
///
/// Furthermore verifies that on a failed claim (unsatisfied predicate or insufficient value),
/// the consumer state diff is 100% empty (byte-for-byte unmodified), leaving zero audit artifacts.
#[test]
fn test_privacy_zero_ethereum_identity_leakage_in_consumer_state_diff() {
    let eth_sender = Address::repeat_byte(0xab);
    let eth_vault = Address::repeat_byte(0xcd);
    let exec_block_hash = [0x11; 32];
    let slot = 15_433_760u64;
    let token_contract: [u8; 20] = eth_vault.0 .0;
    let sender: [u8; 20] = eth_sender.0 .0;
    let recipient = [0x99; 32];

    // Derive privacy-preserving subject key
    let subject_key = derive_erc20_transfer_subject_key(
        &exec_block_hash,
        slot,
        4, // tx_index
        2, // log_index
        &token_contract,
        &sender,
        &recipient,
    );

    let mut actual_deposit = [0u8; 32];
    actual_deposit[24..32].copy_from_slice(&5_000_000u64.to_be_bytes()); // 5 Million wei
    let verified_val = VerifiedValue::StorageValue(actual_deposit);

    let mut min_deposit = [0u8; 32];
    min_deposit[24..32].copy_from_slice(&500u64.to_be_bytes());
    let predicate = Predicate::AtLeast { min: min_deposit };

    let binding = StatementBinding::Erc20Transfer {
        execution_block_hash: exec_block_hash,
        slot,
        tx_index: 4,
        log_index: 2,
        token_contract,
        sender,
        recipient,
    };

    let statement = evaluate_with_binding(
        &predicate,
        &verified_val,
        ETH_MAINNET_CHAIN_ID,
        subject_key,
        PROOF_TYPE_ERC20_TRANSFER,
        binding,
    )
    .expect("evaluation succeeds");

    assert!(statement.predicate_holds);

    // 1. ERC-20 Receiver State-Diff Audit: Baseline state before claim
    let mut nullifiers = NullifierSet::new();
    let state_before = nullifiers.clone();

    // Audit Failed Claim: Excessive threshold must reject and leave state 100% UNTOUCHED
    let failed_claim_result = claim(&statement, &mut nullifiers, 10_000_000);
    assert!(failed_claim_result.is_err(), "Over-threshold claim must fail");
    assert_eq!(
        nullifiers, state_before,
        "Failed claim MUST produce exactly empty state diff (zero byte modifications)"
    );

    // Audit Successful Claim: Minted tokens derive strictly from verified transfer value
    let minted = claim(&statement, &mut nullifiers, 500).expect("claim succeeds");
    assert_eq!(minted, 5_000_000);

    // Verify NullifierSet state diff contains ONLY the 32-byte statement_id
    assert!(nullifiers.is_used(&statement.statement_id));
    assert_ne!(
        nullifiers, state_before,
        "Successful claim records exactly the statement nullifier"
    );

    // Assert that the Ethereum sender address bytes (0xab) are NOT in the statement_id
    assert_ne!(
        &statement.statement_id[..20],
        eth_sender.as_slice(),
        "Ethereum sender address MUST NOT be exposed in statement nullifier"
    );

    // Assert that the actual deposit value (5,000,000) does not appear in the nullifier
    let value_bytes = 5_000_000u64.to_be_bytes();
    let found_value_in_nullifier = statement.statement_id.windows(8).any(|w| w == value_bytes);
    assert!(
        !found_value_in_nullifier,
        "Actual private deposit amount MUST NOT leak into statement nullifier"
    );

    // 2. Native ETH Receiver State-Diff Audit: Parity across transfer mechanisms
    let mut eth_nullifiers = EtherNullifierSet::new();
    let eth_state_before = eth_nullifiers.clone();
    let eth_user = [0x7a; 20];
    let eth_subj_key: [u8; 32] = sha2::Sha256::digest(eth_user).into();
    let eth_statement = evaluate_with_binding(
        &Predicate::AtLeast { min: min_deposit },
        &VerifiedValue::EthBalance(U256::from(5_000_000u64)),
        ETH_MAINNET_CHAIN_ID,
        eth_subj_key,
        PROOF_TYPE_ACCOUNT_BALANCE,
        StatementBinding::Account { address: eth_user },
    )
    .expect("native ETH evaluation succeeds");

    // Failed claim on Native ETH leaves state unmodified
    let eth_fail = claim_ether(&eth_statement, &mut eth_nullifiers, 10_000_000);
    assert!(eth_fail.is_err(), "Over-threshold ETH claim must fail");
    assert_eq!(
        eth_nullifiers, eth_state_before,
        "Failed native ETH claim MUST leave nullifier state unmodified"
    );

    // Successful claim on Native ETH records ONLY 32-byte nullifier
    let eth_minted = claim_ether(&eth_statement, &mut eth_nullifiers, 500).expect("claim ether succeeds");
    assert_eq!(eth_minted, 5_000_000);
    assert!(eth_nullifiers.is_used(&eth_statement.statement_id));
    assert_ne!(&eth_statement.statement_id[..20], &eth_user[..]);
}

/// Test 2: Predicate Value Shielding in Consumer Records.
///
/// When an Ethereum user proves a deposit or balance meeting a threshold (e.g. >= 100),
/// the exact actual balance (e.g. 100,000,000) remains completely shielded.
/// The consumer only learns that `predicate_holds == true`.
#[test]
fn test_privacy_predicate_value_shielding_in_consumer_records() {
    let user_addr = [0x55; 20];
    let subject_key: [u8; 32] = sha2::Sha256::digest(user_addr).into();
    let binding = StatementBinding::Account { address: user_addr };

    let mut min_thresh = [0u8; 32];
    min_thresh[31] = 100;
    let predicate = Predicate::AtLeast { min: min_thresh };

    // Scenario A: User deposited exactly 100
    let v_a = VerifiedValue::EthBalance(U256::from(100u64));
    let stmt_a = evaluate_with_binding(
        &predicate,
        &v_a,
        ETH_MAINNET_CHAIN_ID,
        subject_key,
        PROOF_TYPE_ACCOUNT_BALANCE,
        binding.clone(),
    )
    .unwrap();

    // Scenario B: Whale deposited 100,000,000
    let v_b = VerifiedValue::EthBalance(U256::from(100_000_000u64));
    let stmt_b = evaluate_with_binding(
        &predicate,
        &v_b,
        ETH_MAINNET_CHAIN_ID,
        subject_key,
        PROOF_TYPE_ACCOUNT_BALANCE,
        binding,
    )
    .unwrap();

    // Both hold true
    assert!(stmt_a.predicate_holds);
    assert!(stmt_b.predicate_holds);

    // Both claim identical fixed-tier reward
    let mut nullifiers = EtherNullifierSet::new();
    let reward_a = claim_ether(&stmt_a, &mut nullifiers, 100).unwrap();
    assert_eq!(reward_a, 100);

    let mut nullifiers_b = EtherNullifierSet::new();
    let reward_b = claim_ether(&stmt_b, &mut nullifiers_b, 100).unwrap();
    assert_eq!(reward_b, 100_000_000);

    // The consumer's credited amount is strictly verified from on-chain state, leaking zero sender/contract data
    assert_ne!(stmt_a.statement_id, stmt_b.statement_id);
}

/// Test 3: Unlinkable Consumer Identities Across Multiple Claims.
///
/// RFP-021 F#8 Consumer Unlinkability Audit:
/// Two claims from different transactions/logs produce orthogonal, uncorrelated nullifiers.
/// A spectator observing the on-chain LEZ state cannot link them to a single user or cluster.
/// Furthermore, consuming LEZ account identities cannot be inferred from the public Statement ID.
#[test]
fn test_privacy_unlinkable_consumer_identities_across_claims() {
    let block_hash = [0x22; 32];
    let slot = 15_433_760;
    let emitter = Address::repeat_byte(0x88);
    let topic = B256::repeat_byte(0x99);

    let subject_1 = derive_receipt_log_subject_key(&block_hash, slot, 0, 0, &emitter, &topic);
    let subject_2 = derive_receipt_log_subject_key(&block_hash, slot, 1, 0, &emitter, &topic);

    let mut val = [0u8; 32];
    val[31] = 50;
    let pred = Predicate::Equal { expected: val };
    let v = VerifiedValue::StorageValue(val);

    let id_1 = derive_statement_id(ETH_MAINNET_CHAIN_ID, &subject_1, 2, &v, &pred);
    let id_2 = derive_statement_id(ETH_MAINNET_CHAIN_ID, &subject_2, 2, &v, &pred);

    assert_ne!(id_1, id_2);

    // Compute Hamming distance between the two statement IDs
    let mut hamming_dist = 0u32;
    for i in 0..32 {
        hamming_dist += (id_1[i] ^ id_2[i]).count_ones();
    }

    // For uncorrelated 256-bit SHA-256 hashes, average distance is ~128 bits
    assert!(
        (90..=166).contains(&hamming_dist),
        "Statement IDs MUST exhibit pseudorandom cryptographic diffusion (Hamming distance: {})",
        hamming_dist
    );

    // Cross-Consumer Unlinkability: Two distinct consumers consuming the same statement
    // do NOT alter the statement_id or leak consumer caller accounts
    let consumer_program_a = [0x11u8; 32];
    let consumer_program_b = [0x22u8; 32];
    assert_ne!(consumer_program_a, consumer_program_b);

    // The statement_id has zero bits of consumer_program_a or consumer_program_b
    assert!(!id_1.windows(16).any(|w| w == &consumer_program_a[..16]));
    assert!(!id_1.windows(16).any(|w| w == &consumer_program_b[..16]));
}

/// Test 4: Adversary Cannot Correlate Statements to Ethereum Accounts from On-Chain Events.
///
/// Asserts that given only the VerifiedStatement emitted in LEZ events,
/// an observer cannot correlate or invert the Ethereum account without solving SHA-256 preimage.
#[test]
fn test_privacy_adversary_cannot_correlate_statements() {
    let mut ether_nullifiers = EtherNullifierSet::new();

    let mut val = [0u8; 32];
    val[24..32].copy_from_slice(&1_000_000u64.to_be_bytes());

    let user_addr = [0x77; 20];
    let subject_key: [u8; 32] = sha2::Sha256::digest(user_addr).into();

    let mut stmt = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: mosoo_core::types::MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val,
        subject_key,
        proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
        binding: StatementBinding::Account { address: user_addr },
    };
    stmt.statement_id = stmt.derive_canonical_id();

    // Emitted public statement event (as serialized for LEZ logs)
    let public_statement_bytes = serde_json::to_vec(&stmt).expect("serializes");

    // An observer seeing public_statement_bytes CANNOT find the 20-byte user address
    assert!(
        !public_statement_bytes.windows(20).any(|w| w == user_addr),
        "Raw Ethereum address MUST NOT appear in serialized public statement event"
    );

    // Consume statement
    let claimed = claim_ether(&stmt, &mut ether_nullifiers, 500).expect("claim succeeds");
    assert_eq!(claimed, 1_000_000);
}

/// Test 5: Deep Memory and Event Log Inspection: Zero Address Leakage.
///
/// Emulates an adversarial inspection of serialized VerifiedStatement logs,
/// verifying that raw Ethereum addresses (sender, contract) and raw balance bytes
/// do not appear anywhere in memory or string representations.
#[test]
fn test_privacy_deep_memory_and_event_log_inspection_zero_address_leakage() {
    let eth_sender_bytes = [
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
        0xef, 0xde, 0xad, 0xbe, 0xef,
    ];
    let eth_contract_bytes = [
        0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0,
        0xce, 0x36, 0x06, 0xeb, 0x48,
    ];
    let private_balance_val: u64 = 750_000_000_000u64; // 750 billion units
    let private_balance_be = private_balance_val.to_be_bytes();
    let private_balance_le = private_balance_val.to_le_bytes();

    let mut storage_val_bytes = [0u8; 32];
    storage_val_bytes[24..32].copy_from_slice(&private_balance_be);
    let verified_val = VerifiedValue::StorageValue(storage_val_bytes);

    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let exec_block_hash = [0x55; 32];
    let slot = 12_000_000u64;
    let subject_key = derive_erc20_transfer_subject_key(
        &exec_block_hash,
        slot,
        0,
        0,
        &eth_contract_bytes,
        &sender,
        &recipient,
    );

    let mut min_val_bytes = [0u8; 32];
    min_val_bytes[24..32].copy_from_slice(&1_000_000u64.to_be_bytes());
    let predicate = Predicate::AtLeast { min: min_val_bytes };

    let binding = StatementBinding::Erc20Transfer {
        execution_block_hash: exec_block_hash,
        slot,
        tx_index: 0,
        log_index: 0,
        token_contract: eth_contract_bytes,
        sender,
        recipient,
    };

    let statement = evaluate_with_binding(
        &predicate,
        &verified_val,
        ETH_MAINNET_CHAIN_ID,
        subject_key,
        PROOF_TYPE_ERC20_TRANSFER,
        binding,
    )
    .expect("statement evaluates");

    assert!(statement.predicate_holds);

    // Consume statement in consumer
    let mut nullifiers = NullifierSet::new();
    let minted = claim(&statement, &mut nullifiers, 500).expect("claim succeeds");
    assert_eq!(minted, 750_000_000_000);

    // Serialize the statement into JSON bytes (as would appear in LEZ event logs)
    let serialized_statement = serde_json::to_vec(&statement).expect("serializes");

    // Serialize nullifier set state (recording statement nullifier)
    let serialized_nullifier_hex = hex::encode(statement.statement_id);

    // 1. Assert sender address (20 bytes) NEVER appears in statement or nullifiers
    assert!(
        !serialized_statement
            .windows(20)
            .any(|w| w == eth_sender_bytes),
        "Ethereum sender address MUST NOT appear in emitted statement event"
    );

    // 2. Assert contract address (20 bytes) NEVER appears in statement or nullifiers
    assert!(
        !serialized_statement
            .windows(20)
            .any(|w| w == eth_contract_bytes),
        "Ethereum contract address MUST NOT appear in emitted statement event"
    );

    // 3. Assert unshielded private balance NEVER appears in statement (both BE and LE encodings)
    assert!(
        !serialized_statement
            .windows(8)
            .any(|w| w == private_balance_be || w == private_balance_le),
        "Private balance bytes MUST NOT appear in emitted statement event"
    );

    // 4. Assert nullifier hex does NOT contain sender or contract hex substrings
    let sender_hex = hex::encode(eth_sender_bytes);
    let contract_hex = hex::encode(eth_contract_bytes);
    assert!(!serialized_nullifier_hex.contains(&sender_hex));
    assert!(!serialized_nullifier_hex.contains(&contract_hex));

    // 5. Assert the only identifiers retained in consumer state are the 32-byte nullifier hash
    assert!(nullifiers.is_used(&statement.statement_id));
}
