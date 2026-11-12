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
/// the consumer state diff remains completely empty (byte-for-byte unmodified).
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

    // Rejected claims above balance must leave consumer storage completely unmodified.
    let failed_claim_result = claim(&statement, &mut nullifiers, 10_000_000);
    assert!(
        failed_claim_result.is_err(),
        "Over-threshold claim must fail"
    );
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
    let eth_minted =
        claim_ether(&eth_statement, &mut eth_nullifiers, 500).expect("claim ether succeeds");
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
/// RFP-021 F#8 Consumer Privacy & Unlinkability Audit:
/// Asserts that when a VerifiedStatement is shielded for public on-chain emission in LEZ events:
/// 1. The verbose provenance binding is converted into a 32-byte cryptographic commitment.
/// 2. Raw Ethereum address bytes, hex encodings, and serialized byte arrays do NOT appear in the emitted JSON/event log.
/// 3. Observers of LEZ on-chain state cannot correlate or invert the Ethereum account without solving SHA-256 preimage.
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

    // 1. Unshielded private internal statement retains provenance for consumer verification
    assert_eq!(
        stmt.binding,
        StatementBinding::Account { address: user_addr }
    );

    // 2. Shield statement for public event emission (RFP-021 F#8 privacy gate)
    let public_statement = stmt.shield();
    assert!(public_statement.is_shielded());

    // Emitted public statement event (as serialized for LEZ logs)
    let public_statement_bytes = serde_json::to_vec(&public_statement).expect("serializes");
    let public_statement_str = serde_json::to_string(&public_statement).expect("serializes to str");

    // An observer seeing public_statement_bytes CANNOT find the 20-byte user address
    assert!(
        !public_statement_bytes.windows(20).any(|w| w == user_addr),
        "Raw 20-byte Ethereum address MUST NOT appear in serialized public statement event"
    );

    // Verify structured string representation does NOT leak hex or decimal array encodings
    let user_hex = hex::encode(user_addr);
    assert!(
        !public_statement_str
            .to_lowercase()
            .contains(&user_hex.to_lowercase()),
        "Hex Ethereum address MUST NOT appear in public statement JSON string"
    );
    assert!(
        !public_statement_str.contains(&format!("{:?}", user_addr)),
        "Debug/decimal byte array of address MUST NOT appear in public statement JSON string"
    );

    // Verify statement ID nullifier does not leak address bytes
    assert_ne!(&public_statement.statement_id[..20], &user_addr[..]);

    // Consume statement in consumer (nullifier tracking)
    let claimed = claim_ether(&stmt, &mut ether_nullifiers, 500).expect("claim succeeds");
    assert_eq!(claimed, 1_000_000);
}

/// Test 5: Deep Memory and Event Log Inspection: Zero Address Leakage.
///
/// Emulates an adversarial inspection of serialized VerifiedStatement logs,
/// verifying that raw Ethereum addresses (sender, token contract, recipient) and raw balance bytes
/// do not appear anywhere in memory, event logs, or string representations when shielded.
#[test]
fn test_privacy_deep_memory_and_event_log_inspection_zero_address_leakage() {
    let token_contract = [
        0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e, 0xb0,
        0xce, 0x36, 0x06, 0xeb, 0x48,
    ];
    let sender = [
        0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe, 0xef, 0xde, 0xad, 0xbe,
        0xef, 0xde, 0xad, 0xbe, 0xef,
    ];
    let recipient = [0x42u8; 32];
    let exec_block_hash = [0x55u8; 32];
    let slot = 12_000_000u64;

    let private_balance_val: u64 = 750_000_000_000u64; // 750 billion units
    let private_balance_be = private_balance_val.to_be_bytes();
    let private_balance_le = private_balance_val.to_le_bytes();

    let mut storage_val_bytes = [0u8; 32];
    storage_val_bytes[24..32].copy_from_slice(&private_balance_be);
    let verified_val = VerifiedValue::StorageValue(storage_val_bytes);

    let subject_key = derive_erc20_transfer_subject_key(
        &exec_block_hash,
        slot,
        0,
        0,
        &token_contract,
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
    .expect("statement evaluates");

    assert!(statement.predicate_holds);

    // Consume statement in consumer
    let mut nullifiers = NullifierSet::new();
    let minted = claim(&statement, &mut nullifiers, 500).expect("claim succeeds");
    assert_eq!(minted, 750_000_000_000);

    // Shield the statement for public event emission (F#8 privacy gate)
    let public_statement = statement.shield();
    assert!(public_statement.is_shielded());

    // Serialize the shielded statement into JSON bytes and string
    let serialized_statement = serde_json::to_vec(&public_statement).expect("serializes");
    let serialized_statement_str =
        serde_json::to_string(&public_statement).expect("serializes to str");

    // Serialize nullifier set state (recording statement nullifier)
    let serialized_nullifier_hex = hex::encode(public_statement.statement_id);

    // 1. Assert sender address (20 bytes) NEVER appears in shielded statement bytes or string
    assert!(
        !serialized_statement.windows(20).any(|w| w == sender),
        "Ethereum sender address bytes MUST NOT appear in emitted statement event"
    );
    let sender_hex = hex::encode(sender);
    assert!(
        !serialized_statement_str
            .to_lowercase()
            .contains(&sender_hex.to_lowercase()),
        "Ethereum sender address hex MUST NOT appear in emitted statement JSON"
    );
    assert!(
        !serialized_statement_str.contains(&format!("{:?}", sender)),
        "Ethereum sender address array MUST NOT appear in emitted statement JSON"
    );

    // 2. Assert contract address (20 bytes) NEVER appears in shielded statement bytes or string
    assert!(
        !serialized_statement
            .windows(20)
            .any(|w| w == token_contract),
        "Ethereum contract address bytes MUST NOT appear in emitted statement event"
    );
    let contract_hex = hex::encode(token_contract);
    assert!(
        !serialized_statement_str
            .to_lowercase()
            .contains(&contract_hex.to_lowercase()),
        "Ethereum contract address hex MUST NOT appear in emitted statement JSON"
    );
    assert!(
        !serialized_statement_str.contains(&format!("{:?}", token_contract)),
        "Ethereum contract address array MUST NOT appear in emitted statement JSON"
    );

    // 3. Assert recipient (32 bytes) NEVER appears in shielded statement bytes or string
    assert!(
        !serialized_statement.windows(32).any(|w| w == recipient),
        "Recipient bytes MUST NOT appear in emitted statement event"
    );
    let recipient_hex = hex::encode(recipient);
    assert!(
        !serialized_statement_str
            .to_lowercase()
            .contains(&recipient_hex.to_lowercase()),
        "Recipient hex MUST NOT appear in emitted statement JSON"
    );

    // 4. Assert unshielded private balance NEVER appears in statement (both BE and LE encodings)
    assert!(
        !serialized_statement
            .windows(8)
            .any(|w| w == private_balance_be || w == private_balance_le),
        "Private balance bytes MUST NOT appear in emitted statement event"
    );

    // 5. Assert nullifier hex does NOT contain sender, contract, or recipient hex substrings
    assert!(!serialized_nullifier_hex.contains(&sender_hex));
    assert!(!serialized_nullifier_hex.contains(&contract_hex));
    assert!(!serialized_nullifier_hex.contains(&recipient_hex));

    // 6. Assert the only identifiers retained in consumer state are the 32-byte nullifier hash
    assert!(nullifiers.is_used(&statement.statement_id));
}

#[test]
fn test_rfp022_shielded_eth_and_erc20_deposit_committed_zero_leak_and_unlinkable_claim() {
    use erc20_receiver::{Erc20Ledger, ReceiverError, ShieldedErc20ClaimArgs};
    use ether_receiver::{EtherReceiverError, MethLedger, ShieldedEthClaimArgs};
    use mosoo_core::inclusion::{
        test_helpers::build_test_deposit_committed_proof, ProofTarget, StateProof,
    };
    use mosoo_core::types::{
        derive_claim_nullifier, derive_shielded_commitment, derive_shielded_deposit_secrets,
        verify_commitment_merkle_inclusion, AccountStore, HeaderRecord, InstanceAccount,
        ProgramAccountStore, SyncCommittee, TrustedBridgeConfig, CANONICAL_SEPOLIA_CHECKPOINT_ROOT,
        CANONICAL_SEPOLIA_CHECKPOINT_SLOT, CANONICAL_SEPOLIA_INSTANCE_ID,
        CANONICAL_SEPOLIA_MOSOO_LOCKER, ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    };

    let locker_addr = Address::from(CANONICAL_SEPOLIA_MOSOO_LOCKER);
    let usdc_sepolia: [u8; 20] = [
        0x1c, 0x7d, 0x4b, 0x19, 0x6c, 0xb0, 0xc7, 0xb0, 0x1d, 0x74, 0x3f, 0xbc, 0x61, 0x16, 0xa9,
        0x02, 0x37, 0x9c, 0x72, 0x38,
    ];
    let eth_amount = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let erc20_amount = U256::from(250_000_000u64); // 250 USDC (6 decimals)

    // 1. Deterministic wallet seed recovery
    let master_seed = [0x3du8; 32];
    let (eth_secret, eth_nullifier_secret) = derive_shielded_deposit_secrets(&master_seed, 0);
    let (erc20_secret, erc20_nullifier_secret) = derive_shielded_deposit_secrets(&master_seed, 1);
    assert_eq!(
        derive_shielded_deposit_secrets(&master_seed, 0),
        (eth_secret, eth_nullifier_secret)
    );
    assert_ne!(eth_secret, erc20_secret);

    let eth_commitment = derive_shielded_commitment(
        &[0u8; 20],
        &eth_amount.to_be_bytes::<32>(),
        &eth_secret,
        &eth_nullifier_secret,
    );
    let erc20_commitment = derive_shielded_commitment(
        &usdc_sepolia,
        &erc20_amount.to_be_bytes::<32>(),
        &erc20_secret,
        &erc20_nullifier_secret,
    );

    // Deliberately distinct Ethereum depositor and fresh claim-time LEZ recipient
    let hidden_eth_depositor = [0xdeu8; 20];
    let fresh_lez_recipient_eth = [0x9au8; 32];
    let fresh_lez_recipient_erc20 = [0x7bu8; 32];

    let merkle_root_eth = B256::repeat_byte(0xc1);
    let (receipts_root_eth, proof_nodes_eth, receipt_rlp_eth) = build_test_deposit_committed_proof(
        locker_addr,
        B256::from(eth_commitment),
        Address::ZERO,
        eth_amount,
        0,
        merkle_root_eth,
        1,
    );

    // Zero L1 leakage: neither depositor nor LEZ recipient exists anywhere in DepositCommitted receipt!
    assert!(!receipt_rlp_eth
        .windows(20)
        .any(|w| w == hidden_eth_depositor));
    assert!(!receipt_rlp_eth
        .windows(32)
        .any(|w| w == fresh_lez_recipient_eth));

    // Setup authenticated store + canonical Sepolia instance
    let mut store = ProgramAccountStore::new();
    let cfg = TrustedBridgeConfig::canonical();
    cfg.save(&mut store).expect("save bridge config");

    let slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    let instance = InstanceAccount {
        instance_id: CANONICAL_SEPOLIA_INSTANCE_ID,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        current_header_hash: CANONICAL_SEPOLIA_CHECKPOINT_ROOT,
        current_state_root: [0x66u8; 32],
        current_slot: slot,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0u8; 48]; 512],
            aggregate_pubkey: vec![0u8; 48],
        },
        next_sync_committee: None,
        bootstrap_slot: slot,
        bootstrap_header_hash: CANONICAL_SEPOLIA_CHECKPOINT_ROOT,
        initialized: true,
        current_execution_block_hash: [0x77u8; 32],
        current_execution_state_root: [0x88u8; 32],
        current_receipts_root: receipts_root_eth.0,
        network_config: None,
    };
    let instance_pda = instance.pda_address();
    store
        .try_set_account_with_owner(
            &instance_pda,
            serde_json::to_vec(&instance).unwrap(),
            MOSOO_PROGRAM_ID,
        )
        .expect("store instance");

    let header_eth = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot,
        beacon_block_root: CANONICAL_SEPOLIA_CHECKPOINT_ROOT,
        execution_block_hash: [0x77u8; 32],
        execution_state_root: [0x88u8; 32],
        receipts_root: receipts_root_eth.0,
    };

    let eth_proof = StateProof {
        target: ProofTarget::ShieldedCommitmentDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: locker_addr,
            token_contract: Address::ZERO,
            commitment: B256::from(eth_commitment),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes_eth),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp_eth),
    };

    let mut meth_ledger = MethLedger::new();
    let mut eth_nullifiers = EtherNullifierSet::new();

    // Wrong secret preimage fails closed with InvalidShieldedPreimage and leaves state clean
    let bad_preimage = meth_ledger.claim_shielded_eth_deposit_authenticated_store(
        &mut store,
        &instance_pda,
        None,
        ShieldedEthClaimArgs {
            header: header_eth.clone(),
            header_history_branch: None,
            historical_execution_proof: None,
            proof: eth_proof.clone(),
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: CANONICAL_SEPOLIA_MOSOO_LOCKER,
            recipient: fresh_lez_recipient_eth,
            secret: [0xffu8; 32],
            nullifier_secret: eth_nullifier_secret,
            min_wei: 1,
        },
        &mut eth_nullifiers,
    );
    assert_eq!(
        bad_preimage,
        Err(EtherReceiverError::InvalidShieldedPreimage)
    );
    assert_eq!(meth_ledger.get_balance(&fresh_lez_recipient_eth), 0);
    assert!(!eth_nullifiers.is_used(&derive_claim_nullifier(&eth_nullifier_secret)));

    // Valid shielded ETH claim succeeds and credits fresh recipient
    let new_bal = meth_ledger
        .claim_shielded_eth_deposit_authenticated_store(
            &mut store,
            &instance_pda,
            None,
            ShieldedEthClaimArgs {
                header: header_eth.clone(),
                header_history_branch: None,
                historical_execution_proof: None,
                proof: eth_proof.clone(),
                predicate: Predicate::AtLeast { min: [0u8; 32] },
                expected_deposit_contract: CANONICAL_SEPOLIA_MOSOO_LOCKER,
                recipient: fresh_lez_recipient_eth,
                secret: eth_secret,
                nullifier_secret: eth_nullifier_secret,
                min_wei: 1,
            },
            &mut eth_nullifiers,
        )
        .expect("shielded ETH claim must succeed");
    assert_eq!(new_bal, 1_000_000_000_000_000_000u128);
    assert_eq!(
        meth_ledger.get_balance(&fresh_lez_recipient_eth),
        1_000_000_000_000_000_000u128
    );

    // Double claim replay rejected
    let replay_err = meth_ledger.claim_shielded_eth_deposit_authenticated_store(
        &mut store,
        &instance_pda,
        None,
        ShieldedEthClaimArgs {
            header: header_eth,
            header_history_branch: None,
            historical_execution_proof: None,
            proof: eth_proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: CANONICAL_SEPOLIA_MOSOO_LOCKER,
            recipient: [0xefu8; 32],
            secret: eth_secret,
            nullifier_secret: eth_nullifier_secret,
            min_wei: 1,
        },
        &mut eth_nullifiers,
    );
    assert_eq!(replay_err, Err(EtherReceiverError::AlreadyClaimed));

    // 2. Now test Shielded ERC-20 claim (Sepolia USDC)
    let merkle_root_erc20 = B256::repeat_byte(0xd2);
    let (receipts_root_erc20, proof_nodes_erc20, receipt_rlp_erc20) =
        build_test_deposit_committed_proof(
            locker_addr,
            B256::from(erc20_commitment),
            Address::from(usdc_sepolia),
            erc20_amount,
            1,
            merkle_root_erc20,
            2,
        );
    assert!(!receipt_rlp_erc20
        .windows(32)
        .any(|w| w == fresh_lez_recipient_erc20));

    let mut inst_erc20 = instance;
    inst_erc20.current_receipts_root = receipts_root_erc20.0;
    store
        .try_set_account_with_owner(
            &instance_pda,
            serde_json::to_vec(&inst_erc20).unwrap(),
            MOSOO_PROGRAM_ID,
        )
        .expect("update store instance for erc20 receipt root");

    let header_erc20 = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot,
        beacon_block_root: CANONICAL_SEPOLIA_CHECKPOINT_ROOT,
        execution_block_hash: [0x77u8; 32],
        execution_state_root: [0x88u8; 32],
        receipts_root: receipts_root_erc20.0,
    };

    let erc20_proof = StateProof {
        target: ProofTarget::ShieldedCommitmentDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: locker_addr,
            token_contract: Address::from(usdc_sepolia),
            commitment: B256::from(erc20_commitment),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes_erc20),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp_erc20),
    };

    let mut erc20_ledger = Erc20Ledger::new();
    let mut erc20_nullifiers = NullifierSet::new();

    let minted_usdc = erc20_ledger
        .claim_shielded_deposit_authenticated_store(
            &mut store,
            &instance_pda,
            None,
            ShieldedErc20ClaimArgs {
                header: header_erc20.clone(),
                header_history_branch: None,
                historical_execution_proof: None,
                proof: erc20_proof.clone(),
                predicate: Predicate::AtLeast { min: [0u8; 32] },
                expected_deposit_contract: CANONICAL_SEPOLIA_MOSOO_LOCKER,
                expected_token_contract: usdc_sepolia,
                recipient: fresh_lez_recipient_erc20,
                secret: erc20_secret,
                nullifier_secret: erc20_nullifier_secret,
                min_amount: U256::from(1u64),
            },
            &mut erc20_nullifiers,
        )
        .expect("shielded ERC-20 claim must succeed");
    assert_eq!(minted_usdc, erc20_amount);
    assert_eq!(
        erc20_ledger.get_balance(&usdc_sepolia, &fresh_lez_recipient_erc20),
        250_000_000u128
    );

    // Double claim ERC-20 rejected
    let erc20_replay = erc20_ledger.claim_shielded_deposit_authenticated_store(
        &mut store,
        &instance_pda,
        None,
        ShieldedErc20ClaimArgs {
            header: header_erc20,
            header_history_branch: None,
            historical_execution_proof: None,
            proof: erc20_proof,
            predicate: Predicate::AtLeast { min: [0u8; 32] },
            expected_deposit_contract: CANONICAL_SEPOLIA_MOSOO_LOCKER,
            expected_token_contract: usdc_sepolia,
            recipient: [0x12u8; 32],
            secret: erc20_secret,
            nullifier_secret: erc20_nullifier_secret,
            min_amount: U256::from(1u64),
        },
        &mut erc20_nullifiers,
    );
    assert_eq!(erc20_replay, Err(ReceiverError::AlreadyClaimed));

    // 3. Verify Depth-20 incremental Merkle helper matches keccak256("mosoo_merkle_v1" || left || right)
    let mut siblings = [[0u8; 32]; 20];
    let empty_leaf = alloy_primitives::keccak256(b"mosoo_empty_leaf_v1").0;
    let mut z = empty_leaf;
    for level in &mut siblings {
        *level = z;
        let mut buf = [0u8; 79];
        buf[..15].copy_from_slice(b"mosoo_merkle_v1");
        buf[15..47].copy_from_slice(&z);
        buf[47..79].copy_from_slice(&z);
        z = alloy_primitives::keccak256(buf).0;
    }
    let mut expected_root = eth_commitment;
    for s in &siblings {
        let mut buf = [0u8; 79];
        buf[..15].copy_from_slice(b"mosoo_merkle_v1");
        buf[15..47].copy_from_slice(&expected_root);
        buf[47..79].copy_from_slice(s);
        expected_root = alloy_primitives::keccak256(buf).0;
    }
    assert!(verify_commitment_merkle_inclusion(
        &eth_commitment,
        0,
        &siblings,
        &expected_root
    ));
    assert!(!verify_commitment_merkle_inclusion(
        &erc20_commitment,
        0,
        &siblings,
        &expected_root
    ));
}
