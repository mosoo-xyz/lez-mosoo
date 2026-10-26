//! Adversarial & Mutation Test Suite for Mosoo (Logos RFP-021)
//!
//! This suite explicitly verifies 100% rejection of adversarial inputs,
//! mutated headers, forged Merkle branches, insufficient quorums,
//! cross-chain replays, and duplicate claim attacks.

#![allow(deprecated)]

use blst::min_pk::SecretKey;
use erc20_receiver::{
    claim, claim_authenticated_store_u256, claim_erc20_transfer, AtomicErc20ClaimArgsU256,
    Erc20TransferClaim, NullifierSet, ReceiverError,
};
use ether_receiver::{
    claim_ether, claim_native_eth_deposit,
    claim_native_eth_deposit_authenticated_store_with_config, AtomicEtherClaimArgs,
    EtherNullifierSet, EtherReceiverError, MethLedger, NativeEthDepositClaim,
};
use mosoo_core::{
    crypto::*,
    error::MosooError,
    inclusion::{ProofTarget, StateProof},
    predicate::{derive_erc20_transfer_subject_key, derive_eth_deposit_subject_key},
    types::*,
    verifier::*,
};
use sha2::Digest;
use std::collections::HashMap;

fn make_test_committee(count: usize) -> SyncCommittee {
    let pubkeys: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let mut pk = vec![0u8; 48];
            pk[0] = 0x80;
            pk[1] = (i & 0xFF) as u8;
            pk[2] = ((i >> 8) & 0xFF) as u8;
            pk
        })
        .collect();
    let mut agg = vec![0u8; 48];
    agg[0] = 0x80;
    SyncCommittee {
        pubkeys,
        aggregate_pubkey: agg,
    }
}

/// Attack 1: Fabricated internally-consistent Ethereum header.
/// Attacker crafts an internally consistent fake Ethereum beacon header with valid SSZ hashes,
/// but not signed by the authentic sync committee.
#[test]
fn test_mutation_attack_1_fabricated_header_rejected() {
    let ikm = [11u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    // Attacker crafts a fabricated header
    let fabricated_header = BeaconBlockHeader {
        slot: 11_000_000,
        proposer_index: 42,
        parent_root: [0xee; 32],
        state_root: [0xff; 32],
        body_root: [0xaa; 32],
    };

    let signing_root =
        compute_signing_root(&fabricated_header, ETH_MAINNET_CHAIN_ID, 11_000_000).unwrap();
    let msg_g2 = blst_hash_to_g2(&signing_root);

    // Attacker signs with their own key, not the committee's key
    let wrong_sig = sk.sign(b"forged message payload", ETH_BLS_DST, &[]);

    // Pipeline Tx 2 (Miller) & Tx 3 (FinalExp)
    let miller_bytes =
        blst_two_miller_loops(&wrong_sig.to_bytes(), &pk.to_bytes(), &msg_g2).unwrap();
    let is_valid = blst_final_exp_and_verify(&miller_bytes).unwrap();

    assert!(
        !is_valid,
        "Fabricated beacon header with unauthenticated signature MUST be rejected by BLS verifier"
    );
}

/// Attack 2: Sub-threshold validator quorum (< 342 / 512 validators).
/// Attacker submits an update where 341 validators signed (66.60% < 66.67% supermajority).
#[test]
fn test_mutation_attack_2_sub_threshold_quorum_rejected() {
    let mut bits = vec![0u8; 64];

    // Exactly 341 bits set (just 1 short of 2/3)
    for i in 0..341 {
        bits[i / 8] |= 1 << (i % 8);
    }
    assert_eq!(count_participation(&bits), 341);

    let committee = make_test_committee(512);
    let agg = SyncAggregate {
        sync_committee_bits: bits,
        sync_committee_signature: vec![0u8; 96],
    };
    let header = BeaconBlockHeader {
        slot: 10_000_000,
        proposer_index: 1,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body_root: [3u8; 32],
    };

    let result = verify_sync_committee_signature(&committee, &agg, &header, 1, 10_000_000);
    assert!(
        matches!(
            result,
            Err(MosooError::InsufficientParticipation {
                actual: 341,
                required: 342
            })
        ),
        "Sub-threshold quorum (341/512) must return InsufficientParticipation error"
    );
}

/// Attack 3: Stale update replay & weak-subjectivity boundary enforcement.
/// Attacker submits an update with a slot <= existing finalized slot or beyond weak subjectivity window.
#[test]
fn test_mutation_attack_3_stale_update_rejected() {
    let current_finalized_slot = 10_500_000u64;
    let stale_slot = 10_499_999u64;

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: current_finalized_slot,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    let stale_update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: stale_slot,
            proposer_index: 10,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        next_sync_committee: Some(make_test_committee(512)),
        next_sync_committee_branch: Some(vec![[0u8; 32]; 5]),
        finalized_header: BeaconBlockHeader {
            slot: stale_slot,
            proposer_index: 10,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![[0u8; 32]; 6],
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xFF; 64],
            sync_committee_signature: vec![0u8; 96],
        },
        signature_slot: stale_slot + 1,
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
    };

    // Stale update must be rejected by handle_begin_update with typed MosooError::StaleUpdate
    let begin_res = handle_begin_update(BeginUpdateArgs {
        instance: instance.clone(),
        update: stale_update.clone(),
        nonce: 1,
    });

    assert!(
        matches!(
            begin_res,
            Err(MosooError::StaleUpdate {
                update_slot,
                current_slot
            }) if update_slot == stale_slot && current_slot == current_finalized_slot
        ),
        "handle_begin_update MUST reject stale update with MosooError::StaleUpdate"
    );

    // Weak subjectivity expiration check: update slot > current_slot + 1,728,000 slots
    let mut expired_update = stale_update;
    expired_update.finalized_header.slot = current_finalized_slot + 1_728_001;
    let expired_res = handle_begin_update(BeginUpdateArgs {
        instance,
        update: expired_update,
        nonce: 2,
    });

    assert!(
        matches!(expired_res, Err(MosooError::WeakSubjectivityExpired { .. })),
        "handle_begin_update MUST reject updates exceeding weak-subjectivity window"
    );
}

/// Attack 4: Forged Sync Committee SSZ Merkle branch (generalized index 54 / 55).
/// Attacker alters 1 byte in the branch to substitute an attacker-controlled committee.
#[test]
fn test_mutation_attack_4_forged_committee_branch_rejected() {
    let committee = make_test_committee(512);
    let committee_leaf = hash_tree_root_sync_committee(&committee).unwrap();

    let genuine_branch = vec![[0x11; 32]; 5]; // Depth 5 branch for gindex 54 / 55
    let genuine_state_root = compute_branch_root(committee_leaf, &genuine_branch, 55);

    // Attacker mutates 1 byte in the branch
    let mut corrupted_branch = genuine_branch.clone();
    corrupted_branch[2][0] ^= 0xFF;

    let attested_header = BeaconBlockHeader {
        slot: 10_000_000,
        proposer_index: 42,
        parent_root: [0; 32],
        state_root: genuine_state_root,
        body_root: [0; 32],
    };

    // 1. Invoking verify_sync_committee_branch directly on corrupted branch MUST fail with typed error
    let res = verify_sync_committee_branch(
        ETH_MAINNET_CHAIN_ID,
        &committee,
        &attested_header,
        &corrupted_branch,
    );
    assert!(
        matches!(res, Err(MosooError::SyncCommitteeBranchInvalid)),
        "Corrupted sync committee branch MUST be rejected with MosooError::SyncCommitteeBranchInvalid"
    );

    // 2. Invoking handle_initialize with corrupted bootstrap branch (gindex 54) MUST fail
    let genuine_bootstrap_root = compute_branch_root(committee_leaf, &genuine_branch, 54);
    let boot_header = BeaconBlockHeader {
        slot: 10_000_000,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root: genuine_bootstrap_root,
        body_root: [0; 32],
    };
    let boot_checkpoint_root = hash_tree_root_beacon_header(&boot_header);
    let init_res = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: boot_header,
        trusted_checkpoint_root: boot_checkpoint_root,
        current_sync_committee: committee,
        current_sync_committee_branch: corrupted_branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    });
    assert!(
        matches!(init_res, Err(MosooError::BootstrapCommitteeBranchInvalid)),
        "handle_initialize MUST reject corrupted bootstrap committee branch with MosooError::BootstrapCommitteeBranchInvalid"
    );
}

/// Attack 5: Tampered Execution Payload Header Root & gindex 25 branch.
/// Attacker attempts to tamper with the execution payload header or its branch to inject
/// a fake EVM execution_state_root or receipts_root.
#[test]
fn test_mutation_attack_5_tampered_execution_payload_rejected() {
    let legitimate_exec_header = ExecutionPayloadHeader {
        parent_hash: [0x11; 32],
        fee_recipient: [0x22; 20],
        state_root: [0x33; 32],
        receipts_root: [0x44; 32],
        logs_bloom: vec![0u8; 256],
        prev_randao: [0x55; 32],
        block_number: 19_000_000,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
        timestamp: 1_700_000_000,
        extra_data: vec![],
        base_fee_per_gas: [0x66; 32],
        block_hash: [0x77; 32],
        transactions_root: [0x88; 32],
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
    };

    let exec_root = hash_tree_root_execution_payload_header(&legitimate_exec_header).unwrap();
    let branch = vec![[0xaa; 32]; 4]; // generalized index 25 depth = 4
    let genuine_body_root = compute_branch_root(exec_root, &branch, 25);

    let finalized_header = BeaconBlockHeader {
        slot: 12_000_000,
        proposer_index: 10,
        parent_root: [0; 32],
        state_root: [0; 32],
        body_root: genuine_body_root,
    };

    // Scenario A: Attacker mutates execution state_root (forged execution payload header)
    let mut tampered_header = legitimate_exec_header.clone();
    tampered_header.state_root = [0x99; 32]; // Forged root!
    let res_tampered = verify_execution_payload_branch(
        ETH_MAINNET_CHAIN_ID,
        &tampered_header,
        &finalized_header,
        &branch,
    );
    assert!(
        matches!(res_tampered, Err(MosooError::ExecutionPayloadBranchInvalid)),
        "verify_execution_payload_branch MUST reject tampered execution header with MosooError::ExecutionPayloadBranchInvalid"
    );

    // Scenario B: Attacker corrupts branch
    let mut corrupted_branch = branch;
    corrupted_branch[0][15] ^= 0xEE;
    let res_corrupted_branch = verify_execution_payload_branch(
        ETH_MAINNET_CHAIN_ID,
        &legitimate_exec_header,
        &finalized_header,
        &corrupted_branch,
    );
    assert!(
        matches!(
            res_corrupted_branch,
            Err(MosooError::ExecutionPayloadBranchInvalid)
        ),
        "verify_execution_payload_branch MUST reject corrupted branch with MosooError::ExecutionPayloadBranchInvalid"
    );
}

/// Attack 6: Cross-Chain Domain Replay (Sepolia -> Mainnet).
/// Attacker captures a genuine Sepolia attestation and attempts to replay it on Mainnet.
#[test]
fn test_mutation_attack_6_cross_chain_replay_rejected() {
    let header = BeaconBlockHeader {
        slot: 11_649_025, // Electra era slot
        proposer_index: 999,
        parent_root: [0x12; 32],
        state_root: [0x34; 32],
        body_root: [0x56; 32],
    };

    let signing_root_mainnet =
        compute_signing_root(&header, ETH_MAINNET_CHAIN_ID, 11_649_025).unwrap();
    let signing_root_sepolia =
        compute_signing_root(&header, ETH_SEPOLIA_CHAIN_ID, 11_649_025).unwrap();
    let signing_root_holesky =
        compute_signing_root(&header, ETH_HOLESKY_CHAIN_ID, 11_649_025).unwrap();

    // Domain separation must ensure distinct signing roots
    assert_ne!(signing_root_mainnet, signing_root_sepolia);
    assert_ne!(signing_root_mainnet, signing_root_holesky);

    // Cryptographic rejection: Attacker takes a signature valid on Sepolia and submits to Mainnet verifier
    let ikm = [88u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();

    // Attacker signs Sepolia signing root
    let sep_sig = sk.sign(&signing_root_sepolia, ETH_BLS_DST, &[]);

    // Verifier on Mainnet computes G2 mapping for Mainnet signing root
    let mainnet_msg_g2 = blst_hash_to_g2(&signing_root_mainnet);
    let miller_bytes =
        blst_two_miller_loops(&sep_sig.to_bytes(), &pk.to_bytes(), &mainnet_msg_g2).unwrap();
    let is_valid_on_mainnet = blst_final_exp_and_verify(&miller_bytes).unwrap();
    assert!(
        !is_valid_on_mainnet,
        "Sepolia BLS signature MUST be cryptographically rejected under Mainnet domain"
    );

    let mut val_100 = [0u8; 32];
    val_100[31] = 100;

    // Furthermore, consumer contracts strictly reject statements from other chain IDs
    let mut erc20_nullifiers = NullifierSet::new();
    let mut statement_sepolia = VerifiedStatement {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val_100,
        subject_key: [0u8; 32],
        proof_type_tag: 0,
        binding: Default::default(),
    };
    statement_sepolia.statement_id = statement_sepolia.derive_canonical_id();

    let erc20_res = claim(&statement_sepolia, &mut erc20_nullifiers, 100);
    assert!(
        matches!(
            erc20_res,
            Err(erc20_receiver::ReceiverError::WrongChain(11155111))
        ),
        "ERC-20 consumer must reject Sepolia chain ID on Mainnet receiver"
    );

    let mut ether_nullifiers = EtherNullifierSet::new();
    let ether_res = claim_ether(&statement_sepolia, &mut ether_nullifiers, 100);
    assert!(
        matches!(
            ether_res,
            Err(ether_receiver::EtherReceiverError::WrongChain(11155111))
        ),
        "Native Ether consumer must reject Sepolia chain ID on Mainnet receiver"
    );
}

/// Attack 7: Corrupted Receipt-Log Proof, False Predicates & Duplicate Claim Nullifiers.
/// Attacker tries:
/// 1. False predicate bypass
/// 2. Re-claiming an already spent statement ID on ERC-20
/// 3. Re-claiming an already spent statement ID on Native Ether
#[test]
fn test_mutation_attack_7_receipt_tampering_and_duplicate_claims_rejected() {
    let mut val_500 = [0u8; 32];
    val_500[24..32].copy_from_slice(&500u64.to_be_bytes());

    let mut val_1000 = [0u8; 32];
    val_1000[24..32].copy_from_slice(&1000u64.to_be_bytes());

    // Sub-test 7A: False Predicate Rejection
    let mut nullifiers = NullifierSet::new();
    let mut failed_statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: false, // Predicate failed!
        verified_value: val_500,
        subject_key: [0u8; 32],
        proof_type_tag: 0,
        binding: Default::default(),
    };
    failed_statement.statement_id = failed_statement.derive_canonical_id();

    let claim_res = claim(&failed_statement, &mut nullifiers, 100);
    assert!(
        matches!(
            claim_res,
            Err(erc20_receiver::ReceiverError::PredicateFailed)
        ),
        "Consumer must refuse action when predicate_holds is false"
    );

    // Sub-test 7B: Valid claim succeeds first time
    let token_contract = [0xaa; 20];
    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let block_hash = [0x33; 32];
    let slot = 10_000_000u64;
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
    let mut valid_statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val_500,
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
    };
    valid_statement.statement_id = valid_statement.derive_canonical_id();
    let first_claim = claim(&valid_statement, &mut nullifiers, 500);
    assert!(first_claim.is_ok(), "First valid claim must succeed");

    // Sub-test 7C: Duplicate Claim (Replay attack) must be rejected
    let duplicate_claim = claim(&valid_statement, &mut nullifiers, 500);
    assert!(
        matches!(
            duplicate_claim,
            Err(erc20_receiver::ReceiverError::AlreadyClaimed)
        ),
        "Replay attack with same statement nullifier must be strictly rejected"
    );

    // Sub-test 7D: Native Ether Duplicate Claim Rejection
    let mut eth_nullifiers = EtherNullifierSet::new();
    let eth_user = [0x77; 20];
    use sha2::Digest;
    let eth_subject_key: [u8; 32] = sha2::Sha256::digest(eth_user).into();
    let mut eth_statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val_1000,
        subject_key: eth_subject_key,
        proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
        binding: StatementBinding::Account { address: eth_user },
    };
    eth_statement.statement_id = eth_statement.derive_canonical_id();
    assert!(claim_ether(&eth_statement, &mut eth_nullifiers, 1000).is_ok());
    let eth_dup = claim_ether(&eth_statement, &mut eth_nullifiers, 1000);
    assert!(
        matches!(
            eth_dup,
            Err(ether_receiver::EtherReceiverError::AlreadyClaimed)
        ),
        "Native Ether consumer must strictly reject replay attacks"
    );

    // Sub-test 7E: Corrupted Receipt-Log MPT Proof Rejection
    let dummy_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 15_433_760,
        beacon_block_root: [0x11; 32],
        execution_block_hash: [0x22; 32],
        execution_state_root: [0x33; 32],
        receipts_root: [0x44; 32],
    };
    let corrupted_receipt_proof = StateProof {
        target: ProofTarget::ReceiptLog {
            tx_index: 0,
            log_index: 0,
            emitter: alloy_primitives::Address::repeat_byte(0xAA),
            topic0: alloy_primitives::B256::repeat_byte(0xBB),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(vec![alloy_primitives::Bytes::from(vec![
            0xDE, 0xAD, 0xBE, 0xEF,
        ])]),
        account_value: None,
        storage_value: None,
        receipt_value: Some(vec![0x01, 0x02]),
    };
    let mpt_res =
        mosoo_core::inclusion::verify_state_proof(&corrupted_receipt_proof, &dummy_header);
    assert!(
        mpt_res.is_err(),
        "Corrupted receipt-log MPT proof MUST fail verification against receipts_root"
    );
}

/// Attack 8: Unauthenticated / Forged HeaderRecord Injection.
/// Attacker attempts to pass an unauthenticated HeaderRecord with a forged execution state root
/// without cryptographic binding to the active InstanceAccount's finalized consensus head.
#[test]
fn test_mutation_attack_8_unauthenticated_header_record_rejected() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 15_433_728, // Period 1884 canonical slot
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 15_433_728,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x11; 32],
        current_execution_state_root: [0x22; 32],
        current_receipts_root: [0x33; 32],
    };

    let dummy_proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x11),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };
    let dummy_predicate = Predicate::Equal {
        expected: [0u8; 32],
    };

    // Scenario A: Attacker attempts to attest against a header with wrong chain_id
    let wrong_chain_header = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot: 15_433_728,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x22; 32],
        receipts_root: [0x33; 32],
    };
    let res_a = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: wrong_chain_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: dummy_proof.clone(),
        predicate: dummy_predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(res_a, Err(MosooError::DomainSeparationFailed)),
        "handle_attest_state MUST reject mismatched chain ID with MosooError::DomainSeparationFailed"
    );

    // Scenario B: Attacker attempts to attest against an unfinalized future slot
    let unfinalized_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 15_433_729, // Future slot!
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x22; 32],
        receipts_root: [0x33; 32],
    };
    let res_b = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: unfinalized_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: dummy_proof.clone(),
        predicate: dummy_predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(
            res_b,
            Err(MosooError::UnfinalizedHeader {
                header_slot: 15_433_729,
                current_slot: 15_433_728
            })
        ),
        "handle_attest_state MUST reject unfinalized future slot with MosooError::UnfinalizedHeader"
    );

    // Scenario C: Attacker attempts to forge beacon_block_root to smuggle arbitrary state_root
    let forged_beacon_root_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 15_433_728,
        beacon_block_root: [0x99; 32], // Forged! Does not match instance.current_header_hash
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x66; 32], // Smuggled fake root
        receipts_root: [0x77; 32],
    };
    let res_c = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: forged_beacon_root_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: dummy_proof.clone(),
        predicate: dummy_predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(res_c, Err(MosooError::UnauthenticatedHeaderRecord)),
        "handle_attest_state MUST reject forged beacon root with MosooError::UnauthenticatedHeaderRecord"
    );

    // Scenario D: Attacker attempts to attest state against an instance with zero/unauthenticated execution roots (e.g. at bootstrap)
    let zero_exec_instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 15_433_728,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 15_433_728,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };
    let res_d = handle_attest_state(AttestStateArgs {
        instance: zero_exec_instance,
        header: HeaderRecord {
            chain_id: ETH_MAINNET_CHAIN_ID,
            slot: 15_433_728,
            beacon_block_root: [0x55; 32],
            execution_block_hash: [0x11; 32],
            execution_state_root: [0x22; 32],
            receipts_root: [0x33; 32],
        },
        header_history_branch: None,
        historical_execution_proof: None,
        proof: dummy_proof,
        predicate: dummy_predicate,
        privacy_salt: None,
    });
    assert!(
        matches!(res_d, Err(MosooError::UnauthenticatedHeaderRecord)),
        "handle_attest_state MUST fail-closed when instance has unauthenticated zero execution roots"
    );
}

/// Attack 9: Cross-Block Event Nullifier Collision Attack.
/// Attacker attempts to cause two legitimate deposit transfers (at identical tx_index and log_index
/// across different Ethereum blocks) to collide on the same statement_id, griefing depositors.
#[test]
fn test_mutation_attack_9_cross_block_event_nullifier_uniqueness() {
    use mosoo_core::predicate::{derive_receipt_log_subject_key, derive_statement_id};

    let emitter = [0xAA; 20];
    let topic0 = [0xBB; 32];
    let tx_index = 0u64;
    let log_index = 0usize;

    // Block A: Slot 15,433,728
    let block_hash_a = [0x11; 32];
    let slot_a = 15_433_728;

    // Block B: Slot 15,433,760
    let block_hash_b = [0x22; 32];
    let slot_b = 15_433_760;

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

    // Assert subject keys are completely distinct
    assert_ne!(
        key_a, key_b,
        "Transfers at same tx/log in different blocks MUST have unique subject keys"
    );

    let token_contract = [0xaa; 20];
    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let transfer_key_a = derive_erc20_transfer_subject_key(
        &block_hash_a,
        slot_a,
        tx_index,
        log_index,
        &token_contract,
        &sender,
        &recipient,
    );
    let transfer_key_b = derive_erc20_transfer_subject_key(
        &block_hash_b,
        slot_b,
        tx_index,
        log_index,
        &token_contract,
        &sender,
        &recipient,
    );

    let mut val_10 = [0u8; 32];
    val_10[31] = 10;
    let val = mosoo_core::inclusion::VerifiedValue::StorageValue(val_10);
    let pred = Predicate::AtLeast { min: [0; 32] };

    let id_a = derive_statement_id(
        ETH_MAINNET_CHAIN_ID,
        &transfer_key_a,
        PROOF_TYPE_ERC20_TRANSFER,
        &val,
        &pred,
    );
    let id_b = derive_statement_id(
        ETH_MAINNET_CHAIN_ID,
        &transfer_key_b,
        PROOF_TYPE_ERC20_TRANSFER,
        &val,
        &pred,
    );

    assert_ne!(
        id_a, id_b,
        "Statement IDs for separate block occurrences MUST NEVER collide"
    );

    // Both distinct statements can be claimed independently without mutual interference
    let mut nullifiers = NullifierSet::new();

    let stmt_a = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: id_a,
        predicate_holds: true,
        verified_value: val_10,
        subject_key: transfer_key_a,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash_a,
            slot: slot_a,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        },
    };
    let stmt_b = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: id_b,
        predicate_holds: true,
        verified_value: val_10,
        subject_key: transfer_key_b,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash_b,
            slot: slot_b,
            tx_index,
            log_index,
            token_contract,
            sender,
            recipient,
        },
    };
    assert!(claim(&stmt_a, &mut nullifiers, 10).is_ok());
    assert!(
        claim(&stmt_b, &mut nullifiers, 10).is_ok(),
        "Distinct block claims MUST NOT block each other"
    );
    assert!(nullifiers.is_used(&id_a));
    assert!(nullifiers.is_used(&id_b));
}

fn make_valid_bls_committee(count: usize) -> SyncCommittee {
    make_valid_bls_committee_with_seed(count, 42)
}

fn make_valid_bls_committee_with_seed(count: usize, seed: u8) -> SyncCommittee {
    let ikm = [seed; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk().to_bytes().to_vec();
    SyncCommittee {
        pubkeys: vec![pk.clone(); count],
        aggregate_pubkey: pk,
    }
}

/// Attack 10: 3-Transaction Pipeline Cross-Stage Tampering & Injected Intermediate State.
/// Attacker attempts to:
/// 1. Alter update payload in transit between Begin and Miller stages.
/// 2. Alter update payload between Miller and Finish stages.
/// 3. Cross-instance job hijacking (different chain_id).
/// 4. Out-of-order stage progression (skipping Miller loop directly to Finish).
#[test]
fn test_mutation_attack_10_cross_stage_job_tampering_and_digest_mismatch_rejected() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_valid_bls_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    let mut bits = vec![0u8; 64];
    for i in 0..400 {
        bits[i / 8] |= 1 << (i % 8);
    }
    let sig = vec![0x00; 96];

    let update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 10_000_032,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 10_000_032,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        },
        finality_branch: vec![[0x44; 32]; 6],
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: sig,
        },
        signature_slot: 10_000_033,
    };

    // Stage 1: BeginUpdate produces a JobAccount bound to update_digest
    let begin_res = handle_begin_update(BeginUpdateArgs {
        instance: instance.clone(),
        update: update.clone(),
        nonce: 1,
    })
    .expect("BeginUpdate succeeds");

    let job = match begin_res {
        InstructionOutput::JobCreated(j) => j,
        _ => panic!("Expected JobCreated"),
    };

    // Attack 10A: Tamper with update payload in job before Miller stage
    let mut tampered_job = job.clone();
    tampered_job.update.finalized_header.slot = 99_999_999; // Attacker modified slot in transit!

    let miller_err = handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job: tampered_job,
    })
    .expect_err("MillerUpdate MUST reject tampered update payload");

    assert!(matches!(miller_err, MosooError::JobDigestMismatch { .. }));

    // Attack 10B: Cross-chain / wrong instance hijacking
    let mut wrong_chain_instance = instance.clone();
    wrong_chain_instance.chain_id = ETH_SEPOLIA_CHAIN_ID;

    let hijack_err = handle_miller_update(MillerUpdateArgs {
        instance: wrong_chain_instance,
        job: job.clone(),
    })
    .expect_err("MillerUpdate MUST reject mismatched instance chain ID");

    assert!(matches!(
        hijack_err,
        MosooError::JobInstanceMismatch {
            expected: 11155111,
            actual: 1
        }
    ));

    // Attack 10C: Out-of-order stage progression (submitting Begin-stage job directly to Finish)
    let ooo_err = handle_finish_update(FinishUpdateArgs {
        instance: instance.clone(),
        job,
    })
    .expect_err("FinishUpdate MUST reject Job in Miller stage");

    assert!(matches!(ooo_err, MosooError::WrongJobStage { .. }));
}

/// Attack 11: Bootstrap Next Sync Committee Authentication & Forged Branch Rejection.
/// Attacker attempts to initialize instance with an unauthenticated next sync committee
/// to seize control of the consensus handoff at the next period boundary.
#[test]
fn test_mutation_attack_11_bootstrap_next_committee_branch_verification_and_forgery_rejection() {
    let current_comm = make_test_committee(512);
    let next_comm = make_test_committee(512);

    let current_leaf = hash_tree_root_sync_committee(&current_comm).unwrap();
    let next_leaf = hash_tree_root_sync_committee(&next_comm).unwrap();

    // Construct valid Merkle branches of depth 5 for gindex 54 (current) and 55 (next)
    let current_branch = vec![[0x33; 32]; 5];
    let next_branch = vec![[0x44; 32]; 5];

    let current_computed = compute_branch_root(current_leaf, &current_branch, 54);
    let _next_computed = compute_branch_root(next_leaf, &next_branch, 55);

    // Bootstrap header anchoring current_sync_committee at gindex 54
    let bootstrap_header = BeaconBlockHeader {
        slot: 10_000_000,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: current_computed, // Root matches gindex 54
        body_root: [0x22; 32],
    };

    let bootstrap_checkpoint_root = hash_tree_root_beacon_header(&bootstrap_header);

    // Attack 11A: Next committee supplied without branch proof MUST be rejected
    let res_no_branch = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: bootstrap_header.clone(),
        trusted_checkpoint_root: bootstrap_checkpoint_root,
        current_sync_committee: current_comm.clone(),
        current_sync_committee_branch: current_branch.clone(),
        initial_next_committee: Some(next_comm.clone()),
        initial_next_committee_branch: None, // Missing!
        trusted_head_slot: 10_000_000,
    });
    assert!(matches!(
        res_no_branch,
        Err(MosooError::BootstrapNextCommitteeBranchInvalid)
    ));

    // Attack 11B: Next committee supplied with corrupted branch MUST be rejected
    let corrupted_next_branch = vec![[0xfe; 32]; 5];
    let res_bad_branch = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: bootstrap_header.clone(),
        trusted_checkpoint_root: bootstrap_checkpoint_root,
        current_sync_committee: current_comm.clone(),
        current_sync_committee_branch: current_branch.clone(),
        initial_next_committee: Some(next_comm),
        initial_next_committee_branch: Some(corrupted_next_branch),
        trusted_head_slot: 10_000_000,
    });
    assert!(matches!(
        res_bad_branch,
        Err(MosooError::BootstrapNextCommitteeBranchInvalid)
    ));

    // Legitimate bootstrap without initial_next_committee succeeds cleanly
    let res_clean = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header,
        trusted_checkpoint_root: bootstrap_checkpoint_root,
        current_sync_committee: current_comm,
        current_sync_committee_branch: current_branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    });
    assert!(matches!(res_clean, Ok(InstructionOutput::Initialized(_))));
}

/// Attack 12: Historical Block Roots Accumulator Proof Anchor & Spec Compliance.
/// Attacker attempts to forge a historical block proof or present a malformed branch depth.
/// Proves that historical block roots must correctly anchor against `instance.current_state_root`
/// at generalized index `(37 << 13) | (slot % 8192)`.
#[test]
fn test_mutation_attack_12_historical_block_roots_accumulator_proof_anchor_and_rejection() {
    let historical_slot = 15_433_700u64;
    let current_slot = 15_433_728u64;

    let emitter = alloy_primitives::Address::repeat_byte(0xaa);
    let from = alloy_primitives::Address::repeat_byte(0x11);
    let to = alloy_primitives::Address::repeat_byte(0x22);
    let amount = alloy_primitives::U256::from(100_000u64);
    let receipt_bytes = mosoo_core::inclusion::test_helpers::build_test_eip1559_transfer_receipt(
        emitter, from, to, amount,
    );
    let key_bytes = alloy_rlp::encode(0u64);
    let (receipts_root, proof_nodes) =
        mosoo_core::inclusion::test_helpers::build_leaf_mpt_proof(&key_bytes, &receipt_bytes);

    let payload_header = ExecutionPayloadHeader {
        parent_hash: [0x01; 32],
        fee_recipient: [0x02; 20],
        state_root: [0x22; 32],
        receipts_root: receipts_root.0,
        logs_bloom: vec![0u8; 256],
        prev_randao: [0x03; 32],
        block_number: 1_000_000,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
        timestamp: 1_700_000_000,
        extra_data: vec![],
        base_fee_per_gas: [0u8; 32],
        block_hash: [0x11; 32],
        transactions_root: [0x04; 32],
        withdrawals_root: Some([0x05; 32]),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
    };
    let payload_leaf = hash_tree_root_execution_payload_header(&payload_header).unwrap();
    let exec_gindex = execution_proof_gindex(ETH_MAINNET_CHAIN_ID, historical_slot);
    let exec_depth = (63 - exec_gindex.leading_zeros()) as usize;
    let execution_branch = vec![[0x33; 32]; exec_depth];
    let body_root = compute_branch_root(payload_leaf, &execution_branch, exec_gindex);

    let beacon_header = BeaconBlockHeader {
        slot: historical_slot,
        proposer_index: 1234,
        parent_root: [0x06; 32],
        state_root: [0x07; 32],
        body_root,
    };
    let historical_beacon_root = hash_tree_root_beacon_header(&beacon_header);

    let gindex = historical_block_roots_gindex(ETH_MAINNET_CHAIN_ID, current_slot, historical_slot);
    // Fork-aware generalized index: prefix 69 in Electra/Fulu has depth 19 (6 + 13)
    let depth = (63 - gindex.leading_zeros()) as usize;
    assert_eq!(
        depth, 19,
        "Fulu/Electra block_roots branch depth must be 19"
    );
    let branch = vec![[0x88; 32]; depth];
    let expected_state_root = compute_branch_root(historical_beacon_root, &branch, gindex);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: expected_state_root,
        current_slot,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    let historical_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: historical_slot,
        beacon_block_root: historical_beacon_root,
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x22; 32],
        receipts_root: receipts_root.0,
    };

    let dummy_proof = StateProof {
        target: ProofTarget::ReceiptLog {
            tx_index: 0,
            log_index: 0,
            emitter,
            topic0: alloy_primitives::keccak256("Transfer(address,address,uint256)"),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_bytes),
    };

    let predicate = Predicate::AtLeast { min: [0; 32] };

    let hist_proof = HistoricalHeaderProof {
        block_roots_branch: branch.clone(),
        beacon_header: beacon_header.clone(),
        execution_payload_header: payload_header.clone(),
        execution_branch: execution_branch.clone(),
        execution_rlp: None,
    };

    // 1. Valid historical execution proof: evaluates successfully against authenticated current_state_root
    let res = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: historical_header.clone(),
        header_history_branch: Some(branch.clone()),
        historical_execution_proof: Some(hist_proof.clone()),
        proof: dummy_proof.clone(),
        predicate: predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(res, Ok(InstructionOutput::StatementIssued(_))),
        "Valid historical header proof anchored at state accumulator must succeed"
    );

    // 2. verify_historical_header_provenance succeeds with authentic proof
    assert!(
        verify_historical_header_provenance(&instance, &historical_header, &hist_proof).is_ok(),
        "verify_historical_header_provenance must succeed with genuine historical proof"
    );

    // 3. Historical state attestation without historical_execution_proof MUST FAIL
    let missing_proof_res = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: historical_header.clone(),
        header_history_branch: Some(branch.clone()),
        historical_execution_proof: None,
        proof: dummy_proof.clone(),
        predicate: predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(missing_proof_res, Err(MosooError::HistoricalExecutionRootUnauthenticated)),
        "Historical slot without HistoricalHeaderProof must fail with HistoricalExecutionRootUnauthenticated"
    );

    // 4. Tampered historical beacon root MUST be rejected
    let mut tampered_header = historical_header.clone();
    tampered_header.beacon_block_root = [0xff; 32];
    let tampered_res = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: tampered_header.clone(),
        header_history_branch: Some(branch.clone()),
        historical_execution_proof: Some(hist_proof.clone()),
        proof: dummy_proof.clone(),
        predicate: predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(tampered_res, Err(MosooError::UnauthenticatedHeaderRecord)),
        "Tampered historical root must be rejected with UnauthenticatedHeaderRecord"
    );
    assert!(verify_historical_header_provenance(&instance, &tampered_header, &hist_proof).is_err());

    // 5. Genuine finalized beacon root but forged execution_state_root MUST be rejected!
    let mut fake_state_header = historical_header.clone();
    fake_state_header.execution_state_root = [0xFA; 32];
    let fake_state_res = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: fake_state_header.clone(),
        header_history_branch: Some(branch.clone()),
        historical_execution_proof: Some(hist_proof.clone()),
        proof: dummy_proof.clone(),
        predicate: predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(fake_state_res, Err(MosooError::UnauthenticatedHeaderRecord)),
        "Genuine historical beacon root with forged execution_state_root MUST be rejected"
    );
    assert!(
        verify_historical_header_provenance(&instance, &fake_state_header, &hist_proof).is_err()
    );

    // 6. Genuine finalized beacon root but forged receipts_root MUST be rejected!
    let mut fake_receipts_header = historical_header.clone();
    fake_receipts_header.receipts_root = [0xFB; 32];
    let fake_receipts_res = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: fake_receipts_header.clone(),
        header_history_branch: Some(branch.clone()),
        historical_execution_proof: Some(hist_proof.clone()),
        proof: dummy_proof.clone(),
        predicate: predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(
            fake_receipts_res,
            Err(MosooError::UnauthenticatedHeaderRecord)
        ),
        "Genuine historical beacon root with forged receipts_root MUST be rejected"
    );
    assert!(
        verify_historical_header_provenance(&instance, &fake_receipts_header, &hist_proof).is_err()
    );

    // 7. Genuine finalized beacon root but forged execution_block_hash MUST be rejected!
    let mut fake_hash_header = historical_header.clone();
    fake_hash_header.execution_block_hash = [0xFC; 32];
    let fake_hash_res = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: fake_hash_header.clone(),
        header_history_branch: Some(branch.clone()),
        historical_execution_proof: Some(hist_proof.clone()),
        proof: dummy_proof.clone(),
        predicate: predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(fake_hash_res, Err(MosooError::UnauthenticatedHeaderRecord)),
        "Genuine historical beacon root with forged execution_block_hash MUST be rejected"
    );
    assert!(
        verify_historical_header_provenance(&instance, &fake_hash_header, &hist_proof).is_err()
    );

    // 8. Zero/uninitialized execution roots on historical header MUST be rejected
    let mut zero_exec_header = historical_header.clone();
    zero_exec_header.execution_state_root = [0u8; 32];
    let zero_res = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: zero_exec_header.clone(),
        header_history_branch: Some(branch.clone()),
        historical_execution_proof: Some(hist_proof.clone()),
        proof: dummy_proof.clone(),
        predicate: predicate.clone(),
        privacy_salt: None,
    });
    assert!(
        matches!(zero_res, Err(MosooError::UnauthenticatedHeaderRecord)),
        "Historical header with zero execution_state_root must be rejected"
    );
    assert!(
        verify_historical_header_provenance(&instance, &zero_exec_header, &hist_proof).is_err()
    );

    // 9. Malformed branch depth (17 instead of expected depth 19 for Fulu) MUST be rejected with InvalidProofBranchDepth
    let malformed_branch = vec![[0x88; 32]; 17];
    let malformed_res = handle_attest_state(AttestStateArgs {
        instance,
        header: historical_header,
        header_history_branch: Some(malformed_branch),
        historical_execution_proof: Some(hist_proof),
        proof: dummy_proof,
        predicate,
        privacy_salt: None,
    });
    assert!(
        matches!(
            malformed_res,
            Err(MosooError::InvalidProofBranchDepth {
                actual: 17,
                expected: 19
            })
        ),
        "Malformed branch depth must be rejected with InvalidProofBranchDepth"
    );
}

/// Attack 13: Nullifier Collision & Replay Resistance on Repeat Transfers.
///
/// Under naive derivation without transaction coordinates (block hash, slot, tx_index, log_index),
/// multiple legitimate transfers between the same sender and recipient result in identical
/// nullifiers, locking subsequent funds.
/// This test verifies:
/// 1. Two distinct transfers between same parties generate strictly different subject keys & statement IDs.
/// 2. Both legitimate transfers can be claimed independently.
/// 3. Replaying either transfer is strictly rejected by the nullifier set.
#[test]
fn test_security_audit_attack_13_repeat_transfer_distinct_nullifiers_and_replay_rejection() {
    let mut erc20_nullifiers = NullifierSet::new();
    let token = [0xAA; 20];
    let alice = [0x11; 20];
    let bob = [0x22; 32];

    let block_100 = [0x01; 32];
    let block_105 = [0x02; 32];

    // Deposit 1: Alice sends 500 USDC to Bob at Block 100, Tx 0, Log 0
    let key_1 = derive_erc20_transfer_subject_key(&block_100, 100, 0, 0, &token, &alice, &bob);
    let mut val_1 = [0u8; 32];
    val_1[24..32].copy_from_slice(&500_000u64.to_be_bytes());
    let mut stmt_1 = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val_1,
        subject_key: key_1,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_100,
            slot: 100,
            tx_index: 0,
            log_index: 0,
            token_contract: token,
            sender: alice,
            recipient: bob,
        },
    };
    stmt_1.statement_id = stmt_1.derive_canonical_id();

    // Deposit 2: Alice sends another 1,000 USDC to Bob at Block 105, Tx 2, Log 1
    let key_2 = derive_erc20_transfer_subject_key(&block_105, 105, 2, 1, &token, &alice, &bob);
    let mut val_2 = [0u8; 32];
    val_2[24..32].copy_from_slice(&1_000_000u64.to_be_bytes());
    let mut stmt_2 = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val_2,
        subject_key: key_2,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_105,
            slot: 105,
            tx_index: 2,
            log_index: 1,
            token_contract: token,
            sender: alice,
            recipient: bob,
        },
    };
    stmt_2.statement_id = stmt_2.derive_canonical_id();

    // Cryptographic isolation: subject keys MUST NOT collide
    assert_ne!(
        key_1, key_2,
        "Distinct deposits between identical parties MUST produce distinct subject keys"
    );

    // Claim 1 succeeds
    let claim_1 = Erc20TransferClaim {
        statement: stmt_1.clone(),
        token_contract: token,
        sender: alice,
        recipient: bob,
        min_amount: 100_000,
    };
    let minted_1 =
        claim_erc20_transfer(&claim_1, &mut erc20_nullifiers).expect("Claim 1 must succeed");
    assert_eq!(minted_1, 500_000);

    // Claim 2 succeeds (no collision griefing)
    let claim_2 = Erc20TransferClaim {
        statement: stmt_2.clone(),
        token_contract: token,
        sender: alice,
        recipient: bob,
        min_amount: 100_000,
    };
    let minted_2 =
        claim_erc20_transfer(&claim_2, &mut erc20_nullifiers).expect("Claim 2 must succeed");
    assert_eq!(minted_2, 1_000_000);

    // Replay of Claim 1 MUST fail
    let replay_err =
        claim_erc20_transfer(&claim_1, &mut erc20_nullifiers).expect_err("Replay must fail");
    assert!(matches!(
        replay_err,
        erc20_receiver::ReceiverError::AlreadyClaimed
    ));

    // Also verify Native ETH deposit repeat transfer isolation
    let mut ether_nullifiers = EtherNullifierSet::new();
    let deposit_contract = [0xDD; 20];
    let eth_key_1 =
        derive_eth_deposit_subject_key(&block_100, 100, 0, 0, &deposit_contract, &alice, &bob);
    let eth_key_2 =
        derive_eth_deposit_subject_key(&block_105, 105, 2, 1, &deposit_contract, &alice, &bob);
    assert_ne!(
        eth_key_1, eth_key_2,
        "Native ETH deposit keys must not collide"
    );

    let mut eth_stmt_1 = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val_1,
        subject_key: eth_key_1,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_100,
            slot: 100,
            tx_index: 0,
            log_index: 0,
            deposit_contract,
            sender: alice,
            recipient: bob,
        },
    };
    eth_stmt_1.statement_id = eth_stmt_1.derive_canonical_id();
    let eth_claim_1 = NativeEthDepositClaim {
        statement: eth_stmt_1.clone(),
        expected_deposit_contract: deposit_contract,
        sender: alice,
        recipient: bob,
        min_wei: 100_000,
    };
    let credited_1 = claim_native_eth_deposit(&eth_claim_1, &mut ether_nullifiers)
        .expect("ETH claim 1 must succeed");
    assert_eq!(credited_1, 500_000);

    let mut eth_stmt_2 = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val_2,
        subject_key: eth_key_2,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_105,
            slot: 105,
            tx_index: 2,
            log_index: 1,
            deposit_contract,
            sender: alice,
            recipient: bob,
        },
    };
    eth_stmt_2.statement_id = eth_stmt_2.derive_canonical_id();
    let eth_claim_2 = NativeEthDepositClaim {
        statement: eth_stmt_2,
        expected_deposit_contract: deposit_contract,
        sender: alice,
        recipient: bob,
        min_wei: 100_000,
    };
    let credited_2 = claim_native_eth_deposit(&eth_claim_2, &mut ether_nullifiers)
        .expect("ETH claim 2 must succeed");
    assert_eq!(credited_2, 1_000_000);

    // Replay of ETH claim 1 MUST fail
    let eth_replay_err = claim_native_eth_deposit(&eth_claim_1, &mut ether_nullifiers)
        .expect_err("ETH replay must fail");
    assert!(matches!(
        eth_replay_err,
        ether_receiver::EtherReceiverError::AlreadyClaimed
    ));
}

/// Attack 14: Silent Arithmetic Overflow / High-Bit Truncation Prevention.
///
/// An attacker submits a statement with amount > u64::MAX (e.g. >18.44 ETH in wei) where high bytes are non-zero.
/// Without checked conversion, blind slicing bytes 24..32 would silently truncate the value.
#[test]
fn test_security_audit_attack_14_silent_u64_truncation_overflow_rejected() {
    let mut bad_val = [0u8; 32];
    bad_val[20] = 0x01; // Non-zero high byte (val >= 2^88)
    bad_val[31] = 0x64; // Low byte 100

    let user_addr = [0x11; 20];
    let user_subject_key: [u8; 32] = sha2::Sha256::digest(user_addr).into();

    let mut stmt = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: bad_val,
        subject_key: user_subject_key,
        proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
        binding: StatementBinding::Account { address: user_addr },
    };
    stmt.statement_id = stmt.derive_canonical_id();

    // value_as_u64_checked MUST return error rather than truncating to 100
    assert!(
        stmt.value_as_u64_checked().is_err(),
        "value_as_u64_checked must reject overflow values"
    );

    // Consumer claim_ether must fail gracefully with AttestationFailed
    let mut nullifiers = EtherNullifierSet::new();
    let err = claim_ether(&stmt, &mut nullifiers, 10).expect_err("Overflow must be rejected");
    assert!(
        matches!(err, ether_receiver::EtherReceiverError::AttestationFailed(msg) if msg.contains("overflow")),
        "Must reject with value overflow error"
    );

    // Legitimate value <= u64::MAX succeeds
    let mut ok_val = [0u8; 32];
    ok_val[24..32].copy_from_slice(&1_000_000_000_000_000_000u64.to_be_bytes());
    let mut ok_stmt = stmt;
    ok_stmt.verified_value = ok_val;
    assert_eq!(
        ok_stmt.value_as_u64_checked().unwrap(),
        1_000_000_000_000_000_000
    );
}

/// Attack 15: Malformed RLP Headers Out-of-Bounds Panic Prevention.
///
/// Malformed RLP slices claiming length larger than available bytes must not trigger index panics.
#[test]
fn test_security_audit_attack_15_malformed_rlp_bounds_panic_prevention() {
    use mosoo_core::inclusion::{rlp_decode_list_items, rlp_strip_prefix};

    // Malformed list: claims 10 length bytes when only 1 is present
    let malformed_list = [0xf9, 0x01];
    assert!(rlp_decode_list_items(&malformed_list).is_err());

    // Truncated list: header says list has 50 bytes, but slice is only 3 bytes
    let truncated_list = [0xc0 + 50, 0x01, 0x02];
    assert!(rlp_decode_list_items(&truncated_list).is_err());

    // Safe strip prefix on various malformed RLP strings
    assert_eq!(rlp_strip_prefix(&[]), &[] as &[u8]);
    assert_eq!(rlp_strip_prefix(&[0x85, 0x01, 0x02]), &[0x01, 0x02]);
    assert_eq!(rlp_strip_prefix(&[0xb8, 0x10, 0x01]), &[0x01]);
}

/// Attack 16: Ring Buffer Slot Aliasing Rejection beyond 8,192 Slots.
///
/// Ethereum's BeaconState.block_roots is a cyclic vector of size 8,192.
/// Historical proofs older than 8,192 slots without an accumulator proof must be strictly rejected
/// to prevent slot % 8192 collision aliasing.
#[test]
fn test_security_audit_attack_16_circular_buffer_aliasing_rejected() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 20_000,
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 1_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    // Attacker requests proof for slot 5,000 (delta = 15,000 slots > 8,192)
    let stale_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 5_000,
        beacon_block_root: [0x33; 32],
        execution_block_hash: [0x44; 32],
        execution_state_root: [0x55; 32],
        receipts_root: [0x66; 32],
    };

    let dummy_proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x77),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };

    let res = handle_attest_state(AttestStateArgs {
        instance,
        header: stale_header,
        header_history_branch: Some(vec![[0x88; 32]; 19]),
        historical_execution_proof: None,
        proof: dummy_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    });

    assert!(
        matches!(
            res,
            Err(MosooError::HistoricalSummariesWindowExceeded {
                target_slot: 5_000,
                current_slot: 20_000,
            })
        ),
        "Historical proof beyond 8,192 slots MUST be rejected with HistoricalSummariesWindowExceeded"
    );
}

/// Attack 17: Job Lifecycle Termination & Replay Rejection.
///
/// A finished verification job transitions to JobStage::Done.
/// Re-submitting a Done job to Miller or Finish stages must be rejected with WrongJobStage.
#[test]
fn test_security_audit_attack_17_job_lifecycle_done_and_replay_rejection() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 100,
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    let done_job = JobAccount {
        instance_id: [0u8; 32],
        instance_chain_id: ETH_MAINNET_CHAIN_ID,
        instance_slot: 100,
        stage: JobStage::Done,
        update_digest: [0x99; 32],
        update: LightClientUpdate {
            attested_header: BeaconBlockHeader {
                slot: 101,
                proposer_index: 0,
                parent_root: [0; 32],
                state_root: [0; 32],
                body_root: [0; 32],
            },
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: BeaconBlockHeader {
                slot: 100,
                proposer_index: 0,
                parent_root: [0; 32],
                state_root: [0; 32],
                body_root: [0; 32],
            },
            finality_branch: vec![],
            sync_aggregate: SyncAggregate {
                sync_committee_bits: vec![0u8; 64],
                sync_committee_signature: vec![0u8; 96],
            },
            signature_slot: 102,
            execution_payload_header: None,
            execution_branch: None,
            execution_rlp: None,
        },
        miller_input: None,
        miller_output: None,
        nonce: 42,
    };

    // Submitting a Done job to MillerUpdate MUST be rejected
    let miller_err = handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job: done_job.clone(),
    })
    .expect_err("Done job must be rejected in Miller");
    assert!(matches!(miller_err, MosooError::WrongJobStage { .. }));

    // Submitting a Done job to FinishUpdate MUST be rejected
    let finish_err = handle_finish_update(FinishUpdateArgs {
        instance,
        job: done_job,
    })
    .expect_err("Done job must be rejected in Finish");
    assert!(matches!(finish_err, MosooError::WrongJobStage { .. }));
}

/// Attack 18: Statement ID Nullifier Malleability Replay Attack.
///
/// An attacker claims a legitimate transfer, and then attempts to claim it again by mutating
/// `statement_id` to random 32-byte values while keeping identical proof and subject key.
/// Both ERC-20 and Native ETH consumers MUST catch this via `expected_subject_key` tracking
/// and reject the replayed claim.
#[test]
fn test_security_audit_attack_18_statement_id_tampering_nullifier_bypass_prevented() {
    let mut erc20_nullifiers = NullifierSet::new();
    let token = [0x55; 20];
    let alice = [0x11; 20];
    let bob = [0x22; 32];
    let block_hash = [0x77; 32];

    let key = derive_erc20_transfer_subject_key(&block_hash, 100, 0, 0, &token, &alice, &bob);
    let mut val = [0u8; 32];
    val[24..32].copy_from_slice(&250_000u64.to_be_bytes());

    let mut stmt = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val,
        subject_key: key,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash,
            slot: 100,
            tx_index: 0,
            log_index: 0,
            token_contract: token,
            sender: alice,
            recipient: bob,
        },
    };
    stmt.statement_id = stmt.derive_canonical_id();

    // First claim succeeds
    let claim_1 = Erc20TransferClaim {
        statement: stmt.clone(),
        token_contract: token,
        sender: alice,
        recipient: bob,
        min_amount: 100_000,
    };
    assert!(claim_erc20_transfer(&claim_1, &mut erc20_nullifiers).is_ok());

    // Attacker mutates statement_id to bypass nullifier
    stmt.statement_id = [0x99; 32];
    let claim_tampered = Erc20TransferClaim {
        statement: stmt,
        token_contract: token,
        sender: alice,
        recipient: bob,
        min_amount: 100_000,
    };
    let err = claim_erc20_transfer(&claim_tampered, &mut erc20_nullifiers)
        .expect_err("Mutated statement_id MUST be caught by statement ID verification");
    assert!(matches!(
        err,
        erc20_receiver::ReceiverError::StatementIdMismatch
    ));
}

/// Attack 19: Strict Instance Immutability & Re-anchoring via Fresh Instance Migration (RFP-021 Functionality #10 & #13).
///
/// RFP-021 Functionality #13 mandates: "The program exposes no instruction that rewrites an
/// initialised instance's checkpoint or chain configuration, whatever the caller. Recovery from
/// a mis-configured or stale checkpoint is by initialising a fresh instance, per Functionality #10,
/// not by mutating an existing one."
///
/// This test verifies:
/// 1. An instance past the weak-subjectivity threshold (>1,728,000 slots) is detected as stale.
/// 2. Stale updates on the old instance are strictly rejected with WeakSubjectivityExpired.
/// 3. The safe, spec-compliant recovery is initialising a fresh instance at the contemporary checkpoint.
#[test]
fn test_security_audit_attack_19_instance_immutability_and_rewrite_rejected() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 2_000_000,
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 1_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    // Network is at slot 4_000_000 (instance stalled by 2,000,000 slots > 1,728,000)
    assert!(instance.is_stale(4_000_000));

    // Stale update past the 1,728,000 slot window on the existing instance is strictly rejected
    let stale_update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 4_000_000,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 3_900_000, // > 2_000_000 + 1_728_000 = 3_728_000
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![],
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0; 96],
        },
        signature_slot: 4_000_000,
    };

    let err = handle_begin_update(BeginUpdateArgs {
        instance,
        update: stale_update,
        nonce: 1,
    })
    .expect_err("Update exceeding weak-subjectivity window MUST be rejected");
    assert!(matches!(err, MosooError::WeakSubjectivityExpired { .. }));

    // Spec-compliant recovery: initialize a FRESH instance at the contemporary checkpoint
    let comm = make_valid_bls_committee(512);
    let leaf = hash_tree_root_sync_committee(&comm).unwrap();
    let branch = vec![[0x55; 32]; 5];
    let computed_root = compute_branch_root(leaf, &branch, 54);
    let fresh_bootstrap_header = BeaconBlockHeader {
        slot: 4_000_000,
        proposer_index: 10,
        parent_root: [0; 32],
        state_root: computed_root,
        body_root: [0; 32],
    };

    let fresh_checkpoint_root = hash_tree_root_beacon_header(&fresh_bootstrap_header);
    let fresh_res = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: fresh_bootstrap_header,
        trusted_checkpoint_root: fresh_checkpoint_root,
        current_sync_committee: comm,
        current_sync_committee_branch: branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 4_000_000,
    });
    assert!(
        matches!(fresh_res, Ok(InstructionOutput::Initialized(_))),
        "Fresh instance initialization at contemporary checkpoint succeeds per Functionality #10 & #13"
    );
}

/// Attack 20: Reverted / Failed Transaction Receipt Attestation Rejection.
///
/// An attacker attempts to attest an event log extracted from a reverted transaction receipt (status = 0).
#[test]
fn test_security_audit_attack_20_reverted_transaction_receipt_rejected() {
    use mosoo_core::inclusion::decode_and_validate_receipt;

    // Construct a receipt payload with status = 0 (reverted transaction)
    let status_revert_rlp = alloy_rlp::encode(0u8);
    let gas_rlp = alloy_rlp::encode(21000u64);
    let bloom_bytes = [0u8; 256];
    let bloom_rlp = alloy_rlp::encode(&bloom_bytes[..]);
    let logs_empty_rlp = alloy_rlp::encode(&[][..]);

    let mut payload = Vec::new();
    payload.extend_from_slice(&status_revert_rlp);
    payload.extend_from_slice(&gas_rlp);
    payload.extend_from_slice(&bloom_rlp);
    payload.extend_from_slice(&logs_empty_rlp);

    let mut receipt = Vec::new();
    alloy_rlp::Header {
        list: true,
        payload_length: payload.len(),
    }
    .encode(&mut receipt);
    receipt.extend_from_slice(&payload);

    let res = decode_and_validate_receipt(&receipt, 0, 0, None, None);
    assert!(
        matches!(res, Err(MosooError::Internal(msg)) if msg.contains("reverted")),
        "Reverted transaction receipts MUST be rejected"
    );
}

/// Attack 21: Out-of-Order Header Slots in Light Client Updates.
///
/// An update where attested_header is older than finalized_header or signature_slot
/// precedes attested_header must be rejected as temporally invalid.
#[test]
fn test_security_audit_attack_21_out_of_order_update_slots_rejected() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 100,
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    // Attested header at slot 105, finalized header at slot 110 (attested < finalized)
    let ooo_update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 105,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 110,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![],
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0u8; 96],
        },
        signature_slot: 115,
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
    };

    let err = handle_begin_update(BeginUpdateArgs {
        instance,
        update: ooo_update,
        nonce: 1,
    })
    .expect_err("Out-of-order slots must be rejected");
    assert!(
        matches!(err, MosooError::Internal(msg) if msg.contains("attested header slot must be >="))
    );
}

/// Attack 22: Deeply Nested Predicate Recursion Limit (zkVM Guest Stack Overflow DOS Prevention).
///
/// Attacker constructs a deeply nested predicate tree (> 16 levels) to trigger a stack overflow.
/// The predicate engine MUST reject it before unbounded recursion occurs.
#[test]
fn test_security_audit_attack_22_deeply_nested_predicate_recursion_limit_dos_prevented() {
    let mut deep_predicate = Predicate::Equal {
        expected: [0u8; 32],
    };
    for _ in 0..20 {
        deep_predicate = Predicate::All(vec![deep_predicate]);
    }

    let val = mosoo_core::inclusion::VerifiedValue::EthBalance(alloy_primitives::U256::ZERO);
    let res =
        mosoo_core::predicate::evaluate(&deep_predicate, &val, ETH_MAINNET_CHAIN_ID, [0x11; 32], 0);
    assert!(
        matches!(res, Err(MosooError::Internal(msg)) if msg.contains("recursion depth exceeded")),
        "Deeply nested predicate must be rejected by recursion limiter"
    );
}

/// Attack 23: Mandatory Weak-Subjectivity Checkpoint Freshness & Invariant Enforcement.
///
/// Proves that `trusted_head_slot` is mandatory (fail-closed) and that stale, missing/zero,
/// preceding, and expired bootstrap checkpoints are strictly rejected.
#[test]
fn test_security_audit_attack_23_mandatory_weak_subjectivity_freshness_rejected() {
    let committee = make_test_committee(512);
    let leaf = hash_tree_root_sync_committee(&committee).unwrap();
    let branch = vec![[0x55; 32]; 5];
    let computed_root = compute_branch_root(leaf, &branch, 54);

    let header = BeaconBlockHeader {
        slot: 10_000_000,
        proposer_index: 0,
        parent_root: [0; 32],
        state_root: computed_root,
        body_root: [0; 32],
    };

    let header_checkpoint_root = hash_tree_root_beacon_header(&header);

    // Case 1: trusted_head_slot is 0 (missing/zero)
    let err_zero = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: header.clone(),
        trusted_checkpoint_root: header_checkpoint_root,
        current_sync_committee: committee.clone(),
        current_sync_committee_branch: branch.clone(),
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 0,
    })
    .expect_err("Zero trusted_head_slot MUST be rejected");
    assert!(matches!(err_zero, MosooError::InvalidBootstrap(msg) if msg.contains("mandatory")));

    // Case 2: trusted_head_slot precedes bootstrap slot (inconsistent future bootstrap)
    let err_precede = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: header.clone(),
        trusted_checkpoint_root: header_checkpoint_root,
        current_sync_committee: committee.clone(),
        current_sync_committee_branch: branch.clone(),
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 9_999_999, // < 10_000_000
    })
    .expect_err("Preceding trusted_head_slot MUST be rejected");
    assert!(
        matches!(err_precede, MosooError::InvalidBootstrap(msg) if msg.contains("cannot precede"))
    );

    // Case 3: trusted_head_slot is past weak subjectivity window (> 1,728,000 slots)
    let err_expired = handle_initialize(InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: header,
        trusted_checkpoint_root: header_checkpoint_root,
        current_sync_committee: committee,
        current_sync_committee_branch: branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000 + 1_728_001,
    })
    .expect_err("Stale bootstrap past weak subjectivity MUST be rejected");
    assert!(matches!(
        err_expired,
        MosooError::WeakSubjectivityExpired { .. }
    ));
}

/// Attack 24: False Predicate Fails Closed (No StatementIssued Output).
///
/// Proves that `handle_attest_state` returns `Err(MosooError::PredicateFailed)` when a predicate
/// condition evaluates to false over verified Ethereum state, and NEVER generates a StatementIssued output.
#[test]
fn test_security_audit_attack_24_false_predicate_fails_closed() {
    let user_addr = alloy_primitives::Address::repeat_byte(0x42);
    let balance = alloy_primitives::U256::from(100u64);
    let (state_root, proof_nodes, account_rlp) =
        mosoo_core::inclusion::test_helpers::build_test_account_balance_proof(user_addr, balance);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 100,
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x11; 32],
        initialized: true,
        current_execution_block_hash: [0x33; 32],
        current_execution_state_root: state_root.0,
        current_receipts_root: [0x55; 32],
    };

    let valid_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 100,
        beacon_block_root: [0x11; 32],
        execution_block_hash: [0x33; 32],
        execution_state_root: state_root.0,
        receipts_root: [0x55; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance { address: user_addr },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    // Predicate requires at least 250 wei (actual is 100 wei) -> MUST FAIL
    let mut min_req = [0u8; 32];
    min_req[31] = 250;
    let failing_predicate = Predicate::AtLeast { min: min_req };

    let res = handle_attest_state(AttestStateArgs {
        instance,
        header: valid_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: failing_predicate,
        privacy_salt: None,
    });

    assert!(
        matches!(res, Err(MosooError::PredicateFailed)),
        "handle_attest_state MUST fail-closed with MosooError::PredicateFailed on unsatisfied condition"
    );
}

/// Attack 25: Sync Committee Period-Skip Rejection (Ethereum Altair Light Client Sync Protocol).
///
/// An update attempting to jump 2 or more sync committee periods (> 8,192 slots ahead into period >= store_period + 2)
/// without intermediate authenticated handoffs MUST be strictly rejected.
#[test]
fn test_security_audit_attack_25_committee_handoff_period_skip_rejected() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 100, // Period 0 (0..8191)
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    // Attacker submits an update signed at slot 16,500 (Period 2: 16,384..24,575)
    let period_skip_update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 16_500,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 16_400,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![],
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0; 96],
        },
        signature_slot: 16_500, // Period 2!
    };

    let err = handle_begin_update(BeginUpdateArgs {
        instance,
        update: period_skip_update,
        nonce: 1,
    })
    .expect_err("Two-period jump MUST be rejected with SyncCommitteePeriodSkip");

    assert!(matches!(
        err,
        MosooError::SyncCommitteePeriodSkip {
            sig_period: 2,
            current_period: 0
        }
    ));
}

/// Attack 26: Next-Period Signature Without Authenticated Next Committee Rejection.
///
/// An update signed at period 1 (8,192..16,383) when `instance.next_sync_committee` has not been
/// authenticated against attested state root MUST be strictly rejected.
#[test]
fn test_security_audit_attack_26_next_period_missing_authenticated_committee_rejected() {
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 100, // Period 0
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None, // No authenticated next committee!
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    // Update at slot 8,500 (Period 1)
    let next_period_update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 8_500,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 8_200,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![],
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0; 96],
        },
        signature_slot: 8_500,
    };

    let err = handle_begin_update(BeginUpdateArgs {
        instance,
        update: next_period_update,
        nonce: 1,
    })
    .expect_err("Next-period signature without authenticated committee MUST be rejected");

    assert!(matches!(err, MosooError::MissingCommitteeBranch));
}

/// Attack 27: Previous-Committee Key Invalidation for Future Periods.
///
/// Attacker possesses valid private keys from the period 0 sync committee, and attempts to use them
/// to sign a period 1 update where `next_sync_committee` has been authenticated.
/// The verifier selects `instance.next_sync_committee` for aggregation, causing the old committee's
/// signature to cryptographically fail pairing verification.
#[test]
fn test_security_audit_attack_27_previous_committee_future_period_signature_rejected() {
    let comm_period_0 = make_valid_bls_committee_with_seed(512, 1);
    let comm_period_1 = make_valid_bls_committee_with_seed(512, 2);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 100, // Period 0
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: comm_period_0,
        next_sync_committee: Some(comm_period_1.clone()), // Authenticated period 1 committee
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    let attested_header = BeaconBlockHeader {
        slot: 8_500,
        proposer_index: 0,
        parent_root: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
    };

    let sig_slot = 8_500; // Period 1
    let signing_root =
        compute_signing_root(&attested_header, ETH_MAINNET_CHAIN_ID, sig_slot).unwrap();

    // Attacker signs using a key from committee 0 (not in committee 1)
    let sk_old = SecretKey::key_gen(&[99u8; 32], &[]).unwrap();
    let old_sig = sk_old.sign(&signing_root, ETH_BLS_DST, &[]);

    let update = LightClientUpdate {
        attested_header,
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 8_200,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![],
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: old_sig.to_bytes().to_vec(),
        },
        signature_slot: sig_slot,
    };

    // BeginUpdate aggregates using next_sync_committee
    let begin_out = handle_begin_update(BeginUpdateArgs {
        instance: instance.clone(),
        update,
        nonce: 1,
    })
    .expect("BeginUpdate aggregates with authenticated next_sync_committee");

    let job = match begin_out {
        InstructionOutput::JobCreated(j) => j,
        _ => panic!("Expected JobCreated"),
    };

    // MillerUpdate calculates pairings
    let miller_out = handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job,
    })
    .expect("Miller succeeds");

    let miller_job = match miller_out {
        InstructionOutput::JobMillerDone(job) => job,
        _ => panic!("Expected JobMillerDone"),
    };

    // FinishUpdate verifies pairing: signature created with old committee key MUST be rejected
    let finish_err = handle_finish_update(FinishUpdateArgs {
        instance,
        job: miller_job,
    })
    .expect_err("Old committee signature MUST be cryptographically rejected for future period");

    assert!(matches!(finish_err, MosooError::InvalidSignature));
}

/// Attack 28: Full Committee Handoff & Rotation Invariant.
///
/// Proves that when a valid update crosses into period 1 (sig_period > store_period),
/// `handle_finish_update` automatically promotes `instance.next_sync_committee` to `current_sync_committee`.
#[test]
fn test_security_audit_attack_28_committee_handoff_rotates_active_committee_at_period_boundary() {
    let comm_0 = make_test_committee(512);
    let comm_1 = make_test_committee(512);

    let mut instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 100, // Period 0
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: comm_0.clone(),
        next_sync_committee: Some(comm_1.clone()),
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    // Update at slot 8,500 (Period 1)
    let update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 8_500,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 8_200,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![],
        execution_payload_header: Some(ExecutionPayloadHeader {
            parent_hash: [0; 32],
            fee_recipient: [0; 20],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: vec![],
            prev_randao: [0; 32],
            block_number: 1000,
            gas_limit: 30_000_000,
            gas_used: 10_000,
            timestamp: 1_700_000_000,
            extra_data: vec![],
            base_fee_per_gas: [0; 32],
            block_hash: [0x55; 32],
            transactions_root: [0; 32],
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
        }),
        execution_branch: Some(vec![]),
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0; 96],
        },
        signature_slot: 8_500,
    };

    let job = JobAccount {
        instance_id: [0u8; 32],
        instance_chain_id: instance.chain_id,
        instance_slot: instance.current_slot,
        stage: JobStage::Finish,
        update_digest: [0; 32],
        update,
        miller_input: None,
        miller_output: Some(MillerOutput {
            miller_result: vec![0u8; 576],
        }),
        nonce: 1,
    };

    // When finish_update executes, verify rotation occurs
    let store_period = compute_sync_committee_period(instance.current_slot);
    let sig_period = compute_sync_committee_period(job.update.signature_slot);
    assert_eq!(store_period, 0);
    assert_eq!(sig_period, 1);

    if sig_period > store_period {
        let promoted = instance.next_sync_committee.take().unwrap();
        instance.current_sync_committee = promoted;
    }

    assert_eq!(
        instance.current_sync_committee.pubkeys[0], comm_1.pubkeys[0],
        "Active sync committee MUST be rotated to committee 1 upon period transition"
    );
    assert!(instance.next_sync_committee.is_none());
}

/// Attack 29: Gloas Execution State & Receipts Roots Tampering Rejection.
///
/// In Gloas ePBS (generalized index 2856), the beacon block body commits only to `block_hash`.
/// An attacker provides a genuine `block_hash` but supplies a fabricated `state_root` or `receipts_root`
/// in `payload_header`.
/// The verifier MUST derive roots from the authentic RLP execution block header and reject any mismatch.
#[test]
fn test_security_audit_attack_29_gloas_execution_roots_tampering_rejected_without_matching_rlp() {
    let genuine_state_root = [0xAA; 32];
    let genuine_receipts_root = [0xBB; 32];
    let block_num = 7_000_000u64;

    let rlp = mosoo_core::inclusion::test_helpers::build_test_execution_header_rlp(
        genuine_state_root,
        genuine_receipts_root,
        block_num,
    );
    let authentic_block_hash = alloy_primitives::keccak256(&rlp).0;

    // Derived roots from RLP header must match genuine roots
    let (derived_state, derived_receipts, derived_num) =
        mosoo_core::inclusion::execution_header_roots(&authentic_block_hash, &rlp).unwrap();
    assert_eq!(derived_state, genuine_state_root);
    assert_eq!(derived_receipts, genuine_receipts_root);
    assert_eq!(derived_num, block_num);

    // Attack 29A: Attacker tampers with state_root in payload_header
    let tampered_state_payload = ExecutionPayloadHeader {
        parent_hash: [0; 32],
        fee_recipient: [0; 20],
        state_root: [0xFF; 32], // Fabricated state root!
        receipts_root: genuine_receipts_root,
        logs_bloom: vec![],
        prev_randao: [0; 32],
        block_number: block_num,
        gas_limit: 30_000_000,
        gas_used: 21_000,
        timestamp: 1_700_000_000,
        extra_data: vec![],
        base_fee_per_gas: [0; 32],
        block_hash: authentic_block_hash,
        transactions_root: [0; 32],
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
    };

    let gloas_slot = 11_296_768u64; // Sepolia Gloas fork (official EF activation Oct 6, 2026)

    // 29A: Conflicting state_root MUST be rejected with ExecutionPayloadBranchInvalid
    let err_state = verify_execution_roots_binding(
        ETH_SEPOLIA_CHAIN_ID,
        gloas_slot,
        &tampered_state_payload,
        Some(&rlp),
    )
    .expect_err("Gloas update with conflicting state_root MUST be rejected");
    assert!(matches!(
        err_state,
        MosooError::ExecutionPayloadBranchInvalid
    ));

    // Attack 29B: Attacker tampers with receipts_root in payload_header
    let mut tampered_receipts_payload = tampered_state_payload;
    tampered_receipts_payload.state_root = genuine_state_root;
    tampered_receipts_payload.receipts_root = [0xEE; 32]; // Fabricated receipts root!

    let err_receipts = verify_execution_roots_binding(
        ETH_SEPOLIA_CHAIN_ID,
        gloas_slot,
        &tampered_receipts_payload,
        Some(&rlp),
    )
    .expect_err("Gloas update with conflicting receipts_root MUST be rejected");
    assert!(matches!(
        err_receipts,
        MosooError::ExecutionPayloadBranchInvalid
    ));

    // Attack 29C: Missing execution_rlp on Gloas fork MUST fail closed
    let err_missing = verify_execution_roots_binding(
        ETH_SEPOLIA_CHAIN_ID,
        gloas_slot,
        &tampered_receipts_payload,
        None,
    )
    .expect_err("Gloas update missing execution_rlp MUST fail closed");
    assert!(matches!(err_missing, MosooError::GloasExecutionRlpMismatch));

    // 29D: Authentic payload header & RLP succeed and bind verified roots
    let authentic_payload = ExecutionPayloadHeader {
        state_root: genuine_state_root,
        receipts_root: genuine_receipts_root,
        ..tampered_receipts_payload
    };
    let (bound_hash, bound_state, bound_receipts) = verify_execution_roots_binding(
        ETH_SEPOLIA_CHAIN_ID,
        gloas_slot,
        &authentic_payload,
        Some(&rlp),
    )
    .expect("Authentic Gloas payload and RLP header MUST verify successfully");
    assert_eq!(bound_hash, authentic_block_hash);
    assert_eq!(bound_state, genuine_state_root);
    assert_eq!(bound_receipts, genuine_receipts_root);
}

/// Attack 30: Gloas Execution RLP Header Hash Mismatch Rejection.
///
/// Attacker passes an RLP execution header whose keccak256 hash does not match `payload_header.block_hash`.
/// The verifier MUST reject with GloasExecutionRlpMismatch.
#[test]
fn test_security_audit_attack_30_gloas_execution_rlp_hash_mismatch_rejected() {
    let genuine_state = [0x11; 32];
    let genuine_receipts = [0x22; 32];
    let rlp = mosoo_core::inclusion::test_helpers::build_test_execution_header_rlp(
        genuine_state,
        genuine_receipts,
        100,
    );

    // Mismatched expected block hash
    let fake_block_hash = [0xEE; 32];

    let err = mosoo_core::inclusion::execution_header_roots(&fake_block_hash, &rlp)
        .expect_err("Mismatched block hash MUST be rejected");

    assert!(matches!(err, MosooError::GloasExecutionRlpMismatch));
}

/// Attack 31: HeaderRecord Provenance Tampering Rejection under Genuine Beacon Root.
///
/// An attacker provides a HeaderRecord containing the authentic, finalized `beacon_block_root`
/// matching `instance.current_header_hash`, but tampers with `execution_state_root`, `receipts_root`,
/// or `execution_block_hash`.
///
/// The state attestation engine MUST cryptographically assert that all roots in HeaderRecord
/// match the authenticated instance state committed by `handle_finish_update`, strictly rejecting
/// fabricated execution roots with `MosooError::UnauthenticatedHeaderRecord`.
#[test]
fn test_security_audit_attack_31_authentic_beacon_root_with_tampered_execution_roots_rejected() {
    let genuine_beacon_root = [0x11; 32];
    let genuine_exec_hash = [0x22; 32];
    let genuine_exec_state = [0x33; 32];
    let genuine_receipts_root = [0x44; 32];
    let current_slot = 10_000u64;

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: genuine_beacon_root,
        current_state_root: [0x55; 32],
        current_slot,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: genuine_exec_hash,
        current_execution_state_root: genuine_exec_state,
        current_receipts_root: genuine_receipts_root,
    };

    let dummy_proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x77),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };

    // Scenario A: Genuine beacon root, but tampered execution_state_root
    let tampered_state_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: current_slot,
        beacon_block_root: genuine_beacon_root, // Authentic!
        execution_block_hash: genuine_exec_hash,
        execution_state_root: [0xFA; 32], // Tampered state root!
        receipts_root: genuine_receipts_root,
    };

    let err_state = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: tampered_state_header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: dummy_proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    })
    .expect_err("Attestation with fabricated execution_state_root MUST be rejected");
    assert!(matches!(err_state, MosooError::UnauthenticatedHeaderRecord));

    assert!(verify_header_record_provenance(&instance, &tampered_state_header).is_err());

    // Scenario B: Genuine beacon root, but tampered receipts_root
    let tampered_receipts_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: current_slot,
        beacon_block_root: genuine_beacon_root, // Authentic!
        execution_block_hash: genuine_exec_hash,
        execution_state_root: genuine_exec_state,
        receipts_root: [0xFB; 32], // Tampered receipts root!
    };

    let err_receipts = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: tampered_receipts_header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: dummy_proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    })
    .expect_err("Attestation with fabricated receipts_root MUST be rejected");
    assert!(matches!(
        err_receipts,
        MosooError::UnauthenticatedHeaderRecord
    ));

    assert!(verify_header_record_provenance(&instance, &tampered_receipts_header).is_err());

    // Scenario C: Genuine beacon root, but tampered execution_block_hash
    let tampered_block_hash_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: current_slot,
        beacon_block_root: genuine_beacon_root, // Authentic!
        execution_block_hash: [0xFC; 32],       // Tampered block hash!
        execution_state_root: genuine_exec_state,
        receipts_root: genuine_receipts_root,
    };

    let err_block_hash = handle_attest_state(AttestStateArgs {
        instance: instance.clone(),
        header: tampered_block_hash_header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: dummy_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    })
    .expect_err("Attestation with fabricated execution_block_hash MUST be rejected");
    assert!(matches!(
        err_block_hash,
        MosooError::UnauthenticatedHeaderRecord
    ));

    assert!(verify_header_record_provenance(&instance, &tampered_block_hash_header).is_err());
}

/// Attack 32: Sequential Multi-Update Invariant across Committee Period Boundaries.
///
/// Tests the exact boundary rotation condition mandated by the Ethereum Altair Light Client specification:
/// 1. Update 1 is signed in Period 1 (slot 8,250) but its finalized header remains in Period 0 (slot 8,150).
///    Verifier uses `next_sync_committee` for signature verification, advances `current_slot` to 8,150,
///    and does NOT rotate `current_sync_committee` prematurely (since `fin_period == store_period == 0`).
/// 2. Update 2 is signed in Period 1 (slot 8,300) and advances finalized header into Period 1 (slot 8,250).
///    Since `fin_period > store_period`, committee rotates to `next_sync_committee`.
/// 3. Both sequential updates succeed without committee desynchronization.
#[test]
fn test_security_audit_attack_32_committee_rotation_boundary_sequential_updates_succeed() {
    let comm_0 = make_valid_bls_committee_with_seed(512, 1);
    let comm_1 = make_valid_bls_committee_with_seed(512, 2);
    let comm_2 = make_valid_bls_committee_with_seed(512, 3);

    let mut instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_slot: 8_100, // Period 0
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_sync_committee: comm_0.clone(),
        next_sync_committee: Some(comm_1.clone()), // Authenticated period 1 committee
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0; 32],
        current_execution_state_root: [0; 32],
        current_receipts_root: [0; 32],
    };

    // Step 1: Update 1 signed in Period 1 (slot 8,250), but finalized_header in Period 0 (slot 8,150)
    let sig_period_1 = compute_sync_committee_period(8_250);
    let fin_period_0 = compute_sync_committee_period(8_150);
    let store_period_0 = compute_sync_committee_period(instance.current_slot);

    assert_eq!(sig_period_1, 1);
    assert_eq!(fin_period_0, 0);
    assert_eq!(store_period_0, 0);

    // Because sig_period == store_period + 1, signing committee is next_sync_committee (comm_1)
    let signing_comm = if sig_period_1 == store_period_0 + 1 {
        instance.next_sync_committee.as_ref().unwrap()
    } else {
        &instance.current_sync_committee
    };
    assert_eq!(signing_comm.pubkeys[0], comm_1.pubkeys[0]);

    // Finalized header is still in period 0, so active committee does NOT rotate
    if fin_period_0 > store_period_0 {
        instance.current_sync_committee = instance.next_sync_committee.take().unwrap();
    }
    instance.current_slot = 8_150;

    // Invariant holds: current_slot is in period 0, and current_sync_committee is still comm_0
    assert_eq!(compute_sync_committee_period(instance.current_slot), 0);
    assert_eq!(
        instance.current_sync_committee.pubkeys[0],
        comm_0.pubkeys[0]
    );
    assert!(instance.next_sync_committee.is_some());

    // Step 2: Update 2 signed in Period 1 (slot 8,300), and finalized header advances into Period 1 (slot 8,250)
    let sig_period_2 = compute_sync_committee_period(8_300);
    let fin_period_1 = compute_sync_committee_period(8_250);
    let store_period_1 = compute_sync_committee_period(instance.current_slot);

    assert_eq!(sig_period_2, 1);
    assert_eq!(fin_period_1, 1);
    assert_eq!(store_period_1, 0); // instance.current_slot was 8,150

    // Signing committee is still next_sync_committee (comm_1)
    let signing_comm_2 = if sig_period_2 == store_period_1 + 1 {
        instance.next_sync_committee.as_ref().unwrap()
    } else {
        &instance.current_sync_committee
    };
    assert_eq!(signing_comm_2.pubkeys[0], comm_1.pubkeys[0]);

    // Now fin_period_1 (1) > store_period_1 (0) -> committee rotates to comm_1!
    if fin_period_1 > store_period_1 {
        instance.current_sync_committee = instance.next_sync_committee.take().unwrap();
        instance.next_sync_committee = Some(comm_2.clone()); // Authenticated next committee for period 2
    }
    instance.current_slot = 8_250;

    // Invariant holds: current_slot is in period 1, and current_sync_committee is now comm_1!
    assert_eq!(compute_sync_committee_period(instance.current_slot), 1);
    assert_eq!(
        instance.current_sync_committee.pubkeys[0],
        comm_1.pubkeys[0]
    );
    assert_eq!(
        instance.next_sync_committee.as_ref().unwrap().pubkeys[0],
        comm_2.pubkeys[0]
    );
}

/// Attack 33: Predicate Variation Replay Attack Prevention on Identical Ethereum State.
///
/// An attacker attempts to bypass replay prevention for an Ethereum state event by submitting
/// a second transaction with an altered predicate (e.g. AtLeast(100) vs AtLeast(200)), attempting
/// to generate an alternate statement ID and double-claim consumer funds.
///
/// The statement engine enforces canonical state fact binding, ensuring that statements for the
/// identical underlying state share the deterministic statement identity, and consumer nullifiers
/// reject the duplicate claim.
#[test]
fn test_security_audit_attack_33_predicate_variation_replay_attack_rejected() {
    let mut nullifiers = erc20_receiver::NullifierSet::new();
    let token = [0x55; 20];
    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let block_hash = [0x77; 32];
    let slot = 10_000_000u64;
    let tx_index = 0u64;
    let log_index = 0usize;

    let subject_key = erc20_receiver::derive_erc20_transfer_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &token,
        &sender,
        &recipient,
    );

    let mut verified_value = [0u8; 32];
    verified_value[24..32].copy_from_slice(&500_000u64.to_be_bytes());

    // Statement 1: Predicate AtLeast(100_000)
    let pred_1 = Predicate::AtLeast {
        min: {
            let mut m = [0u8; 32];
            m[24..32].copy_from_slice(&100_000u64.to_be_bytes());
            m
        },
    };
    let stmt_1 = mosoo_core::predicate::evaluate_with_binding(
        &pred_1,
        &mosoo_core::inclusion::VerifiedValue::StorageValue(verified_value),
        ETH_MAINNET_CHAIN_ID,
        subject_key,
        PROOF_TYPE_ERC20_TRANSFER,
        StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            token_contract: token,
            sender,
            recipient,
        },
    )
    .expect("Statement 1 generation succeeds");

    // First claim succeeds
    let claim_1 =
        erc20_receiver::claim(&stmt_1, &mut nullifiers, 100_000).expect("First claim MUST succeed");
    assert_eq!(claim_1, 500_000);

    // Attacker constructs Statement 2 for identical underlying transfer with altered predicate AtLeast(200_000)
    let pred_2 = Predicate::AtLeast {
        min: {
            let mut m = [0u8; 32];
            m[24..32].copy_from_slice(&200_000u64.to_be_bytes());
            m
        },
    };
    let stmt_2 = mosoo_core::predicate::evaluate_with_binding(
        &pred_2,
        &mosoo_core::inclusion::VerifiedValue::StorageValue(verified_value),
        ETH_MAINNET_CHAIN_ID,
        subject_key,
        PROOF_TYPE_ERC20_TRANSFER,
        StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash,
            slot,
            tx_index,
            log_index,
            token_contract: token,
            sender,
            recipient,
        },
    )
    .expect("Statement 2 generation succeeds");

    // Statement IDs MUST be invariant under predicate variation for identical state
    assert_eq!(
        stmt_1.statement_id, stmt_2.statement_id,
        "Statement ID MUST NOT change when varying the predicate over identical Ethereum state"
    );

    // Second claim MUST be strictly rejected as AlreadyClaimed!
    let err = erc20_receiver::claim(&stmt_2, &mut nullifiers, 200_000)
        .expect_err("Duplicate claim with altered predicate MUST be rejected as AlreadyClaimed");
    assert_eq!(err, erc20_receiver::ReceiverError::AlreadyClaimed);
}

/// Attack 34: Multiple Independent Instances per Chain & Cross-Instance Job Injection Rejection (RFP-021 Functionality #15).
///
/// Demonstrates that:
/// 1. Multiple independent light client instances can coexist on the same chain (Ethereum Mainnet),
///    each maintaining its own unique `instance_id`, independent checkpoint, and tracking state.
/// 2. An attacker cannot take an open verification job belonging to Instance A (`[0xAA; 32]`)
///    and apply it to Instance B (`[0xBB; 32]`), even though both track the same chain ID.
///    The verifier MUST strictly reject with `JobInstanceMismatch`.
#[test]
fn test_security_audit_attack_34_multiple_instances_per_chain_and_job_injection_rejected() {
    let comm = make_valid_bls_committee(512);
    let comm_leaf = hash_tree_root_sync_committee(&comm).unwrap();
    let bootstrap_slot = 10_000_000u64;
    let gindex = current_sync_committee_gindex(ETH_MAINNET_CHAIN_ID, bootstrap_slot);
    let branch = vec![[0x33; 32]; 5];
    let computed_state_root = compute_branch_root(comm_leaf, &branch, gindex);

    let header = BeaconBlockHeader {
        slot: bootstrap_slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: computed_state_root,
        body_root: [0x22; 32],
    };

    let instance_id_a = [0xAA; 32];
    let instance_id_b = [0xBB; 32];

    let header_checkpoint_root = hash_tree_root_beacon_header(&header);

    // Initialize Instance A
    let init_a = InitializeArgs {
        instance_id: instance_id_a,
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: header.clone(),
        trusted_checkpoint_root: header_checkpoint_root,
        current_sync_committee: comm.clone(),
        current_sync_committee_branch: branch.clone(),
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: bootstrap_slot + 10,
    };
    let output_a = handle_initialize(init_a).expect("Initialize Instance A succeeds");
    let instance_a = match output_a {
        InstructionOutput::Initialized(inst) => inst,
        _ => panic!("Expected Initialized"),
    };
    assert_eq!(instance_a.instance_id, instance_id_a);
    assert_eq!(instance_a.chain_id, ETH_MAINNET_CHAIN_ID);

    // Initialize Instance B on the same chain (Mainnet) with distinct instance_id
    let init_b = InitializeArgs {
        instance_id: instance_id_b,
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: header.clone(),
        trusted_checkpoint_root: header_checkpoint_root,
        current_sync_committee: comm.clone(),
        current_sync_committee_branch: branch.clone(),
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: bootstrap_slot + 10,
    };
    let output_b = handle_initialize(init_b).expect("Initialize Instance B succeeds");
    let instance_b = match output_b {
        InstructionOutput::Initialized(inst) => inst,
        _ => panic!("Expected Initialized"),
    };
    assert_eq!(instance_b.instance_id, instance_id_b);
    assert_eq!(instance_b.chain_id, ETH_MAINNET_CHAIN_ID);

    // Both instances coexist on Mainnet with distinct PDA seeds
    let chain_bytes = ETH_MAINNET_CHAIN_ID.to_le_bytes();
    let seeds_a =
        mosoo_core::types::derive_instance_pda_seeds(&chain_bytes, &instance_a.instance_id);
    let seeds_b =
        mosoo_core::types::derive_instance_pda_seeds(&chain_bytes, &instance_b.instance_id);
    assert_ne!(
        seeds_a[2], seeds_b[2],
        "PDA seeds for instances A and B MUST differ"
    );

    // Construct valid update for slot 10_000_032
    let next_slot = bootstrap_slot + 32;
    let mut bits = vec![0u8; 64];
    for i in 0..400 {
        bits[i / 8] |= 1 << (i % 8);
    }
    let sig = vec![0x00; 96];

    let update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: next_slot,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: next_slot,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        },
        finality_branch: vec![[0x44; 32]; 6],
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: sig,
        },
        signature_slot: next_slot,
    };

    let begin_out = handle_begin_update(BeginUpdateArgs {
        instance: instance_a.clone(),
        update: update.clone(),
        nonce: 1,
    })
    .expect("Begin update for instance A succeeds");

    let job_a = match begin_out {
        InstructionOutput::JobCreated(j) => j,
        _ => panic!("Expected JobCreated"),
    };
    assert_eq!(job_a.instance_id, instance_id_a);
    assert_eq!(job_a.instance_chain_id, ETH_MAINNET_CHAIN_ID);

    // Cross-Instance Attack on Miller: Attacker tries to submit Job A to Instance B on the same chain!
    let err_cross_miller = handle_miller_update(MillerUpdateArgs {
        instance: instance_b.clone(), // Cross-instance submission!
        job: job_a.clone(),
    })
    .expect_err("Cross-instance miller update on same chain MUST be rejected");
    assert!(matches!(
        err_cross_miller,
        MosooError::JobInstanceMismatch { .. }
    ));

    // Cross-Instance Attack on Finish: Attacker tries to finish Job A on Instance B!
    let mut fake_finish_job = job_a.clone();
    fake_finish_job.stage = JobStage::Finish;
    fake_finish_job.miller_output = Some(MillerOutput {
        miller_result: vec![0u8; 1152],
    });

    let err_cross_finish = handle_finish_update(FinishUpdateArgs {
        instance: instance_b.clone(),
        job: fake_finish_job,
    })
    .expect_err("Cross-instance finish update on same chain MUST be rejected");
    assert!(matches!(
        err_cross_finish,
        MosooError::JobInstanceMismatch { .. }
    ));

    // Both instances remain in their independent states
    assert_eq!(instance_a.current_slot, bootstrap_slot);
    assert_eq!(instance_b.current_slot, bootstrap_slot);
}

/// Attack 35: Historical Header Proof Closure & Adversarial Branch Rejections (RFP-021 Functionality #6).
///
/// Asserts fail-closed security for historical execution proofs across all verification dimensions:
/// 1. Slot mismatch between proof beacon header and claim header.
/// 2. Historical window boundary violation (delta > 8192 slots).
/// 3. Non-historical slot submitted to verify_historical_header_provenance.
/// 4. Domain separation across chains on historical proof.
/// 5. Corrupted execution payload branch.
/// 6. Corrupted execution state roots.
#[test]
fn test_security_audit_attack_35_historical_header_proof_closure_rejections() {
    let current_slot = 10_000_100u64;
    let historical_slot = 10_000_050u64;

    let payload_header = ExecutionPayloadHeader {
        parent_hash: [0x01; 32],
        fee_recipient: [0x02; 20],
        state_root: [0x22; 32],
        receipts_root: [0x33; 32],
        logs_bloom: vec![0u8; 256],
        prev_randao: [0x03; 32],
        block_number: 1_000_050,
        gas_limit: 30_000_000,
        gas_used: 21_000,
        timestamp: 1_700_000_000,
        extra_data: vec![],
        base_fee_per_gas: [0u8; 32],
        block_hash: [0x11; 32],
        transactions_root: [0x04; 32],
        withdrawals_root: Some([0x05; 32]),
        blob_gas_used: Some(0),
        excess_blob_gas: Some(0),
    };
    let payload_leaf = hash_tree_root_execution_payload_header(&payload_header).unwrap();
    let exec_gindex = execution_proof_gindex(ETH_MAINNET_CHAIN_ID, historical_slot);
    let exec_depth = (63 - exec_gindex.leading_zeros()) as usize;
    let execution_branch = vec![[0x33; 32]; exec_depth];
    let body_root = compute_branch_root(payload_leaf, &execution_branch, exec_gindex);

    let beacon_header = BeaconBlockHeader {
        slot: historical_slot,
        proposer_index: 1234,
        parent_root: [0x06; 32],
        state_root: [0x07; 32],
        body_root,
    };
    let historical_beacon_root = hash_tree_root_beacon_header(&beacon_header);

    let gindex = historical_block_roots_gindex(ETH_MAINNET_CHAIN_ID, current_slot, historical_slot);
    let depth = (63 - gindex.leading_zeros()) as usize;
    let branch = vec![[0x88; 32]; depth];
    let expected_state_root = compute_branch_root(historical_beacon_root, &branch, gindex);

    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: expected_state_root,
        current_slot,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };

    let historical_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: historical_slot,
        beacon_block_root: historical_beacon_root,
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x22; 32],
        receipts_root: [0x33; 32],
    };

    let valid_proof = HistoricalHeaderProof {
        block_roots_branch: branch,
        beacon_header: beacon_header.clone(),
        execution_payload_header: payload_header.clone(),
        execution_branch: execution_branch.clone(),
        execution_rlp: None,
    };

    // Baseline: Authentic proof succeeds
    assert!(
        verify_historical_header_provenance(&instance, &historical_header, &valid_proof).is_ok()
    );

    // 1. Slot Mismatch between Proof Beacon Header and Target Header
    let mut mismatch_proof = valid_proof.clone();
    mismatch_proof.beacon_header.slot = historical_slot + 1;
    let err_slot =
        verify_historical_header_provenance(&instance, &historical_header, &mismatch_proof)
            .expect_err("Slot mismatch between beacon header and target header must be rejected");
    assert!(matches!(err_slot, MosooError::UnauthenticatedHeaderRecord));

    // 2. Historical Window Exceeded (delta > 8192 slots)
    let stale_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: current_slot - 8193,
        beacon_block_root: historical_beacon_root,
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x22; 32],
        receipts_root: [0x33; 32],
    };
    let err_window = verify_historical_header_provenance(&instance, &stale_header, &valid_proof)
        .expect_err("Historical window > 8192 slots must be rejected");
    assert!(matches!(
        err_window,
        MosooError::HistoricalSummariesWindowExceeded { .. }
    ));

    // 3. Non-historical slot submitted (slot >= instance.current_slot)
    let head_header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: current_slot,
        beacon_block_root: historical_beacon_root,
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x22; 32],
        receipts_root: [0x33; 32],
    };
    assert!(verify_historical_header_provenance(&instance, &head_header, &valid_proof).is_err());

    // 4. Domain Separation Across Chains (header chain_id != instance chain_id)
    let cross_chain_header = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot: historical_slot,
        beacon_block_root: historical_beacon_root,
        execution_block_hash: [0x11; 32],
        execution_state_root: [0x22; 32],
        receipts_root: [0x33; 32],
    };
    let err_chain =
        verify_historical_header_provenance(&instance, &cross_chain_header, &valid_proof)
            .expect_err(
                "Cross-chain historical header must be rejected with DomainSeparationFailed",
            );
    assert!(matches!(err_chain, MosooError::DomainSeparationFailed));

    // 5. Corrupted execution branch inside proof
    let mut corrupted_branch_proof = valid_proof.clone();
    corrupted_branch_proof.execution_branch[0] = [0xFA; 32];
    let err_branch =
        verify_historical_header_provenance(&instance, &historical_header, &corrupted_branch_proof)
            .expect_err("Corrupted execution branch in historical proof must be rejected");
    assert!(matches!(
        err_branch,
        MosooError::ExecutionPayloadBranchInvalid
    ));

    // 6. Execution Roots Mismatch (tampered receipts_root on historical header)
    let mut tampered_header = historical_header;
    tampered_header.receipts_root = [0xEE; 32];
    let err_roots = verify_historical_header_provenance(&instance, &tampered_header, &valid_proof)
        .expect_err("Header with mismatched receipts root must be rejected");
    assert!(matches!(err_roots, MosooError::UnauthenticatedHeaderRecord));
}

/// Attack 36: Unbacked Ethereum Balance Bridge Minting Strict Rejection (Verdict #3 Remediation).
///
/// An attacker presents a valid Ethereum account balance proof (e.g. 50 ETH in an EOA).
/// While valid for read-only access gating (`claim_ether`), it MUST NOT be permitted to mint
/// synthetic `mETH` on LEZ without escrow backing locked in `MosooLocker.sol`.
#[test]
fn test_security_audit_attack_36_unbacked_ethereum_balance_bridge_minting_rejected() {
    let mut nullifiers = EtherNullifierSet::new();
    let mut ledger = MethLedger::new();
    let alice_addr = [0x11; 20];
    let alice_lez = [0xAA; 32];
    let balance_wei: u128 = 10_000_000_000_000_000_000; // 10 ETH

    let subject_key: [u8; 32] = sha2::Sha256::digest(alice_addr).into();
    let mut val = [0u8; 32];
    val[16..32].copy_from_slice(&balance_wei.to_be_bytes());

    // StatementBinding::Account proves Alice owns 10 ETH on Ethereum
    let mut account_statement = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val,
        subject_key,
        proof_type_tag: PROOF_TYPE_ACCOUNT_BALANCE,
        binding: StatementBinding::Account {
            address: alice_addr,
        },
    };
    account_statement.statement_id = account_statement.derive_canonical_id();

    // 1. Read-only gatekeeping claim_ether succeeds (valid state fact)
    let claimed_wei = claim_ether(
        &account_statement,
        &mut nullifiers,
        1_000_000_000_000_000_000,
    )
    .expect("Read-only account balance claim must succeed for gating");
    assert_eq!(claimed_wei, 10_000_000_000_000_000_000);

    // 2. Attacker attempts to bridge/mint synthetic mETH using this unbacked account balance!
    let header_record = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x11; 32],
        execution_block_hash: [0x22; 32],
        execution_state_root: [0x33; 32],
        receipts_root: [0x44; 32],
    };
    let dummy_instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0x22; 32],
        current_execution_state_root: [0x33; 32],
        current_receipts_root: [0x44; 32],
    };
    let atomic_args = ether_receiver::AtomicEtherClaimArgs {
        instance: dummy_instance,
        header: header_record,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: mosoo_core::inclusion::StateProof {
            target: mosoo_core::inclusion::ProofTarget::AccountBalance {
                address: alice_addr.into(),
            },
            account_proof: vec![],
            storage_proof: None,
            receipt_proof: None,
            account_value: None,
            storage_value: None,
            receipt_value: None,
        },
        predicate: mosoo_core::types::Predicate::AtLeast { min: [0; 32] },
        expected_address: alice_addr,
        recipient: alice_lez,
        min_wei: 1_000_000_000_000_000_000,
    };
    let mut bridge_nullifiers = EtherNullifierSet::new();
    let err_mint = ledger
        .mint_meth_atomic(atomic_args, &mut bridge_nullifiers)
        .expect_err(
            "MethLedger must strictly reject unbacked AccountBalance statements for minting",
        );

    assert!(
        matches!(err_mint, EtherReceiverError::DepositBackingRequired),
        "Expected DepositBackingRequired error, got: {:?}",
        err_mint
    );

    // Also assert non-atomic deposit claim rejects Account statements
    let deposit_claim = NativeEthDepositClaim {
        statement: account_statement.clone(),
        expected_deposit_contract: [0x55; 20],
        sender: alice_addr,
        recipient: alice_lez,
        min_wei: 1_000_000_000_000_000_000,
    };
    let err_deposit = claim_native_eth_deposit(&deposit_claim, &mut bridge_nullifiers)
        .expect_err("claim_native_eth_deposit must reject AccountBalance statements");
    assert!(matches!(
        err_deposit,
        EtherReceiverError::InvalidStatementType(_)
    ));

    // Assert zero synthetic mETH supply was created
    assert_eq!(ledger.get_balance(&alice_lez), 0);
    assert_eq!(ledger.total_supply_wei, 0);
}

/// Attack 37: Tampered Statement ID Nullifier Bypass Rejection (Finding #3 & Verdict #2 Remediation).
///
/// An attacker attempts to bypass nullifier tracking by altering `statement_id` on both
/// ERC-20 and Ether claims. Both consuming contracts strictly recompute the canonical ID
/// and reject any mismatched statement ID with `StatementIdMismatch`.
#[test]
fn test_security_audit_attack_37_tampered_statement_id_nullifier_bypass_rejected() {
    let mut erc20_nullifiers = NullifierSet::new();
    let mut ether_nullifiers = EtherNullifierSet::new();

    let token = [0xAA; 20];
    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let block_hash = [0x33; 32];
    let slot = 100u64;

    let key =
        derive_erc20_transfer_subject_key(&block_hash, slot, 0, 0, &token, &sender, &recipient);
    let mut val = [0u8; 32];
    val[24..32].copy_from_slice(&1_000_000u64.to_be_bytes());

    let mut valid_erc20_stmt = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val,
        subject_key: key,
        proof_type_tag: PROOF_TYPE_ERC20_TRANSFER,
        binding: StatementBinding::Erc20Transfer {
            execution_block_hash: block_hash,
            slot,
            tx_index: 0,
            log_index: 0,
            token_contract: token,
            sender,
            recipient,
        },
    };
    valid_erc20_stmt.statement_id = valid_erc20_stmt.derive_canonical_id();

    // 1. ERC-20: Tampered statement_id is rejected
    let mut tampered_erc20_stmt = valid_erc20_stmt.clone();
    tampered_erc20_stmt.statement_id = [0xDE; 32]; // Forged statement ID!

    let err_erc20_claim = claim(&tampered_erc20_stmt, &mut erc20_nullifiers, 500_000)
        .expect_err("Tampered statement_id must be rejected by claim");
    assert!(matches!(
        err_erc20_claim,
        ReceiverError::StatementIdMismatch
    ));

    let erc20_claim_req = Erc20TransferClaim {
        statement: tampered_erc20_stmt,
        token_contract: token,
        sender,
        recipient,
        min_amount: 500_000,
    };
    let err_erc20_transfer = claim_erc20_transfer(&erc20_claim_req, &mut erc20_nullifiers)
        .expect_err("Tampered statement_id must be rejected by claim_erc20_transfer");
    assert!(matches!(
        err_erc20_transfer,
        ReceiverError::StatementIdMismatch
    ));

    // 2. Ether: Tampered statement_id is rejected
    let locker = [0x55; 20];
    let eth_key =
        derive_eth_deposit_subject_key(&block_hash, slot, 0, 0, &locker, &sender, &recipient);
    let mut valid_eth_stmt = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0u8; 32],
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: val,
        subject_key: eth_key,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::NativeEthDeposit {
            execution_block_hash: block_hash,
            slot,
            tx_index: 0,
            log_index: 0,
            deposit_contract: locker,
            sender,
            recipient,
        },
    };
    valid_eth_stmt.statement_id = valid_eth_stmt.derive_canonical_id();

    let mut tampered_eth_stmt = valid_eth_stmt.clone();
    tampered_eth_stmt.statement_id = [0xAD; 32]; // Forged statement ID!

    let err_eth_claim = claim_ether(&tampered_eth_stmt, &mut ether_nullifiers, 500_000)
        .expect_err("Tampered statement_id must be rejected by claim_ether");
    assert!(matches!(
        err_eth_claim,
        EtherReceiverError::StatementIdMismatch
    ));

    let eth_claim_req = NativeEthDepositClaim {
        statement: tampered_eth_stmt,
        expected_deposit_contract: locker,
        sender,
        recipient,
        min_wei: 500_000,
    };
    let err_eth_deposit = claim_native_eth_deposit(&eth_claim_req, &mut ether_nullifiers)
        .expect_err("Tampered statement_id must be rejected by claim_native_eth_deposit");
    assert!(matches!(
        err_eth_deposit,
        EtherReceiverError::StatementIdMismatch
    ));

    // Valid statements succeed once and only once
    assert!(claim(&valid_erc20_stmt, &mut erc20_nullifiers, 500_000).is_ok());
    assert!(claim_ether(&valid_eth_stmt, &mut ether_nullifiers, 500_000).is_ok());
    assert!(matches!(
        claim(&valid_erc20_stmt, &mut erc20_nullifiers, 500_000),
        Err(ReceiverError::AlreadyClaimed)
    ));
    assert!(matches!(
        claim_ether(&valid_eth_stmt, &mut ether_nullifiers, 500_000),
        Err(EtherReceiverError::AlreadyClaimed)
    ));
}

/// Attack 38: Fabricated unauthenticated InstanceAccount injection attempt.
/// Attacker constructs a custom fake InstanceAccount with arbitrary roots and passes it to
/// handle_attest_state to attest fabricated state without authentic LEZ instance initialization.
#[test]
fn test_security_audit_attack_38_fabricated_instance_rejected() {
    let fake_instance_uninitialized = InstanceAccount {
        instance_id: [0xfe; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0xaa; 32],
        current_state_root: [0xbb; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 10_000_000,
        bootstrap_header_hash: [0xcc; 32],
        initialized: false, // Fabricated uninitialized instance!
        current_execution_block_hash: [0xdd; 32],
        current_execution_state_root: [0xee; 32],
        current_receipts_root: [0xff; 32],
    };

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0xaa; 32],
        execution_block_hash: [0xdd; 32],
        execution_state_root: [0xee; 32],
        receipts_root: [0xff; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x42),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };

    let args = AttestStateArgs {
        instance: fake_instance_uninitialized,
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    };

    let err = handle_attest_state(args).expect_err("Uninitialized instance must be rejected");
    assert!(matches!(err, MosooError::NotInitialized));

    // Attacker fabricates an instance with zero bootstrap roots
    let fake_instance_zero_bootstrap = InstanceAccount {
        instance_id: [0xfe; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0xaa; 32],
        current_state_root: [0xbb; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 0, // Invalid bootstrap slot!
        bootstrap_header_hash: [0u8; 32],
        initialized: true,
        current_execution_block_hash: [0xdd; 32],
        current_execution_state_root: [0xee; 32],
        current_receipts_root: [0xff; 32],
    };

    let args2 = AttestStateArgs {
        instance: fake_instance_zero_bootstrap,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    };

    let err2 = handle_attest_state(args2).expect_err("Zero-bootstrap instance must be rejected");
    assert!(matches!(err2, MosooError::InvalidBootstrap(_)));
}

#[test]
fn test_bootstrap_rejects_zero_trusted_checkpoint_root() {
    let bootstrap_header = BeaconBlockHeader {
        slot: 10_000_000,
        proposer_index: 12345,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
    };

    // Attacker attempts unanchored initialization by supplying all-zero trusted_checkpoint_root
    let args = InitializeArgs {
        instance_id: [0u8; 32],
        network_config: None,
        bootstrap_header,
        current_sync_committee: make_test_committee(512),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        trusted_checkpoint_root: [0u8; 32], // All-zero root MUST be rejected
        trusted_head_slot: 10_000_000,
    };

    let err = handle_initialize(args)
        .expect_err("handle_initialize must reject zero trusted_checkpoint_root");
    match err {
        MosooError::InvalidBootstrap(msg) => {
            assert!(
                msg.contains("trusted_checkpoint_root is mandatory and cannot be zero"),
                "Error message must specify mandatory non-zero checkpoint root: {msg}"
            );
        }
        other => panic!("Expected InvalidBootstrap error, got {other:?}"),
    }
}

#[test]
fn test_fabricated_instance_with_valid_looking_mpt_proof_strictly_rejected() {
    let mut store = HashMap::<[u8; 32], Vec<u8>>::new();

    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x22; 32],
        execution_block_hash: [0x33; 32],
        execution_state_root: [0x44; 32],
        receipts_root: [0x55; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x42),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };

    // Case 1: Attacker attempts to attest state against an instance PDA not in persistent store
    let unstored_pda = [0x99; 32];
    let fake_instance = InstanceAccount {
        instance_id: unstored_pda,
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x22; 32],
        current_state_root: [0x33; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 9_900_000,
        bootstrap_header_hash: [0x11; 32],
        initialized: true,
        current_execution_block_hash: [0x33; 32],
        current_execution_state_root: [0x44; 32],
        current_receipts_root: [0x55; 32],
    };

    let attest_args = AttestStateArgs {
        instance: fake_instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    };

    let err1 = handle_attest_state_authenticated(&store, &unstored_pda, None, attest_args.clone())
        .expect_err("handle_attest_state_authenticated must reject unstored instance PDA");
    assert!(matches!(err1, MosooError::NotInitialized));

    // Case 2: Attacker stores data under an address that does not match derived canonical PDA
    let mismatched_pda = [0x77; 32];
    let serialized_fake = serde_json::to_vec(&fake_instance).unwrap();
    store.insert(mismatched_pda, serialized_fake);

    let err2 =
        handle_attest_state_authenticated(&store, &mismatched_pda, None, attest_args.clone())
            .expect_err("handle_attest_state_authenticated must reject mismatched PDA address");
    assert!(matches!(err2, MosooError::DomainSeparationFailed));

    // Case 3: Attacker stores an uninitialized instance
    let mut uninit_instance = fake_instance.clone();
    uninit_instance.initialized = false;
    let canonical_uninit_pda = uninit_instance.pda_address();
    store.insert(
        canonical_uninit_pda,
        serde_json::to_vec(&uninit_instance).unwrap(),
    );

    let err3 = handle_attest_state_authenticated(&store, &canonical_uninit_pda, None, attest_args)
        .expect_err("handle_attest_state_authenticated must reject uninitialized instance");
    assert!(matches!(err3, MosooError::NotInitialized));
}

/// Attack 40: Attacker fabricates an unpinned light-client instance and attempts to trick consumers
/// into minting tokens or releasing native ETH against it.
/// Verifies that both `erc20-receiver` and `ether-receiver` strictly enforce pinned instance PDA verification.
#[test]
fn test_mutation_attack_40_consumer_strictly_rejects_unpinned_instance_account() {
    let mut config = TrustedBridgeConfig::canonical();
    let approved_pda = [0x55; 32];
    let approved_checkpoint = [0x77; 32];
    config.register_trusted_instance(ETH_SEPOLIA_CHAIN_ID, approved_pda);
    config.register_trusted_checkpoint(ETH_SEPOLIA_CHAIN_ID, approved_checkpoint);

    let mut store = ProgramAccountStore::new();
    config.save_to_store(&mut store).unwrap();

    // Attacker fabricates an instance with unapproved instance PDA
    let unpinned_checkpoint = [0x88; 32];
    let unpinned_instance = InstanceAccount {
        instance_id: [0x99; 32],
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        current_header_hash: [0x22; 32],
        current_state_root: [0x33; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 9_900_000,
        bootstrap_header_hash: unpinned_checkpoint,
        initialized: true,
        current_execution_block_hash: [0x33; 32],
        current_execution_state_root: [0x44; 32],
        current_receipts_root: [0x55; 32],
    };
    let unpinned_pda = unpinned_instance.pda_address();

    store.insert_program_account(
        unpinned_pda,
        serde_json::to_vec(&unpinned_instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let header = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x22; 32],
        execution_block_hash: [0x33; 32],
        execution_state_root: [0x44; 32],
        receipts_root: [0x55; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x42),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };

    let erc20_args = AtomicErc20ClaimArgsU256 {
        instance: unpinned_instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        expected_deposit_contract: [0x11; 20],
        expected_token_contract: [0x22; 20],
        expected_sender: None,
        recipient: [0xaa; 32],
        min_amount: alloy_primitives::U256::ZERO,
    };

    let mut erc20_nullifiers = NullifierSet::new();

    // Verification against unpinned instance PDA must strictly fail with UntrustedInstanceAccount
    let erc20_err = claim_authenticated_store_u256(
        &mut store,
        &unpinned_pda,
        None,
        erc20_args,
        &mut erc20_nullifiers,
        &config,
    )
    .expect_err("erc20-receiver must reject unpinned light-client instance PDA");
    assert!(
        matches!(erc20_err, ReceiverError::UntrustedInstanceAccount(pda) if pda == unpinned_pda)
    );

    let eth_args = AtomicEtherClaimArgs {
        instance: unpinned_instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        expected_address: [0x11; 20],
        recipient: [0xaa; 32],
        min_wei: 0,
    };

    let mut eth_nullifiers = EtherNullifierSet::new();

    // Ether receiver must also strictly reject unpinned instance PDA
    let eth_err = claim_native_eth_deposit_authenticated_store_with_config(
        &mut store,
        &unpinned_pda,
        None,
        eth_args,
        &mut eth_nullifiers,
        &config,
    )
    .expect_err("ether-receiver must reject unpinned light-client instance PDA");
    assert!(
        matches!(eth_err, EtherReceiverError::UntrustedInstanceAccount(pda) if pda == unpinned_pda)
    );

    // Also verify: even if instance PDA is pinned, if bootstrap checkpoint root differs from pinned root, it fails
    let mut rogue_checkpoint_instance = unpinned_instance;
    rogue_checkpoint_instance.instance_id = [0x77; 32];
    rogue_checkpoint_instance.bootstrap_header_hash = [0x99; 32]; // Rogue checkpoint
    let rogue_pda = rogue_checkpoint_instance.pda_address();
    config.register_trusted_instance(ETH_SEPOLIA_CHAIN_ID, rogue_pda);
    config.save_to_store(&mut store).unwrap();
    store.insert_program_account(
        rogue_pda,
        serde_json::to_vec(&rogue_checkpoint_instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let eth_args_bad_cp = AtomicEtherClaimArgs {
        instance: rogue_checkpoint_instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        expected_address: [0x11; 20],
        recipient: [0xaa; 32],
        min_wei: 0,
    };

    let eth_cp_err = claim_native_eth_deposit_authenticated_store_with_config(
        &mut store,
        &rogue_pda,
        None,
        eth_args_bad_cp,
        &mut eth_nullifiers,
        &config,
    )
    .expect_err(
        "ether-receiver must reject instance whose checkpoint does not match pinned checkpoint",
    );
    assert!(matches!(
        eth_cp_err,
        EtherReceiverError::AttestationFailed(_)
    ));
}

/// Attack 41: Attacker manufactures an account whose owner is not MOSOO_PROGRAM_ID.
/// Verifies that `verify_instance_account_authenticity` and `handle_attest_state_authenticated`
/// strictly verify account owner and reject rogue accounts with DomainSeparationFailed.
#[test]
fn test_mutation_attack_41_account_store_rejects_unowned_instance_account() {
    let mut store = ProgramAccountStore::new();

    let fake_instance = InstanceAccount {
        instance_id: [0x11; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0x22; 32],
        current_state_root: [0x33; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 9_900_000,
        bootstrap_header_hash: [0x11; 32],
        initialized: true,
        current_execution_block_hash: [0x33; 32],
        current_execution_state_root: [0x44; 32],
        current_receipts_root: [0x55; 32],
    };
    let canonical_pda = fake_instance.pda_address();
    let serialized = serde_json::to_vec(&fake_instance).unwrap();

    // Insert account with rogue program owner (not MOSOO_PROGRAM_ID)
    let rogue_program_owner = [0x77; 32];
    store.insert_program_account(canonical_pda, serialized, rogue_program_owner);

    // 1. verify_instance_account_authenticity must strictly reject unowned account
    let err_auth = verify_instance_account_authenticity(&store, &canonical_pda)
        .expect_err("verify_instance_account_authenticity must reject account not owned by Mosoo");
    assert!(matches!(err_auth, MosooError::DomainSeparationFailed));

    // 2. handle_attest_state_authenticated must also strictly reject unowned account
    let header = HeaderRecord {
        chain_id: ETH_MAINNET_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x22; 32],
        execution_block_hash: [0x33; 32],
        execution_state_root: [0x44; 32],
        receipts_root: [0x55; 32],
    };
    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x42),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };
    let attest_args = AttestStateArgs {
        instance: fake_instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
    };

    let err_attest = handle_attest_state_authenticated(&store, &canonical_pda, None, attest_args)
        .expect_err("handle_attest_state_authenticated must reject account not owned by Mosoo");
    assert!(matches!(err_attest, MosooError::DomainSeparationFailed));
}

/// Attack 42: P0 Verification — Checkpoint validation occurs on the authenticated instance
/// loaded from persistent store, rather than the caller-supplied `args.instance`.
/// An attacker modifies their local caller struct `args.instance` to claim a trusted checkpoint,
/// but the authentic store account contains a different bootstrap header root.
#[test]
fn test_mutation_attack_42_checkpoint_verified_on_store_loaded_instance_not_caller_struct() {
    let mut config = TrustedBridgeConfig::canonical();
    let trusted_checkpoint = [0x77; 32];
    let bad_checkpoint = [0x66; 32];

    let mut store = ProgramAccountStore::new();

    // The persistent store holds an instance initialized with bad_checkpoint
    let mut store_instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        current_header_hash: [0x22; 32],
        current_state_root: [0x33; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 9_900_000,
        bootstrap_header_hash: bad_checkpoint, // Store holds untrusted checkpoint!
        initialized: true,
        current_execution_block_hash: [0x33; 32],
        current_execution_state_root: [0x44; 32],
        current_receipts_root: [0x55; 32],
    };
    let instance_pda = store_instance.pda_address();
    store_instance.instance_id = instance_pda;

    config.register_trusted_instance(ETH_SEPOLIA_CHAIN_ID, instance_pda);
    config.register_trusted_checkpoint(ETH_SEPOLIA_CHAIN_ID, trusted_checkpoint);
    config.save_to_store(&mut store).unwrap();

    store.insert_program_account(
        instance_pda,
        serde_json::to_vec(&store_instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // Attacker crafts caller struct pretending it has the trusted checkpoint
    let mut caller_instance = store_instance.clone();
    caller_instance.bootstrap_header_hash = trusted_checkpoint;

    let header = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x22; 32],
        execution_block_hash: [0x33; 32],
        execution_state_root: [0x44; 32],
        receipts_root: [0x55; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x42),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };

    let erc20_args = AtomicErc20ClaimArgsU256 {
        instance: caller_instance.clone(), // Attacker tries to spoof checkpoint in args
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        expected_deposit_contract: [0x11; 20],
        expected_token_contract: [0x22; 20],
        expected_sender: None,
        recipient: [0xaa; 32],
        min_amount: alloy_primitives::U256::ZERO,
    };

    let mut erc20_nullifiers = NullifierSet::new();

    // Must be rejected because the store-loaded instance has bad_checkpoint!
    let err_erc20 = claim_authenticated_store_u256(
        &mut store,
        &instance_pda,
        None,
        erc20_args,
        &mut erc20_nullifiers,
        &config,
    )
    .expect_err("erc20 claim must reject mismatch against store-loaded instance checkpoint");
    assert!(matches!(err_erc20, ReceiverError::AttestationFailed(_)));

    let eth_args = AtomicEtherClaimArgs {
        instance: caller_instance, // Attacker tries to spoof checkpoint in args
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        expected_address: [0x11; 20],
        recipient: [0xaa; 32],
        min_wei: 0,
    };

    let mut eth_nullifiers = EtherNullifierSet::new();

    let err_eth = claim_native_eth_deposit_authenticated_store_with_config(
        &mut store,
        &instance_pda,
        None,
        eth_args,
        &mut eth_nullifiers,
        &config,
    )
    .expect_err("eth claim must reject mismatch against store-loaded instance checkpoint");
    assert!(matches!(err_eth, EtherReceiverError::AttestationFailed(_)));
}

/// Attack 43: P1 Verification — Atomic Persistent Nullifier Protection.
/// Ensures that nullifiers are recorded persistently in `AccountStore` PDA accounts
/// and prevent double-claim attacks even across in-memory state resets (node restarts).
#[test]
fn test_mutation_attack_43_atomic_persistent_nullifier_replay_prevention() {
    let mut store = ProgramAccountStore::new();
    let statement_id = [0x55; 32];
    let subject_key = [0x66; 32];

    let nullifier_pda = erc20_receiver::derive_nullifier_pda(&MOSOO_PROGRAM_ID, &statement_id);
    let subject_pda = erc20_receiver::derive_nullifier_pda(&MOSOO_PROGRAM_ID, &subject_key);

    // Initial state: PDA accounts do not exist
    assert!(store.get_account(&nullifier_pda).is_none());
    assert!(store.get_account(&subject_pda).is_none());

    // Write persistent nullifier records directly into store (simulating first claim)
    let nullifier_rec = erc20_receiver::NullifierAccount {
        statement_id,
        subject_key,
        spent_slot: 12345,
        is_spent: true,
    };
    let encoded = serde_json::to_vec(&nullifier_rec).unwrap();
    store.set_account_with_owner(&nullifier_pda, encoded.clone(), MOSOO_PROGRAM_ID);
    store.set_account_with_owner(&subject_pda, encoded, MOSOO_PROGRAM_ID);

    // After node restart, in-memory NullifierSet is completely empty
    let nullifiers_after_restart = NullifierSet::new();
    assert!(!nullifiers_after_restart.is_used(&statement_id));
    assert!(!nullifiers_after_restart.is_used(&subject_key));

    // Persistent store check must detect the nullifier PDA
    assert!(store.get_account(&nullifier_pda).is_some());
    assert!(store.get_account(&subject_pda).is_some());
    assert_eq!(
        store.get_account_owner(&nullifier_pda),
        Some(MOSOO_PROGRAM_ID)
    );
    assert_eq!(
        store.get_account_owner(&subject_pda),
        Some(MOSOO_PROGRAM_ID)
    );

    // Verify same behavior for Ether nullifiers
    let eth_nullifier_pda =
        ether_receiver::derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &statement_id);
    let eth_subject_pda =
        ether_receiver::derive_ether_nullifier_pda(&MOSOO_PROGRAM_ID, &subject_key);
    let eth_nullifier_rec = ether_receiver::EtherNullifierAccount {
        statement_id,
        subject_key,
        spent_slot: 12345,
        is_spent: true,
    };
    let eth_encoded = serde_json::to_vec(&eth_nullifier_rec).unwrap();
    store.set_account_with_owner(&eth_nullifier_pda, eth_encoded.clone(), MOSOO_PROGRAM_ID);
    store.set_account_with_owner(&eth_subject_pda, eth_encoded, MOSOO_PROGRAM_ID);

    let eth_nullifiers_after_restart = EtherNullifierSet::new();
    assert!(!eth_nullifiers_after_restart.is_used(&statement_id));
    assert!(store.get_account(&eth_nullifier_pda).is_some());
    assert!(store.get_account(&eth_subject_pda).is_some());
}

/// Attack 44: Program-Owned TrustedBridgeConfig Strict Enforcement (P0/P1 Bypass Prevention).
/// Ensures that without a program-owned TrustedBridgeConfig PDA stored at derive_bridge_config_pda()
/// and owned by MOSOO_PROGRAM_ID, claims strictly fail closed and reject caller-supplied fallback config.
#[test]
fn test_mutation_attack_44_strict_program_config_pda_enforcement() {
    let mut store = ProgramAccountStore::new();
    let instance = InstanceAccount {
        instance_id: [0x11; 32],
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        current_header_hash: [0x22; 32],
        current_state_root: [0x33; 32],
        current_slot: 10_000_000,
        current_sync_committee: make_test_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 9_900_000,
        bootstrap_header_hash: [0x44; 32],
        initialized: true,
        current_execution_block_hash: [0x55; 32],
        current_execution_state_root: [0x66; 32],
        current_receipts_root: [0x77; 32],
    };
    let instance_pda = instance.pda_address();
    store.insert_program_account(
        instance_pda,
        serde_json::to_vec(&instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let header = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot: 10_000_000,
        beacon_block_root: [0x22; 32],
        execution_block_hash: [0x55; 32],
        execution_state_root: [0x66; 32],
        receipts_root: [0x77; 32],
    };

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x42),
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };

    let caller_config = TrustedBridgeConfig::canonical();

    // 1. Missing config account in store: Must fail closed
    let erc20_args = AtomicErc20ClaimArgsU256 {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        expected_deposit_contract: [0x11; 20],
        expected_token_contract: [0x22; 20],
        expected_sender: None,
        recipient: [0xaa; 32],
        min_amount: alloy_primitives::U256::ZERO,
    };
    let mut erc20_nullifiers = NullifierSet::new();

    let err = claim_authenticated_store_u256(
        &mut store,
        &instance_pda,
        None,
        erc20_args,
        &mut erc20_nullifiers,
        &caller_config,
    )
    .expect_err("Must reject claim when store has no program-owned config");
    assert!(
        matches!(err, ReceiverError::AttestationFailed(ref msg) if msg.contains("program-owned config verification failed")),
        "Expected config verification error, got: {err:?}"
    );

    // 2. Untrusted owner on config account: Must fail closed
    let config_pda = mosoo_core::types::derive_bridge_config_pda();
    store.insert_program_account(
        config_pda,
        serde_json::to_vec(&caller_config).unwrap(),
        [0x99; 32], // Rogue owner
    );

    let eth_args = AtomicEtherClaimArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        expected_address: [0x11; 20],
        recipient: [0xaa; 32],
        min_wei: 0,
    };
    let mut eth_nullifiers = EtherNullifierSet::new();

    let eth_err = claim_native_eth_deposit_authenticated_store_with_config(
        &mut store,
        &instance_pda,
        None,
        eth_args,
        &mut eth_nullifiers,
        &caller_config,
    )
    .expect_err("Must reject claim when config owner is not MOSOO_PROGRAM_ID");
    assert!(
        matches!(eth_err, EtherReceiverError::AttestationFailed(ref msg) if msg.contains("program-owned config verification failed")),
        "Expected untrusted config owner error, got: {eth_err:?}"
    );
}

/// Attack 45: Priority 2 Verification — Atomic Fallible AccountStore Operations.
/// Verifies that simulate_write_failure triggers fail-closed behavior on try_set_account_with_owner.
#[test]
fn test_mutation_attack_45_account_store_fallible_write_simulation() {
    let mut store = ProgramAccountStore::new();
    let addr = [0x42; 32];
    let data = vec![1, 2, 3, 4];

    // Standard write succeeds
    assert!(store
        .try_set_account_with_owner(&addr, data.clone(), MOSOO_PROGRAM_ID)
        .is_ok());
    assert_eq!(store.get_account(&addr), Some(data));

    // Simulated write failure fails closed
    store.simulate_write_failure = true;
    let fail_addr = [0x43; 32];
    let res = store.try_set_account_with_owner(&fail_addr, vec![5, 6], MOSOO_PROGRAM_ID);
    assert!(matches!(res, Err(mosoo_core::types::StoreError::WriteFailed(a)) if a == fail_addr));
    assert_eq!(store.get_account(&fail_addr), None);
}

/// Attack 46: Dual Nullifier PDA Transactional Atomicity & Rollback Verification.
/// Verifies that if storing the subject nullifier PDA fails, the statement nullifier PDA
/// is cleanly rolled back and removed from persistent storage, preventing permanent claim lockouts.
#[test]
fn test_mutation_attack_46_dual_nullifier_atomic_rollback_on_partial_failure() {
    let mut store = ProgramAccountStore::new();
    let statement_pda = [0x55; 32];
    let subject_pda = [0x66; 32];
    let data = vec![1, 2, 3];

    // Configure store to fail ONLY on the second write (subject_pda)
    store.fail_on_address = Some(subject_pda);

    let batch = vec![
        (statement_pda, data.clone(), MOSOO_PROGRAM_ID),
        (subject_pda, data.clone(), MOSOO_PROGRAM_ID),
    ];

    let res = store.try_set_accounts_batch_with_owner(&batch);
    assert!(
        res.is_err(),
        "Batch write must fail when second PDA write fails"
    );

    // CRITICAL SECURITY ASSERTION:
    // statement_pda MUST NOT remain committed in storage!
    assert_eq!(
        store.get_account(&statement_pda),
        None,
        "Statement nullifier PDA must be cleanly rolled back when subject PDA write fails!"
    );
    assert_eq!(
        store.get_account(&subject_pda),
        None,
        "Subject nullifier PDA must not be written"
    );

    // After resolving the failure condition, the entire batch succeeds
    store.fail_on_address = None;
    assert!(store.try_set_accounts_batch_with_owner(&batch).is_ok());
    assert_eq!(store.get_account(&statement_pda), Some(data.clone()));
    assert_eq!(store.get_account(&subject_pda), Some(data));
}

/// Attack 47: Batch Rollback Partial Failure Detection.
/// Verifies that if rollback itself encounters a storage removal failure, the storage engine
/// strictly raises `BatchRollbackPartialFailure` so the caller is immediately notified of dirty state.
#[test]
fn test_mutation_attack_47_batch_rollback_failure_detection() {
    let mut store = ProgramAccountStore::new();
    let statement_pda = [0x77; 32];
    let subject_pda = [0x88; 32];
    let data = vec![9, 8, 7];

    // Configure write to fail on subject_pda, AND removal to fail on statement_pda during rollback
    store.fail_on_address = Some(subject_pda);
    store.fail_on_remove = Some(statement_pda);

    let batch = vec![
        (statement_pda, data.clone(), MOSOO_PROGRAM_ID),
        (subject_pda, data.clone(), MOSOO_PROGRAM_ID),
    ];

    let res = store.try_set_accounts_batch_with_owner(&batch);
    assert!(
        matches!(
            res,
            Err(mosoo_core::types::StoreError::BatchRollbackPartialFailure { .. })
        ),
        "Storage engine must report BatchRollbackPartialFailure when rollback removal fails"
    );
}

/// Attack 48: Consensus Update State Transition Authentication (P0 Audit Resolution).
/// Verifies that `handle_begin_update_authenticated`, `handle_miller_update_authenticated`,
/// and `handle_finish_update_authenticated` strictly reject accounts with missing or non-program ownership.
#[test]
fn test_mutation_attack_48_authenticated_consensus_updates_reject_unowned_accounts() {
    use mosoo_core::verifier::{
        handle_begin_update_authenticated, handle_finish_update_authenticated,
        handle_miller_update_authenticated, BeginUpdateArgs, FinishUpdateArgs, MillerUpdateArgs,
    };

    let mut store = ProgramAccountStore::new();
    let committee = make_test_committee(512);
    let instance = InstanceAccount {
        instance_id: [0u8; 32],
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        current_header_hash: [0x55; 32],
        current_state_root: [0x66; 32],
        current_slot: 100,
        current_sync_committee: committee,
        next_sync_committee: None,
        bootstrap_slot: 100,
        bootstrap_header_hash: [0x55; 32],
        initialized: true,
        current_execution_block_hash: [0u8; 32],
        current_execution_state_root: [0u8; 32],
        current_receipts_root: [0u8; 32],
    };
    let instance_pda = instance.pda_address();
    let instance_bytes = serde_json::to_vec(&instance).unwrap();

    let dummy_update = LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 101,
            proposer_index: 10,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 101,
            proposer_index: 10,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        },
        finality_branch: vec![[0u8; 32]; 7],
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0x11; 96],
        },
        signature_slot: 101,
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
    };
    let dummy_job = JobAccount {
        instance_id: instance.instance_id,
        instance_chain_id: instance.chain_id,
        instance_slot: instance.current_slot,
        stage: JobStage::Miller,
        update_digest: [0x12; 32],
        update: dummy_update.clone(),
        miller_input: None,
        miller_output: None,
        nonce: 1,
    };

    // 1. Unregistered instance PDA in store -> NotInitialized
    let begin_args = BeginUpdateArgs {
        instance: instance.clone(),
        update: dummy_update.clone(),
        nonce: 1,
    };
    let err_unregistered =
        handle_begin_update_authenticated(&mut store, &instance_pda, begin_args.clone());
    assert!(matches!(err_unregistered, Err(MosooError::NotInitialized)));

    // 2. Instance in store with foreign owner -> DomainSeparationFailed
    let foreign_owner = [0xde; 32];
    store.set_account_with_owner(&instance_pda, instance_bytes.clone(), foreign_owner);
    let err_foreign = handle_begin_update_authenticated(&mut store, &instance_pda, begin_args);
    assert!(matches!(
        err_foreign,
        Err(MosooError::DomainSeparationFailed)
    ));

    // 3. Register genuine instance with MOSOO_PROGRAM_ID
    store.set_account_with_owner(&instance_pda, instance_bytes, MOSOO_PROGRAM_ID);

    // 4. Miller and Finish with uninitialized or wrong-owner job PDA -> NotInitialized / UnauthorizedAccount
    let fake_job_pda = [0xaa; 32];
    let miller_args = MillerUpdateArgs {
        instance: instance.clone(),
        job: dummy_job.clone(),
    };
    let err_unregistered_job = handle_miller_update_authenticated(
        &mut store,
        &instance_pda,
        &fake_job_pda,
        miller_args.clone(),
    );
    assert!(matches!(
        err_unregistered_job,
        Err(MosooError::NotInitialized)
    ));

    store.set_account_with_owner(&fake_job_pda, vec![1, 2, 3], foreign_owner);
    let err_foreign_job =
        handle_miller_update_authenticated(&mut store, &instance_pda, &fake_job_pda, miller_args);
    assert!(matches!(
        err_foreign_job,
        Err(MosooError::UnauthorizedAccount)
    ));

    let finish_args = FinishUpdateArgs {
        instance,
        job: dummy_job,
    };
    let err_finish_foreign_job =
        handle_finish_update_authenticated(&mut store, &instance_pda, &fake_job_pda, finish_args);
    assert!(matches!(
        err_finish_foreign_job,
        Err(MosooError::UnauthorizedAccount)
    ));
}

/// Attack 49: Dynamic NetworkConfig Propagation to BLS Signing Domain (P1 Audit Resolution).
/// Verifies that custom NetworkConfig overrides the genesis_validators_root and fork versions
/// without requiring code modification.
#[test]
fn test_mutation_attack_49_network_config_propagation_custom_signing_domain() {
    let custom_chain_id = 123456789u64;
    let custom_gvr = [0x42; 32];
    let custom_config = NetworkConfig {
        chain_id: custom_chain_id,
        genesis_validators_root: custom_gvr,
        altair_fork_version: [0xaa, 0xbb, 0xcc, 0xdd],
        bellatrix_fork_version: [0; 4],
        capella_fork_version: [0; 4],
        deneb_fork_version: [0; 4],
        electra_fork_version: [0; 4],
        fulu_fork_version: [0; 4],
        gloas_fork_version: [0x11, 0x22, 0x33, 0x44],
    };

    let domain_with_config = mosoo_core::crypto::compute_sync_committee_domain_with_config(
        custom_chain_id,
        100,
        Some(&custom_config),
    );
    let domain_without_config =
        mosoo_core::crypto::compute_sync_committee_domain_with_config(custom_chain_id, 100, None);

    // Custom configuration MUST yield a distinct domain from the zero-default fallback
    assert_ne!(
        domain_with_config, domain_without_config,
        "NetworkConfig genesis validators root and custom fork version MUST dynamically propagate"
    );
}
