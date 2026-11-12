use super::*;

/// Scenario: Fabricated internally-consistent Ethereum header.
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

/// Scenario: Sub-threshold validator quorum (< 342 / 512 validators).
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

/// Scenario: Stale update replay & weak-subjectivity boundary enforcement.
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
        trusted_head_slot: None,
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
        trusted_head_slot: None,
    });

    assert!(
        matches!(expired_res, Err(MosooError::WeakSubjectivityExpired { .. })),
        "handle_begin_update MUST reject updates exceeding weak-subjectivity window"
    );
}

/// Scenario: Forged Sync Committee SSZ Merkle branch (generalized index 54 / 55).
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

/// Scenario: Tampered Execution Payload Header Root & gindex 25 branch.
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

/// Scenario: Cross-Chain Domain Replay (Sepolia -> Mainnet).
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

/// Scenario: Corrupted Receipt-Log Proof, False Predicates & Duplicate Claim Nullifiers.
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

/// Scenario: Unauthenticated / Forged HeaderRecord Injection.
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
    });
    assert!(
        matches!(res_d, Err(MosooError::UnauthenticatedHeaderRecord)),
        "handle_attest_state MUST fail-closed when instance has unauthenticated zero execution roots"
    );
}

/// Scenario: Cross-Block Event Nullifier Collision Attack.
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

/// Scenario: 3-Transaction Pipeline Cross-Stage Tampering & Injected Intermediate State.
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
        trusted_head_slot: None,
    })
    .expect("BeginUpdate succeeds");

    let job = match begin_res {
        InstructionOutput::JobCreated(j) => j,
        _ => panic!("Expected JobCreated"),
    };

    // Tamper with update payload in job before Miller stage
    let mut tampered_job = job.clone();
    tampered_job.update.finalized_header.slot = 99_999_999; // Attacker modified slot in transit!

    let miller_err = handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job: tampered_job,
    })
    .expect_err("MillerUpdate MUST reject tampered update payload");

    assert!(matches!(miller_err, MosooError::JobDigestMismatch { .. }));

    // Cross-chain / wrong instance hijacking
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

    // Out-of-order stage progression (submitting Begin-stage job directly to Finish)
    let ooo_err = handle_finish_update(FinishUpdateArgs {
        instance: instance.clone(),
        job,
    })
    .expect_err("FinishUpdate MUST reject Job in Miller stage");

    assert!(matches!(ooo_err, MosooError::WrongJobStage { .. }));
}

/// Scenario: Bootstrap Next Sync Committee Authentication & Forged Branch Rejection.
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

    // Next committee supplied without branch proof MUST be rejected
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

    // Next committee supplied with corrupted branch MUST be rejected
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

/// Scenario: Historical Block Roots Accumulator Proof Anchor & Spec Compliance.
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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

/// Scenario: Nullifier Collision & Replay Resistance on Repeat Transfers.
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
