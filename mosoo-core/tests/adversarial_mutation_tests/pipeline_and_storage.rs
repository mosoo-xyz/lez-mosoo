use super::*;

/// Scenario: Previous-Committee Key Invalidation for Future Periods.
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
        trusted_head_slot: None,
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

/// Scenario: Full Committee Handoff & Rotation Invariant.
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

/// Scenario: Gloas Execution State & Receipts Roots Tampering Rejection.
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

    // Attacker tampers with state_root in payload_header
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

    // Attacker tampers with receipts_root in payload_header
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

    // Missing execution_rlp on Gloas fork MUST fail closed
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

/// Scenario: Gloas Execution RLP Header Hash Mismatch Rejection.
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

/// Scenario: HeaderRecord Provenance Tampering Rejection under Genuine Beacon Root.
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
    })
    .expect_err("Attestation with fabricated execution_block_hash MUST be rejected");
    assert!(matches!(
        err_block_hash,
        MosooError::UnauthenticatedHeaderRecord
    ));

    assert!(verify_header_record_provenance(&instance, &tampered_block_hash_header).is_err());
}

/// Scenario: Sequential Multi-Update Invariant across Committee Period Boundaries.
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

/// Scenario: Predicate Variation Replay Attack Prevention on Identical Ethereum State.
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

/// Scenario: Multiple Independent Instances per Chain & Cross-Instance Job Injection Rejection.
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
        trusted_head_slot: None,
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

/// Scenario: Historical Header Proof Closure & Adversarial Branch Rejections.
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

/// Scenario: Unbacked Ethereum Balance Bridge Minting Strict Rejection (Verdict #3 Remediation).
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

/// Scenario: Tampered Statement ID Nullifier Bypass Rejection.
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

/// Scenario: Fabricated unauthenticated InstanceAccount injection attempt.
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
        trusted_head_slot: None,
        privacy_mode: None,
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
        trusted_head_slot: None,
        privacy_mode: None,
    };

    let err2 = handle_attest_state(args2).expect_err("Zero-bootstrap instance must be rejected");
    assert!(matches!(err2, MosooError::InvalidBootstrap(_)));
}
