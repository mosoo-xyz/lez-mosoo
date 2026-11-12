use super::*;

/// Scenario: Silent Arithmetic Overflow / High-Bit Truncation Prevention.
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

/// Scenario: Malformed RLP Headers Out-of-Bounds Panic Prevention.
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

/// Scenario: Ring Buffer Slot Aliasing Rejection beyond 8,192 Slots.
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
        trusted_head_slot: None,
        privacy_mode: None,
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

/// Scenario: Job Lifecycle Termination & Replay Rejection.
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

/// Scenario: Statement ID Nullifier Malleability Replay Attack.
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

/// Scenario: Strict Instance Immutability & Re-anchoring via Fresh Instance Migration.
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
        trusted_head_slot: None,
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

/// Scenario: Reverted / Failed Transaction Receipt Attestation Rejection.
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

/// Scenario: Out-of-Order Header Slots in Light Client Updates.
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
        trusted_head_slot: None,
    })
    .expect_err("Out-of-order slots must be rejected");
    assert!(
        matches!(err, MosooError::Internal(msg) if msg.contains("attested header slot must be >="))
    );
}

/// Scenario: Deeply Nested Predicate Recursion Limit (zkVM Guest Stack Overflow DOS Prevention).
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

/// Scenario: Mandatory Weak-Subjectivity Checkpoint Freshness & Invariant Enforcement.
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

/// Scenario: False Predicate Fails Closed (No StatementIssued Output).
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
        trusted_head_slot: None,
        privacy_mode: None,
    });

    assert!(
        matches!(res, Err(MosooError::PredicateFailed)),
        "handle_attest_state MUST fail-closed with MosooError::PredicateFailed on unsatisfied condition"
    );
}

/// Scenario: Sync Committee Period-Skip Rejection (Ethereum Altair Light Client Sync Protocol).
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
        trusted_head_slot: None,
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

/// Scenario: Next-Period Signature Without Authenticated Next Committee Rejection.
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
        trusted_head_slot: None,
    })
    .expect_err("Next-period signature without authenticated committee MUST be rejected");

    assert!(matches!(err, MosooError::MissingCommitteeBranch));
}
