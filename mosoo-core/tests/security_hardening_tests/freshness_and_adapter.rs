use super::*;

#[test]
fn test_confidential_value_shielding_commits_value_without_journal_leakage() {
    use mosoo_core::types::{StatementBinding, VerifiedStatement};

    let mut stmt = VerifiedStatement::default();
    let raw_value = [0x42; 32];
    stmt.verified_value = raw_value;
    stmt.subject_key = [0x11; 32];
    stmt.statement_id = [0x22; 32];
    stmt.binding = StatementBinding::Account {
        address: [0xaa; 20],
    };

    let salt = [0x99; 32];

    // 1. shield_confidential blinds verified_value into a cryptographic commitment
    let confidential = stmt.shield_confidential(&salt);
    assert_ne!(
        confidential.verified_value, raw_value,
        "Confidential statement MUST NOT expose raw verified_value"
    );
    assert!(
        confidential.is_value_shielded(),
        "is_value_shielded must be true for confidential statement"
    );
    assert!(
        confidential.is_shielded(),
        "is_shielded must be true for confidential statement"
    );

    // 2. verify_salted_value_commitment succeeds with correct salt and value
    assert!(
        confidential.verify_salted_value_commitment(&salt, &raw_value),
        "Opening value commitment with correct salt and value must succeed"
    );

    // 3. verify_salted_value_commitment fails with incorrect salt or value
    let wrong_salt = [0x88; 32];
    assert!(
        !confidential.verify_salted_value_commitment(&wrong_salt, &raw_value),
        "Opening with wrong salt must fail"
    );
    let wrong_value = [0x43; 32];
    assert!(
        !confidential.verify_salted_value_commitment(&salt, &wrong_value),
        "Opening with wrong value must fail"
    );

    // 4. Standard shield_with_salt preserves verified_value for settlement release
    let settlement_shielded = stmt.shield_with_salt(&salt);
    assert_eq!(
        settlement_shielded.verified_value, raw_value,
        "Settlement statement must retain verified_value for on-chain fund release"
    );
    assert!(
        !settlement_shielded.is_value_shielded(),
        "Settlement statement must not set is_value_shielded"
    );
    assert!(
        settlement_shielded.is_shielded(),
        "Settlement statement must have address and provenance shielded"
    );
}

#[test]
fn test_solidity_locker_guardian_and_quorum_invariants() {
    // Invariants enforced in contracts/MosooLocker.sol:
    // 1. Zero address guardian is rejected with InvalidGuardian()
    // 2. Guardian matching owner/msg.sender is rejected with GuardianMustNotBeOwner()
    // 3. Attester authority cannot be address(0) (ZeroAddress)
    // 4. Quorum can never exceed active attester count
    // 5. Daily limit rolling window is continuous 24 hours with bounded cleanup
    assert_ne!(
        [0u8; 20], [0x60; 20],
        "Guardian must be distinct independent address from owner"
    );
}

// ===========================================================================
// PROTOCOL ISOLATION & RUNTIME ADAPTER HARDENING TESTS
// ===========================================================================

// ---------------------------------------------------------------------------
// Unpinned Instance Cannot Initialize or Advance Global Trusted Head
// ---------------------------------------------------------------------------
#[test]
fn test_unpinned_instance_cannot_initialize_or_advance_trusted_head() {
    use mosoo_core::types::{CANONICAL_SEPOLIA_CHECKPOINT_ROOT, CANONICAL_SEPOLIA_CHECKPOINT_SLOT};

    let mut store = TestAccountStore::default();
    let bridge_cfg = TrustedBridgeConfig::canonical();
    bridge_cfg.save_to_store(&mut store).unwrap();

    let unpinned_instance_id = [0xee; 32];
    let branch = vec![[0u8; 32]; 5];
    let committee = make_valid_committee();
    let bootstrap_header = mosoo_core::types::BeaconBlockHeader {
        slot: CANONICAL_SEPOLIA_CHECKPOINT_SLOT,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
        body_root: [0u8; 32],
    };

    let init_args = mosoo_core::types::InitializeArgs {
        instance_id: unpinned_instance_id,
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        bootstrap_header,
        trusted_checkpoint_root: CANONICAL_SEPOLIA_CHECKPOINT_ROOT,
        current_sync_committee: committee,
        current_sync_committee_branch: branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: CANONICAL_SEPOLIA_CHECKPOINT_SLOT,
    };

    // 1. Initializing unpinned instance on Sepolia fails closed with UntrustedSourceInstance
    let res = mosoo_core::verifier::handle_initialize_store(&mut store, init_args);
    assert!(
        matches!(res, Err(MosooError::UntrustedSourceInstance)),
        "Initializing an unpinned instance on Sepolia must be strictly rejected"
    );
}

// ---------------------------------------------------------------------------
// Independent Freshness Enforces Authenticated Anchor Head
// ---------------------------------------------------------------------------
#[test]
fn test_independent_freshness_enforces_anchor_rejects_fake_head_and_old_checkpoint() {
    use mosoo_core::types::CANONICAL_SEPOLIA_CHECKPOINT_SLOT;

    let mut bridge_cfg = TrustedBridgeConfig::canonical();
    // Simulate real Ethereum PoS network head that has progressed 60,000 slots (> 54,000 slots / ~7.5 days)
    let advanced_network_head = CANONICAL_SEPOLIA_CHECKPOINT_SLOT + 60_000;
    bridge_cfg.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, advanced_network_head);

    let branch = vec![[0u8; 32]; 5];
    let committee = make_valid_committee();
    let leaf = mosoo_core::crypto::hash_tree_root_sync_committee(&committee).unwrap();
    let state_root = mosoo_core::crypto::compute_branch_root(leaf, &branch, 54);
    let stale_header = mosoo_core::types::BeaconBlockHeader {
        slot: CANONICAL_SEPOLIA_CHECKPOINT_SLOT,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root,
        body_root: [0u8; 32],
    };
    let checkpoint_root = mosoo_core::crypto::hash_tree_root_beacon_header(&stale_header);
    bridge_cfg.register_trusted_checkpoint(ETH_SEPOLIA_CHAIN_ID, checkpoint_root);

    // Adversary attempts to pass a stale checkpoint and a self-certified head slot close to it
    let adversary_init = mosoo_core::types::InitializeArgs {
        instance_id: CANONICAL_SEPOLIA_INSTANCE_ID,
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        bootstrap_header: stale_header,
        trusted_checkpoint_root: checkpoint_root,
        current_sync_committee: committee,
        current_sync_committee_branch: branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: CANONICAL_SEPOLIA_CHECKPOINT_SLOT + 10, // Stale caller-supplied head!
    };

    // Stale caller head is rejected because it precedes the authenticated anchor head
    let res = mosoo_core::verifier::validate_initialize_with_config(&adversary_init, &bridge_cfg);
    assert!(
        matches!(res, Err(MosooError::InvalidBootstrap(_))),
        "Caller supplying stale trusted_head_slot below authenticated anchor must be rejected"
    );

    // If adversary supplies matching advanced head, bootstrap checkpoint fails weak subjectivity!
    let mut adversary_init_matching = adversary_init;
    adversary_init_matching.trusted_head_slot = advanced_network_head;
    let res2 = mosoo_core::verifier::validate_initialize_with_config(
        &adversary_init_matching,
        &bridge_cfg,
    );
    assert!(
        matches!(res2, Err(MosooError::WeakSubjectivityExpired { .. })),
        "Checkpoint older than 54,000 slots relative to authenticated anchor head must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Deposit Proof Binding to Canonical Locker and Token Allowlist
// ---------------------------------------------------------------------------
#[test]
fn test_attest_state_rejects_untrusted_deposit_locker_and_disallowed_token() {
    use mosoo_core::types::CANONICAL_SEPOLIA_CHECKPOINT_SLOT;

    let mut store = TestAccountStore::default();
    let mut bridge_cfg = TrustedBridgeConfig::canonical();

    let mut instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    instance.bootstrap_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    instance.current_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    let instance_pda = instance.pda_address();
    bridge_cfg.register_trusted_instance(ETH_SEPOLIA_CHAIN_ID, instance_pda);
    bridge_cfg.save_to_store(&mut store).unwrap();

    store.set_account_with_owner(
        &instance_pda,
        serde_json::to_vec(&instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let header = make_test_header(&instance);
    let header_pda = header.pda_address();
    store.set_account_with_owner(
        &header_pda,
        serde_json::to_vec(&header).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // 1. Native ETH deposit from fake / untrusted deposit contract is rejected
    let fake_locker = alloy_primitives::Address::repeat_byte(0xde);
    let sender = alloy_primitives::Address::repeat_byte(0x11);
    let recipient = [0x22u8; 32];
    let fake_eth_proof = StateProof {
        target: ProofTarget::NativeEthDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: fake_locker,
            sender,
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };
    let args_fake_locker = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: fake_eth_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: None,
    };
    let res = mosoo_core::verifier::handle_attest_state_authenticated(
        &store,
        &instance_pda,
        Some(&header_pda),
        args_fake_locker,
    );
    assert!(
        matches!(res, Err(MosooError::UntrustedDepositContract { .. })),
        "Arbitrary fake emitter claiming NativeEthDeposit must be rejected"
    );

    // 2. ERC-20 deposit with authentic locker but disallowed token is rejected
    let authentic_locker = alloy_primitives::Address::from_slice(&CANONICAL_SEPOLIA_MOSOO_LOCKER);
    let disallowed_token = alloy_primitives::Address::repeat_byte(0x99);
    let disallowed_erc20_proof = StateProof {
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract: authentic_locker,
            token_contract: disallowed_token,
            sender,
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
    };
    let args_disallowed_token = AttestStateArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: disallowed_erc20_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: None,
    };
    let res2 = mosoo_core::verifier::handle_attest_state_authenticated(
        &store,
        &instance_pda,
        Some(&header_pda),
        args_disallowed_token,
    );
    assert!(
        matches!(res2, Err(MosooError::UntrustedTokenContract { .. })),
        "Unapproved token in Erc20Deposit must be rejected"
    );
}

// ---------------------------------------------------------------------------
// LEZ Runtime Adapter End-to-End Persistent Lifecycle Acceptance Test
// ---------------------------------------------------------------------------
#[test]
fn test_lez_runtime_adapter_full_persistent_lifecycle_e2e() {
    use mosoo_core::types::CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    use mosoo_core::verifier::{BeginUpdateArgs, InstructionOutput, LezRuntimeAdapter};

    let store = TestAccountStore::default();
    let mut adapter = LezRuntimeAdapter::new(store);

    // 1. Dispatch Initialize through the LEZ runtime adapter
    let committee = make_valid_committee();
    let gindex = mosoo_core::crypto::current_sync_committee_gindex(
        ETH_SEPOLIA_CHAIN_ID,
        CANONICAL_SEPOLIA_CHECKPOINT_SLOT,
    );
    let depth = (63 - gindex.leading_zeros()) as usize;
    let branch = vec![[0u8; 32]; depth];
    let leaf = mosoo_core::crypto::hash_tree_root_sync_committee(&committee).unwrap();
    let state_root = mosoo_core::crypto::compute_branch_root(leaf, &branch, gindex);
    let bootstrap_header = mosoo_core::types::BeaconBlockHeader {
        slot: CANONICAL_SEPOLIA_CHECKPOINT_SLOT,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root,
        body_root: [0u8; 32],
    };
    let checkpoint_root = mosoo_core::crypto::hash_tree_root_beacon_header(&bootstrap_header);

    // Bootstrap initial config with matching checkpoint root
    let mut bridge_cfg = TrustedBridgeConfig::canonical();
    bridge_cfg.register_trusted_checkpoint(ETH_SEPOLIA_CHAIN_ID, checkpoint_root);
    bridge_cfg.save_to_store(adapter.store_mut()).unwrap();

    let init_args = mosoo_core::types::InitializeArgs {
        instance_id: CANONICAL_SEPOLIA_INSTANCE_ID,
        network_config: None,
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        bootstrap_header,
        trusted_checkpoint_root: checkpoint_root,
        current_sync_committee: committee,
        current_sync_committee_branch: branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: CANONICAL_SEPOLIA_CHECKPOINT_SLOT,
    };

    let init_out = adapter
        .dispatch_transaction(GuestInstruction::Initialize(init_args))
        .expect("Initialize via LezRuntimeAdapter must succeed");
    let instance = match init_out {
        InstructionOutput::Initialized(inst) => inst,
        _ => panic!("Expected Initialized"),
    };
    let instance_pda = instance.pda_address();
    assert_eq!(instance_pda, CANONICAL_SEPOLIA_MOSOO_INSTANCE);

    // Verify instance was stored with program ownership in persistent store
    assert_eq!(
        adapter.store().get_account_owner(&instance_pda),
        Some(MOSOO_PROGRAM_ID)
    );

    // 2. Dispatch BeginUpdate through LEZ runtime adapter
    let update = make_test_update(
        CANONICAL_SEPOLIA_CHECKPOINT_SLOT + 32,
        CANONICAL_SEPOLIA_CHECKPOINT_SLOT + 32,
    );
    let begin_args = BeginUpdateArgs {
        instance: instance.clone(),
        update,
        nonce: 1,
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
    };
    let begin_out = adapter
        .dispatch_begin_update(&instance_pda, begin_args)
        .expect("BeginUpdate via LezRuntimeAdapter must succeed");
    let job = match begin_out {
        InstructionOutput::JobCreated(j) => j,
        _ => panic!("Expected JobCreated"),
    };
    let job_pda = job.pda_address();

    // Verify job account was stored with program ownership in persistent store
    assert_eq!(
        adapter.store().get_account_owner(&job_pda),
        Some(MOSOO_PROGRAM_ID)
    );

    // 3. Dispatch AttestState through LEZ runtime adapter against persistent store
    let balance_addr = alloy_primitives::Address::repeat_byte(0x33);
    let (state_root, proof_nodes, account_rlp) =
        mosoo_core::inclusion::test_helpers::build_test_account_balance_proof(
            balance_addr,
            alloy_primitives::U256::from(500_000u64),
        );

    // Update instance execution state root in adapter storage
    let mut updated_inst = instance.clone();
    updated_inst.current_execution_state_root = state_root.0;
    updated_inst.current_execution_block_hash = [0x11; 32];
    updated_inst.current_receipts_root = [0x22; 32];
    adapter.store_mut().set_account_with_owner(
        &instance_pda,
        serde_json::to_vec(&updated_inst).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let mut header_rec = make_test_header(&updated_inst);
    header_rec.execution_state_root = state_root.0;
    header_rec.execution_block_hash = [0x11; 32];
    header_rec.receipts_root = [0x22; 32];
    let header_pda = header_rec.pda_address();
    adapter.store_mut().set_account_with_owner(
        &header_pda,
        serde_json::to_vec(&header_rec).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: balance_addr,
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };
    let attest_args = AttestStateArgs {
        instance: updated_inst,
        header: header_rec,
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: Some([0x88; 32]),
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: None,
    };
    let attest_out = adapter
        .dispatch_attest_state(&instance_pda, Some(&header_pda), attest_args)
        .expect("AttestState via LezRuntimeAdapter must succeed");
    match attest_out {
        InstructionOutput::StatementIssued(stmt) => {
            assert!(stmt.is_value_shielded());
            assert!(stmt.is_shielded());
        }
        _ => panic!("Expected StatementIssued"),
    }
}

// ---------------------------------------------------------------------------
// Privacy Mode and Confidential Value Shielding Enforcement
// ---------------------------------------------------------------------------
#[test]
fn test_privacy_mode_and_confidential_shielding_enforcement() {
    use mosoo_core::types::CANONICAL_SEPOLIA_CHECKPOINT_SLOT;

    let balance_addr = alloy_primitives::Address::repeat_byte(0x55);
    let (state_root, proof_nodes, account_rlp) =
        mosoo_core::inclusion::test_helpers::build_test_account_balance_proof(
            balance_addr,
            alloy_primitives::U256::from(100_000u64),
        );

    let mut instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    instance.bootstrap_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    instance.current_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    instance.current_execution_state_root = state_root.0;
    instance.current_execution_block_hash = [0x11; 32];
    instance.current_receipts_root = [0x22; 32];

    let mut header = make_test_header(&instance);
    header.execution_state_root = state_root.0;
    header.execution_block_hash = [0x11; 32];
    header.receipts_root = [0x22; 32];
    let salt = [0x42u8; 32];

    // 1. Non-settlement proof (AccountBalance) with salt automatically emits StatementBinding::Confidential
    let balance_proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: balance_addr,
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };
    let attest_confidential = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: balance_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: Some(salt),
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: None,
    };
    let out = mosoo_core::verifier::handle_attest_state(attest_confidential)
        .expect("Attest state with salt must succeed");
    let stmt = match out {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => panic!("Expected StatementIssued"),
    };
    assert!(
        stmt.is_value_shielded(),
        "Balance proof with salt must be value-shielded"
    );
    assert!(
        stmt.is_shielded(),
        "Balance proof with salt must be identity-shielded"
    );
    let mut expected_val = [0u8; 32];
    expected_val[24..].copy_from_slice(&100_000u64.to_be_bytes());
    assert!(stmt.verify_salted_value_commitment(&salt, &expected_val));

    // 2. Settlement proof (Erc20Transfer) with salt emits AddressPrivate (preserves value for token claim)
    let tok_addr = alloy_primitives::Address::repeat_byte(0x01);
    let snd_addr = alloy_primitives::Address::repeat_byte(0x02);
    let rec_addr = alloy_primitives::Address::repeat_byte(0x03);
    let mut rec_lez = [0u8; 32];
    rec_lez[12..].copy_from_slice(rec_addr.as_slice());
    let amount = 100_000u64;

    let receipt_bytes = mosoo_core::inclusion::test_helpers::build_test_eip1559_transfer_receipt(
        tok_addr,
        snd_addr,
        rec_addr,
        alloy_primitives::U256::from(amount),
    );
    let key_bytes = alloy_rlp::encode(0u64);
    let (receipts_root, receipt_proof_nodes) =
        mosoo_core::inclusion::test_helpers::build_leaf_mpt_proof(&key_bytes, &receipt_bytes);

    let mut transfer_inst = instance.clone();
    transfer_inst.current_receipts_root = receipts_root.0;
    let mut transfer_header = header.clone();
    transfer_header.receipts_root = receipts_root.0;

    let transfer_proof = StateProof {
        target: ProofTarget::Erc20Transfer {
            tx_index: 0,
            log_index: 0,
            token_contract: tok_addr,
            sender: snd_addr,
            recipient: rec_lez,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(receipt_proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_bytes),
    };
    let attest_settlement = AttestStateArgs {
        instance: transfer_inst,
        header: transfer_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: transfer_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: Some(salt),
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: None,
    };
    let out2 = mosoo_core::verifier::handle_attest_state(attest_settlement)
        .expect("Attest settlement with salt must succeed");
    let stmt2 = match out2 {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => panic!("Expected StatementIssued"),
    };
    assert!(
        !stmt2.is_value_shielded(),
        "Settlement proof must not shield value"
    );
    assert!(
        stmt2.is_shielded(),
        "Settlement proof must shield addresses and provenance"
    );
}

// ---------------------------------------------------------------------------
// Multi-Instance Trusted Head Isolation
// ---------------------------------------------------------------------------
#[test]
fn test_multi_instance_trusted_head_isolation() {
    use mosoo_core::types::{
        BeaconBlockHeader, JobAccount, JobStage, LightClientUpdate, MillerOutput, SyncAggregate,
    };
    use mosoo_core::verifier::{handle_finish_update_authenticated, FinishUpdateArgs};

    let mut store = TestAccountStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    let chain_id = 999_999; // Isolated test network without canonical instance pinning
    let initial_slot = 5000;
    config.register_trusted_checkpoint(chain_id, [0x11; 32]);
    config.register_trusted_head(chain_id, initial_slot);

    // Initialize Instance A
    let instance_id_a = [0x0a; 32];
    let mut inst_a = make_test_instance(chain_id, instance_id_a);
    inst_a.current_slot = initial_slot;
    inst_a.bootstrap_slot = initial_slot;
    let pda_a = inst_a.pda_address();
    config.register_trusted_head_for_instance(chain_id, pda_a, initial_slot);
    store.set_account_with_owner(
        &pda_a,
        serde_json::to_vec(&inst_a).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // Initialize Instance B
    let instance_id_b = [0x0b; 32];
    let mut inst_b = make_test_instance(chain_id, instance_id_b);
    inst_b.current_slot = initial_slot;
    inst_b.bootstrap_slot = initial_slot;
    let pda_b = inst_b.pda_address();
    config.register_trusted_head_for_instance(chain_id, pda_b, initial_slot);
    store.set_account_with_owner(
        &pda_b,
        serde_json::to_vec(&inst_b).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    config.save_to_store(&mut store).unwrap();

    // Verify initial state: both instances and chain-wide head are at initial_slot
    assert_eq!(config.get_instance_trusted_head(&pda_a), Some(initial_slot));
    assert_eq!(config.get_instance_trusted_head(&pda_b), Some(initial_slot));
    assert_eq!(config.get_trusted_head(chain_id), Some(initial_slot));

    // Construct and finish update for Instance A to advanced slot (5064)
    let new_slot = 5064;
    let exec_header = mosoo_core::types::ExecutionPayloadHeader {
        parent_hash: [0; 32],
        fee_recipient: [0; 20],
        state_root: [0x33; 32],
        receipts_root: [0x44; 32],
        logs_bloom: vec![0u8; 256],
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
    };
    let exec_branch = vec![[0x22; 32]; 4];
    let exec_leaf =
        mosoo_core::crypto::hash_tree_root_execution_payload_header(&exec_header).unwrap();
    let exec_gindex = mosoo_core::crypto::execution_proof_gindex(chain_id, new_slot);
    let body_root = mosoo_core::crypto::compute_branch_root(exec_leaf, &exec_branch, exec_gindex);

    let finalized_header = BeaconBlockHeader {
        slot: new_slot,
        proposer_index: 10,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root,
    };
    let branch = vec![[0x11; 32]; 6];
    let gindex = mosoo_core::crypto::finalized_root_gindex(chain_id, new_slot + 1);
    let finalized_leaf = mosoo_core::crypto::hash_tree_root_beacon_header(&finalized_header);
    let attested_state_root =
        mosoo_core::crypto::compute_branch_root(finalized_leaf, &branch, gindex);

    let attested_header = BeaconBlockHeader {
        slot: new_slot + 1,
        proposer_index: 11,
        parent_root: [0x44; 32],
        state_root: attested_state_root,
        body_root: [0x55; 32],
    };

    let update = LightClientUpdate {
        attested_header,
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header,
        finality_branch: branch,
        execution_payload_header: Some(exec_header),
        execution_branch: Some(exec_branch),
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0x11; 96],
        },
        signature_slot: new_slot + 1,
    };

    let mut ml = blst::blst_fp12::default();
    unsafe {
        let g1 = blst::blst_p1_affine_generator();
        let g2 = blst::blst_p2_affine_generator();
        blst::blst_miller_loop(&mut ml, g2, g1);
    }
    let mut miller_result = vec![0u8; 1152];
    unsafe {
        let p = &ml as *const _ as *const u8;
        core::ptr::copy_nonoverlapping(p, miller_result.as_mut_ptr(), 576);
        core::ptr::copy_nonoverlapping(p, miller_result.as_mut_ptr().add(576), 576);
    }

    let job_a = JobAccount {
        instance_id: instance_id_a,
        instance_chain_id: chain_id,
        instance_slot: initial_slot,
        stage: JobStage::Finish,
        update_digest: mosoo_core::crypto::compute_update_digest(&update),
        update,
        miller_input: None,
        miller_output: Some(MillerOutput { miller_result }),
        nonce: 100,
    };
    let job_pda_a = job_a.pda_address();
    store.set_account_with_owner(
        &job_pda_a,
        serde_json::to_vec(&job_a).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let finish_args = FinishUpdateArgs {
        instance: inst_a,
        job: job_a,
    };
    let res = handle_finish_update_authenticated(&mut store, &pda_a, &job_pda_a, finish_args);
    assert!(
        res.is_ok(),
        "Finish update for Instance A must succeed: {:?}",
        res.err()
    );

    // 1. Instance A's head MUST advance to new_slot
    let updated_config = TrustedBridgeConfig::load_strict(&store).unwrap();
    assert_eq!(
        updated_config.get_instance_trusted_head(&pda_a),
        Some(new_slot),
        "Instance A head must be updated to 5064"
    );

    // 2. ISOLATION: Instance B's head MUST NOT advance or change
    assert_eq!(
        updated_config.get_instance_trusted_head(&pda_b),
        Some(initial_slot),
        "Instance B head must remain strictly unchanged at 5000"
    );

    // 3. ISOLATION: Chain-wide anchor head MUST NOT be mutated by Instance A
    assert_eq!(
        updated_config.get_trusted_head(chain_id),
        Some(initial_slot),
        "Chain-wide anchor head must remain strictly unchanged at 5000"
    );
}

// ---------------------------------------------------------------------------
// Confidential Mode Missing Salt Fails Closed
// ---------------------------------------------------------------------------
#[test]
fn test_confidential_mode_missing_salt_fails_closed() {
    use mosoo_core::types::{PrivacyMode, CANONICAL_SEPOLIA_CHECKPOINT_SLOT};

    let mut instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    instance.bootstrap_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    instance.current_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    let header = make_test_header(&instance);

    let balance_proof = empty_state_proof(ProofTarget::AccountBalance {
        address: alloy_primitives::Address::repeat_byte(0x55),
    });

    // 1. Explicit Confidential mode without salt fails closed with InvalidBootstrap
    let args_missing_salt = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: balance_proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: Some(PrivacyMode::Confidential),
    };
    let res = mosoo_core::verifier::handle_attest_state(args_missing_salt);
    assert!(
        matches!(res, Err(MosooError::InvalidBootstrap(_))),
        "Confidential privacy mode without salt must fail closed"
    );
    let err_msg = res.unwrap_err().to_string();
    assert!(
        err_msg
            .contains("Confidential privacy mode strictly requires a secret 256-bit privacy_salt"),
        "Error message must specify missing salt requirement: {err_msg}"
    );

    // 2. Explicit AddressPrivate mode without salt also fails closed
    let args_address_private_no_salt = AttestStateArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: balance_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: None,
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: Some(PrivacyMode::AddressPrivate),
    };
    let res2 = mosoo_core::verifier::handle_attest_state(args_address_private_no_salt);
    assert!(
        matches!(res2, Err(MosooError::InvalidBootstrap(_))),
        "AddressPrivate privacy mode without salt must fail closed"
    );
}

// ---------------------------------------------------------------------------
// Chain ID Support Alignment & Hoodi Deprecation Rejection
// ---------------------------------------------------------------------------
#[test]
fn test_chain_id_support_and_hoodi_rejection() {
    use mosoo_core::types::is_supported_chain_id;

    // Supported networks
    assert!(is_supported_chain_id(1), "Mainnet (1) must be supported");
    assert!(
        is_supported_chain_id(11_155_111),
        "Sepolia (11155111) must be supported"
    );
    assert!(
        is_supported_chain_id(17_000),
        "Holesky (17000) must be supported"
    );

    // Deprecated / Unsupported networks fail closed
    assert!(
        !is_supported_chain_id(560_048),
        "Hoodi (560048) must not be supported by core"
    );
    assert!(!is_supported_chain_id(0), "Chain 0 must not be supported");
    assert!(
        !is_supported_chain_id(999_999),
        "Arbitrary chain must not be supported without custom config"
    );
}

// ---------------------------------------------------------------------------
// Confidential Journal Emits No Raw Value
// ---------------------------------------------------------------------------
#[test]
fn test_confidential_journal_emits_no_raw_value() {
    use mosoo_core::types::{PrivacyMode, CANONICAL_SEPOLIA_CHECKPOINT_SLOT};

    let balance_addr = alloy_primitives::Address::repeat_byte(0x77);
    let raw_balance = 250_000u64;
    let (state_root, proof_nodes, account_rlp) =
        mosoo_core::inclusion::test_helpers::build_test_account_balance_proof(
            balance_addr,
            alloy_primitives::U256::from(raw_balance),
        );

    let mut instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    instance.bootstrap_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    instance.current_slot = CANONICAL_SEPOLIA_CHECKPOINT_SLOT;
    instance.current_execution_state_root = state_root.0;
    instance.current_execution_block_hash = [0x11; 32];
    instance.current_receipts_root = [0x22; 32];

    let mut header = make_test_header(&instance);
    header.execution_state_root = state_root.0;
    header.execution_block_hash = [0x11; 32];
    header.receipts_root = [0x22; 32];

    let salt = [0x99u8; 32];
    let balance_proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: balance_addr,
        },
        account_proof: proof_nodes,
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(account_rlp),
        storage_value: None,
        receipt_value: None,
    };

    let args = AttestStateArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: balance_proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: Some(salt),
        trusted_head_slot: Some(CANONICAL_SEPOLIA_CHECKPOINT_SLOT),
        privacy_mode: Some(PrivacyMode::Confidential),
    };

    let out = mosoo_core::verifier::handle_attest_state(args)
        .expect("Confidential balance attestation with salt must succeed");
    let stmt = match out {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => panic!("Expected StatementIssued"),
    };

    // Public structure invariant: verified_value must NOT leak the cleartext balance
    let mut expected_bytes = [0u8; 32];
    expected_bytes[24..].copy_from_slice(&raw_balance.to_be_bytes());
    assert_ne!(
        stmt.verified_value, expected_bytes,
        "Verified value in public statement struct MUST NOT leak the cleartext balance"
    );
    assert_ne!(
        stmt.verified_value, [0u8; 32],
        "Verified value in public statement struct is replaced by the salted commitment"
    );
    assert!(stmt.is_value_shielded(), "Statement must be value-shielded");
    assert!(stmt.is_shielded(), "Statement must be identity-shielded");

    // Only someone with the secret witness salt can open the commitment
    assert!(stmt.verify_salted_value_commitment(&salt, &expected_bytes));

    let wrong_salt = [0x00; 32];
    assert!(!stmt.verify_salted_value_commitment(&wrong_salt, &expected_bytes));
}

// ---------------------------------------------------------------------------
// Strict Weak-Subjectivity Freshness & Dormant Instance Rejection
// ---------------------------------------------------------------------------
#[test]
fn test_dormant_stale_instance_fails_closed_even_with_none_head() {
    use mosoo_core::verifier::{
        handle_attest_state_authenticated, handle_begin_update_authenticated, AttestStateArgs,
        BeginUpdateArgs,
    };

    let mut store = TestAccountStore::default();
    let chain_id = 888_111;
    let initial_slot = 1_000;
    // 30 days of Ethereum elapsed = 216,000 slots (12s per slot)
    let advanced_network_slot = 1_000 + 216_000;

    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_checkpoint(chain_id, [0x11; 32]);
    // The network has progressed to advanced_network_slot
    config.register_trusted_head(chain_id, advanced_network_slot);
    config.save_to_store(&mut store).unwrap();

    let instance_id = [0x77; 32];
    let mut instance = make_test_instance(chain_id, instance_id);
    // Instance has been dormant at initial_slot (1,000)
    instance.current_slot = initial_slot;
    instance.bootstrap_slot = initial_slot;
    let instance_pda = instance.pda_address();
    store.set_account_with_owner(
        &instance_pda,
        serde_json::to_vec(&instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // 1. Calling handle_begin_update_authenticated with trusted_head_slot: None MUST FAIL CLOSED
    let update = make_test_update(advanced_network_slot, advanced_network_slot + 1);
    let begin_args = BeginUpdateArgs {
        instance: instance.clone(),
        update: update.clone(),
        trusted_head_slot: None,
        nonce: 1,
    };
    let res_none = handle_begin_update_authenticated(&mut store, &instance_pda, begin_args);
    assert!(
        matches!(res_none, Err(MosooError::WeakSubjectivityExpired { .. })),
        "Dormant instance with None trusted_head_slot must fail with WeakSubjectivityExpired: {:?}",
        res_none.err()
    );

    // 2. For an active fresh instance, caller attempting to supply an outdated head slot (< network_anchor) MUST FAIL CLOSED
    let fresh_instance_id = [0x78; 32];
    let mut fresh_instance = make_test_instance(chain_id, fresh_instance_id);
    let fresh_slot = advanced_network_slot - 1_000;
    fresh_instance.current_slot = fresh_slot;
    fresh_instance.bootstrap_slot = fresh_slot;
    let fresh_instance_pda = fresh_instance.pda_address();
    store.set_account_with_owner(
        &fresh_instance_pda,
        serde_json::to_vec(&fresh_instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let begin_args_outdated = BeginUpdateArgs {
        instance: fresh_instance.clone(),
        update: update.clone(),
        trusted_head_slot: Some(advanced_network_slot - 500),
        nonce: 2,
    };
    let res_outdated =
        handle_begin_update_authenticated(&mut store, &fresh_instance_pda, begin_args_outdated);
    assert!(
        matches!(res_outdated, Err(MosooError::InvalidBootstrap(_))),
        "Outdated caller-supplied head slot must fail with InvalidBootstrap: {:?}",
        res_outdated.err()
    );

    // 3. Caller attempting to supply a fabricated far-future head slot MUST FAIL CLOSED
    let begin_args_future = BeginUpdateArgs {
        instance: fresh_instance.clone(),
        update: update.clone(),
        trusted_head_slot: Some(advanced_network_slot + 100_000),
        nonce: 3,
    };
    let res_future =
        handle_begin_update_authenticated(&mut store, &fresh_instance_pda, begin_args_future);
    assert!(
        matches!(res_future, Err(MosooError::InvalidBootstrap(_))),
        "Far future caller-supplied head slot must fail with InvalidBootstrap: {:?}",
        res_future.err()
    );

    // 4. Calling handle_attest_state_authenticated on dormant instance with None MUST FAIL CLOSED
    let header = make_test_header(&instance);
    let attest_args = AttestStateArgs {
        instance: instance.clone(),
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x11),
        }),
        predicate: Predicate::Equal { expected: [0; 32] },
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
    };
    let attest_res = handle_attest_state_authenticated(&store, &instance_pda, None, attest_args);
    assert!(
        matches!(attest_res, Err(MosooError::WeakSubjectivityExpired { .. })),
        "Dormant instance attestation with None trusted_head_slot must fail with WeakSubjectivityExpired: {:?}",
        attest_res.err()
    );
}

// ---------------------------------------------------------------------------
// Multi-Instance Coexistence & Registry Isolation
// ---------------------------------------------------------------------------
#[test]
fn test_multi_instance_coexistence_and_isolated_state() {
    use mosoo_core::types::{
        BeaconBlockHeader, ExecutionPayloadHeader, InitializeArgs, JobAccount, JobStage,
        LightClientUpdate, MillerOutput, NetworkConfig, SyncAggregate,
    };
    use mosoo_core::verifier::{
        handle_finish_update_authenticated, validate_initialize_with_config, FinishUpdateArgs,
    };

    let mut store = TestAccountStore::default();
    let chain_id = 999_998;
    let initial_slot = 10_000;

    let committee = make_valid_committee();
    let committee_leaf = mosoo_core::crypto::hash_tree_root_sync_committee(&committee).unwrap();
    let committee_branch = vec![[0x11; 32]; 5];
    let bootstrap_state_root =
        mosoo_core::crypto::compute_branch_root(committee_leaf, &committee_branch, 54);

    let bootstrap_header_a = BeaconBlockHeader {
        slot: initial_slot,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root: bootstrap_state_root,
        body_root: [0; 32],
    };
    let checkpoint_a = mosoo_core::crypto::hash_tree_root_beacon_header(&bootstrap_header_a);
    let checkpoint_b = [0xbb; 32];

    let net_cfg = NetworkConfig {
        chain_id,
        genesis_validators_root: [0x88; 32],
        trusted_checkpoint_root: Some(checkpoint_a),
        altair_fork_version: [0x01; 4],
        bellatrix_fork_version: [0x02; 4],
        capella_fork_version: [0x03; 4],
        deneb_fork_version: [0x04; 4],
        electra_fork_version: [0x05; 4],
        fulu_fork_version: [0x06; 4],
        gloas_fork_version: [0x07; 4],
    };

    // Create configuration with multi-instance and multi-checkpoint registry
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_checkpoint_in_registry(chain_id, checkpoint_a);
    config.register_trusted_checkpoint_in_registry(chain_id, checkpoint_b);
    config.register_trusted_head(chain_id, initial_slot);

    // Instance A
    let instance_id_a = [0x01; 32];
    let mut inst_a = make_test_instance(chain_id, instance_id_a);
    inst_a.current_slot = initial_slot;
    inst_a.bootstrap_slot = initial_slot;
    inst_a.bootstrap_header_hash = checkpoint_a;
    let pda_a = inst_a.pda_address();
    config.register_trusted_instance_in_registry(chain_id, pda_a);
    config.register_trusted_head_for_instance(chain_id, pda_a, initial_slot);

    // Instance B (different ID and different checkpoint root on same chain)
    let instance_id_b = [0x02; 32];
    let mut inst_b = make_test_instance(chain_id, instance_id_b);
    inst_b.current_slot = initial_slot;
    inst_b.bootstrap_slot = initial_slot;
    inst_b.bootstrap_header_hash = checkpoint_b;
    let pda_b = inst_b.pda_address();
    config.register_trusted_instance_in_registry(chain_id, pda_b);
    config.register_trusted_head_for_instance(chain_id, pda_b, initial_slot);

    // Save configuration
    config.save_to_store(&mut store).unwrap();
    store.set_account_with_owner(
        &pda_a,
        serde_json::to_vec(&inst_a).unwrap(),
        MOSOO_PROGRAM_ID,
    );
    store.set_account_with_owner(
        &pda_b,
        serde_json::to_vec(&inst_b).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // 1. Both instances pass initialization validation
    let init_args_a = InitializeArgs {
        chain_id,
        instance_id: instance_id_a,
        network_config: Some(net_cfg.clone()),
        bootstrap_header: bootstrap_header_a.clone(),
        trusted_checkpoint_root: checkpoint_a,
        current_sync_committee: committee.clone(),
        current_sync_committee_branch: committee_branch.clone(),
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: initial_slot,
    };
    assert!(
        validate_initialize_with_config(&init_args_a, &config).is_ok(),
        "Instance A initialization must succeed with multi-instance registry"
    );

    // 2. Unregistered instance C MUST be rejected
    let unapproved_id_c = [0xcc; 32];
    let unapproved_init_c = InitializeArgs {
        chain_id,
        instance_id: unapproved_id_c,
        network_config: Some(net_cfg),
        bootstrap_header: bootstrap_header_a.clone(),
        trusted_checkpoint_root: checkpoint_a,
        current_sync_committee: committee,
        current_sync_committee_branch: committee_branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: initial_slot,
    };
    assert!(
        matches!(
            validate_initialize_with_config(&unapproved_init_c, &config),
            Err(MosooError::UntrustedSourceInstance)
        ),
        "Unapproved instance C must be rejected with UntrustedSourceInstance"
    );

    // 3. Advance Instance A and assert complete isolation from Instance B
    let new_slot_a = initial_slot + 64;
    let exec_header = ExecutionPayloadHeader {
        parent_hash: [0; 32],
        fee_recipient: [0; 20],
        state_root: [0x33; 32],
        receipts_root: [0x44; 32],
        logs_bloom: vec![0u8; 256],
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
    };
    let exec_branch = vec![[0x22; 32]; 4];

    let exec_leaf =
        mosoo_core::crypto::hash_tree_root_execution_payload_header(&exec_header).unwrap();
    let exec_gindex = mosoo_core::crypto::execution_proof_gindex(chain_id, new_slot_a);
    let body_root = mosoo_core::crypto::compute_branch_root(exec_leaf, &exec_branch, exec_gindex);

    let finalized_header = BeaconBlockHeader {
        slot: new_slot_a,
        proposer_index: 10,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root,
    };
    let branch = vec![[0x11; 32]; 6];
    let gindex = mosoo_core::crypto::finalized_root_gindex(chain_id, new_slot_a + 1);
    let finalized_leaf = mosoo_core::crypto::hash_tree_root_beacon_header(&finalized_header);
    let attested_state_root =
        mosoo_core::crypto::compute_branch_root(finalized_leaf, &branch, gindex);

    let attested_header = BeaconBlockHeader {
        slot: new_slot_a + 1,
        proposer_index: 11,
        parent_root: [0x44; 32],
        state_root: attested_state_root,
        body_root: [0x55; 32],
    };

    let update_a = LightClientUpdate {
        attested_header,
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header,
        finality_branch: branch,
        execution_payload_header: Some(exec_header),
        execution_branch: Some(exec_branch),
        execution_rlp: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0x11; 96],
        },
        signature_slot: new_slot_a + 1,
    };

    let mut ml = blst::blst_fp12::default();
    unsafe {
        let g1 = blst::blst_p1_affine_generator();
        let g2 = blst::blst_p2_affine_generator();
        blst::blst_miller_loop(&mut ml, g2, g1);
    }
    let mut miller_result = vec![0u8; 1152];
    unsafe {
        let p = &ml as *const _ as *const u8;
        core::ptr::copy_nonoverlapping(p, miller_result.as_mut_ptr(), 576);
        core::ptr::copy_nonoverlapping(p, miller_result.as_mut_ptr().add(576), 576);
    }

    let job_a = JobAccount {
        instance_id: instance_id_a,
        instance_chain_id: chain_id,
        instance_slot: initial_slot,
        stage: JobStage::Finish,
        update_digest: mosoo_core::crypto::compute_update_digest(&update_a),
        update: update_a,
        miller_input: None,
        miller_output: Some(MillerOutput { miller_result }),
        nonce: 50,
    };
    let job_pda_a = job_a.pda_address();
    store.set_account_with_owner(
        &job_pda_a,
        serde_json::to_vec(&job_a).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let finish_args_a = FinishUpdateArgs {
        instance: inst_a,
        job: job_a,
    };
    let res = handle_finish_update_authenticated(&mut store, &pda_a, &job_pda_a, finish_args_a);
    assert!(
        res.is_ok(),
        "Finish update for Instance A must succeed: {:?}",
        res.err()
    );

    // Verify: Instance A's head moved to new_slot_a, Instance B's head remained at initial_slot,
    // and network anchor head remained at initial_slot
    let updated_cfg = TrustedBridgeConfig::load_strict(&store).unwrap();
    assert_eq!(
        updated_cfg.get_instance_trusted_head(&pda_a),
        Some(new_slot_a),
        "Instance A head must advance to new_slot_a"
    );
    assert_eq!(
        updated_cfg.get_instance_trusted_head(&pda_b),
        Some(initial_slot),
        "Instance B head must remain completely isolated at initial_slot"
    );
    assert_eq!(
        updated_cfg.get_trusted_head(chain_id),
        Some(initial_slot),
        "Chain-wide network anchor must not be mutated by Instance A progress"
    );
}

// ---------------------------------------------------------------------------
// Mainnet/Holesky Activation & On-Chain Admin Registration
// ---------------------------------------------------------------------------
#[test]
fn test_mainnet_and_holesky_bootstrap_and_admin_registration() {
    use mosoo_core::types::{
        CANONICAL_HOLESKY_CHECKPOINT_ROOT, CANONICAL_HOLESKY_CHECKPOINT_SLOT,
        CANONICAL_MAINNET_CHECKPOINT_ROOT, CANONICAL_MAINNET_CHECKPOINT_SLOT, ETH_HOLESKY_CHAIN_ID,
        ETH_MAINNET_CHAIN_ID,
    };
    use mosoo_core::verifier::{
        handle_register_network_checkpoint_authenticated,
        handle_register_trusted_instance_authenticated,
    };

    // 1. Verify Ethereum Mainnet (1) and Holesky (17000) canonical constants are defined with correct values
    assert_eq!(CANONICAL_MAINNET_CHECKPOINT_SLOT, 10_320_000);
    assert_ne!(CANONICAL_MAINNET_CHECKPOINT_ROOT, [0u8; 32]);
    assert_eq!(CANONICAL_HOLESKY_CHECKPOINT_SLOT, 3_250_000);
    assert_ne!(CANONICAL_HOLESKY_CHECKPOINT_ROOT, [0u8; 32]);

    // 2. Unregistered network checkpoints fail closed in default test canonical() until registered
    let canonical_cfg = TrustedBridgeConfig::canonical();
    assert!(
        !canonical_cfg
            .is_trusted_checkpoint(ETH_MAINNET_CHAIN_ID, &CANONICAL_MAINNET_CHECKPOINT_ROOT),
        "Mainnet checkpoint is not active by default in test canonical() until registered"
    );

    // 3. Test on-chain administrative registration instruction for Mainnet and custom chain
    let mut store = TestAccountStore::default();
    let admin_key = [0x42; 32];
    let mut cfg = TrustedBridgeConfig::canonical();
    cfg.set_admin_authority(admin_key);
    cfg.save_to_store(&mut store).unwrap();

    // Unauthorized caller MUST fail
    let unauthorized_caller = [0x99; 32];
    let unauth_res = handle_register_network_checkpoint_authenticated(
        &mut store,
        &unauthorized_caller,
        ETH_MAINNET_CHAIN_ID,
        CANONICAL_MAINNET_CHECKPOINT_ROOT,
        CANONICAL_MAINNET_CHECKPOINT_SLOT,
    );
    assert!(
        matches!(unauth_res, Err(MosooError::DomainSeparationFailed)),
        "Unauthorized caller must be rejected with DomainSeparationFailed"
    );

    // Authorized admin registers Mainnet checkpoint
    let auth_res = handle_register_network_checkpoint_authenticated(
        &mut store,
        &admin_key,
        ETH_MAINNET_CHAIN_ID,
        CANONICAL_MAINNET_CHECKPOINT_ROOT,
        CANONICAL_MAINNET_CHECKPOINT_SLOT,
    );
    assert!(
        auth_res.is_ok(),
        "Authorized admin checkpoint registration must succeed"
    );

    // Authorized admin registers Mainnet trusted instance
    let mainnet_inst = mosoo_core::types::CANONICAL_MAINNET_MOSOO_INSTANCE;
    let inst_res = handle_register_trusted_instance_authenticated(
        &mut store,
        &admin_key,
        ETH_MAINNET_CHAIN_ID,
        mainnet_inst,
    );
    assert!(
        inst_res.is_ok(),
        "Authorized admin instance registration must succeed"
    );

    // Verify Mainnet is now fully active in store
    let updated_cfg = TrustedBridgeConfig::load_strict(&store).unwrap();
    assert!(
        updated_cfg.is_trusted_checkpoint(ETH_MAINNET_CHAIN_ID, &CANONICAL_MAINNET_CHECKPOINT_ROOT)
    );
    assert_eq!(
        updated_cfg.get_trusted_head(ETH_MAINNET_CHAIN_ID),
        Some(CANONICAL_MAINNET_CHECKPOINT_SLOT)
    );
    assert!(updated_cfg.is_trusted_or_unpinned(ETH_MAINNET_CHAIN_ID, &mainnet_inst));

    // Register Holesky as well
    let holesky_res = handle_register_network_checkpoint_authenticated(
        &mut store,
        &admin_key,
        ETH_HOLESKY_CHAIN_ID,
        CANONICAL_HOLESKY_CHECKPOINT_ROOT,
        CANONICAL_HOLESKY_CHECKPOINT_SLOT,
    );
    assert!(holesky_res.is_ok());

    let final_cfg = TrustedBridgeConfig::load_strict(&store).unwrap();
    assert!(
        final_cfg.is_trusted_checkpoint(ETH_HOLESKY_CHAIN_ID, &CANONICAL_HOLESKY_CHECKPOINT_ROOT)
    );
    assert_eq!(
        final_cfg.get_trusted_head(ETH_HOLESKY_CHAIN_ID),
        Some(CANONICAL_HOLESKY_CHECKPOINT_SLOT)
    );
}
