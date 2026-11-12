use super::*;

#[test]
fn test_fabricated_committee_and_execution_roots_under_canonical_pda_fails_closed() {
    use mosoo_core::verifier::{dispatch_store_instruction, AttestStateArgs, GuestInstruction};

    let mut store = TestAccountStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();

    // 1. Genuine canonical Sepolia instance stored in persistent storage
    let mut genuine_instance =
        make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    genuine_instance.current_slot = 11_435_000;
    genuine_instance.bootstrap_slot = 11_434_912;
    genuine_instance.current_header_hash = [0x11; 32];
    genuine_instance.current_execution_block_hash = [0x22; 32];
    genuine_instance.current_execution_state_root = [0x33; 32]; // Authentic state root
    genuine_instance.current_receipts_root = [0x44; 32];

    let canonical_pda = genuine_instance.pda_address();
    assert_eq!(canonical_pda, CANONICAL_SEPOLIA_MOSOO_INSTANCE);

    let inst_bytes = serde_json::to_vec(&genuine_instance).unwrap();
    store
        .try_set_account_with_owner(&canonical_pda, inst_bytes, MOSOO_PROGRAM_ID)
        .unwrap();

    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 11_435_000);
    config.save_to_store(&mut store).unwrap();

    // 2. Adversary fabricates an instance in memory matching the canonical PDA and instance ID,
    // but with completely fabricated sync committee and fabricated execution state roots.
    let mut fake_instance = genuine_instance.clone();
    fake_instance.current_execution_state_root = [0x99; 32]; // Forged root!
    fake_instance.current_sync_committee = SyncCommittee {
        pubkeys: vec![vec![0xfe; 48]; 512],
        aggregate_pubkey: vec![0xfe; 48],
    };

    // Adversary also fabricates a HeaderRecord matching their forged execution state root
    let fake_header = HeaderRecord {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        slot: 11_435_000,
        beacon_block_root: [0x11; 32],
        execution_block_hash: [0x22; 32],
        execution_state_root: [0x99; 32], // Forged root!
        receipts_root: [0x44; 32],
    };

    let args = AttestStateArgs {
        instance: fake_instance,
        header: fake_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x77),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
    };

    let instruction = GuestInstruction::AttestStateAuthenticated {
        expected_instance_pda: canonical_pda,
        expected_header_pda: None,
        args,
    };

    // 3. Dispatch through persistent store dispatcher:
    // dispatch_store_instruction strictly loads the authentic instance from store
    // (which has execution_state_root == [0x33; 32]), overwriting the caller's fake instance.
    // The attestation against fake_header ([0x99; 32]) fails closed!
    let res = dispatch_store_instruction(&mut store, instruction);
    assert!(
        res.is_err(),
        "Attestation with fabricated execution roots under canonical PDA must fail closed"
    );
    assert!(matches!(
        res.unwrap_err(),
        MosooError::UnauthenticatedHeaderRecord
    ));
}

#[test]
fn test_weak_subjectivity_attestation_staleness_direction_and_head_slot() {
    use mosoo_core::verifier::{handle_attest_state, AttestStateArgs};

    let instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    let mut stale_historical_header = make_test_header(&instance);
    // Set historical header older than canonical weak subjectivity window (54,000 slots)
    // instance.current_slot = 10_000, header.slot = 10_000 - 60_000 -> underflow/stale!
    let current_slot = 100_000u64;
    let mut fresh_instance = instance.clone();
    fresh_instance.current_slot = current_slot;
    stale_historical_header.slot = current_slot - 55_000; // 55,000 slots old > 54,000!

    let args_stale_history = AttestStateArgs {
        instance: fresh_instance.clone(),
        header: stale_historical_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x01),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
    };

    let res_stale_hist = handle_attest_state(args_stale_history);
    assert!(
        matches!(
            res_stale_hist.unwrap_err(),
            MosooError::WeakSubjectivityExpired { .. }
        ),
        "Historical header exceeding weak subjectivity window must fail closed"
    );

    // 2. trusted_head_slot preceding instance.current_slot is rejected
    let mut valid_header = make_test_header(&fresh_instance);
    valid_header.slot = current_slot;
    let args_head_preceding = AttestStateArgs {
        instance: fresh_instance.clone(),
        header: valid_header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x01),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: Some(current_slot - 100), // Precedes instance!
        privacy_mode: None,
    };
    let res_preceding = handle_attest_state(args_head_preceding);
    assert!(matches!(
        res_preceding.unwrap_err(),
        MosooError::InvalidBootstrap(_)
    ));

    // 3. trusted_head_slot exceeding weak subjectivity window relative to instance fails closed
    let args_head_stale = AttestStateArgs {
        instance: fresh_instance,
        header: valid_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x01),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: Some(current_slot + 60_000), // 60,000 slots ahead of instance!
        privacy_mode: None,
    };
    let res_head_stale = handle_attest_state(args_head_stale);
    assert!(matches!(
        res_head_stale.unwrap_err(),
        MosooError::WeakSubjectivityExpired { .. }
    ));
}

// ===========================================================================
// Consensus Invariants: Boundary Synchronization & Timelock Governance
// ===========================================================================

// ---------------------------------------------------------------------------
// Job PDA Derivation Inconsistency Unification (Medium #4)
// ---------------------------------------------------------------------------
#[test]
fn test_job_pda_derivation_unification() {
    use mosoo_core::types::{
        derive_instance_pda, JobAccount, JobStage, LightClientUpdate, RuntimeAccount,
        SyncAggregate, CANONICAL_MAINNET_INSTANCE_ID, CANONICAL_SEPOLIA_INSTANCE_ID,
        ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    };

    let test_cases = [
        (ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID, 0u64),
        (ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID, 42u64),
        (ETH_MAINNET_CHAIN_ID, CANONICAL_MAINNET_INSTANCE_ID, 1u64),
        (
            ETH_MAINNET_CHAIN_ID,
            CANONICAL_MAINNET_INSTANCE_ID,
            99999u64,
        ),
        (1337u64, [0x77; 32], 100u64),
    ];

    for (chain_id, inst_id, nonce) in test_cases {
        let dummy_header = mosoo_core::types::BeaconBlockHeader {
            slot: 5000,
            proposer_index: 0,
            parent_root: [0; 32],
            state_root: [0; 32],
            body_root: [0; 32],
        };
        let dummy_update = LightClientUpdate {
            attested_header: dummy_header.clone(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: dummy_header,
            finality_branch: vec![[0u8; 32]; 6],
            execution_payload_header: None,
            execution_branch: None,
            execution_rlp: None,
            sync_aggregate: SyncAggregate {
                sync_committee_bits: vec![0xff; 64],
                sync_committee_signature: vec![0x11; 96],
            },
            signature_slot: 5001,
        };

        let job = JobAccount {
            instance_chain_id: chain_id,
            instance_id: inst_id,
            instance_slot: 5000,
            update_digest: [0xaa; 32],
            stage: JobStage::Begin,
            update: dummy_update,
            miller_input: None,
            miller_output: None,
            nonce,
        };

        // 1. Invariant: job.instance_pda() strictly equals derive_instance_pda(chain_id, &instance_id)
        let expected_inst_pda = derive_instance_pda(chain_id, &inst_id);
        assert_eq!(
            job.instance_pda(),
            expected_inst_pda,
            "job.instance_pda() must match derive_instance_pda with MOSOO_PROGRAM_ID"
        );

        // 2. Invariant: job.pda_address() strictly equals JobAccount::derive_pda(&job.instance_pda(), nonce)
        let expected_job_pda = JobAccount::derive_pda(&expected_inst_pda, nonce);
        assert_eq!(
            job.pda_address(),
            expected_job_pda,
            "job.pda_address() must match JobAccount::derive_pda(&job.instance_pda(), nonce)"
        );

        // 3. RuntimeAccount authenticity parsing succeeds with matching PDA
        let job_bytes = serde_json::to_vec(&job).unwrap();
        let runtime_acc = RuntimeAccount {
            address: expected_job_pda,
            owner: MOSOO_PROGRAM_ID,
            data: job_bytes.clone(),
        };
        let parsed = JobAccount::try_from_runtime_account(&runtime_acc);
        assert!(parsed.is_ok());

        // 4. RuntimeAccount with tampered PDA fails closed with UnauthenticatedJobAccount
        let tampered_acc = RuntimeAccount {
            address: [0xde; 32],
            owner: MOSOO_PROGRAM_ID,
            data: job_bytes,
        };
        let err = JobAccount::try_from_runtime_account(&tampered_acc);
        assert!(matches!(
            err.unwrap_err(),
            mosoo_core::error::MosooError::UnauthenticatedJobAccount
        ));
    }
}

// ---------------------------------------------------------------------------
// Stale Instance Chained Incremental Update Rejection (High #2)
// ---------------------------------------------------------------------------
#[test]
fn test_stale_instance_cannot_advance_via_small_incremental_updates() {
    use mosoo_core::types::{
        LightClientUpdate, SyncAggregate, TrustedBridgeConfig, CANONICAL_SEPOLIA_INSTANCE_ID,
        CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS, ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    };
    use mosoo_core::verifier::{handle_begin_update_authenticated, BeginUpdateArgs};

    let mut store = TestAccountStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();
    let instance_id = CANONICAL_SEPOLIA_INSTANCE_ID;
    let initial_slot = 1_000_000u64;

    // Instance was stalled at slot 1,000,000
    let mut inst = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    inst.current_slot = initial_slot;
    let inst_pda = inst.pda_address();
    store.set_account_with_owner(
        &inst_pda,
        serde_json::to_vec(&inst).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // Network has advanced to slot 2,000,000 (well past weak-subjectivity window: 1,000,000 slots delta >> 54,000)
    let authenticated_head = initial_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 50_000;
    let mut bridge_cfg = TrustedBridgeConfig::canonical();
    bridge_cfg.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, authenticated_head);
    bridge_cfg.save_to_store(&mut store).unwrap();

    // Adversary attempts to revive the stale instance via small chained incremental updates:
    // Update 1: slot 1,000,100 (delta = 100)
    // Update 2: slot 1,000,200 (delta = 100)
    // Update 3: slot 1,000,300 (delta = 100)
    for jump in [100u64, 200, 300, 400] {
        let dummy_header = mosoo_core::types::BeaconBlockHeader {
            slot: initial_slot + jump,
            proposer_index: 1,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        };
        let update = LightClientUpdate {
            attested_header: dummy_header.clone(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: dummy_header,
            finality_branch: vec![[0u8; 32]; 6],
            execution_payload_header: None,
            execution_branch: None,
            execution_rlp: None,
            sync_aggregate: SyncAggregate {
                sync_committee_bits: vec![0xff; 64],
                sync_committee_signature: vec![0x11; 96],
            },
            signature_slot: initial_slot + jump + 1,
        };

        // 1. Adversary omits trusted_head_slot (trusted_head_slot: None) to hide staleness
        let args_omitted = BeginUpdateArgs {
            instance: inst.clone(),
            update: update.clone(),
            nonce: jump,
            trusted_head_slot: None,
        };
        let res_omitted = handle_begin_update_authenticated(&mut store, &inst_pda, args_omitted);
        assert!(
            matches!(
                res_omitted.unwrap_err(),
                MosooError::WeakSubjectivityExpired { .. }
            ),
            "Chained small update (jump {}) with None head must fail closed against authenticated head",
            jump
        );

        // 2. Adversary supplies a fake low trusted_head_slot to attempt clock rollback
        let args_faked = BeginUpdateArgs {
            instance: inst.clone(),
            update,
            nonce: jump + 10_000,
            trusted_head_slot: Some(initial_slot + jump + 5), // Fake head!
        };
        let res_faked = handle_begin_update_authenticated(&mut store, &inst_pda, args_faked);
        assert!(
            matches!(
                res_faked.unwrap_err(),
                MosooError::InvalidBootstrap(..) | MosooError::WeakSubjectivityExpired { .. }
            ),
            "Chained small update (jump {}) with faked low head must fail closed against authenticated anchor",
            jump
        );
    }
}

// ---------------------------------------------------------------------------
// Unregistered Networks & Placeholder Trust Anchor Elimination
// ---------------------------------------------------------------------------
#[test]
fn test_unregistered_networks_fail_closed_without_config_registration() {
    use mosoo_core::types::{
        BeaconBlockHeader, InitializeArgs, NetworkConfig, TrustedBridgeConfig,
        ETH_HOLESKY_CHAIN_ID, ETH_MAINNET_CHAIN_ID,
    };
    use mosoo_core::verifier::{validate_initialize, validate_initialize_with_config};

    let dummy_header = BeaconBlockHeader {
        slot: 10_000,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root: [0x11; 32],
        body_root: [0; 32],
    };
    let dummy_root = mosoo_core::crypto::hash_tree_root_beacon_header(&dummy_header);

    // 1. Mainnet (chain 1) has no active trusted checkpoint in canonical TrustedBridgeConfig
    let init_mainnet = InitializeArgs {
        instance_id: [1; 32],
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: dummy_header.clone(),
        trusted_checkpoint_root: dummy_root,
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_050,
        network_config: None,
    };
    let res_mainnet = validate_initialize(&init_mainnet);
    assert!(
        matches!(
            res_mainnet,
            Err(mosoo_core::error::MosooError::UnconfiguredTrustedCheckpoint { chain_id: 1 })
        ),
        "Mainnet without authorized TrustedBridgeConfig checkpoint must fail closed"
    );

    // 2. Holesky (chain 17000) has no active trusted checkpoint in canonical TrustedBridgeConfig
    let init_holesky = InitializeArgs {
        instance_id: [2; 32],
        chain_id: ETH_HOLESKY_CHAIN_ID,
        bootstrap_header: dummy_header.clone(),
        trusted_checkpoint_root: dummy_root,
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_050,
        network_config: None,
    };
    let res_holesky = validate_initialize(&init_holesky);
    assert!(
        matches!(
            res_holesky,
            Err(mosoo_core::error::MosooError::UnconfiguredTrustedCheckpoint { chain_id: 17000 })
        ),
        "Holesky without authorized TrustedBridgeConfig checkpoint must fail closed"
    );

    // 3. Custom network (chain 777777) with caller-supplied NetworkConfig is NEVER self-certifying
    let net_cfg_custom = NetworkConfig {
        chain_id: 777777,
        genesis_validators_root: [0x55; 32],
        trusted_checkpoint_root: Some(dummy_root), // Caller supplied!
        altair_fork_version: [1; 4],
        bellatrix_fork_version: [2; 4],
        capella_fork_version: [3; 4],
        deneb_fork_version: [4; 4],
        electra_fork_version: [5; 4],
        fulu_fork_version: [6; 4],
        gloas_fork_version: [7; 4],
    };
    let init_custom = InitializeArgs {
        instance_id: [3; 32],
        chain_id: 777777,
        bootstrap_header: dummy_header,
        trusted_checkpoint_root: dummy_root,
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_050,
        network_config: Some(net_cfg_custom),
    };
    let res_custom = validate_initialize(&init_custom);
    assert!(
        matches!(
            res_custom,
            Err(mosoo_core::error::MosooError::UnconfiguredTrustedCheckpoint { chain_id: 777777 })
        ),
        "Self-certifying custom network must fail closed without prior TrustedBridgeConfig registration"
    );

    // 4. Once explicitly registered in TrustedBridgeConfig by authorized admin, initialization succeeds
    let mut bridge_cfg = TrustedBridgeConfig::canonical();
    let admin = [0x99; 32];
    bridge_cfg.set_admin_authority(admin);
    assert!(bridge_cfg.register_trusted_checkpoint_authorized(&admin, 777777, dummy_root));
    assert!(validate_initialize_with_config(&init_custom, &bridge_cfg).is_ok());

    // 5. Canonical config has zero placeholder checkpoints for Mainnet and Holesky
    let canonical = TrustedBridgeConfig::canonical();
    assert!(canonical
        .get_trusted_checkpoint(ETH_MAINNET_CHAIN_ID)
        .is_none());
    assert!(canonical
        .get_trusted_checkpoint(ETH_HOLESKY_CHAIN_ID)
        .is_none());
}

// ---------------------------------------------------------------------------
// Untrusted Serialized Store Rejection in zkVM Guest Path
// ---------------------------------------------------------------------------
#[test]
fn test_adversarial_forged_store_fails_closed() {
    use mosoo_core::types::{AccountStore, HeaderRecord, MOSOO_PROGRAM_ID};
    use mosoo_core::verifier::{handle_attest_state_authenticated, AttestStateArgs};

    let mut fake_store = TestAccountStore::default();
    let chain_id = 11155111u64;
    let fake_instance_id = [0xee; 32];
    let fake_instance = make_test_instance(chain_id, fake_instance_id);
    let fake_pda = fake_instance.pda_address();

    // Adversary fabricates an in-memory store with MOSOO_PROGRAM_ID ownership and forged execution root
    fake_store.set_account_with_owner(
        &fake_pda,
        serde_json::to_vec(&fake_instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let forged_header = HeaderRecord {
        chain_id,
        slot: 1000,
        beacon_block_root: [0xaa; 32],
        execution_block_hash: [0xbb; 32],
        execution_state_root: [0xcc; 32], // Fabricated!
        receipts_root: [0xdd; 32],
    };
    let forged_header_pda = forged_header.pda_address();
    fake_store.set_account_with_owner(
        &forged_header_pda,
        serde_json::to_vec(&forged_header).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // Attestation against unpinned instance PDA must fail closed
    let args = AttestStateArgs {
        instance: fake_instance,
        header: forged_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x01),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
    };

    // Authenticated attestation verifies instance against canonical pinned instance:
    // Sepolia is pinned to CANONICAL_SEPOLIA_MOSOO_INSTANCE.
    // The adversary's fabricated fake_pda is rejected!
    let res =
        handle_attest_state_authenticated(&fake_store, &fake_pda, Some(&forged_header_pda), args);
    // When fake_instance is validated for authenticity, its instance_id is [0xee; 32]
    // which does not match CANONICAL_SEPOLIA_INSTANCE_ID -> validation fails closed!
    assert!(
        res.is_err(),
        "Attestation with fabricated instance in untrusted store must fail closed"
    );
}

#[test]
fn test_initialization_rejects_bootstrap_exceeding_canonical_weak_subjectivity() {
    use mosoo_core::types::{
        BeaconBlockHeader, InitializeArgs, CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS,
        ETH_MAINNET_CHAIN_ID,
    };
    use mosoo_core::verifier::handle_initialize;

    let committee = make_valid_committee();
    let leaf = mosoo_core::crypto::hash_tree_root_sync_committee(&committee).unwrap();
    let branch = vec![[0x11; 32]; 5];
    let state_root = mosoo_core::crypto::compute_branch_root(leaf, &branch, 54);

    let bootstrap_slot = 10_000_000;
    let bootstrap_header = BeaconBlockHeader {
        slot: bootstrap_slot,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root,
        body_root: [0; 32],
    };
    let checkpoint_root = mosoo_core::crypto::hash_tree_root_beacon_header(&bootstrap_header);

    // Case 1: Within canonical weak subjectivity window (54,000 slots) -> Succeeds
    let valid_args = InitializeArgs {
        instance_id: [0x11; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header: bootstrap_header.clone(),
        trusted_checkpoint_root: checkpoint_root,
        current_sync_committee: committee.clone(),
        current_sync_committee_branch: branch.clone(),
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: bootstrap_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS,
    };
    let init_res = handle_initialize(valid_args);
    assert!(
        init_res.is_ok(),
        "Initialization within 54,000 slots must succeed"
    );

    // Case 2: Exceeding canonical weak subjectivity window (54,001 slots / > 7.5 days) -> Fails closed
    let stale_args = InitializeArgs {
        instance_id: [0x22; 32],
        network_config: None,
        chain_id: ETH_MAINNET_CHAIN_ID,
        bootstrap_header,
        trusted_checkpoint_root: checkpoint_root,
        current_sync_committee: committee,
        current_sync_committee_branch: branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: bootstrap_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 1,
    };
    let stale_res = handle_initialize(stale_args);
    assert!(
        matches!(
            stale_res.unwrap_err(),
            MosooError::WeakSubjectivityExpired {
                update_slot,
                current_slot
            } if update_slot == bootstrap_slot && current_slot == bootstrap_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 1
        ),
        "Bootstrap checkpoint exceeding 54,000 slots must fail closed with WeakSubjectivityExpired"
    );
}

#[test]
fn test_finish_update_advances_authenticated_head_slot() {
    use mosoo_core::types::{
        BeaconBlockHeader, ExecutionPayloadHeader, JobAccount, JobStage, LightClientUpdate,
        MillerOutput, SyncAggregate,
    };
    use mosoo_core::verifier::{handle_finish_update_authenticated, FinishUpdateArgs};

    let mut store = TestAccountStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();
    let instance_id = [0x55; 32];
    let chain_id = 888888;
    let initial_slot = 5000;

    let mut instance = make_test_instance(chain_id, instance_id);
    instance.current_slot = initial_slot;
    instance.bootstrap_slot = initial_slot;
    let instance_pda = instance.pda_address();

    store.set_account_with_owner(
        &instance_pda,
        serde_json::to_vec(&instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // Initial bridge config with head registered at 5000
    let mut bridge_cfg = TrustedBridgeConfig::canonical();
    bridge_cfg.register_trusted_head(chain_id, initial_slot);
    bridge_cfg.save_to_store(&mut store).unwrap();

    let new_slot = 5064;

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

    // Construct valid Fp12 miller results such that blst_fp12_finalverify returns true
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

    let job = JobAccount {
        instance_id,
        instance_chain_id: chain_id,
        instance_slot: initial_slot,
        stage: JobStage::Finish,
        update_digest: mosoo_core::crypto::compute_update_digest(&update),
        update,
        miller_input: None,
        miller_output: Some(MillerOutput { miller_result }),
        nonce: 101,
    };
    let job_pda = job.pda_address();

    store.set_account_with_owner(
        &job_pda,
        serde_json::to_vec(&job).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let finish_args = FinishUpdateArgs {
        instance: instance.clone(),
        job,
    };

    let res = handle_finish_update_authenticated(&mut store, &instance_pda, &job_pda, finish_args);
    assert!(res.is_ok(), "Finish update must succeed: {:?}", res.err());

    // Verify that TrustedBridgeConfig in store was automatically updated for this instance
    let updated_config = TrustedBridgeConfig::load_strict(&store).unwrap();
    assert_eq!(
        updated_config.get_instance_trusted_head(&instance_pda),
        Some(new_slot),
        "Authenticated instance head must automatically advance to finalized update slot"
    );
    // Confirm chain-wide anchor head was NOT altered by this single instance update
    assert_eq!(
        updated_config.get_trusted_head(chain_id),
        Some(5000),
        "Chain-wide anchor head must remain isolated and unaltered by single instance update"
    );
}

#[test]
fn test_core_loader_enforces_instance_pinning() {
    use mosoo_core::types::Predicate;
    use mosoo_core::verifier::{handle_attest_state_authenticated, AttestStateArgs};

    let mut store = TestAccountStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();

    // Canonical Sepolia instance is pinned to CANONICAL_SEPOLIA_MOSOO_INSTANCE.
    // Create an unpinned instance under Sepolia chain_id (11155111) with a different instance_id.
    let unpinned_instance_id = [0x99; 32];
    let unpinned_instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, unpinned_instance_id);
    let unpinned_pda = unpinned_instance.pda_address();

    assert_ne!(unpinned_pda, CANONICAL_SEPOLIA_MOSOO_INSTANCE);

    store.set_account_with_owner(
        &unpinned_pda,
        serde_json::to_vec(&unpinned_instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let header = make_test_header(&unpinned_instance);
    let header_pda = header.pda_address();
    store.set_account_with_owner(
        &header_pda,
        serde_json::to_vec(&header).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let args = AttestStateArgs {
        instance: unpinned_instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x55),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: Some(1000),
        privacy_mode: None,
    };

    // Attestation against unpinned instance PDA on pinned chain MUST fail with UntrustedSourceInstance
    let res = handle_attest_state_authenticated(&store, &unpinned_pda, Some(&header_pda), args);
    assert!(
        matches!(res.unwrap_err(), MosooError::UntrustedSourceInstance),
        "Attestation against unpinned instance on Sepolia must be rejected with UntrustedSourceInstance"
    );
}

#[test]
fn test_salted_privacy_shielding_prevents_dictionary_matching() {
    use mosoo_core::types::{StatementBinding, VerifiedStatement};

    let depositor_address = [0x42u8; 20];
    let mut subject_key = [0u8; 32];
    subject_key[12..32].copy_from_slice(&depositor_address);

    let statement = VerifiedStatement {
        chain_id: 11155111,
        genesis_validators_root: [0x11; 32],
        source_instance_id: [0x22; 32],
        source_instance_pda: [0x33; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0x44; 32],
        predicate_holds: true,
        verified_value: [0x55; 32],
        subject_key,
        proof_type_tag: 1,
        binding: StatementBinding::Storage {
            contract: [0x66; 20],
            slot: [0x77; 32],
        },
    };

    let salt_a = [0x11u8; 32];
    let salt_b = [0x22u8; 32];

    let shielded_a = statement.shield_with_salt(&salt_a);
    let shielded_b = statement.shield_with_salt(&salt_b);

    // 1. Outputs for same depositor under different salts are completely unlinkable
    assert_ne!(
        shielded_a.subject_key, shielded_b.subject_key,
        "Blinded subject keys under distinct salts must be distinct"
    );
    assert_ne!(
        shielded_a.statement_id, shielded_b.statement_id,
        "Blinded statement IDs under distinct salts must be distinct"
    );

    // 2. An adversary attempting deterministic dictionary attack (without salt) cannot match
    let deterministic_shielded = statement.shield();
    assert_ne!(
        shielded_a.subject_key, deterministic_shielded.subject_key,
        "Salted subject key must differ from deterministic unsalted shield"
    );
    assert_ne!(
        shielded_b.subject_key, deterministic_shielded.subject_key,
        "Salted subject key must differ from deterministic unsalted shield"
    );

    // 3. Legitimate recipient holding secret salt can verify the binding
    assert!(
        shielded_a.verify_salted_blinding(&salt_a, &subject_key, &statement.statement_id),
        "Salt A must successfully verify shielded_a"
    );
    assert!(
        !shielded_a.verify_salted_blinding(&salt_b, &subject_key, &statement.statement_id),
        "Salt B must fail verification of shielded_a"
    );
}

#[test]
fn test_lez_runtime_adapter_dispatch_flow() {
    use mosoo_core::types::Predicate;
    use mosoo_core::verifier::{AttestStateArgs, LezRuntimeAdapter};

    let mut store = TestAccountStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let mut instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    instance.current_slot = 11_435_000;
    instance.bootstrap_slot = 11_434_912;
    let instance_pda = instance.pda_address();

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

    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 11_435_000);
    config.save_to_store(&mut store).unwrap();

    let adapter = LezRuntimeAdapter::new(store);

    let attest_args = AttestStateArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x99),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: Some([0x77; 32]),
        trusted_head_slot: Some(11_435_000),
        privacy_mode: None,
    };

    let res = adapter.dispatch_attest_state(&instance_pda, Some(&header_pda), attest_args);
    // Attestation loaded genuine instance and header from adapter store and proceeded to state inclusion proof
    assert!(res.is_err());
    assert!(!matches!(
        res.unwrap_err(),
        MosooError::UnauthenticatedInstance | MosooError::UntrustedSourceInstance
    ));
}

#[test]
fn test_production_guest_dispatcher_rejects_unauthenticated_state_and_forged_pda() {
    use mosoo_core::types::Predicate;
    use mosoo_core::verifier::{dispatch_guest_instruction, AttestStateArgs, GuestInstruction};

    // 1. Zero instance PDA rejected
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    let header = make_test_header(&instance);
    let args = AttestStateArgs {
        instance,
        header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x11),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: None,
        privacy_mode: None,
    };

    let zero_pda_instruction = GuestInstruction::AttestStateAuthenticated {
        expected_instance_pda: [0u8; 32],
        expected_header_pda: None,
        args: args.clone(),
    };
    let res = dispatch_guest_instruction(zero_pda_instruction);
    assert!(matches!(
        res.unwrap_err(),
        MosooError::UnauthenticatedInstance
    ));

    // 2. Unpinned instance rejected
    let unpinned_id = [0xbb; 32];
    let unpinned_instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, unpinned_id);
    let unpinned_pda = unpinned_instance.pda_address();
    let unpinned_instruction = GuestInstruction::AttestStateAuthenticated {
        expected_instance_pda: unpinned_pda,
        expected_header_pda: None,
        args: AttestStateArgs {
            instance: unpinned_instance,
            privacy_mode: None,
            ..args
        },
    };
    let res2 = dispatch_guest_instruction(unpinned_instruction);
    assert!(matches!(
        res2.unwrap_err(),
        MosooError::UntrustedSourceInstance
    ));
}

#[test]
fn test_strict_config_loading_fails_closed_when_missing_or_untrusted_owner() {
    use mosoo_core::types::{derive_bridge_config_pda, ConfigError, Predicate};
    use mosoo_core::verifier::{
        handle_attest_state_authenticated, handle_begin_update_authenticated, AttestStateArgs,
        BeginUpdateArgs,
    };

    let mut empty_store = TestAccountStore::default();
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    let instance_pda = instance.pda_address();

    empty_store.set_account_with_owner(
        &instance_pda,
        serde_json::to_vec(&instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let header = make_test_header(&instance);
    let header_pda = header.pda_address();
    empty_store.set_account_with_owner(
        &header_pda,
        serde_json::to_vec(&header).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    // 1. handle_attest_state_authenticated strictly fails closed with ConfigError when config is missing
    let attest_args = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x22),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: Some(11_435_000),
        privacy_mode: None,
    };
    let res_attest = handle_attest_state_authenticated(
        &empty_store,
        &instance_pda,
        Some(&header_pda),
        attest_args,
    );
    assert!(matches!(
        res_attest.unwrap_err(),
        MosooError::ConfigError(ConfigError::ConfigNotFound(_))
    ));

    // 2. handle_begin_update_authenticated strictly fails closed when config is missing
    let update = make_test_update(11_435_001, 11_435_000);
    let begin_args = BeginUpdateArgs {
        instance: instance.clone(),
        update: update.clone(),
        nonce: 1,
        trusted_head_slot: Some(11_435_000),
    };
    let res_begin = handle_begin_update_authenticated(&mut empty_store, &instance_pda, begin_args);
    assert!(matches!(
        res_begin.unwrap_err(),
        MosooError::ConfigError(ConfigError::ConfigNotFound(_))
    ));

    // 3. Foreign owner for config account -> UntrustedOwner
    let foreign_owner = [0x55; 32];
    let config_pda = derive_bridge_config_pda();
    empty_store.set_account_with_owner(&config_pda, vec![1, 2, 3], foreign_owner);

    let res_untrusted_owner = handle_begin_update_authenticated(
        &mut empty_store,
        &instance_pda,
        BeginUpdateArgs {
            instance,
            update,
            nonce: 2,
            trusted_head_slot: Some(11_435_000),
        },
    );
    assert!(matches!(
        res_untrusted_owner.unwrap_err(),
        MosooError::ConfigError(ConfigError::UntrustedOwner { .. })
    ));
}

#[test]
fn test_freshness_enforces_anchor_rejects_fake_head_and_stale_instance() {
    use mosoo_core::verifier::{handle_begin_update_authenticated, BeginUpdateArgs};

    let mut store = TestAccountStore::default();
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let mut instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    instance.current_slot = 11_435_000;
    instance.bootstrap_slot = 11_434_912;
    let instance_pda = instance.pda_address();

    store.set_account_with_owner(
        &instance_pda,
        serde_json::to_vec(&instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 11_435_000);
    config.save_to_store(&mut store).unwrap();

    let update = make_test_update(11_435_001, 11_435_000);

    // 1. Caller supplies older head than authenticated anchor -> rejected with InvalidBootstrap
    let older_args = BeginUpdateArgs {
        instance: instance.clone(),
        update: update.clone(),
        nonce: 10,
        trusted_head_slot: Some(11_434_000), // Precedes anchor head (11_435_000)
    };
    let res_older = handle_begin_update_authenticated(&mut store, &instance_pda, older_args);
    assert!(matches!(
        res_older.unwrap_err(),
        MosooError::InvalidBootstrap(_)
    ));

    // 2. Caller supplies fake larger head exceeding weak-subjectivity window -> rejected with InvalidBootstrap
    let excessive_args = BeginUpdateArgs {
        instance: instance.clone(),
        update: update.clone(),
        nonce: 11,
        trusted_head_slot: Some(11_435_000 + 54_001), // Exceeds 54,000 window
    };
    let res_excessive =
        handle_begin_update_authenticated(&mut store, &instance_pda, excessive_args);
    assert!(matches!(
        res_excessive.unwrap_err(),
        MosooError::InvalidBootstrap(_)
    ));

    // 3. Stale instance exceeding weak-subjectivity window beyond current anchor -> WeakSubjectivityExpired
    let mut stale_instance = instance.clone();
    stale_instance.current_slot = 11_435_000 - 54_001; // Stale by > 54,000 slots
    stale_instance.bootstrap_slot = stale_instance.current_slot - 32;
    let stale_pda = stale_instance.pda_address();
    store.set_account_with_owner(
        &stale_pda,
        serde_json::to_vec(&stale_instance).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let stale_args = BeginUpdateArgs {
        instance: stale_instance,
        update,
        nonce: 12,
        trusted_head_slot: None, // Uses anchor head 11_435_000
    };
    let res_stale = handle_begin_update_authenticated(&mut store, &stale_pda, stale_args);
    assert!(matches!(
        res_stale.unwrap_err(),
        MosooError::WeakSubjectivityExpired { .. }
    ));
}
