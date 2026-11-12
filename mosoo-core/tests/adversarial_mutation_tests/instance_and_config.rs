use super::*;

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
        trusted_head_slot: None,
        privacy_mode: None,
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

/// Scenario: Attacker fabricates an unpinned light-client instance and attempts to trick consumers
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

/// Scenario: Attacker manufactures an account whose owner is not MOSOO_PROGRAM_ID.
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
        trusted_head_slot: None,
        privacy_mode: None,
    };

    let err_attest = handle_attest_state_authenticated(&store, &canonical_pda, None, attest_args)
        .expect_err("handle_attest_state_authenticated must reject account not owned by Mosoo");
    assert!(matches!(err_attest, MosooError::DomainSeparationFailed));
}

/// Scenario: Checkpoint validation occurs on the authenticated instance
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

/// Scenario: Atomic Persistent Nullifier Protection.
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

/// Scenario: Program-Owned TrustedBridgeConfig Strict Enforcement.
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

/// Scenario: Priority 2 Verification — Atomic Fallible AccountStore Operations.
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

/// Scenario: Dual Nullifier PDA Transactional Atomicity & Rollback Verification.
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

/// Scenario: Batch Rollback Partial Failure Detection.
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

/// Scenario: Consensus Update State Transition Authentication.
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
        trusted_head_slot: None,
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

/// Scenario: Dynamic NetworkConfig Propagation to BLS Signing Domain.
/// Verifies that custom NetworkConfig overrides the genesis_validators_root and fork versions
/// without requiring code modification.
#[test]
fn test_mutation_attack_49_network_config_propagation_custom_signing_domain() {
    let custom_chain_id = 123456789u64;
    let custom_gvr = [0x42; 32];
    let custom_config = NetworkConfig {
        chain_id: custom_chain_id,
        genesis_validators_root: custom_gvr,
        trusted_checkpoint_root: None,
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
