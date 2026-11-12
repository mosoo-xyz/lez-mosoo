use super::*;

// ---------------------------------------------------------------------------
// Batch-Write Rollback Restores Original State
// ---------------------------------------------------------------------------

#[test]
fn test_finding17_batch_write_rollback_restores_existing_accounts() {
    use mosoo_core::types::ProgramAccountStore;

    let mut store = ProgramAccountStore::default();
    let addr1 = [0x11; 32];
    let orig_data1 = vec![0xaa; 64];
    let orig_owner1 = [0x55; 32];
    store
        .try_set_account_with_owner(&addr1, orig_data1.clone(), orig_owner1)
        .unwrap();

    let addr2 = [0x22; 32];
    let new_data2 = vec![0xbb; 32];

    let addr3 = [0x33; 32];
    // Configure simulated failure on 3rd write
    store.fail_on_address = Some(addr3);

    let batch = vec![
        (addr1, vec![0xcc; 64], MOSOO_PROGRAM_ID), // Overwrites addr1
        (addr2, new_data2, MOSOO_PROGRAM_ID),      // Creates new addr2
        (addr3, vec![0xdd; 32], MOSOO_PROGRAM_ID), // Fails
    ];

    let res = store.try_set_accounts_batch_with_owner(&batch);
    assert!(res.is_err());

    // CRITICAL: addr1 must be restored to its original pre-batch data and owner, NOT removed!
    assert_eq!(store.get_account(&addr1), Some(orig_data1));
    assert_eq!(store.get_account_owner(&addr1), Some(orig_owner1));

    // addr2 was newly created, so it must be removed on rollback
    assert_eq!(store.get_account(&addr2), None);
    assert_eq!(store.get_account_owner(&addr2), None);

    // addr3 was never written
    assert_eq!(store.get_account(&addr3), None);
}

// ---------------------------------------------------------------------------
// ERC-20 Deposit Exact 32-Byte Recipient Matching
// ---------------------------------------------------------------------------

#[test]
fn test_finding18_erc20_deposit_exact_32byte_recipient_matching_and_rejection() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::{
        test_helpers::build_test_deposit_erc20_proof, verify_state_proof, ProofTarget, StateProof,
    };

    let deposit_contract = Address::repeat_byte(0x42);
    let token = Address::repeat_byte(0xa0);
    let sender = Address::repeat_byte(0x11);
    let recipient_exact = [0x22u8; 32];
    let amount = U256::from(100_000_000u64);
    let nonce = 1u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_erc20_proof(
        deposit_contract,
        token,
        sender,
        recipient_exact,
        amount,
        nonce,
    );

    let header = HeaderRecord {
        chain_id: 1,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x66; 32],
        execution_state_root: [0x77; 32],
        receipts_root: receipts_root.0,
    };

    // 1. Exact 32-byte matching succeeds
    let proof_valid = StateProof {
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract,
            token_contract: token,
            sender,
            recipient: recipient_exact,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes.clone()),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp.clone()),
    };
    assert!(verify_state_proof(&proof_valid, &header).is_ok());

    // 2. Mismatched high 12 bytes strictly fails closed with RecipientMismatch (no ambiguous address fallback)
    let mut mismatched_recipient = recipient_exact;
    mismatched_recipient[0] ^= 0x01; // Tamper with top byte

    let proof_tampered = StateProof {
        target: ProofTarget::Erc20Deposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract,
            token_contract: token,
            sender,
            recipient: mismatched_recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };
    let res = verify_state_proof(&proof_tampered, &header);
    assert!(matches!(res, Err(MosooError::RecipientMismatch)));
}

// ---------------------------------------------------------------------------
// ERC-20 Transfer Strict ABI Shape Enforcement
// ---------------------------------------------------------------------------

#[test]
fn test_finding19_erc20_transfer_strict_abi_shape_enforcement() {
    use alloy_primitives::{Address, B256, U256};
    use mosoo_core::inclusion::{
        test_helpers::{
            build_custom_eip1559_transfer_receipt, build_leaf_mpt_proof,
            build_test_eip1559_transfer_receipt,
        },
        verify_state_proof, ProofTarget, StateProof,
    };

    let tok_addr = Address::repeat_byte(0x55);
    let snd_addr = Address::repeat_byte(0x12);
    let mut recipient = [0u8; 32];
    recipient[12..32].copy_from_slice(Address::repeat_byte(0x34).as_slice());
    let amount = U256::from(500_000u64);

    let rec_addr = Address::from_slice(&recipient[12..32]);

    // 1. Valid Transfer log (exactly 3 topics, exactly 32-byte uint256 data) succeeds
    let valid_receipt = build_test_eip1559_transfer_receipt(tok_addr, snd_addr, rec_addr, amount);
    let key = alloy_rlp::encode(0u64);
    let (root, proof_nodes) = build_leaf_mpt_proof(&key, &valid_receipt);

    let header = HeaderRecord {
        chain_id: 1,
        slot: 10_000_000,
        beacon_block_root: [0xaa; 32],
        execution_block_hash: [0xbb; 32],
        execution_state_root: [0xcc; 32],
        receipts_root: root.0,
    };

    let proof_valid = StateProof {
        target: ProofTarget::Erc20Transfer {
            tx_index: 0,
            log_index: 0,
            token_contract: tok_addr,
            sender: snd_addr,
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(valid_receipt),
    };
    assert!(verify_state_proof(&proof_valid, &header).is_ok());

    // 2. Malformed Transfer log with 4 topics strictly fails closed
    let transfer_sig = B256::from(alloy_primitives::keccak256(
        b"Transfer(address,address,uint256)",
    ));
    let mut from_topic = [0u8; 32];
    from_topic[12..32].copy_from_slice(snd_addr.as_slice());
    let mut to_topic = [0u8; 32];
    to_topic[12..32].copy_from_slice(rec_addr.as_slice());

    let malformed_topics_4 = vec![
        transfer_sig,
        B256::from(from_topic),
        B256::from(to_topic),
        B256::from([0x99; 32]), // Extra 4th topic!
    ];
    let malformed_receipt_bytes = build_custom_eip1559_transfer_receipt(
        tok_addr,
        malformed_topics_4,
        amount.to_be_bytes::<32>().to_vec(),
    );
    let (root4, proof_nodes4) = build_leaf_mpt_proof(&key, &malformed_receipt_bytes);
    let mut header4 = header.clone();
    header4.receipts_root = root4.0;

    let proof_4_topics = StateProof {
        target: ProofTarget::Erc20Transfer {
            tx_index: 0,
            log_index: 0,
            token_contract: tok_addr,
            sender: snd_addr,
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes4),
        account_value: None,
        storage_value: None,
        receipt_value: Some(malformed_receipt_bytes),
    };
    assert!(verify_state_proof(&proof_4_topics, &header4).is_err());

    // 3. Malformed data length (e.g. 64 bytes instead of 32 bytes) strictly fails closed
    let valid_topics_3 = vec![transfer_sig, B256::from(from_topic), B256::from(to_topic)];
    let malformed_receipt_64 = build_custom_eip1559_transfer_receipt(
        tok_addr,
        valid_topics_3,
        vec![0u8; 64], // Invalid length for uint256 Transfer data
    );
    let (root64, proof_nodes64) = build_leaf_mpt_proof(&key, &malformed_receipt_64);
    let mut header64 = header.clone();
    header64.receipts_root = root64.0;

    let proof_64_data = StateProof {
        target: ProofTarget::Erc20Transfer {
            tx_index: 0,
            log_index: 0,
            token_contract: tok_addr,
            sender: snd_addr,
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes64),
        account_value: None,
        storage_value: None,
        receipt_value: Some(malformed_receipt_64),
    };
    assert!(verify_state_proof(&proof_64_data, &header64).is_err());
}

// ---------------------------------------------------------------------------
// Salted Shielding Blinds Subject Keys & Statement IDs
// ---------------------------------------------------------------------------

#[test]
fn test_finding20_salted_shielding_blinds_subject_key_and_statement_id() {
    let binding = StatementBinding::Account {
        address: [0x42; 20],
    };
    let original = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0x01; 32],
        source_instance_id: [0x02; 32],
        source_instance_pda: [0xaa; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0x03; 32],
        predicate_holds: true,
        verified_value: [0x04; 32],
        subject_key: [0x05; 32],
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: binding.clone(),
    };

    let salt1 = [0x11; 32];
    let salt2 = [0x22; 32];

    let shielded1 = original.shield_with_salt(&salt1);
    let shielded2 = original.shield_with_salt(&salt2);

    // 1. Unlinkability across different salts
    assert_ne!(shielded1.binding, shielded2.binding);
    assert_ne!(shielded1.subject_key, shielded2.subject_key);
    assert_ne!(shielded1.statement_id, shielded2.statement_id);

    // 2. Correlation defense: blinded identifiers differ from raw on-chain identifiers
    assert_ne!(shielded1.subject_key, original.subject_key);
    assert_ne!(shielded1.statement_id, original.statement_id);

    // 3. Cryptographic verification of salted blinding with knowledge of salt
    assert!(shielded1.verify_salted_blinding(
        &salt1,
        &original.subject_key,
        &original.statement_id
    ));
    assert!(shielded2.verify_salted_blinding(
        &salt2,
        &original.subject_key,
        &original.statement_id
    ));

    // Wrong salt fails verification
    assert!(!shielded1.verify_salted_blinding(
        &salt2,
        &original.subject_key,
        &original.statement_id
    ));
}

// ---------------------------------------------------------------------------
// Store-Backed Guest Instruction Execution
// ---------------------------------------------------------------------------

#[test]
fn test_finding21_guest_entrypoint_store_backed_dispatches_with_account_store() {
    use mosoo_core::types::{
        AccountStore, Predicate, ProgramAccountStore, CANONICAL_SEPOLIA_INSTANCE_ID,
        ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    };
    use mosoo_core::verifier::{dispatch_guest_instruction, AttestStateArgs, GuestInstruction};

    let mut store = ProgramAccountStore::default();
    let chain_id = ETH_SEPOLIA_CHAIN_ID;
    let instance_id = CANONICAL_SEPOLIA_INSTANCE_ID;

    // Genuine instance in store with authentic committee
    let genuine_instance = make_test_instance(chain_id, instance_id);
    let instance_pda = genuine_instance.pda_address();
    let instance_bytes = serde_json::to_vec(&genuine_instance).unwrap();
    store
        .try_set_account_with_owner(&instance_pda, instance_bytes.clone(), MOSOO_PROGRAM_ID)
        .unwrap();

    let genuine_header = make_test_header(&genuine_instance);
    let header_pda = genuine_header.pda_address();
    let header_bytes = serde_json::to_vec(&genuine_header).unwrap();
    store
        .try_set_account_with_owner(&header_pda, header_bytes, MOSOO_PROGRAM_ID)
        .unwrap();

    // 1. Attacker crafts a fabricated instance under the SAME PDA with altered committee and header
    let mut fabricated_instance = genuine_instance.clone();
    fabricated_instance.current_sync_committee.pubkeys[0] = vec![0xff; 48]; // Altered validator pubkey!
    fabricated_instance.current_header_hash = [0xde; 32]; // Altered header!
    assert_eq!(fabricated_instance.pda_address(), instance_pda);

    let args = AttestStateArgs {
        instance: fabricated_instance, // Attacker provides fabricated instance!
        header: genuine_header.clone(),
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

    // Store-backed dispatch must load and authenticate the genuine instance from store,
    // completely overriding the attacker's fabricated committee and state!
    let guest_instruction = GuestInstruction::StoreBacked {
        store: store.clone(),
        instruction: Box::new(GuestInstruction::AttestStateAuthenticated {
            expected_instance_pda: instance_pda,
            expected_header_pda: Some(header_pda),
            args,
        }),
    };

    // In store-backed dispatch, handle_attest_state_authenticated overwrites args.instance with genuine_instance!
    let out = dispatch_guest_instruction(guest_instruction);
    // State proof verification on empty proof fails with Trie error (not UnauthenticatedInstance),
    // proving the store loaded and authenticated the instance!
    assert!(out.is_err());
    assert!(!matches!(
        out.unwrap_err(),
        MosooError::UnauthenticatedInstance
    ));

    // 2. Adversary supplying an unauthenticated instance PDA not in store is rejected
    let random_pda = [0x99; 32];
    let bad_instruction = GuestInstruction::StoreBacked {
        store: store.clone(),
        instruction: Box::new(GuestInstruction::AttestStateAuthenticated {
            expected_instance_pda: random_pda,
            expected_header_pda: Some(header_pda),
            args: AttestStateArgs {
                instance: genuine_instance.clone(),
                header: genuine_header.clone(),
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
            },
        }),
    };
    let res = dispatch_guest_instruction(bad_instruction);
    assert!(matches!(res.unwrap_err(), MosooError::NotInitialized));

    // 3. Adversary supplying an instance owned by a foreign program is rejected
    let attacker_owned_pda = [0x77; 32];
    store
        .try_set_account_with_owner(
            &attacker_owned_pda,
            instance_bytes.clone(),
            [0xee; 32], // Not MOSOO_PROGRAM_ID!
        )
        .unwrap();
    let foreign_owner_instruction = GuestInstruction::StoreBacked {
        store,
        instruction: Box::new(GuestInstruction::AttestStateAuthenticated {
            expected_instance_pda: attacker_owned_pda,
            expected_header_pda: Some(header_pda),
            args: AttestStateArgs {
                instance: genuine_instance,
                header: genuine_header,
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
            },
        }),
    };
    let res_foreign = dispatch_guest_instruction(foreign_owner_instruction);
    assert!(matches!(
        res_foreign.unwrap_err(),
        MosooError::DomainSeparationFailed
    ));
}

// ---------------------------------------------------------------------------
// Native ETH Deposit Exact 32-Byte Recipient Matching
// ---------------------------------------------------------------------------

#[test]
fn test_finding22_native_eth_deposit_exact_32byte_recipient_matching() {
    use alloy_primitives::{Address, U256};
    use mosoo_core::inclusion::{
        test_helpers::build_test_deposit_eth_canonical_proof, verify_state_proof, ProofTarget,
        StateProof,
    };
    use mosoo_core::types::HeaderRecord;

    let deposit_contract = Address::repeat_byte(0x42);
    let sender = Address::repeat_byte(0x11);
    let recipient_exact = [0x22u8; 32];
    let amount = U256::from(5_000_000_000_000_000_000u128); // 5 ETH
    let nonce = 10u64;

    let (receipts_root, proof_nodes, receipt_rlp) = build_test_deposit_eth_canonical_proof(
        deposit_contract,
        sender,
        recipient_exact,
        amount,
        nonce,
    );

    let header = HeaderRecord {
        chain_id: 1,
        slot: 10_000_000,
        beacon_block_root: [0x55; 32],
        execution_block_hash: [0x66; 32],
        execution_state_root: [0x77; 32],
        receipts_root: receipts_root.0,
    };

    // 1. Exact 32-byte matching succeeds
    let proof_valid = StateProof {
        target: ProofTarget::NativeEthDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract,
            sender,
            recipient: recipient_exact,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes.clone()),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp.clone()),
    };
    assert!(verify_state_proof(&proof_valid, &header).is_ok());

    // 2. Ambiguous partial matching (e.g. matching first 20 bytes but differing trailing bytes) is strictly REJECTED
    let mut recipient_tampered = recipient_exact;
    recipient_tampered[31] ^= 0xff; // Alter last byte
    let proof_tampered = StateProof {
        target: ProofTarget::NativeEthDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract,
            sender,
            recipient: recipient_tampered,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes.clone()),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp.clone()),
    };
    let res = verify_state_proof(&proof_tampered, &header);
    assert!(matches!(
        res,
        Err(mosoo_core::error::MosooError::RecipientMismatch)
    ));

    // 3. Fallback offset match (first 20 bytes matching 20-byte address) is strictly REJECTED
    let mut recipient_offset = [0u8; 32];
    recipient_offset[0..20].copy_from_slice(&recipient_exact[12..32]);
    let proof_offset = StateProof {
        target: ProofTarget::NativeEthDeposit {
            tx_index: 0,
            log_index: 0,
            deposit_contract,
            sender,
            recipient: recipient_offset,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_rlp),
    };
    assert!(matches!(
        verify_state_proof(&proof_offset, &header),
        Err(mosoo_core::error::MosooError::RecipientMismatch)
    ));
}

// ---------------------------------------------------------------------------
// Batch Write Rollback Preserves Unowned Accounts
// ---------------------------------------------------------------------------

#[test]
fn test_finding23_batch_write_rollback_preserves_unowned_account_without_adopting_mosoo_owner() {
    use mosoo_core::types::{AccountStore, ProgramAccountStore, MOSOO_PROGRAM_ID};

    let mut store = ProgramAccountStore::default();
    let addr1 = [0x11; 32];
    let orig_data1 = vec![0xaa; 64];

    // Insert an unowned account (owner is None)
    store.insert_unowned_account(addr1, orig_data1.clone());
    assert_eq!(store.get_account(&addr1), Some(orig_data1.clone()));
    assert_eq!(store.get_account_owner(&addr1), None);

    let addr2 = [0x22; 32];
    let new_data2 = vec![0xbb; 32];

    let addr3 = [0x33; 32];
    // Configure simulated failure on 3rd write
    store.fail_on_address = Some(addr3);

    let batch = vec![
        (addr1, vec![0xcc; 64], MOSOO_PROGRAM_ID), // Overwrites unowned addr1 with program account
        (addr2, new_data2, MOSOO_PROGRAM_ID),      // Creates new addr2
        (addr3, vec![0xdd; 32], MOSOO_PROGRAM_ID), // Fails and triggers rollback
    ];

    let res = store.try_set_accounts_batch_with_owner(&batch);
    assert!(res.is_err());

    // CRITICAL: addr1 must be restored to its pre-batch data AND unowned status (owner == None).
    // It must NEVER be converted into a MOSOO_PROGRAM_ID owned account!
    assert_eq!(store.get_account(&addr1), Some(orig_data1));
    assert_eq!(
        store.get_account_owner(&addr1),
        None,
        "Rollback of unowned account must preserve owner == None without adopting MOSOO_PROGRAM_ID"
    );

    // addr2 was newly created, so it must be removed on rollback
    assert_eq!(store.get_account(&addr2), None);
    assert_eq!(store.get_account_owner(&addr2), None);
}

// ---------------------------------------------------------------------------
// Custom Network Independent Checkpoint Anchor Registration
// ---------------------------------------------------------------------------

#[test]
fn test_finding24_custom_network_independent_checkpoint_anchor_registration() {
    use mosoo_core::types::{
        BeaconBlockHeader, InitializeArgs, NetworkConfig, TrustedBridgeConfig,
    };
    use mosoo_core::verifier::{validate_initialize, validate_initialize_with_config};

    let chain_id = 888888u64;
    let custom_checkpoint = [0x99; 32];

    let header = BeaconBlockHeader {
        slot: 1_000,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root: [0x55; 32],
        body_root: [0; 32],
    };
    let header_hash = mosoo_core::crypto::hash_tree_root_beacon_header(&header);

    // 1. Custom network without trusted_checkpoint_root in NetworkConfig fails closed
    let net_cfg_unanchored = NetworkConfig {
        chain_id,
        genesis_validators_root: [0x42; 32],
        trusted_checkpoint_root: None, // Missing independent trust anchor!
        altair_fork_version: [1; 4],
        bellatrix_fork_version: [2; 4],
        capella_fork_version: [3; 4],
        deneb_fork_version: [4; 4],
        electra_fork_version: [5; 4],
        fulu_fork_version: [6; 4],
        gloas_fork_version: [7; 4],
    };
    let init_unanchored = InitializeArgs {
        instance_id: [1; 32],
        chain_id,
        bootstrap_header: header.clone(),
        trusted_checkpoint_root: header_hash,
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 1_050,
        network_config: Some(net_cfg_unanchored),
    };
    let res = validate_initialize(&init_unanchored);
    assert!(
        matches!(
            res,
            Err(mosoo_core::error::MosooError::UnconfiguredTrustedCheckpoint { chain_id: 888888 })
        ),
        "Unanchored custom network must fail with UnconfiguredTrustedCheckpoint"
    );

    // 2. Custom network with self-certifying NetworkConfig (not registered in TrustedBridgeConfig) fails closed
    let net_cfg_anchored = NetworkConfig {
        chain_id,
        genesis_validators_root: [0x42; 32],
        trusted_checkpoint_root: Some(header_hash),
        altair_fork_version: [1; 4],
        bellatrix_fork_version: [2; 4],
        capella_fork_version: [3; 4],
        deneb_fork_version: [4; 4],
        electra_fork_version: [5; 4],
        fulu_fork_version: [6; 4],
        gloas_fork_version: [7; 4],
    };
    let init_anchored = InitializeArgs {
        instance_id: [1; 32],
        chain_id,
        bootstrap_header: header.clone(),
        trusted_checkpoint_root: header_hash,
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 1_050,
        network_config: Some(net_cfg_anchored),
    };
    let res_unreg = validate_initialize(&init_anchored);
    assert!(
        matches!(
            res_unreg,
            Err(mosoo_core::error::MosooError::UnconfiguredTrustedCheckpoint { chain_id: 888888 })
        ),
        "Self-certifying custom network without registration in TrustedBridgeConfig must fail closed"
    );

    // 3. Register custom network in TrustedBridgeConfig with administrative authorization
    let mut bridge_cfg = TrustedBridgeConfig::canonical();
    let admin = [0x55; 32];
    bridge_cfg.set_admin_authority(admin);
    assert!(bridge_cfg.register_trusted_checkpoint_authorized(&admin, chain_id, header_hash));
    assert_eq!(
        bridge_cfg.get_trusted_checkpoint(chain_id),
        Some(header_hash)
    );
    assert!(bridge_cfg.is_trusted_checkpoint(chain_id, &header_hash));

    // 4. Once registered in TrustedBridgeConfig, validation succeeds for matching checkpoint
    assert!(validate_initialize_with_config(&init_anchored, &bridge_cfg).is_ok());

    // 5. Mismatched checkpoint against registered TrustedBridgeConfig fails closed with UntrustedCheckpoint
    let net_cfg_mismatched = NetworkConfig {
        chain_id,
        genesis_validators_root: [0x42; 32],
        trusted_checkpoint_root: Some(custom_checkpoint), // Different from registered header_hash!
        altair_fork_version: [1; 4],
        bellatrix_fork_version: [2; 4],
        capella_fork_version: [3; 4],
        deneb_fork_version: [4; 4],
        electra_fork_version: [5; 4],
        fulu_fork_version: [6; 4],
        gloas_fork_version: [7; 4],
    };
    let init_mismatched = InitializeArgs {
        instance_id: [1; 32],
        chain_id,
        bootstrap_header: header,
        trusted_checkpoint_root: custom_checkpoint,
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 1_050,
        network_config: Some(net_cfg_mismatched),
    };
    let res_mismatch = validate_initialize_with_config(&init_mismatched, &bridge_cfg);
    assert!(
        matches!(
            res_mismatch,
            Err(mosoo_core::error::MosooError::UntrustedCheckpoint { chain_id: 888888 })
        ),
        "Mismatched custom network checkpoint against registered config must fail with UntrustedCheckpoint"
    );
}

// ---------------------------------------------------------------------------
// Public Statement Shielding Prevents Subject Key Linkability
// ---------------------------------------------------------------------------

#[test]
fn test_finding25_public_statement_shielding_prevents_subject_key_linkability() {
    use mosoo_core::types::{
        StatementBinding, VerifiedStatement, MOSOO_PROGRAM_ID, PROOF_TYPE_ETH_DEPOSIT,
    };

    let original = VerifiedStatement {
        chain_id: 11155111,
        genesis_validators_root: [0x11; 32],
        source_instance_id: [0x22; 32],
        source_instance_pda: [0x33; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0x44; 32],
        predicate_holds: true,
        verified_value: [0x55; 32],
        subject_key: [0x66; 32],
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: StatementBinding::Account {
            address: [0x77; 20],
        },
    };

    // 1. shield() blinds binding, subject_key, and statement_id
    let shielded = original.shield();
    assert!(shielded.is_shielded());
    assert_ne!(shielded.binding, original.binding);
    assert_ne!(shielded.subject_key, original.subject_key);
    assert_ne!(shielded.statement_id, original.statement_id);

    // 2. Calling shield() on an already shielded statement is idempotent (does not double-blind)
    let double_shielded = shielded.shield();
    assert_eq!(double_shielded.binding, shielded.binding);
    assert_eq!(double_shielded.subject_key, shielded.subject_key);
    assert_eq!(double_shielded.statement_id, shielded.statement_id);

    // 3. Calling shield() on an already salted statement preserves the salted blinding
    let salt = [0x88; 32];
    let salted = original.shield_with_salt(&salt);
    let shielded_salted = salted.shield();
    assert_eq!(shielded_salted.binding, salted.binding);
    assert_eq!(shielded_salted.subject_key, salted.subject_key);
    assert_eq!(shielded_salted.statement_id, salted.statement_id);
    assert!(shielded_salted.verify_salted_blinding(
        &salt,
        &original.subject_key,
        &original.statement_id
    ));
}

// ---------------------------------------------------------------------------
// Native ETH Deposit Missing Canonical 12-Zero Sender Topic Padding
// ---------------------------------------------------------------------------

#[test]
fn test_finding26_native_eth_deposit_sender_canonical_12zero_padding() {
    use alloy_primitives::{Address, B256, U256};
    use mosoo_core::error::MosooError;
    use mosoo_core::inclusion::{decode_deposit_erc20_log, decode_deposit_eth_log, VerifiedLog};

    let deposit_contract = Address::repeat_byte(0x11);
    let sender = Address::repeat_byte(0x22);
    let recipient = [0x33; 32];
    let amount = U256::from(1_000_000_000_000_000_000u64); // 1 ETH
    let nonce = 5u64;

    let deposit_eth_sig = B256::from(alloy_primitives::keccak256(
        b"DepositETH(address,bytes32,uint256,uint64)",
    ));

    // 1. Canonical topic: 12 leading zeros + 20 bytes of sender address
    let mut canonical_sender_topic = [0u8; 32];
    canonical_sender_topic[12..32].copy_from_slice(sender.as_slice());

    // 2. Non-canonical topic: non-zero garbage in first 12 bytes
    let mut non_canonical_sender_topic = canonical_sender_topic;
    non_canonical_sender_topic[0] = 0xff; // Corrupted padding!

    let mut nonce_topic = [0u8; 32];
    nonce_topic[24..32].copy_from_slice(&nonce.to_be_bytes());

    // Valid canonical log
    let valid_log = VerifiedLog {
        emitter: deposit_contract,
        tx_index: 0,
        log_index: 0,
        topics: vec![
            deposit_eth_sig,
            B256::from(canonical_sender_topic),
            B256::from(recipient),
            B256::from(nonce_topic),
        ],
        data: amount.to_be_bytes::<32>().to_vec(),
    };

    let decoded = decode_deposit_eth_log(&valid_log)
        .expect("Canonical DepositETH log must decode successfully");
    assert_eq!(decoded.0, sender);
    assert_eq!(decoded.1, recipient);
    assert_eq!(decoded.2, amount);
    assert_eq!(decoded.3, nonce);

    // Corrupted log with non-canonical 12 leading bytes must fail closed!
    let corrupted_log = VerifiedLog {
        emitter: deposit_contract,
        tx_index: 0,
        log_index: 0,
        topics: vec![
            deposit_eth_sig,
            B256::from(non_canonical_sender_topic),
            B256::from(recipient),
            B256::from(nonce_topic),
        ],
        data: amount.to_be_bytes::<32>().to_vec(),
    };

    let err = decode_deposit_eth_log(&corrupted_log).unwrap_err();
    assert!(
        matches!(err, MosooError::Internal(ref msg) if msg.contains("canonical 12 leading zero bytes"))
    );

    // 3. Test ERC-20 log canonical 12-zero topic padding
    let deposit_erc20_sig = B256::from(alloy_primitives::keccak256(
        b"DepositERC20(address,address,bytes32,uint256,uint64)",
    ));
    let token = Address::repeat_byte(0x55);
    let mut canonical_token_topic = [0u8; 32];
    canonical_token_topic[12..32].copy_from_slice(token.as_slice());

    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&amount.to_be_bytes::<32>());
    data.extend_from_slice(&U256::from(nonce).to_be_bytes::<32>());

    let valid_erc20_log = VerifiedLog {
        emitter: deposit_contract,
        tx_index: 0,
        log_index: 0,
        topics: vec![
            deposit_erc20_sig,
            B256::from(canonical_token_topic),
            B256::from(canonical_sender_topic),
            B256::from(recipient),
        ],
        data: data.clone(),
    };
    let decoded_erc20 =
        decode_deposit_erc20_log(&valid_erc20_log).expect("Canonical DepositERC20 log must decode");
    assert_eq!(decoded_erc20.0, token);
    assert_eq!(decoded_erc20.1, sender);

    // Corrupt sender topic padding in ERC-20
    let corrupted_erc20_log = VerifiedLog {
        emitter: deposit_contract,
        tx_index: 0,
        log_index: 0,
        topics: vec![
            deposit_erc20_sig,
            B256::from(canonical_token_topic),
            B256::from(non_canonical_sender_topic),
            B256::from(recipient),
        ],
        data,
    };
    let err_erc20 = decode_deposit_erc20_log(&corrupted_erc20_log).unwrap_err();
    assert!(
        matches!(err_erc20, MosooError::Internal(ref msg) if msg.contains("canonical 12 leading zero bytes"))
    );
}

// ---------------------------------------------------------------------------
// Shielded Statement Redemption with Witness in Consumers
// ---------------------------------------------------------------------------

#[test]
fn test_finding27_shielded_statement_consumer_redemption_with_witness() {
    use alloy_primitives::U256;
    use erc20_receiver::{claim_shielded_statement_u256, NullifierSet, ShieldedErc20ClaimWitness};
    use ether_receiver::{
        claim_shielded_ether_statement_u256, EtherNullifierSet, ShieldedEtherClaimWitness,
    };
    use mosoo_core::predicate::{derive_erc20_deposit_subject_key, derive_eth_deposit_subject_key};
    use mosoo_core::types::{
        StatementBinding, VerifiedStatement, CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID, PROOF_TYPE_ERC20_DEPOSIT, PROOF_TYPE_ETH_DEPOSIT,
    };

    let chain_id = ETH_SEPOLIA_CHAIN_ID;
    let block_hash = [0x11; 32];
    let slot = 1000u64;
    let tx_index = 0u64;
    let log_index = 0usize;
    let deposit_contract = [0x22; 20];
    let token_contract = [0x33; 20];
    let sender = [0x44; 20];
    let recipient = [0x55; 32];
    let amount_u256 = U256::from(500_000_000u64);
    let salt = [0x77; 32];

    // --- 1. Test Shielded ERC-20 Deposit Claim ---
    let unshielded_erc20_binding = StatementBinding::Erc20Deposit {
        execution_block_hash: block_hash,
        slot,
        tx_index,
        log_index,
        deposit_contract,
        token_contract,
        sender,
        recipient,
    };
    let unshielded_erc20_subject_key = derive_erc20_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &token_contract,
        &sender,
        &recipient,
    );

    let raw_erc20_stmt = VerifiedStatement {
        chain_id,
        genesis_validators_root: [0xaa; 32],
        source_instance_id: [0xbb; 32],
        source_instance_pda: CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32], // Computed below
        predicate_holds: true,
        verified_value: amount_u256.to_be_bytes::<32>(),
        subject_key: unshielded_erc20_subject_key,
        proof_type_tag: PROOF_TYPE_ERC20_DEPOSIT,
        binding: unshielded_erc20_binding.clone(),
    };
    let mut raw_erc20_stmt = raw_erc20_stmt;
    raw_erc20_stmt.statement_id = raw_erc20_stmt.derive_canonical_id();

    // Blind the statement with the secret 256-bit salt
    let shielded_erc20_stmt = raw_erc20_stmt.shield_with_salt(&salt);
    assert!(shielded_erc20_stmt.is_shielded());
    assert_ne!(
        shielded_erc20_stmt.statement_id,
        raw_erc20_stmt.statement_id
    );
    assert_ne!(shielded_erc20_stmt.subject_key, raw_erc20_stmt.subject_key);

    let mut erc20_nullifiers = NullifierSet::new();
    let valid_erc20_witness = ShieldedErc20ClaimWitness {
        unshielded_binding: unshielded_erc20_binding.clone(),
        privacy_salt: Some(salt),
    };

    // Claimant redeems shielded statement with private witness
    let claimed_amount = claim_shielded_statement_u256(
        &shielded_erc20_stmt,
        &valid_erc20_witness,
        &mut erc20_nullifiers,
        U256::from(100_000u64),
    )
    .expect("Shielded ERC-20 statement must redeem successfully");
    assert_eq!(claimed_amount, amount_u256);

    // Replay attack with same shielded statement must be rejected by blinded nullifier
    let replay_err = claim_shielded_statement_u256(
        &shielded_erc20_stmt,
        &valid_erc20_witness,
        &mut erc20_nullifiers,
        U256::from(100_000u64),
    )
    .unwrap_err();
    assert_eq!(replay_err, erc20_receiver::ReceiverError::AlreadyClaimed);

    // Adversary with incorrect salt is strictly rejected
    let bad_salt_witness = ShieldedErc20ClaimWitness {
        unshielded_binding: unshielded_erc20_binding,
        privacy_salt: Some([0x99; 32]), // Wrong salt!
    };
    let bad_salt_err = claim_shielded_statement_u256(
        &shielded_erc20_stmt,
        &bad_salt_witness,
        &mut NullifierSet::new(),
        U256::from(100_000u64),
    )
    .unwrap_err();
    assert_eq!(
        bad_salt_err,
        erc20_receiver::ReceiverError::SubjectKeyMismatch
    );

    // --- 2. Test Shielded Native ETH Deposit Claim ---
    let unshielded_eth_binding = StatementBinding::NativeEthDeposit {
        execution_block_hash: block_hash,
        slot,
        tx_index,
        log_index,
        deposit_contract,
        sender,
        recipient,
    };
    let unshielded_eth_subject_key = derive_eth_deposit_subject_key(
        &block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );

    let raw_eth_stmt = VerifiedStatement {
        chain_id,
        genesis_validators_root: [0xaa; 32],
        source_instance_id: [0xbb; 32],
        source_instance_pda: CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0u8; 32],
        predicate_holds: true,
        verified_value: amount_u256.to_be_bytes::<32>(),
        subject_key: unshielded_eth_subject_key,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: unshielded_eth_binding.clone(),
    };
    let mut raw_eth_stmt = raw_eth_stmt;
    raw_eth_stmt.statement_id = raw_eth_stmt.derive_canonical_id();

    let shielded_eth_stmt = raw_eth_stmt.shield_with_salt(&salt);
    let mut eth_nullifiers = EtherNullifierSet::new();
    let valid_eth_witness = ShieldedEtherClaimWitness {
        unshielded_binding: unshielded_eth_binding,
        privacy_salt: Some(salt),
    };

    let claimed_wei = claim_shielded_ether_statement_u256(
        &shielded_eth_stmt,
        &valid_eth_witness,
        &mut eth_nullifiers,
        U256::from(100_000u64),
    )
    .expect("Shielded Native ETH statement must redeem successfully");
    assert_eq!(claimed_wei, amount_u256);

    // Replay attack rejected
    let eth_replay_err = claim_shielded_ether_statement_u256(
        &shielded_eth_stmt,
        &valid_eth_witness,
        &mut eth_nullifiers,
        U256::from(100_000u64),
    )
    .unwrap_err();
    assert_eq!(
        eth_replay_err,
        ether_receiver::EtherReceiverError::AlreadyClaimed
    );
}

// ---------------------------------------------------------------------------
// zkVM Guest Authenticated Dispatch and Host Storage Boundaries
// ---------------------------------------------------------------------------

#[test]
fn test_finding28_zkvm_guest_rejects_untrusted_instance_and_forged_store() {
    use mosoo_core::error::MosooError;
    use mosoo_core::types::{
        AccountStore, Predicate, ProgramAccountStore, CANONICAL_SEPOLIA_INSTANCE_ID,
        ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    };
    use mosoo_core::verifier::{
        dispatch_guest_instruction, dispatch_store_instruction, AttestStateArgs, GuestInstruction,
    };

    // 1. In zkVM guest, AttestStateAuthenticated for unpinned chain must fail closed
    let unpinned_chain_id = 999999u64;
    let fake_instance = make_test_instance(unpinned_chain_id, [0x44; 32]);
    let fake_pda = fake_instance.pda_address();
    let fake_header = make_test_header(&fake_instance);

    let unpinned_instruction = GuestInstruction::AttestStateAuthenticated {
        expected_instance_pda: fake_pda,
        expected_header_pda: Some(fake_header.pda_address()),
        args: AttestStateArgs {
            instance: fake_instance,
            header: fake_header,
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
        },
    };

    let res_unpinned = dispatch_guest_instruction(unpinned_instruction);
    assert!(matches!(
        res_unpinned.unwrap_err(),
        MosooError::UntrustedSourceInstance
    ));

    // 2. dispatch_store_instruction MUST use host's persistent store and ignore any caller-provided fake store
    let mut host_store = ProgramAccountStore::default();
    let genuine_instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    let genuine_pda = genuine_instance.pda_address();
    host_store
        .try_set_account_with_owner(
            &genuine_pda,
            serde_json::to_vec(&genuine_instance).unwrap(),
            MOSOO_PROGRAM_ID,
        )
        .unwrap();

    let mut fake_store = ProgramAccountStore::default();
    let mut forged_instance = genuine_instance.clone();
    forged_instance.current_slot = 999999;
    fake_store
        .try_set_account_with_owner(
            &genuine_pda,
            serde_json::to_vec(&forged_instance).unwrap(),
            MOSOO_PROGRAM_ID,
        )
        .unwrap();

    let genuine_header = make_test_header(&genuine_instance);
    host_store
        .try_set_account_with_owner(
            &genuine_header.pda_address(),
            serde_json::to_vec(&genuine_header).unwrap(),
            MOSOO_PROGRAM_ID,
        )
        .unwrap();

    // Adversary wraps their call in StoreBacked passing fake_store
    let wrapped_instruction = GuestInstruction::StoreBacked {
        store: fake_store,
        instruction: Box::new(GuestInstruction::AttestStateAuthenticated {
            expected_instance_pda: genuine_pda,
            expected_header_pda: Some(genuine_header.pda_address()),
            args: AttestStateArgs {
                instance: forged_instance,
                header: genuine_header,
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
            },
        }),
    };

    // When dispatched via dispatch_store_instruction, host_store is used!
    // The attacker's fake_store is completely ignored!
    let res = dispatch_store_instruction(&mut host_store, wrapped_instruction);
    // It verifies against host_store (empty proof fails with InvalidTrieProof, NOT UntrustedSourceInstance)
    assert!(res.is_err());
    assert!(!matches!(
        res.unwrap_err(),
        MosooError::UntrustedSourceInstance
    ));
}

// ---------------------------------------------------------------------------
// Invariant Hardening: Weak-Subjectivity Expiry, Canonical Statement ID,
// and zkVM Guest Authenticated Dispatch Hardening
// ---------------------------------------------------------------------------

#[test]
fn test_finding30_weak_subjectivity_window_expiry_rejected() {
    let instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    let current_slot = instance.current_slot;

    // 1. Direct update jump exceeding canonical weak-subjectivity window (54,000 slots)
    let mut update_jump_expired = mosoo_core::types::LightClientUpdate {
        attested_header: mosoo_core::types::BeaconBlockHeader {
            slot: current_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body_root: [0u8; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: mosoo_core::types::BeaconBlockHeader {
            slot: current_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 1,
            proposer_index: 0,
            parent_root: [0u8; 32],
            state_root: [0u8; 32],
            body_root: [0u8; 32],
        },
        finality_branch: vec![[0u8; 32]; 6],
        sync_aggregate: mosoo_core::types::SyncAggregate {
            sync_committee_bits: vec![0xFF; 64],
            sync_committee_signature: vec![0u8; 96],
        },
        signature_slot: current_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 2,
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
    };

    let res_jump =
        mosoo_core::verifier::handle_begin_update(mosoo_core::verifier::BeginUpdateArgs::new(
            instance.clone(),
            update_jump_expired.clone(),
            1,
        ));
    assert!(
        matches!(res_jump, Err(MosooError::WeakSubjectivityExpired { .. })),
        "update jumping beyond CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS MUST fail closed with WeakSubjectivityExpired"
    );

    // 2. Adversary attempts to advance a stale instance (stalled beyond 54,000 slots from current Ethereum time)
    //    using small incremental updates (e.g. 50 slots).
    //    When trusted_head_slot is provided, the stale instance MUST fail closed!
    update_jump_expired.finalized_header.slot = current_slot + 50;
    update_jump_expired.attested_header.slot = current_slot + 50;
    update_jump_expired.signature_slot = current_slot + 51;

    let small_update_args =
        mosoo_core::verifier::BeginUpdateArgs::new(instance.clone(), update_jump_expired, 2)
            .with_trusted_head_slot(current_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 500);

    let res_stale_chained = mosoo_core::verifier::handle_begin_update(small_update_args);
    assert!(
        matches!(
            res_stale_chained,
            Err(MosooError::WeakSubjectivityExpired { .. })
        ),
        "adversary cannot advance an expired/stale instance using small chained updates"
    );

    // 3. State attestation against an expired instance MUST fail closed
    let mut current_header = make_test_header(&instance);
    current_header.slot = current_slot;
    let attest_args = AttestStateArgs {
        instance: instance.clone(),
        header: current_header,
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x01),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        privacy_salt: None,
        trusted_head_slot: Some(current_slot + CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS + 10),
        privacy_mode: None,
    };
    let res_attest_stale = mosoo_core::verifier::handle_attest_state(attest_args);
    assert!(
        matches!(
            res_attest_stale,
            Err(MosooError::WeakSubjectivityExpired { .. })
        ),
        "state attestation on stale instance MUST fail closed with WeakSubjectivityExpired"
    );
}

#[test]
fn test_finding31_statement_id_cross_instance_consistency() {
    let chain_id = ETH_SEPOLIA_CHAIN_ID;
    let gvr = crypto::genesis_validators_root(chain_id);
    let mut verified_value = [0u8; 32];
    verified_value[31] = 100; // 100 wei
    let proof_type = PROOF_TYPE_ETH_DEPOSIT;

    let deposit_contract = CANONICAL_SEPOLIA_MOSOO_LOCKER;
    let sender = [0x11; 20];
    let recipient = [0x22; 32];
    let execution_block_hash = [0x33; 32];
    let slot = 100;
    let tx_index = 0;
    let log_index = 0;

    let subject_key = ether_receiver::derive_eth_deposit_subject_key(
        &execution_block_hash,
        slot,
        tx_index,
        log_index,
        &deposit_contract,
        &sender,
        &recipient,
    );

    // Two independent light client instances verifying the exact same state fact
    let inst_a_id = CANONICAL_SEPOLIA_INSTANCE_ID;
    let inst_b_id = [0x02; 32];
    let pda_a = CANONICAL_SEPOLIA_MOSOO_INSTANCE;
    let pda_b = mosoo_core::types::derive_instance_pda(chain_id, &inst_b_id);

    // 1. Both produce IDENTICAL statement IDs
    let stmt_id_a =
        derive_statement_id_v2(chain_id, &gvr, &subject_key, proof_type, &verified_value);
    let stmt_id_b =
        derive_statement_id_v2(chain_id, &gvr, &subject_key, proof_type, &verified_value);
    assert_eq!(
        stmt_id_a, stmt_id_b,
        "Identical verified state facts MUST produce identical deterministic statement IDs across instances"
    );

    // 2. Emitted statements retain source_instance_pda for consumer binding
    let stmt_a = evaluate_with_binding_v2(
        &Predicate::Equal {
            expected: verified_value,
        },
        &VerifiedValue::StorageValue(verified_value),
        chain_id,
        gvr,
        inst_a_id,
        pda_a,
        subject_key,
        proof_type,
        StatementBinding::NativeEthDeposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        },
    )
    .unwrap();

    let stmt_b = evaluate_with_binding_v2(
        &Predicate::Equal {
            expected: verified_value,
        },
        &VerifiedValue::StorageValue(verified_value),
        chain_id,
        gvr,
        inst_b_id,
        pda_b,
        subject_key,
        proof_type,
        StatementBinding::NativeEthDeposit {
            execution_block_hash,
            slot,
            tx_index,
            log_index,
            deposit_contract,
            sender,
            recipient,
        },
    )
    .unwrap();

    assert_eq!(stmt_a.statement_id, stmt_b.statement_id);
    assert_ne!(stmt_a.source_instance_pda, stmt_b.source_instance_pda);

    // 3. Consumer pinned to canonical instance A accepts stmt_a but rejects stmt_b
    let mut ledger_a = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let stmt_acc_a = StatementAccount::new_authentic(stmt_a);
    let stmt_acc_b = StatementAccount::new_authentic(stmt_b);

    let mint_res_a = ledger_a.mint_deposit_authenticated_pda_u256(
        &stmt_acc_a,
        CANONICAL_SEPOLIA_MOSOO_LOCKER,
        &mut nullifiers,
    );
    assert!(mint_res_a.is_ok(), "Expected ok, got {:?}", mint_res_a);
    let mint_res_b = ledger_a.mint_deposit_authenticated_pda_u256(
        &stmt_acc_b,
        CANONICAL_SEPOLIA_MOSOO_LOCKER,
        &mut nullifiers,
    );
    assert!(
        mint_res_b.is_err(),
        "Statement from untrusted instance B must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Security Invariants: Multi-Instance Isolation & Zero-Leakage Privacy
// ---------------------------------------------------------------------------

#[test]
fn test_pda_derivation_invariants_across_all_networks() {
    use mosoo_core::types::{
        derive_instance_pda, CANONICAL_HOLESKY_INSTANCE_ID, CANONICAL_HOLESKY_MOSOO_INSTANCE,
        CANONICAL_MAINNET_INSTANCE_ID, CANONICAL_MAINNET_MOSOO_INSTANCE,
        CANONICAL_SEPOLIA_INSTANCE_ID, CANONICAL_SEPOLIA_MOSOO_INSTANCE, ETH_HOLESKY_CHAIN_ID,
        ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
    };

    // 1. Direct derivation helper invariant tests
    assert_eq!(
        derive_instance_pda(ETH_SEPOLIA_CHAIN_ID, &CANONICAL_SEPOLIA_INSTANCE_ID),
        CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        "Sepolia canonical PDA derivation mismatch"
    );
    assert_eq!(
        derive_instance_pda(ETH_MAINNET_CHAIN_ID, &CANONICAL_MAINNET_INSTANCE_ID),
        CANONICAL_MAINNET_MOSOO_INSTANCE,
        "Mainnet canonical PDA derivation mismatch"
    );
    assert_eq!(
        derive_instance_pda(ETH_HOLESKY_CHAIN_ID, &CANONICAL_HOLESKY_INSTANCE_ID),
        CANONICAL_HOLESKY_MOSOO_INSTANCE,
        "Holesky canonical PDA derivation mismatch"
    );

    // 2. InstanceAccount::pda_address() method invariant tests
    let sepolia_inst = make_test_instance(ETH_SEPOLIA_CHAIN_ID, CANONICAL_SEPOLIA_INSTANCE_ID);
    assert_eq!(
        sepolia_inst.pda_address(),
        CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        "Sepolia instance account method mismatch"
    );
    assert_eq!(
        sepolia_inst.pda_address(),
        derive_instance_pda(ETH_SEPOLIA_CHAIN_ID, &CANONICAL_SEPOLIA_INSTANCE_ID)
    );

    let mainnet_inst = make_test_instance(ETH_MAINNET_CHAIN_ID, CANONICAL_MAINNET_INSTANCE_ID);
    assert_eq!(
        mainnet_inst.pda_address(),
        CANONICAL_MAINNET_MOSOO_INSTANCE,
        "Mainnet instance account method mismatch"
    );
    assert_eq!(
        mainnet_inst.pda_address(),
        derive_instance_pda(ETH_MAINNET_CHAIN_ID, &CANONICAL_MAINNET_INSTANCE_ID)
    );

    let holesky_inst = make_test_instance(ETH_HOLESKY_CHAIN_ID, CANONICAL_HOLESKY_INSTANCE_ID);
    assert_eq!(
        holesky_inst.pda_address(),
        CANONICAL_HOLESKY_MOSOO_INSTANCE,
        "Holesky instance account method mismatch"
    );
    assert_eq!(
        holesky_inst.pda_address(),
        derive_instance_pda(ETH_HOLESKY_CHAIN_ID, &CANONICAL_HOLESKY_INSTANCE_ID)
    );
}
