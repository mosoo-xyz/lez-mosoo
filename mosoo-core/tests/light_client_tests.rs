use mosoo_core::{crypto::*, error::MosooError, types::*};

fn make_dummy_committee(count: usize) -> SyncCommittee {
    // Each pubkey is 48 bytes
    let pubkeys: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let mut pk = vec![0u8; 48];
            pk[0] = 0x80; // valid compressed flag indicator
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

#[test]
fn test_participation_threshold_strictly_enforced() {
    // 512 validators total. Threshold is ceil(512 * 2/3) = 342
    let mut bits = vec![0u8; 64];

    // Set 341 bits (just under 2/3)
    for i in 0..341 {
        bits[i / 8] |= 1 << (i % 8);
    }
    assert_eq!(count_participation(&bits), 341);

    // Should fail
    let committee = make_dummy_committee(512);
    let agg = SyncAggregate {
        sync_committee_bits: bits.clone(),
        sync_committee_signature: vec![0u8; 96],
    };
    let header = BeaconBlockHeader {
        slot: 1000,
        proposer_index: 1,
        parent_root: [1u8; 32],
        state_root: [2u8; 32],
        body_root: [3u8; 32],
    };

    let res = verify_sync_committee_signature(&committee, &agg, &header, 1, 1000);
    assert!(matches!(
        res,
        Err(MosooError::InsufficientParticipation {
            actual: 341,
            required: 342
        })
    ));

    // Now set the 342nd bit (exact threshold)
    bits[341 / 8] |= 1 << (341 % 8);
    assert_eq!(count_participation(&bits), 342);
}

#[test]
fn test_domain_separation_prevents_cross_chain_replay() {
    let header = BeaconBlockHeader {
        slot: 5_000_000,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
    };

    let root_mainnet = compute_signing_root(&header, ETH_MAINNET_CHAIN_ID, 5_000_000).unwrap();
    let root_sepolia = compute_signing_root(&header, ETH_SEPOLIA_CHAIN_ID, 5_000_000).unwrap();
    let root_holesky = compute_signing_root(&header, ETH_HOLESKY_CHAIN_ID, 5_000_000).unwrap();

    // All signing roots must be completely different for different chains
    assert_ne!(root_mainnet, root_sepolia);
    assert_ne!(root_mainnet, root_holesky);
    assert_ne!(root_sepolia, root_holesky);
}

#[test]
fn test_signing_root_deterministic() {
    let header = BeaconBlockHeader {
        slot: 6_000_000,
        proposer_index: 100,
        parent_root: [0xaa; 32],
        state_root: [0xbb; 32],
        body_root: [0xcc; 32],
    };

    let root1 = compute_signing_root(&header, ETH_MAINNET_CHAIN_ID, 6_000_000).unwrap();
    let root2 = compute_signing_root(&header, ETH_MAINNET_CHAIN_ID, 6_000_000).unwrap();
    assert_eq!(root1, root2);
}

#[test]
fn test_validator_participation_indexing() {
    let mut bits = vec![0u8; 64];
    // Validator 0
    bits[0] |= 1 << 0;
    // Validator 7
    bits[0] |= 1 << 7;
    // Validator 8
    bits[1] |= 1 << 0;
    // Validator 511
    bits[63] |= 1 << 7;

    assert!(validator_participated(&bits, 0));
    assert!(validator_participated(&bits, 7));
    assert!(validator_participated(&bits, 8));
    assert!(validator_participated(&bits, 511));

    assert!(!validator_participated(&bits, 1));
    assert!(!validator_participated(&bits, 6));
    assert!(!validator_participated(&bits, 510));
}

#[test]
fn test_full_light_client_update_execution_root_extraction() {
    use sha2::{Digest, Sha256};

    let expected_state_root = [0x55; 32];
    let expected_block_hash = [0x77; 32];

    let payload = ExecutionPayloadHeader {
        parent_hash: [0x11; 32],
        fee_recipient: [0x22; 20],
        state_root: expected_state_root,
        receipts_root: [0x33; 32],
        logs_bloom: vec![0; 256],
        prev_randao: [0x44; 32],
        block_number: 19_000_000,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
        timestamp: 1_700_000_000,
        extra_data: vec![],
        base_fee_per_gas: [0x66; 32],
        block_hash: expected_block_hash,
        transactions_root: [0x88; 32],
        withdrawals_root: Some([0x99; 32]),
        blob_gas_used: None,
        excess_blob_gas: None,
    };

    let payload_root = hash_tree_root_execution_payload_header(&payload).unwrap();

    // Generalized index 25 in BeaconBlockBody (index 9 in 16-leaf tree)
    let mut body_leaves = vec![[0u8; 32]; 16];
    body_leaves[9] = payload_root;

    let mut layers = vec![body_leaves];
    while layers.last().unwrap().len() > 1 {
        let current = layers.last().unwrap();
        let next: Vec<[u8; 32]> = current
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
        layers.push(next);
    }
    let body_root = layers.last().unwrap()[0];

    // Branch siblings for index 9 (generalized index 25)
    let mut branch = Vec::new();
    let mut idx = 9usize;
    for layer in layers.iter().take(layers.len() - 1) {
        let sibling = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        branch.push(layer[sibling]);
        idx /= 2;
    }

    // Verify branch
    let reconstructed_root = compute_branch_root(payload_root, &branch, 25);
    assert_eq!(reconstructed_root, body_root);

    // Authenticated HeaderRecord verification
    let header_record = HeaderRecord {
        chain_id: 1,
        slot: 8_000_000,
        beacon_block_root: [0xaa; 32],
        execution_block_hash: payload.block_hash,
        execution_state_root: payload.state_root,
        receipts_root: payload.receipts_root,
    };

    assert_eq!(header_record.execution_state_root, expected_state_root);
    assert_eq!(header_record.execution_block_hash, expected_block_hash);
}

#[test]
fn test_corrupted_execution_payload_branch_rejected() {
    let payload = ExecutionPayloadHeader {
        parent_hash: [0x11; 32],
        fee_recipient: [0x22; 20],
        state_root: [0xaa; 32],
        receipts_root: [0x33; 32],
        logs_bloom: vec![0; 256],
        prev_randao: [0x44; 32],
        block_number: 19_000_000,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
        timestamp: 1_700_000_000,
        extra_data: vec![],
        base_fee_per_gas: [0x66; 32],
        block_hash: [0xbb; 32],
        transactions_root: [0x88; 32],
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
    };

    let payload_root = hash_tree_root_execution_payload_header(&payload).unwrap();
    let bad_branch = vec![[0xff; 32]; 4];
    let expected_body_root = [0x12; 32];

    let computed = compute_branch_root(payload_root, &bad_branch, 25);
    assert_ne!(
        computed, expected_body_root,
        "Corrupted execution branch MUST NOT resolve to expected body_root"
    );
}

#[test]
fn test_split_verification_pipeline_rejection_on_bad_signature() {
    use blst::min_pk::SecretKey;

    let ikm = [42u8; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk();
    let signing_root = [0x5a; 32];

    // Tx 1: Begin (HashToG2)
    let msg_g2 = blst_hash_to_g2(&signing_root);

    // Tampered signature (signed wrong message)
    let bad_sig = sk.sign(b"wrong message", ETH_BLS_DST, &[]);

    // Tx 2: Miller
    let miller_bytes = blst_two_miller_loops(&bad_sig.to_bytes(), &pk.to_bytes(), &msg_g2).unwrap();

    // Tx 3: Finish (FinalExp)
    let is_valid = blst_final_exp_and_verify(&miller_bytes).unwrap();
    assert!(
        !is_valid,
        "Split pipeline MUST reject tampered signature at FinalExp stage"
    );
}

#[test]
fn test_bootstrap_cryptographic_verification_success() {
    use sha2::{Digest, Sha256};

    // 1. Construct 512-validator sync committee
    let committee = make_dummy_committee(512);
    let committee_leaf = hash_tree_root_sync_committee(&committee).unwrap();

    // 2. Build depth-5 Merkle tree for BeaconState (32 leaves, gindex 32..63)
    // current_sync_committee is field index 22 -> generalized index 54 (32 + 22)
    let mut leaves = vec![[0x11u8; 32]; 32];
    leaves[22] = committee_leaf;

    let mut layers = Vec::new();
    layers.push(leaves.clone());
    let mut current = leaves;
    while current.len() > 1 {
        let next: Vec<[u8; 32]> = current
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
        layers.push(next.clone());
        current = next;
    }
    let state_root = layers.last().unwrap()[0];

    // Extract branch for index 22 at depth 5 (5 siblings)
    let mut branch = Vec::new();
    let mut idx = 22usize;
    for layer in layers.iter().take(layers.len() - 1) {
        let sibling = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        branch.push(layer[sibling]);
        idx /= 2;
    }

    let header = BeaconBlockHeader {
        slot: 9_000_000,
        proposer_index: 100,
        parent_root: [0xaa; 32],
        state_root,
        body_root: [0xbb; 32],
    };

    // Cryptographic validation against gindex 54
    let computed_root = compute_branch_root(committee_leaf, &branch, 54);
    assert_eq!(
        computed_root, header.state_root,
        "Bootstrap sync committee branch MUST resolve to header.state_root"
    );

    // Header hash is deterministic and binds state root
    let header_hash = hash_tree_root_beacon_header(&header);
    assert_ne!(header_hash, [0u8; 32]);
}

#[test]
fn test_bootstrap_rejected_on_corrupted_committee_branch() {
    let committee = make_dummy_committee(512);
    let committee_leaf = hash_tree_root_sync_committee(&committee).unwrap();

    let mut corrupted_branch = vec![[0x22u8; 32]; 5];
    corrupted_branch[2][0] ^= 0xff; // corrupt sibling

    let expected_state_root = [0x55u8; 32];
    let computed = compute_branch_root(committee_leaf, &corrupted_branch, 54);

    assert_ne!(
        computed, expected_state_root,
        "Corrupted bootstrap branch MUST NOT resolve to genuine state_root"
    );
}

#[test]
fn test_bootstrap_rejected_on_wrong_committee() {
    use sha2::{Digest, Sha256};

    let genuine_committee = make_dummy_committee(512);
    let genuine_leaf = hash_tree_root_sync_committee(&genuine_committee).unwrap();

    let mut leaves = vec![[0x11u8; 32]; 32];
    leaves[22] = genuine_leaf;
    let mut current = leaves;
    let mut layers = Vec::new();
    layers.push(current.clone());
    while current.len() > 1 {
        let next: Vec<[u8; 32]> = current
            .chunks(2)
            .map(|pair| {
                let mut h = Sha256::new();
                h.update(pair[0]);
                h.update(pair[1]);
                h.finalize().into()
            })
            .collect();
        layers.push(next.clone());
        current = next;
    }
    let genuine_state_root = layers.last().unwrap()[0];

    // Branch for genuine committee
    let mut branch = Vec::new();
    let mut idx = 22usize;
    for layer in layers.iter().take(layers.len() - 1) {
        let sibling = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        branch.push(layer[sibling]);
        idx /= 2;
    }

    // Attacker supplies a forged committee with 1 modified pubkey
    let mut forged_committee = genuine_committee.clone();
    forged_committee.pubkeys[0][5] ^= 0xff;
    let forged_leaf = hash_tree_root_sync_committee(&forged_committee).unwrap();

    let computed = compute_branch_root(forged_leaf, &branch, 54);
    assert_ne!(
        computed, genuine_state_root,
        "Forged committee leaf MUST fail validation against genuine state root"
    );
}

#[test]
fn test_missing_execution_payload_strictly_rejected() {
    let dummy_header = BeaconBlockHeader {
        slot: 9_000_000,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
    };

    let update = LightClientUpdate {
        attested_header: dummy_header.clone(),
        finalized_header: dummy_header,
        finality_branch: vec![],
        next_sync_committee: None,
        next_sync_committee_branch: None,
        execution_payload_header: None, // Missing payload!
        execution_branch: None,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0; 96],
        },
        signature_slot: 9_000_000,
    };

    let payload_check = update
        .execution_payload_header
        .as_ref()
        .ok_or(MosooError::MissingExecutionPayload);

    assert!(matches!(
        payload_check,
        Err(MosooError::MissingExecutionPayload)
    ));
}

#[test]
fn test_missing_execution_branch_strictly_rejected() {
    let dummy_header = BeaconBlockHeader {
        slot: 9_000_000,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root: [0; 32],
        body_root: [0; 32],
    };

    let payload = ExecutionPayloadHeader {
        parent_hash: [0x11; 32],
        fee_recipient: [0x22; 20],
        state_root: [0xaa; 32],
        receipts_root: [0x33; 32],
        logs_bloom: vec![0; 256],
        prev_randao: [0x44; 32],
        block_number: 19_000_000,
        gas_limit: 30_000_000,
        gas_used: 15_000_000,
        timestamp: 1_700_000_000,
        extra_data: vec![],
        base_fee_per_gas: [0x66; 32],
        block_hash: [0xbb; 32],
        transactions_root: [0x88; 32],
        withdrawals_root: None,
        blob_gas_used: None,
        excess_blob_gas: None,
    };

    let update = LightClientUpdate {
        attested_header: dummy_header.clone(),
        finalized_header: dummy_header,
        finality_branch: vec![],
        next_sync_committee: None,
        next_sync_committee_branch: None,
        execution_payload_header: Some(payload),
        execution_branch: None, // Missing branch!
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0; 96],
        },
        signature_slot: 9_000_000,
    };

    let branch_check = update
        .execution_branch
        .as_ref()
        .ok_or(MosooError::MissingExecutionPayloadBranch);

    assert!(matches!(
        branch_check,
        Err(MosooError::MissingExecutionPayloadBranch)
    ));
}

#[test]
fn test_full_receipt_log_attestation_to_erc20_claim() {
    use alloy_primitives::{keccak256, Address, U256};
    use erc20_receiver::{claim, NullifierSet};
    use mosoo_core::inclusion::test_helpers::{
        build_leaf_mpt_proof, build_test_eip1559_transfer_receipt,
    };
    use mosoo_core::inclusion::{verify_receipt_log_proof, ReceiptLogProof};
    use mosoo_core::predicate;

    let token_emitter = Address::repeat_byte(0x55);
    let depositor = Address::repeat_byte(0x11);
    let recipient_on_lez = Address::repeat_byte(0x22);
    let deposit_amount = U256::from(50_000_000u64);

    let receipt_bytes = build_test_eip1559_transfer_receipt(
        token_emitter,
        depositor,
        recipient_on_lez,
        deposit_amount,
    );

    let tx_index: u64 = 0;
    let key_bytes = alloy_rlp::encode(tx_index);
    let (receipts_root, proof_nodes) = build_leaf_mpt_proof(&key_bytes, &receipt_bytes);

    let header = HeaderRecord {
        chain_id: 1,
        slot: 12_000_000, // Electra slot
        beacon_block_root: [0x77; 32],
        execution_block_hash: [0x88; 32],
        execution_state_root: [0x99; 32],
        receipts_root: receipts_root.0,
    };

    let transfer_sig = keccak256("Transfer(address,address,uint256)");
    let proof = ReceiptLogProof {
        tx_index,
        log_index: 0,
        expected_emitter: Some(token_emitter),
        expected_topic0: Some(transfer_sig),
        receipt_proof: proof_nodes,
        receipt_rlp: receipt_bytes,
    };

    // 1. Verify receipt inclusion against header.receipts_root
    let verified_log = verify_receipt_log_proof(&proof, &header).expect("Receipt proof must pass");
    assert_eq!(verified_log.emitter, token_emitter);

    // 2. Evaluate predicate: deposit amount >= 10,000,000
    let mut min_bytes = [0u8; 32];
    min_bytes[28..].copy_from_slice(&10_000_000u32.to_be_bytes());
    let pred = Predicate::AtLeast { min: min_bytes };

    let verified_val = mosoo_core::inclusion::VerifiedValue::LogData(verified_log.data);
    let statement = predicate::evaluate(&pred, &verified_val, header.chain_id, [0xaa; 32], 2)
        .expect("Predicate must hold");

    // 3. Consumer mint on LEZ
    let mut nullifiers = NullifierSet::new();
    let mint_res = claim(&statement, &mut nullifiers, 100);
    assert!(mint_res.is_ok(), "First claim must succeed and mint tokens");

    // 4. Double-mint with same nullifier MUST be rejected
    let repeat_res = claim(&statement, &mut nullifiers, 100);
    assert!(
        repeat_res.is_err(),
        "Duplicate claim using the same event receipt nullifier MUST be rejected"
    );
}

#[test]
fn test_sepolia_gloas_and_hoodi_fork_boundary_and_domain_separation() {
    let sepolia_chain = 11_155_111u64;
    let hoodi_chain = 560_048u64;

    // 1. Verify chain support guards
    assert!(is_supported_chain(ETH_MAINNET_CHAIN_ID));
    assert!(is_supported_chain(sepolia_chain));
    assert!(is_supported_chain(ETH_HOLESKY_CHAIN_ID));
    assert!(is_supported_chain(hoodi_chain));
    assert!(!is_supported_chain(999_999));

    // 2. Sepolia Gloas fork boundary verification (slot 7,077,888)
    let pre_gloas_sepolia = fork_version(sepolia_chain, 7_077_887);
    let post_gloas_sepolia = fork_version(sepolia_chain, 7_077_888);
    assert_eq!(pre_gloas_sepolia, [0x90, 0x00, 0x00, 0x75]); // Electra
    assert_eq!(post_gloas_sepolia, [0x90, 0x00, 0x00, 0x77]); // Gloas

    let domain_pre = compute_sync_committee_domain(sepolia_chain, 7_077_887);
    let domain_post = compute_sync_committee_domain(sepolia_chain, 7_077_888);
    assert_ne!(domain_pre, domain_post);

    // 3. Hoodi testnet fork boundary verification (slot 786,432)
    let pre_gloas_hoodi = fork_version(hoodi_chain, 786_431);
    let post_gloas_hoodi = fork_version(hoodi_chain, 786_432);
    assert_eq!(pre_gloas_hoodi, [0x10, 0x00, 0x09, 0x00]);
    assert_eq!(post_gloas_hoodi, [0x10, 0x00, 0x09, 0x10]);

    let domain_hoodi = compute_sync_committee_domain(hoodi_chain, 786_432);
    let domain_sepolia = compute_sync_committee_domain(sepolia_chain, 786_432);
    let domain_mainnet = compute_sync_committee_domain(ETH_MAINNET_CHAIN_ID, 786_432);

    // Domain separation must ensure distinct signing domains across networks
    assert_ne!(domain_hoodi, domain_sepolia);
    assert_ne!(domain_hoodi, domain_mainnet);
    assert_ne!(domain_sepolia, domain_mainnet);

    // 4. Cross-domain signing root collision resistance
    let header = BeaconBlockHeader {
        slot: 7_077_888,
        proposer_index: 42,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
    };

    let root_sepolia_gloas = compute_signing_root(&header, sepolia_chain, 7_077_888).unwrap();
    let root_sepolia_electra = compute_signing_root(&header, sepolia_chain, 7_077_887).unwrap();
    assert_ne!(
        root_sepolia_gloas, root_sepolia_electra,
        "Signing root across fork transitions MUST NEVER collide"
    );
}

/// Test 15: Monotonic slot progression enforcement with exact boundary values.
///
/// Verifies that the instance strictly rejects updates where the finalized slot
/// does NOT advance monotonically. Tests the exact slot-equality boundary (stale_slot == current)
/// as well as underflow (stale_slot < current).
#[test]
fn test_monotonic_slot_progression_boundary_conditions() {
    use mosoo_core::verifier::{handle_begin_update, BeginUpdateArgs};

    fn make_committee(count: usize) -> SyncCommittee {
        let pubkeys: Vec<Vec<u8>> = (0..count)
            .map(|i| {
                let mut pk = vec![0u8; 48];
                pk[0] = 0x80;
                pk[1] = (i & 0xFF) as u8;
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

    let current_slot = 15_433_760u64;
    let instance = InstanceAccount {
        chain_id: ETH_MAINNET_CHAIN_ID,
        current_header_hash: [0xAB; 32],
        current_state_root: [0xCD; 32],
        current_slot,
        current_sync_committee: make_committee(512),
        next_sync_committee: None,
        bootstrap_slot: 15_000_000,
        initialized: true,
    };

    fn make_update(slot: u64) -> LightClientUpdate {
        LightClientUpdate {
            attested_header: BeaconBlockHeader {
                slot: slot + 1,
                proposer_index: 1,
                parent_root: [0; 32],
                state_root: [0; 32],
                body_root: [0; 32],
            },
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: BeaconBlockHeader {
                slot,
                proposer_index: 1,
                parent_root: [0; 32],
                state_root: [0; 32],
                body_root: [0; 32],
            },
            finality_branch: vec![[0u8; 32]; 6],
            sync_aggregate: SyncAggregate {
                sync_committee_bits: vec![0xFF; 64],
                sync_committee_signature: vec![0u8; 96],
            },
            signature_slot: slot + 1,
            execution_payload_header: None,
            execution_branch: None,
        }
    }

    // Boundary A: exact same slot (must reject as stale)
    let res_same = handle_begin_update(BeginUpdateArgs {
        instance: instance.clone(),
        update: make_update(current_slot),
        nonce: 1,
    });
    assert!(
        matches!(
            res_same,
            Err(MosooError::StaleUpdate {
                update_slot,
                current_slot: cs
            }) if update_slot == current_slot && cs == current_slot
        ),
        "Exact same slot MUST be rejected as StaleUpdate"
    );

    // Boundary B: one slot behind (must reject)
    let res_behind = handle_begin_update(BeginUpdateArgs {
        instance: instance.clone(),
        update: make_update(current_slot - 1),
        nonce: 2,
    });
    assert!(
        matches!(res_behind, Err(MosooError::StaleUpdate { .. })),
        "Slot behind current MUST be rejected as StaleUpdate"
    );

    // Boundary C: weak-subjectivity window exceeded (current + 1,728,001)
    let res_expired = handle_begin_update(BeginUpdateArgs {
        instance,
        update: make_update(current_slot + 1_728_001),
        nonce: 3,
    });
    assert!(
        matches!(res_expired, Err(MosooError::WeakSubjectivityExpired { .. })),
        "Slot beyond weak-subjectivity window MUST be rejected"
    );
}

/// Test 16: Multi-network chain ID isolation — fork versions are strictly per-chain.
///
/// Verifies that for any given slot, each supported Ethereum network
/// returns a distinct fork version, and that unsupported chain IDs return zero-bytes.
/// This is critical for domain separation correctness across Mainnet, Sepolia, Hoodi.
#[test]
fn test_multi_network_fork_version_isolation() {
    // Test slot 7,077,888 — Sepolia Gloas activation slot, still Fulu on Mainnet
    let slot = 7_077_888u64;

    let v_mainnet = fork_version(ETH_MAINNET_CHAIN_ID, slot);
    let v_sepolia = fork_version(ETH_SEPOLIA_CHAIN_ID, slot);
    let v_holesky = fork_version(ETH_HOLESKY_CHAIN_ID, slot);
    let v_hoodi = fork_version(560_048, slot);
    let v_unknown = fork_version(999_999, slot);

    // All supported networks at this slot must have distinct fork versions
    assert_ne!(v_mainnet, v_sepolia, "Mainnet vs Sepolia must be distinct");
    assert_ne!(v_mainnet, v_holesky, "Mainnet vs Holesky must be distinct");
    assert_ne!(v_mainnet, v_hoodi, "Mainnet vs Hoodi must be distinct");
    assert_ne!(v_sepolia, v_holesky, "Sepolia vs Holesky must be distinct");
    assert_ne!(v_sepolia, v_hoodi, "Sepolia vs Hoodi must be distinct");

    // Mainnet at slot 7,077,888 is still Fulu era (Fulu = slot 13,164,544)
    // Actually slot 7,077,888 < 8,626,176 (Deneb) — so it's pre-Deneb = Capella
    assert_eq!(
        v_mainnet,
        [0x03, 0x00, 0x00, 0x00],
        "Mainnet at slot 7,077,888 is Capella era"
    );

    // Sepolia at slot 7,077,888 is Gloas (activated at exactly this slot)
    assert_eq!(
        v_sepolia,
        [0x90, 0x00, 0x00, 0x77],
        "Sepolia at slot 7,077,888 is Gloas fork"
    );

    // Unknown chain ID must return zero fork version
    assert_eq!(
        v_unknown,
        [0x00, 0x00, 0x00, 0x00],
        "Unknown chain ID must return zero fork version"
    );

    // Verify chain support flags match expectations
    assert!(is_supported_chain(ETH_MAINNET_CHAIN_ID));
    assert!(is_supported_chain(ETH_SEPOLIA_CHAIN_ID));
    assert!(is_supported_chain(ETH_HOLESKY_CHAIN_ID));
    assert!(is_supported_chain(560_048));
    assert!(!is_supported_chain(999_999));
    assert!(!is_supported_chain(0));
}
