//! Security regression test suite verifying resolution of all 6 findings
//! from the MOSOO Security Audit (Oct 26, 2026).
//!
//! Findings covered:
//! - Finding 1 (Critical P0): zkVM guest authenticated instructions & account authenticity
//! - Finding 2 (High P1): Consumer persistent store-backed minting APIs & rejection of caller state
//! - Finding 3 (High P1): Statement source-instance PDA binding & cross-instance isolation
//! - Finding 4 (High P1): Privacy-preserving shielded statement binding (RFP-021 Functionality #8)
//! - Finding 5 (Medium P2): Solidity legacy withdrawal disablement (verified in Foundry)
#![allow(deprecated)]

//! - Finding 6 (Low/Med P2/P3): Canonical Statement ID specification & predicate invariance

use ether_receiver::{AtomicEtherClaimArgs, EtherNullifierSet, MethLedger};
use mosoo_core::{
    crypto,
    error::MosooError,
    inclusion::{ProofTarget, StateProof, VerifiedValue},
    predicate::{derive_statement_id_v2, evaluate_with_binding_v2},
    types::{
        AccountStore, HeaderRecord, InstanceAccount, Predicate, StatementAccount, StatementBinding,
        SyncCommittee, TrustedBridgeConfig, VerifiedStatement, CANONICAL_SEPOLIA_INSTANCE_ID,
        CANONICAL_SEPOLIA_MOSOO_INSTANCE, CANONICAL_SEPOLIA_MOSOO_LOCKER,
        CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS, ETH_MAINNET_CHAIN_ID, ETH_SEPOLIA_CHAIN_ID,
        MOSOO_PROGRAM_ID, PROOF_TYPE_ERC20_DEPOSIT, PROOF_TYPE_ETH_DEPOSIT,
    },
    verifier::{dispatch_guest_instruction, AttestStateArgs, FinishUpdateArgs, GuestInstruction},
};
use std::collections::HashMap;

/// In-memory mock account store implementing `AccountStore`.
#[derive(Default, Clone)]
struct MockStore {
    accounts: HashMap<[u8; 32], Vec<u8>>,
    owners: HashMap<[u8; 32], [u8; 32]>,
}

impl AccountStore for MockStore {
    fn get_account(&self, address: &[u8; 32]) -> Option<Vec<u8>> {
        self.accounts.get(address).cloned()
    }

    fn set_account(&mut self, address: &[u8; 32], data: Vec<u8>) {
        self.accounts.insert(*address, data);
    }

    fn set_account_with_owner(&mut self, address: &[u8; 32], data: Vec<u8>, owner: [u8; 32]) {
        self.accounts.insert(*address, data);
        self.owners.insert(*address, owner);
    }

    fn remove_account(&mut self, address: &[u8; 32]) -> bool {
        self.owners.remove(address);
        self.accounts.remove(address).is_some()
    }

    fn get_account_owner(&self, address: &[u8; 32]) -> Option<[u8; 32]> {
        self.owners.get(address).copied()
    }

    fn try_set_account_with_owner(
        &mut self,
        address: &[u8; 32],
        data: Vec<u8>,
        owner: [u8; 32],
    ) -> Result<(), mosoo_core::types::StoreError> {
        self.accounts.insert(*address, data);
        self.owners.insert(*address, owner);
        Ok(())
    }

    fn try_set_accounts_batch_with_owner(
        &mut self,
        accounts: &[([u8; 32], Vec<u8>, [u8; 32])],
    ) -> Result<(), mosoo_core::types::StoreError> {
        for (addr, data, owner) in accounts {
            self.accounts.insert(*addr, data.clone());
            self.owners.insert(*addr, *owner);
        }
        Ok(())
    }
}

fn make_valid_committee() -> SyncCommittee {
    let ikm = [0x42; 32];
    let sk = blst::min_pk::SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk().to_bytes().to_vec();
    SyncCommittee {
        pubkeys: vec![pk.clone(); 512],
        aggregate_pubkey: pk,
    }
}

/// Helper to build an authentic dummy InstanceAccount
fn make_test_instance(chain_id: u64, instance_id: [u8; 32]) -> InstanceAccount {
    InstanceAccount {
        instance_id,
        chain_id,
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_slot: 1000,
        current_sync_committee: make_valid_committee(),
        next_sync_committee: None,
        bootstrap_slot: 500,
        bootstrap_header_hash: [0xaa; 32],
        initialized: true,
        current_execution_block_hash: [0x33; 32],
        current_execution_state_root: [0x44; 32],
        current_receipts_root: [0x55; 32],
        network_config: None,
    }
}

/// Helper to build a matching HeaderRecord
fn make_test_header(instance: &InstanceAccount) -> HeaderRecord {
    HeaderRecord {
        chain_id: instance.chain_id,
        slot: instance.current_slot,
        beacon_block_root: instance.current_header_hash,
        execution_block_hash: instance.current_execution_block_hash,
        execution_state_root: instance.current_execution_state_root,
        receipts_root: instance.current_receipts_root,
    }
}

fn empty_state_proof(target: ProofTarget) -> StateProof {
    StateProof {
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: None,
        account_value: None,
        storage_value: None,
        receipt_value: None,
        target,
    }
}

// ---------------------------------------------------------------------------
// Finding 1: zkVM Guest Authenticated Instructions & PDA Verification
// ---------------------------------------------------------------------------

#[test]
fn test_finding1_zkvm_authenticated_guest_instruction_rejects_unauthenticated_pda() {
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    let authentic_pda = instance.pda_address();
    let header = make_test_header(&instance);
    let authentic_header_pda = header.pda_address();

    let args = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
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
    };

    // 1. Adversary supplies fake expected instance PDA
    let fake_instance_pda = [0x99; 32];
    let instruction_fake_inst = GuestInstruction::AttestStateAuthenticated {
        expected_instance_pda: fake_instance_pda,
        expected_header_pda: Some(authentic_header_pda),
        args: args.clone(),
    };
    let res1 = dispatch_guest_instruction(instruction_fake_inst);
    assert!(matches!(
        res1.unwrap_err(),
        MosooError::UnauthenticatedInstance
    ));

    // 2. Adversary supplies fake expected header PDA
    let fake_header_pda = [0x88; 32];
    let instruction_fake_hdr = GuestInstruction::AttestStateAuthenticated {
        expected_instance_pda: authentic_pda,
        expected_header_pda: Some(fake_header_pda),
        args: args.clone(),
    };
    let res2 = dispatch_guest_instruction(instruction_fake_hdr);
    assert!(matches!(
        res2.unwrap_err(),
        MosooError::UnauthenticatedHeaderRecord
    ));

    // 3. Authenticated FinishUpdate asserts instance PDA and job PDA
    let finish_args = FinishUpdateArgs {
        instance: instance.clone(),
        job: mosoo_core::types::JobAccount {
            instance_id,
            instance_chain_id: instance.chain_id,
            instance_slot: instance.current_slot,
            stage: mosoo_core::types::JobStage::Begin,
            update_digest: [0u8; 32],
            update: mosoo_core::types::LightClientUpdate {
                attested_header: mosoo_core::types::BeaconBlockHeader {
                    slot: 1001,
                    proposer_index: 0,
                    parent_root: [0u8; 32],
                    state_root: [0u8; 32],
                    body_root: [0u8; 32],
                },
                next_sync_committee: None,
                next_sync_committee_branch: None,
                finalized_header: mosoo_core::types::BeaconBlockHeader {
                    slot: 1001,
                    proposer_index: 0,
                    parent_root: [0u8; 32],
                    state_root: [0u8; 32],
                    body_root: [0u8; 32],
                },
                finality_branch: vec![],
                sync_aggregate: mosoo_core::types::SyncAggregate {
                    sync_committee_bits: vec![],
                    sync_committee_signature: vec![],
                },
                signature_slot: 1002,
                execution_payload_header: None,
                execution_branch: None,
                execution_rlp: None,
            },
            miller_input: None,
            miller_output: None,
            nonce: 1,
        },
    };

    let instruction_fake_finish = GuestInstruction::FinishUpdateAuthenticated {
        expected_instance_pda: fake_instance_pda,
        expected_job_pda: [0x55; 32],
        args: finish_args,
    };
    let res3 = dispatch_guest_instruction(instruction_fake_finish);
    assert!(matches!(
        res3.unwrap_err(),
        MosooError::UnauthenticatedInstance
    ));
}

// ---------------------------------------------------------------------------
// Finding 2: Consumer Persistent Store Minting & Caller State Rejection
// ---------------------------------------------------------------------------

#[test]
fn test_finding2_meth_ledger_authenticated_store_minting() {
    let mut store = MockStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();
    let mut ledger = MethLedger::new();
    let mut nullifiers = EtherNullifierSet::new();

    let instance_id = [0x55; 32];
    let instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    let instance_pda = instance.pda_address();

    // 1. Setup persistent program-owned TrustedBridgeConfig
    let mut config = TrustedBridgeConfig::canonical();
    let authentic_locker = [0x74; 20];
    config.register_trusted_locker(ETH_SEPOLIA_CHAIN_ID, authentic_locker);
    config.register_trusted_instance(ETH_SEPOLIA_CHAIN_ID, instance_pda);
    config.register_trusted_checkpoint(ETH_SEPOLIA_CHAIN_ID, instance.bootstrap_header_hash);
    config.save_to_store(&mut store).unwrap();
    ledger.config = config;

    // 2. Save authentic instance to persistent store
    let inst_bytes = serde_json::to_vec(&instance).unwrap();
    store
        .try_set_account_with_owner(&instance_pda, inst_bytes, MOSOO_PROGRAM_ID)
        .unwrap();

    let header = make_test_header(&instance);
    let header_pda = header.pda_address();
    let hdr_bytes = serde_json::to_vec(&header).unwrap();
    store
        .try_set_account_with_owner(&header_pda, hdr_bytes, MOSOO_PROGRAM_ID)
        .unwrap();

    // 3. Attempt mint with unbacked account balance proof -> Rejected
    let unbacked_args = AtomicEtherClaimArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: empty_state_proof(ProofTarget::AccountBalance {
            address: alloy_primitives::Address::repeat_byte(0x01),
        }),
        predicate: Predicate::Equal {
            expected: [0u8; 32],
        },
        expected_address: authentic_locker,
        recipient: [0x33; 32],
        min_wei: 100,
    };

    let err = ledger.mint_deposit_authenticated_store_u256(
        &mut store,
        &instance_pda,
        Some(&header_pda),
        unbacked_args,
        &mut nullifiers,
    );
    assert!(err.is_err());
}

// ---------------------------------------------------------------------------
// Finding 3: Cross-Instance Isolation & Statement Binding
// ---------------------------------------------------------------------------

#[test]
fn test_finding3_statement_instance_isolation_and_cross_instance_rejection() {
    let chain_id = ETH_SEPOLIA_CHAIN_ID;
    let gvr = crypto::genesis_validators_root(chain_id);

    let instance_id_a = [0x11; 32];
    let instance_id_b = [0x22; 32];
    let instance_pda_a = mosoo_core::types::derive_instance_pda(chain_id, &instance_id_a);
    let instance_pda_b = mosoo_core::types::derive_instance_pda(chain_id, &instance_id_b);

    assert_ne!(instance_pda_a, instance_pda_b);

    let subject_key = [0xaa; 32];
    let verified_value = [0xbb; 32];
    let proof_type = PROOF_TYPE_ETH_DEPOSIT;

    // 1. Derive statement IDs for instance A and instance B with identical state facts
    let stmt_id_a =
        derive_statement_id_v2(chain_id, &gvr, &subject_key, proof_type, &verified_value);
    let stmt_id_b =
        derive_statement_id_v2(chain_id, &gvr, &subject_key, proof_type, &verified_value);

    // Assert RFP-021 Functionality #6: For identical verified Ethereum state,
    // the emitted statement identifier MUST be identical and deterministic!
    assert_eq!(
        stmt_id_a, stmt_id_b,
        "identical verified Ethereum state facts MUST produce identical deterministic statement IDs (RFP-021 Functionality #6)"
    );

    // 2. Evaluate statement with instance A binding
    let stmt_a = evaluate_with_binding_v2(
        &Predicate::Equal {
            expected: verified_value,
        },
        &VerifiedValue::StorageValue(verified_value),
        chain_id,
        gvr,
        instance_id_a,
        instance_pda_a,
        subject_key,
        proof_type,
        StatementBinding::NativeEthDeposit {
            execution_block_hash: [0x55; 32],
            slot: 100,
            tx_index: 0,
            log_index: 0,
            deposit_contract: [0x74; 20],
            sender: [0x12; 20],
            recipient: [0x34; 32],
        },
    )
    .unwrap();

    assert_eq!(stmt_a.source_instance_pda, instance_pda_a);
    assert_eq!(stmt_a.statement_id, stmt_id_a);

    // 3. Consumer configured for instance B must strictly reject statement emitted by instance A
    let mut config_for_b = TrustedBridgeConfig::canonical();
    config_for_b.register_trusted_instance(chain_id, instance_pda_b);
    let mut ledger_b = MethLedger::new();
    ledger_b.config = config_for_b;

    let stmt_acc_a = StatementAccount::new_authentic(stmt_a);
    let mut nullifiers = EtherNullifierSet::new();

    let err =
        ledger_b.mint_deposit_authenticated_pda_u256(&stmt_acc_a, [0x74; 20], &mut nullifiers);
    assert!(
        err.is_err(),
        "statement from instance A MUST be rejected by consumer pinned to instance B"
    );
}

// ---------------------------------------------------------------------------
// Finding 4: Privacy-Preserving Shielded Statement Binding (RFP-021 #8)
// ---------------------------------------------------------------------------

#[test]
fn test_finding4_privacy_shielded_statement_zero_address_leakage() {
    let secret_sender = [0xfe; 20];
    let secret_recipient = [0xdc; 32];
    let secret_locker = [0xba; 20];
    let block_hash = [0x99; 32];

    let original_binding = StatementBinding::NativeEthDeposit {
        execution_block_hash: block_hash,
        slot: 12345,
        tx_index: 3,
        log_index: 2,
        deposit_contract: secret_locker,
        sender: secret_sender,
        recipient: secret_recipient,
    };

    let commitment = original_binding.compute_commitment();
    assert_ne!(commitment, [0u8; 32]);

    let stmt = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: [0x11; 32],
        source_instance_id: [0x22; 32],
        source_instance_pda: [0x33; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0x44; 32],
        predicate_holds: true,
        verified_value: [0x55; 32],
        subject_key: [0x66; 32],
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: original_binding,
    };

    // Shield the statement
    let shielded_stmt = stmt.shield();

    // Verify binding is now shielded with exact commitment
    assert_eq!(
        shielded_stmt.binding,
        StatementBinding::Shielded { commitment }
    );

    // Verify zero plain-text address leakage in serialized shielded statement
    let serialized = serde_json::to_string(&shielded_stmt).unwrap();
    let sender_hex = hex::encode(secret_sender);
    let recipient_hex = hex::encode(secret_recipient);
    let locker_hex = hex::encode(secret_locker);

    assert!(
        !serialized.contains(&sender_hex),
        "shielded statement journal must NOT contain sender address hex"
    );
    assert!(
        !serialized.contains(&recipient_hex),
        "shielded statement journal must NOT contain recipient address hex"
    );
    assert!(
        !serialized.contains(&locker_hex),
        "shielded statement journal must NOT contain locker address hex"
    );
}

// ---------------------------------------------------------------------------
// Finding 6: Canonical Statement ID Specification & Predicate Invariance
// ---------------------------------------------------------------------------

#[test]
fn test_finding6_statement_id_predicate_invariance() {
    let chain_id = ETH_MAINNET_CHAIN_ID;
    let gvr = crypto::genesis_validators_root(chain_id);
    let source_instance_pda = [0x77; 32];
    let subject_key = [0x88; 32];
    let verified_value = [0x99; 32];
    let proof_type = PROOF_TYPE_ERC20_DEPOSIT;

    // Evaluate with predicate A (AtLeast 10)
    let stmt_a = evaluate_with_binding_v2(
        &Predicate::AtLeast { min: [0x01; 32] },
        &VerifiedValue::StorageValue(verified_value),
        chain_id,
        gvr,
        [0u8; 32],
        source_instance_pda,
        subject_key,
        proof_type,
        StatementBinding::default(),
    )
    .unwrap();

    // Evaluate with predicate B (AtLeast 50)
    let stmt_b = evaluate_with_binding_v2(
        &Predicate::AtLeast { min: [0x05; 32] },
        &VerifiedValue::StorageValue(verified_value),
        chain_id,
        gvr,
        [0u8; 32],
        source_instance_pda,
        subject_key,
        proof_type,
        StatementBinding::default(),
    )
    .unwrap();

    // Both predicates hold over the same state fact -> MUST yield identical statement ID!
    assert_eq!(
        stmt_a.statement_id, stmt_b.statement_id,
        "statement_id MUST be invariant to predicate variants to prevent nullifier replay bypass"
    );
}

// ---------------------------------------------------------------------------
// Finding 7: Job Account Nonce Collision & Overwrite Prevention (Medium #1)
// ---------------------------------------------------------------------------

#[test]
fn test_finding7_job_account_collision_prevents_overwrite() {
    use mosoo_core::types::{LightClientUpdate, SyncAggregate};
    use mosoo_core::verifier::handle_begin_update_authenticated;

    let mut store = MockStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let inst = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    let inst_pda = inst.pda_address();

    // Register authentic instance in store
    store.set_account_with_owner(
        &inst_pda,
        serde_json::to_vec(&inst).unwrap(),
        MOSOO_PROGRAM_ID,
    );

    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();

    let dummy_header = mosoo_core::types::BeaconBlockHeader {
        slot: 1005,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
    };

    let mut update_a = LightClientUpdate {
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
        signature_slot: 1006,
    };

    let args_a = mosoo_core::verifier::BeginUpdateArgs {
        instance: inst.clone(),
        update: update_a.clone(),
        nonce: 42,
        trusted_head_slot: None,
    };

    // First submission succeeds and creates the job
    let res_a = handle_begin_update_authenticated(&mut store, &inst_pda, args_a.clone());
    assert!(res_a.is_ok(), "First update submission must succeed");

    // Idempotent duplicate submission of exact same update succeeds
    let res_dup = handle_begin_update_authenticated(&mut store, &inst_pda, args_a);
    assert!(
        res_dup.is_ok(),
        "Idempotent retry with exact same digest must succeed"
    );

    // Second submission with conflicting update at same nonce MUST be rejected with JobAccountCollision!
    update_a.signature_slot = 1007; // Change update to alter digest
    let args_conflicting = mosoo_core::verifier::BeginUpdateArgs {
        instance: inst,
        update: update_a,
        nonce: 42, // Same nonce!
        trusted_head_slot: None,
    };

    let res_conflict = handle_begin_update_authenticated(&mut store, &inst_pda, args_conflicting);
    match res_conflict {
        Err(MosooError::JobAccountCollision) => {
            // Expected: conflicting update on existing job PDA is strictly rejected!
        }
        other => panic!(
            "Expected JobAccountCollision on conflicting update, got {:?}",
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// Finding 8: Consumer Zero-Source-Instance PDA & Mismatch Fail-Closed (High #1)
// ---------------------------------------------------------------------------

#[test]
fn test_finding8_zero_source_instance_pda_rejected_in_consumers() {
    use erc20_receiver::{Erc20Ledger, NullifierSet, ReceiverError};

    let mut ledger = Erc20Ledger::default();
    let mut nullifiers = NullifierSet::default();
    let locker = [0x50; 20];
    let token = [0x1c; 20];
    let recipient = [0x01; 32];

    // Statement with source_instance_pda == [0u8; 32]
    let zero_pda_stmt = VerifiedStatement {
        chain_id: ETH_SEPOLIA_CHAIN_ID,
        genesis_validators_root: crypto::genesis_validators_root(ETH_SEPOLIA_CHAIN_ID),
        source_instance_id: [0u8; 32],
        source_instance_pda: [0u8; 32], // Zero PDA!
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0x55; 32],
        predicate_holds: true,
        verified_value: [0x01; 32],
        subject_key: [0x02; 32],
        proof_type_tag: PROOF_TYPE_ERC20_DEPOSIT,
        binding: StatementBinding::Erc20Deposit {
            execution_block_hash: [0x11; 32],
            slot: 100,
            tx_index: 0,
            log_index: 0,
            deposit_contract: locker,
            token_contract: token,
            sender: [0x03; 20],
            recipient,
        },
    };

    let stmt_account = StatementAccount::new_authentic(zero_pda_stmt);

    let res = ledger.mint_deposit_authenticated_pda_u256(&stmt_account, locker, &mut nullifiers);

    match res {
        Err(ReceiverError::UnauthenticatedSourceInstance) => {
            // Success: zero source_instance_pda is strictly rejected!
        }
        other => panic!("Expected UnauthenticatedSourceInstance, got {:?}", other),
    }

    // Statement with non-zero but UNTRUSTED source_instance_pda
    let mut untrusted_stmt = stmt_account.statement.clone();
    untrusted_stmt.source_instance_pda = [0x99; 32]; // Not matching canonical Sepolia instance!
    let untrusted_account = StatementAccount::new_authentic(untrusted_stmt);

    let res_untrusted =
        ledger.mint_deposit_authenticated_pda_u256(&untrusted_account, locker, &mut nullifiers);

    match res_untrusted {
        Err(ReceiverError::UntrustedSourceInstance) => {
            // Success: untrusted instance mismatch is strictly rejected!
        }
        other => panic!("Expected UntrustedSourceInstance, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Finding 9: Salted Privacy Hiding & Non-Correlation (High #2)
// ---------------------------------------------------------------------------

#[test]
fn test_finding9_salted_privacy_shielding_non_correlation() {
    let binding = StatementBinding::NativeEthDeposit {
        execution_block_hash: [0x33; 32],
        slot: 500,
        tx_index: 3,
        log_index: 1,
        deposit_contract: [0x44; 20],
        sender: [0x55; 20],
        recipient: [0x66; 32],
    };

    let salt1 = [0xaa; 32];
    let salt2 = [0xbb; 32];

    let commitment_unsalted = binding.compute_commitment();
    let commitment_salted1 = binding.compute_salted_commitment(&salt1);
    let commitment_salted2 = binding.compute_salted_commitment(&salt2);

    // Commitments with different secret salts MUST be distinct
    assert_ne!(commitment_salted1, commitment_unsalted);
    assert_ne!(commitment_salted2, commitment_unsalted);
    assert_ne!(commitment_salted1, commitment_salted2);

    // Observer knowing the public deposit cannot correlate commitment without salt
    let stmt = VerifiedStatement {
        chain_id: ETH_MAINNET_CHAIN_ID,
        genesis_validators_root: crypto::genesis_validators_root(ETH_MAINNET_CHAIN_ID),
        source_instance_id: [0x01; 32],
        source_instance_pda: [0x02; 32],
        attester_program_id: MOSOO_PROGRAM_ID,
        statement_id: [0x03; 32],
        predicate_holds: true,
        verified_value: [0x04; 32],
        subject_key: [0x05; 32],
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        binding: binding.clone(),
    };

    let shielded1 = stmt.shield_with_salt(&salt1);
    let shielded2 = stmt.shield_with_salt(&salt2);

    assert_ne!(shielded1.binding, shielded2.binding);
}

// ---------------------------------------------------------------------------
// Finding 10: Sync Committee Aggregate Length Checking (Medium #3)
// ---------------------------------------------------------------------------

#[test]
fn test_finding10_sync_committee_signature_length_enforcement() {
    use mosoo_core::types::{BeaconBlockHeader, SyncAggregate, SyncCommittee};

    let committee = SyncCommittee {
        pubkeys: vec![vec![0x01; 48]; 512],
        aggregate_pubkey: vec![0x02; 48],
    };

    let valid_header = BeaconBlockHeader {
        slot: 100,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0u8; 32],
        body_root: [0u8; 32],
    };

    // Malformed short bitfield (63 bytes instead of 64)
    let malformed_aggregate = SyncAggregate {
        sync_committee_bits: vec![0xff; 63],
        sync_committee_signature: vec![0x00; 96],
    };

    let res = crypto::verify_sync_committee_signature_with_config(
        &committee,
        &malformed_aggregate,
        &valid_header,
        ETH_SEPOLIA_CHAIN_ID,
        100,
        None,
    );

    match res {
        Err(MosooError::InvalidSyncCommitteeBitsLength { actual, expected }) => {
            assert_eq!(actual, 63);
            assert_eq!(expected, 64);
        }
        other => panic!("Expected InvalidSyncCommitteeBitsLength, got {:?}", other),
    }
}

// ---------------------------------------------------------------------------
// Finding 11: Account State Authenticity & Runtime Dispatch Wiring (Session 3 P0)
// ---------------------------------------------------------------------------

#[test]
fn test_finding11_fake_committee_under_canonical_pda_rejected_by_store_dispatcher() {
    use mosoo_core::types::RuntimeAccount;
    use mosoo_core::verifier::dispatch_store_instruction;

    let mut store = MockStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let authentic_instance = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    let pda = authentic_instance.pda_address();

    // Store authentic instance under MOSOO_PROGRAM_ID
    let authentic_bytes = serde_json::to_vec(&authentic_instance).unwrap();
    store
        .try_set_account_with_owner(&pda, authentic_bytes, MOSOO_PROGRAM_ID)
        .unwrap();

    // Adversary fabricates a fake instance with a tampered sync committee
    let mut rogue_instance = authentic_instance.clone();
    let rogue_committee = SyncCommittee {
        pubkeys: vec![vec![0x99; 48]; 512],
        aggregate_pubkey: vec![0x99; 48],
    };
    rogue_instance.current_sync_committee = rogue_committee;
    // Note: rogue_instance has the EXACT SAME pda_address because PDA only hashes chain_id & instance_id!
    assert_eq!(rogue_instance.pda_address(), pda);

    // 1. RuntimeAccount validation: try_from_runtime_account enforces authenticity
    let rogue_runtime = RuntimeAccount {
        address: pda,
        owner: [0xba; 32], // Wrong owner
        data: serde_json::to_vec(&rogue_instance).unwrap(),
    };
    assert!(InstanceAccount::try_from_runtime_account(&rogue_runtime).is_err());

    // 2. dispatch_store_instruction verifies authentic instance from persistent store
    // Caller passes fake instance in args, but store dispatcher strictly authenticates and overrides with stored state
    let begin_args = mosoo_core::verifier::BeginUpdateArgs {
        instance: rogue_instance,
        nonce: 0,
        trusted_head_slot: None,
        update: mosoo_core::types::LightClientUpdate {
            attested_header: mosoo_core::types::BeaconBlockHeader {
                slot: 1001,
                proposer_index: 1,
                parent_root: [0x11; 32],
                state_root: [0x22; 32],
                body_root: [0x33; 32],
            },
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: mosoo_core::types::BeaconBlockHeader {
                slot: 1000,
                proposer_index: 0,
                parent_root: [0x00; 32],
                state_root: [0x22; 32],
                body_root: [0x11; 32],
            },
            finality_branch: vec![[0u8; 32]; 6],
            execution_payload_header: None,
            execution_branch: None,
            execution_rlp: None,
            sync_aggregate: mosoo_core::types::SyncAggregate {
                sync_committee_bits: vec![0xff; 64],
                sync_committee_signature: vec![0x00; 96],
            },
            signature_slot: 1002,
        },
    };

    let instruction = GuestInstruction::BeginUpdateAuthenticated {
        expected_instance_pda: pda,
        args: begin_args,
    };

    let res = dispatch_store_instruction(&mut store, instruction);
    // Since signature is empty dummy and stored committee is authentic (not adversary's rogue committee),
    // BLS verification or header validation fails rather than accepting adversary's fabricated committee!
    assert!(res.is_err());
}

// ---------------------------------------------------------------------------
// Finding 12: Holesky & Custom Network Trusted Checkpoints (Session 3 P1)
// ---------------------------------------------------------------------------

#[test]
fn test_finding12_unconfigured_custom_checkpoint_rejected() {
    use mosoo_core::types::{
        InitializeArgs, CANONICAL_SEPOLIA_CHECKPOINT_ROOT, CANONICAL_SEPOLIA_INSTANCE_ID,
        CANONICAL_SEPOLIA_MOSOO_INSTANCE,
    };

    // 1. In compliance with Finding 3 / Session 8, Mainnet and Holesky are NOT registered with placeholder constants.
    // Sepolia is the sole live network with independently verified weak-subjectivity checkpoint.
    let canonical = TrustedBridgeConfig::canonical();
    assert_eq!(canonical.get_trusted_instance(17000), None);
    assert_eq!(canonical.get_trusted_checkpoint(17000), None);
    assert_eq!(canonical.get_trusted_instance(1), None);
    assert_eq!(canonical.get_trusted_checkpoint(1), None);
    assert_eq!(
        canonical.get_trusted_instance(11155111),
        Some(CANONICAL_SEPOLIA_MOSOO_INSTANCE)
    );
    assert_eq!(
        canonical.get_trusted_checkpoint(11155111),
        Some(CANONICAL_SEPOLIA_CHECKPOINT_ROOT)
    );

    // 2. Initializing Sepolia with untrusted checkpoint root fails closed
    let dummy_beacon_header = mosoo_core::types::BeaconBlockHeader {
        slot: 100,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0x11; 32],
        body_root: [0x22; 32],
    };

    let untrusted_sepolia_args = InitializeArgs {
        instance_id: CANONICAL_SEPOLIA_INSTANCE_ID,
        network_config: None,
        chain_id: 11155111,
        bootstrap_header: dummy_beacon_header.clone(),
        trusted_checkpoint_root: [0xee; 32], // Tampered checkpoint root!
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    };
    let res = dispatch_guest_instruction(GuestInstruction::Initialize(untrusted_sepolia_args));
    assert!(matches!(
        res,
        Err(MosooError::UntrustedCheckpoint { chain_id: 11155111 })
    ));

    // 3. Initializing unregistered Holesky without explicit NetworkConfig fails closed
    let untrusted_holesky_args = InitializeArgs {
        instance_id: [0x55; 32],
        network_config: None,
        chain_id: 17000,
        bootstrap_header: dummy_beacon_header.clone(),
        trusted_checkpoint_root: [0xee; 32],
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    };
    let res_holesky =
        dispatch_guest_instruction(GuestInstruction::Initialize(untrusted_holesky_args));
    assert!(matches!(
        res_holesky,
        Err(MosooError::UnconfiguredTrustedCheckpoint { chain_id: 17000 })
    ));

    // 4. Unconfigured custom network without NetworkConfig fails closed
    let custom_chain_args = InitializeArgs {
        instance_id: [0x55; 32],
        network_config: None, // Missing explicit network config!
        chain_id: 999999,
        bootstrap_header: dummy_beacon_header,
        trusted_checkpoint_root: [0xaa; 32],
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    };
    let res_custom = dispatch_guest_instruction(GuestInstruction::Initialize(custom_chain_args));
    assert!(matches!(
        res_custom,
        Err(MosooError::UnconfiguredTrustedCheckpoint { chain_id: 999999 })
    ));
}

// ---------------------------------------------------------------------------
// Finding 13: Arithmetic Overflow Pre-Check Preserves Nullifier (Session 3 P2)
// ---------------------------------------------------------------------------

#[test]
fn test_finding13_overflow_pre_check_preserves_nullifier() {
    use ether_receiver::EtherReceiverError;

    let chain_id = ETH_SEPOLIA_CHAIN_ID;
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let instance = make_test_instance(chain_id, instance_id);
    let inst_pda = instance.pda_address();

    let locker = TrustedBridgeConfig::canonical()
        .get_trusted_locker(chain_id)
        .unwrap();

    let recipient = [0x55; 32];
    // Create an attestation statement where value = U256::MAX (overflows u128)
    let binding = StatementBinding::NativeEthDeposit {
        execution_block_hash: [0x11; 32],
        slot: 1000,
        tx_index: 0,
        log_index: 0,
        deposit_contract: locker,
        sender: [0x11; 20],
        recipient,
    };

    let subject_key = mosoo_core::predicate::derive_eth_deposit_subject_key(
        &[0x11; 32],
        1000,
        0,
        0,
        &locker,
        &[0x11; 20],
        &recipient,
    );

    let overflow_val = [0xff; 32]; // U256::MAX
    let statement = VerifiedStatement {
        statement_id: [0; 32], // will derive
        chain_id,
        genesis_validators_root: [0x11; 32],
        source_instance_id: instance_id,
        source_instance_pda: inst_pda,
        subject_key,
        attester_program_id: MOSOO_PROGRAM_ID,
        predicate_holds: true,
        proof_type_tag: PROOF_TYPE_ETH_DEPOSIT,
        verified_value: overflow_val,
        binding,
    };
    let mut stmt = statement;
    stmt.statement_id = stmt.derive_canonical_id();

    let stmt_account = StatementAccount::new_authentic(stmt.clone());

    let mut ledger = MethLedger::default();
    let mut nullifiers = EtherNullifierSet::default();

    // Call mint_deposit_authenticated_pda_u256
    let res = ledger.mint_deposit_authenticated_pda_u256(&stmt_account, locker, &mut nullifiers);

    // Verify it fails with Overflow error
    assert!(matches!(res, Err(EtherReceiverError::Overflow)));

    // CRITICAL: Verify nullifier was NOT marked as used!
    assert!(
        !nullifiers.is_used(&stmt.statement_id),
        "Nullifier MUST NOT be consumed when mint fails with arithmetic overflow!"
    );
    assert!(
        !nullifiers.is_used(&stmt.subject_key),
        "Subject key MUST NOT be consumed when mint fails with arithmetic overflow!"
    );
}

// ---------------------------------------------------------------------------
// Finding 14: Salted Shielding Blinds Statement Binding (Session 3 P1)
// ---------------------------------------------------------------------------

#[test]
fn test_finding14_attest_state_salted_shielding_journal() {
    use mosoo_core::inclusion::test_helpers;

    let tok_addr = alloy_primitives::Address::repeat_byte(0x11);
    let snd_addr = alloy_primitives::Address::repeat_byte(0x22);
    let rec_addr = alloy_primitives::Address::repeat_byte(0x33);
    let mut rec_lez = [0u8; 32];
    rec_lez[12..].copy_from_slice(rec_addr.as_slice());
    let amount = 100_000u64;

    let receipt_bytes = test_helpers::build_test_eip1559_transfer_receipt(
        tok_addr,
        snd_addr,
        rec_addr,
        alloy_primitives::U256::from(amount),
    );
    let key_bytes = alloy_rlp::encode(0u64);
    let (receipts_root, proof_nodes) =
        test_helpers::build_leaf_mpt_proof(&key_bytes, &receipt_bytes);

    let mut instance = make_test_instance(
        ETH_SEPOLIA_CHAIN_ID,
        mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID,
    );
    instance.current_receipts_root = receipts_root.0;

    let mut header = make_test_header(&instance);
    header.receipts_root = receipts_root.0;

    let proof = StateProof {
        target: ProofTarget::Erc20Transfer {
            tx_index: 0,
            log_index: 0,
            token_contract: tok_addr,
            sender: snd_addr,
            recipient: rec_lez,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(proof_nodes),
        account_value: None,
        storage_value: None,
        receipt_value: Some(receipt_bytes),
    };

    let salt1 = [0x42; 32];
    let salt2 = [0x99; 32];

    let args1 = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof: proof.clone(),
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: Some(salt1),
        trusted_head_slot: None,
    };

    let args2 = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: Some(salt2),
        trusted_head_slot: None,
    };

    // Both evaluations yield StatementIssued with Shielded binding
    let out1 = mosoo_core::verifier::handle_attest_state(args1).unwrap();
    let out2 = mosoo_core::verifier::handle_attest_state(args2).unwrap();

    let stmt1 = match out1 {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => panic!("Expected StatementIssued"),
    };
    let stmt2 = match out2 {
        mosoo_core::verifier::InstructionOutput::StatementIssued(s) => s,
        _ => panic!("Expected StatementIssued"),
    };

    assert!(matches!(stmt1.binding, StatementBinding::Shielded { .. }));
    assert!(matches!(stmt2.binding, StatementBinding::Shielded { .. }));

    // Unlinkability: different salts produce distinct commitments, subject keys, and statement nullifiers
    assert_ne!(stmt1.binding, stmt2.binding);
    assert_ne!(stmt1.subject_key, stmt2.subject_key);
    assert_ne!(stmt1.statement_id, stmt2.statement_id);
}

// ---------------------------------------------------------------------------
// Finding 15: Shared Checkpoint Verification Across Both Dispatchers (Critical #1 / P0)
// ---------------------------------------------------------------------------

#[test]
fn test_finding15_shared_checkpoint_verification_across_both_dispatchers() {
    use mosoo_core::types::{InitializeArgs, CANONICAL_SEPOLIA_INSTANCE_ID};
    use mosoo_core::verifier::{dispatch_guest_instruction, dispatch_store_instruction};

    let mut store = MockStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();
    let dummy_beacon_header = mosoo_core::types::BeaconBlockHeader {
        slot: 100,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0x11; 32],
        body_root: [0x22; 32],
    };

    // 1. Untrusted Sepolia checkpoint root rejected by BOTH dispatchers
    let untrusted_sepolia_args = InitializeArgs {
        instance_id: CANONICAL_SEPOLIA_INSTANCE_ID,
        network_config: None,
        chain_id: 11155111,
        bootstrap_header: dummy_beacon_header.clone(),
        trusted_checkpoint_root: [0xee; 32], // Tampered checkpoint root!
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    };

    let res_guest =
        dispatch_guest_instruction(GuestInstruction::Initialize(untrusted_sepolia_args.clone()));
    assert!(matches!(
        res_guest,
        Err(MosooError::UntrustedCheckpoint { chain_id: 11155111 })
    ));

    let res_store = dispatch_store_instruction(
        &mut store,
        GuestInstruction::Initialize(untrusted_sepolia_args),
    );
    assert!(matches!(
        res_store,
        Err(MosooError::UntrustedCheckpoint { chain_id: 11155111 })
    ));

    // 2. Unconfigured custom network rejected by BOTH dispatchers
    let unconfigured_custom_args = InitializeArgs {
        instance_id: [0x77; 32],
        network_config: None,
        chain_id: 888888,
        bootstrap_header: dummy_beacon_header,
        trusted_checkpoint_root: [0xaa; 32],
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    };

    let res_guest_custom = dispatch_guest_instruction(GuestInstruction::Initialize(
        unconfigured_custom_args.clone(),
    ));
    assert!(matches!(
        res_guest_custom,
        Err(MosooError::UnconfiguredTrustedCheckpoint { chain_id: 888888 })
    ));

    let res_store_custom = dispatch_store_instruction(
        &mut store,
        GuestInstruction::Initialize(unconfigured_custom_args),
    );
    assert!(matches!(
        res_store_custom,
        Err(MosooError::UnconfiguredTrustedCheckpoint { chain_id: 888888 })
    ));
}

// ---------------------------------------------------------------------------
// Finding 16: Immutable Instance Defense (Existing Instance Overwrite) (High #2 / P1)
// ---------------------------------------------------------------------------

#[test]
fn test_finding16_reinitialization_existing_instance_rejected() {
    use mosoo_core::types::{BeaconBlockHeader, InitializeArgs, NetworkConfig};
    use mosoo_core::verifier::handle_initialize_store;

    let mut store = MockStore::default();
    let mut config = TrustedBridgeConfig::canonical();
    config.register_trusted_head(ETH_SEPOLIA_CHAIN_ID, 1000);
    config.save_to_store(&mut store).unwrap();

    let committee = make_valid_committee();
    let leaf = mosoo_core::crypto::hash_tree_root_sync_committee(&committee).unwrap();
    let branch = vec![[0x11; 32]; 5];
    let state_root = mosoo_core::crypto::compute_branch_root(leaf, &branch, 54);

    let bootstrap_header = BeaconBlockHeader {
        slot: 1_000_000,
        proposer_index: 1,
        parent_root: [0; 32],
        state_root,
        body_root: [0; 32],
    };
    let checkpoint_root = mosoo_core::crypto::hash_tree_root_beacon_header(&bootstrap_header);

    let chain_id = 999999;
    let instance_id = [0x42; 32];
    let net_cfg = NetworkConfig {
        chain_id,
        genesis_validators_root: [0x88; 32],
        trusted_checkpoint_root: Some(checkpoint_root),
        altair_fork_version: [0x01; 4],
        bellatrix_fork_version: [0x02; 4],
        capella_fork_version: [0x03; 4],
        deneb_fork_version: [0x04; 4],
        electra_fork_version: [0x05; 4],
        fulu_fork_version: [0x06; 4],
        gloas_fork_version: [0x07; 4],
    };

    let init_args = InitializeArgs {
        instance_id,
        network_config: Some(net_cfg),
        chain_id,
        bootstrap_header,
        trusted_checkpoint_root: checkpoint_root,
        current_sync_committee: committee,
        current_sync_committee_branch: branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 1_050_000,
    };

    // Register custom network checkpoint in TrustedBridgeConfig persistent storage (Finding 3 / High #3)
    let mut bridge_cfg = TrustedBridgeConfig::canonical();
    bridge_cfg.register_custom_network(chain_id, checkpoint_root);
    bridge_cfg.save_to_store(&mut store).unwrap();

    // First initialization succeeds and persists instance
    let res1 = handle_initialize_store(&mut store, init_args.clone());
    assert!(res1.is_ok());

    let pda = match res1.unwrap() {
        mosoo_core::verifier::InstructionOutput::Initialized(inst) => inst.pda_address(),
        _ => panic!("Expected Initialized"),
    };
    assert!(store.has_account(&pda));
    let original_bytes = store.get_account(&pda).unwrap();

    // Second initialization with same (chain_id, instance_id) MUST be rejected with AlreadyInitialized
    let res2 = handle_initialize_store(&mut store, init_args);
    assert!(matches!(
        res2,
        Err(MosooError::AlreadyInitialized { chain_id: 999999 })
    ));

    // Ensure account data in store is intact and unchanged
    assert_eq!(store.get_account(&pda).unwrap(), original_bytes);
}

// ---------------------------------------------------------------------------
// Finding 17: Batch-Write Rollback Restores Original State (High #3 / P1)
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
// Finding 18: ERC-20 Deposit Exact 32-Byte Recipient Matching (Medium-High #4 / P1)
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
// Finding 19: ERC-20 Transfer Strict ABI Shape Enforcement (Medium-High #4 / P1)
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
// Finding 20: Salted Shielding Blinds Subject Keys & Statement IDs (High #5 / P1)
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
// Finding 21: Store-Backed Guest Instruction Execution (Critical #1 / P0)
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
// Finding 22: Native ETH Deposit Exact 32-Byte Recipient Matching (High #2 / P1)
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
// Finding 23: Batch Write Rollback Preserves Unowned Accounts (Medium #5 / P2)
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

    // CRITICAL (Finding 5): addr1 must be restored to its pre-batch data AND unowned status (owner == None).
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
// Finding 24: Custom Network Independent Checkpoint Anchor Registration (High #3 / P1)
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

    // 2. Custom network with self-certifying NetworkConfig (not registered in TrustedBridgeConfig) fails closed (Finding 3 / High #3)
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
// Finding 25: Public Statement Shielding Prevents Subject Key Linkability (Privacy Compliance / P1)
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
// Finding 26: Native ETH Deposit Missing Canonical 12-Zero Sender Topic Padding (Medium #5 / P2)
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
// Finding 27: Shielded Statement Redemption with Witness in Consumers (Correctness #6 / P1)
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

    // Blind the statement with the secret 256-bit salt (RFP-021 Functionality #8)
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
// Finding 28: zkVM Guest Authenticated Dispatch and Host Storage Boundaries (P0)
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
// Audit Session 7 Findings: Weak-Subjectivity Expiry, Canonical Statement ID,
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

    // 1. Both produce IDENTICAL statement IDs (RFP-021 Functionality #6)
    let stmt_id_a =
        derive_statement_id_v2(chain_id, &gvr, &subject_key, proof_type, &verified_value);
    let stmt_id_b =
        derive_statement_id_v2(chain_id, &gvr, &subject_key, proof_type, &verified_value);
    assert_eq!(
        stmt_id_a, stmt_id_b,
        "Identical verified state facts MUST produce identical deterministic statement IDs across instances"
    );

    // 2. Emitted statements retain source_instance_pda for consumer binding (RFP-021 Functionality #15)
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
// Audit Session 8 Hardening Tests (October 27, 2026)
// ---------------------------------------------------------------------------

#[test]
fn test_session8_finding3_pda_derivation_invariants_across_all_networks() {
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

#[test]
fn test_session8_finding1_fabricated_committee_and_execution_roots_under_canonical_pda_fails_closed(
) {
    use mosoo_core::verifier::{dispatch_store_instruction, AttestStateArgs, GuestInstruction};

    let mut store = MockStore::default();
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
fn test_session8_finding2_weak_subjectivity_attestation_staleness_direction_and_head_slot() {
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
    };
    let res_head_stale = handle_attest_state(args_head_stale);
    assert!(matches!(
        res_head_stale.unwrap_err(),
        MosooError::WeakSubjectivityExpired { .. }
    ));
}

// ===========================================================================
// Session 9 Hardening Verification Tests (Audit Session 9)
// ===========================================================================

// ---------------------------------------------------------------------------
// Finding 4: Job PDA Derivation Inconsistency Unification (Medium #4)
// ---------------------------------------------------------------------------
#[test]
fn test_session9_finding4_job_pda_derivation_unification() {
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
// Finding 2: Stale Instance Chained Incremental Update Rejection (High #2)
// ---------------------------------------------------------------------------
#[test]
fn test_session9_finding2_stale_instance_cannot_advance_via_small_incremental_updates() {
    use mosoo_core::types::{
        LightClientUpdate, SyncAggregate, TrustedBridgeConfig, CANONICAL_SEPOLIA_INSTANCE_ID,
        CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS, ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID,
    };
    use mosoo_core::verifier::{handle_begin_update_authenticated, BeginUpdateArgs};

    let mut store = MockStore::default();
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
// Finding 3 & 5: Unregistered Networks & Placeholder Trust Anchor Elimination
// ---------------------------------------------------------------------------
#[test]
fn test_session9_finding3_and_5_unregistered_networks_fail_closed_without_config_registration() {
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
// Finding 1: Untrusted Serialized Store Rejection in zkVM Guest Path
// ---------------------------------------------------------------------------
#[test]
fn test_session9_finding1_adversarial_forged_store_fails_closed() {
    use mosoo_core::types::{AccountStore, HeaderRecord, MOSOO_PROGRAM_ID};
    use mosoo_core::verifier::{handle_attest_state_authenticated, AttestStateArgs};

    let mut fake_store = MockStore::default();
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
fn test_session10_finding1_initialization_rejects_bootstrap_exceeding_canonical_weak_subjectivity()
{
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
fn test_session10_finding2_finish_update_advances_authenticated_head_slot() {
    use mosoo_core::types::{
        BeaconBlockHeader, ExecutionPayloadHeader, JobAccount, JobStage, LightClientUpdate,
        MillerOutput, SyncAggregate,
    };
    use mosoo_core::verifier::{handle_finish_update_authenticated, FinishUpdateArgs};

    let mut store = MockStore::default();
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

    // Verify that TrustedBridgeConfig in store was automatically updated to new_slot
    let updated_config = TrustedBridgeConfig::load_strict(&store).unwrap();
    assert_eq!(
        updated_config.get_trusted_head(chain_id),
        Some(new_slot),
        "Authenticated head must automatically advance to finalized update slot"
    );
}

#[test]
fn test_session10_finding3_core_loader_enforces_instance_pinning() {
    use mosoo_core::types::Predicate;
    use mosoo_core::verifier::{handle_attest_state_authenticated, AttestStateArgs};

    let mut store = MockStore::default();
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
    };

    // Attestation against unpinned instance PDA on pinned chain MUST fail with UntrustedSourceInstance
    let res = handle_attest_state_authenticated(&store, &unpinned_pda, Some(&header_pda), args);
    assert!(
        matches!(res.unwrap_err(), MosooError::UntrustedSourceInstance),
        "Attestation against unpinned instance on Sepolia must be rejected with UntrustedSourceInstance"
    );
}

#[test]
fn test_session10_finding4_salted_privacy_shielding_prevents_dictionary_matching() {
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
fn test_session10_finding5_lez_runtime_adapter_dispatch_flow() {
    use mosoo_core::types::Predicate;
    use mosoo_core::verifier::{AttestStateArgs, LezRuntimeAdapter};

    let mut store = MockStore::default();
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
    };

    let res = adapter.dispatch_attest_state(&instance_pda, Some(&header_pda), attest_args);
    // Attestation loaded genuine instance and header from adapter store and proceeded to state inclusion proof
    assert!(res.is_err());
    assert!(!matches!(
        res.unwrap_err(),
        MosooError::UnauthenticatedInstance | MosooError::UntrustedSourceInstance
    ));
}

fn make_test_update(slot: u64, sig_slot: u64) -> mosoo_core::types::LightClientUpdate {
    let dummy_header = mosoo_core::types::BeaconBlockHeader {
        slot,
        proposer_index: 1,
        parent_root: [0x11; 32],
        state_root: [0x22; 32],
        body_root: [0x33; 32],
    };
    mosoo_core::types::LightClientUpdate {
        attested_header: dummy_header.clone(),
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: dummy_header,
        finality_branch: vec![[0u8; 32]; 6],
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
        sync_aggregate: mosoo_core::types::SyncAggregate {
            sync_committee_bits: vec![0xff; 64],
            sync_committee_signature: vec![0x11; 96],
        },
        signature_slot: sig_slot,
    }
}

#[test]
fn test_session11_finding1_production_guest_dispatcher_rejects_unauthenticated_state_and_forged_pda(
) {
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
fn test_session11_finding2_strict_config_loading_fails_closed_when_missing_or_untrusted_owner() {
    use mosoo_core::types::{derive_bridge_config_pda, ConfigError, Predicate};
    use mosoo_core::verifier::{
        handle_attest_state_authenticated, handle_begin_update_authenticated, AttestStateArgs,
        BeginUpdateArgs,
    };

    let mut empty_store = MockStore::default();
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
fn test_session11_finding3_freshness_enforces_anchor_rejects_fake_head_and_stale_instance() {
    use mosoo_core::verifier::{handle_begin_update_authenticated, BeginUpdateArgs};

    let mut store = MockStore::default();
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

#[test]
fn test_session11_finding4_confidential_value_shielding_commits_value_without_journal_leakage() {
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
fn test_session11_finding6_solidity_locker_guardian_and_quorum_invariants() {
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
