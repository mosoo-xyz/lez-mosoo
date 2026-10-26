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
        SyncCommittee, TrustedBridgeConfig, VerifiedStatement, ETH_MAINNET_CHAIN_ID,
        ETH_SEPOLIA_CHAIN_ID, MOSOO_PROGRAM_ID, PROOF_TYPE_ERC20_DEPOSIT, PROOF_TYPE_ETH_DEPOSIT,
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
    let stmt_id_a = derive_statement_id_v2(
        chain_id,
        &gvr,
        &instance_pda_a,
        &subject_key,
        proof_type,
        &verified_value,
    );
    let stmt_id_b = derive_statement_id_v2(
        chain_id,
        &gvr,
        &instance_pda_b,
        &subject_key,
        proof_type,
        &verified_value,
    );

    // Assert multi-instance separation: Identical state facts produce distinct statement IDs!
    assert_ne!(
        stmt_id_a, stmt_id_b,
        "different instances MUST produce distinct statement IDs"
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
    let instance_id = mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID;
    let inst = make_test_instance(ETH_SEPOLIA_CHAIN_ID, instance_id);
    let inst_pda = inst.pda_address();

    // Register authentic instance in store
    store.set_account_with_owner(
        &inst_pda,
        serde_json::to_vec(&inst).unwrap(),
        MOSOO_PROGRAM_ID,
    );

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
        InitializeArgs, CANONICAL_HOLESKY_CHECKPOINT_ROOT, CANONICAL_HOLESKY_INSTANCE_ID,
        CANONICAL_HOLESKY_MOSOO_INSTANCE,
    };

    // 1. Holesky canonical registration verification
    let canonical = TrustedBridgeConfig::canonical();
    assert_eq!(
        canonical.get_trusted_instance(17000),
        Some(CANONICAL_HOLESKY_MOSOO_INSTANCE)
    );
    assert_eq!(
        canonical.get_trusted_checkpoint(17000),
        Some(CANONICAL_HOLESKY_CHECKPOINT_ROOT)
    );

    // 2. Initializing Holesky with untrusted checkpoint root fails closed
    let dummy_beacon_header = mosoo_core::types::BeaconBlockHeader {
        slot: 100,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0x11; 32],
        body_root: [0x22; 32],
    };

    let untrusted_holesky_args = InitializeArgs {
        instance_id: CANONICAL_HOLESKY_INSTANCE_ID,
        network_config: None,
        chain_id: 17000,
        bootstrap_header: dummy_beacon_header.clone(),
        trusted_checkpoint_root: [0xee; 32], // Tampered checkpoint root!
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    };
    let res = dispatch_guest_instruction(GuestInstruction::Initialize(untrusted_holesky_args));
    assert!(matches!(
        res,
        Err(MosooError::UntrustedCheckpoint { chain_id: 17000 })
    ));

    // 3. Unconfigured custom network without NetworkConfig fails closed
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
    };

    let args2 = AttestStateArgs {
        instance: instance.clone(),
        header: header.clone(),
        header_history_branch: None,
        historical_execution_proof: None,
        proof,
        predicate: Predicate::AtLeast { min: [0; 32] },
        privacy_salt: Some(salt2),
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
    use mosoo_core::types::{InitializeArgs, CANONICAL_HOLESKY_INSTANCE_ID};
    use mosoo_core::verifier::{dispatch_guest_instruction, dispatch_store_instruction};

    let mut store = MockStore::default();
    let dummy_beacon_header = mosoo_core::types::BeaconBlockHeader {
        slot: 100,
        proposer_index: 0,
        parent_root: [0u8; 32],
        state_root: [0x11; 32],
        body_root: [0x22; 32],
    };

    // 1. Untrusted Holesky checkpoint root rejected by BOTH dispatchers
    let untrusted_holesky_args = InitializeArgs {
        instance_id: CANONICAL_HOLESKY_INSTANCE_ID,
        network_config: None,
        chain_id: 17000,
        bootstrap_header: dummy_beacon_header.clone(),
        trusted_checkpoint_root: [0xee; 32], // Tampered checkpoint root!
        current_sync_committee: make_valid_committee(),
        current_sync_committee_branch: vec![[0u8; 32]; 5],
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot: 10_000_000,
    };

    let res_guest =
        dispatch_guest_instruction(GuestInstruction::Initialize(untrusted_holesky_args.clone()));
    assert!(matches!(
        res_guest,
        Err(MosooError::UntrustedCheckpoint { chain_id: 17000 })
    ));

    let res_store = dispatch_store_instruction(
        &mut store,
        GuestInstruction::Initialize(untrusted_holesky_args),
    );
    assert!(matches!(
        res_store,
        Err(MosooError::UntrustedCheckpoint { chain_id: 17000 })
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
