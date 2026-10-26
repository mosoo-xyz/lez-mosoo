//! Security regression test suite verifying resolution of all 6 findings
//! from the MOSOO Security Audit (Oct 26, 2026).
//!
//! Findings covered:
//! - Finding 1 (Critical P0): zkVM guest authenticated instructions & account authenticity
//! - Finding 2 (High P1): Consumer persistent store-backed minting APIs & rejection of caller state
//! - Finding 3 (High P1): Statement source-instance PDA binding & cross-instance isolation
//! - Finding 4 (High P1): Privacy-preserving shielded statement binding (RFP-021 Functionality #8)
//! - Finding 5 (Medium P2): Solidity legacy withdrawal disablement (verified in Foundry)
//! - Finding 6 (Low/Med P2/P3): Canonical Statement ID specification & predicate invariance

#![allow(deprecated)]

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

/// Helper to build an authentic dummy InstanceAccount
fn make_test_instance(chain_id: u64, instance_id: [u8; 32]) -> InstanceAccount {
    InstanceAccount {
        instance_id,
        chain_id,
        current_header_hash: [0x11; 32],
        current_state_root: [0x22; 32],
        current_slot: 1000,
        current_sync_committee: SyncCommittee {
            pubkeys: vec![vec![0x01; 48]; 512],
            aggregate_pubkey: vec![0x02; 48],
        },
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
    let instance_id = [0x42; 32];
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
