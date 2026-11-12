//! Security regression tests covering authenticated guest dispatch, persistent
//! store checks, instance/statement binding, shielded commitments, and replay protection.
#![allow(deprecated)]

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
struct TestAccountStore {
    accounts: HashMap<[u8; 32], Vec<u8>>,
    owners: HashMap<[u8; 32], [u8; 32]>,
}

impl AccountStore for TestAccountStore {
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

mod deposit_and_forks;
mod freshness_and_adapter;
mod guest_and_store;
mod privacy_and_instance;
