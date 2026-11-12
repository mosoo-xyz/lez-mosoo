//! Adversarial & Mutation Test Suite for Mosoo (Logos RFP-021)
//!
//! This suite explicitly verifies strict rejection of adversarial inputs,
//! mutated headers, forged Merkle branches, insufficient quorums,
//! cross-chain replays, and duplicate claim attacks.

#![allow(deprecated)]

use blst::min_pk::SecretKey;
use erc20_receiver::{
    claim, claim_authenticated_store_u256, claim_erc20_transfer, AtomicErc20ClaimArgsU256,
    Erc20TransferClaim, NullifierSet, ReceiverError,
};

use ether_receiver::{
    claim_ether, claim_native_eth_deposit,
    claim_native_eth_deposit_authenticated_store_with_config, AtomicEtherClaimArgs,
    EtherNullifierSet, EtherReceiverError, MethLedger, NativeEthDepositClaim,
};

use mosoo_core::{
    crypto::*,
    error::MosooError,
    inclusion::{ProofTarget, StateProof},
    predicate::{derive_erc20_transfer_subject_key, derive_eth_deposit_subject_key},
    types::*,
    verifier::*,
};

use sha2::Digest;

use std::collections::HashMap;

fn make_test_committee(count: usize) -> SyncCommittee {
    let pubkeys: Vec<Vec<u8>> = (0..count)
        .map(|i| {
            let mut pk = vec![0u8; 48];
            pk[0] = 0x80;
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

fn make_valid_bls_committee(count: usize) -> SyncCommittee {
    make_valid_bls_committee_with_seed(count, 42)
}

fn make_valid_bls_committee_with_seed(count: usize, seed: u8) -> SyncCommittee {
    let ikm = [seed; 32];
    let sk = SecretKey::key_gen(&ikm, &[]).unwrap();
    let pk = sk.sk_to_pk().to_bytes().to_vec();
    SyncCommittee {
        pubkeys: vec![pk.clone(); count],
        aggregate_pubkey: pk,
    }
}

mod consensus_and_branches;
mod instance_and_config;
mod pipeline_and_storage;
mod state_and_replay;
