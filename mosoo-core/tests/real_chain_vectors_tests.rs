//! Integration tests running Mosoo's real cryptographic verification pipeline
//! against committed real-chain Beacon & Execution proof vectors in `vectors/`:
//! - Ethereum Mainnet (chain_id = 1, Fulu fork, slot 15,632,288 -> 15,632,352, EL block 26,392,691)
//! - Ethereum Sepolia (chain_id = 11155111, Gloas ePBS fork, slot 11,556,544, EL blocks 12,082,214 / 12,112,710 / 12,112,801)
//! - Ethereum Hoodi (chain_id = 560048, Fulu cross-period transition 530 -> 531, slot 4,349,856 -> 4,349,920)

use alloy_primitives::{Address, B256, U256};
use mosoo_core::crypto;
use mosoo_core::error::MosooError;
use mosoo_core::inclusion::{
    self, execution_header_roots, verify_state_proof, ProofTarget, StateProof, VerifiedValue,
};
use mosoo_core::types::{
    compute_sync_committee_period, derive_instance_pda, is_supported_chain_id, BeaconBlockHeader,
    ExecutionPayloadHeader, HeaderRecord, InitializeArgs, InstanceAccount, LightClientUpdate,
    NetworkConfig, Predicate, SyncAggregate, SyncCommittee,
};
use mosoo_core::verifier::{
    handle_attest_state, handle_begin_update, handle_finish_update, handle_initialize,
    handle_miller_update, verify_execution_payload_branch, verify_execution_roots_binding,
    verify_finality_branch, verify_sync_committee_branch, verify_weak_subjectivity_checkpoint,
    AttestStateArgs, BeginUpdateArgs, FinishUpdateArgs, InstructionOutput, MillerUpdateArgs,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn read_vector(rel: &str) -> String {
    let path = repo_root().join("vectors").join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {}: {e}", path.display()))
}

fn decode_hex_vec(s: &str) -> Vec<u8> {
    let clean = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(clean).unwrap_or_else(|e| panic!("invalid hex '{s}': {e}"))
}

fn decode_hex32(s: &str) -> [u8; 32] {
    let bytes = decode_hex_vec(s);
    bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected 32 bytes for '{s}', got {}", v.len()))
}

fn decode_hex20(s: &str) -> [u8; 20] {
    let bytes = decode_hex_vec(s);
    bytes
        .try_into()
        .unwrap_or_else(|v: Vec<u8>| panic!("expected 20 bytes for '{s}', got {}", v.len()))
}

fn parse_u64_str(s: &str) -> u64 {
    s.parse::<u64>()
        .unwrap_or_else(|e| panic!("invalid u64 '{s}': {e}"))
}

fn parse_u256_le32(s: &str) -> [u8; 32] {
    let v = if let Some(hex_str) = s.strip_prefix("0x") {
        let bytes = hex::decode(hex_str).expect("valid hex base_fee_per_gas");
        U256::from_be_slice(&bytes)
    } else {
        U256::from_str_radix(s, 10).expect("valid decimal base_fee_per_gas")
    };
    v.to_le_bytes::<32>()
}

#[derive(Deserialize)]
struct ManifestJson {
    networks: BTreeMap<String, ManifestNetwork>,
}

#[derive(Deserialize)]
struct ManifestNetwork {
    hashes: BTreeMap<String, String>,
}

#[derive(Deserialize)]
struct RawBootstrapWrapper {
    block_root: String,
    bootstrap: RawBootstrapEnvelope,
}

#[derive(Deserialize)]
struct RawBootstrapEnvelope {
    data: RawBootstrapData,
}

#[derive(Deserialize)]
struct RawBootstrapData {
    header: RawHeaderWrapper,
    current_sync_committee: RawSyncCommittee,
    current_sync_committee_branch: Vec<String>,
}

#[derive(Deserialize)]
struct RawUpdateEnvelope {
    data: RawUpdateData,
}

#[derive(Deserialize)]
struct RawUpdateData {
    attested_header: RawHeaderWrapper,
    finalized_header: RawHeaderWrapper,
    finality_branch: Vec<String>,
    sync_aggregate: RawSyncAggregate,
    signature_slot: String,
    #[serde(default)]
    next_sync_committee: Option<RawSyncCommittee>,
    #[serde(default)]
    next_sync_committee_branch: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawHeaderWrapper {
    beacon: RawBeaconHeader,
    #[serde(default)]
    execution: Option<RawExecutionHeader>,
    #[serde(default)]
    execution_block_hash: Option<String>,
    #[serde(default)]
    execution_branch: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct RawBeaconHeader {
    slot: String,
    proposer_index: String,
    parent_root: String,
    state_root: String,
    body_root: String,
}

#[derive(Deserialize)]
struct RawExecutionHeader {
    parent_hash: String,
    fee_recipient: String,
    state_root: String,
    receipts_root: String,
    logs_bloom: String,
    prev_randao: String,
    block_number: String,
    gas_limit: String,
    gas_used: String,
    timestamp: String,
    extra_data: String,
    base_fee_per_gas: String,
    block_hash: String,
    transactions_root: String,
    withdrawals_root: String,
    #[serde(default)]
    blob_gas_used: Option<String>,
    #[serde(default)]
    excess_blob_gas: Option<String>,
}

#[derive(Deserialize)]
struct RawSyncCommittee {
    pubkeys: Vec<String>,
    aggregate_pubkey: String,
}

#[derive(Deserialize)]
struct RawSyncAggregate {
    sync_committee_bits: String,
    sync_committee_signature: String,
}

#[derive(Deserialize)]
struct MainnetExecutionProofFile {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    state_root: String,
    receipts_root: String,
    header_rlp: String,
    weth: AccountStorageVector,
    usdc: AccountStorageVector,
}

#[derive(Deserialize)]
struct AccountStorageVector {
    address: String,
    balance_wei: String,
    account_rlp: String,
    account_proof: Vec<String>,
    storage_slot: String,
    storage_value_hex: String,
    storage_value_rlp: String,
    storage_proof: Vec<String>,
}

#[derive(Deserialize)]
struct MainnetReceiptProofFile {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    receipts_root: String,
    tx_index: u64,
    log_index: usize,
    emitter: String,
    from_address: String,
    to_address: String,
    amount_u256_be: String,
    receipt_rlp: String,
    receipt_proof: Vec<String>,
}

#[derive(Deserialize)]
struct SepoliaExecutionBlockFile {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    state_root: String,
    receipts_root: String,
    execution_rlp: String,
}

#[derive(Deserialize)]
struct SepoliaLatestSnapshotFile {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    state_root: String,
    receipts_root: String,
    header_rlp: String,
    mosoo_locker: SepoliaLockerAccountVector,
}

#[derive(Deserialize)]
struct SepoliaLockerAccountVector {
    address: String,
    balance_wei: String,
    account_rlp: String,
    account_proof: Vec<String>,
}

#[derive(Deserialize)]
struct SepoliaDepositVectorFile {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    state_root: String,
    receipts_root: String,
    header_rlp: String,
    tx_index: u64,
    log_index: usize,
    deposit_contract: String,
    receipt_rlp: String,
    receipt_proof: Vec<String>,
}

#[derive(Deserialize)]
struct SepoliaShieldedDepositVectorFile {
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    state_root: String,
    receipts_root: String,
    header_rlp: String,
    tx_index: u64,
    log_index: usize,
    deposit_contract: String,
    token_contract: String,
    commitment: String,
    amount_wei: String,
    leaf_index: u32,
    new_root: String,
    nonce: u64,
    receipt_rlp: String,
    receipt_proof: Vec<String>,
}

fn to_beacon_header(h: &RawBeaconHeader) -> BeaconBlockHeader {
    BeaconBlockHeader {
        slot: parse_u64_str(&h.slot),
        proposer_index: parse_u64_str(&h.proposer_index),
        parent_root: decode_hex32(&h.parent_root),
        state_root: decode_hex32(&h.state_root),
        body_root: decode_hex32(&h.body_root),
    }
}

fn to_sync_committee(c: &RawSyncCommittee) -> SyncCommittee {
    SyncCommittee {
        pubkeys: c.pubkeys.iter().map(|p| decode_hex_vec(p)).collect(),
        aggregate_pubkey: decode_hex_vec(&c.aggregate_pubkey),
    }
}

fn to_execution_payload(w: &RawHeaderWrapper) -> Option<ExecutionPayloadHeader> {
    if let Some(exec) = &w.execution {
        Some(ExecutionPayloadHeader {
            parent_hash: decode_hex32(&exec.parent_hash),
            fee_recipient: decode_hex20(&exec.fee_recipient),
            state_root: decode_hex32(&exec.state_root),
            receipts_root: decode_hex32(&exec.receipts_root),
            logs_bloom: decode_hex_vec(&exec.logs_bloom),
            prev_randao: decode_hex32(&exec.prev_randao),
            block_number: parse_u64_str(&exec.block_number),
            gas_limit: parse_u64_str(&exec.gas_limit),
            gas_used: parse_u64_str(&exec.gas_used),
            timestamp: parse_u64_str(&exec.timestamp),
            extra_data: decode_hex_vec(&exec.extra_data),
            base_fee_per_gas: parse_u256_le32(&exec.base_fee_per_gas),
            block_hash: decode_hex32(&exec.block_hash),
            transactions_root: decode_hex32(&exec.transactions_root),
            withdrawals_root: Some(decode_hex32(&exec.withdrawals_root)),
            blob_gas_used: exec.blob_gas_used.as_deref().map(parse_u64_str),
            excess_blob_gas: exec.excess_blob_gas.as_deref().map(parse_u64_str),
        })
    } else {
        w.execution_block_hash
            .as_deref()
            .map(|bh| ExecutionPayloadHeader {
                parent_hash: [0u8; 32],
                fee_recipient: [0u8; 20],
                state_root: [0u8; 32],
                receipts_root: [0u8; 32],
                logs_bloom: vec![0u8; 256],
                prev_randao: [0u8; 32],
                block_number: 0,
                gas_limit: 0,
                gas_used: 0,
                timestamp: 0,
                extra_data: Vec::new(),
                base_fee_per_gas: [0u8; 32],
                block_hash: decode_hex32(bh),
                transactions_root: [0u8; 32],
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
            })
    }
}

fn to_light_client_update(
    raw: &RawUpdateData,
    execution_rlp: Option<Vec<u8>>,
) -> LightClientUpdate {
    LightClientUpdate {
        attested_header: to_beacon_header(&raw.attested_header.beacon),
        next_sync_committee: raw.next_sync_committee.as_ref().map(to_sync_committee),
        next_sync_committee_branch: raw
            .next_sync_committee_branch
            .as_ref()
            .map(|b| b.iter().map(|s| decode_hex32(s)).collect()),
        finalized_header: to_beacon_header(&raw.finalized_header.beacon),
        finality_branch: raw
            .finality_branch
            .iter()
            .map(|s| decode_hex32(s))
            .collect(),
        execution_payload_header: to_execution_payload(&raw.finalized_header),
        execution_branch: raw
            .finalized_header
            .execution_branch
            .as_ref()
            .map(|b| b.iter().map(|s| decode_hex32(s)).collect()),
        execution_rlp,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: decode_hex_vec(&raw.sync_aggregate.sync_committee_bits),
            sync_committee_signature: decode_hex_vec(&raw.sync_aggregate.sync_committee_signature),
        },
        signature_slot: parse_u64_str(&raw.signature_slot),
    }
}

fn init_from_bootstrap(
    chain_id: u64,
    instance_tag: &[u8],
    bootstrap: &RawBootstrapWrapper,
    trusted_head_slot: u64,
) -> (InstanceAccount, [u8; 32]) {
    let instance_id: [u8; 32] = Sha256::digest(instance_tag).into();
    let header = to_beacon_header(&bootstrap.bootstrap.data.header.beacon);
    let block_root = decode_hex32(&bootstrap.block_root);
    assert_eq!(
        crypto::hash_tree_root_beacon_header(&header),
        block_root,
        "bootstrap header SSZ hash_tree_root must equal block_root"
    );
    let current_sync_committee =
        to_sync_committee(&bootstrap.bootstrap.data.current_sync_committee);
    let current_sync_committee_branch: Vec<[u8; 32]> = bootstrap
        .bootstrap
        .data
        .current_sync_committee_branch
        .iter()
        .map(|s| decode_hex32(s))
        .collect();

    let network_config = if !is_supported_chain_id(chain_id) {
        Some(NetworkConfig {
            chain_id,
            genesis_validators_root: crypto::genesis_validators_root(chain_id),
            trusted_checkpoint_root: Some(block_root),
            altair_fork_version: [0; 4],
            bellatrix_fork_version: [0; 4],
            capella_fork_version: [0; 4],
            deneb_fork_version: [0; 4],
            electra_fork_version: [0; 4],
            fulu_fork_version: [0; 4],
            gloas_fork_version: [0; 4],
        })
    } else {
        None
    };

    let report = verify_weak_subjectivity_checkpoint(
        chain_id,
        &header,
        &current_sync_committee,
        &current_sync_committee_branch,
        None,
        None,
        trusted_head_slot,
        Some(block_root),
        network_config.as_ref(),
    )
    .expect("bootstrap weak subjectivity checkpoint must verify");
    assert!(report.is_valid);

    let args = InitializeArgs {
        instance_id,
        chain_id,
        bootstrap_header: header,
        trusted_checkpoint_root: block_root,
        current_sync_committee,
        current_sync_committee_branch,
        initial_next_committee: None,
        initial_next_committee_branch: None,
        trusted_head_slot,
        network_config,
    };
    let out = handle_initialize(args).expect("handle_initialize must accept real bootstrap");
    let instance = match out {
        InstructionOutput::Initialized(inst) => inst,
        other => panic!("unexpected Initialize output: {other:?}"),
    };
    (instance, block_root)
}

#[test]
fn test_real_chain_vectors_manifest_sha256_integrity() {
    let manifest: ManifestJson =
        serde_json::from_str(&read_vector("manifest.json")).expect("valid manifest.json");
    assert_eq!(manifest.networks.len(), 3);

    for (network, entry) in &manifest.networks {
        for (stem, expected_sha) in &entry.hashes {
            let fname = if stem == "bootstrap_fin" {
                "bootstrap"
            } else {
                stem.as_str()
            };
            let rel = format!("{network}/{fname}.json");
            let bytes = fs::read(repo_root().join("vectors").join(&rel))
                .unwrap_or_else(|e| panic!("missing vector {rel}: {e}"));
            let actual_sha = hex::encode(Sha256::digest(&bytes));
            assert_eq!(
                &actual_sha, expected_sha,
                "SHA-256 mismatch for committed real-chain vector {rel}"
            );
        }
    }
}

#[test]
fn test_real_mainnet_fulu_consensus_pipeline_and_mpt_proofs() {
    let bootstrap_earlier: RawBootstrapWrapper =
        serde_json::from_str(&read_vector("mainnet/bootstrap_earlier.json"))
            .expect("mainnet earlier bootstrap");
    let finality_env: RawUpdateEnvelope =
        serde_json::from_str(&read_vector("mainnet/finality_update.json"))
            .expect("mainnet finality_update");
    let period_updates: Vec<RawUpdateEnvelope> =
        serde_json::from_str(&read_vector("mainnet/period_updates.json"))
            .expect("mainnet period_updates");
    let exec_proofs: MainnetExecutionProofFile =
        serde_json::from_str(&read_vector("mainnet/execution_proof.json"))
            .expect("mainnet execution_proof");
    let receipt_proof: MainnetReceiptProofFile =
        serde_json::from_str(&read_vector("mainnet/receipt_proof.json"))
            .expect("mainnet receipt_proof");

    assert_eq!(exec_proofs.chain_id, 1);
    assert_eq!(receipt_proof.chain_id, 1);
    assert_eq!(receipt_proof.block_number, exec_proofs.block_number);
    assert_eq!(receipt_proof.block_hash, exec_proofs.block_hash);
    assert_eq!(receipt_proof.receipts_root, exec_proofs.receipts_root);

    let sig_slot = parse_u64_str(&finality_env.data.signature_slot);
    let (instance, _) = init_from_bootstrap(
        1,
        b"mosoo_real_mainnet_fulu_v1",
        &bootstrap_earlier,
        sig_slot,
    );
    assert_eq!(instance.current_slot, 15_632_288);

    // Run full 3-transaction split consensus pipeline on real Mainnet Fulu finality_update
    let update = to_light_client_update(&finality_env.data, None);
    let job_begin = match handle_begin_update(
        BeginUpdateArgs::new(instance.clone(), update.clone(), 1).with_trusted_head_slot(sig_slot),
    )
    .expect("Mainnet Fulu BeginUpdate must accept real update")
    {
        InstructionOutput::JobCreated(j) => j,
        other => panic!("unexpected output: {other:?}"),
    };

    let job_miller = match handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job: job_begin,
    })
    .expect("Mainnet Fulu MillerUpdate must succeed")
    {
        InstructionOutput::JobMillerDone(j) => j,
        other => panic!("unexpected output: {other:?}"),
    };

    let (updated_instance, header_record) = match handle_finish_update(FinishUpdateArgs {
        instance: instance.clone(),
        job: job_miller,
    })
    .expect("Mainnet Fulu FinishUpdate must verify BLS + SSZ Fulu branches")
    {
        InstructionOutput::UpdateFinished {
            updated_instance,
            header_record,
            ..
        } => (updated_instance, header_record),
        other => panic!("unexpected output: {other:?}"),
    };

    assert_eq!(updated_instance.current_slot, 15_632_352);
    assert_eq!(
        header_record.execution_block_hash,
        decode_hex32(&exec_proofs.block_hash)
    );
    assert_eq!(
        header_record.execution_state_root,
        decode_hex32(&exec_proofs.state_root)
    );
    assert_eq!(
        header_record.receipts_root,
        decode_hex32(&exec_proofs.receipts_root)
    );

    // Also verify execution RLP matches Mainnet execution_proof block header
    let (rlp_state, rlp_receipts, rlp_num) = execution_header_roots(
        &header_record.execution_block_hash,
        &decode_hex_vec(&exec_proofs.header_rlp),
    )
    .expect("Mainnet execution RLP roots must match beacon payload hash");
    assert_eq!(rlp_state, header_record.execution_state_root);
    assert_eq!(rlp_receipts, header_record.receipts_root);
    assert_eq!(rlp_num, exec_proofs.block_number);

    // Negative test: flipping 1 bit in real BLS signature must fail FinishUpdate
    let mut bad_update = update.clone();
    bad_update.sync_aggregate.sync_committee_signature[10] ^= 0x01;
    let bad_begin = match handle_begin_update(
        BeginUpdateArgs::new(instance.clone(), bad_update, 2).with_trusted_head_slot(sig_slot),
    )
    .expect("BeginUpdate defers pairing check to Miller/Finish")
    {
        InstructionOutput::JobCreated(j) => j,
        _ => unreachable!(),
    };
    let tamper_rejected = match handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job: bad_begin,
    }) {
        Err(MosooError::InvalidSignature) => true,
        Ok(InstructionOutput::JobMillerDone(bad_miller)) => {
            let fin_err = handle_finish_update(FinishUpdateArgs {
                instance: instance.clone(),
                job: bad_miller,
            })
            .unwrap_err();
            assert!(matches!(fin_err, MosooError::InvalidSignature));
            true
        }
        other => panic!("unexpected tampered BLS outcome: {other:?}"),
    };
    assert!(
        tamper_rejected,
        "1-bit tampered Mainnet BLS signature must fail"
    );

    // Verify period_updates[1] (Period 1908) next_sync_committee branch against attested_header.state_root
    let pu_1908 = to_light_client_update(&period_updates[1].data, None);
    verify_sync_committee_branch(
        1,
        pu_1908
            .next_sync_committee
            .as_ref()
            .expect("period update includes next_sync_committee"),
        &pu_1908.attested_header,
        pu_1908
            .next_sync_committee_branch
            .as_ref()
            .expect("period update includes branch"),
    )
    .expect("Mainnet period 1908 next_sync_committee branch must verify");

    // Verify Mainnet WETH balance + storage slot 0 ("Wrapped Ether") via full handle_attest_state
    let weth_addr = Address::from(decode_hex20(&exec_proofs.weth.address));
    let weth_bal_proof = StateProof {
        target: ProofTarget::AccountBalance { address: weth_addr },
        account_proof: exec_proofs
            .weth
            .account_proof
            .iter()
            .map(|n| decode_hex_vec(n).into())
            .collect(),
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(decode_hex_vec(&exec_proofs.weth.account_rlp)),
        storage_value: None,
        receipt_value: None,
    };
    let expected_weth_balance: U256 = exec_proofs
        .weth
        .balance_wei
        .parse()
        .expect("valid WETH wei balance");
    let stmt_weth = match handle_attest_state(
        AttestStateArgs::new(
            updated_instance.clone(),
            header_record.clone(),
            None,
            None,
            weth_bal_proof.clone(),
            Predicate::Equal {
                expected: expected_weth_balance.to_be_bytes(),
            },
        )
        .with_trusted_head_slot(sig_slot),
    )
    .expect("Mainnet WETH balance AttestState must pass")
    {
        InstructionOutput::StatementIssued(s) => s,
        other => panic!("unexpected AttestState output: {other:?}"),
    };
    assert!(stmt_weth.predicate_holds);
    assert_eq!(
        stmt_weth.verified_value,
        expected_weth_balance.to_be_bytes()
    );

    let weth_storage_proof = StateProof {
        target: ProofTarget::StorageSlot {
            contract: weth_addr,
            slot: B256::from(decode_hex32(&exec_proofs.weth.storage_slot)),
        },
        account_proof: weth_bal_proof.account_proof.clone(),
        storage_proof: Some(
            exec_proofs
                .weth
                .storage_proof
                .iter()
                .map(|n| decode_hex_vec(n).into())
                .collect(),
        ),
        receipt_proof: None,
        account_value: weth_bal_proof.account_value.clone(),
        storage_value: Some(decode_hex_vec(&exec_proofs.weth.storage_value_rlp)),
        receipt_value: None,
    };
    let expected_weth_slot = decode_hex32(&exec_proofs.weth.storage_value_hex);
    let val_weth_slot =
        verify_state_proof(&weth_storage_proof, &header_record).expect("WETH storage slot proof");
    assert_eq!(
        val_weth_slot,
        VerifiedValue::StorageValue(expected_weth_slot)
    );

    // Verify USDC account balance (= 0) and zero/non-inclusion storage slot proof
    let usdc_addr = Address::from(decode_hex20(&exec_proofs.usdc.address));
    let usdc_bal_proof = StateProof {
        target: ProofTarget::AccountBalance { address: usdc_addr },
        account_proof: exec_proofs
            .usdc
            .account_proof
            .iter()
            .map(|n| decode_hex_vec(n).into())
            .collect(),
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(decode_hex_vec(&exec_proofs.usdc.account_rlp)),
        storage_value: None,
        receipt_value: None,
    };
    assert_eq!(
        verify_state_proof(&usdc_bal_proof, &header_record).expect("USDC balance proof"),
        VerifiedValue::EthBalance(U256::ZERO)
    );

    let usdc_slot_value = if exec_proofs.usdc.storage_value_rlp == "0x80" {
        None
    } else {
        Some(decode_hex_vec(&exec_proofs.usdc.storage_value_rlp))
    };
    let usdc_storage_proof = StateProof {
        target: ProofTarget::StorageSlot {
            contract: usdc_addr,
            slot: B256::from(decode_hex32(&exec_proofs.usdc.storage_slot)),
        },
        account_proof: usdc_bal_proof.account_proof.clone(),
        storage_proof: Some(
            exec_proofs
                .usdc
                .storage_proof
                .iter()
                .map(|n| decode_hex_vec(n).into())
                .collect(),
        ),
        receipt_proof: None,
        account_value: usdc_bal_proof.account_value.clone(),
        storage_value: usdc_slot_value,
        receipt_value: None,
    };
    assert_eq!(
        verify_state_proof(&usdc_storage_proof, &header_record)
            .expect("USDC implementation slot exclusion proof"),
        VerifiedValue::StorageValue([0u8; 32])
    );

    // Verify Mainnet ERC-20 Transfer receipt inclusion proof via handle_attest_state
    let mut padded_recipient = [0u8; 32];
    padded_recipient[12..32].copy_from_slice(&decode_hex20(&receipt_proof.to_address));
    let r_proof = StateProof {
        target: ProofTarget::Erc20Transfer {
            tx_index: receipt_proof.tx_index,
            log_index: receipt_proof.log_index,
            token_contract: Address::from(decode_hex20(&receipt_proof.emitter)),
            sender: Address::from(decode_hex20(&receipt_proof.from_address)),
            recipient: padded_recipient,
        },
        account_proof: Vec::new(),
        storage_proof: None,
        receipt_proof: Some(
            receipt_proof
                .receipt_proof
                .iter()
                .map(|n| decode_hex_vec(n).into())
                .collect(),
        ),
        account_value: None,
        storage_value: None,
        receipt_value: Some(decode_hex_vec(&receipt_proof.receipt_rlp)),
    };
    let expected_transfer_amount = decode_hex32(&receipt_proof.amount_u256_be);
    let stmt_rcpt = match handle_attest_state(
        AttestStateArgs::new(
            updated_instance.clone(),
            header_record.clone(),
            None,
            None,
            r_proof.clone(),
            Predicate::Equal {
                expected: expected_transfer_amount,
            },
        )
        .with_trusted_head_slot(sig_slot),
    )
    .expect("Mainnet ERC-20 Transfer receipt AttestState must pass")
    {
        InstructionOutput::StatementIssued(s) => s,
        other => panic!("unexpected receipt output: {other:?}"),
    };
    assert_eq!(stmt_rcpt.verified_value, expected_transfer_amount);

    // Negative MPT tamper check: corrupt 1 byte inside receipt RLP
    let mut tampered_r_proof = r_proof;
    let bytes = tampered_r_proof.receipt_value.as_mut().unwrap();
    let last = bytes.len() - 1;
    bytes[last] ^= 0xff;
    let err = verify_state_proof(&tampered_r_proof, &header_record).unwrap_err();
    assert!(
        matches!(err, MosooError::InvalidTrieProof),
        "tampered receipt RLP must fail MPT verification, got {err:?}"
    );
}

#[test]
fn test_real_sepolia_gloas_epbs_and_live_mosoo_locker_deposit() {
    let bootstrap: RawBootstrapWrapper =
        serde_json::from_str(&read_vector("sepolia/bootstrap.json")).expect("sepolia bootstrap");
    let finality_env: RawUpdateEnvelope =
        serde_json::from_str(&read_vector("sepolia/finality_update.json"))
            .expect("sepolia finality_update");
    let exec_block: SepoliaExecutionBlockFile =
        serde_json::from_str(&read_vector("sepolia/execution_block.json"))
            .expect("sepolia execution_block");
    let snapshot: SepoliaLatestSnapshotFile =
        serde_json::from_str(&read_vector("sepolia/latest_proof_snapshot.json"))
            .expect("sepolia latest_proof_snapshot");
    let deposit_vec: SepoliaDepositVectorFile =
        serde_json::from_str(&read_vector("sepolia/deposit_12082214.json"))
            .expect("sepolia deposit_12082214");

    assert_eq!(exec_block.chain_id, 11_155_111);
    assert_eq!(exec_block.block_number, 12_112_710);
    assert_eq!(snapshot.chain_id, 11_155_111);
    assert_eq!(deposit_vec.chain_id, 11_155_111);

    let sig_slot = parse_u64_str(&finality_env.data.signature_slot);
    // 1. Verify Gloas bootstrap checkpoint at slot 11,556,544 (gindex 2945, depth 11)
    let (mut instance, _) = init_from_bootstrap(
        11_155_111,
        b"mosoo_real_sepolia_gloas_v1",
        &bootstrap,
        sig_slot,
    );
    assert_eq!(instance.current_slot, 11_556_544);

    // 2. Verify Sepolia Gloas finality_update BLS aggregate sig, finality branch (735), execution_block_hash branch (2856)
    let exec_rlp = decode_hex_vec(&exec_block.execution_rlp);
    let update = to_light_client_update(&finality_env.data, Some(exec_rlp.clone()));
    crypto::verify_sync_committee_signature(
        &instance.current_sync_committee,
        &update.sync_aggregate,
        &update.attested_header,
        11_155_111,
        update.signature_slot,
    )
    .expect("Sepolia Gloas sync committee signature must verify");

    verify_finality_branch(
        11_155_111,
        &update.finalized_header,
        &update.attested_header,
        &update.finality_branch,
    )
    .expect("Sepolia Gloas finality_branch (gindex 735) must verify");

    let payload_header = update
        .execution_payload_header
        .as_ref()
        .expect("Gloas execution_block_hash synthesized into payload_header");
    let exec_branch = update
        .execution_branch
        .as_ref()
        .expect("Gloas execution_branch");
    verify_execution_payload_branch(
        11_155_111,
        payload_header,
        &update.finalized_header,
        exec_branch,
    )
    .expect("Sepolia Gloas execution_branch (gindex 2856) must verify");

    // 3. Verify Gloas RLP root binding succeeds with RLP and fails closed when omitted
    let (auth_hash, auth_state, auth_receipts) = verify_execution_roots_binding(
        11_155_111,
        update.finalized_header.slot,
        payload_header,
        Some(&exec_rlp),
    )
    .expect("Gloas execution_rlp roots binding must pass");
    assert_eq!(auth_hash, decode_hex32(&exec_block.block_hash));
    assert_eq!(auth_state, decode_hex32(&exec_block.state_root));
    assert_eq!(auth_receipts, decode_hex32(&exec_block.receipts_root));

    let missing_rlp_err = verify_execution_roots_binding(
        11_155_111,
        update.finalized_header.slot,
        payload_header,
        None,
    )
    .unwrap_err();
    assert!(matches!(
        missing_rlp_err,
        MosooError::GloasExecutionRlpMismatch
    ));

    // Also confirm incremental 3-tx update processing works end-to-end on Gloas when advancing from an earlier slot in the same period
    instance.current_slot = 11_556_512;
    let job_begin = match handle_begin_update(
        BeginUpdateArgs::new(instance.clone(), update, 1).with_trusted_head_slot(sig_slot),
    )
    .expect("Sepolia Gloas BeginUpdate must pass")
    {
        InstructionOutput::JobCreated(j) => j,
        _ => unreachable!(),
    };
    let job_miller = match handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job: job_begin,
    })
    .expect("Sepolia Gloas MillerUpdate must pass")
    {
        InstructionOutput::JobMillerDone(j) => j,
        _ => unreachable!(),
    };
    let (updated_instance, header_12112710) = match handle_finish_update(FinishUpdateArgs {
        instance: instance.clone(),
        job: job_miller,
    })
    .expect("Sepolia Gloas FinishUpdate must pass")
    {
        InstructionOutput::UpdateFinished {
            updated_instance,
            header_record,
            ..
        } => (updated_instance, header_record),
        _ => unreachable!(),
    };
    assert_eq!(header_12112710.execution_state_root, auth_state);
    assert_eq!(updated_instance.current_receipts_root, auth_receipts);

    // Negative test: flipping 1 bit in Sepolia BLS signature fails closed
    let mut bad_agg = to_light_client_update(&finality_env.data, None).sync_aggregate;
    bad_agg.sync_committee_signature[0] ^= 0x80;
    let bad_bls = crypto::verify_sync_committee_signature(
        &instance.current_sync_committee,
        &bad_agg,
        &header_12112710_header(&finality_env.data.attested_header.beacon),
        11_155_111,
        sig_slot,
    )
    .unwrap_err();
    assert!(matches!(bad_bls, MosooError::InvalidSignature));

    // 4. Verify live Sepolia MosooLocker balance (0.025 ETH = 3 real deposits) in latest_proof_snapshot.json
    let (snap_state, snap_receipts, snap_num) = execution_header_roots(
        &decode_hex32(&snapshot.block_hash),
        &decode_hex_vec(&snapshot.header_rlp),
    )
    .expect("Sepolia snapshot header RLP must match");
    assert_eq!(snap_num, snapshot.block_number);
    assert_eq!(snap_state, decode_hex32(&snapshot.state_root));
    assert_eq!(snap_receipts, decode_hex32(&snapshot.receipts_root));

    let snap_header = HeaderRecord {
        chain_id: 11_155_111,
        slot: 11_556_544,
        beacon_block_root: decode_hex32(&bootstrap.block_root),
        execution_block_hash: decode_hex32(&snapshot.block_hash),
        execution_state_root: snap_state,
        receipts_root: snap_receipts,
    };
    let locker_addr = Address::from(decode_hex20(&snapshot.mosoo_locker.address));
    let locker_proof = StateProof {
        target: ProofTarget::AccountBalance {
            address: locker_addr,
        },
        account_proof: snapshot
            .mosoo_locker
            .account_proof
            .iter()
            .map(|n| decode_hex_vec(n).into())
            .collect(),
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(decode_hex_vec(&snapshot.mosoo_locker.account_rlp)),
        storage_value: None,
        receipt_value: None,
    };
    let expected_locker_bal: U256 = snapshot
        .mosoo_locker
        .balance_wei
        .parse()
        .expect("valid wei string");
    assert_eq!(
        verify_state_proof(&locker_proof, &snap_header).expect("MosooLocker account balance proof"),
        VerifiedValue::EthBalance(expected_locker_bal)
    );
    assert_eq!(expected_locker_bal, U256::from(25_000_000_000_000_000u64));

    // 5. Verify real live Sepolia DepositETH tx 0x6ecddbdd... (block 12082214, nonce 3, 0.01 ETH)
    let (dep_state, dep_receipts, dep_num) = execution_header_roots(
        &decode_hex32(&deposit_vec.block_hash),
        &decode_hex_vec(&deposit_vec.header_rlp),
    )
    .expect("Sepolia deposit block header RLP must match");
    assert_eq!(dep_num, deposit_vec.block_number);
    assert_eq!(dep_state, decode_hex32(&deposit_vec.state_root));
    assert_eq!(dep_receipts, decode_hex32(&deposit_vec.receipts_root));

    let dep_header = HeaderRecord {
        chain_id: 11_155_111,
        slot: 11_556_544,
        beacon_block_root: decode_hex32(&bootstrap.block_root),
        execution_block_hash: decode_hex32(&deposit_vec.block_hash),
        execution_state_root: dep_state,
        receipts_root: dep_receipts,
    };
    let dep_receipt_rlp = decode_hex_vec(&deposit_vec.receipt_rlp);
    let verified_log = inclusion::decode_and_validate_receipt(
        &dep_receipt_rlp,
        deposit_vec.tx_index,
        deposit_vec.log_index,
        Some(Address::from(decode_hex20(&deposit_vec.deposit_contract))),
        None,
    )
    .expect("real Sepolia DepositETH receipt decodes");
    let (sender, lez_recipient, amount, nonce) =
        inclusion::decode_deposit_eth_log(&verified_log).expect("DepositETH topic decode");
    assert_eq!(amount, U256::from(10_000_000_000_000_000u64));
    assert_eq!(nonce, 3);

    let dep_state_proof = StateProof {
        target: ProofTarget::NativeEthDeposit {
            tx_index: deposit_vec.tx_index,
            log_index: deposit_vec.log_index,
            deposit_contract: Address::from(decode_hex20(&deposit_vec.deposit_contract)),
            sender,
            recipient: lez_recipient,
        },
        account_proof: Vec::new(),
        storage_proof: None,
        receipt_proof: Some(
            deposit_vec
                .receipt_proof
                .iter()
                .map(|n| decode_hex_vec(n).into())
                .collect(),
        ),
        account_value: None,
        storage_value: None,
        receipt_value: Some(dep_receipt_rlp),
    };
    let verified_dep =
        verify_state_proof(&dep_state_proof, &dep_header).expect("real Sepolia DepositETH proof");
    assert_eq!(
        verified_dep.as_bytes32(),
        U256::from(10_000_000_000_000_000u64).to_be_bytes::<32>()
    );

    // Negative tests on live DepositETH proof: wrong sender & corrupted receipt fail closed
    let mut wrong_sender_proof = dep_state_proof.clone();
    wrong_sender_proof.target = ProofTarget::NativeEthDeposit {
        tx_index: deposit_vec.tx_index,
        log_index: deposit_vec.log_index,
        deposit_contract: Address::from(decode_hex20(&deposit_vec.deposit_contract)),
        sender: Address::from([0x11; 20]),
        recipient: lez_recipient,
    };
    assert!(verify_state_proof(&wrong_sender_proof, &dep_header).is_err());

    let mut tampered_dep = dep_state_proof;
    let buf = tampered_dep.receipt_value.as_mut().unwrap();
    buf[10] ^= 0x01;
    assert!(matches!(
        verify_state_proof(&tampered_dep, &dep_header).unwrap_err(),
        MosooError::InvalidTrieProof
    ));

    // 6. Verify real live Sepolia MosooLocker v2 shielded DepositCommitted tx 0xe017525b... (block 12113199, leafIndex 1, 0.01 ETH)
    let v2_dep: SepoliaShieldedDepositVectorFile =
        serde_json::from_str(&read_vector("sepolia/deposit_v2_shielded.json"))
            .expect("sepolia deposit_v2_shielded");
    assert_eq!(v2_dep.chain_id, 11_155_111);
    let (v2_state, v2_receipts, v2_num) = execution_header_roots(
        &decode_hex32(&v2_dep.block_hash),
        &decode_hex_vec(&v2_dep.header_rlp),
    )
    .expect("Sepolia v2 deposit block header RLP must match");
    assert_eq!(v2_num, v2_dep.block_number);
    assert_eq!(v2_state, decode_hex32(&v2_dep.state_root));
    assert_eq!(v2_receipts, decode_hex32(&v2_dep.receipts_root));

    let v2_header = HeaderRecord {
        chain_id: 11_155_111,
        slot: 11_556_544,
        beacon_block_root: decode_hex32(&bootstrap.block_root),
        execution_block_hash: decode_hex32(&v2_dep.block_hash),
        execution_state_root: v2_state,
        receipts_root: v2_receipts,
    };
    let v2_receipt_rlp = decode_hex_vec(&v2_dep.receipt_rlp);
    let v2_contract = Address::from(decode_hex20(&v2_dep.deposit_contract));
    assert_eq!(
        v2_contract,
        Address::from(mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_LOCKER_V2)
    );
    let v2_verified_log = inclusion::decode_and_validate_receipt(
        &v2_receipt_rlp,
        v2_dep.tx_index,
        v2_dep.log_index,
        Some(v2_contract),
        None,
    )
    .expect("real Sepolia v2 DepositCommitted receipt decodes");
    let (dec_comm, dec_tok, dec_amt, dec_leaf, dec_root, dec_nonce) =
        inclusion::decode_deposit_committed_log(&v2_verified_log)
            .expect("DepositCommitted log decode");
    let expected_comm = B256::from(decode_hex32(&v2_dep.commitment));
    let expected_tok = Address::from(decode_hex20(&v2_dep.token_contract));
    let expected_amt: U256 = v2_dep.amount_wei.parse().expect("valid v2 wei string");
    assert_eq!(dec_comm, expected_comm);
    assert_eq!(dec_tok, expected_tok);
    assert_eq!(dec_amt, expected_amt);
    assert_eq!(dec_leaf, v2_dep.leaf_index);
    assert_eq!(dec_root, B256::from(decode_hex32(&v2_dep.new_root)));
    assert_eq!(dec_nonce, v2_dep.nonce);

    let v2_state_proof = StateProof {
        target: ProofTarget::ShieldedCommitmentDeposit {
            tx_index: v2_dep.tx_index,
            log_index: v2_dep.log_index,
            deposit_contract: v2_contract,
            token_contract: expected_tok,
            commitment: expected_comm,
        },
        account_proof: Vec::new(),
        storage_proof: None,
        receipt_proof: Some(
            v2_dep
                .receipt_proof
                .iter()
                .map(|n| decode_hex_vec(n).into())
                .collect(),
        ),
        account_value: None,
        storage_value: None,
        receipt_value: Some(v2_receipt_rlp),
    };
    let verified_v2 = verify_state_proof(&v2_state_proof, &v2_header)
        .expect("real Sepolia v2 ShieldedCommitmentDeposit MPT proof must verify");
    assert_eq!(verified_v2.as_bytes32(), expected_amt.to_be_bytes::<32>());

    // Canonical TrustedBridgeConfig must also accept live Sepolia v2 (0xEFEf...) end-to-end
    let v2_stmt = mosoo_core::verifier::verify_statement_against_authenticated_header(
        11_155_111,
        mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID,
        mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_INSTANCE,
        crypto::genesis_validators_root(11_155_111),
        &v2_header,
        &v2_state_proof,
        &Predicate::AtLeast {
            min: U256::from(10_000_000_000_000_000u64).to_be_bytes::<32>(),
        },
        Some([0x5a; 32]),
        Some(mosoo_core::types::PrivacyMode::Confidential),
        None,
    )
    .expect("canonical config must verify live Sepolia v2 DepositCommitted statement");
    assert_eq!(
        v2_stmt.proof_type_tag,
        mosoo_core::types::PROOF_TYPE_SHIELDED_DEPOSIT
    );

    // Negative check: mismatched commitment & untrusted locker fail closed against real Sepolia v2 receipt
    let mut wrong_locker = v2_state_proof.clone();
    wrong_locker.target = ProofTarget::ShieldedCommitmentDeposit {
        tx_index: v2_dep.tx_index,
        log_index: v2_dep.log_index,
        deposit_contract: Address::repeat_byte(0x99),
        token_contract: expected_tok,
        commitment: expected_comm,
    };
    assert!(
        mosoo_core::verifier::verify_statement_against_authenticated_header(
            11_155_111,
            mosoo_core::types::CANONICAL_SEPOLIA_INSTANCE_ID,
            mosoo_core::types::CANONICAL_SEPOLIA_MOSOO_INSTANCE,
            crypto::genesis_validators_root(11_155_111),
            &v2_header,
            &wrong_locker,
            &Predicate::AtLeast {
                min: U256::from(1u64).to_be_bytes::<32>(),
            },
            Some([0x5a; 32]),
            Some(mosoo_core::types::PrivacyMode::Confidential),
            None,
        )
        .is_err()
    );

    let mut wrong_comm = v2_state_proof;
    wrong_comm.target = ProofTarget::ShieldedCommitmentDeposit {
        tx_index: v2_dep.tx_index,
        log_index: v2_dep.log_index,
        deposit_contract: v2_contract,
        token_contract: expected_tok,
        commitment: B256::repeat_byte(0xff),
    };
    assert!(verify_state_proof(&wrong_comm, &v2_header).is_err());
}

fn header_12112710_header(h: &RawBeaconHeader) -> BeaconBlockHeader {
    to_beacon_header(h)
}

#[test]
fn test_real_hoodi_fulu_cross_period_530_to_531_transition() {
    let bootstrap_earlier: RawBootstrapWrapper =
        serde_json::from_str(&read_vector("hoodi/bootstrap_earlier.json"))
            .expect("hoodi bootstrap_earlier");
    let current_period_updates: Vec<RawUpdateEnvelope> =
        serde_json::from_str(&read_vector("hoodi/current_period_update.json"))
            .expect("hoodi current_period_update");
    let finality_env: RawUpdateEnvelope =
        serde_json::from_str(&read_vector("hoodi/finality_update.json"))
            .expect("hoodi finality_update");

    let fin_sig_slot = parse_u64_str(&finality_env.data.signature_slot);
    let (mut instance, _) = init_from_bootstrap(
        560_048,
        b"mosoo_real_hoodi_fulu_v1",
        &bootstrap_earlier,
        fin_sig_slot,
    );
    assert_eq!(instance.current_slot, 4_349_856);
    assert_eq!(compute_sync_committee_period(instance.current_slot), 530);
    assert_eq!(
        instance.pda_address(),
        derive_instance_pda(560_048, &instance.instance_id)
    );

    // 1. Trying to process period 531 signature BEFORE Period 531 next_sync_committee is authenticated MUST fail
    let fin_update = to_light_client_update(&finality_env.data, None);
    assert_eq!(
        compute_sync_committee_period(fin_update.signature_slot),
        531
    );
    let missing_next_err = handle_begin_update(
        BeginUpdateArgs::new(instance.clone(), fin_update.clone(), 1)
            .with_trusted_head_slot(fin_sig_slot),
    )
    .unwrap_err();
    assert!(
        matches!(missing_next_err, MosooError::MissingCommitteeBranch),
        "must reject period 531 signature without authenticated next_sync_committee, got {missing_next_err:?}"
    );

    // 2. Authenticate period 530 update (`current_period_update[0]`) under Period 530 committee to derive Period 531 next_sync_committee
    let p530_update = to_light_client_update(&current_period_updates[0].data, None);
    assert_eq!(
        compute_sync_committee_period(p530_update.signature_slot),
        530
    );
    crypto::verify_sync_committee_signature(
        &instance.current_sync_committee,
        &p530_update.sync_aggregate,
        &p530_update.attested_header,
        560_048,
        p530_update.signature_slot,
    )
    .expect("Hoodi period 530 committee signature must verify");
    verify_finality_branch(
        560_048,
        &p530_update.finalized_header,
        &p530_update.attested_header,
        &p530_update.finality_branch,
    )
    .expect("Hoodi period 530 finality branch must verify");

    let period_531_committee = p530_update
        .next_sync_committee
        .clone()
        .expect("period 530 update contains next_sync_committee for 531");
    let next_branch = p530_update
        .next_sync_committee_branch
        .as_ref()
        .expect("period 530 update contains next_sync_committee_branch");
    verify_sync_committee_branch(
        560_048,
        &period_531_committee,
        &p530_update.attested_header,
        next_branch,
    )
    .expect("Hoodi Period 531 next_sync_committee branch must verify against state_root");

    // 3. Negative check: Period 530 committee CANNOT verify the Period 531 signature in finality_update
    let wrong_period_err = crypto::verify_sync_committee_signature(
        &instance.current_sync_committee,
        &fin_update.sync_aggregate,
        &fin_update.attested_header,
        560_048,
        fin_update.signature_slot,
    )
    .unwrap_err();
    assert!(matches!(wrong_period_err, MosooError::InvalidSignature));

    // 4. Attach authenticated Period 531 committee as next_sync_committee and run full 3-tx pipeline on finality_update
    instance.next_sync_committee = Some(period_531_committee);

    let job_begin = match handle_begin_update(
        BeginUpdateArgs::new(instance.clone(), fin_update, 2).with_trusted_head_slot(fin_sig_slot),
    )
    .expect("Hoodi cross-period 530->531 BeginUpdate must accept Period 531 signature")
    {
        InstructionOutput::JobCreated(j) => j,
        _ => unreachable!(),
    };

    let job_miller = match handle_miller_update(MillerUpdateArgs {
        instance: instance.clone(),
        job: job_begin,
    })
    .expect("Hoodi MillerUpdate must succeed")
    {
        InstructionOutput::JobMillerDone(j) => j,
        _ => unreachable!(),
    };

    let (updated_instance, header_record) = match handle_finish_update(FinishUpdateArgs {
        instance: instance.clone(),
        job: job_miller,
    })
    .expect("Hoodi FinishUpdate must verify Period 531 BLS + Fulu SSZ branches")
    {
        InstructionOutput::UpdateFinished {
            updated_instance,
            header_record,
            ..
        } => (updated_instance, header_record),
        _ => unreachable!(),
    };

    assert_eq!(updated_instance.current_slot, 4_349_920);
    assert_eq!(header_record.chain_id, 560_048);
    assert_ne!(header_record.execution_state_root, [0u8; 32]);
    assert_ne!(header_record.receipts_root, [0u8; 32]);
}
