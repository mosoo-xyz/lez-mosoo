use std::{fs, path::Path};

use alloy_primitives::{Address, B256, U256};
use anyhow::{Context, Result, anyhow};
use mosoo_core::{
    crypto,
    inclusion::{ProofTarget, StateProof},
    types::{
        BeaconBlockHeader, ExecutionPayloadHeader, LightClientUpdate, Predicate, SyncAggregate,
        SyncCommittee,
    },
};
use mosoo_lez_v03::wire::{
    WireBeaconHeader, WireExecutionPayloadHeader, WireKeyWitness, WirePredicate, WireStateProof,
    WireSyncCommittee, WireUpdate,
};
use serde::Deserialize;

#[derive(Deserialize)]
struct RawBootstrapEarlierFile {
    block_root: String,
    bootstrap: RawBootstrapWrapper,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawBootstrapWrapper {
    WithData { data: RawBootstrapData },
    Direct(RawBootstrapData),
}

impl RawBootstrapWrapper {
    fn inner(&self) -> &RawBootstrapData {
        match self {
            Self::WithData { data } | Self::Direct(data) => data,
        }
    }
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
    weth: AccountStorageVector,
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
    tx_index: u64,
    log_index: usize,
    emitter: String,
    from_address: String,
    to_address: String,
    amount_u256_be: String,
    receipt_rlp: String,
    receipt_proof: Vec<String>,
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(trimmed).with_context(|| format!("invalid hex: {s}"))
}

pub fn decode_hex32(s: &str) -> Result<[u8; 32]> {
    let b = decode_hex(s)?;
    b.try_into()
        .map_err(|_| anyhow!("expected 32 bytes in {s}"))
}

pub fn decode_topic_addr32(s: &str) -> Result<[u8; 32]> {
    let b = decode_hex(s)?;
    match b.len() {
        32 => Ok(b.try_into().unwrap()),
        20 => {
            let mut out = [0u8; 32];
            out[12..32].copy_from_slice(&b);
            Ok(out)
        }
        other => anyhow::bail!("expected 20 or 32 bytes in {s}, got {other}"),
    }
}

pub fn decode_hex20(s: &str) -> Result<[u8; 20]> {
    let b = decode_hex(s)?;
    b.try_into()
        .map_err(|_| anyhow!("expected 20 bytes in {s}"))
}

pub fn parse_u64_str(s: &str) -> Result<u64> {
    if let Some(hex_part) = s.strip_prefix("0x") {
        u64::from_str_radix(hex_part, 16).with_context(|| format!("invalid hex u64: {s}"))
    } else {
        s.parse::<u64>()
            .with_context(|| format!("invalid decimal u64: {s}"))
    }
}

fn parse_u256_str(s: &str) -> Result<U256> {
    if let Some(hex_part) = s.strip_prefix("0x") {
        U256::from_str_radix(hex_part, 16).with_context(|| format!("invalid hex U256: {s}"))
    } else {
        U256::from_str_radix(s, 10).with_context(|| format!("invalid decimal U256: {s}"))
    }
}

fn parse_beacon_header(raw: &RawBeaconHeader) -> Result<BeaconBlockHeader> {
    Ok(BeaconBlockHeader {
        slot: parse_u64_str(&raw.slot)?,
        proposer_index: parse_u64_str(&raw.proposer_index)?,
        parent_root: decode_hex32(&raw.parent_root)?,
        state_root: decode_hex32(&raw.state_root)?,
        body_root: decode_hex32(&raw.body_root)?,
    })
}

fn parse_sync_committee(raw: &RawSyncCommittee) -> Result<SyncCommittee> {
    let pubkeys = raw
        .pubkeys
        .iter()
        .map(|s| decode_hex(s))
        .collect::<Result<Vec<_>>>()?;
    Ok(SyncCommittee {
        pubkeys,
        aggregate_pubkey: decode_hex(&raw.aggregate_pubkey)?,
    })
}

fn parse_execution_header(raw: &RawExecutionHeader) -> Result<ExecutionPayloadHeader> {
    Ok(ExecutionPayloadHeader {
        parent_hash: decode_hex32(&raw.parent_hash)?,
        fee_recipient: decode_hex20(&raw.fee_recipient)?,
        state_root: decode_hex32(&raw.state_root)?,
        receipts_root: decode_hex32(&raw.receipts_root)?,
        logs_bloom: decode_hex(&raw.logs_bloom)?,
        prev_randao: decode_hex32(&raw.prev_randao)?,
        block_number: parse_u64_str(&raw.block_number)?,
        gas_limit: parse_u64_str(&raw.gas_limit)?,
        gas_used: parse_u64_str(&raw.gas_used)?,
        timestamp: parse_u64_str(&raw.timestamp)?,
        extra_data: decode_hex(&raw.extra_data)?,
        base_fee_per_gas: parse_u256_str(&raw.base_fee_per_gas)?.to_le_bytes(),
        block_hash: decode_hex32(&raw.block_hash)?,
        transactions_root: decode_hex32(&raw.transactions_root)?,
        withdrawals_root: Some(decode_hex32(&raw.withdrawals_root)?),
        blob_gas_used: raw.blob_gas_used.as_deref().map(parse_u64_str).transpose()?,
        excess_blob_gas: raw
            .excess_blob_gas
            .as_deref()
            .map(parse_u64_str)
            .transpose()?,
    })
}

pub struct MainnetBundle {
    pub checkpoint: [u8; 32],
    pub bootstrap_header: WireBeaconHeader,
    pub bootstrap_committee: WireSyncCommittee,
    pub bootstrap_committee_branch: Vec<[u8; 32]>,
    pub bootstrap_exec_header: Option<WireExecutionPayloadHeader>,
    pub bootstrap_exec_branch: Option<Vec<[u8; 32]>>,
    pub update: WireUpdate,
    pub witness: WireKeyWitness,
    pub weth_balance_proof: WireStateProof,
    pub weth_balance_pred: WirePredicate,
    pub weth_storage_proof: WireStateProof,
    pub weth_storage_pred: WirePredicate,
    pub receipt_proof: WireStateProof,
    pub receipt_pred: WirePredicate,
    pub finalized_slot: u64,
    pub exec_block_number: u64,
}

pub fn load_mainnet_bundle(vectors_dir: &Path) -> Result<MainnetBundle> {
    let dir = vectors_dir.join("mainnet");
    let boot_raw: RawBootstrapEarlierFile = serde_json::from_str(
        &fs::read_to_string(dir.join("bootstrap_earlier.json"))
            .context("reading bootstrap_earlier.json")?,
    )?;
    let update_raw: RawUpdateEnvelope = serde_json::from_str(
        &fs::read_to_string(dir.join("finality_update.json"))
            .context("reading finality_update.json")?,
    )?;
    let exec_raw: MainnetExecutionProofFile = serde_json::from_str(
        &fs::read_to_string(dir.join("execution_proof.json"))
            .context("reading execution_proof.json")?,
    )?;
    let rcpt_raw: MainnetReceiptProofFile = serde_json::from_str(
        &fs::read_to_string(dir.join("receipt_proof.json"))
            .context("reading receipt_proof.json")?,
    )?;

    anyhow::ensure!(exec_raw.chain_id == 1 && rcpt_raw.chain_id == 1);
    anyhow::ensure!(exec_raw.block_number == rcpt_raw.block_number);

    let boot = boot_raw.bootstrap.inner();
    let boot_hdr = parse_beacon_header(&boot.header.beacon)?;
    let boot_comm = parse_sync_committee(&boot.current_sync_committee)?;
    let boot_comm_branch = boot
        .current_sync_committee_branch
        .iter()
        .map(|s| decode_hex32(s))
        .collect::<Result<Vec<_>>>()?;
    let boot_exec = boot
        .header
        .execution
        .as_ref()
        .map(parse_execution_header)
        .transpose()?;
    let boot_exec_branch = boot
        .header
        .execution_branch
        .as_ref()
        .map(|v| v.iter().map(|s| decode_hex32(s)).collect::<Result<Vec<_>>>())
        .transpose()?;

    let ud = &update_raw.data;
    let attested = parse_beacon_header(&ud.attested_header.beacon)?;
    let finalized = parse_beacon_header(&ud.finalized_header.beacon)?;
    let finality_branch = ud
        .finality_branch
        .iter()
        .map(|s| decode_hex32(s))
        .collect::<Result<Vec<_>>>()?;
    let sync_agg = SyncAggregate {
        sync_committee_bits: decode_hex(&ud.sync_aggregate.sync_committee_bits)?,
        sync_committee_signature: decode_hex(&ud.sync_aggregate.sync_committee_signature)?,
    };
    let fin_exec = ud
        .finalized_header
        .execution
        .as_ref()
        .map(parse_execution_header)
        .transpose()?;
    let fin_exec_branch = ud
        .finalized_header
        .execution_branch
        .as_ref()
        .map(|v| v.iter().map(|s| decode_hex32(s)).collect::<Result<Vec<_>>>())
        .transpose()?;
    let next_sc = ud
        .next_sync_committee
        .as_ref()
        .map(parse_sync_committee)
        .transpose()?;
    let next_sc_branch = ud
        .next_sync_committee_branch
        .as_ref()
        .map(|v| v.iter().map(|s| decode_hex32(s)).collect::<Result<Vec<_>>>())
        .transpose()?;

    let core_update = LightClientUpdate {
        attested_header: attested,
        next_sync_committee: next_sc,
        next_sync_committee_branch: next_sc_branch,
        finalized_header: finalized.clone(),
        finality_branch,
        execution_payload_header: fin_exec,
        execution_branch: fin_exec_branch,
        execution_rlp: None,
        sync_aggregate: sync_agg.clone(),
        signature_slot: parse_u64_str(&ud.signature_slot)?,
    };

    let witness = crypto::build_complement_key_witness(&boot_comm, &sync_agg.sync_committee_bits)
        .map_err(|e| anyhow!("build_complement_key_witness failed: {e}"))?;

    // State proofs for finalized block 26392691
    let weth_addr = Address::from(decode_hex20(&exec_raw.weth.address)?);
    let weth_acc_rlp = decode_hex(&exec_raw.weth.account_rlp)?;
    let weth_acc_proof = exec_raw
        .weth
        .account_proof
        .iter()
        .map(|s| decode_hex(s).map(Into::into))
        .collect::<Result<Vec<_>>>()?;
    let weth_bal_be = parse_u256_str(&exec_raw.weth.balance_wei)?.to_be_bytes::<32>();

    let weth_balance_state_proof = StateProof {
        target: ProofTarget::AccountBalance { address: weth_addr },
        account_proof: weth_acc_proof.clone(),
        storage_proof: None,
        receipt_proof: None,
        account_value: Some(weth_acc_rlp.clone()),
        storage_value: None,
        receipt_value: None,
    };

    let storage_slot = B256::from(decode_hex32(&exec_raw.weth.storage_slot)?);
    let weth_storage_state_proof = StateProof {
        target: ProofTarget::StorageSlot {
            contract: weth_addr,
            slot: storage_slot,
        },
        account_proof: weth_acc_proof,
        storage_proof: Some(
            exec_raw
                .weth
                .storage_proof
                .iter()
                .map(|s| decode_hex(s).map(Into::into))
                .collect::<Result<Vec<_>>>()?,
        ),
        receipt_proof: None,
        account_value: Some(weth_acc_rlp),
        storage_value: Some(decode_hex(&exec_raw.weth.storage_value_rlp)?),
        receipt_value: None,
    };
    let expected_storage_be = decode_hex32(&exec_raw.weth.storage_value_hex)?;

    let emitter = Address::from(decode_hex20(&rcpt_raw.emitter)?);
    let sender = Address::from(decode_hex20(&rcpt_raw.from_address)?);
    let recipient = decode_topic_addr32(&rcpt_raw.to_address)?;
    let receipt_state_proof = StateProof {
        target: ProofTarget::Erc20Transfer {
            tx_index: rcpt_raw.tx_index,
            log_index: rcpt_raw.log_index,
            token_contract: emitter,
            sender,
            recipient,
        },
        account_proof: vec![],
        storage_proof: None,
        receipt_proof: Some(
            rcpt_raw
                .receipt_proof
                .iter()
                .map(|s| decode_hex(s).map(Into::into))
                .collect::<Result<Vec<_>>>()?,
        ),
        account_value: None,
        storage_value: None,
        receipt_value: Some(decode_hex(&rcpt_raw.receipt_rlp)?),
    };
    let transfer_amount_be = decode_hex32(&rcpt_raw.amount_u256_be)?;

    Ok(MainnetBundle {
        checkpoint: decode_hex32(&boot_raw.block_root)?,
        bootstrap_header: (&boot_hdr).into(),
        bootstrap_committee: (&boot_comm).into(),
        bootstrap_committee_branch: boot_comm_branch,
        bootstrap_exec_header: boot_exec.as_ref().map(Into::into),
        bootstrap_exec_branch: boot_exec_branch,
        update: (&core_update).into(),
        witness: (&witness).into(),
        weth_balance_proof: (&weth_balance_state_proof).into(),
        weth_balance_pred: (&Predicate::AtLeast { min: weth_bal_be }).into(),
        weth_storage_proof: (&weth_storage_state_proof).into(),
        weth_storage_pred: (&Predicate::Equal {
            expected: expected_storage_be,
        })
            .into(),
        receipt_proof: (&receipt_state_proof).into(),
        receipt_pred: (&Predicate::Equal {
            expected: transfer_amount_be,
        })
            .into(),
        finalized_slot: finalized.slot,
        exec_block_number: exec_raw.block_number,
    })
}
