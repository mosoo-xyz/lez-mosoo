//! mosoo-daemon — permissionless update-submission service.
//!
//! Runs continuously, watching Ethereum for new finalized headers and
//! submitting the corresponding light-client update to the Mosoo LEZ
//! instance via three transactions (Begin → Miller → Finish).
//!
//! **Permissionless design:** anyone can run this daemon. Multiple operators
//! running simultaneously is fine — the LEZ program is idempotent and the
//! randomized jitter delay reduces the chance of duplicate submissions.

use alloy::signers::Signer;
use clap::Parser;
use mosoo_core::types::{
    BeaconBlockHeader, ExecutionPayloadHeader, LightClientUpdate, SyncAggregate, SyncCommittee,
};
use rand::Rng;
use serde::Deserialize;
use sha2::Digest;
use std::time::Duration;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug, Clone)]
#[command(
    name = "mosoo-daemon",
    about = "Permissionless Ethereum -> LEZ consensus update submitter for Mosoo",
    version
)]
pub struct Cli {
    /// Ethereum Beacon Node (consensus layer) RPC endpoint.
    /// Must support the standard Ethereum Beacon API (/eth/v1/beacon/...)
    #[arg(
        long,
        env = "ETH_CONSENSUS_RPC",
        default_value = "https://lodestar-sepolia.chainsafe.io"
    )]
    pub eth_consensus_rpc: String,

    /// Ethereum Execution Layer RPC endpoint.
    #[arg(
        long,
        env = "ETH_EXECUTION_RPC",
        default_value = "https://rpc.sepolia.org"
    )]
    pub eth_execution_rpc: String,

    /// EIP-155 chain ID of the Ethereum network to track (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi, 17000 = Holesky).
    #[arg(long, env = "ETH_CHAIN_ID", default_value = "11155111")]
    pub eth_chain_id: u64,

    /// LEZ sequencer JSON-RPC URL (defaults to local sequencer at http://127.0.0.1:8545).
    #[arg(long, env = "LEZ_RPC_URL", default_value = "http://127.0.0.1:8545")]
    pub lez_rpc_url: String,

    /// Hex-encoded private key of the LEZ wallet for gas payments and transaction envelope signing.
    /// In live daemon operation, this must be provided by the operator.
    #[arg(long, env = "LEZ_PRIVATE_KEY")]
    pub lez_private_key: Option<String>,

    /// Logos Ethereum Core module verified-proxy endpoint.
    /// In compliance with Logos RFP-021, defaults to the official Logos Core Ethereum proxy catalog service.
    /// Can be overridden or routed directly to a custom beacon node via CLI flags or env vars.
    #[arg(
        long,
        env = "LOGOS_ETHEREUM_CORE_RPC",
        default_value = "https://ethereum-core.logos.co"
    )]
    pub logos_ethereum_core_rpc: Option<String>,

    /// Polling interval in seconds.
    #[arg(long, env = "POLL_INTERVAL_SECS", default_value = "60")]
    pub poll_interval_secs: u64,

    /// Log format: "json" or "pretty".
    #[arg(long, env = "LOG_FORMAT", default_value = "json")]
    pub log_format: String,

    /// Log level.
    #[arg(long, env = "RUST_LOG", default_value = "mosoo_daemon=info,warn")]
    pub log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Guard: Validate chain ID alignment against supported networks
    if !mosoo_core::crypto::is_supported_chain(cli.eth_chain_id) {
        anyhow::bail!(
            "Chain ID {} is not supported by mosoo-core. Supported networks: Ethereum Mainnet (1), Sepolia (11155111), Hoodi (560048), Holesky (17000)",
            cli.eth_chain_id
        );
    }

    let filter = EnvFilter::try_new(&cli.log_level).unwrap_or_else(|_| EnvFilter::new("info"));
    if cli.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt()
            .pretty()
            .with_env_filter(filter)
            .init();
    }

    info!(
        chain_id = cli.eth_chain_id,
        consensus_rpc = %cli.eth_consensus_rpc,
        lez_rpc = %cli.lez_rpc_url,
        poll_secs = cli.poll_interval_secs,
        "Mosoo consensus update daemon started"
    );

    run_daemon(&cli).await
}

pub async fn run_daemon(cli: &Cli) -> anyhow::Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .build()?;

    if cli.lez_private_key.is_none() {
        warn!("LEZ_PRIVATE_KEY is not specified; daemon will run in dry-run/read-only mode");
    }

    info!("Consensus updater event loop running; listening for shutdown signals (SIGINT / Ctrl+C)");

    tokio::select! {
        res = daemon_loop(cli, &client) => res,
        _ = tokio::signal::ctrl_c() => {
            info!("Shutdown signal received (SIGINT / Ctrl+C); terminating updater daemon gracefully");
            Ok(())
        }
    }
}

async fn daemon_loop(cli: &Cli, client: &reqwest::Client) -> anyhow::Result<()> {
    loop {
        match try_submit_update(cli, client).await {
            Ok(SubmitResult::Submitted { slot }) => {
                info!(
                    slot = slot,
                    "Successfully finalized consensus update on LEZ"
                );
            }
            Ok(SubmitResult::AlreadyUpToDate { lez_slot, eth_slot }) => {
                info!(
                    lez_slot = lez_slot,
                    eth_slot = eth_slot,
                    "LEZ instance is up to date"
                );
            }
            Ok(SubmitResult::JobAlreadyOpen { slot }) => {
                info!(
                    slot = slot,
                    "Verification job already open on LEZ by peer operator; skipping"
                );
            }
            Err(e) => {
                let err_msg = e.to_string();
                if err_msg.contains("JobAlreadyOpen") {
                    info!("Verification job already open on LEZ by peer operator; skipping");
                } else {
                    error!(error = %e, "Transient failure in update loop; applying retry backoff");
                }
            }
        }

        let jitter = rand::thread_rng().gen_range(1.0_f64..=2.5_f64);
        let wait = Duration::from_secs_f64(cli.poll_interval_secs as f64 * jitter);
        info!(
            wait_secs = wait.as_secs(),
            "Sleeping until next poll interval"
        );
        tokio::time::sleep(wait).await;
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubmitResult {
    Submitted { slot: u64 },
    AlreadyUpToDate { lez_slot: u64, eth_slot: u64 },
    JobAlreadyOpen { slot: u64 },
}

pub async fn try_submit_update(
    cli: &Cli,
    client: &reqwest::Client,
) -> anyhow::Result<SubmitResult> {
    // 1. Reliability guard: check if an unfinalized job from a previous crashed/restarted daemon is pending completion
    match query_active_job(cli, client).await {
        Ok(Some(open_job)) => {
            info!(
                job_nonce = open_job.job_nonce,
                stage = %open_job.stage,
                "Resuming uncompleted consensus job from prior session"
            );
            return resume_open_job(cli, client, open_job).await;
        }
        Ok(None) => {}
        Err(e) => {
            tracing::warn!("Active job query returned error (proceeding): {}", e);
        }
    }

    let lez_head_slot = fetch_lez_head_slot(cli, client).await?;
    let eth_finalized_slot = fetch_eth_finalized_slot(cli, client).await?;

    if eth_finalized_slot <= lez_head_slot {
        return Ok(SubmitResult::AlreadyUpToDate {
            lez_slot: lez_head_slot,
            eth_slot: eth_finalized_slot,
        });
    }

    info!(
        current_lez_slot = lez_head_slot,
        target_eth_slot = eth_finalized_slot,
        "Fetching Beacon light client finality update"
    );

    let update = fetch_light_client_update(cli, client, lez_head_slot, eth_finalized_slot).await?;

    info!(slot = eth_finalized_slot, "Submitting Tx 1/3: BeginUpdate");
    let job_nonce = match submit_begin(cli, client, &update).await {
        Ok(nonce) => nonce,
        Err(e) if e.to_string().contains("JobAlreadyOpen") => {
            if let Some(open_job) = query_active_job(cli, client).await? {
                info!(
                    job_nonce = open_job.job_nonce,
                    stage = %open_job.stage,
                    "Detected open verification job on LEZ; resuming completion"
                );
                return resume_open_job(cli, client, open_job).await;
            }
            return Ok(SubmitResult::JobAlreadyOpen {
                slot: eth_finalized_slot,
            });
        }
        Err(e) => return Err(e),
    };

    tokio::time::sleep(Duration::from_millis(500)).await;

    info!(job_nonce = job_nonce, "Submitting Tx 2/3: MillerUpdate");
    submit_miller(cli, client, job_nonce).await?;

    tokio::time::sleep(Duration::from_millis(500)).await;

    info!(job_nonce = job_nonce, "Submitting Tx 3/3: FinishUpdate");
    submit_finish(cli, client, job_nonce).await?;

    Ok(SubmitResult::Submitted {
        slot: eth_finalized_slot,
    })
}

#[derive(Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OpenJobStatus {
    pub job_nonce: u64,
    pub stage: String,
    pub target_slot: u64,
}

pub async fn query_active_job(
    cli: &Cli,
    client: &reqwest::Client,
) -> anyhow::Result<Option<OpenJobStatus>> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "lez_getActiveJob",
        "params": [cli.eth_chain_id],
        "id": 10
    });

    let resp = client
        .post(&cli.lez_rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Network error querying active job from LEZ RPC {}: {}",
                cli.lez_rpc_url,
                e
            )
        })?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "LEZ RPC returned HTTP {} when querying active job",
            resp.status()
        );
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| {
        anyhow::anyhow!("Failed parsing JSON response from lez_getActiveJob: {}", e)
    })?;

    if let Some(err) = json.get("error").filter(|v| !v.is_null()) {
        anyhow::bail!("LEZ RPC error on lez_getActiveJob: {}", err);
    }

    if let Some(result) = json.get("result").filter(|v| !v.is_null()) {
        if let Some(nonce) = result.get("job_nonce").and_then(|n| n.as_u64()) {
            let stage = result
                .get("stage")
                .and_then(|s| s.as_str())
                .ok_or_else(|| {
                    anyhow::anyhow!("Active job payload missing mandatory 'stage' field")
                })?
                .to_string();
            let target_slot = result
                .get("target_slot")
                .and_then(|s| s.as_u64())
                .ok_or_else(|| {
                    anyhow::anyhow!("Active job payload missing mandatory 'target_slot' field")
                })?;
            return Ok(Some(OpenJobStatus {
                job_nonce: nonce,
                stage,
                target_slot,
            }));
        }
    }
    Ok(None)
}

pub async fn resume_open_job(
    cli: &Cli,
    client: &reqwest::Client,
    job: OpenJobStatus,
) -> anyhow::Result<SubmitResult> {
    info!(
        job_nonce = job.job_nonce,
        stage = %job.stage,
        target_slot = job.target_slot,
        "Resuming unfinalized verification job from previous daemon run"
    );

    match job.stage.as_str() {
        "begin" | "miller" => {
            info!(job_nonce = job.job_nonce, "Resuming Tx 2/3: MillerUpdate");
            submit_miller(cli, client, job.job_nonce).await?;
            tokio::time::sleep(Duration::from_millis(500)).await;

            info!(job_nonce = job.job_nonce, "Resuming Tx 3/3: FinishUpdate");
            submit_finish(cli, client, job.job_nonce).await?;
            Ok(SubmitResult::Submitted {
                slot: job.target_slot,
            })
        }
        "finish" => {
            info!(job_nonce = job.job_nonce, "Resuming Tx 3/3: FinishUpdate");
            submit_finish(cli, client, job.job_nonce).await?;
            Ok(SubmitResult::Submitted {
                slot: job.target_slot,
            })
        }
        other => {
            anyhow::bail!("Unrecognized open job stage: {}", other);
        }
    }
}

// Ethereum Beacon REST API Response Models

#[derive(Deserialize, Debug)]
struct BeaconHeaderResponse {
    data: BeaconHeaderData,
}

#[derive(Deserialize, Debug)]
struct BeaconHeaderData {
    header: BeaconHeaderMessageWrap,
}

#[derive(Deserialize, Debug)]
struct BeaconHeaderMessageWrap {
    message: BeaconHeaderMessage,
}

#[derive(Deserialize, Debug)]
struct BeaconHeaderMessage {
    slot: String,
}

#[derive(Deserialize, Debug)]
pub struct FinalityUpdateResponse {
    pub data: FinalityUpdateData,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum UpdateItemWrapper {
    Versioned {
        #[serde(default)]
        version: Option<String>,
        data: FinalityUpdateData,
    },
    Direct(FinalityUpdateData),
}

#[derive(Deserialize, Debug)]
pub struct LightClientUpdatesResponse {
    pub data: Vec<UpdateItemWrapper>,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
pub enum UpdatesApiResponse {
    Array(Vec<UpdateItemWrapper>),
    Wrapped(LightClientUpdatesResponse),
}

#[derive(Deserialize, Debug)]
pub struct FinalityUpdateData {
    attested_header: BeaconHeaderObj,
    finalized_header: BeaconHeaderObj,
    finality_branch: Vec<String>,
    sync_aggregate: SyncAggregateObj,
    signature_slot: String,
    #[serde(default)]
    next_sync_committee: Option<SyncCommitteeObj>,
    #[serde(default)]
    next_sync_committee_branch: Option<Vec<String>>,
    #[serde(default)]
    execution_payload_header: Option<ExecutionPayloadHeaderObj>,
    #[serde(default)]
    execution_branch: Option<Vec<String>>,
    #[serde(default)]
    execution_rlp: Option<String>,
}

#[derive(Deserialize, Debug, Clone)]
struct SyncCommitteeObj {
    pubkeys: Vec<String>,
    aggregate_pubkey: String,
}

#[derive(Deserialize, Debug, Clone)]
struct ExecutionPayloadHeaderObj {
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
    #[serde(default)]
    withdrawals_root: Option<String>,
    #[serde(default)]
    blob_gas_used: Option<String>,
    #[serde(default)]
    excess_blob_gas: Option<String>,
}

#[derive(Deserialize, Debug)]
struct BeaconHeaderObj {
    beacon: BeaconHeaderFields,
    #[serde(default)]
    execution: Option<ExecutionPayloadHeaderObj>,
    #[serde(default)]
    execution_block_hash: Option<String>,
    #[serde(default)]
    execution_branch: Option<Vec<String>>,
}

#[derive(Deserialize, Debug)]
struct BeaconHeaderFields {
    slot: String,
    proposer_index: String,
    parent_root: String,
    state_root: String,
    body_root: String,
}

#[derive(Deserialize, Debug)]
struct SyncAggregateObj {
    sync_committee_bits: String,
    sync_committee_signature: String,
}

// Production RPC & REST Implementations

/// Fetch current finalized slot tracked by the Mosoo instance on LEZ via JSON-RPC.
pub async fn fetch_lez_head_slot(cli: &Cli, client: &reqwest::Client) -> anyhow::Result<u64> {
    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "lez_getInstanceSlot",
        "params": [cli.eth_chain_id],
        "id": 1
    });

    let resp = client
        .post(&cli.lez_rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("LEZ endpoint unreachable at {}: {}", cli.lez_rpc_url, e))?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "LEZ endpoint returned HTTP {}: {}",
            resp.status(),
            cli.lez_rpc_url
        );
    }

    let json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse LEZ slot response: {}", e))?;

    if let Some(err) = json.get("error") {
        anyhow::bail!("LEZ RPC returned error for lez_getInstanceSlot: {}", err);
    }

    json.get("result").and_then(|r| r.as_u64()).ok_or_else(|| {
        anyhow::anyhow!(
            "Invalid slot in LEZ RPC response from {}: {:?}",
            cli.lez_rpc_url,
            json
        )
    })
}

/// Derive the appropriate URL for consensus layer requests.
/// When `logos_ethereum_core_rpc` is configured, routes through Logos Ethereum Core verified proxy.
/// Otherwise, falls back to direct Ethereum consensus RPC endpoints.
pub fn derive_consensus_url(cli: &Cli, path_suffix: &str) -> String {
    if let Some(ref proxy) = cli.logos_ethereum_core_rpc {
        format!(
            "{}/v1/ethereum-core/consensus/{}",
            proxy.trim_end_matches('/'),
            path_suffix.trim_start_matches('/')
        )
    } else {
        format!(
            "{}/eth/v1/beacon/{}",
            cli.eth_consensus_rpc.trim_end_matches('/'),
            path_suffix.trim_start_matches('/')
        )
    }
}

/// Query standard Ethereum Beacon Node REST API (or Logos Ethereum Core verified proxy) for finalized block header.
pub async fn fetch_eth_finalized_slot(cli: &Cli, client: &reqwest::Client) -> anyhow::Result<u64> {
    let url = derive_consensus_url(cli, "headers/finalized");
    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow::anyhow!("Consensus endpoint unreachable at {}: {}", url, e))?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Consensus endpoint returned HTTP {} at {}",
            resp.status(),
            url
        );
    }

    let body: BeaconHeaderResponse = resp.json().await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse finalized beacon header from {}: {}",
            url,
            e
        )
    })?;
    let slot: u64 = body
        .data
        .header
        .message
        .slot
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse beacon slot string: {}", e))?;
    Ok(slot)
}

/// Fetch real LightClientUpdate from Ethereum Beacon API or Logos Ethereum Core proxy.
/// Following Ethereum light client specifications:
/// - When staying within the current sync committee period (`to_period == from_period`), queries `/light_client/finality_update`.
/// - When crossing a sync committee period boundary (`to_period > from_period`), queries `/light_client/updates?start_period={from_period}&count=1`
///   to obtain `next_sync_committee` and its Merkle authentication branch.
pub async fn fetch_light_client_update(
    cli: &Cli,
    client: &reqwest::Client,
    from_slot: u64,
    to_slot: u64,
) -> anyhow::Result<LightClientUpdate> {
    let from_period = mosoo_core::types::compute_sync_committee_period(from_slot);
    let to_period = mosoo_core::types::compute_sync_committee_period(to_slot);

    if to_period > from_period {
        info!(
            from_period = from_period,
            to_period = to_period,
            "Sync committee period boundary transition detected; querying /light_client/updates for next_sync_committee"
        );
        let url = derive_consensus_url(
            cli,
            &format!("light_client/updates?start_period={}&count=1", from_period),
        );
        match fetch_updates_from_url(client, &url).await {
            Ok(update) => return Ok(update),
            Err(e) => {
                anyhow::bail!(
                    "Sync committee period transition required from period {} to {}, but query to {} failed: {}. Refusing to fall back to finality_update without next_sync_committee.",
                    from_period,
                    to_period,
                    url,
                    e
                );
            }
        }
    }

    let url = derive_consensus_url(cli, "light_client/finality_update");
    let resp = client.get(&url).send().await.map_err(|e| {
        anyhow::anyhow!(
            "Consensus light client update endpoint unreachable at {}: {}",
            url,
            e
        )
    })?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Consensus light client update endpoint returned HTTP {} at {}",
            resp.status(),
            url
        );
    }

    let body: FinalityUpdateResponse = resp.json().await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to parse light client finality update from {}: {}",
            url,
            e
        )
    })?;
    parse_beacon_update(body)
}

async fn fetch_updates_from_url(
    client: &reqwest::Client,
    url: &str,
) -> anyhow::Result<LightClientUpdate> {
    let resp = client.get(url).send().await.map_err(|e| {
        anyhow::anyhow!(
            "Light client updates endpoint unreachable at {}: {}",
            url,
            e
        )
    })?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "Light client updates endpoint returned HTTP {} at {}",
            resp.status(),
            url
        );
    }

    let raw_text = resp.text().await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to read light client updates body from {}: {}",
            url,
            e
        )
    })?;
    parse_updates_json(&raw_text)
        .map_err(|e| anyhow::anyhow!("Failed to parse light client updates from {}: {}", url, e))
}

fn parse_update_items(items: Vec<UpdateItemWrapper>) -> anyhow::Result<LightClientUpdate> {
    let first = items
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty updates array returned by beacon node"))?;
    let data = match first {
        UpdateItemWrapper::Versioned { data, .. } => data,
        UpdateItemWrapper::Direct(data) => data,
    };
    parse_beacon_update_data(data)
}

/// Parse Beacon API `/eth/v1/beacon/light_client/updates` JSON accepting both bare JSON arrays
/// (`[{version, data}, ...]`, standard Beacon REST API) and `{"data": [...]}` wrappers.
pub fn parse_updates_json(raw: &str) -> anyhow::Result<LightClientUpdate> {
    let res: UpdatesApiResponse = serde_json::from_str(raw)?;
    let items = match res {
        UpdatesApiResponse::Array(items) => items,
        UpdatesApiResponse::Wrapped(wrapped) => wrapped.data,
    };
    parse_update_items(items)
}

/// Parse Beacon API updates list response into a native Mosoo `LightClientUpdate`.
pub fn parse_beacon_updates_response(
    res: LightClientUpdatesResponse,
) -> anyhow::Result<LightClientUpdate> {
    parse_update_items(res.data)
}

/// Parse standard Beacon API finality update response into native Mosoo types.
pub fn parse_beacon_update(res: FinalityUpdateResponse) -> anyhow::Result<LightClientUpdate> {
    parse_beacon_update_data(res.data)
}

fn parse_base_fee_per_gas(s: &str) -> anyhow::Result<[u8; 32]> {
    let trimmed = s.trim();
    if trimmed.starts_with("0x") || trimmed.starts_with("0X") {
        hex_to_32(trimmed)
    } else {
        let val = alloy::primitives::U256::from_str_radix(trimmed, 10).map_err(|e| {
            anyhow::anyhow!("Failed to parse decimal base_fee_per_gas '{trimmed}': {e}")
        })?;
        Ok(val.to_le_bytes::<32>())
    }
}

/// Parse raw Beacon update data into native Mosoo types.
/// Supports both synthetic flat fields and real Beacon REST API nested header execution fields
/// (Altair–Fulu `finalized_header.execution` + decimal `base_fee_per_gas`, and Gloas ePBS `execution_block_hash`).
pub fn parse_beacon_update_data(d: FinalityUpdateData) -> anyhow::Result<LightClientUpdate> {
    let attested = parse_header(&d.attested_header.beacon)?;
    let finalized = parse_header(&d.finalized_header.beacon)?;

    let bits = hex::decode(
        d.sync_aggregate
            .sync_committee_bits
            .trim_start_matches("0x"),
    )?;
    let sig = hex::decode(
        d.sync_aggregate
            .sync_committee_signature
            .trim_start_matches("0x"),
    )?;

    let mut finality_branch = Vec::with_capacity(d.finality_branch.len());
    for b in d.finality_branch {
        finality_branch.push(hex_to_32(&b)?);
    }

    let exec_payload_obj = d.execution_payload_header.or(d.finalized_header.execution);
    let exec_branch_strs = d.execution_branch.or(d.finalized_header.execution_branch);

    let execution_payload_header =
        if let Some(p) = exec_payload_obj {
            Some(ExecutionPayloadHeader {
                parent_hash: hex_to_32(&p.parent_hash)?,
                fee_recipient: hex_to_20(&p.fee_recipient)?,
                state_root: hex_to_32(&p.state_root)?,
                receipts_root: hex_to_32(&p.receipts_root)?,
                logs_bloom: hex::decode(p.logs_bloom.trim_start_matches("0x")).map_err(|e| {
                    anyhow::anyhow!("Failed to parse execution payload logs_bloom hex: {e}")
                })?,
                prev_randao: hex_to_32(&p.prev_randao)?,
                block_number: p.block_number.parse().map_err(|e| {
                    anyhow::anyhow!("Failed to parse execution payload block_number: {e}")
                })?,
                gas_limit: p.gas_limit.parse().map_err(|e| {
                    anyhow::anyhow!("Failed to parse execution payload gas_limit: {e}")
                })?,
                gas_used: p.gas_used.parse().map_err(|e| {
                    anyhow::anyhow!("Failed to parse execution payload gas_used: {e}")
                })?,
                timestamp: p.timestamp.parse().map_err(|e| {
                    anyhow::anyhow!("Failed to parse execution payload timestamp: {e}")
                })?,
                extra_data: hex::decode(p.extra_data.trim_start_matches("0x")).map_err(|e| {
                    anyhow::anyhow!("Failed to parse execution payload extra_data hex: {e}")
                })?,
                base_fee_per_gas: parse_base_fee_per_gas(&p.base_fee_per_gas)?,
                block_hash: hex_to_32(&p.block_hash)?,
                transactions_root: hex_to_32(&p.transactions_root)?,
                withdrawals_root: p.withdrawals_root.as_deref().map(hex_to_32).transpose()?,
                blob_gas_used: p
                    .blob_gas_used
                    .as_deref()
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to parse execution payload blob_gas_used: {e}")
                    })?,
                excess_blob_gas: p
                    .excess_blob_gas
                    .as_deref()
                    .map(|s| s.parse())
                    .transpose()
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to parse execution payload excess_blob_gas: {e}")
                    })?,
            })
        } else if let Some(ref block_hash_hex) = d.finalized_header.execution_block_hash {
            Some(ExecutionPayloadHeader {
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
                block_hash: hex_to_32(block_hash_hex)?,
                transactions_root: [0u8; 32],
                withdrawals_root: None,
                blob_gas_used: None,
                excess_blob_gas: None,
            })
        } else {
            None
        };

    let execution_branch = if let Some(eb) = exec_branch_strs {
        let mut branch = Vec::new();
        for b in eb {
            branch.push(hex_to_32(&b)?);
        }
        Some(branch)
    } else {
        None
    };

    let next_sync_committee = if let Some(nsc) = d.next_sync_committee {
        let mut pubkeys = Vec::with_capacity(nsc.pubkeys.len());
        for pk_str in nsc.pubkeys {
            let pk = hex::decode(pk_str.trim_start_matches("0x"))
                .map_err(|e| anyhow::anyhow!("Invalid sync committee pubkey hex: {e}"))?;
            if pk.len() != 48 {
                anyhow::bail!("Sync committee pubkey must be 48 bytes, got {}", pk.len());
            }
            pubkeys.push(pk);
        }
        let agg_pk = hex::decode(nsc.aggregate_pubkey.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid aggregate pubkey hex: {e}"))?;
        if agg_pk.len() != 48 {
            anyhow::bail!("Aggregate pubkey must be 48 bytes, got {}", agg_pk.len());
        }
        Some(SyncCommittee {
            pubkeys,
            aggregate_pubkey: agg_pk,
        })
    } else {
        None
    };

    let next_sync_committee_branch = if let Some(branch_strs) = d.next_sync_committee_branch {
        let mut branch = Vec::with_capacity(branch_strs.len());
        for b in branch_strs {
            branch.push(hex_to_32(&b)?);
        }
        Some(branch)
    } else {
        None
    };

    let execution_rlp = if let Some(rlp_str) = d.execution_rlp {
        let rlp_bytes = hex::decode(rlp_str.trim_start_matches("0x"))
            .map_err(|e| anyhow::anyhow!("Invalid execution RLP hex: {e}"))?;
        Some(rlp_bytes)
    } else {
        None
    };

    Ok(LightClientUpdate {
        attested_header: attested,
        next_sync_committee,
        next_sync_committee_branch,
        finalized_header: finalized,
        finality_branch,
        sync_aggregate: SyncAggregate {
            sync_committee_bits: bits,
            sync_committee_signature: sig,
        },
        signature_slot: d
            .signature_slot
            .parse()
            .map_err(|e| anyhow::anyhow!("Failed to parse signature_slot: {e}"))?,
        execution_payload_header,
        execution_branch,
        execution_rlp,
    })
}

fn parse_header(f: &BeaconHeaderFields) -> anyhow::Result<BeaconBlockHeader> {
    Ok(BeaconBlockHeader {
        slot: f.slot.parse()?,
        proposer_index: f.proposer_index.parse()?,
        parent_root: hex_to_32(&f.parent_root)?,
        state_root: hex_to_32(&f.state_root)?,
        body_root: hex_to_32(&f.body_root)?,
    })
}

fn hex_to_32(s: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    if bytes.len() != 32 {
        anyhow::bail!("Expected 32 hex bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn hex_to_20(s: &str) -> anyhow::Result<[u8; 20]> {
    let bytes = hex::decode(s.trim_start_matches("0x"))?;
    if bytes.len() != 20 {
        anyhow::bail!("Expected 20 hex bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

// Submissions to LEZ Sequencer

pub async fn submit_begin(
    cli: &Cli,
    client: &reqwest::Client,
    update: &LightClientUpdate,
) -> anyhow::Result<u64> {
    let key = cli.lez_private_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("LEZ_PRIVATE_KEY is required to sign and submit consensus updates to LEZ")
    })?;

    let signer: alloy::signers::local::PrivateKeySigner = key
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid LEZ_PRIVATE_KEY: {e}"))?;
    let sender_address = signer.address();

    let update_json = serde_json::to_string(update)?;
    let update_hex = format!("0x{}", hex::encode(update_json.as_bytes()));

    let tx_digest = {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"lez_tx_v1");
        sha2::Digest::update(
            &mut hasher,
            b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
        );
        sha2::Digest::update(&mut hasher, b"begin_update");
        sha2::Digest::update(&mut hasher, cli.eth_chain_id.to_be_bytes());
        sha2::Digest::update(&mut hasher, update_json.as_bytes());
        alloy::primitives::B256::from_slice(&sha2::Digest::finalize(hasher))
    };

    let sig = signer
        .sign_hash(&tx_digest)
        .await
        .map_err(|e| anyhow::anyhow!("Local transaction signing failed for begin_update: {e}"))?;

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "lez_sendTransaction",
        "params": [{
            "to": "0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
            "instruction": "begin_update",
            "chain_id": cli.eth_chain_id,
            "data": update_hex,
            "from": format!("{:#x}", sender_address),
            "signature": format!("0x{}", hex::encode(sig.as_bytes())),
        }],
        "id": 2
    });

    let resp = client
        .post(&cli.lez_rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to send begin_update to LEZ sequencer at {}: {}",
                cli.lez_rpc_url,
                e
            )
        })?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "LEZ sequencer returned HTTP {} on begin_update",
            resp.status()
        );
    }

    let resp_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse begin_update response: {}", e))?;

    if let Some(err) = resp_json.get("error") {
        let err_str = err.to_string();
        if err_str.contains("JobAlreadyOpen") || err_str.contains("already active") {
            anyhow::bail!("JobAlreadyOpen");
        }
        anyhow::bail!("LEZ RPC execution error on begin_update: {}", err);
    }

    let job_nonce = resp_json
        .get("result")
        .and_then(|r| r.get("job_nonce").or(Some(r)))
        .and_then(|v| v.as_u64())
        .ok_or_else(|| {
            anyhow::anyhow!("LEZ begin_update response missing valid numeric job_nonce in result")
        })?;
    Ok(job_nonce)
}

pub async fn submit_miller(
    cli: &Cli,
    client: &reqwest::Client,
    job_nonce: u64,
) -> anyhow::Result<()> {
    let key = cli.lez_private_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("LEZ_PRIVATE_KEY is required to sign and submit consensus updates to LEZ")
    })?;

    let signer: alloy::signers::local::PrivateKeySigner = key
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid LEZ_PRIVATE_KEY: {e}"))?;
    let sender_address = signer.address();

    let tx_digest = {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"lez_tx_v1");
        sha2::Digest::update(
            &mut hasher,
            b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
        );
        sha2::Digest::update(&mut hasher, b"miller_update");
        sha2::Digest::update(&mut hasher, cli.eth_chain_id.to_be_bytes());
        sha2::Digest::update(&mut hasher, job_nonce.to_be_bytes());
        alloy::primitives::B256::from_slice(&sha2::Digest::finalize(hasher))
    };

    let sig = signer
        .sign_hash(&tx_digest)
        .await
        .map_err(|e| anyhow::anyhow!("Local transaction signing failed for miller_update: {e}"))?;

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "lez_sendTransaction",
        "params": [{
            "to": "0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
            "instruction": "miller_update",
            "chain_id": cli.eth_chain_id,
            "job_nonce": job_nonce,
            "from": format!("{:#x}", sender_address),
            "signature": format!("0x{}", hex::encode(sig.as_bytes())),
        }],
        "id": 3
    });

    let resp = client
        .post(&cli.lez_rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to send miller_update to LEZ sequencer at {}: {}",
                cli.lez_rpc_url,
                e
            )
        })?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "LEZ sequencer returned HTTP {} on miller_update",
            resp.status()
        );
    }

    let resp_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse miller_update response: {}", e))?;

    if let Some(err) = resp_json.get("error") {
        anyhow::bail!("LEZ RPC execution error on miller_update: {}", err);
    }

    let tx_hash = resp_json
        .get("result")
        .and_then(|r| r.as_str())
        .unwrap_or("confirmed");
    info!(job_nonce = job_nonce, tx_hash = %tx_hash, "MillerUpdate transaction confirmed on LEZ sequencer");
    Ok(())
}

pub async fn submit_finish(
    cli: &Cli,
    client: &reqwest::Client,
    job_nonce: u64,
) -> anyhow::Result<()> {
    let key = cli.lez_private_key.as_deref().ok_or_else(|| {
        anyhow::anyhow!("LEZ_PRIVATE_KEY is required to sign and submit consensus updates to LEZ")
    })?;

    let signer: alloy::signers::local::PrivateKeySigner = key
        .trim()
        .parse()
        .map_err(|e| anyhow::anyhow!("Invalid LEZ_PRIVATE_KEY: {e}"))?;
    let sender_address = signer.address();

    let tx_digest = {
        let mut hasher = sha2::Sha256::new();
        sha2::Digest::update(&mut hasher, b"lez_tx_v1");
        sha2::Digest::update(
            &mut hasher,
            b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
        );
        sha2::Digest::update(&mut hasher, b"finish_update");
        sha2::Digest::update(&mut hasher, cli.eth_chain_id.to_be_bytes());
        sha2::Digest::update(&mut hasher, job_nonce.to_be_bytes());
        alloy::primitives::B256::from_slice(&sha2::Digest::finalize(hasher))
    };

    let sig = signer
        .sign_hash(&tx_digest)
        .await
        .map_err(|e| anyhow::anyhow!("Local transaction signing failed for finish_update: {e}"))?;

    let payload = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "lez_sendTransaction",
        "params": [{
            "to": "0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
            "instruction": "finish_update",
            "chain_id": cli.eth_chain_id,
            "job_nonce": job_nonce,
            "from": format!("{:#x}", sender_address),
            "signature": format!("0x{}", hex::encode(sig.as_bytes())),
        }],
        "id": 4
    });

    let resp = client
        .post(&cli.lez_rpc_url)
        .json(&payload)
        .send()
        .await
        .map_err(|e| {
            anyhow::anyhow!(
                "Failed to send finish_update to LEZ sequencer at {}: {}",
                cli.lez_rpc_url,
                e
            )
        })?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "LEZ sequencer returned HTTP {} on finish_update",
            resp.status()
        );
    }

    let resp_json: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse finish_update response: {}", e))?;

    if let Some(err) = resp_json.get("error") {
        anyhow::bail!("LEZ RPC execution error on finish_update: {}", err);
    }

    let tx_hash = resp_json
        .get("result")
        .and_then(|r| r.as_str())
        .unwrap_or("confirmed");
    info!(job_nonce = job_nonce, tx_hash = %tx_hash, "FinishUpdate transaction finalized on LEZ sequencer");
    Ok(())
}

#[cfg(test)]
mod tests;
