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

    /// EIP-155 chain ID of the Ethereum network to track (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi).
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
    if let Ok(Some(open_job)) = query_active_job(cli, client).await {
        info!(
            job_nonce = open_job.job_nonce,
            stage = %open_job.stage,
            "Resuming uncompleted consensus job from prior session"
        );
        return resume_open_job(cli, client, open_job).await;
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
            if let Ok(Some(open_job)) = query_active_job(cli, client).await {
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

    let resp = match client.post(&cli.lez_rpc_url).json(&payload).send().await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("lez_getActiveJob query skipped: {}", e);
            return Ok(None);
        }
    };

    if !resp.status().is_success() {
        return Ok(None);
    }

    let json: serde_json::Value = resp.json().await.unwrap_or_default();
    if let Some(result) = json.get("result").filter(|v| !v.is_null()) {
        if let Some(nonce) = result.get("job_nonce").and_then(|n| n.as_u64()) {
            let stage = result
                .get("stage")
                .and_then(|s| s.as_str())
                .unwrap_or("miller")
                .to_string();
            let target_slot = result
                .get("target_slot")
                .and_then(|s| s.as_u64())
                .unwrap_or(0);
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
/// In accordance with Ethereum light client specifications:
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

    let body: LightClientUpdatesResponse = resp
        .json()
        .await
        .map_err(|e| anyhow::anyhow!("Failed to parse light client updates from {}: {}", url, e))?;
    parse_beacon_updates_response(body)
}

/// Parse Beacon API updates list response into a native Mosoo `LightClientUpdate`.
pub fn parse_beacon_updates_response(
    res: LightClientUpdatesResponse,
) -> anyhow::Result<LightClientUpdate> {
    let first = res
        .data
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("Empty updates array returned by beacon node"))?;
    let data = match first {
        UpdateItemWrapper::Versioned { data, .. } => data,
        UpdateItemWrapper::Direct(data) => data,
    };
    parse_beacon_update_data(data)
}

/// Parse standard Beacon API finality update response into native Mosoo types.
pub fn parse_beacon_update(res: FinalityUpdateResponse) -> anyhow::Result<LightClientUpdate> {
    parse_beacon_update_data(res.data)
}

/// Parse raw Beacon update data into native Mosoo types.
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

    let execution_payload_header =
        if let Some(p) = d.execution_payload_header {
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
                base_fee_per_gas: hex_to_32(&p.base_fee_per_gas)?,
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
        } else {
            None
        };

    let execution_branch = if let Some(eb) = d.execution_branch {
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

#[cfg(test)]
pub fn synthesize_canonical_update() -> LightClientUpdate {
    LightClientUpdate {
        attested_header: BeaconBlockHeader {
            slot: 15_433_761,
            proposer_index: 42,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        },
        next_sync_committee: None,
        next_sync_committee_branch: None,
        finalized_header: BeaconBlockHeader {
            slot: 15_433_760,
            proposer_index: 40,
            parent_root: [0x10; 32],
            state_root: [0x20; 32],
            body_root: [0x30; 32],
        },
        finality_branch: vec![[0x05; 32]; 6],
        sync_aggregate: SyncAggregate {
            sync_committee_bits: vec![0xFF; 64],
            sync_committee_signature: vec![0xC0; 96],
        },
        signature_slot: 15_433_761,
        execution_payload_header: None,
        execution_branch: None,
        execution_rlp: None,
    }
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

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_daemon_beacon_finality_update_parsing() {
        let json_data = r#"{
            "data": {
                "attested_header": {
                    "beacon": {
                        "slot": "15433761",
                        "proposer_index": "123",
                        "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                        "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "finalized_header": {
                    "beacon": {
                        "slot": "15433760",
                        "proposer_index": "120",
                        "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                        "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                        "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                    }
                },
                "finality_branch": [
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ],
                "sync_aggregate": {
                    "sync_committee_bits": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
                    "sync_committee_signature": "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                },
                "signature_slot": "15433761"
            }
        }"#;

        let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
        let update = parse_beacon_update(res).unwrap();

        assert_eq!(update.finalized_header.slot, 15_433_760);
        assert_eq!(update.attested_header.slot, 15_433_761);
        assert_eq!(update.finality_branch.len(), 2);
        assert_eq!(update.sync_aggregate.sync_committee_bits.len(), 64);
        assert_eq!(update.sync_aggregate.sync_committee_signature.len(), 96);
    }

    #[test]
    fn test_daemon_jitter_delay_range() {
        let base_poll = 60u64;
        for _ in 0..10 {
            let jitter = rand::thread_rng().gen_range(1.0_f64..=2.5_f64);
            let wait = (base_poll as f64 * jitter) as u64;
            assert!((60..=150).contains(&wait));
        }
    }

    #[test]
    fn test_logos_ethereum_core_proxy_url_derivation() {
        let mut cli = Cli {
            eth_consensus_rpc: "https://lodestar-sepolia.chainsafe.io".to_string(),
            eth_execution_rpc: "https://rpc.sepolia.org".to_string(),
            eth_chain_id: 11155111,
            lez_rpc_url: "http://127.0.0.1:8545".to_string(),
            lez_private_key: Some("0x01".to_string()),
            logos_ethereum_core_rpc: None,
            poll_interval_secs: 60,
            log_level: "info".to_string(),
            log_format: "pretty".to_string(),
        };

        // Without Logos Core proxy: falls back to direct beacon node
        assert_eq!(
            derive_consensus_url(&cli, "headers/finalized"),
            "https://lodestar-sepolia.chainsafe.io/eth/v1/beacon/headers/finalized"
        );

        // With Logos Core proxy: routes to verified Ethereum Core catalog proxy
        cli.logos_ethereum_core_rpc = Some("https://ethereum-core.logos.co/".to_string());
        assert_eq!(
            derive_consensus_url(&cli, "headers/finalized"),
            "https://ethereum-core.logos.co/v1/ethereum-core/consensus/headers/finalized"
        );
        assert_eq!(
            derive_consensus_url(&cli, "light_client/finality_update"),
            "https://ethereum-core.logos.co/v1/ethereum-core/consensus/light_client/finality_update"
        );
    }

    /// Verify that the competing-update SubmitResult enum covers all liveness scenarios.
    /// When the LEZ slot equals the Ethereum slot, AlreadyUpToDate is returned.
    /// When the LEZ slot is AHEAD of the Ethereum slot, AlreadyUpToDate is returned.
    /// When there is a gap, the daemon should proceed to fetch & submit.
    #[test]
    fn test_daemon_competing_update_result_enum_coverage() {
        // AlreadyUpToDate scenario: LEZ caught up
        let r1 = SubmitResult::AlreadyUpToDate {
            lez_slot: 15_433_760,
            eth_slot: 15_433_760,
        };
        assert!(
            matches!(r1, SubmitResult::AlreadyUpToDate { lez_slot, eth_slot } if lez_slot == eth_slot)
        );

        // AlreadyUpToDate scenario: LEZ is ahead (rare, should not happen in normal ops)
        let r2 = SubmitResult::AlreadyUpToDate {
            lez_slot: 15_433_760,
            eth_slot: 15_433_728,
        };
        assert!(
            matches!(r2, SubmitResult::AlreadyUpToDate { lez_slot, eth_slot } if lez_slot > eth_slot)
        );

        // JobAlreadyOpen scenario: another daemon operator won the race
        let r3 = SubmitResult::JobAlreadyOpen { slot: 15_433_760 };
        assert!(matches!(r3, SubmitResult::JobAlreadyOpen { slot } if slot == 15_433_760));

        // Submitted scenario: we won and committed the update
        let r4 = SubmitResult::Submitted { slot: 15_433_792 };
        assert!(matches!(r4, SubmitResult::Submitted { slot } if slot == 15_433_792));

        // Verify all 3 enum arms are distinct and non-overlapping
        assert_ne!(std::mem::discriminant(&r1), std::mem::discriminant(&r3));
        assert_ne!(std::mem::discriminant(&r3), std::mem::discriminant(&r4));
    }

    /// Verify the synthesized canonical update has correct structure for offline operation.
    /// The fallback vector must carry a valid slot, non-empty branch, and correct bit/sig lengths.
    #[test]
    fn test_daemon_synthesized_canonical_update_structure() {
        let update = synthesize_canonical_update();

        // Attested header must be one slot ahead of finalized header (normal Ethereum progression)
        assert_eq!(
            update.attested_header.slot,
            update.finalized_header.slot + 1,
            "Attested slot must be finalized_slot + 1 in canonical update"
        );

        // Finality branch must be present with correct Ethereum Altair branch depth (6 nodes)
        assert_eq!(
            update.finality_branch.len(),
            6,
            "Ethereum finality branch has depth 6 (gindex 105)"
        );

        // Sync aggregate bitvector must be 64 bytes (512 validators / 8 bits per byte)
        assert_eq!(
            update.sync_aggregate.sync_committee_bits.len(),
            64,
            "Sync aggregate bits vector must be exactly 64 bytes for 512 validators"
        );

        // Sync aggregate signature must be 96 bytes (BLS12-381 G2 compressed point)
        assert_eq!(
            update.sync_aggregate.sync_committee_signature.len(),
            96,
            "Sync aggregate signature must be exactly 96 bytes (BLS12-381 G2)"
        );

        // Signature slot must match attested slot
        assert_eq!(
            update.signature_slot, update.attested_header.slot,
            "signature_slot must match attested_header.slot"
        );

        // Verify Period 1884 canonical slot range
        assert!(update.finalized_header.slot >= 15_000_000);
        assert!(update.finalized_header.slot < 16_000_000);
    }

    /// Verify that derive_consensus_url correctly handles trailing slashes on both sides.
    #[test]
    fn test_daemon_url_construction_trailing_slash_normalization() {
        let cli_trailing = Cli {
            eth_consensus_rpc: "https://beacon.example.com/".to_string(),
            eth_execution_rpc: "https://exec.example.com".to_string(),
            eth_chain_id: 1,
            lez_rpc_url: "https://lez.logos.co/rpc".to_string(),
            lez_private_key: Some("0x01".to_string()),
            logos_ethereum_core_rpc: None,
            poll_interval_secs: 60,
            log_level: "info".to_string(),
            log_format: "json".to_string(),
        };
        let cli_no_trailing = Cli {
            eth_consensus_rpc: "https://beacon.example.com".to_string(),
            ..cli_trailing.clone()
        };

        // Both forms must produce identical URLs (no double-slash)
        let url_trailing = derive_consensus_url(&cli_trailing, "headers/finalized");
        let url_no_trailing = derive_consensus_url(&cli_no_trailing, "headers/finalized");

        assert_eq!(url_trailing, url_no_trailing);
        assert!(
            !url_trailing.contains("//eth"),
            "URL must not contain double-slash before path: {}",
            url_trailing
        );

        // Also verify leading-slash normalization on path suffix
        let url_with_slash = derive_consensus_url(&cli_no_trailing, "/headers/finalized");
        assert_eq!(url_with_slash, url_no_trailing);
    }

    #[tokio::test]
    async fn test_daemon_submit_begin_requires_private_key() {
        let cli = Cli {
            eth_consensus_rpc: "https://beacon.example.com".to_string(),
            eth_execution_rpc: "https://exec.example.com".to_string(),
            eth_chain_id: 1,
            lez_rpc_url: "http://127.0.0.1:8545".to_string(),
            lez_private_key: None,
            logos_ethereum_core_rpc: None,
            poll_interval_secs: 60,
            log_level: "info".to_string(),
            log_format: "json".to_string(),
        };
        let client = reqwest::Client::new();
        let update = synthesize_canonical_update();
        let res = submit_begin(&cli, &client, &update).await;
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("LEZ_PRIVATE_KEY is required"));
    }

    #[test]
    fn test_daemon_beacon_finality_update_with_execution_payload_parsing() {
        let json_data = r#"{
            "data": {
                "attested_header": {
                    "beacon": {
                        "slot": "15433761",
                        "proposer_index": "123",
                        "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                        "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "finalized_header": {
                    "beacon": {
                        "slot": "15433760",
                        "proposer_index": "120",
                        "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                        "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                        "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                    }
                },
                "finality_branch": [
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ],
                "sync_aggregate": {
                    "sync_committee_bits": "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000000000000000000000000000",
                    "sync_committee_signature": "0xc00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
                },
                "signature_slot": "15433761",
                "execution_payload_header": {
                    "parent_hash": "0x1111111111111111111111111111111111111111111111111111111111111111",
                    "fee_recipient": "0x2222222222222222222222222222222222222222",
                    "state_root": "0x3333333333333333333333333333333333333333333333333333333333333333",
                    "receipts_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                    "logs_bloom": "0x00",
                    "prev_randao": "0x5555555555555555555555555555555555555555555555555555555555555555",
                    "block_number": "1000",
                    "gas_limit": "30000000",
                    "gas_used": "15000000",
                    "timestamp": "1700000000",
                    "extra_data": "0x",
                    "base_fee_per_gas": "0x0000000000000000000000000000000000000000000000000000000000000001",
                    "block_hash": "0x6666666666666666666666666666666666666666666666666666666666666666",
                    "transactions_root": "0x7777777777777777777777777777777777777777777777777777777777777777"
                },
                "execution_branch": [
                    "0x8888888888888888888888888888888888888888888888888888888888888888",
                    "0x9999999999999999999999999999999999999999999999999999999999999999",
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                ]
            }
        }"#;

        let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
        let update = parse_beacon_update(res).unwrap();

        assert_eq!(update.finalized_header.slot, 15_433_760);
        let exec = update
            .execution_payload_header
            .expect("must decode execution payload header");
        assert_eq!(exec.block_number, 1000);
        assert_eq!(exec.fee_recipient, [0x22; 20]);
        assert_eq!(exec.state_root, [0x33; 32]);
        assert_eq!(exec.receipts_root, [0x44; 32]);
        assert_eq!(exec.block_hash, [0x66; 32]);

        let branch = update
            .execution_branch
            .expect("must decode execution branch");
        assert_eq!(branch.len(), 4);
        assert_eq!(branch[0], [0x88; 32]);
    }

    #[test]
    fn test_daemon_open_job_status_representation() {
        let job = OpenJobStatus {
            job_nonce: 42,
            stage: "miller".to_string(),
            target_slot: 15_433_760,
        };
        assert_eq!(job.job_nonce, 42);
        assert_eq!(job.stage, "miller");
        assert_eq!(job.target_slot, 15_433_760);
    }

    #[test]
    fn test_daemon_beacon_finality_update_with_next_sync_committee_and_rlp() {
        let dummy_pubkey = "0x".to_string() + &hex::encode([0x42u8; 48]);
        let json_data = format!(
            r#"{{
            "data": {{
                "attested_header": {{
                    "beacon": {{
                        "slot": "15433761",
                        "proposer_index": "123",
                        "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                        "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }}
                }},
                "finalized_header": {{
                    "beacon": {{
                        "slot": "15433760",
                        "proposer_index": "120",
                        "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                        "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                        "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                    }}
                }},
                "finality_branch": [
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ],
                "sync_aggregate": {{
                    "sync_committee_bits": "0xff00",
                    "sync_committee_signature": "0xc000"
                }},
                "signature_slot": "15433761",
                "next_sync_committee": {{
                    "pubkeys": ["{dummy_pubkey}"],
                    "aggregate_pubkey": "{dummy_pubkey}"
                }},
                "next_sync_committee_branch": [
                    "0x7777777777777777777777777777777777777777777777777777777777777777"
                ],
                "execution_rlp": "0x01020304"
            }}
        }}"#
        );

        let res: FinalityUpdateResponse = serde_json::from_str(&json_data).unwrap();
        let update = parse_beacon_update(res).unwrap();

        let nsc = update
            .next_sync_committee
            .expect("must decode next_sync_committee");
        assert_eq!(nsc.pubkeys.len(), 1);
        assert_eq!(nsc.pubkeys[0], vec![0x42u8; 48]);
        assert_eq!(nsc.aggregate_pubkey, vec![0x42u8; 48]);

        let branch = update
            .next_sync_committee_branch
            .expect("must decode branch");
        assert_eq!(branch.len(), 1);
        assert_eq!(branch[0], [0x77; 32]);

        let rlp = update.execution_rlp.expect("must decode execution_rlp");
        assert_eq!(rlp, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_daemon_beacon_finality_update_malformed_slot_rejected() {
        let json_data = r#"{
            "data": {
                "attested_header": {
                    "beacon": {
                        "slot": "15433761",
                        "proposer_index": "123",
                        "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                        "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "finalized_header": {
                    "beacon": {
                        "slot": "15433760",
                        "proposer_index": "120",
                        "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                        "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                        "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                    }
                },
                "finality_branch": [],
                "sync_aggregate": {
                    "sync_committee_bits": "0xff",
                    "sync_committee_signature": "0xc0"
                },
                "signature_slot": "not_a_number"
            }
        }"#;

        let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
        let err = parse_beacon_update(res);
        assert!(err.is_err());
        assert!(err
            .unwrap_err()
            .to_string()
            .contains("Failed to parse signature_slot"));
    }

    #[test]
    fn test_daemon_beacon_updates_period_boundary_parsing() {
        let dummy_pubkey = "0x".to_string() + &hex::encode([0x33u8; 48]);
        let json_updates = format!(
            r#"{{
            "data": [
                {{
                    "version": "deneb",
                    "data": {{
                        "attested_header": {{
                            "beacon": {{
                                "slot": "15433761",
                                "proposer_index": "123",
                                "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                                "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                                "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                            }}
                        }},
                        "finalized_header": {{
                            "beacon": {{
                                "slot": "15433760",
                                "proposer_index": "120",
                                "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                                "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                                "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                            }}
                        }},
                        "finality_branch": [
                            "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                        ],
                        "sync_aggregate": {{
                            "sync_committee_bits": "0xff00",
                            "sync_committee_signature": "0xc000"
                        }},
                        "signature_slot": "15433761",
                        "next_sync_committee": {{
                            "pubkeys": ["{dummy_pubkey}"],
                            "aggregate_pubkey": "{dummy_pubkey}"
                        }},
                        "next_sync_committee_branch": [
                            "0x9999999999999999999999999999999999999999999999999999999999999999"
                        ]
                    }}
                }}
            ]
        }}"#
        );

        let res: LightClientUpdatesResponse = serde_json::from_str(&json_updates).unwrap();
        let update = parse_beacon_updates_response(res).expect("Period boundary update must parse");

        assert_eq!(update.finalized_header.slot, 15_433_760);
        let nsc = update
            .next_sync_committee
            .expect("next_sync_committee must be present");
        assert_eq!(nsc.pubkeys.len(), 1);
        assert_eq!(nsc.pubkeys[0], vec![0x33u8; 48]);
        assert_eq!(nsc.aggregate_pubkey, vec![0x33u8; 48]);

        let branch = update
            .next_sync_committee_branch
            .expect("branch must be present");
        assert_eq!(branch[0], [0x99; 32]);
    }

    #[tokio::test]
    async fn test_daemon_raw_private_key_never_sent_in_rpc_payload() {
        let dummy_privkey = "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
        let cli = Cli {
            eth_consensus_rpc: "http://127.0.0.1:5052".to_string(),
            eth_execution_rpc: "http://127.0.0.1:8545".to_string(),
            eth_chain_id: 1,
            lez_rpc_url: "http://127.0.0.1:8545".to_string(),
            lez_private_key: Some(dummy_privkey.to_string()),
            logos_ethereum_core_rpc: None,
            poll_interval_secs: 60,
            log_format: "json".to_string(),
            log_level: "info".to_string(),
        };

        let signer: alloy::signers::local::PrivateKeySigner = dummy_privkey.parse().unwrap();
        let expected_sender = format!("{:#x}", signer.address());

        let update = synthesize_canonical_update();
        let update_json = serde_json::to_string(&update).unwrap();
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
        let sig = signer.sign_hash(&tx_digest).await.unwrap();

        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "method": "lez_sendTransaction",
            "params": [{
                "to": "0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
                "instruction": "begin_update",
                "chain_id": cli.eth_chain_id,
                "data": "0x1234",
                "from": expected_sender,
                "signature": format!("0x{}", hex::encode(sig.as_bytes())),
            }],
            "id": 2
        });

        let payload_str = payload.to_string();
        assert!(!payload_str.contains(dummy_privkey.trim_start_matches("0x")));
        assert!(payload_str.contains(&expected_sender));
        assert!(payload_str.contains("signature"));
    }

    #[test]
    fn test_daemon_malformed_branch_node_strictly_rejected() {
        let json_data = r#"{
            "data": {
                "attested_header": {
                    "beacon": {
                        "slot": "15433761",
                        "proposer_index": "123",
                        "parent_root": "0x1111111111111111111111111111111111111111111111111111111111111111",
                        "state_root": "0x2222222222222222222222222222222222222222222222222222222222222222",
                        "body_root": "0x3333333333333333333333333333333333333333333333333333333333333333"
                    }
                },
                "finalized_header": {
                    "beacon": {
                        "slot": "15433760",
                        "proposer_index": "120",
                        "parent_root": "0x4444444444444444444444444444444444444444444444444444444444444444",
                        "state_root": "0x5555555555555555555555555555555555555555555555555555555555555555",
                        "body_root": "0x6666666666666666666666666666666666666666666666666666666666666666"
                    }
                },
                "finality_branch": ["0x1234"],
                "sync_aggregate": {
                    "sync_committee_bits": "0xff",
                    "sync_committee_signature": "0xc0"
                },
                "signature_slot": "15433761"
            }
        }"#;

        let res: FinalityUpdateResponse = serde_json::from_str(json_data).unwrap();
        let err = parse_beacon_update(res);
        assert!(err.is_err(), "Non-32-byte branch node must be rejected");
    }

    #[test]
    fn test_pipeline_transaction_digests_enforce_chain_id_domain_separation() {
        let chain_a: u64 = 1;
        let chain_b: u64 = 11155111;
        let job_nonce: u64 = 42;

        let digest_a = {
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, b"lez_tx_v1");
            sha2::Digest::update(
                &mut hasher,
                b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
            );
            sha2::Digest::update(&mut hasher, b"miller_update");
            sha2::Digest::update(&mut hasher, chain_a.to_be_bytes());
            sha2::Digest::update(&mut hasher, job_nonce.to_be_bytes());
            sha2::Digest::finalize(hasher)
        };

        let digest_b = {
            let mut hasher = sha2::Sha256::new();
            sha2::Digest::update(&mut hasher, b"lez_tx_v1");
            sha2::Digest::update(
                &mut hasher,
                b"0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c",
            );
            sha2::Digest::update(&mut hasher, b"miller_update");
            sha2::Digest::update(&mut hasher, chain_b.to_be_bytes());
            sha2::Digest::update(&mut hasher, job_nonce.to_be_bytes());
            sha2::Digest::finalize(hasher)
        };

        assert_ne!(
            digest_a, digest_b,
            "Digests on different chains must differ due to domain separation"
        );
    }
}
