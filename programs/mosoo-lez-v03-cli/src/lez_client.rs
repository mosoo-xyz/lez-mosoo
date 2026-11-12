use std::collections::{BTreeMap, HashSet};

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use borsh::{BorshDeserialize, BorshSerialize};
use lee::{
    AccountId, FeeDeclaration, PrivacyPreservingTransaction, PrivateKey, ProgramId,
    ProgramShardSelector, PublicTransaction, V03State, ValidatedStateDiff,
    program::Program,
    public_transaction::{Message, WitnessSet},
};
use lee_core::{
    BlockId, Timestamp,
    account::{Cycles, Nonce},
    program::PROGRAM_LOADER_ACCOUNT_ID,
};
use program_loader_core::{Instruction as LoaderInstruction, MAX_SEGMENT_DATA_LEN, ProgramHeader};
use serde::{Deserialize, Serialize};
use tokio::time::{Duration, sleep};

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub struct HashType(pub [u8; 32]);

/// LEZ v0.3 wire transaction union matching `common::transaction::LeeTransaction`.
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum LeeTransaction {
    Public(PublicTransaction),
    PrivacyPreserving(PrivacyPreservingTransaction),
}

/// LEZ v0.3.1 wire block header (`common` prior to block producer/sig fields).
#[derive(Debug, Clone, BorshDeserialize)]
#[allow(dead_code)]
pub struct V031BlockHeader {
    pub block_id: BlockId,
    pub prev_block_hash: HashType,
    pub hash: HashType,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub struct BlockBody {
    pub transactions: Vec<LeeTransaction>,
}

#[derive(Debug, Clone, BorshDeserialize)]
pub enum BedrockStatus {
    Pending,
    Safe,
    Finalized,
}

#[derive(Debug, Clone, BorshDeserialize)]
#[allow(dead_code)]
pub struct V031Block {
    pub header: V031BlockHeader,
    pub body: BlockBody,
    pub bedrock_status: BedrockStatus,
}

#[derive(Debug, Clone, Deserialize)]
#[allow(dead_code)]
pub struct FeeStateQuote {
    pub height: u64,
    pub base_fee_exec: u64,
    pub base_fee_stor: u64,
    pub next_base_fee_exec_floor: u64,
    pub next_base_fee_exec_ceiling: u64,
    pub next_base_fee_stor_floor: u64,
    pub next_base_fee_stor_ceiling: u64,
    pub max_gas_exec: u64,
    pub max_gas_stor: u64,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcAccountData {
    pub shards: BTreeMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RpcAccount {
    pub nonce: u128,
    pub data: RpcAccountData,
}

impl RpcAccount {
    pub fn shard_bytes(&self, program_id: &AccountId) -> &[u8] {
        self.data
            .shards
            .get(&program_id.to_string())
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

#[derive(Deserialize)]
struct JsonRpcResp<T> {
    result: Option<T>,
    error: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcReq<'a, P: Serialize> {
    jsonrpc: &'a str,
    id: u64,
    method: &'a str,
    params: P,
}

pub struct LezRpc {
    pub url: String,
    pub http: reqwest::Client,
}

impl LezRpc {
    pub fn connect(url: &str) -> Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(25))
            .build()?;
        Ok(Self {
            url: url.to_owned(),
            http,
        })
    }

    async fn call<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<R> {
        let resp: JsonRpcResp<R> = self
            .http
            .post(&self.url)
            .json(&JsonRpcReq {
                jsonrpc: "2.0",
                id: 1,
                method,
                params,
            })
            .send()
            .await
            .with_context(|| format!("HTTP error on {method}"))?
            .json()
            .await
            .with_context(|| format!("JSON decode error on {method}"))?;
        if let Some(err) = resp.error {
            bail!("RPC {method} error: {err}");
        }
        resp.result
            .ok_or_else(|| anyhow!("RPC {method} returned null result"))
    }

    async fn call_opt<P: Serialize, R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        params: P,
    ) -> Result<Option<R>> {
        let resp: JsonRpcResp<Option<R>> = self
            .http
            .post(&self.url)
            .json(&JsonRpcReq {
                jsonrpc: "2.0",
                id: 1,
                method,
                params,
            })
            .send()
            .await
            .with_context(|| format!("HTTP error on {method}"))?
            .json()
            .await
            .with_context(|| format!("JSON decode error on {method}"))?;
        if let Some(err) = resp.error {
            bail!("RPC {method} error: {err}");
        }
        Ok(resp.result.flatten())
    }

    pub async fn get_fee_state(&self) -> Result<FeeStateQuote> {
        self.call("getFeeState", Vec::<serde_json::Value>::new()).await
    }

    pub async fn get_account(&self, id: AccountId) -> Result<RpcAccount> {
        self.call("getAccount", [id.to_string()]).await
    }

    pub async fn get_balance(&self, id: AccountId) -> Result<u128> {
        self.call("getAccountBalance", [id.to_string()]).await
    }

    pub async fn get_v031_block(&self, block_id: BlockId) -> Result<V031Block> {
        let b64: String = self
            .call_opt("getBlock", [block_id])
            .await?
            .ok_or_else(|| anyhow!("getBlock({block_id}) returned null"))?;
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64.as_bytes())
            .context("base64 decode block")?;
        let mut slice: &[u8] = &raw;
        let blk = V031Block::deserialize(&mut slice).context("borsh decode V031Block")?;
        if !slice.is_empty() {
            bail!(
                "V031Block({block_id}) had {} trailing undecoded bytes",
                slice.len()
            );
        }
        Ok(blk)
    }

    pub async fn send_and_wait(
        &self,
        tx: PublicTransaction,
        timeout_secs: u64,
    ) -> Result<(String, BlockId)> {
        let borsh_bytes = borsh::to_vec(&LeeTransaction::Public(tx))?;
        let b64 = base64::engine::general_purpose::STANDARD.encode(&borsh_bytes);
        let hash_hex: String = self.call("sendTransaction", [b64]).await?;
        let attempts = timeout_secs.max(10);
        for elapsed in 0..attempts {
            if let Ok(Some((_, block_id))) =
                self.call_opt::<_, (String, BlockId)>("getTransaction", [hash_hex.clone()]).await
            {
                return Ok((hash_hex, block_id));
            }
            if elapsed > 0 && elapsed % 30 == 0 {
                if let Ok(fs) = self.get_fee_state().await {
                    println!("    still waiting for {hash_hex} ({elapsed}s elapsed, chain height={})...", fs.height);
                }
            }
            sleep(Duration::from_secs(1)).await;
        }
        bail!("timed out after {attempts}s waiting for tx {hash_hex}")
    }
}

/// Build a signed LEZ v0.3.1 `PublicTransaction` with an explicit gas limit and fee reserve check.
pub fn build_signed_tx<T: BorshSerialize>(
    program_id: AccountId,
    shard_selectors: Vec<ProgramShardSelector>,
    instruction: T,
    extra_signers: &[(&PrivateKey, AccountId, Nonce)],
    payer_key: &PrivateKey,
    payer_id: AccountId,
    payer_nonce: Nonce,
    gas_limit: u64,
    fee_quote: &FeeStateQuote,
) -> Result<(PublicTransaction, u128, u64)> {
    let instruction_data = Program::serialize_instruction(instruction)
        .map_err(|e| anyhow!("serialize instruction failed: {e}"))?;

    let mut signer_keys: Vec<&PrivateKey> = Vec::new();
    let mut nonces: Vec<Nonce> = Vec::new();
    let mut seen: HashSet<AccountId> = HashSet::new();

    for &(sk, id, nonce) in extra_signers {
        if !seen.insert(id) {
            bail!("duplicate extra signer {id}");
        }
        signer_keys.push(sk);
        nonces.push(nonce);
    }
    if seen.insert(payer_id) {
        signer_keys.push(payer_key);
        nonces.push(payer_nonce);
    }

    let exec_price = fee_quote
        .next_base_fee_exec_ceiling
        .max(fee_quote.base_fee_exec) as u128;
    let stor_price = fee_quote
        .next_base_fee_stor_ceiling
        .max(fee_quote.base_fee_stor) as u128;

    let dummy_msg = Message::new_preserialized(
        program_id,
        shard_selectors.clone(),
        nonces.clone(),
        instruction_data.clone(),
        Some(FeeDeclaration::new(payer_id, gas_limit, 0, u128::MAX)),
    );
    let dummy_ws = WitnessSet::for_message(&dummy_msg, &signer_keys);
    let dummy_tx = PublicTransaction::new(dummy_msg, dummy_ws);
    let data_bytes = borsh::to_vec(&LeeTransaction::Public(dummy_tx))?.len() as u64;

    let reserve_ceiling = (gas_limit as u128) * exec_price + (data_bytes as u128) * stor_price;
    let max_fee = reserve_ceiling.saturating_mul(2);

    let msg = Message::new_preserialized(
        program_id,
        shard_selectors,
        nonces,
        instruction_data,
        Some(FeeDeclaration::new(payer_id, gas_limit, 0, max_fee)),
    );
    let ws = WitnessSet::for_message(&msg, &signer_keys);
    let tx = PublicTransaction::new(msg, ws);

    let opening_reserve = (gas_limit as u128) * (fee_quote.base_fee_exec as u128)
        + (data_bytes as u128) * (fee_quote.base_fee_stor as u128);
    Ok((tx, opening_reserve, data_bytes))
}

pub fn chunk_user_elf(user_elf: &[u8]) -> Vec<&[u8]> {
    user_elf.chunks(MAX_SEGMENT_DATA_LEN).collect()
}

pub fn build_write_segment_tx(
    target_sk: &PrivateKey,
    target_id: AccountId,
    chunk: &[u8],
    next_segment: Option<AccountId>,
    payer_sk: &PrivateKey,
    payer_id: AccountId,
    payer_nonce: Nonce,
    fee_quote: &FeeStateQuote,
) -> Result<(PublicTransaction, u128, u64)> {
    let mut selectors = vec![ProgramShardSelector::new(
        target_id,
        PROGRAM_LOADER_ACCOUNT_ID,
    )];
    if let Some(next_id) = next_segment {
        selectors.push(ProgramShardSelector::new(next_id, PROGRAM_LOADER_ACCOUNT_ID));
    }
    build_signed_tx(
        PROGRAM_LOADER_ACCOUNT_ID,
        selectors,
        LoaderInstruction::WriteSegment {
            bytecode: chunk.to_vec(),
            next_segment,
        },
        &[(target_sk, target_id, 0u128.into())],
        payer_sk,
        payer_id,
        payer_nonce,
        50_000,
        fee_quote,
    )
}

pub fn build_create_header_tx(
    header_sk: &PrivateKey,
    header_id: AccountId,
    segment_ids: &[AccountId],
    immutable: bool,
    payer_sk: &PrivateKey,
    payer_id: AccountId,
    payer_nonce: Nonce,
    fee_quote: &FeeStateQuote,
) -> Result<(PublicTransaction, u128, u64)> {
    let first_segment = *segment_ids
        .first()
        .ok_or_else(|| anyhow!("cannot create header with 0 segments"))?;
    let mut selectors = Vec::with_capacity(1 + segment_ids.len());
    selectors.push(ProgramShardSelector::new(
        header_id,
        PROGRAM_LOADER_ACCOUNT_ID,
    ));
    for seg_id in segment_ids {
        selectors.push(ProgramShardSelector::new(*seg_id, PROGRAM_LOADER_ACCOUNT_ID));
    }
    build_signed_tx(
        PROGRAM_LOADER_ACCOUNT_ID,
        selectors,
        LoaderInstruction::CreateHeader {
            first_segment,
            immutable,
        },
        &[(header_sk, header_id, 0u128.into())],
        payer_sk,
        payer_id,
        payer_nonce,
        50_000,
        fee_quote,
    )
}

pub fn exec_local_and_apply(
    state: &mut V03State,
    tx: &PublicTransaction,
    block_id: BlockId,
    timestamp_ms: Timestamp,
    cycle_budget: Cycles,
) -> Result<u64> {
    let (diff, charge) = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        tx,
        state,
        block_id,
        timestamp_ms,
        cycle_budget,
    )
    .map_err(|e| anyhow!("LEE execution failed: {e}"))?;
    let _events = state.apply_state_diff(diff);
    Ok(charge.cycles)
}

pub fn decode_program_header(account: &RpcAccount) -> Option<ProgramHeader> {
    let shard = account.shard_bytes(&PROGRAM_LOADER_ACCOUNT_ID);
    ProgramHeader::from_bytes(shard)
}

pub fn format_image_id_hex(id: &ProgramId) -> String {
    let mut bytes = [0u8; 32];
    for (i, w) in id.iter().enumerate() {
        bytes[i * 4..(i + 1) * 4].copy_from_slice(&w.to_le_bytes());
    }
    hex::encode(bytes)
}
