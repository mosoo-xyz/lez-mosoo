mod lez_client;
mod vectors;
mod wallets;

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, anyhow, bail};
use borsh::BorshDeserialize;
use clap::{Parser, Subcommand};
use lee::{
    AccountId, ProgramShardSelector, V03State, ValidatedStateDiff,
    program::Program,
    public_transaction::PublicTransaction,
};
use lee_core::{
    native_token::{Instruction as NativeInstruction, NATIVE_TOKEN_PROGRAM_ID},
    program::PROGRAM_LOADER_ACCOUNT_ID,
};
use mosoo_core::{
    crypto,
    types::{BeaconBlockHeader, LightClientUpdate, compute_sync_committee_period},
};
use mosoo_lez_v03::{
    Instruction, MosooHeaderRecord, MosooInstance, MosooJob, header_account,
    instance_account, job_account, job_id,
    wire::{WireExecutionPayloadHeader, WirePredicate, WirePrivacyMode, WireUpdate},
};
use rand::{RngCore, rngs::OsRng};
use risc0_binfmt::ProgramBinary;
use risc0_zkos_v1compat::V1COMPAT_ELF;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    lez_client::{
        FeeStateQuote, LezRpc, build_create_header_tx, build_signed_tx, build_write_segment_tx,
        chunk_user_elf, decode_program_header, exec_local_and_apply, format_image_id_hex,
    },
    vectors::{MainnetBundle, load_mainnet_bundle},
    wallets::{LoadedWallet, create_and_save_deploy_keys, load_wallet},
};

const MAX_GAS_EXEC: u64 = 10_000_000;
const CHAIN_ID_MAINNET: u64 = 1;
const MIN_PARTICIPATION: u16 = 342;
const WEAK_SUB_WINDOW_SLOTS: u64 = 54_000;

#[derive(Parser)]
#[command(name = "mosoo-v03", about = "Mosoo LEZ v0.3.1 pack/simulate/deploy/run CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Wrap raw riscv32im user ELF with risc0_zkos_v1compat kernel into a LEZ v0.3 .bin binary.
    Pack {
        #[arg(long)]
        elf: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify local wallet secrets derive expected Base58 AccountIds and inspect live LEZ RPC state.
    CheckWallets {
        #[arg(long, default_value = "https://testnet.lez.logos.co")]
        rpc: String,
        #[arg(long = "wallet")]
        wallets: Vec<PathBuf>,
    },
    /// Deploy (in memory) + execute full Mosoo lifecycle + negative refusals on local V03State.
    Simulate {
        #[arg(long)]
        bin: PathBuf,
        #[arg(long, default_value = "vectors")]
        vectors: PathBuf,
    },
    /// Deploy `mosoo_lc.bin` onto live LEZ RPC via `program_loader`.
    Deploy {
        #[arg(long)]
        bin: PathBuf,
        #[arg(long)]
        payer: PathBuf,
        #[arg(long, default_value = "https://testnet.lez.logos.co")]
        rpc: String,
        #[arg(long)]
        out: PathBuf,
        #[arg(long, default_value = "/root/build-cache/mosoo_v03_deploy_keys.json")]
        key_store: PathBuf,
        #[arg(long, default_value_t = true)]
        immutable: bool,
    },
    /// Transfer native lepta from one local wallet to another.
    Transfer {
        #[arg(long)]
        from: PathBuf,
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        amount: u128,
        #[arg(long, default_value = "https://testnet.lez.logos.co")]
        rpc: String,
    },
    /// Drive Init -> Begin -> Miller -> Finish -> Attests + refusals against deployed Mosoo program.
    RunTestnet {
        #[arg(long)]
        program_id: String,
        #[arg(long)]
        bin: PathBuf,
        #[arg(long, default_value = "vectors")]
        vectors: PathBuf,
        #[arg(long, default_value = "https://testnet.lez.logos.co")]
        rpc: String,
        #[arg(long)]
        init_payer: PathBuf,
        #[arg(long)]
        begin_payer: PathBuf,
        #[arg(long)]
        miller_payer: PathBuf,
        #[arg(long)]
        finish_payer: PathBuf,
        #[arg(long)]
        attest_payer: PathBuf,
        #[arg(long)]
        out_dir: PathBuf,
        #[arg(long)]
        instance_seed: Option<String>,
    },
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis() as u64
}

fn compute_next_instance(cur: &MosooInstance, update: &WireUpdate) -> Result<MosooInstance> {
    let core_update: LightClientUpdate = update.into();
    let payload = core_update
        .execution_payload_header
        .as_ref()
        .ok_or_else(|| anyhow!("update missing execution payload header"))?;
    let mut rotated_curr = cur.current_committee_root;
    let mut next_comm = cur.next_committee_root;
    let store_period = compute_sync_committee_period(cur.current_slot);
    let fin_period = compute_sync_committee_period(core_update.finalized_header.slot);
    if fin_period > store_period {
        rotated_curr = next_comm
            .take()
            .ok_or_else(|| anyhow!("missing next_sync_committee for rotation"))?;
    }
    if let Some(ref nc) = core_update.next_sync_committee {
        next_comm = Some(
            crypto::hash_tree_root_sync_committee(nc)
                .map_err(|e| anyhow!("next committee hash failed: {e}"))?,
        );
    }
    let fin_hash = crypto::hash_tree_root_beacon_header(&core_update.finalized_header);
    let exec_wire: WireExecutionPayloadHeader = payload.into();
    Ok(MosooInstance {
        current_slot: core_update.finalized_header.slot,
        current_committee_root: rotated_curr,
        next_committee_root: next_comm,
        current_header_hash: fin_hash,
        current_state_root: core_update.finalized_header.state_root,
        execution_block_number: exec_wire.block_number,
        execution_block_hash: exec_wire.block_hash,
        execution_state_root: exec_wire.state_root,
        receipts_root: exec_wire.receipts_root,
        ..cur.clone()
    })
}

fn make_init_ix(instance_id: [u8; 32], b: &MainnetBundle) -> Instruction {
    Instruction::Init {
        instance_id,
        chain_id: CHAIN_ID_MAINNET,
        checkpoint: b.checkpoint,
        network_config: None,
        min_participation: MIN_PARTICIPATION,
        weak_subjectivity_window: WEAK_SUB_WINDOW_SLOTS,
        header: b.bootstrap_header.clone(),
        committee: b.bootstrap_committee.clone(),
        committee_branch: b.bootstrap_committee_branch.clone(),
        execution_payload_header: b.bootstrap_exec_header.clone(),
        execution_branch: b.bootstrap_exec_branch.clone(),
        execution_rlp: None,
    }
}

fn make_initial_instance(instance_id: [u8; 32], b: &MainnetBundle) -> Result<MosooInstance> {
    let boot_hdr: BeaconBlockHeader = (&b.bootstrap_header).into();
    let boot_comm = (&b.bootstrap_committee).into();
    let committee_root = crypto::hash_tree_root_sync_committee(&boot_comm)
        .map_err(|e| anyhow!("committee root failed: {e}"))?;
    let header_hash = crypto::hash_tree_root_beacon_header(&boot_hdr);
    let gvr = crypto::genesis_validators_root(CHAIN_ID_MAINNET);
    let (eb_num, eb_hash, eb_state, rcpts) = if let Some(ref p) = b.bootstrap_exec_header {
        (p.block_number, p.block_hash, p.state_root, p.receipts_root)
    } else {
        (0, [0u8; 32], [0u8; 32], [0u8; 32])
    };
    Ok(MosooInstance {
        instance_id,
        chain_id: CHAIN_ID_MAINNET,
        checkpoint: b.checkpoint,
        genesis_validators_root: gvr,
        network_config: None,
        min_participation: MIN_PARTICIPATION,
        weak_subjectivity_window: WEAK_SUB_WINDOW_SLOTS,
        current_slot: b.bootstrap_header.slot,
        current_committee_root: committee_root,
        next_committee_root: None,
        current_header_hash: header_hash,
        current_state_root: b.bootstrap_header.state_root,
        execution_block_number: eb_num,
        execution_block_hash: eb_hash,
        execution_state_root: eb_state,
        receipts_root: rcpts,
    })
}

fn mosoo_tx(
    program_id: AccountId,
    pda_accounts: Vec<AccountId>,
    ix: Instruction,
    payer: &LoadedWallet,
    payer_nonce: u128,
    gas_limit: u64,
    fee_quote: &FeeStateQuote,
) -> Result<(PublicTransaction, u128, u64)> {
    let selectors = pda_accounts
        .into_iter()
        .map(|id| ProgramShardSelector::new(id, program_id))
        .collect();
    build_signed_tx(
        program_id,
        selectors,
        ix,
        &[],
        payer.private_key(),
        payer.account_id,
        payer_nonce.into(),
        gas_limit,
        fee_quote,
    )
}

fn cmd_pack(elf_path: &Path, out_path: &Path) -> Result<()> {
    let user_elf = fs::read(elf_path)
        .with_context(|| format!("failed to read ELF {}", elf_path.display()))?;
    let binary = ProgramBinary::new(&user_elf, V1COMPAT_ELF);
    let encoded = binary.encode();
    let image_id_digest = binary.compute_image_id()?;
    let image_id_words: [u32; 8] = image_id_digest.into();
    let image_id_hex = format_image_id_hex(&image_id_words);
    let chunks = chunk_user_elf(binary.user_elf);

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, &encoded)?;

    let mut hasher = Sha256::new();
    hasher.update(&encoded);
    let bin_sha = hex::encode(hasher.finalize());
    let file_name = out_path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("mosoo_lc.bin");
    fs::write(
        out_path.with_extension("bin.sha256"),
        format!("{bin_sha}  {file_name}\n"),
    )?;
    let meta = serde_json::json!({
        "binary_file": file_name,
        "binary_bytes": encoded.len(),
        "binary_sha256": bin_sha,
        "user_elf_bytes": binary.user_elf.len(),
        "segment_count": chunks.len(),
        "image_id_hex": image_id_hex,
        "image_id_u32": image_id_words,
    });
    fs::write(
        out_path.with_extension("image_id.json"),
        serde_json::to_string_pretty(&meta)? + "\n",
    )?;

    println!("Packed LEZ v0.3 ProgramBinary -> {}", out_path.display());
    println!("  binary_bytes  : {}", encoded.len());
    println!("  user_elf_bytes: {}", binary.user_elf.len());
    println!("  segments (96K): {}", chunks.len());
    println!("  image_id_hex  : {image_id_hex}");
    println!("  image_id_u32  : {image_id_words:?}");
    println!("  sha256        : {bin_sha}");
    Ok(())
}

async fn cmd_check_wallets(rpc_url: &str, paths: &[PathBuf]) -> Result<()> {
    let client = LezRpc::connect(rpc_url)?;
    let fs_quote = client.get_fee_state().await?;
    println!(
        "Connected RPC {rpc_url}: height={}, base_fee_exec={}, base_fee_stor={}, max_gas_exec={}, max_gas_stor={}",
        fs_quote.height,
        fs_quote.base_fee_exec,
        fs_quote.base_fee_stor,
        fs_quote.max_gas_exec,
        fs_quote.max_gas_stor
    );
    let blk1 = client.get_v031_block(1).await?;
    let blk_head = client.get_v031_block(fs_quote.height).await?;
    println!(
        "V031Block decoding verified: blk#1 txs={} ts={}, head blk#{} txs={} ts={}",
        blk1.body.transactions.len(),
        blk1.header.timestamp,
        blk_head.header.block_id,
        blk_head.body.transactions.len(),
        blk_head.header.timestamp
    );

    let mut total: u128 = 0;
    for path in paths {
        let label = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("wallet");
        let w = load_wallet(path, label)?;
        let acct = client.get_account(w.account_id).await?;
        let bal = client.get_balance(w.account_id).await?;
        total += bal;
        println!(
            "  [OK] {:15} account={} nonce={} balance={} lepta",
            w.label, w.account_id, acct.nonce, bal
        );
    }
    println!("Total verified balance across {} wallets: {total} lepta", paths.len());
    Ok(())
}

fn synthetic_fee_quote() -> FeeStateQuote {
    FeeStateQuote {
        height: 1,
        base_fee_exec: 8,
        base_fee_stor: 8,
        next_base_fee_exec_floor: 8,
        next_base_fee_exec_ceiling: 9,
        next_base_fee_stor_floor: 8,
        next_base_fee_stor_ceiling: 9,
        max_gas_exec: MAX_GAS_EXEC,
        max_gas_stor: 1_000_000,
    }
}

#[derive(Serialize)]
struct SimReport {
    image_id_hex: String,
    image_id_u32: [u32; 8],
    segment_count: usize,
    init_cycles: u64,
    begin_cycles: u64,
    miller_cycles: u64,
    finish_cycles: u64,
    attest_balance_cycles: u64,
    attest_storage_cycles: u64,
    attest_receipt_cycles: u64,
    attest_confidential_cycles: u64,
}

fn run_local_sim(bin_path: &Path, vectors_dir: &Path) -> Result<SimReport> {
    let bin_bytes = fs::read(bin_path)?;
    let program = Program::new(bin_bytes.clone().into())
        .map_err(|e| anyhow!("Program::new invalid bytecode: {e}"))?;
    let binary = ProgramBinary::decode(&bin_bytes)?;
    anyhow::ensure!(
        binary.kernel_elf == V1COMPAT_ELF,
        "kernel ELF does not match risc0_zkos_v1compat"
    );
    let chunks = chunk_user_elf(binary.user_elf);
    let fq = synthetic_fee_quote();

    let payer_sk = wallets::generate_fresh_key()?;
    let payer_dummy = LoadedWallet::from_ephemeral("sim-payer", payer_sk.clone());
    let payer_id = payer_dummy.account_id;
    let hdr_sk = wallets::generate_fresh_key()?;
    let hdr_id = wallets::account_id_of(&hdr_sk);
    let mut seg_pairs = Vec::new();
    for _ in 0..chunks.len() {
        let sk = wallets::generate_fresh_key()?;
        let id = wallets::account_id_of(&sk);
        seg_pairs.push((sk, id));
    }

    let mut state = V03State::new().with_public_account_balances([(payer_id, 1_000_000_000)]);
    let now_ms = current_unix_ms();
    let mut block_id = 1u64;
    let mut payer_nonce = 0u128;

    println!("=== 1. Local V03State program_loader deployment ({} segments) ===", chunks.len());
    for i in (0..chunks.len()).rev() {
        let next_seg = seg_pairs.get(i + 1).map(|p| p.1);
        let (tx, reserve, bytes) = build_write_segment_tx(
            &seg_pairs[i].0,
            seg_pairs[i].1,
            chunks[i],
            next_seg,
            &payer_sk,
            payer_id,
            payer_nonce.into(),
            &fq,
        )?;
        let cyc = exec_local_and_apply(&mut state, &tx, block_id, now_ms, MAX_GAS_EXEC)?;
        println!("  WriteSegment[{i}] bytes={bytes} reserve={reserve} cycles={cyc}");
        payer_nonce += 1;
        block_id += 1;
    }
    let seg_ids: Vec<AccountId> = seg_pairs.iter().map(|p| p.1).collect();
    let (hdr_tx, hdr_res, hdr_bytes) = build_create_header_tx(
        &hdr_sk,
        hdr_id,
        &seg_ids,
        true,
        &payer_sk,
        payer_id,
        payer_nonce.into(),
        &fq,
    )?;
    let hdr_cyc = exec_local_and_apply(&mut state, &hdr_tx, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  CreateHeader bytes={hdr_bytes} reserve={hdr_res} cycles={hdr_cyc}");
    payer_nonce += 1;
    block_id += 1;

    let deployed_id = state
        .get_program_image_id(hdr_id)
        .ok_or_else(|| anyhow!("deployed program missing in V03State"))?;
    anyhow::ensure!(deployed_id == program.id(), "deployed image ID mismatch");
    let prog_id = hdr_id;
    let image_hex = format_image_id_hex(&deployed_id);
    println!("  Verified local deployed header={prog_id}, image_id={image_hex}");

    println!("=== 2. Executing Mosoo lifecycle & negative refusals under 10M cycle cap ===");
    let b = load_mainnet_bundle(vectors_dir)?;
    let inst_id = [0x42u8; 32];
    let inst_pda = instance_account(&prog_id, &inst_id);
    let init_hdr_pda = header_account(&prog_id, &inst_id, b.bootstrap_header.slot);

    let init_ix = make_init_ix(inst_id, &b);
    let (tx, _, bytes) = mosoo_tx(
        prog_id,
        vec![inst_pda, init_hdr_pda],
        init_ix.clone(),
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let init_cycles = exec_local_and_apply(&mut state, &tx, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  [PASS] Init (slot={}): cycles={init_cycles} (<10M={}) bytes={bytes}",
        b.bootstrap_header.slot, init_cycles <= MAX_GAS_EXEC);
    anyhow::ensure!(init_cycles <= MAX_GAS_EXEC, "Init exceeded 10M cycle cap");
    payer_nonce += 1;
    block_id += 1;

    // Duplicate Init refusal
    let (dup_tx, _, _) = mosoo_tx(
        prog_id,
        vec![inst_pda, init_hdr_pda],
        init_ix,
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let dup_res = ValidatedStateDiff::from_public_transaction_with_cycle_budget(
        &dup_tx,
        &state,
        block_id,
        now_ms,
        MAX_GAS_EXEC,
    );
    match dup_res {
        Err(e) => println!("  [REFUSED OK] Duplicate Init rejected: {e}"),
        Ok(_) => bail!("Duplicate Init unexpectedly succeeded!"),
    }

    let inst0 = make_initial_instance(inst_id, &b)?;
    let onchain_inst_bytes = state.get_account_by_id(inst_pda).data.shard(prog_id).to_vec();
    let onchain_inst0 = MosooInstance::try_from_slice(&onchain_inst_bytes)?;
    anyhow::ensure!(onchain_inst0 == inst0, "on-chain instance mismatch with computed");

    // Negative: Begin with corrupted finality branch
    let mut bad_update = b.update.clone();
    bad_update.finality_branch[0][0] ^= 0x01;
    let bad_jid = job_id(&inst0, &bad_update);
    let bad_job_pda = job_account(&prog_id, &inst_id, &bad_jid);
    let (bad_begin_tx, _, _) = mosoo_tx(
        prog_id,
        vec![inst_pda, bad_job_pda],
        Instruction::Begin {
            instance_id: inst_id,
            current: inst0.clone(),
            update: bad_update,
            committee: b.bootstrap_committee.clone(),
            witness: b.witness.clone(),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    anyhow::ensure!(
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &bad_begin_tx,
            &state,
            block_id,
            now_ms,
            MAX_GAS_EXEC,
        )
        .is_err(),
        "Corrupted finality branch Begin must fail"
    );
    println!("  [REFUSED OK] Begin rejected corrupted finality branch");

    // Honest Begin
    let jid = job_id(&inst0, &b.update);
    let jpda = job_account(&prog_id, &inst_id, &jid);
    let (begin_tx, _, begin_bytes) = mosoo_tx(
        prog_id,
        vec![inst_pda, jpda],
        Instruction::Begin {
            instance_id: inst_id,
            current: inst0.clone(),
            update: b.update.clone(),
            committee: b.bootstrap_committee.clone(),
            witness: b.witness.clone(),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let begin_cycles = exec_local_and_apply(&mut state, &begin_tx, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  [PASS] Begin (slot->{}): cycles={begin_cycles} (<10M={}) bytes={begin_bytes}",
        b.finalized_slot, begin_cycles <= MAX_GAS_EXEC);
    anyhow::ensure!(begin_cycles <= MAX_GAS_EXEC, "Begin exceeded 10M cycle cap");
    payer_nonce += 1;
    block_id += 1;

    let inst1 = compute_next_instance(&inst0, &b.update)?;
    let fin_hdr_pda = header_account(&prog_id, &inst_id, inst1.current_slot);

    // Negative: premature Finish BEFORE Miller
    let (premature_fin_tx, _, _) = mosoo_tx(
        prog_id,
        vec![inst_pda, jpda, fin_hdr_pda],
        Instruction::Finish {
            instance_id: inst_id,
            job_id: jid,
            current: inst0.clone(),
            next: inst1.clone(),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    anyhow::ensure!(
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &premature_fin_tx,
            &state,
            block_id,
            now_ms,
            MAX_GAS_EXEC,
        )
        .is_err(),
        "Premature Finish before Miller must fail"
    );
    println!("  [REFUSED OK] Finish rejected before Miller ran (E7395)");

    // Honest Miller
    let (miller_tx, _, miller_bytes) = mosoo_tx(
        prog_id,
        vec![jpda],
        Instruction::Miller {
            instance_id: inst_id,
            job_id: jid,
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let miller_cycles = exec_local_and_apply(&mut state, &miller_tx, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  [PASS] Miller: cycles={miller_cycles} (<10M={}) bytes={miller_bytes}",
        miller_cycles <= MAX_GAS_EXEC);
    anyhow::ensure!(miller_cycles <= MAX_GAS_EXEC, "Miller exceeded 10M cycle cap");
    payer_nonce += 1;
    block_id += 1;

    // Honest Finish
    let (finish_tx, _, finish_bytes) = mosoo_tx(
        prog_id,
        vec![inst_pda, jpda, fin_hdr_pda],
        Instruction::Finish {
            instance_id: inst_id,
            job_id: jid,
            current: inst0.clone(),
            next: inst1.clone(),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let finish_cycles = exec_local_and_apply(&mut state, &finish_tx, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  [PASS] Finish (block #{}): cycles={finish_cycles} (<10M={}) bytes={finish_bytes}",
        b.exec_block_number, finish_cycles <= MAX_GAS_EXEC);
    anyhow::ensure!(finish_cycles <= MAX_GAS_EXEC, "Finish exceeded 10M cycle cap");
    payer_nonce += 1;
    block_id += 1;

    // Verify instance advanced + job cleared + header stored
    let post_inst = MosooInstance::try_from_slice(state.get_account_by_id(inst_pda).data.shard(prog_id))?;
    anyhow::ensure!(post_inst.execution_block_number == b.exec_block_number);
    anyhow::ensure!(state.get_account_by_id(jpda).data.shard(prog_id).is_empty(), "job PDA not cleared");
    let hdr_rec = MosooHeaderRecord::try_from_slice(state.get_account_by_id(fin_hdr_pda).data.shard(prog_id))?;
    anyhow::ensure!(hdr_rec.slot == b.finalized_slot);

    // Forged BLS signature full split rejection test (second instance)
    let forged_inst_id = [0x99u8; 32];
    let forged_inst_pda = instance_account(&prog_id, &forged_inst_id);
    let forged_hdr_pda = header_account(&prog_id, &forged_inst_id, b.bootstrap_header.slot);
    let (f_init, _, _) = mosoo_tx(
        prog_id,
        vec![forged_inst_pda, forged_hdr_pda],
        make_init_ix(forged_inst_id, &b),
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    exec_local_and_apply(&mut state, &f_init, block_id, now_ms, MAX_GAS_EXEC)?;
    payer_nonce += 1;
    block_id += 1;
    let f_inst0 = make_initial_instance(forged_inst_id, &b)?;
    let mut forged_upd = b.update.clone();
    forged_upd.sync_aggregate.sync_committee_signature[0] ^= 0x01;
    let f_jid = job_id(&f_inst0, &forged_upd);
    let f_jpda = job_account(&prog_id, &forged_inst_id, &f_jid);
    let f_fin_hdr = header_account(&prog_id, &forged_inst_id, b.finalized_slot);
    let (f_beg, _, _) = mosoo_tx(
        prog_id,
        vec![forged_inst_pda, f_jpda],
        Instruction::Begin {
            instance_id: forged_inst_id,
            current: f_inst0.clone(),
            update: forged_upd.clone(),
            committee: b.bootstrap_committee.clone(),
            witness: b.witness.clone(),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    exec_local_and_apply(&mut state, &f_beg, block_id, now_ms, MAX_GAS_EXEC)?;
    payer_nonce += 1;
    block_id += 1;
    let (f_mil, _, _) = mosoo_tx(
        prog_id,
        vec![f_jpda],
        Instruction::Miller {
            instance_id: forged_inst_id,
            job_id: f_jid,
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    exec_local_and_apply(&mut state, &f_mil, block_id, now_ms, MAX_GAS_EXEC)?;
    payer_nonce += 1;
    block_id += 1;
    let f_inst1 = compute_next_instance(&f_inst0, &forged_upd)?;
    let (f_fin, _, _) = mosoo_tx(
        prog_id,
        vec![forged_inst_pda, f_jpda, f_fin_hdr],
        Instruction::Finish {
            instance_id: forged_inst_id,
            job_id: f_jid,
            current: f_inst0,
            next: f_inst1,
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    anyhow::ensure!(
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &f_fin,
            &state,
            block_id,
            now_ms,
            MAX_GAS_EXEC,
        )
        .is_err(),
        "Forged BLS signature Finish must fail final_exponentiation"
    );
    println!("  [REFUSED OK] Forged BLS signature rejected by Finish final_exponentiation");

    // Consumer Attestations + Negative Attests
    let (tx_bal, _, b_bytes) = mosoo_tx(
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id: inst_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.weth_balance_proof.clone(),
            predicate: b.weth_balance_pred.clone(),
            privacy_salt: None,
            privacy_mode: Some(WirePrivacyMode::Public),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let attest_balance_cycles = exec_local_and_apply(&mut state, &tx_bal, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  [PASS] Attest (WETH Balance): cycles={attest_balance_cycles} bytes={b_bytes}");
    anyhow::ensure!(attest_balance_cycles <= MAX_GAS_EXEC);
    payer_nonce += 1;
    block_id += 1;

    let (tx_stor, _, s_bytes) = mosoo_tx(
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id: inst_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.weth_storage_proof.clone(),
            predicate: b.weth_storage_pred.clone(),
            privacy_salt: None,
            privacy_mode: Some(WirePrivacyMode::Public),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let attest_storage_cycles = exec_local_and_apply(&mut state, &tx_stor, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  [PASS] Attest (WETH Storage): cycles={attest_storage_cycles} bytes={s_bytes}");
    anyhow::ensure!(attest_storage_cycles <= MAX_GAS_EXEC);
    payer_nonce += 1;
    block_id += 1;

    let (tx_rcpt, _, r_bytes) = mosoo_tx(
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id: inst_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.receipt_proof.clone(),
            predicate: b.receipt_pred.clone(),
            privacy_salt: None,
            privacy_mode: Some(WirePrivacyMode::Public),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let attest_receipt_cycles = exec_local_and_apply(&mut state, &tx_rcpt, block_id, now_ms, MAX_GAS_EXEC)?;
    println!("  [PASS] Attest (USDC Receipt): cycles={attest_receipt_cycles} bytes={r_bytes}");
    anyhow::ensure!(attest_receipt_cycles <= MAX_GAS_EXEC);
    payer_nonce += 1;
    block_id += 1;

    let (tx_conf, _, c_bytes) = mosoo_tx(
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id: inst_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.receipt_proof.clone(),
            predicate: b.receipt_pred.clone(),
            privacy_salt: Some([0xABu8; 32]),
            privacy_mode: Some(WirePrivacyMode::Confidential),
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    let attest_confidential_cycles =
        exec_local_and_apply(&mut state, &tx_conf, block_id, now_ms, MAX_GAS_EXEC)?;
    println!(
        "  [PASS] Attest (Confidential Shielded): cycles={attest_confidential_cycles} bytes={c_bytes}"
    );
    anyhow::ensure!(attest_confidential_cycles <= MAX_GAS_EXEC);
    payer_nonce += 1;

    // Negative Attests: wrong chain_id, failing predicate, corrupted receipt RLP
    let (bad_chain, _, _) = mosoo_tx(
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id: inst_id,
            slot: b.finalized_slot,
            chain_id: 11_155_111,
            proof: b.receipt_proof.clone(),
            predicate: b.receipt_pred.clone(),
            privacy_salt: None,
            privacy_mode: None,
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    anyhow::ensure!(
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &bad_chain,
            &state,
            block_id,
            now_ms,
            MAX_GAS_EXEC,
        )
        .is_err(),
        "Wrong chain_id Attest must fail"
    );
    println!("  [REFUSED OK] Attest rejected wrong chain_id (11155111 != 1)");

    let mut bad_pred = b.receipt_pred.clone();
    if let WirePredicate::Equal { ref mut expected } = bad_pred {
        expected[31] ^= 0xff;
    }
    let (bad_pred_tx, _, _) = mosoo_tx(
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id: inst_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.receipt_proof.clone(),
            predicate: bad_pred,
            privacy_salt: None,
            privacy_mode: None,
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    anyhow::ensure!(
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &bad_pred_tx,
            &state,
            block_id,
            now_ms,
            MAX_GAS_EXEC,
        )
        .is_err(),
        "Wrong predicate Attest must fail"
    );
    println!("  [REFUSED OK] Attest rejected wrong predicate (E7311)");

    let mut tampered = b.receipt_proof.clone();
    if let Some(ref mut v) = tampered.receipt_value {
        let last = v.len() - 1;
        v[last] ^= 0xff;
    }
    let (tamper_tx, _, _) = mosoo_tx(
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id: inst_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: tampered,
            predicate: b.receipt_pred.clone(),
            privacy_salt: None,
            privacy_mode: None,
        },
        &payer_dummy,
        payer_nonce,
        MAX_GAS_EXEC,
        &fq,
    )?;
    anyhow::ensure!(
        ValidatedStateDiff::from_public_transaction_with_cycle_budget(
            &tamper_tx,
            &state,
            block_id,
            now_ms,
            MAX_GAS_EXEC,
        )
        .is_err(),
        "Tampered receipt RLP must fail"
    );
    println!("  [REFUSED OK] Attest rejected tampered receipt RLP (E7312)");

    Ok(SimReport {
        image_id_hex: image_hex,
        image_id_u32: deployed_id,
        segment_count: chunks.len(),
        init_cycles,
        begin_cycles,
        miller_cycles,
        finish_cycles,
        attest_balance_cycles,
        attest_storage_cycles,
        attest_receipt_cycles,
        attest_confidential_cycles,
    })
}

#[derive(Serialize)]
struct DeploySegmentRecord {
    index: usize,
    segment_account: String,
    next_segment: Option<String>,
    bytes: usize,
    tx_hash: String,
    block_id: u64,
    payer: String,
    fee_paid_lepta: u128,
}

#[derive(Serialize)]
struct DeployManifest {
    rpc_url: String,
    program_id: String,
    image_id_hex: String,
    image_id_u32: [u32; 8],
    immutable: bool,
    segment_count: usize,
    user_elf_bytes: usize,
    binary_bytes: usize,
    binary_sha256: String,
    payer_account: String,
    payer_pre_balance_lepta: u128,
    payer_post_balance_lepta: u128,
    total_fee_paid_lepta: u128,
    header_tx_hash: String,
    header_block_id: u64,
    segments: Vec<DeploySegmentRecord>,
}

async fn cmd_deploy(
    bin_path: &Path,
    payer_path: &Path,
    rpc_url: &str,
    out_path: &Path,
    key_store: &Path,
    immutable: bool,
) -> Result<()> {
    let bin_bytes = fs::read(bin_path)?;
    let binary = ProgramBinary::decode(&bin_bytes)?;
    anyhow::ensure!(binary.kernel_elf == V1COMPAT_ELF, "invalid kernel ELF");
    let image_id = binary.compute_image_id()?;
    let image_id_u32: [u32; 8] = image_id.into();
    let image_id_hex = format_image_id_hex(&image_id_u32);
    let mut sh = Sha256::new();
    sh.update(&bin_bytes);
    let bin_sha = hex::encode(sh.finalize());

    let chunks = chunk_user_elf(binary.user_elf);
    let (hdr_sk, hdr_id, seg_pairs) = create_and_save_deploy_keys(chunks.len(), key_store)?;
    let seg_ids: Vec<AccountId> = seg_pairs.iter().map(|p| p.1).collect();

    let payer = load_wallet(payer_path, "deploy-payer")?;
    let client = LezRpc::connect(rpc_url)?;
    let pre_bal = client.get_balance(payer.account_id).await?;
    println!(
        "Deploying {} ({} segments, image_id={}) to target program_id={hdr_id} using payer={} (bal={pre_bal})",
        bin_path.display(),
        chunks.len(),
        image_id_hex,
        payer.account_id
    );

    let mut seg_records = Vec::with_capacity(chunks.len());
    for i in (0..chunks.len()).rev() {
        let next_seg = seg_ids.get(i + 1).copied();
        let existing_seg = client.get_account(seg_ids[i]).await?;
        let pre_step_bal = client.get_balance(payer.account_id).await?;

        if !existing_seg.shard_bytes(&PROGRAM_LOADER_ACCOUNT_ID).is_empty() {
            println!("  Segment[{i}] ({}) already on-chain, skipping write", seg_ids[i]);
            seg_records.push(DeploySegmentRecord {
                index: i,
                segment_account: seg_ids[i].to_string(),
                next_segment: next_seg.map(|s| s.to_string()),
                bytes: chunks[i].len(),
                tx_hash: "already-landed".into(),
                block_id: 0,
                payer: payer.account_id.to_string(),
                fee_paid_lepta: 0,
            });
            continue;
        }

        let payer_acct = client.get_account(payer.account_id).await?;
        let fq = client.get_fee_state().await?;
        let (tx, reserve, tx_bytes) = build_write_segment_tx(
            &seg_pairs[i].0,
            seg_ids[i],
            chunks[i],
            next_seg,
            payer.private_key(),
            payer.account_id,
            payer_acct.nonce.into(),
            &fq,
        )?;
        anyhow::ensure!(
            pre_step_bal >= reserve,
            "payer {} balance {} < segment[{}] reserve {}",
            payer.account_id,
            pre_step_bal,
            i,
            reserve
        );
        println!(
            "  Submitting WriteSegment[{i}/{}] ({}) chunk={}B tx={}B reserve={}...",
            chunks.len(),
            seg_ids[i],
            chunks[i].len(),
            tx_bytes,
            reserve
        );
        let (tx_hash, block_id) = client.send_and_wait(tx, 1200).await?;
        let post_step_bal = client.get_balance(payer.account_id).await?;
        let fee_paid = pre_step_bal.saturating_sub(post_step_bal);
        println!("    landed tx={tx_hash} block={block_id} fee_paid={fee_paid} lepta");

        let landed = client.get_account(seg_ids[i]).await?;
        anyhow::ensure!(
            !landed.shard_bytes(&PROGRAM_LOADER_ACCOUNT_ID).is_empty(),
            "segment[{i}] landed in block {block_id} but loader shard is empty (reverted)"
        );
        seg_records.push(DeploySegmentRecord {
            index: i,
            segment_account: seg_ids[i].to_string(),
            next_segment: next_seg.map(|s| s.to_string()),
            bytes: chunks[i].len(),
            tx_hash,
            block_id,
            payer: payer.account_id.to_string(),
            fee_paid_lepta: fee_paid,
        });
    }
    seg_records.sort_by_key(|r| r.index);

    // CreateHeader
    let existing_hdr = client.get_account(hdr_id).await?;
    let (hdr_tx_hash, hdr_block_id) = if let Some(h) = decode_program_header(&existing_hdr) {
        anyhow::ensure!(h.image_id == image_id_u32, "existing header image_id mismatch");
        println!("  Header ({hdr_id}) already deployed on-chain!");
        ("already-landed".to_owned(), 0)
    } else {
        let payer_acct = client.get_account(payer.account_id).await?;
        let pre_step_bal = client.get_balance(payer.account_id).await?;
        let fq = client.get_fee_state().await?;
        let (tx, reserve, tx_bytes) = build_create_header_tx(
            &hdr_sk,
            hdr_id,
            &seg_ids,
            immutable,
            payer.private_key(),
            payer.account_id,
            payer_acct.nonce.into(),
            &fq,
        )?;
        anyhow::ensure!(pre_step_bal >= reserve, "insufficient balance for CreateHeader");
        println!("  Submitting CreateHeader ({hdr_id}) tx={tx_bytes}B reserve={reserve}...");
        let (tx_hash, blk) = client.send_and_wait(tx, 1200).await?;
        println!("    landed tx={tx_hash} block={blk}");
        (tx_hash, blk)
    };

    let deployed_acct = client.get_account(hdr_id).await?;
    let decoded = decode_program_header(&deployed_acct)
        .ok_or_else(|| anyhow!("CreateHeader finished but ProgramHeader shard missing!"))?;
    anyhow::ensure!(
        decoded.image_id == image_id_u32,
        "on-chain ProgramHeader image_id {:?} != local {:?}",
        decoded.image_id,
        image_id_u32
    );
    let post_bal = client.get_balance(payer.account_id).await?;
    let total_fee = pre_bal.saturating_sub(post_bal);

    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let manifest = DeployManifest {
        rpc_url: rpc_url.to_owned(),
        program_id: hdr_id.to_string(),
        image_id_hex,
        image_id_u32,
        immutable,
        segment_count: chunks.len(),
        user_elf_bytes: binary.user_elf.len(),
        binary_bytes: bin_bytes.len(),
        binary_sha256: bin_sha,
        payer_account: payer.account_id.to_string(),
        payer_pre_balance_lepta: pre_bal,
        payer_post_balance_lepta: post_bal,
        total_fee_paid_lepta: total_fee,
        header_tx_hash: hdr_tx_hash,
        header_block_id: hdr_block_id,
        segments: seg_records,
    };
    fs::write(out_path, serde_json::to_string_pretty(&manifest)? + "\n")?;
    println!("LIVE DEPLOY VERIFIED! program_id={hdr_id} image_id={} total_fee_paid={total_fee} lepta", manifest.image_id_hex);
    Ok(())
}

async fn cmd_transfer(from: &Path, to: &Path, amount: u128, rpc_url: &str) -> Result<()> {
    let w_from = load_wallet(from, "from")?;
    let w_to = load_wallet(to, "to")?;
    let client = LezRpc::connect(rpc_url)?;
    let pre_from = client.get_balance(w_from.account_id).await?;
    let pre_to = client.get_balance(w_to.account_id).await?;
    let acct_from = client.get_account(w_from.account_id).await?;
    let fq = client.get_fee_state().await?;

    let (tx, reserve, _) = build_signed_tx(
        NATIVE_TOKEN_PROGRAM_ID,
        vec![
            ProgramShardSelector::native_balance(w_from.account_id),
            ProgramShardSelector::native_balance(w_to.account_id),
        ],
        NativeInstruction::Transfer { amount },
        &[(w_from.private_key(), w_from.account_id, acct_from.nonce.into())],
        w_from.private_key(),
        w_from.account_id,
        acct_from.nonce.into(),
        5_000,
        &fq,
    )?;
    anyhow::ensure!(
        pre_from >= amount + reserve,
        "insufficient balance {} for amount {} + reserve {}",
        pre_from,
        amount,
        reserve
    );
    let (hash, blk) = client.send_and_wait(tx, 120).await?;
    let post_from = client.get_balance(w_from.account_id).await?;
    let post_to = client.get_balance(w_to.account_id).await?;
    println!(
        "Transfer landed tx={hash} block={blk}: {} ({pre_from}->{post_from}) => {} ({pre_to}->{post_to})",
        w_from.account_id, w_to.account_id
    );
    Ok(())
}

#[derive(Serialize)]
struct LiveTxStep {
    step: String,
    kind: String,
    outcome: String,
    tx_hash: String,
    block_id: u64,
    block_timestamp_ms: u64,
    payer: String,
    gas_limit: u64,
    data_bytes: u64,
    pre_balance_lepta: u128,
    post_balance_lepta: u128,
    fee_paid_lepta: u128,
    local_sim_cycles: u64,
    notes: String,
}

#[derive(Serialize)]
struct LiveLifecycleManifest {
    rpc_url: String,
    program_id: String,
    image_id_hex: String,
    instance_id_hex: String,
    instance_pda: String,
    init_header_pda: String,
    finalized_header_pda: String,
    job_id_hex: String,
    job_pda: String,
    bootstrap_slot: u64,
    finalized_slot: u64,
    execution_block_number: u64,
    total_fee_paid_lepta: u128,
    steps: Vec<LiveTxStep>,
}

async fn submit_live_step(
    client: &LezRpc,
    step: &str,
    kind: &str,
    program_id: AccountId,
    pda_accounts: Vec<AccountId>,
    ix: Instruction,
    payer: &LoadedWallet,
    gas_limit: u64,
    sim_cycles: u64,
    expect_revert: bool,
    notes: &str,
) -> Result<LiveTxStep> {
    let pre_bal = client.get_balance(payer.account_id).await?;
    let acct = client.get_account(payer.account_id).await?;
    let fq = client.get_fee_state().await?;
    let (tx, reserve, data_bytes) = mosoo_tx(
        program_id,
        pda_accounts,
        ix,
        payer,
        acct.nonce.into(),
        gas_limit,
        &fq,
    )?;
    anyhow::ensure!(
        pre_bal >= reserve,
        "payer {} ({}) balance {} < tx reserve {} for step {step}",
        payer.label,
        payer.account_id,
        pre_bal,
        reserve
    );
    println!(
        "  Submitting [{step}] payer={} gas_limit={gas_limit} data_bytes={data_bytes} reserve={reserve}...",
        payer.account_id
    );
    match client.send_and_wait(tx, 1200).await {
        Ok((tx_hash, block_id)) => {
            let blk = client.get_v031_block(block_id).await?;
            let post_bal = client.get_balance(payer.account_id).await?;
            let fee_paid = pre_bal.saturating_sub(post_bal);
            let outcome = if expect_revert {
                "reverted_in_block"
            } else {
                "applied"
            }
            .to_owned();
            println!("    landed tx={tx_hash} block={block_id} fee_paid={fee_paid} lepta ({outcome})");
            Ok(LiveTxStep {
                step: step.to_owned(),
                kind: kind.to_owned(),
                outcome,
                tx_hash,
                block_id,
                block_timestamp_ms: blk.header.timestamp as u64,
                payer: payer.account_id.to_string(),
                gas_limit,
                data_bytes,
                pre_balance_lepta: pre_bal,
                post_balance_lepta: post_bal,
                fee_paid_lepta: fee_paid,
                local_sim_cycles: sim_cycles,
                notes: notes.to_owned(),
            })
        }
        Err(err) if expect_revert => {
            let post_bal = client.get_balance(payer.account_id).await?;
            println!("    refused at submission as expected: {err}");
            Ok(LiveTxStep {
                step: step.to_owned(),
                kind: kind.to_owned(),
                outcome: "rejected_by_rpc".to_owned(),
                tx_hash: "none".into(),
                block_id: 0,
                block_timestamp_ms: 0,
                payer: payer.account_id.to_string(),
                gas_limit,
                data_bytes,
                pre_balance_lepta: pre_bal,
                post_balance_lepta: post_bal,
                fee_paid_lepta: pre_bal.saturating_sub(post_bal),
                local_sim_cycles: sim_cycles,
                notes: format!("{notes}; rpc error: {err}"),
            })
        }
        Err(err) => Err(err),
    }
}

async fn cmd_run_testnet(
    program_id_str: &str,
    bin_path: &Path,
    vectors_dir: &Path,
    rpc_url: &str,
    init_payer_path: &Path,
    begin_payer_path: &Path,
    miller_payer_path: &Path,
    finish_payer_path: &Path,
    attest_payer_path: &Path,
    out_dir: &Path,
    instance_seed: Option<&str>,
) -> Result<()> {
    let sim = run_local_sim(bin_path, vectors_dir)?;
    let sim_headroom = |c: u64| -> u64 { ((c.saturating_mul(105)) / 100 + 50_000).min(MAX_GAS_EXEC) };

    let prog_id: AccountId = program_id_str
        .parse()
        .map_err(|e| anyhow!("invalid program_id Base58: {e:?}"))?;
    let client = LezRpc::connect(rpc_url)?;
    let hdr_acct = client.get_account(prog_id).await?;
    let decoded_hdr = decode_program_header(&hdr_acct)
        .ok_or_else(|| anyhow!("program {prog_id} does not have a valid ProgramHeader on {rpc_url}"))?;
    anyhow::ensure!(
        decoded_hdr.image_id == sim.image_id_u32,
        "live program ImageID mismatch"
    );

    let w_init = load_wallet(init_payer_path, "init-payer")?;
    let w_begin = load_wallet(begin_payer_path, "begin-payer")?;
    let w_miller = load_wallet(miller_payer_path, "miller-payer")?;
    let w_finish = load_wallet(finish_payer_path, "finish-payer")?;
    let w_attest = load_wallet(attest_payer_path, "attest-payer")?;

    let b = load_mainnet_bundle(vectors_dir)?;
    let instance_id: [u8; 32] = if let Some(seed_hex) = instance_seed {
        let mut h = Sha256::new();
        h.update(seed_hex.as_bytes());
        h.finalize().into()
    } else {
        let mut r = [0u8; 32];
        OsRng.fill_bytes(&mut r);
        r
    };
    let inst_pda = instance_account(&prog_id, &instance_id);
    let init_hdr_pda = header_account(&prog_id, &instance_id, b.bootstrap_header.slot);
    let inst0 = make_initial_instance(instance_id, &b)?;
    let jid = job_id(&inst0, &b.update);
    let jpda = job_account(&prog_id, &instance_id, &jid);
    let inst1 = compute_next_instance(&inst0, &b.update)?;
    let fin_hdr_pda = header_account(&prog_id, &instance_id, inst1.current_slot);

    println!("=== LIVE LEZ v0.3.1 RUN ===");
    println!("  program_id    : {prog_id}");
    println!("  image_id_hex  : {}", sim.image_id_hex);
    println!("  instance_id   : {}", hex::encode(instance_id));
    println!("  instance_pda  : {inst_pda}");
    println!("  init_hdr_pda  : {init_hdr_pda}");
    println!("  job_pda       : {jpda}");
    println!("  fin_hdr_pda   : {fin_hdr_pda}");

    let mut steps = Vec::new();
    let init_ix = make_init_ix(instance_id, &b);

    // 1. Init
    let s1 = submit_live_step(
        &client,
        "Init",
        "positive",
        prog_id,
        vec![inst_pda, init_hdr_pda],
        init_ix.clone(),
        &w_init,
        sim_headroom(sim.init_cycles),
        sim.init_cycles,
        false,
        &format!("Bootstrap mainnet slot {}", b.bootstrap_header.slot),
    )
    .await?;
    steps.push(s1);
    let live_inst0 = MosooInstance::try_from_slice(client.get_account(inst_pda).await?.shard_bytes(&prog_id))?;
    anyhow::ensure!(live_inst0 == inst0, "live Init state mismatch");

    // 2. Begin
    let s2 = submit_live_step(
        &client,
        "Begin",
        "positive",
        prog_id,
        vec![inst_pda, jpda],
        Instruction::Begin {
            instance_id,
            current: inst0.clone(),
            update: b.update.clone(),
            committee: b.bootstrap_committee.clone(),
            witness: b.witness.clone(),
        },
        &w_begin,
        sim_headroom(sim.begin_cycles),
        sim.begin_cycles,
        false,
        &format!("Open BLS split-pairing job to slot {}", b.finalized_slot),
    )
    .await?;
    steps.push(s2);
    let live_job = MosooJob::try_from_slice(client.get_account(jpda).await?.shard_bytes(&prog_id))?;
    anyhow::ensure!(live_job.miller_result.is_none());

    // 3. Miller
    let s3 = submit_live_step(
        &client,
        "Miller",
        "positive",
        prog_id,
        vec![jpda],
        Instruction::Miller {
            instance_id,
            job_id: jid,
        },
        &w_miller,
        sim_headroom(sim.miller_cycles),
        sim.miller_cycles,
        false,
        "Compute BLS12-381 multi_miller_loop intermediate Fq12 state",
    )
    .await?;
    steps.push(s3);
    let live_job_m = MosooJob::try_from_slice(client.get_account(jpda).await?.shard_bytes(&prog_id))?;
    anyhow::ensure!(live_job_m.miller_result.is_some());

    // 4. Finish
    let s4 = submit_live_step(
        &client,
        "Finish",
        "positive",
        prog_id,
        vec![inst_pda, jpda, fin_hdr_pda],
        Instruction::Finish {
            instance_id,
            job_id: jid,
            current: inst0.clone(),
            next: inst1.clone(),
        },
        &w_finish,
        sim_headroom(sim.finish_cycles),
        sim.finish_cycles,
        false,
        &format!("Verify final_exponentiation + advance to slot {} / block {}", b.finalized_slot, b.exec_block_number),
    )
    .await?;
    steps.push(s4);
    let live_inst1 = MosooInstance::try_from_slice(client.get_account(inst_pda).await?.shard_bytes(&prog_id))?;
    anyhow::ensure!(live_inst1.execution_block_number == b.exec_block_number);
    anyhow::ensure!(client.get_account(jpda).await?.shard_bytes(&prog_id).is_empty(), "live job PDA must close");
    let live_hdr1 = MosooHeaderRecord::try_from_slice(client.get_account(fin_hdr_pda).await?.shard_bytes(&prog_id))?;
    anyhow::ensure!(live_hdr1.execution_block_number == b.exec_block_number);

    // 5. Attest WETH Balance
    let s5 = submit_live_step(
        &client,
        "Attest_WETH_Balance",
        "positive",
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.weth_balance_proof.clone(),
            predicate: b.weth_balance_pred.clone(),
            privacy_salt: None,
            privacy_mode: Some(WirePrivacyMode::Public),
        },
        &w_attest,
        sim_headroom(sim.attest_balance_cycles),
        sim.attest_balance_cycles,
        false,
        "Verify Ethereum Mainnet WETH balance MPT inclusion + Predicate::AtLeast",
    )
    .await?;
    steps.push(s5);

    // 6. Attest WETH Storage
    let s6 = submit_live_step(
        &client,
        "Attest_WETH_Storage",
        "positive",
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.weth_storage_proof.clone(),
            predicate: b.weth_storage_pred.clone(),
            privacy_salt: None,
            privacy_mode: Some(WirePrivacyMode::Public),
        },
        &w_attest,
        sim_headroom(sim.attest_storage_cycles),
        sim.attest_storage_cycles,
        false,
        "Verify WETH slot 0 storage MPT inclusion",
    )
    .await?;
    steps.push(s6);

    // 7. Attest USDC Transfer Receipt (Confidential)
    let s7 = submit_live_step(
        &client,
        "Attest_USDC_Transfer_Confidential",
        "positive",
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id,
            slot: b.finalized_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.receipt_proof.clone(),
            predicate: b.receipt_pred.clone(),
            privacy_salt: Some([0xABu8; 32]),
            privacy_mode: Some(WirePrivacyMode::Confidential),
        },
        &w_attest,
        sim_headroom(sim.attest_confidential_cycles),
        sim.attest_confidential_cycles,
        false,
        "Verify USDC ERC20 Transfer receipt MPT inclusion + Confidential commitment shielding",
    )
    .await?;
    steps.push(s7);

    // Negative refusal 1: Wrong chain_id on Attest (runs after all 7 positive steps)
    let s8 = submit_live_step(
        &client,
        "Refusal_Attest_Wrong_Chain",
        "negative",
        prog_id,
        vec![fin_hdr_pda],
        Instruction::Attest {
            instance_id,
            slot: b.finalized_slot,
            chain_id: 11_155_111,
            proof: b.weth_balance_proof.clone(),
            predicate: b.weth_balance_pred.clone(),
            privacy_salt: None,
            privacy_mode: None,
        },
        &w_attest,
        220_000,
        0,
        true,
        "Attempt Attest with Sepolia chain_id=11155111 against Mainnet header_pda (E7313)",
    )
    .await?;
    steps.push(s8);
    let after_wrong_chain =
        MosooInstance::try_from_slice(client.get_account(inst_pda).await?.shard_bytes(&prog_id))?;
    anyhow::ensure!(after_wrong_chain == live_inst1, "Refused wrong-chain Attest altered instance");

    // Negative refusal 2: Attest against unrecorded future slot header PDA
    let missing_slot = b.finalized_slot + 1;
    let missing_hdr_pda = header_account(&prog_id, &instance_id, missing_slot);
    let s9 = submit_live_step(
        &client,
        "Refusal_Attest_Unknown_Slot",
        "negative",
        prog_id,
        vec![missing_hdr_pda],
        Instruction::Attest {
            instance_id,
            slot: missing_slot,
            chain_id: CHAIN_ID_MAINNET,
            proof: b.weth_balance_proof.clone(),
            predicate: b.weth_balance_pred.clone(),
            privacy_salt: None,
            privacy_mode: None,
        },
        &w_attest,
        220_000,
        0,
        true,
        "Attempt Attest against unrecorded beacon slot PDA (E7392)",
    )
    .await?;
    steps.push(s9);
    anyhow::ensure!(
        client.get_account(missing_hdr_pda).await?.shard_bytes(&prog_id).is_empty(),
        "Unknown slot header PDA must remain empty"
    );

    fs::create_dir_all(out_dir)?;
    let total_fee: u128 = steps.iter().map(|s| s.fee_paid_lepta).sum();
    let manifest = LiveLifecycleManifest {
        rpc_url: rpc_url.to_owned(),
        program_id: prog_id.to_string(),
        image_id_hex: sim.image_id_hex.clone(),
        instance_id_hex: hex::encode(instance_id),
        instance_pda: inst_pda.to_string(),
        init_header_pda: init_hdr_pda.to_string(),
        finalized_header_pda: fin_hdr_pda.to_string(),
        job_id_hex: hex::encode(jid),
        job_pda: jpda.to_string(),
        bootstrap_slot: b.bootstrap_header.slot,
        finalized_slot: b.finalized_slot,
        execution_block_number: b.exec_block_number,
        total_fee_paid_lepta: total_fee,
        steps,
    };

    let mut tsv = String::from("step\tkind\toutcome\ttx_hash\tblock_id\tpayer\tgas_limit\tlocal_sim_cycles\tfee_paid_lepta\n");
    for s in &manifest.steps {
        tsv.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\n",
            s.step,
            s.kind,
            s.outcome,
            s.tx_hash,
            s.block_id,
            s.payer,
            s.gas_limit,
            s.local_sim_cycles,
            s.fee_paid_lepta
        ));
    }
    fs::write(out_dir.join("run.tsv"), tsv)?;
    fs::write(
        out_dir.join("lifecycle_manifest.json"),
        serde_json::to_string_pretty(&manifest)? + "\n",
    )?;
    println!("LIVE RUN COMPLETE! Total fees paid = {total_fee} lepta. Manifest saved to {}", out_dir.display());
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Pack { elf, out } => cmd_pack(&elf, &out),
        Commands::CheckWallets { rpc, wallets } => cmd_check_wallets(&rpc, &wallets).await,
        Commands::Simulate { bin, vectors } => {
            let r = run_local_sim(&bin, &vectors)?;
            println!("\n=== SIMULATION SUMMARY (10M MAX_GAS_EXEC GATE) ===");
            println!(
                "Init={} Begin={} Miller={} Finish={} AttestBal={} AttestStor={} AttestRcpt={} AttestConf={}",
                r.init_cycles,
                r.begin_cycles,
                r.miller_cycles,
                r.finish_cycles,
                r.attest_balance_cycles,
                r.attest_storage_cycles,
                r.attest_receipt_cycles,
                r.attest_confidential_cycles
            );
            Ok(())
        }
        Commands::Deploy {
            bin,
            payer,
            rpc,
            out,
            key_store,
            immutable,
        } => cmd_deploy(&bin, &payer, &rpc, &out, &key_store, immutable).await,
        Commands::Transfer {
            from,
            to,
            amount,
            rpc,
        } => cmd_transfer(&from, &to, amount, &rpc).await,
        Commands::RunTestnet {
            program_id,
            bin,
            vectors,
            rpc,
            init_payer,
            begin_payer,
            miller_payer,
            finish_payer,
            attest_payer,
            out_dir,
            instance_seed,
        } => {
            cmd_run_testnet(
                &program_id,
                &bin,
                &vectors,
                &rpc,
                &init_payer,
                &begin_payer,
                &miller_payer,
                &finish_payer,
                &attest_payer,
                &out_dir,
                instance_seed.as_deref(),
            )
            .await
        }
    }
}
