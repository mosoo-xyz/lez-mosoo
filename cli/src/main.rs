//! Mosoo CLI — Ethereum light-client and state attestation tool for LEZ (RFP-021).
//!
//! Exposes interactive simulation, canonical fixture verification, and live empirical benchmarks.

#![allow(deprecated)]

use clap::{Parser, Subcommand};
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "mosoo",
    about = "Trustless Ethereum State Attestation for the Logos Execution Zone (RFP-021)",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Run an end-to-end attestation & consumer demo
    Demo {
        /// Chain ID (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi, 17000 = Holesky)
        #[arg(long, default_value = "1")]
        chain_id: u64,
        /// Deposit amount in token units
        #[arg(long, default_value = "1000")]
        amount: u64,
        /// Execution mode: "simulation" (local mock data) or "fixture" (real cryptographic vectors)
        #[arg(long, default_value = "simulation")]
        mode: String,
    },
    /// Attest Ethereum state, account balance, or receipt logs with MPT proof to LEZ (RFP-021)
    Attest {
        /// Chain ID (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi, 17000 = Holesky)
        #[arg(long, default_value = "1")]
        chain_id: u64,
        /// Target Ethereum address (0x...)
        #[arg(long, default_value = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045")]
        address: String,
        /// Optional token owner address (0x...) for ERC-20 mapping slot derivation
        #[arg(long)]
        owner: Option<String>,
        /// Optional mapping slot index for ERC-20 private _balances layout (default: 0)
        #[arg(long, default_value = "0")]
        mapping_slot: u64,
        /// Optional transaction hash (0x...) for live deposit event receipt extraction
        #[arg(long)]
        tx_hash: Option<String>,
        /// Enable local simulation/demo mode (permits synthetic fixture testing and test BLS committees)
        #[arg(long)]
        demo: bool,
        /// Allow fallback to unfinalized block ("latest") when "finalized" block tag is absent on RPC node (e.g. devnet)
        #[arg(long)]
        allow_unfinalized: bool,
        /// Slot number for the target state
        #[arg(long, default_value = "15433760")]
        slot: u64,
        /// Target proof type: "balance", "erc20", or "deposit"
        #[arg(long, default_value = "balance")]
        target: String,
        /// Minimum predicate value (e.g. in wei or token units)
        #[arg(long, default_value = "1000000000000000000")]
        min_value: u64,
        /// Optional Ethereum JSON-RPC endpoint for live eth_getProof extraction
        #[arg(long)]
        rpc_url: Option<String>,
        /// Optional Logos Core Ethereum proxy RPC endpoint
        #[arg(long)]
        logos_core_rpc: Option<String>,
        /// Perform local cryptographic validation without submitting to LEZ
        #[arg(long)]
        dry_run: bool,
        /// Privacy mode for emitted statement: "public", "address-private", or "confidential" (RFP-021 F#8)
        #[arg(long, default_value = "public")]
        privacy_mode: String,
        /// Optional 32-byte secret salt (hex 0x...) for privacy-preserving blinding commitments
        #[arg(long)]
        privacy_salt: Option<String>,
        /// Optional path to a JSON LightClientBootstrap or checkpoint file containing authentic sync committee keys
        #[arg(long)]
        bootstrap_file: Option<String>,
        /// Optional public Beacon REST endpoint to load live sync committee keys from an active consensus client
        #[arg(long)]
        beacon_rpc: Option<String>,
        /// Optional LEZ Sequencer JSON-RPC URL for querying authentic deployed program accounts
        #[arg(long)]
        sequencer_url: Option<String>,
        /// Broadcast signed attestation transaction to the LEZ Sequencer (requires --sequencer-url and funded account)
        #[arg(long)]
        broadcast: bool,
    },
    /// Offline local simulation of BLS light client update and MPT proof verification (RFP-021)
    DryRun {
        /// Chain ID (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi, 17000 = Holesky)
        #[arg(long, default_value = "1")]
        chain_id: u64,
        /// Optional path to a JSON LightClientUpdate file
        #[arg(long)]
        update_file: Option<String>,
    },
    /// Manually submit a verified consensus update to the LEZ Sequencer (RFP-021)
    SubmitUpdate {
        /// Chain ID (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi, 17000 = Holesky)
        #[arg(long, default_value = "1")]
        chain_id: u64,
        /// Optional path to a JSON LightClientUpdate file (defaults to canonical testnet update)
        #[arg(long)]
        update_file: Option<String>,
        /// LEZ Sequencer RPC URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        lez_rpc: String,
        /// Signer private key for LEZ gas payments
        #[arg(long)]
        private_key: Option<String>,
    },
    /// Display system configuration, fork schedules, contract addresses, and weak-subjectivity parameters (RFP-021)
    Config {
        /// Filter config display by chain ID (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi, 17000 = Holesky)
        #[arg(long, default_value = "1")]
        chain_id: u64,
        /// Optional light-client instance ID or PDA (hex 0x...) to inspect on-chain instance configuration
        #[arg(long)]
        instance: Option<String>,
    },
    /// Independently verify a weak-subjectivity bootstrap checkpoint against consensus rules and public beacon data (RFP-021)
    VerifyCheckpoint {
        /// Chain ID (1 = Mainnet, 11155111 = Sepolia, 560048 = Hoodi, 17000 = Holesky)
        #[arg(long, default_value = "1")]
        chain_id: u64,
        /// Optional path to a JSON Bootstrap checkpoint file (defaults to canonical testnet fixture)
        #[arg(long)]
        bootstrap_file: Option<String>,
        /// Trusted network head slot (for weak-subjectivity freshness bounds verification)
        #[arg(long, default_value = "15450000")]
        trusted_head_slot: u64,
        /// Optional public beacon block root (hex 0x...) for cryptographic root cross-check
        #[arg(long)]
        trusted_block_root: Option<String>,
        /// Optional public Beacon chain RPC endpoint
        #[arg(long)]
        beacon_rpc: Option<String>,
        /// Run in local demo mode (allows unanchored self-consistent simulation)
        #[arg(long)]
        demo: bool,
    },
    /// Run real empirical benchmarks measuring execution times, zkVM cycles, and gas
    Benchmarks,
    /// Inspect supported chains, technical architecture, and test suite verification evidence
    Info,
}

pub(crate) fn print_banner() {
    println!("\x1b[1;36m");
    println!(r#"  __  __  ___  ____   ___   ___  "#);
    println!(r#" |  \/  |/ _ \/ ___| / _ \ / _ \ "#);
    println!(r#" | |\/| | | | \___ \| | | | | | |"#);
    println!(r#" | |  | | |_| |___) | |_| | |_| |"#);
    println!(r#" |_|  |_|\___/|____/ \___/ \___/ "#);
    println!("\x1b[0m");
    println!("\x1b[1m Mosoo: Trustless Ethereum State Attestation for LEZ (RFP-021)\x1b[0m");
    println!(" Ethereum consensus & state verification module \n");
}

pub(crate) fn sleep_step() {
    std::thread::sleep(Duration::from_millis(80));
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    print_banner();

    match cli.command {
        Commands::Demo {
            chain_id,
            amount,
            mode,
        } => run_demo(chain_id, amount, &mode),
        Commands::Attest {
            chain_id,
            address,
            owner,
            mapping_slot,
            tx_hash,
            demo,
            allow_unfinalized,
            slot,
            target,
            min_value,
            rpc_url,
            logos_core_rpc,
            dry_run,
            privacy_mode,
            privacy_salt,
            bootstrap_file,
            beacon_rpc,
            sequencer_url,
            broadcast,
        } => run_attest(AttestArgs {
            chain_id,
            address_str: &address,
            owner_str: owner.as_deref(),
            mapping_slot,
            tx_hash: tx_hash.as_deref(),
            demo,
            allow_unfinalized,
            slot,
            target: &target,
            min_value,
            rpc_url: rpc_url.as_deref(),
            logos_core_rpc: logos_core_rpc.as_deref(),
            dry_run,
            privacy_mode: &privacy_mode,
            privacy_salt: privacy_salt.as_deref(),
            bootstrap_file: bootstrap_file.as_deref(),
            beacon_rpc: beacon_rpc.as_deref(),
            sequencer_url: sequencer_url.as_deref(),
            broadcast,
        }),
        Commands::DryRun {
            chain_id,
            update_file,
        } => run_dry_run(chain_id, update_file.as_deref()),
        Commands::SubmitUpdate {
            chain_id,
            update_file,
            lez_rpc,
            private_key,
        } => run_submit_update(
            chain_id,
            update_file.as_deref(),
            &lez_rpc,
            private_key.as_deref(),
        ),
        Commands::Config { chain_id, instance } => run_config(chain_id, instance.as_deref()),
        Commands::VerifyCheckpoint {
            chain_id,
            bootstrap_file,
            trusted_head_slot,
            trusted_block_root,
            beacon_rpc,
            demo,
        } => run_verify_checkpoint(
            chain_id,
            bootstrap_file.as_deref(),
            trusted_head_slot,
            trusted_block_root.as_deref(),
            beacon_rpc.as_deref(),
            demo,
        ),
        Commands::Benchmarks => run_benchmarks(),
        Commands::Info => run_info(),
    }
}

mod attest;
mod consensus;
mod demo;
#[allow(unused_imports)]
use attest::*;
#[allow(unused_imports)]
use consensus::*;
#[allow(unused_imports)]
use demo::*;

#[cfg(test)]
mod tests;
