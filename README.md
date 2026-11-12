# Mosoo

[![CI](https://github.com/mosoo-xyz/lez-mosoo/actions/workflows/ci.yml/badge.svg)](https://github.com/mosoo-xyz/lez-mosoo/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/Rust-1.88%2B-orange.svg)](https://www.rust-lang.org)

Mosoo is an Ethereum consensus light client and state-attestation program for the Logos Execution Zone (LEZ), built for [Logos RFP-021](https://github.com/logos-co/rfp).

It verifies 512-validator Ethereum sync-committee BLS12-381 aggregate signatures across a 3-transaction split (`begin`, `miller`, `finish`) to stay under LEZ's 10M per-transaction gas cap, then verifies Merkle-Patricia Trie (MPT) inclusion proofs for Ethereum balances, storage slots, and receipt logs against authenticated `HeaderRecord` PDAs.

---

## Current Status & Honest Boundaries

### Deployed & Verified
- **LEZ v0.3.1 Program (`mosoo_lc`)**: Built from [`programs/mosoo-lez-v03/`](programs/mosoo-lez-v03/src/lib.rs) + [`mosoo-core/`](mosoo-core/), deployed immutably at `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg` (blocks `81142`–`81148`, ImageID `961a7e12973295f5d728443b4ee3aea6131c9de03111aba40e6751adae8503e0`) on `https://testnet.lez.logos.co`. Executed across 9 live transactions (`81154`–`81163`: `Init`, `Begin`, `Miller`, `Finish`, 3 `Attest` calls advancing PDA state to Mainnet slot `15,632,352` / execution block `#26,392,691`, and 2 on-chain refusals). Verified `30/30` live via [`scripts/verify-mosoo-lez.py`](scripts/verify-mosoo-lez.py) ([`evidence/mosoo-testnet-v03/`](evidence/mosoo-testnet-v03/README.md)).
- **Sepolia `MosooLocker` v2**: Deployed and commissioned with a `2-of-2` EIP-712 attester quorum at [`0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b`](https://sepolia.etherscan.io/address/0xEFEf6dA5f8690D6C1cE8EA83c19DFD72DE621B1b) (`strictFixedDenominationMode = true`, live `DepositCommitted` and `UnlockedShieldedETH` roundtrip verified; earlier v1 contract at [`0x74625D146B8d9413F3c3976B323d94A739be7856`](https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856)).
- **Local Test Suite**: `331` Rust workspace tests (`cargo test --workspace`) + `20` Foundry EVM tests (`forge test -vvv`) pass cleanly with `cargo fmt --all -- --check` and `cargo clippy --workspace --all-targets -- -D warnings`. Includes real Beacon/execution JSON vectors for Mainnet Fulu, Sepolia Gloas (`DepositCommitted`), and Hoodi Fulu under [`vectors/`](vectors/).
- **v0.4 Target Guest Binary**: Compiled `riscv32im-risc0-zkvm-elf` ELF (`922,052` bytes) archived at [`artifacts/v04-guest/mosoo-guest`](artifacts/v04-guest/mosoo-guest) (`SHA-256: 733bff2a...`).

### Limitations & Unimplemented Pieces
- **Public LEZ v0.4 Testnet**: Upstream public LEZ `v0.4` is not released yet (`v0.3.1` is current). All `v0.4` tests (`sequencer_e2e_tests`, `lez_v04_acceptance_tests`, [`evidence/sequencer-harness-v04/`](evidence/sequencer-harness-v04/run.tsv)) run against an offline `LezRuntimeAdapter` harness rather than a live `v0.4` RPC.
- **Deployed `mosoo_lc` Binary Age**: Live immutable `Co5EYuBR...` (`mosoo_lc.bin`) was compiled before the final workspace hardening checks in [`mosoo-core/src/crypto.rs`](mosoo-core/src/crypto.rs) (`is_supported_chain_or_configured` strict built-in chain check) and [`mosoo-core/src/types.rs`](mosoo-core/src/types.rs) (`is_trusted_shielded_locker` default recognition of Sepolia v2 `0xEFEf...`). Redeploying to a new program ID picks up those checks.
- **RFP-021 vs RFP-022 Scope**: Mosoo targets inbound state attestation (RFP-021). The bridge/escrow components (`contracts/MosooLocker.sol`, `consumers/*`) explore two-way bridging with `DepositCommitted` events and fixed-denomination tiers, **not** full RFP-022 privacy:
  - No on-LEZ Groth16 circuit hides `tx_index`/`log_index` or Merkle paths during LEZ claims.
  - No wrapped token/consumer program is deployed on `testnet.lez.logos.co` yet (`consumers/*` are verified via Rust workspace tests and Python simulation).
  - Live Sepolia v2 currently has `shieldedDepositsOnly = false`, and 6-decimal ERC-20 tokens require owner `setStandardDenomination` configuration while `strictFixedDenominationMode = true`.
  - Outbound Ethereum unlocks rely on a `2-of-2` EIP-712 attester quorum rather than an on-chain L1 validity proof of LEZ state.
  - No Basecamp mini-app is included.
- **Daemon & External Audit**: `mosoo-daemon` does not yet expose HTTP `/metrics` or `/healthz` endpoints, and no third-party security audit has been conducted yet.

---

## Architecture

### Why the 3-Transaction BLS Split Exists

Verifying a 512-validator BLS12-381 aggregate signature in one RISC Zero zkVM call exceeds LEZ's `10,000,000` gas cap (modeled ~`13.3M` total gas; see [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md)). Because LEZ does not currently expose host BLS12-381 precompiles, Mosoo splits signature verification across three transactions linked by a `JobAccount` PDA (`update_digest` commitment):

1. **`begin_update`**: Checks monotonic slot progression, validates the 64-byte participation bitfield (`>= 342 / 512`), aggregates participating G1 pubkeys, and computes the G2 signing root point.
2. **`miller_update`**: Computes the dual Miller loop pairing accumulator `e(sig, G1) * e(msg, agg_pk)^-1` via `blst`.
3. **`finish_update`**: Executes the `F_p12` final exponentiation, checks identity, authenticates the execution payload branch and Committee handoff branch, writes the `HeaderRecord` PDA, and closes the job.

Measured `r0vm 3.0.5` cycle counts for `mosoo_lc` are recorded in [`evidence/mosoo-testnet-v03/local_simulation.txt`](evidence/mosoo-testnet-v03/local_simulation.txt) (`Init`: `927,806`, `Begin`: `2,558,057`, `Miller`: `4,568,088`, `Finish`: `3,705,545`, `Attest`: `200,594`–`362,755` cycles). Modeled v0.4 gas estimates and host CPU timings are separated in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

### Fork-Aware SSZ Generalized Indices

[`mosoo-core/src/crypto.rs`](mosoo-core/src/crypto.rs) selects SSZ generalized indices dynamically by chain/slot:

| Proof Field | Altair / Deneb | Electra / Fulu | Gloas (ePBS) |
| :--- | :---: | :---: | :---: |
| Current sync committee | 54 | 86 | 2945 |
| Next sync committee | 55 | 87 | 2946 |
| Finalized checkpoint root | 105 | 169 | 735 |
| Execution payload / block hash | 25 | 25 | 2856 |
| Historical block roots vector | 37 | 69 | 352 |

For Gloas ePBS, `gindex 2856` commits to `block_hash`, so [`mosoo-core/src/verifier.rs`](mosoo-core/src/verifier.rs) requires `execution_rlp`, asserts `keccak256(execution_rlp) == block_hash`, and extracts `state_root` and `receipts_root` from RLP.

### Replay Protection & Consumer Verification

Consumers verify Merkle-Patricia Trie proofs (`alloy-trie`) against an authenticated `HeaderRecord` and derive canonical V2 statement IDs ([`mosoo-core/src/predicate.rs`](mosoo-core/src/predicate.rs)):

```text
statement_id = sha256("mosoo_statement_v2" || chain_id || genesis_validators_root || source_instance_pda || subject_key || proof_type_tag || verified_value)
```

- Predicate evaluation (`Equal`, `AtLeast`, `LessThan`, `And`, `Or`, `Not`) executes over the verified value inside the attestation, while `statement_id` depends only on the underlying state fact so attackers cannot vary predicate thresholds to replay a claim.
- Consumers bind explicitly to trusted instance PDAs, locker addresses, token allowlists, and persistent nullifier PDAs via `TrustedBridgeConfig` ([`docs/CONSUMERS.md`](docs/CONSUMERS.md)).

---

## Quick Verification

```bash
git clone https://github.com/mosoo-xyz/lez-mosoo && cd lez-mosoo

# Rust workspace (331 unit, integration & doc-tests)
cargo test --workspace

# Solidity vault tests (20 Foundry tests; requires foundry/solc)
forge test -vvv

# Verify Mosoo's live LEZ v0.3.1 deployment, 6 segments & Mainnet #26,392,691 PDAs (30 checks)
python3 scripts/verify-mosoo-lez.py

# Verify offline sequencer harness & mutation suite
python3 scripts/verify-evidence.py
python3 scripts/test-evidence-mutation.py

# Query live Sepolia v2 DepositCommitted + simulate LEZ bridge steps locally
python3 scripts/testnet-two-way-bridge.py --mode live
python3 scripts/testnet-two-way-bridge.py --mode simulated

# Local host CPU crypto benchmarks & fixture walkthrough
cargo run -p mosoo-cli -- benchmarks
cargo run -p mosoo-cli -- demo --mode fixture
```

Full check scripts: [`scripts/verify_all.sh`](scripts/verify_all.sh) / [`scripts/verify_all.ps1`](scripts/verify_all.ps1). Reproducible zkVM container instructions (`docker/Dockerfile.guest`, Rust `1.88.0` + `cargo-risczero 1.2.6`): [`docs/REPRODUCE.md`](docs/REPRODUCE.md).

---

## Repository Layout

```text
lez-mosoo/
├── mosoo-core/              Core crypto (blst), SSZ/fork proofs, MPT inclusion, predicates, runtime adapter
├── methods/guest/           RISC Zero guest target (riscv32im-risc0-zkvm-elf)
├── programs/mosoo-lez-v03/  LEZ v0.3.1 deployed light-client wrapper + CLI
├── consumers/               Reference consumer logic (erc20-receiver, ether-receiver)
├── daemon/                  Beacon polling relayer with randomized jitter & verified proxy option
├── cli/                     Developer CLI (demo, attest, dry-run, submit-update, benchmarks, config)
├── contracts/               MosooLocker.sol + Foundry tests (contracts/test/MosooLocker.t.sol)
├── vectors/                 Real Ethereum chain fixtures (Mainnet Fulu, Sepolia Gloas/v2, Hoodi Fulu)
├── evidence/                Live LEZ v0.3.1 traces, offline v0.4 harness manifest & verify logs
├── benchmarks/              Host CPU timings & hardware/ELF profiles
├── docker/                  Dockerfile.guest for reproducible RISC0 guest ELF builds
├── scripts/                 Verification, deployment, wallet & simulation scripts
└── docs/                    Architecture, deployment registry, security review, ADRs, SPEL IDL
```

---

## Documentation

- [`docs/DEPLOYMENTS.md`](docs/DEPLOYMENTS.md) — Live Sepolia v2/v1, live LEZ `mosoo_lc`, and offline harness boundaries.
- [`docs/REPRODUCE.md`](docs/REPRODUCE.md) — Reproducible Docker/RISC0 guest build and ID boundaries.
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — System design, generalized indices, and PDA state schema.
- [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) — Measured `r0vm 3.0.5` cycles, host CPU timings, and modeled v0.4 estimates.
- [`docs/BLS_LIBRARY_ANALYSIS.md`](docs/BLS_LIBRARY_ANALYSIS.md) — Why `blst` was selected over pure-Rust BLS crates.
- [`docs/CONSUMERS.md`](docs/CONSUMERS.md) — Atomic consumer integration pattern and verification checks.
- [`docs/DAEMON.md`](docs/DAEMON.md) & [`docs/OPERATIONS.md`](docs/OPERATIONS.md) — Relayer configuration, proxy routing, and incident handling.
- [`docs/TRUST_ASSUMPTIONS.md`](docs/TRUST_ASSUMPTIONS.md) & [`docs/security-review.md`](docs/security-review.md) — Threat model, economic attack bounds, trust boundaries, and security invariants.
- [`docs/DECISIONS.md`](docs/DECISIONS.md) & [`docs/PRIOR_ART.md`](docs/PRIOR_ART.md) — Architectural decision records and Helios/prior-art evaluation.
- [`docs/TESTING.md`](docs/TESTING.md), [`docs/SPEL_IDL.md`](docs/SPEL_IDL.md), & [`docs/V04_MIGRATION.md`](docs/V04_MIGRATION.md) — Test matrix, SPEL IDL, and v0.4 runtime migration notes.

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
