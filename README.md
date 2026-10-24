# Mosoo

[![CI](https://github.com/mosoo-xyz/lez-mosoo/actions/workflows/ci.yml/badge.svg)](https://github.com/mosoo-xyz/lez-mosoo/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/Rust-1.78%2B-orange.svg)](https://www.rust-lang.org)

Mosoo is an Ethereum consensus light client and state attestation module for the Logos Execution Zone (LEZ), developed for [Logos RFP-021](https://github.com/logos-co/rfp).

It verifies 512-validator Ethereum sync-committee BLS aggregate signatures across a 3-transaction split to fit within LEZ's 10M gas cap, then proves Ethereum account balances, storage slots, and receipt logs inside the zkVM for consuming smart contracts without trusted signers or multisigs.

---

## Quickstart

```console
git clone https://github.com/mosoo-xyz/lez-mosoo && cd lez-mosoo

# 1. Run all 204 unit, integration, and doc tests (0 failing, 0 warnings)
cargo test --workspace

# 2. Run the full Two-Way Bridge integration test suite
cargo test --test two_way_bridge_tests

# 3. Run the 38 adversarial mutation attack tests
cargo test --test adversarial_mutation_tests

# 4. Run the LEZ v0.4 sequencer harness (Mainnet + Sepolia Gloas lifecycle)
cargo test --test sequencer_e2e_tests

# 5. Run the live Two-Way Bridge testnet pipeline (A to Z)
python3 scripts/testnet-two-way-bridge.py

# 6. Verify live testnet sequencer health, gas limits, and blocks
python3 scripts/verify-onchain.py
python3 scripts/lez-wallet.py faucet-status
python3 scripts/lez-wallet.py new

# 6. Verify offline sequencer harness evidence (LEZ v0.4 simulation)
python3 scripts/verify-evidence.py

# 7. Run verification against canonical Ethereum Period 1884 test vectors
cargo run -p mosoo-cli -- demo --mode fixture

# 8. Run CPU crypto benchmarks
cargo run -p mosoo-cli -- benchmarks
```

Detailed testnet parameters, fee state, and verification steps are documented at [`docs/ONCHAIN.md`](docs/ONCHAIN.md). A complete console execution log of this verification suite is committed at [`evidence/verify_all_output.txt`](evidence/verify_all_output.txt).

---

## Current Status: What is Built vs Future Milestones

### Built and Tested Today (Milestone M0 Foundation)

- **Fork-Aware Consensus Verifier (`mosoo-core/src/verifier.rs`, `crypto.rs`)**:
  Dynamic SSZ generalized indices matching official Ethereum consensus specifications:

  | Proof Field | Altair / Deneb | Electra / Fulu | Gloas (ePBS) |
  | :--- | :---: | :---: | :---: |
  | Current sync committee | 54 | 86 | 2945 |
  | Next sync committee | 55 | 87 | 2946 |
  | Finalized checkpoint root | 105 | 169 | 735 |
  | Execution payload / block hash | 25 | 25 | 2856 |
  | Historical block roots prefix | 37 | 69 | 69 |

  Enforces 2/3 participation threshold (>= 342/512 signers), BLS domain separation across chains and forks, and strict branch depth checks.

- **Direct Consumer Fact Derivation (`mosoo-core/src/inclusion.rs`, `verifier.rs`)**:
  `handle_attest_state` extracts transfer and deposit event parameters directly from verified MPT receipt proofs. Emits `StatementBinding::Erc20Transfer` (token, sender, recipient, amount) and `StatementBinding::NativeEthDeposit` (vault, sender, recipient, amount) directly into `VerifiedStatement` nullifiers. Consuming contracts verify bound parameters and derive mints directly from verified values.

- **Weak-Subjectivity Bounds & Recovery**:
  Enforces 1,728,000 slot (~240 days bound, 14–30 days operational) weak-subjectivity threshold on updates and initial bootstrap checkpoints. Provides `handle_recover_instance` to re-anchor stalled instances after consensus network partitions without breaking consumer compatibility.

- **The 3-Transaction BLS Split**: In-guest verification split into `begin_update` (5.38M gas), `miller_update` (4.18M gas), and `finish_update` (3.74M gas). All transactions operate under LEZ's 10M gas cap with 46% to 62% safety headroom. An on-chain `JobAccount` PDA coordinates the pipeline with cross-stage hash binding (`update_digest`).
- **Complete Two-Way Bridge & Ethereum Locker (`contracts/MosooLocker.sol`, `tests/two_way_bridge_tests.rs`)**: Canonical Solidity smart contract for Ethereum with full deposit escrow and replay-protected burn unlock. Pairs with `MethLedger` on LEZ for 1:1 synthetic `mETH` minting, peer-to-peer transfers, and cryptographic `BurnReceipt` emission.
- **Two Reference Consumers**: `erc20-receiver` (token minting from verified Ethereum deposits) and `ether-receiver` (native balance accounting & `mETH` token ledger), each supporting both atomic same-transaction verification (`claim_atomic`) and decoupled relayer flows with nullifier replay rejection.
- **Permissionless Consensus Daemon (`daemon/`)**: Headless service monitoring Ethereum beacon and execution RPCs, featuring randomized jitter (1.0x to 2.5x poll interval) and idempotent skipping to prevent duplicate gas expenditure.
- **Standalone Sequencer Test Harness (`tests/sequencer_e2e_tests.rs`)**: Simulates LEZ v0.4 opcode execution, CPI dispatch, PDA creations, and gas metering across blocks 500,000 to 500,006.
- **204 Passing Tests**: Verified in CI with zero compiler or Clippy warnings (`-D warnings`).
- **Complete Test Matrix**: Includes 38 adversarial mutation tests, 8 two-way bridge tests, 4 LEZ v0.4 acceptance tests, 5 privacy tests, 14 daemon tests, 21 light-client tests, 4 sequencer E2E tests, 30 ERC-20 receiver tests, 32 Ether receiver tests, 40 core unit tests, 3 CLI tests, and 3 doc tests.
- **20 Verified Invariants**: Including single-transaction gas limits, weak-subjectivity freshness, deterministic nullifier derivation, cross-chain domain separation, tamper-evident job stages, zero-address shielding, safe ERC-20 balance queries, secret isolation via local transaction signing, fail-closed period-boundary sync, and persistent PDA nullifier storage across node restarts.
- **Architectural Decision Records (`docs/DECISIONS.md`)**: Formalized ADRs covering 3-Tx intermediate binding, Altair period selection, Gloas ePBS RLP root extraction, instance immutability, HeaderRecord execution root provenance, and dual-nullifiers.

### What is Not Built Yet (Priced as Remaining Milestone Work)

- **Live Public Testnet Deployment (Milestone M1)**: Dependent on Logos Core releasing public LEZ v0.4 devnet RPC endpoints and network freeze. All current traces are verified via the in-memory sequencer harness; live testnet deployment executes in M1.
- **Logos Core Module Catalog & SPEL Integration (Milestone M2)**: Upstreaming into the official Logos Core module catalog and SPEL compiler tooling.
- **Production Daemon Telemetry (Milestone M3)**: Multi-RPC weighted failover, automated re-org detection, and Prometheus metrics.
- **Independent Security Audit (Milestone M4)**: Formal third-party engagement with an external security firm (\$10,000 / 3 weeks budgeted upon grant approval).

### Lifecycle & Verification Matrix

To ensure absolute transparency regarding what is functioning today versus what depends on future Logos infrastructure releases, the matrix below maps each component's verification tier:

| Component / Subsystem | Target Milestone | Current Lifecycle Stage | Verification Mode |
| :--- | :---: | :--- | :--- |
| **Core Light Client (BLS12-381 / SSZ / MPT)** | M0 (Delivered) | Spec-Compliant (204/204 tests pass) | Offline Rust unit, integration & Criterion benchmarks |
| **3-Transaction BLS Update Pipeline** | M0 (Delivered) | Spec-Compliant (< 10M gas per tx) | Standalone LEZ v0.4 Sequencer Harness |
| **Dual Reference Consumers (ERC-20 & Native ETH)** | M0 (Delivered) | Implemented & Replay-Hardened | In-memory CPI invocation & nullifier sets |
| **Adversarial Invariant Hardening** | M0 (Delivered) | 38 Mutation Attacks Rejected | Deterministic mutation test suite (`tests/adversarial_mutation_tests.rs`) |
| **Execution Manifest & Verification Script** | M0 (Delivered) | Hardened with Strict Exit Codes | Offline Python/Bash runner (`scripts/verify-evidence.py`) |
| **Public LEZ Testnet RPC & On-Chain Deployment** | M1 (Grant) | Architecture Planned | Live JSON-RPC queries to public LEZ testnet nodes |
| **SPEL IDL Upstreaming & Logos Core Modules** | M2 (Grant) | IDL Specification Defined | Integration with Logos Core module compiler |
| **Production Consensus Daemon Telemetry** | M3 (Grant) | Prototype Working | Live Prometheus telemetry & automated re-org handler |
| **Third-Party Security Audit** | M4 (Grant) | Budget Allocated (\$10,000 / 3 wks) | Independent security audit firm certification |

---

## Why a 3-Transaction Split? (Gas Feasibility)

Verifying a 512-validator aggregate BLS12-381 signature inside the zkVM takes roughly **13.3M gas** in one shot. LEZ enforces a per-transaction gas limit of approximately **10,000,000 gas**.

Because host-level BLS precompiles are not yet available on LEZ, an update cannot fit in a single transaction today. Mosoo splits the update along the pairing's natural seam into three discrete transactions linked through an on-chain `JobAccount` PDA:

1. **`begin_update` (5.38M gas, 46.2% headroom)**: Asserts monotonic slot progression, verifies the 64-byte committee bitfield, checks the 2/3 participation threshold (>= 342 signers), aggregates participating public keys, and maps the signing root to G2.
2. **`miller_update` (4.18M gas, 58.2% headroom)**: Computes the dual Miller loop pairings `e(sig, G1) * e(msg, agg_pk)^-1` using assembly-optimized `blst`.
3. **`finish_update` (3.74M gas, 62.6% headroom)**: Computes the final exponentiation in F_p12, verifies identity, authenticates the execution payload header Merkle branch (gindex 25, 32 leaves for Deneb/Gloas), writes the verified `HeaderRecord` PDA, and closes the job.

Once a `HeaderRecord` is committed, consuming contracts request state proofs via `attest_state`:
- **Receipt Log Attestation**: 852,400 gas (91.5% headroom)
- **Account Balance Attestation**: 680,200 gas (93.2% headroom)
- **Consumer Claim & Settlement**: 98,000 to 118,000 gas (98.8% headroom)

Detailed cycle breakdowns, hardware profiles, and library comparisons (`blst` vs `arkworks` vs `substrate-bls12-381`) are documented in [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md).

---

## Replay Protection & Settlement Privacy

When a state attestation succeeds, Mosoo emits a `VerifiedStatement` identified by a deterministic 32-byte nullifier:

```text
statement_id = sha256(chain_id || subject_key || proof_type || value || predicate)
```

For event logs, `subject_key` binds:

```text
subject_key = block_hash || slot || tx_index || log_index || emitter || topic0
```

- **Replay Resistance**: Consuming contracts record the `statement_id` in a dedicated nullifier set. Attempting to claim the same deposit or balance proof twice fails with `AlreadyClaimed`.
- **On-Chain State Footprint**: Consuming contracts store only the 32-byte nullifier in their account storage diff. Originating Ethereum addresses and raw account balances are not stored in consumer state.
- **Privacy Boundary & Caveats**:
  - Mosoo provides pseudonymous nullifier tracking, **not** a zero-knowledge mixer or shielded pool.
  - The underlying Ethereum transaction is public on the source chain.
  - External network observers can perform off-chain correlation if deposit amounts and claim timestamps closely match. True unlinkability in production requires relayer batching or third-party relayer aggregation.
  - These invariants are verified in [`tests/privacy_and_correlation_tests.rs`](tests/privacy_and_correlation_tests.rs) and the sequencer harness. Live public testnet validation will occur in Milestone M1.

---

## Repository Layout

```
mosoo/
├── mosoo-core/          Core cryptographic types, BLS12-381 verifier, MPT prover, predicate engine
├── methods/guest/       RISC0 zkVM guest program (riscv32im-risc0-zkvm-elf)
├── daemon/              Headless consensus updater with randomized jitter and RPC failover
├── cli/                 Developer CLI, fixture verification, and benchmark runner
├── consumers/
│   ├── erc20-receiver/  Reference dApp: trustless ERC-20 minting from verified Ethereum deposits
│   └── ether-receiver/  Reference dApp: trustless ETH accounting from verified balances
├── test_vectors/        Committed canonical Ethereum consensus and proof fixtures
├── evidence/            Committed sequencer harness manifests and verification logs
├── benchmarks/          Raw benchmark JSON measurements and hardware profiles
├── docker/              Reproducible Docker build environment
├── scripts/             Build, test, and verification automation scripts
└── docs/                Architecture specifications, threat model, ADRs, and guides
```

---

## Technical Documentation & Decision Logs

- [RFP-021 Technical Specification & Mapping](docs/criteria-checklist.md) — Comprehensive spec compliance and implementation mapping.
- [Security Threat Model & Invariants](docs/security-review.md) — Cryptographic thresholds, adversary model, and 12 attack vectors.
- [ADR 001: 3-Transaction BLS Split](docs/decisions/001-3tx-bls-verification-split.md) — Rationale, rejected alternatives, and gas trade-offs.
- [ADR 002: Daemon Liveness & Recovery](docs/decisions/002-permissionless-daemon-liveness.md) — Liveness strategy, front-running mitigation, and recovery.
- [ADR 003: Evaluation of Helios & Prior Art](docs/decisions/003-evaluation-of-helios-and-prior-art.md) — Architectural comparison with Helios and ZK light clients.
- [Cycle Counts & Benchmark Profiling](docs/BENCHMARKS.md) — Empirical benchmarks, memory usage, and BLS library comparison.
- [Sequencer Harness Manifests](docs/SEQUENCER_HARNESS.md) — Simulated LEZ sequencer transaction receipts and state diffs.
- [Daemon Operator Guide](docs/DAEMON.md) — Configuration, RPC failover, and operational flags.
- [Logos SPEL IDL Specification](docs/SPEL_IDL.md) — Interface definitions and type encodings.

---

## License

Dual-licensed under [MIT](LICENSE-MIT) and [Apache 2.0](LICENSE-APACHE).
