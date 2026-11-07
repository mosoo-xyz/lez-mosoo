# Mosoo

[![CI](https://github.com/mosoo-xyz/lez-mosoo/actions/workflows/ci.yml/badge.svg)](https://github.com/mosoo-xyz/lez-mosoo/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg)](LICENSE-MIT)
[![Rust](https://img.shields.io/badge/Rust-1.78%2B-orange.svg)](https://www.rust-lang.org)

Mosoo is an Ethereum consensus light client and state attestation module for the Logos Execution Zone (LEZ), developed for [Logos RFP-021](https://github.com/logos-co/rfp).

It verifies 512-validator Ethereum sync-committee BLS aggregate signatures across a 3-transaction split to fit within LEZ's 10M gas cap, then proves Ethereum account balances, storage slots, and receipt logs inside the zkVM for consuming smart contracts without trusted signers or multisigs.

---

## Canonical Test Inventory & Verification

The Mosoo test suite contains **334 automated tests** (318 Rust tests across 13 test binaries + 3 doc-tests, plus 16 Foundry EVM tests). All tests pass with 0 failures and 0 warnings.
For an exhaustive, canonical breakdown of every test file, unique counts, sub-category mappings (adversarial, hardening regressions, light-client, bridge), and reproduction steps, see [`docs/TEST_INVENTORY.md`](docs/TEST_INVENTORY.md).

## Quickstart & Environment Verification

Verification evidence is partitioned into four distinct operational environments:
1. **Public LEZ v0.3.1 Network**: Live on-chain program deployment (`DQprfeSk1wPCW1oJYaqsGDg5b95sXygSticDYFeJCfuf`, ImageID: `ad6fbedb983da6b6...`) with all 7 code segments (blocks 77987–78000), CreateHeader (block 78002), and all 12 lifecycle steps mined on-chain (blocks 78005–78025) verified via `scripts/verify-lez-deployment.py` (29/29 checks passed) and `scripts/verify-onchain.py` (27/27 checks passed).
2. **Ethereum Sepolia Testnet**: Deployed canonical `MosooLocker` contract at [`0x74625D146B8d9413F3c3976B323d94A739be7856`](https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856) with live confirmed deposits (Tx `0x743aea...` block 11990019, and Tx [`0x6ecddb...`](https://sepolia.etherscan.io/tx/0x6ecddbdd03284e4053a9fd957ebf611b188f9a67a2173a8b6b55844e0bcc8913) block 12082214).
3. **Offline LEZ v0.4 Sequencer Harness**: Reproducible local environment simulating LEZ v0.4 containerized sequencer, 10M gas limit, and 3-tx BLS split.
4. **Public LEZ v0.4 Network**: Scheduled for milestone deployment upon official Logos LEZ v0.4 public testnet release (never claimed as currently deployed).

```console
git clone https://github.com/mosoo-xyz/lez-mosoo && cd lez-mosoo

# 1. Run all 318 Rust workspace tests across 13 test suites + doc-tests (0 failing, 0 warnings)
cargo test --workspace

# 2. Run the Foundry Solidity test suite (16 passing tests, 334 total automated tests)
forge test -vvv

# 2. Run the full Two-Way Bridge integration test suite (22 passing tests)
cargo test --test two_way_bridge_tests

# 3. Run the adversarial mutation attack tests (42 attack scenarios in 50 tests)
cargo test --test adversarial_mutation_tests

# 4. Run the LEZ v0.4 sequencer harness (Canonical Mainnet Period 1884 + simulated Sepolia Gloas ePBS lifecycle)
cargo test --test sequencer_e2e_tests

# 5. Run the Two-Way Bridge pipeline (simulated demo or live testnet mode)
python3 scripts/testnet-two-way-bridge.py --mode simulated
# Live mode connects directly to live LEZ Sequencer and Ethereum Sepolia RPC:
python3 scripts/testnet-two-way-bridge.py --mode live
# Deployed Sepolia Locker: 0x74625D146B8d9413F3c3976B323d94A739be7856 (https://sepolia.etherscan.io/address/0x74625D146B8d9413F3c3976B323d94A739be7856)

# 6. Verify live testnet sequencer health, gas limits, and blocks
python3 scripts/verify-lez-deployment.py
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

## Technical Architecture & Implemented Components

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

- **Weak-Subjectivity Bounds & Instance Immutability**:
  Enforces a canonical operational freshness window of 54,000 slots (`CANONICAL_WEAK_SUBJECTIVITY_WINDOW_SLOTS`, ~7.5 days at 12s/slot) with a hard protocol safety ceiling of 1,728,000 slots (`MAX_WEAK_SUBJECTIVITY_WINDOW_SLOTS` / 54,000 epochs, ~240 days) on updates and initial bootstrap checkpoints. Per ADR-004, instances are strictly immutable and never rewritten in place. Stalled instances after network partitions are retired and replaced with fresh instances initialized via `bootstrap_instance` with `verify_anchored_checkpoint`.

- **The 3-Transaction BLS Split**: In-guest verification split into `begin_update` (5.38M gas), `miller_update` (4.18M gas), and `finish_update` (3.74M gas). All transactions operate under LEZ's 10M gas cap with 46% to 62% safety headroom. An on-chain `JobAccount` PDA coordinates the pipeline with cross-stage hash binding (`update_digest`).
- **Two-Way Cross-Chain Settlement Architecture (`contracts/MosooLocker.sol`, `mosoo-core/tests/two_way_bridge_tests.rs`)**:
  - **Inbound State Attestation (Ethereum → LEZ)**: Ethereum consensus and state proofs verified inside the RISC Zero zkVM guest. Sync committee BLS12-381 signatures and execution payload MPT inclusion roots are validated mathematically on-chain without trusting intermediate relayers.
  - **Outbound Witness Settlement (LEZ → Ethereum)**: LEZ burn receipts verified using an M-of-N multi-signer attester committee. Protected on-chain by a continuous rolling 24-hour rate-limiting sliding window with bounded cleanup (`MAX_CLEANUP_BATCH = 32`) to guarantee O(1) gas, 2-step timelocked governance on committee/quorum changes (`GOVERNANCE_TIMELOCK_DELAY = 2 days`), a mandatory 24-hour timelock queue for large withdrawals (>= 10 ETH), and independent Guardian veto protection.
  - **Trust Model & Boundaries**: Inbound safety is bound to Ethereum's 2/3 honest sync committee quorum and weak-subjectivity freshness (`54,000 slots`). Outbound safety is bound to the M-of-N attester threshold and timelock guardian oversight.
- **Two Reference Consumers**: `erc20-receiver` (token minting from verified Ethereum deposits) and `ether-receiver` (native balance accounting & `mETH` token ledger), each supporting storage-authenticated verification (`claim_authenticated_store_u256`, `claim_native_eth_deposit_authenticated_store_with_config`) strictly binding to approved light-client instances (`config.is_trusted_instance`) and program-owned persistent accounts (`store.get_account_owner == MOSOO_PROGRAM_ID`), atomic test harness verification, and decoupled relayer flows with nullifier replay rejection, backed by program-owned authenticated locker and token allowlist configurations.
- **Permissionless Consensus Daemon (`daemon/`)**: Headless service monitoring Ethereum beacon and execution RPCs, featuring randomized jitter (1.0x to 2.5x poll interval) and idempotent skipping to prevent duplicate gas expenditure.
- **Standalone Sequencer Test Harness (`tests/sequencer_e2e_tests.rs`)**: Simulates LEZ v0.4 opcode execution, CPI dispatch, PDA creations, and gas metering across blocks 500,000 to 500,006.
- **318 Passing Tests** (Rust Workspace) + **16 Passing Tests** (Foundry Solidity Suite) = **334 Total Passing Tests**: Verified in CI with zero compiler or Clippy warnings (`-D warnings`).
- **Complete Test Matrix (334 Total Tests)**:
  - `mosoo-core/tests/audit_oct26_hardening_tests.rs`: 58 security hardening regression tests.
  - `mosoo-core/tests/adversarial_mutation_tests.rs`: 50 test functions covering 42 distinct mutation attack scenarios.
  - `mosoo-core/tests/two_way_bridge_tests.rs`: 22 cross-chain bridge lifecycle, rate-limiting, and timelock governance tests.
  - `mosoo-core/tests/integration_tests.rs` & `light_client_tests.rs`: 24 consensus, bootstrap, fork, and storage slot tests.
  - `mosoo-core/tests/privacy_and_correlation_tests.rs`: 5 zero-correlation and state-diff shielding tests.
  - `mosoo-core/tests/sequencer_e2e_tests.rs`: 4 standalone sequencer lifecycle tests.
  - `mosoo-core` unit tests: 47 cryptographic, verifier, and admin bootstrap unit tests.
  - `consumers/erc20-receiver`: 42 unit tests (and 1 doc test).
  - `consumers/ether-receiver`: 39 unit tests (and 1 doc test).
  - `daemon/src/main.rs`: 15 operational consensus daemon tests.
  - `cli/src/main.rs`: 4 local verification, authentic committee fail-closed, and dry-run tests.
  - Documentation tests: 3 doc tests (erc20, ether, predicate).
  - `contracts/test/MosooLocker.t.sol`: 16 Foundry EVM unit and fuzz tests.
  - All verified in fresh execution trace [`evidence/verify_all_output.txt`](evidence/verify_all_output.txt).
- **20 Verified Invariants**: Including single-transaction gas limits, weak-subjectivity freshness, deterministic nullifier derivation, cross-chain domain separation, tamper-evident job stages, zero-address shielding, safe ERC-20 balance queries, secret isolation via local transaction signing, fail-closed period-boundary sync, and persistent PDA nullifier storage across node restarts.
- **Public LEZ v0.3.1 Testnet Verification & Two-Way Settlement Evidence (`evidence/public-testnet-v03/`)**: Live on-chain consensus, block state, and fee verification against the active public LEZ testnet sequencer (`https://testnet.lez.logos.co`, block height > 78,600) via `scripts/verify-onchain.py` (27/27 on-chain checks) and `scripts/verify-lez-deployment.py` (29/29 checks), paired with live two-way settlement verification linking live Ethereum Sepolia escrow deposit (`MosooLocker.sol` at `0x74625D146B8d9413F3c3976B323d94A739be7856`) with verified zkVM state machine execution via `scripts/testnet-two-way-bridge.py --mode live`.
- **Architectural Decision Records (`docs/DECISIONS.md`)**: Formalized ADRs covering 3-Tx intermediate binding, Altair period selection, Gloas ePBS RLP root extraction, instance immutability, HeaderRecord execution root provenance, and dual-nullifiers.
- **Trust Assumptions & Threat Model (`docs/TRUST_ASSUMPTIONS.md`)**: Specification of checkpoint provenance, 2/3 honest sync committee quorum assumptions, off-chain daemon safety vs liveness boundaries, privacy limitations, and reorganization failure conditions.
- **Evaluation of Prior Art & Audited Light Clients (`docs/decisions/003-evaluation-of-helios-and-prior-art.md`)**: Architectural assessment of `helios` (a16z), `revm-helios`, `spl-helios`, and `r0vm-helios` (Boundless), delineating reused Altair SSZ primitives versus independent 3-Tx split innovation, and audit surface impact.

### Subsystem Verification Status (RFP-021 Alignment)

| Component / Subsystem | Status | Verification Evidence / Roadmap |
| :--- | :---: | :--- |
| **Core Light Client (BLS12-381 / SSZ / MPT)** | Complete (Offline Verified) | 188 `mosoo-core` tests passing; offline Rust unit, integration & Criterion benchmarks |
| **Full Protocol Test Suite** | 334 / 334 Tests Passing | Canonical inventory documented in [`docs/TEST_INVENTORY.md`](docs/TEST_INVENTORY.md) (318 Rust + 16 Foundry EVM) |
| **3-Transaction BLS Update Pipeline** | Complete (Offline Verified) | Verified (< 10M gas/tx) in standalone LEZ v0.4 sequencer harness; 3 transactions (5.38M, 4.18M, 3.74M gas) |
| **Dual Reference Consumers (ERC-20 & Native ETH)** | Partially Complete | In-memory CPI invocation & nullifier sets verified (81 tests); public LEZ v0.4 on-chain deployment planned in M4 |
| **Composite Predicates (`And`, `Or`, `Not`)** | Partially Complete | Basic predicates (`AtLeast`, `Equal`, `WithinRange`) complete; composite boolean tree scheduled for M2 |
| **Settlement Privacy & State Diffs (F#8)** | Partially Complete | 32-byte Statement ID state footprint verified; comprehensive state/event diff & unlinkability test suite in progress |
| **Adversarial Invariant Hardening** | Complete (Offline Verified) | 42 mutation attack scenarios rejected in 50 tests (`mosoo-core/tests/adversarial_mutation_tests.rs`) |
| **Security Hardening Regression Suite** | Complete (Offline Verified) | 58 regression tests passing (`mosoo-core/tests/audit_oct26_hardening_tests.rs`) |
| **Logos Ethereum Core Proxy Integration** | Partially Complete (Functional Prototype) | 3 verified proxy routing paths implemented in daemon & CLI; production hardening & failover in M3 |
| **Consensus Daemon Service** | Partially Complete (Functional Prototype) | Relayer daemon with randomized jitter & RPC retry implemented; 72-hour soak & dual-relayer redundancy in M3 |
| **CLI Workflows & Dry-Run Parity** | Partially Complete | All 4 RFP workflows supported (`attest`, `dry-run`, `submit-update`, `config`); typed error parity suite in M1 |
| **Two-Way Bridge (Outbound Settlement)** | Experimental Research Prototype | Secondary experimental component; explicitly decoupled from primary RFP-021 inbound acceptance |
| **External Security Audit** | Partially Complete | Internal security review and 58 regression tests complete; independent 3rd-party audit pending Logos contracting |

### Roadmap

- **Public LEZ v0.4 Devnet Migration**: Deployment and verification on the public LEZ v0.4 devnet once Logos Core completes the v0.4 network freeze and release.
- **Logos Module Catalog & SPEL Release**: Upstream publication to the official Logos Core module catalog.
- **Production Daemon Observability**: Prometheus telemetry exporter, `/healthz` liveness probes, and automated consensus re-org recovery.
- **External Security Audit**: Independent third-party audit engagement and published certification prior to mainnet release.

---
### Reproducing All Tests Locally

```bash
# 1. Run all Rust workspace tests (316 tests across 16 test binaries)
cargo test --workspace

# 2. Run MosooLocker Solidity EVM tests (16 tests via Foundry)
forge test -vvv

# GRAND TOTAL: 318 Rust + 16 Foundry = 334 tests (+ 12 sequencer harness evidence checks)

# 4. Verify committed execution manifest & gas headroom
python scripts/verify-evidence.py
```

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

## Scope Separation: Inbound Attestation vs Experimental Outbound Bridge

> [!IMPORTANT]
> **RFP-021 Primary Scope:** The primary deliverable of this grant is **Inbound Ethereum State Attestation for LEZ**: verifying Ethereum consensus updates, state roots, and account/storage/receipt inclusion proofs inside the LEZ zkVM guest context.
> **Experimental Secondary Scope:** The Two-Way Cross-Chain Bridge (`contracts/MosooLocker.sol`, `two_way_bridge_tests.rs`) is an **experimental research prototype** designed to explore reverse-direction (LEZ-to-Ethereum) settlement via an attester committee and timelocked guardian. It is strictly optional and explicitly decoupled from RFP-021 milestone evaluation and grant acceptance.

## Native ETH & ERC-20 Deposit Binding Requirements

For both ERC-20 token transfers and native ETH deposits, consuming applications MUST enforce strict cryptographic and contextual binding to prevent fabricated claim attacks:
- **Canonical Locker Binding**: Deposits must originate from the authentic, verified `MosooLocker` contract address (e.g. `0x74625D146B8d9413F3c3976B323d94A739be7856` on Sepolia). Claims referencing arbitrary emitter contracts are rejected.
- **Value & Semantics Binding**: The verified value must match the exact transferred wei or token amount (converted via safe U256-to-u128 primitives).
- **Sender & Recipient Binding**: Event logs must strictly bind the Ethereum depositor address and the destination LEZ account public key.
- **Nullifier Replay Protection**: Each deposit emits a deterministic `statement_id`. Upon claim, this 32-byte identifier is stored in the consumer's persistent Nullifier PDA. Replayed claims revert immediately with `AlreadyClaimed`.
- **Atomic Revert**: If any inclusion proof, locker address check, or predicate condition fails, the entire transaction reverts fail-closed with zero state modification.

## Recommended Consumer Pattern

Consuming applications verify state inclusion proofs and evaluate predicates **inside the consuming transaction** (Atomic Same-Transaction Claim) to eliminate reliance on unauthenticated out-of-band statements:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                 Recommended Consumer Pattern (Atomic Claim)                 │
│                                                                             │
│  1. In-Transaction Verification: Direct MPT proof verification against an   │
│     authenticated HeaderRecord committed on the instance PDA.               │
│  2. In-Guest Predicate Evaluation: Evaluates conditions (AtLeast, Equal)   │
│     directly over verified state in the same zkVM guest execution context.  │
│  3. Nullifier Replay Guard: Records deterministic 32-byte statement_id into │
│     the consumer's persistent Nullifier PDA (reverts with AlreadyClaimed).  │
│  4. Strict Binding: Asserts chain_id, trusted instance PDA provenance,      │
│     canonical locker address, and token allowlists.                         │
│  5. Fail-Closed Revert: If ANY step fails (stale header, bad proof, failed │
│     predicate), the entire transaction aborts atomically.                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

Integration guides, typed error hierarchies, and reference code examples are documented in [`docs/CONSUMERS.md`](docs/CONSUMERS.md).

---

## Replay Protection & Settlement Privacy

When a state attestation succeeds, Mosoo emits a `VerifiedStatement` identified by a deterministic, collision-resistant 32-byte nullifier derived strictly from the underlying Ethereum state facts (ADR-006, RFP-021 Functionality #6):

```text
// V2 Canonical Statement ID (invariant to predicate variations to prevent replay bypass):
statement_id = sha256("mosoo_statement_v2" || chain_id || genesis_validators_root || subject_key || proof_type_tag || verified_value)
```

For event logs, `subject_key` is derived to guarantee uniqueness across blocks and transactions:

```text
subject_key = sha256("mosoo_receipt_log_v1" || execution_block_hash || slot || tx_index || log_index || emitter || topic0)
```

- **Replay Resistance**: Consuming contracts record the `statement_id` in a dedicated nullifier set. Attempting to claim the same deposit or balance proof twice fails with `AlreadyClaimed`.
- **On-Chain State Footprint**: Consuming contracts store only the 32-byte nullifier in their account storage diff. Originating Ethereum addresses and raw account balances are not stored in consumer state.
- **Privacy Boundary & Caveats**:
  - Mosoo provides pseudonymous nullifier tracking, **not** a zero-knowledge mixer or shielded pool.
  - The underlying Ethereum transaction is public on the source chain.
  - External network observers can perform off-chain correlation if deposit amounts and claim timestamps closely match. True unlinkability in production requires relayer batching or third-party relayer aggregation.
  - These invariants are verified in [`mosoo-core/tests/privacy_and_correlation_tests.rs`](mosoo-core/tests/privacy_and_correlation_tests.rs), the sequencer harness, and the live two-way bridge settlement pipeline (`evidence/public-testnet-v03/`). Full public v0.4 devnet upgrade validation will occur upon devnet release.

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

- [RFP-021 Technical Specification & Mapping](docs/criteria-checklist.md) — Specification checklist and module mapping.
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
