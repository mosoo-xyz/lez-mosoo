# Mosoo Testing & Verification Matrix

Automated verification spans Rust workspace unit and integration tests, Solidity Escrow Foundry tests, deterministic Python evidence/mutation checks, and offline CLI/harness simulations.

---

## Quick Verification Commands

```powershell
# Windows (runs cargo fmt, clippy -D warnings, all 339 Rust tests, and 31 Foundry tests)
.\scripts\verify_all.ps1
```

```bash
# Linux / macOS
./scripts/verify_all.sh
```

```powershell
# Individual checks
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
forge test --root contracts -vvv

# Evidence integrity & mutation checks
py -3 scripts/verify-evidence.py --manifest evidence/sequencer-harness-v04/run.tsv
py -3 scripts/test-evidence-mutation.py

# Deterministic CLI & simulated bridge walkthroughs
cargo run -p mosoo-cli -- demo --mode fixture
cargo run -p mosoo-cli -- dry-run
py -3 scripts/testnet-two-way-bridge.py --mode simulated
```

---

## Rust Workspace Test Inventory (339 Total)

### Unit & Doc Tests (`162` unit + `3` doc = `165`)

| Crate | Source Location | Unit | Doc | Primary Scope |
| :--- | :--- | :---: | :---: | :--- |
| `mosoo-core` | `mosoo-core/src/*.rs` | 56 | 1 | BLS12-381 split math, SSZ gindices, MPT proofs, `outbound_zk` ABI/witness checks, bounds & RLP checks, runtime signer auth, predicate engine, V2 IDs |
| `erc20-receiver` | `consumers/erc20-receiver/src/{lib,tests}.rs` | 42 | 1 | `claim_atomic`, ERC-20 deposit/transfer proofs, token allowlists, shielded claims, nullifier PDAs |
| `ether-receiver` | `consumers/ether-receiver/src/{lib,tests}.rs` | 39 | 1 | `claim_ether_atomic`, `MethLedger`, shielded ETH claims, burn receipts, custody checks |
| `mosoo-daemon` | `daemon/src/{main,tests}.rs` | 18 | 0 | Beacon API parsing, period-boundary sync fail-closed guards, jittered submission, private key isolation, health endpoints |
| `mosoo-cli` | `cli/src/{main,tests}.rs` | 7 | 0 | CLI subcommands (`demo`, `attest`, `dry-run`, `submit-update`, `config`, `verify-checkpoint`, `benchmarks`) |

### Integration & Adversarial Suites (`mosoo-core/tests/`, `174` total)

| Suite | File / Directory | Count | Focus |
| :--- | :--- | :---: | :--- |
| Security Hardening | `mosoo-core/tests/security_hardening_tests/` | 58 | Account ownership, instance/checkpoint pinning, weak-subjectivity bounds, fork adapters (`guest_and_store`, `privacy_and_instance`, `deposit_and_forks`, `freshness_and_adapter`) |
| Adversarial Mutation | `mosoo-core/tests/adversarial_mutation_tests/` | 50 | Mutated headers, quorum deficits, period skips, Gloas RLP mismatch, replay, storage/job tampering (`consensus_and_branches`, `state_and_replay`, `pipeline_and_storage`, `instance_and_config`) |
| Two-Way Bridge | `mosoo-core/tests/two_way_bridge_tests.rs` | 24 | EIP-712 attester separation, burn-to-unlock flow, `outbound_zk` burn witness & 288-byte journal roundtrip, rate caps, guardian veto paths |
| Light Client | `mosoo-core/tests/light_client_tests.rs` | 22 | End-to-end Altair–Gloas updates, 3-tx `JobAccount` execution, receipt inclusion |
| Privacy & Correlation | `mosoo-core/tests/privacy_and_correlation_tests.rs` | 6 | Confidential commitment salts, `DepositCommitted` unlinkability checks |
| LEZ v0.4 Acceptance | `mosoo-core/tests/lez_v04_acceptance_tests.rs` | 4 | Offline LEZ v0.4-target conformance, isolated instances, 10M gas ceilings |
| Real Chain Vectors | `mosoo-core/tests/real_chain_vectors_tests.rs` | 4 | SHA-256 vector manifest verification + Mainnet Fulu, Sepolia Gloas, Hoodi Fulu JSON vectors |
| Sequencer Harness | `mosoo-core/tests/sequencer_e2e_tests.rs` | 4 | Multi-tx persistence across simulated restart, PDA nullifier durability |
| E2E Consumer Flow | `mosoo-core/tests/e2e_consumer_tests.rs` | 2 | Full light-client update -> attestation -> consumer mint integration |

---

## Solidity, Live LEZ & Python Verifiers

- **Foundry (`contracts/test/MosooLocker.t.sol` + `contracts/test/MosooZkBurnVerifier.t.sol`):** `31` unit and fuzz tests (`27` `MosooLockerTest` + `4` `MosooZkBurnVerifierTest`) covering EIP-712 cross-contract replay protection, EIP-2 low-`s` checks, `DepositCommitted` commitment tree insertion, strict fixed denominations, irreversible `productionCommissioned >= 2` quorum latch, `owner != guardian` invariants, non-zero rolling 24h withdrawal caps, 24h large-withdrawal queue (`>= 10 ETH`) + Guardian veto, 24h authority delay, 48h multisig/config/verifier timelocks, and RISC Zero `IRiscZeroVerifier` outbound burn journal + state-root lineage verification.
- **Evidence Integrity (`scripts/verify-evidence.py`):** Verifies SHA-256 hashes, deterministic `r0vm` / host witness artifacts, and sequencer run logs (`evidence/sequencer-harness-v04/run.tsv`).
- **Evidence Mutation (`scripts/test-evidence-mutation.py`):** Runs `7` negative mutation cases against temporary manifest copies and confirms `verify-evidence.py` fails with the expected diagnostic error on every tampered input.
- **Live LEZ v0.3.1 Verifier (`scripts/verify-mosoo-lez.py`):** Independently validates the live immutable `mosoo_lc` deployment (`Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg`) across `30/30` RPC state and transaction checks (logged in `evidence/mosoo-testnet-v03/`).
- **LEZ v0.3 Guest Crate Compile Check (WSL / Linux with `riscv32` & Risc0 toolchain):**
  ```bash
  cargo check --manifest-path programs/mosoo-lez-v03/Cargo.toml
  cargo check --manifest-path programs/mosoo-lez-v03-cli/Cargo.toml
  ```

---

## Scope & Honest Test Boundaries

- **Verified locally & in CI (`370/370` automated tests):** `339` Rust workspace tests + `31` Foundry tests (`27` `MosooLockerTest` + `4` `MosooZkBurnVerifierTest`; note that `MosooZkBurnVerifierTest` uses `MockRiscZeroVerifier` binding `(imageId, sha256(journal))` ahead of live `RiscZeroVerifierRouter` wiring).
- **Verified live on public testnets (`v0.3.1` + Sepolia `v4`):** Immutable `mosoo_lc` on LEZ v0.3.1 (`Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg`) and hardened EIP-170 commissioned `2-of-2` `MosooLocker` v4 on Sepolia (`0xF94eA0F9Ecbf5c0edB780F871552164ad68d14Cd`). See [`docs/DEPLOYMENTS.md`](DEPLOYMENTS.md).
- **Not yet run against public network:** Live public LEZ `v0.4` deployment awaits upstream LEZ `v0.4` testnet availability; the `v0.4` target guest is verified today against offline sequencer harnesses and local unit/integration suites.
