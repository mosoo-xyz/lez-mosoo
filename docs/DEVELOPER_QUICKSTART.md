# Mosoo Developer Quickstart Guide

This guide walks through cloning, building, testing, and integrating the **Mosoo Ethereum Consensus and State Attestation Module** for the Logos Execution Zone (LEZ).

---

## 1. Prerequisites & Toolchain Setup

Mosoo requires a standard Rust toolchain and optional Foundry environment for Solidity EVM contract tests:

- **Rust:** `1.79.0` or higher (tested with stable toolchain).
- **Cargo & Clippy:** Installed via `rustup default stable`.
- **Foundry (Optional for EVM reference tests):** `forge` CLI.
- **Python (Optional for harness verification script):** `python3` (3.9+).

```bash
# Verify toolchain versions
rustc --version
cargo --version
forge --version
```

---

## 2. Clone & Build from Source

Clone the repository and build the workspace:

```bash
git clone --branch v0.4.0 --depth 1 https://github.com/mosoo-xyz/lez-mosoo.git
cd lez-mosoo

# Build all workspace crates (mosoo-core, mosoo-cli, and tests)
cargo build --workspace --release
```

---

## 3. Running the Test Suite (332 Total Tests)

Every test executes deterministically from a clean checkout without flaky behavior or network dependencies:

```bash
# 1. Run all 316 Rust workspace tests (includes core verifier, 50 adversarial mutation tests, 58 hardening tests)
cargo test --workspace

# 2. Run the 16 Foundry Solidity fuzz and invariant tests
forge test -vvv

# 3. Execute the standalone LEZ v0.4 deterministic sequencer harness evidence checks (12/12 checks)
python scripts/verify-evidence.py
```

### Test Suite Breakdown:
- **Rust Workspace Unit & Integration Tests:** 315 tests (covering SSZ multi-fork trees, non-signer subtraction, MPT trie verification, predicate evaluation, and state transitions).
- **CLI Subcommand Tests:** 3 tests (testing `inspect`, `verify`, and `benchmarks` CLI subcommands).
- **Adversarial Mutation Tests:** 50 tests covering 42 attack vectors (invalid BLS signatures, sub-threshold quorums, non-monotonic slots, tampered MPT proofs).
- **Security Hardening Tests:** 58 tests validating audit regression invariants.
- **Foundry Reference Suite:** 16 tests in `MosooLocker.t.sol` testing consumer rate-limiting, timelocks, and guardian veto.
- **Grand Total Automated Tests:** **332 tests**.

---

## 4. Using the Developer CLI (`mosoo-cli`)

`mosoo-cli` provides developer commands to inspect headers, simulate verification, and benchmark cycles:

```bash
# Inspect Ethereum sync-committee state or deterministic test fixtures
cargo run -p mosoo-cli -- inspect --period 1884

# Verify a 3-transaction split consensus update against canonical fixtures
cargo run -p mosoo-cli -- verify --fixture fixtures/period_1884.json

# Run empirical Criterion benchmarks and measure gas headroom
cargo run -p mosoo-cli -- benchmarks
```

---

## 5. Consumer Integration Quickstart (Recommended Pattern)

Consumer smart contracts on LEZ consume verified Ethereum state atomically using **Pattern A: Atomic Same-Transaction Verification**:

```rust
use mosoo_core::predicate::{evaluate_with_binding_v2, Predicate, derive_receipt_log_subject_key};
use mosoo_core::types::{VerifiedStatement, StatementBinding};

// 1. Mandatory authenticated non-zero instance binding
let authorized_instance_pda: [u8; 32] = get_authorized_instance_pda();
assert_ne!(source_instance_pda, [0u8; 32], "Zero instance PDA rejected");
assert_eq!(source_instance_pda, authorized_instance_pda, "Unauthorized instance");

// 2. Chain binding verification
assert_eq!(chain_id, 1, "Expected Ethereum Mainnet chain ID");

// 3. Derive canonical subject key with block hash binding
let subject_key = derive_receipt_log_subject_key(
    &execution_block_hash,
    slot,
    tx_index,
    log_index,
    &deposit_contract,
    &deposit_topic0,
);

// 4. Evaluate statement and obtain deterministic V2 Statement ID
let stmt: VerifiedStatement = evaluate_with_binding_v2(
    &predicate,
    &verified_value,
    chain_id,
    genesis_validators_root,
    source_instance_id,
    source_instance_pda,
    subject_key,
    proof_type_tag,
    binding,
)?;

// 5. Enforce deterministic nullifier uniqueness to prevent double-spending
assert!(!is_nullifier_spent(&stmt.statement_id), "Duplicate claim rejected");
record_nullifier(&stmt.statement_id);

// 6. Execute atomic consumer action (e.g. mint token or credit balance)
mint_tokens(recipient, verified_amount);
```

For complete integration guidance, see [`docs/CONSUMERS.md`](./CONSUMERS.md).

---

## 6. Further Documentation

- **Architecture Specification:** [`docs/ARCHITECTURE.md`](./ARCHITECTURE.md)
- **Empirical Benchmarks & Gas Headroom:** [`docs/BENCHMARKS.md`](./BENCHMARKS.md)
- **Trust Assumptions & Security Model:** [`docs/TRUST_ASSUMPTIONS.md`](./TRUST_ASSUMPTIONS.md)
- **Quantitative Economic Attack Model:** [`docs/ECONOMIC_ATTACK_MODEL.md`](./ECONOMIC_ATTACK_MODEL.md)
- **Reproduction Guide:** [`docs/REPRODUCE.md`](./REPRODUCE.md)
- **SPEL Module Interface Definition:** [`docs/SPEL_IDL.md`](./SPEL_IDL.md)
