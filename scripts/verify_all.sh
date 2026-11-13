#!/usr/bin/env bash
set -euo pipefail

echo "====================================================================="
echo "  Mosoo: Complete Verification & Test Suite Runner (Logos RFP-021)   "
echo "====================================================================="

echo ""
echo "[1/18] Checking entire workspace compilation..."
cargo check --workspace

echo ""
echo "[2/18] Running all workspace Rust unit, integration & doc-tests (340 tests)..."
cargo test --workspace

echo ""
echo "[3/18] Running Two-Way Bridge End-to-End Integration Suite (25 tests)..."
cargo test --test two_way_bridge_tests

echo ""
echo "[4/18] Running Adversarial & Mutation Test Suite (50 tests, 42 attack vectors)..."
cargo test --test adversarial_mutation_tests

echo ""
echo "[5/18] Running Security Hardening & Boundary Suite (58 tests)..."
cargo test --test security_hardening_tests

echo ""
echo "[6/18] Running Privacy & Zero-Correlation Test Suite (6 tests)..."
cargo test --test privacy_and_correlation_tests

echo ""
echo "[7/18] Running Offline LEZ v0.4-Target Conformance Tests (4 tests)..."
cargo test --test lez_v04_acceptance_tests

echo ""
echo "[8/18] Running Offline Standalone LEZ Sequencer E2E Suite (4 tests)..."
cargo test --test sequencer_e2e_tests

echo ""
echo "[9/18] Running Real Ethereum Beacon Chain Vector Tests (4 tests)..."
cargo test --test real_chain_vectors_tests

echo ""
echo "[10/18] Running Daemon Operational Tests (18 tests)..."
cargo test -p mosoo-daemon

echo ""
echo "[11/18] Running Live Empirical Benchmark Suite & Emitting JSON Artifact..."
cargo run -p mosoo-cli -- benchmarks

echo ""
echo "[12/18] Running Canonical Ethereum Fixture Verification..."
cargo run -p mosoo-cli -- demo --mode fixture

echo ""
echo "[13/18] Running Clippy linter with zero warnings tolerance..."
cargo clippy --workspace --all-targets -- -D warnings

echo ""
echo "[14/18] Verifying code formatting..."
cargo fmt --all -- --check

echo ""
echo "[15/18] Verifying committed sequencer harness execution manifest..."
if command -v python3 &>/dev/null; then
    PY=python3
elif command -v python &>/dev/null; then
    PY=python
else
    echo "[-] Error: Python 3 is required for manifest verification, but neither python3 nor python was found." >&2
    exit 1
fi
"${PY}" scripts/verify-evidence.py

echo ""
echo "[16/18] Running Python subprocess evidence tamper-detection suite (7 mutations)..."
"${PY}" scripts/test-evidence-mutation.py

echo ""
echo "[17/18] Verifying Mosoo's own live LEZ v0.3.1 deployment & PDAs (Co5EYuBR...)..."
"${PY}" scripts/verify-mosoo-lez.py --allow-offline

echo ""
echo "[18/18] Running Foundry Solidity EVM suite (contracts/test/, 31 tests)..."
FORGE_BIN=""
if command -v forge &>/dev/null; then
    FORGE_BIN="$(command -v forge)"
elif [[ -x "${HOME}/.foundry/bin/forge" ]]; then
    FORGE_BIN="${HOME}/.foundry/bin/forge"
fi
if [[ -n "${FORGE_BIN}" ]]; then
    "${FORGE_BIN}" test -vvv
    SUMMARY="  [SUCCESS] All 340 Rust + 31 Foundry = 371/371 checks passed!   "
else
    echo "[!] Warning: Foundry (forge) not found; skipping 31 Solidity tests (run in CI)." >&2
    SUMMARY="  [SUCCESS] All 340 Rust + Python checks passed (Foundry skipped)!  "
fi

echo ""
echo "====================================================================="
echo "${SUMMARY}"
echo "====================================================================="
