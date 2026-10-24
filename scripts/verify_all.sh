#!/usr/bin/env bash
set -euo pipefail

echo "====================================================================="
echo "  Mosoo: Complete Verification & Test Suite Runner (Logos RFP-021)   "
echo "====================================================================="

echo ""
echo "[1/12] Checking entire workspace compilation..."
cargo check --workspace

echo ""
echo "[2/12] Running all workspace unit & integration tests (162 tests)..."
cargo test --workspace

echo ""
echo "[3/12] Running Two-Way Bridge End-to-End Integration Suite (ETH & ERC-20)..."
cargo test --test two_way_bridge_tests

echo ""
echo "[4/12] Running 32/32 Adversarial & Mutation Test Suite..."
cargo test --test adversarial_mutation_tests

echo ""
echo "[5/12] Running 5/5 Privacy & Zero-Correlation Test Suite..."
cargo test --test privacy_and_correlation_tests

echo ""
echo "[6/12] Running Standalone LEZ Sequencer E2E Suite (Mainnet & Sepolia Gloas)..."
cargo test --test sequencer_e2e_tests

echo ""
echo "[7/12] Running Daemon Operational Tests (Proxy, Jitter, Competing-Update Recovery)..."
cargo test -p mosoo-daemon

echo ""
echo "[8/12] Running Live Empirical Benchmark Suite & Emitting JSON Artifact..."
cargo run -p mosoo-cli -- benchmarks

echo ""
echo "[9/12] Running Canonical Ethereum Fixture Verification (Period 1884 & Sepolia Gloas)..."
cargo run -p mosoo-cli -- demo --mode fixture

echo ""
echo "[10/12] Running Clippy linter with zero warnings tolerance..."
cargo clippy --workspace --all-targets -- -D warnings

echo ""
echo "[11/12] Verifying code formatting..."
cargo fmt --all -- --check

echo ""
echo "[12/12] Verifying committed sequencer harness execution manifest..."
if command -v python3 &>/dev/null; then
    python3 scripts/verify-evidence.py
elif command -v python &>/dev/null; then
    python scripts/verify-evidence.py
else
    echo "[-] Error: Python 3 is required for manifest verification, but neither python3 nor python was found." >&2
    exit 1
fi

echo ""
echo "====================================================================="
echo "  [SUCCESS] All Mosoo verification checks passed cleanly!            "
echo "====================================================================="
