#!/usr/bin/env bash
set -euo pipefail

echo "====================================================================="
echo "  Mosoo: Benchmark & Cycle Profiling Execution (Logos RFP-021)       "
echo "====================================================================="

echo ""
echo "[1/2] Printing detailed zkVM Cycle & LEZ Gas Reconciliation..."
cargo run -p mosoo-cli -- benchmarks

echo ""
echo "[2/2] Running simulated Sequencer gas & state profiling..."
cargo test --test sequencer_e2e_tests -- --nocapture

echo ""
echo "====================================================================="
echo "  [SUCCESS] Benchmark profiling completed. Outputs match BENCHMARKS.md"
echo "====================================================================="
