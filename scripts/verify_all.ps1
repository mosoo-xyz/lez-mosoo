# Mosoo: Complete Verification & Test Suite Runner (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Mosoo: Complete Verification & Test Suite Runner (Logos RFP-021)   " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Host "`n[1/12] Checking entire workspace compilation..." -ForegroundColor Yellow
cargo check --workspace

Write-Host "`n[2/12] Running all workspace unit & integration tests (162 tests)..." -ForegroundColor Yellow
cargo test --workspace

Write-Host "`n[3/12] Running Two-Way Bridge End-to-End Integration Suite (ETH & ERC-20)..." -ForegroundColor Yellow
cargo test --test two_way_bridge_tests

Write-Host "`n[4/12] Running 32/32 Adversarial & Mutation Test Suite..." -ForegroundColor Yellow
cargo test --test adversarial_mutation_tests

Write-Host "`n[5/12] Running 5/5 Privacy & Zero-Correlation Test Suite..." -ForegroundColor Yellow
cargo test --test privacy_and_correlation_tests

Write-Host "`n[6/12] Running Standalone LEZ Sequencer E2E Suite (Mainnet & Sepolia Gloas)..." -ForegroundColor Yellow
cargo test --test sequencer_e2e_tests

Write-Host "`n[7/12] Running Daemon Operational Tests (Proxy, Jitter, Competing-Update Recovery)..." -ForegroundColor Yellow
cargo test -p mosoo-daemon

Write-Host "`n[8/12] Running Live Empirical Benchmark Suite & Emitting JSON Artifact..." -ForegroundColor Yellow
cargo run -p mosoo-cli -- benchmarks

Write-Host "`n[9/12] Running Canonical Ethereum Fixture Verification (Period 1884 & Sepolia Gloas)..." -ForegroundColor Yellow
cargo run -p mosoo-cli -- demo --mode fixture

Write-Host "`n[10/12] Running Clippy linter with zero warnings tolerance..." -ForegroundColor Yellow
cargo clippy --workspace --all-targets -- -D warnings

Write-Host "`n[11/12] Verifying code formatting..." -ForegroundColor Yellow
cargo fmt --all -- --check

Write-Host "`n[12/12] Verifying committed sequencer harness execution manifest..." -ForegroundColor Yellow
if (Get-Command py -ErrorAction SilentlyContinue) {
    py -3 scripts/verify-evidence.py
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    python3 scripts/verify-evidence.py
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    python scripts/verify-evidence.py
} else {
    Write-Error "Python 3 is required for manifest verification, but neither py, python3, nor python was found."
    exit 1
}

Write-Host "`n=====================================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] All Mosoo verification checks passed cleanly!            " -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
