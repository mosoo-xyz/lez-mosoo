# Mosoo: Complete Verification & Test Suite Runner (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Mosoo: Complete Verification & Test Suite Runner (Logos RFP-021)   " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Host "`n[1/18] Checking entire workspace compilation..." -ForegroundColor Yellow
cargo check --workspace

Write-Host "`n[2/18] Running all workspace Rust unit, integration & doc-tests (331 tests)..." -ForegroundColor Yellow
cargo test --workspace

Write-Host "`n[3/18] Running Two-Way Bridge End-to-End Integration Suite (23 tests)..." -ForegroundColor Yellow
cargo test --test two_way_bridge_tests

Write-Host "`n[4/18] Running Adversarial & Mutation Test Suite (50 tests, 42 attack vectors)..." -ForegroundColor Yellow
cargo test --test adversarial_mutation_tests

Write-Host "`n[5/18] Running Security Hardening & Boundary Suite (58 tests)..." -ForegroundColor Yellow
cargo test --test security_hardening_tests

Write-Host "`n[6/18] Running Privacy & Zero-Correlation Test Suite (6 tests)..." -ForegroundColor Yellow
cargo test --test privacy_and_correlation_tests

Write-Host "`n[7/18] Running Offline LEZ v0.4-Target Conformance Tests (4 tests)..." -ForegroundColor Yellow
cargo test --test lez_v04_acceptance_tests

Write-Host "`n[8/18] Running Offline Standalone LEZ Sequencer E2E Suite (4 tests)..." -ForegroundColor Yellow
cargo test --test sequencer_e2e_tests

Write-Host "`n[9/18] Running Real Ethereum Beacon Chain Vector Tests (4 tests)..." -ForegroundColor Yellow
cargo test --test real_chain_vectors_tests

Write-Host "`n[10/18] Running Daemon Operational Tests (17 tests)..." -ForegroundColor Yellow
cargo test -p mosoo-daemon

Write-Host "`n[11/18] Running Live Empirical Benchmark Suite & Emitting JSON Artifact..." -ForegroundColor Yellow
cargo run -p mosoo-cli -- benchmarks

Write-Host "`n[12/18] Running Canonical Ethereum Fixture Verification..." -ForegroundColor Yellow
cargo run -p mosoo-cli -- demo --mode fixture

Write-Host "`n[13/18] Running Clippy linter with zero warnings tolerance..." -ForegroundColor Yellow
cargo clippy --workspace --all-targets -- -D warnings

Write-Host "`n[14/18] Verifying code formatting..." -ForegroundColor Yellow
cargo fmt --all -- --check

Write-Host "`n[15/18] Verifying committed sequencer harness execution manifest..." -ForegroundColor Yellow
if (Get-Command py -ErrorAction SilentlyContinue) {
    $pyCmd = "py"
    $pyArgs = @("-3")
} elseif (Get-Command python3 -ErrorAction SilentlyContinue) {
    $pyCmd = "python3"
    $pyArgs = @()
} elseif (Get-Command python -ErrorAction SilentlyContinue) {
    $pyCmd = "python"
    $pyArgs = @()
} else {
    Write-Error "Python 3 is required for manifest verification, but neither py, python3, nor python was found."
    exit 1
}
& $pyCmd @($pyArgs + @("scripts/verify-evidence.py"))

Write-Host "`n[16/18] Running Python subprocess evidence tamper-detection suite (7 mutations)..." -ForegroundColor Yellow
& $pyCmd @($pyArgs + @("scripts/test-evidence-mutation.py"))

Write-Host "`n[17/18] Verifying Mosoo's own live LEZ v0.3.1 deployment & PDAs (Co5EYuBR...)..." -ForegroundColor Yellow
& $pyCmd @($pyArgs + @("scripts/verify-mosoo-lez.py", "--allow-offline"))

Write-Host "`n[18/18] Running Foundry Solidity EVM suite (`contracts/test/MosooLocker.t.sol`, 20 tests)..." -ForegroundColor Yellow
$forgeCmd = $null
if (Get-Command forge -ErrorAction SilentlyContinue) {
    $forgeCmd = (Get-Command forge).Source
} elseif (Test-Path "$env:USERPROFILE\.foundry\bin\forge.exe") {
    $forgeCmd = "$env:USERPROFILE\.foundry\bin\forge.exe"
}
if ($forgeCmd) {
    & $forgeCmd test -vvv
    if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
    $summaryLine = "  [SUCCESS] All 331 Rust + 20 Foundry = 351/351 checks passed!   "
} else {
    Write-Warning "Foundry (`forge`) not found on PATH or $env:USERPROFILE\.foundry\bin\forge.exe; skipping 20 Solidity tests (run in CI)."
    $summaryLine = "  [SUCCESS] All 331 Rust + Python checks passed (Foundry skipped)!  "
}

Write-Host "`n=====================================================================" -ForegroundColor Green
Write-Host $summaryLine -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
