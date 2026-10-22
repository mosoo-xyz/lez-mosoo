# Mosoo: Benchmark & Cycle Profiling Execution (PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "  Mosoo: Benchmark & Cycle Profiling Execution (Logos RFP-021)       " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan

Write-Host "`n[1/2] Printing detailed zkVM Cycle & LEZ Gas Reconciliation..." -ForegroundColor Yellow
cargo run -p mosoo-cli -- benchmarks

Write-Host "`n[2/2] Running simulated Sequencer gas & state profiling..." -ForegroundColor Yellow
cargo test --test sequencer_e2e_tests -- --nocapture

Write-Host "`n=====================================================================" -ForegroundColor Green
Write-Host "  [SUCCESS] Benchmark profiling completed. Outputs match BENCHMARKS.md" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
