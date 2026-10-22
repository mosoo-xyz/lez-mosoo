# Mosoo Empirical Benchmarks & Profiling Artifacts

This directory contains raw, machine-readable performance measurements and profiling logs generated from live local test runs and zkVM execution traces.

## Committed Artifacts

- **`raw_crypto_benchmarks.json`**:
  Direct output emitted by `cargo run -p mosoo-cli --release -- benchmarks`. Records measured nanosecond durations across 50 iterations, in-guest zkVM cycle count breakdowns, and LEZ gas consumption calculations.
- **`raw_cli_output.txt`**:
  Verbatim terminal stdout from executing `cargo run -p mosoo-cli --release -- benchmarks`.
- **`hardware_profile.txt`**:
  Hardware test environment specifications and profiler configuration parameters.

## Reproducing Benchmarks Locally

To re-run the live benchmark workload and regenerate `raw_crypto_benchmarks.json`:

```bash
cargo run -p mosoo-cli --release -- benchmarks
```

For zkVM cycle and memory profiling under RISC Zero:

```bash
# Set segment size to PO2=18 to restrict peak memory to < 12 GB
export RISC0_DEV_MODE=0
export SEGMENT_PO2=18
cargo test --test lez_v04_acceptance_tests -- --nocapture
```
