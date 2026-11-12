# Mosoo Host Crypto Benchmarks & Modeled Profiles

This directory contains native host CPU cryptographic measurements (`mosoo-cli -- benchmarks`) alongside modeled zkVM cycle and hardware profiles.

## Committed Artifacts

- **`raw_crypto_benchmarks.json`**:
  Direct output emitted by `cargo run -p mosoo-cli -- benchmarks`. Records **measured host CPU nanosecond durations** (`measured_durations_ns`) across 50 iterations, paired with modeled zkVM cycle counts (`cycle_counts`) and LEZ gas consumption targets (`lez_gas_consumption`).
- **`raw_cli_output.txt`**:
  Verbatim plain-text terminal output from executing `cargo run -p mosoo-cli -- benchmarks`.
- **`hardware_profile.txt`**:
  Compiled ELF sizes, measured `r0vm 3.0.5` cycle baseline (`evidence/mosoo-testnet-v03/local_simulation.txt`), and `riscv32im-risc0-zkvm-elf` segment configuration parameters (`PO2 = 18`; build via [`docker/Dockerfile.guest`](../docker/Dockerfile.guest)).

## Reproducing Host Benchmarks Locally

To re-run the live host cryptographic benchmark workload and regenerate `raw_crypto_benchmarks.json`:

```bash
cargo run -p mosoo-cli --release -- benchmarks
```

To run the offline LEZ v0.4-target conformance acceptance tests:

```bash
cargo test --test lez_v04_acceptance_tests -- --nocapture
```
