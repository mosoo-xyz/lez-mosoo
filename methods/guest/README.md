# Mosoo zkVM Guest Program (`methods/guest`)

This directory contains the source code for the **Mosoo zkVM Guest Binary**, which executes within the RISC Zero zkVM on the Logos Execution Zone (LEZ).

---

## Architecture & Entry Point

The guest program entrypoint is [`methods/guest/src/main.rs`](src/main.rs). It receives a tagged `GuestInstruction` envelope from `env::read()` and executes the core light client logic:

1. **`Initialize`**: Bootstrap an instance with an authentic consensus checkpoint anchor.
2. **`BeginUpdate`**: Transaction 1 of the pipelined BLS verification (~5.4 M gas).
3. **`MillerUpdate`**: Transaction 2 of the pipelined BLS verification (~4.2 M gas).
4. **`FinishUpdate`**: Transaction 3 of the pipelined BLS verification + state root commitment (~3.8 M gas).
5. **`AttestState`**: Verifies MPT inclusion proofs and issues a private or public statement nullifier.

---

## Build Targets

- **Production zkVM Target:** `riscv32im-risc0-zkvm-elf` (compiled via `docker/Dockerfile.guest` or `cargo risczero build`).
- **Host Test Mock:** Host target (compiled via `cargo test -p mosoo-guest` or `cargo build -p mosoo-guest`).

For complete reproducible build instructions, see [docs/BUILD_REPRODUCIBILITY.md](../../docs/BUILD_REPRODUCIBILITY.md).
For testnet deployment provenance, see [docs/PROVENANCE.md](../../docs/PROVENANCE.md).
