# Building & Reproducing Verification

This document covers host setup, deterministic RISC Zero guest ELF builds (`riscv32im-risc0-zkvm-elf`), identifier boundaries, and test execution.

---

## 1. Prerequisites

- **Rust Toolchain:** `1.88.0+` (`Cargo.lock` v4 and `icu_collections 2.3.0`)
- **Foundry:** `forge` & `solc` (`contracts/test/MosooLocker.t.sol`)
- **Python 3.9+:** Verification and mutation scripts (`scripts/*.py`)
- **Docker (or Linux/WSL2 `rzup`):** Needed for compiling the `riscv32im-risc0-zkvm-elf` guest ELF (`cargo-risczero 1.2.6` + `rzup install cpp` for `mosoo-guest`; LEZ v0.3.1 `mosoo_lc` uses `r0vm 3.0.5`)

---

## 2. Binary & Identifier Boundaries

| Identifier | Value | Notes |
|---|---|---|
| **Live LEZ v0.3.1 Program (`mosoo_lc`)** | `Co5EYuBRRS21wiawBQRXjMyEBUbbzquZM6LmNHYYo7Fg` | Deployed immutably on `https://testnet.lez.logos.co` (Block `81148`; verified via `scripts/verify-mosoo-lez.py`) |
| **Live LEZ v0.3.1 ImageID** | `961a7e12973295f5d728443b4ee3aea6131c9de03111aba40e6751adae8503e0` | Matches [`artifacts/programs/v0.3/mosoo_lc.bin`](../artifacts/programs/v0.3/mosoo_lc.bin) (`601,892` B package; `569,468` B user ELF; `SHA-256: 0fc6ce72...`) |
| **Compiled v0.4 Target ELF (`mosoo-guest`)** | `SHA-256: 733bff2a3fa6440458b00cdbdb163efa0315784de89baf75b4cd6b78d5d715d2` | [`artifacts/v04-guest/mosoo-guest`](../artifacts/v04-guest/mosoo-guest) (`922,052` B `riscv32im-risc0-zkvm-elf`; awaits public LEZ `v0.4` release) |
| **Offline Harness Constant (`MOSOO_PROGRAM_ID`)** | `0x01ab35fda434bdfe7af601eabc14992b9ca807bc4ddfec46c896d81dc4961e1c` | Static Rust constant in `mosoo-core/src/types.rs` for offline harness PDA derivation (not a binary hash) |
| **Offline Harness Diagnostic ImageID** | `0x7a9f145e82c14d33b847226e90153dfa8801be4f5c318726aac90473512ed8b4` | Diagnostic ID emitted by offline `mosoo-cli` fixtures (`evidence/sequencer-harness-v04/run.tsv`) |

Running `cargo build -p mosoo-guest --release` on a host OS compiles a **host executable** for unit tests, not the `riscv32im-risc0-zkvm-elf` guest ELF. Use `docker/Dockerfile.guest` or `cargo risczero build` for the zkVM target.

---

## 3. Reproducible zkVM Guest ELF Build

[`docker/Dockerfile.guest`](../docker/Dockerfile.guest) pins `Ubuntu 22.04`, `RUST_VERSION=1.88.0`, `SOURCE_DATE_EPOCH=1700000000`, `cargo-risczero 1.2.6`, and `rzup install cpp`:

```bash
# Containerized deterministic build
docker build -t mosoo-guest-builder -f docker/Dockerfile.guest .

CONTAINER_ID=$(docker create mosoo-guest-builder)
mkdir -p target/zkvm-elf
docker cp "${CONTAINER_ID}:/out/mosoo-guest" target/zkvm-elf/mosoo-guest
docker cp "${CONTAINER_ID}:/out/mosoo-guest.sha256" target/zkvm-elf/mosoo-guest.sha256
docker rm "${CONTAINER_ID}"

cat target/zkvm-elf/mosoo-guest.sha256
sha256sum target/zkvm-elf/mosoo-guest
```

Host-based Linux/macOS/WSL2 ELF build (without Docker):

```bash
curl -L https://risczero.com/install | bash
rzup install cargo-risczero 1.2.6
rzup install cpp
cargo risczero build --manifest-path methods/guest/Cargo.toml --release
sha256sum target/riscv32im-risc0-zkvm-elf/release/mosoo-guest
```

---

## 4. Running Workspace & Verification Suites

```bash
cargo check --workspace
cargo test --workspace
forge test -vvv
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit --ignore RUSTSEC-2026-0387 --ignore RUSTSEC-2025-0055

python3 scripts/verify-evidence.py
python3 scripts/test-evidence-mutation.py
python3 scripts/verify-mosoo-lez.py --allow-offline
python3 scripts/testnet-two-way-bridge.py --mode live
```

Or run the bundled runner: `./scripts/verify_all.sh` (Linux/macOS) or `.\scripts\verify_all.ps1` (Windows).

---

## 5. Operational Notes

- **RISC0 C++ Cross-Compiler (`blst`):** Ensure `$HOME/.risc0/bin` is on `$PATH` in CI/non-interactive shells so `cargo-risczero` finds its C toolchain.
- **Sepolia RPC Receipt Pruning:** Public Ethereum Sepolia endpoints prune historical receipts inconsistently across nodes. When running `scripts/testnet-two-way-bridge.py --mode live` or fetching historical blocks, use `--eth-rpc` with an archive-capable RPC or a fallback from `SEPOLIA_RPCS`.
