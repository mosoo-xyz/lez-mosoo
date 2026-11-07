# Mosoo zkVM Guest Build Reproducibility

This document details how to reproduce the byte-for-byte identical **Mosoo RISC0 zkVM Guest ELF** binary for the `riscv32im-risc0-zkvm-elf` target.

---

## 1. Prerequisites

Byte-for-byte reproducibility requires a pinned build environment with:
- **Rust Toolchain:** `1.78.0`
- **RISC Zero Toolchain:** `cargo-risczero 1.0.5`
- **Target:** `riscv32im-risc0-zkvm-elf`
- **Build Timestamp (SOURCE_DATE_EPOCH):** `1700000000`

---

## 2. Recommended: Containerized Reproducible Build

We provide a pinned multi-stage Docker build environment in `docker/Dockerfile.guest`:

```bash
# Build the reproducible container image
docker build -t mosoo-guest-builder -f docker/Dockerfile.guest .

# Extract the verified ELF and SHA-256 checksum
CONTAINER_ID=$(docker create mosoo-guest-builder)
mkdir -p target/zkvm-elf
docker cp "${CONTAINER_ID}:/out/mosoo-guest" target/zkvm-elf/mosoo-guest
docker cp "${CONTAINER_ID}:/out/mosoo-guest.sha256" target/zkvm-elf/mosoo-guest.sha256
docker rm "${CONTAINER_ID}"

# Verify checksum
cat target/zkvm-elf/mosoo-guest.sha256
sha256sum target/zkvm-elf/mosoo-guest
```

---

## 3. Host-Based Build (Requires RISC Zero Toolchain)

If compiling directly on a Linux/macOS host:

```bash
# 1. Install RISC Zero toolchain via rzup
curl -L https://risczero.com/install | bash
rzup install cargo-risczero 1.0.5
rzup install cpp

# 2. Build guest program for riscv32im target
cargo risczero build --manifest-path methods/guest/Cargo.toml --release

# 3. Check emitted ELF
ls -lh target/riscv32im-risc0-zkvm-elf/release/mosoo-guest
sha256sum target/riscv32im-risc0-zkvm-elf/release/mosoo-guest
```

> [!NOTE]
> Compiling `mosoo-guest` with standard `cargo build -p mosoo-guest --release` produces an **x86_64 host mock binary**, which is used solely for local unit testing and CI smoke validation. Real zkVM proving and LEZ deployment strictly requires the `riscv32im-risc0-zkvm-elf` target compiled via Docker or `cargo risczero build`.
