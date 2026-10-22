#!/usr/bin/env bash
# Mosoo Deterministic Guest Build Script
# Generates reproducible RISC0 ELF and emits ImageID
set -euo pipefail

echo "=================================================="
echo " Building Mosoo RISC0 zkVM Guest Binary"
echo " Target: riscv32im-risc0-zkvm-elf"
echo "=================================================="

if command -v docker >/dev/null 2>&1; then
    echo "[+] Using Docker container build for 100% byte-for-byte reproducibility..."
    docker build -t mosoo-guest-builder -f docker/Dockerfile.guest .
    docker run --rm mosoo-guest-builder
else
    echo "[!] Docker not detected. Attempting host-based build with cargo-risczero..."
    if ! command -v cargo-risczero >/dev/null 2>&1; then
        echo "[-] Error: Neither Docker nor cargo-risczero is installed."
        echo "    Install rzup: curl -L https://risczero.com/install | bash"
        exit 1
    fi
    cargo risczero build --manifest-path methods/guest/Cargo.toml --release
    sha256sum target/riscv32im-risc0-zkvm-elf/release/mosoo-guest
fi

echo "=================================================="
echo " Deterministic Guest Build Completed Successfully"
echo "=================================================="
