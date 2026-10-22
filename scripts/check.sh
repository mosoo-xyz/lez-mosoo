#!/usr/bin/env bash
set -euo pipefail

echo "==> Running cargo check..."
cargo check --workspace

echo "==> Running tests..."
cargo test --workspace

echo "==> Running clippy..."
cargo clippy --workspace --all-targets -- -D warnings

echo "==> Checking format..."
cargo fmt --all -- --check

echo "==> All checks passed!"
