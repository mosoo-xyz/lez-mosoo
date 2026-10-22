# Contributing to Mosoo

Thank you for your interest in contributing to Mosoo.

## Development Workflow

### Prerequisites

- Rust 1.78+ (`rustup default stable`)
- Git

### Building and Testing

```bash
# Check compilation across all crates
cargo check --workspace

# Run full test suite
cargo test --workspace

# Run linter
cargo clippy --workspace --all-targets -- -D warnings

# Format check
cargo fmt --all -- --check
```

Or using `make`:

```bash
make all
```

### Git Commits

Follow standard Conventional Commits:

- `feat:` new feature or instruction
- `fix:` bug fix or cryptographic correction
- `refactor:` code restructuring without behavioral change
- `docs:` documentation updates
- `test:` test suite additions

### Licensing

By contributing, you agree that your contributions will be dual-licensed under both the MIT License and the Apache License 2.0.
