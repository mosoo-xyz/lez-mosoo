.PHONY: all build check test clippy fmt fmt-check demo clean

all: check test clippy fmt-check

build:
	cargo build --workspace

check:
	cargo check --workspace

test:
	cargo test --workspace

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

fmt:
	cargo fmt --all

fmt-check:
	cargo fmt --all -- --check

demo:
	cargo run -p mosoo-cli -- demo

clean:
	cargo clean
