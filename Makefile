.PHONY: dev test build lint

dev:
	cargo run -- --health

test:
	cargo test

build:
	cargo build --locked

lint:
	cargo fmt --check
	cargo clippy -- -D warnings
