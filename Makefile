.PHONY: dev test build lint

dev:
	cargo run -- --health

test:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-actions-github-api.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-actions-git-journal.py
	cargo test

build:
	cargo build --locked

lint:
	cargo fmt --check
	cargo clippy -- -D warnings
