.PHONY: dev test build lint

dev:
	cargo run -- --health

test:
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-actions-ci-inspect.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-actions-github-api.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-actions-git-journal.py
	cargo test
	cargo build --locked --bin zach-actions
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-actions-journal-coordinator.py
	PYTHONDONTWRITEBYTECODE=1 python3 scripts/test-actions-request-handler.py

build:
	cargo build --locked

lint:
	cargo fmt --check
	cargo clippy -- -D warnings
