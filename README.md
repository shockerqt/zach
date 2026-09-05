# Zach

Zach is the restricted, GitHub-mediated workspace control agent for this
workspace. It will accept only typed, governed operations and publish
structured receipts; it is not a general-purpose shell executor.

The name Zach is inspired by the creator's cat.

## Bootstrap commands

```sh
make dev
make test
make build
make lint
```

Linux builds require the SQLite development linker library (`libsqlite3-dev`
on Ubuntu). Secure materialization uses platform-specific libc bindings rather
than assuming identical numeric open flags on x86_64 and ARM64.

The existing binary provides bootstrap commands, the v1 ledger webhook and
the integration-audit command. The new ordinary-JSON Issue decoder is exposed
through `zach::ledger::actions`; see [the transport contract](docs/actions-transport.md).
Actions execution and journal-backed side effects remain gated by ZACH-003
and the Governance Web-only pilot. No credentials belong in this repository.
