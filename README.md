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

## Preparatory ledger candidate CLI

`cargo run --bin zach-ledger-candidate -- --mirror /absolute/trusted/governance-mirror --request request.json --accepted-at 2026-09-30T22:00:00Z --trusted-context context.json --output new-candidate.json`

The request file contains the full ordinary Governance ledger request object,
not the Actions transport envelope. Its canonical digest binds that request.
Acceptance time is supplied separately from the frozen trusted journal.
The optional context object permits only `remote_preflight` and
`remote_evidence` mappings; the caller must establish their authority before
invocation. The pinned Governance mutator checks their operation-specific
identity and lifecycle requirements. No closure evidence is accepted.

This preparatory tool returns unauthenticated `governance-ledger-candidate`
data with exact UTF-8 changes, blob identities and a validated Git tree. It
does not publish, fetch, call GitHub, activate the fast path, or claim receipt
authentication. `task.complete`, `task.complete_verified`, and task transitions
to `completed` are excluded. The eight initial bookkeeping operations are the
reviewed `actions_candidate` allowlist in Governance. Control/Actions wiring
remains a separately reviewed composition.

Tooling is compiled to integrated Governance revision
`7f7af5752ef2e016ffe7116f84648b3350fe507f` and exact contract/mutator blobs;
the existing webhook compatibility pins remain unchanged. The mirror is
trusted absolute local configuration, and must already contain that revision
and the requested base commit. Candidate content is treated as data; only
pinned validators execute, in a private temporary workspace with sanitized
Git/Python environments. Input files must be regular, at most 256 KiB and
not symlinks. Output uses exclusive creation with mode 0600 and at most
60,000 UTF-8 bytes. Failures print a bounded code only.
