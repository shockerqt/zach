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

## Preparatory frozen integration collector

`integration_observer::collect_frozen_integration` is a Rust library API for
trusted Actions composition. Its typed request fixes the Governance commit,
task ID, explicitly linked implementation run ID and accepted request ID.
Reviewed runtime policy supplies the CI workflow path (`.github/workflows/ci.yml`),
never Issue parameters. It reads canonical records at that single SHA, requires
a completed standard v1 GitHub connector run with owned evidence, independently
checks implementation CI, merged representation and exact merge-SHA CI from
the same workflow, and reports canonical branch/open-PR observations even when
the branch is absent. The API host is fixed to `https://api.github.com` and
canonical Governance source to `shockerqt/workspace-governance`; configuration
overrides fail before HTTP. The frozen Governance revision must be an ancestor
of the independently observed integrated `master` head before any canonical
records are read. Merge CI must be a push on the target repository's observed
default branch. Present branch SHAs and repeated open-PR observations must agree;
unstable or truncated cleanup evidence fails closed.
The observer sends its bounded Authorization header
through stdin, never process arguments. It hard-caps stdout (1 MiB plus status)
and stderr (8 KiB), kills/reaps on excess or failure, and also sets curl request
timeouts and rejects redirects. Repository, workflow and verified CI run IDs
must fit the safe integer range.
Requests use bounded GETs; up to 100
linked runs and the first 100 merge-CI candidates are supported. Missing evidence
fails closed. Attempt-specific implementation CI URLs are currently unsupported
and rejected instead of substituting the latest attempt.

The output is plain observations, not an authenticated receipt or closure
attestation. There is no new authentication path, durable store or lifecycle writer.
The existing Actions journal must own acceptance, claims and replay. A separate
Publisher must still authenticate the verification job and immutable artifact,
bind their bytes to that accepted request, and apply the Governance closure
gates. This API does not activate closure or replace the required Web pilot.
The legacy audit API retains its existing unavailable-store behavior.

`serialize_integration_observations` adds separately supplied trusted Actions
request digest, accepted journal SHA, policy/tool revisions and UTC verification
time to the collected facts. It emits at most 32 KiB using Governance's exact
`json-ascii-sorted-compact-v1` observation schema, including ASCII escapes and
UTF-16 surrogate pairs. Repository identity in that schema is the canonical
Governance alias; URLs remain bound to the full GitHub repository name.
The serializer rejects inconsistent identities, unsuccessful CI, unrepresented
merges, invalid timestamps and outstanding open PRs. Remote-only local cleanup
is `not-applicable`. These deterministic bytes remain unauthenticated observations;
they contain no verification envelope or job/artifact proof.

The trusted read-only executable `zach-integration-observe --input /absolute/input.json
--output /absolute/new-observation.json` accepts exactly `request` (Governance
SHA, task/run/request IDs) and `bindings` (accepted journal SHA, request digest,
policy/tool revisions, verified UTC time). Input is strict JSON capped at 16 KiB
from a regular non-symlink file. The output uses exclusive creation with mode
0600. It uses only `ZACH_INSTALLATION_TOKEN`, fixed GitHub/Governance routing and
`.github/workflows/ci.yml` policy. It emits static failure codes and no success
metadata on stdout. This executable is trusted tooling for the existing Actions
owner, not a service, candidate-code runner, authenticator or publisher.
