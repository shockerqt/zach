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

## Local HTTP gateway

The gateway is an explicit, authenticated loopback adapter for the daemon's Unix
socket. It reads snapshots and subscribes to events through that socket; decisions
are applied by the existing coordinator. Start it alongside a running daemon, or
opt in when starting the daemon:

```sh
zach web --socket ~/.local/state/zach/zach.sock
zach daemon --web
```

Both forms default to `127.0.0.1:8096`. Use `--web-port 8097` or a complete
`--bind 127.0.0.1:8097` address with `zach web`; the daemon form accepts
`--web-bind`. Do not combine an explicit bind address and a port option.
`ZACH_WEB_ADDR` supplies a default bind address when enabled. Non-loopback
addresses, zero/invalid ports, duplicate options and unknown options are rejected
before readiness. Without `--web`, the daemon starts no HTTP listener.
Standalone `web` accepts a socket path, not a database path.

On explicit gateway startup, its private state directory contains a stable
`web_session_token` file. The directory must be owned by the operator and private;
the regular token file must be owned by that operator with owner-only permissions.
New credentials come from OS entropy and are created with mode `0600`. Insecure
files, symlinks, empty existing token files and generation/persistence failures stop startup.
An empty file is preserved; it is never regenerated to bypass configuration failure. The gateway does
not print credentials, return them through HTTP, or provide a session/token
endpoint. `ZACH_STATE_DIR` overrides the default `~/.local/state/zach` directory.
Only the local owner should retrieve the credential; no token belongs in this
repository, a URL, a log, or shared shell history.

All three endpoints require `Authorization: Bearer TOKEN`. URL credentials are
rejected even alongside a valid bearer, including decoded/case variants of
`token`, `access_token`, `session_token`, `web_session_token`, `authorization` and
`bearer`. Cookies and alternate authentication headers do not authenticate.
The 64-byte comparison uses pinned `subtle` 2.6.1 `ConstantTimeEq` with equal
public lengths. Its optimization barrier and compiler/platform assumptions
apply; behavioral release tests do not prove physical timing guarantees.
See the [primitive contract](https://docs.rs/subtle/2.6.1/subtle/trait.ConstantTimeEq.html).

The exact built-in Origin is `http://` plus the numeric loopback bind authority
(e.g. `http://127.0.0.1:8096` or `http://[::1]:8096`). GET may omit Origin for
native clients. POST must supply that exact Origin or an explicitly allowed one;
a missing, `null`, malformed or disallowed Origin returns 403 before backend work.
Host and forwarding headers never select an origin. Localhost aliases, other
ports and schemes require explicit configuration. Both startup forms accept:

```sh
zach web --web-allow-origin https://zach.shocker.cl
zach daemon --web --web-allow-origin https://zach.shocker.cl
```

`--web-allow-origin` is repeatable (16 entries, 512 bytes each); values must be
exact serialized HTTP(S) origins without credentials, wildcard, path/trailing
slash, query or fragment. Duplicates and malformed policy fail startup, including
for library callers. Policy flags on daemon require `--web`. No policy environment
alias exists. Actual responses and SSE grant only a validated exact Origin with
`Vary: Origin`, never credentials or a wildcard. OPTIONS alone needs no bearer:
it requires a matching Origin, known route and matching requested method, with
a unique subset of `authorization`, `content-type`, `last-event-id` request
headers, and no body. A valid preflight returns 204 without backend work.
Actual requests still need the bearer.

Endpoints:

| Endpoint | Behavior |
|---|---|
| `GET /api/snapshot` | Returns tasks, open decisions, snapshot `as_of_seq`, and daemon status. The watermark describes the snapshot; status is a subsequent read. |
| `GET /api/events` | Continuous SSE task events with `id` equal to `seq_id`, with optional `group` and `since_seq` query parameters. |
| `POST /api/decide` | JSON `decision_id`, `choice`, and optional `by`/`note`; forwards once and waits for the coordinator's decision result. |

This example reads the local credential without placing its value in command
arguments or printing it; only the authenticated response is printed:

```sh
python3 - <<'PY'
import os
from pathlib import Path
from urllib.request import Request, urlopen

state = Path(os.environ.get("ZACH_STATE_DIR") or
             str(Path(os.environ.get("XDG_STATE_HOME") or
                      Path.home() / ".local/state") / "zach"))
token = (state / "web_session_token").read_text().strip()
request = Request("http://127.0.0.1:8096/api/snapshot",
                  headers={"Authorization": "Bearer " + token})
with urlopen(request, timeout=5) as response:
    print(response.read().decode())
PY
```

For reconnecting SSE clients, send the last successfully received task-event ID
in `Last-Event-ID`; it takes precedence over `since_seq`. A missing cursor starts
at zero. Invalid, duplicate, negative or overflowing cursors are rejected.
Snapshot and resync control frames carry no SSE ID and must not advance the last
event cursor. A resync control or backend disconnect ends the stream; reconnect
from the last task event, obtaining a new snapshot when resync is required. The
gateway consumes the coordinator's existing replay/live protocol without polling
SQLite. Browser clients use authenticated `fetch` streaming and parse SSE frames;
native `EventSource` cannot set the required Authorization header. Never put a
token into the stream URL as a substitute.

Before forwarding a decision, the gateway reads its authoritative record through
`GetDecision` on the existing socket, including resolved records. Missing records
return 404; invalid/mismatched backend records fail closed. The default kind
allowlist is: `plan_approval`, `human-plan-approval`, `retries_exhausted`,
`scope_violation`, `plan_rework_limit`, `review_rework_limit`,
`governance_close_failed`, `governance_publication_failed`,
`checkpoint_unverifiable`, `repository_ownership_conflict`,
`cross_family_reviewer_unavailable`, `merge_failed`, `post_merge_failure`,
`new_apk_required`, `prod_promotion_approval`, `delivery_contract_error`.
Other kinds return 403, including **both** `merge_approval` and
`human-merge-approval`, irrespective of ID, choice or resolved status.
Repeatable `--web-allow-decision-kind KIND` extends this allowlist (32 entries,
64 lowercase ASCII letter/digit/underscore/hyphen bytes each, no duplicates).
Enabling a kind delegates its existing coordinator capability. Each merge kind
requires its exact name; enabling one does not enable the other.

Native POST callers must add an Origin header, for example this synthetic request:

```http
POST /api/decide HTTP/1.1
Host: 127.0.0.1:8096
Origin: http://127.0.0.1:8096
Authorization: Bearer <LOCAL_PRIVATE_TOKEN>
Content-Type: application/json
Content-Length: 51

{"decision_id":"SYNTHETIC-PLAN","choice":"APPROVE"}
```

A decision returns HTTP 200 only after `RESOLVED` or `ALREADY_RESOLVED` is received;
missing decisions return 404, malformed payloads 400, and unavailable/timeout
backends 503/504. A timeout or disconnect after dispatch can mean the decision
was applied without its acknowledgment reaching the caller. Check the next
snapshot/events before deciding what to do; do not blindly repeat the request.

Requests are bounded to a 4096-byte request line, 16 KiB headers, 64 headers,
32 query fields and 16 KiB body. Backend frames (4 MiB), active clients (32),
SSE sessions (8) and operations (5 seconds) are bounded.
Slow/disconnected clients are released, and shutdown stops and joins gateway
resources. No wildcard CORS policy is enabled. This task installs no service,
opens no firewall rule and exposes no public endpoint. The web UI belongs to
ZACH-030, and host/public exposure to INF-020.

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

Repository-owned promotion contracts may opt in to `current_source_authority: plan`
under a promotion in schema version 1. The selector is exclusive with
`current_source_probe`; omitted selectors preserve the existing probe behavior
(and `none` when no probe is configured). Unknown, empty and null selectors fail
closed. A generic promotion fragment is:

```yaml
current_source_authority: plan
plan_inputs:
  build_run_id: '${build_run_id}'
  source_sha: '${source_sha}'
  artifact_digest: '${artifact_digest}'
  approve_production: 'false'
approve_inputs:
  build_run_id: '${build_run_id}'
  source_sha: '${source_sha}'
  artifact_digest: '${artifact_digest}'
  expected_current: '${expected_current}'
  approve_production: 'true'
plan_file: plan.json
delivery_file: result.json
```

The read-only producer must observe the actual deployment host and return a
normalized top-level `expected_current` string, explicitly `none` for an empty
host, alongside `source_sha`, `build_run_id` and `artifact_digest` (or
`artifact_sha256`). Current identities may be safe opaque tokens; missing, null,
empty, nonstring and unsafe values are errors. Plan inputs cannot reference
`${expected_current}`. This mode requires a complete delivery receipt through
`delivery_file`.

Zach verifies the exact dispatched plan run and its immutable tuple before
saving the observed current at `plan_validated` and opening human production
approval. Approval triggers a new read-only run. Equal current is durably saved
at `apply_ready` before one apply dispatch; drift adopts the newly verified
current and requires a fresh approval. The host must still enforce
expected-current CAS during apply, and the final receipt must match the entire
approved tuple. A failed apply requires a fresh plan and approval through Retry.
Restarting an unknown dispatch outcome requires intervention and never replays
that dispatch automatically.
