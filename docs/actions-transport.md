# Actions request transport

Implementation target for ZACH-003 and Governance ADR-010. This transport is
not activated until integrated contracts, provisioning and the Web-only pilot
have passed. The existing v1 webhook remains a compatibility interface.

## Request

An Issue in the configured control repository contains ordinary JSON, optionally
inside one `json` fence. The client does not compute canonical JSON or a digest.
The entire body is the request; prose, multiple fences and duplicate JSON keys
are rejected. The four keys are required and additional keys are rejected:

```json
{
  "schema_version": 1,
  "request_id": "uds007-inspect-build-01",
  "operation": "github.ci.inspect",
  "parameters": {
    "repository": "ui-design-sandbox",
    "source_sha": "4330f61359da78543b12bd3b71f79fdaef235a86"
  }
}
```

The transport recognizes only `governance.ledger`,
`governance.audit-task-integration`, `github.ci.inspect` and
`workspace.recipe.dispatch`. Recognition does not authorize execution: each
handler must validate its own typed parameters and installed recipe policy.
Unsupported handlers fail closed. Parameters cannot select a shell command,
trusted tooling revision, credential or trusted evidence source.

The parser bounds the GitHub event to 256 KiB, request body to 32 KiB and JSON
nesting to 32 before recursive parsing. Request IDs are 8–128 ASCII characters
from letters, digits, underscore and hyphen. JSON integers must be within the
existing canonicalizer's safe range. Parameters must be an object.

## Identity and acceptance

Trusted Actions code receives the GitHub-owned event file. It checks event type
and action, configured numeric repository ID and full name, Issue ID/number,
numeric Issue author ID and numeric event sender ID against configured identity
allowlists. Pull requests masquerading as Issues are rejected. Author strings,
labels and claims inside the body do not confer authority. `opened` and `edited`
events can propose acceptance; edits cannot change an accepted transaction.

Canonicalization and hashing happen on the server. Before any effect, the
durable journal freezes the repository/Issue identity, initial actor identities,
canonical request, digest, acceptance timestamp and integrated execution policy
revision. Request IDs are unique across that journal. Exact repeats resume the
same transaction; conflicting IDs or changed Issue contents are rejected.
The Issue number alone is insufficient identity after transfers or recreation.

## Effects and recovery

The journal records accepted, executing and terminal state with exact effect
identities. Before retrying a write, the executor reconciles its recorded intent
with actual GitHub state. An ambiguous publication or deployment blocks further
effects until reconciliation. An expiring runner or missing result comment is
not evidence that an operation did not execute.

Do not use Actions concurrency as the durable queue. Requests remain discoverable
from the journal and Issues if a queued workflow is cancelled or lost. Privileged
jobs run integrated default-branch tooling; candidate code executes separately
without App publication or production credentials.

Results are bounded, authenticated Issue comments containing the request digest,
state, exact source/CI/integration identities and durable result references.
Generated files are not embedded in comments. The connector must verify the
configured App/bot identity and the frozen request binding before acting on a
result. Actual Web connector support for those identity fields remains an
activation gate.

GitHub's reference update API exposes `sha` and `force`, not an expected-old-SHA
parameter. Publication uses a single-parent commit, non-forced fast-forward and
readback of parent/tree; receipts describe those checks without claiming native
compare-and-swap. See [GitHub reference API](https://docs.github.com/en/rest/git/refs)
and [workflow concurrency](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).

## Implemented journal boundary

The pure `ledger::actions_journal::JournalRecord` API freezes acceptance and
exposes state through read-only accessors. Its transitions grant execution once,
require reconciliation on repeated claims, and retain the original owner after
ambiguous effects. Terminal outcomes permit only identical replay. Serialized
records are bounded and revalidated on restart, including canonical request
bindings and state consistency. Storage must enforce global request-ID uniqueness
and durable claim publication before executing an effect. This module does not
provide persistence, workflow handlers or independent effect observations.

## Local Actions adapter and Git persistence

`zach-actions` exposes accept, replay, claim, complete, ambiguous and reconcile.
It reads bounded event/record files and writes the validated record to stdout;
trusted workflows must redirect that output to files rather than logs. Claim
returns 0 only for a new grant, 75 for required reconciliation and 10 for a
terminal replay. The CLI never persists its output or verifies reconciliation
observations itself. Existing `cargo run` continues to select `zach`.

`scripts/actions_git_journal.py` stores each request at its global SHA-256-derived
path on the fixed Governance automation/requests branch. It requires an injected
authenticated API transport and transition validator. Reads bind Git tree modes,
blob identity and exact commit; publication validates a fresh complete snapshot,
creates one changed path and a single-parent commit, updates without force and
checks the actual ref/parent/tree. A lost update response can succeed only when
that independent readback proves the exact candidate. Unresolved publication
blocks execution; it is never an automatic retry. No native CAS API is claimed.

The Rust transition callback and Actions job wiring remain pending. The branch must be provisioned explicitly; missing/inaccessible refs
and truncated trees fail closed. Repository Contents can follow symlinks, so
its file-shaped response alone is not used as proof of a regular journal file.
See [GitHub Contents behavior](https://docs.github.com/en/rest/repos/contents).


## Authenticated HTTP transport

`scripts/actions_github_api.py` implements the journal transport interface using
GitHub's fixed HTTPS API host and an explicit subset of the four configured
repository namespaces. It rejects redirects, encoded traversal, oversized URLs,
ambiguous request keys and non-finite or duplicate response JSON. Requests have
an 8 KiB ASCII path limit, 256 KiB body limit and 20-second timeout; responses are
bounded to 2 MiB. Errors omit credentials and response bodies. Mutations are never
automatically retried. Installation tokens are injected only by trusted runtime
code; the transport does not establish actor authorization or transition policy.
The pinned REST API version is 2026-03-10. A read-only live repository lookup was
verified with existing user authentication; App provisioning and workflow
activation remain pending.
