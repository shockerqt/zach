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
