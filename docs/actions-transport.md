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

The Actions job wiring remains pending. The branch must be provisioned explicitly; missing/inaccessible refs
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


## Durable journal coordinator

`scripts/actions_journal_coordinator.py` connects an explicitly pinned trusted
`zach-actions` executable with the Git journal. Its publish callback binds the
exact loaded record and exact Rust-generated replacement. Acceptance replay
preserves the first timestamp and policy revision. A claim grants execution only
after its record is durably published and read back; repeated claims, including
the same execution owner, require reconciliation. Completion and ambiguity
updates require the stored execution owner. Publication conflicts propagate and
never trigger automatic retries. No reconciliation or effect handler is exposed.

The child receives private bounded files, a minimal environment and bounded I/O
with a timeout. Runtime code must supply the reviewed executable and trusted
operation results, keep credentials out of event/record content, and consume
only the returned claim disposition as execution permission. Data fields are
omitted from result representations to reduce accidental logging. This remains
preparatory tooling; no Actions workflow is activated by the coordinator.


## Read-only CI inspection

`scripts/actions_ci_inspect.py` accepts only the configured repository alias and
exact source SHA. Trusted configuration supplies numeric repository/workflow IDs
and the registered CI path. Complete bounded API pagination, foreign-identity
rejection and selected-attempt job checks precede its bounded response. It lists
up to ten newest created runs and their current attempts, plus failed-step labels
for the selected run. Raw logs and artifacts are not included. A final run-list
and selected-run read reject observed races; the response remains a point-in-time
observation, not permission to merge or deploy. No request is mutated or retried.
The 16 KiB limit is enforced rather than silently dropping authoritative facts.

Full Issue workflow wiring remains pending. A failed-step label identifies where
CI failed; detailed compiler/test diagnostics will require a separately bounded
reporting path before the complete Web debugging pilot can pass.

## Typed recipe dispatch

`scripts/actions_recipe_dispatch.py` implements only the recipe selected by the
trusted Control policy. Issue JSON supplies `recipe`, `operation`, immutable
source/artifact identities and expected current state; it cannot select a
repository, workflow, ref, command or credential. Deploy requires the CI
run/attempt, artifact ID and distinct outer transport digest. Rollback forbids
those deploy-only fields and binds the exact retained source/digest pair.

Before its single mutation, Control reads back the configured repository ID,
default branch and active workflow ID/path. It POSTs one `workflow_dispatch`
using policy-selected ref and exact string inputs. The API response must contain
the new run ID and canonical URLs; an immediate readback must bind that run to
the configured repository, workflow, ref, Control bot identity,
`workflow_dispatch` event, request-bound run name and acceptance-time window.
The authenticated receipt reports only `dispatched`
and the observed run identity/status. Completion and production success come
from the recipe's own bounded result, observed separately.

A 4xx dispatch rejection is terminal and safe to report as rejected. A timeout,
5xx, malformed successful response or failed/mismatched run readback after POST
is ambiguous: Control publishes no terminal receipt and never repeats the POST.
`control-reconcile` consumes the retained immutable prepare result and performs
two complete, bounded workflow-run scans. It accepts exactly one stable run
whose run name, acceptance-time window, actor, repository, workflow, ref and
event match, verifies it again by immutable ID, and only then publishes the
same `dispatched` receipt. Zero matches, multiple matches, unstable pagination
or malformed observations remain ambiguous without another dispatch.

## Isolated phase CLI

`scripts/actions_phase_cli.py` is the minimal machine entry point for separate
separate trusted Actions jobs. It never fetches or synthesizes an Issue event.
The sequential `ActionsRequestHandler` facade remains a compatibility/test
composition and is not the credential-bearing Actions runtime.
The Publisher workflow must fetch the actual Issue and construct a bounded event
file with the GitHub-owned repository and Issue fields plus authenticated
workflow actor metadata before calling `prepare`.

Every invocation reads its installation token only from
`ZACH_INSTALLATION_TOKEN` and writes its machine result to a newly created,
mode-0600 `--output-file`; it writes no result or payload to stdout. The trusted
policy is a checked-in or otherwise trusted workflow input with this exact shape:

```json
{
  "schema_version": 1,
  "repository": {"id": 1001, "full_name": "shockerqt/zach"},
  "allowed_actor_ids": [2001],
  "control_identity": {"app_id": 9876, "bot_user_id": 54321},
  "ci": {
    "repository_alias": "ui-design-sandbox",
    "repository_id": 1002,
    "repository_full_name": "shockerqt/ui-design-sandbox",
    "workflow_id": 339778910,
    "workflow_path": ".github/workflows/ci.yml"
  },
  "recipe": {
    "recipe": "sandbox.delivery",
    "repository_alias": "ui-design-sandbox",
    "repository_id": 1324116785,
    "repository_full_name": "shockerqt/ui-design-sandbox",
    "workflow_id": 123456,
    "workflow_path": ".github/workflows/sandbox-delivery.yml",
    "ref": "main",
    "actor_id": 54321
  },
  "policy_revision": "4ae216576b054f528c9edbcfed4a2711bccaa476"
}
```

The `recipe` object is optional only for the already deployed CI-inspection
canary policy. A `workspace.recipe.dispatch` bundle fails closed when it is
absent. Its `actor_id` must equal `control_identity.bot_user_id`. Control opens
the Issue repository plus the repository required by the selected operation;
recipe dispatch does not inherit the CI repository namespace.

The workflow, rather than Issue JSON, selects this policy and the absolute path
to the reviewed, integrated `zach-actions` executable. The normal calls are:

```text
python3 scripts/actions_phase_cli.py prepare \
  --policy-file POLICY.json --event-file EVENT.json \
  --execution-id RUN_ID --accepted-at 2026-09-10T22:21:00Z \
  --rust-cli /absolute/path/to/zach-actions --output-file PREPARE.json

python3 scripts/actions_phase_cli.py control \
  --policy-file POLICY.json --prepare-result PREPARE.json \
  --output-file CONTROL.json

# Only after an ambiguous Control result; this performs no workflow dispatch.
python3 scripts/actions_phase_cli.py control-reconcile \
  --policy-file POLICY.json --prepare-result PREPARE.json \
  --output-file CONTROL-RECONCILE.json

python3 scripts/actions_phase_cli.py finalize \
  --policy-file POLICY.json --prepare-result PREPARE.json \
  --rust-cli /absolute/path/to/zach-actions --output-file FINALIZE.json
```

`prepare` returns `granted`, `reconciliation_required`, or `terminal_replay`.
Only `granted` includes an immutable execution bundle and permits the Control
job to run. `control` uses only the bundle and its Control installation token;
`control-reconcile` uses the same frozen bundle and Control namespace but is
read-only until it publishes a uniquely reconciled receipt. Neither receives the
Publisher coordinator. `finalize` reloads the durable
journal and independently observes the authenticated receipt, without consuming
the Control result file. Each job must expose only its own installation token.
An ambiguous Control publication and every sanitized phase error return nonzero;
the CLI performs no automatic retry or second effect.
