# Daemon supervision

`zachd` owns scheduling, workers, pipeline checkpoints, and Governance write-back.
`zach run [--task ID | --group GROUP] [--once]` submits a scheduling request to
its socket and returns an acknowledgment. A run request does not create another
supervisor. `--dry-run` opens the existing database read-only and builds previews;
it does not reconcile units, stage credentials, create proxies, or publish stages.

The internal SQLite schema is version 3. The `ws-task export` wire contract stays
at version 2. Migrations inspect columns before adding them, preserve nullable
usage counters and existing supervision columns, and reject a newer database.
Task memory uses defaulted fields so older records remain readable.

## Ownership and responsive control

The daemon acquires `<state_dir>/zachd.lock` with nonblocking flock and CLOEXEC
before it unlinks or binds the socket. Keep the same state directory across
restarts. A separate coordinator thread owns daemon SQLite mutations. The 50ms
socket loop uses bounded, nonblocking reads/writes and typed mpsc requests and
responses. Partial writes are retained; oversized or stalled consumers reconnect
and replay the durable event log.

Four general workers run preparation, validation, checks, Git operations and
resumable merge phases. Two reserved monitoring workers run systemd operations;
a separate Governance worker runs exports and lifecycle publication. Queue sizes
and per-tick event drains are bounded. Heavy checks acquire their semaphore on
workers. A panic or task operation failure becomes a supervisor event, retry,
or decision, while store/startup/isolation errors can stop the daemon.

The initial isolation preflight, unit reconciliation and synchronized export form
a dispatch barrier. Recovery inspects exact persisted unit names as well as the
unit enumeration, reconnects interrupted task/attempt references, resumes saved
post-processing, stops superseded/unrecognized workers, and rebuilds repository
ownership. Lease expiry alone never establishes that a unit is dead.

Every stage owns `(repository, "*")`, including plan and plan-review. Different
repositories can execute in parallel up to `max_parallel_tasks`. Queued merges,
human gates, and a blocked post-merge lane reserve their repository without
consuming a task execution slot. Confirmed-stop execution failures release their
lane during backoff. Ordinary abort/rejection remains blocked and releases its
lane after execution stops. A post-merge receipt or close-pending lane stays
reserved until close succeeds or an explicit lane resolution authorizes release.

## Detached units and isolation resources

Preparation creates protected artifacts under `<state_dir>/attempts/<attempt>`
and a versioned manifest with actual route, policy, identity, paths and
`sha_before`. The final launch uses canonical absolute file-backed stdin/stdout/
stderr, `--no-block`, `--service-type=exec`, `RemainAfterExit=yes` and
`CollectMode=inactive`. Runtime, memory, CPU, task-count and process-tree limits
remain enforced. The pure command builder performs no filesystem or unit work.
Codex review schemas retain an explicit read-only file mount.

Task ownership, attempt identity, lease, repository lock and launch intent commit
before invoking systemd-run. An accepted asynchronous start is observed for a
bounded startup interval; blank InvocationID and ControlGroup values are refreshed
lazily. A conflicting nonblank InvocationID fails closed. Manager communication
errors are distinct from a confirmed not-found unit.

Attempt phases are:

```text
LAUNCH_PENDING -> RUNNING -> EXIT_OBSERVED -> HARVESTED
              -> POSTPROCESSING -> COMPLETE
```

The task checkpoint records preparation and individual post-processing operations
as well as confirmed-stop cleanup. A clean worker exit remains `active/exited`;
it is harvested, not treated as a running process. Failure output and exit code
kind/status are also harvested. The coordinator records HARVESTED before stop,
confirms stop/reset-failed, records cleanup intent, then removes staged auth and
proxy resources. Failed stop/inspection retains ownership and files. Cleanup and
replayed stop are idempotent. Successful worker output is not rerun for publication
failure. Detached manifests are protected from age-only pruning because pending
stage/close receipts may still reference their evidence.

The supervisor owns `PreparedResources` and `ProxyHandle` through harvest and
stop. Registry destruction preserves staged auth and the mounted `net/` directory.
A live compatible ProviderApi attempt restores its family-specific policy and
rebinds `<attempt>/net/proxy.sock`. The sandbox sees the replacement inode through
`--ro-bind <attempt>/net /run/zach-net`; the mounted directory itself is never
replaced. Peer UID checks, allowlists, DNS/IP validation and tunnel limits remain
in force. Missing auth, an unsafe manifest or a legacy socket-inode mount causes
stop and infrastructure retry. Direct networking is never a recovery fallback.

## Liveness, retries and human decisions

Live workers sample combined stdout/stderr growth and cgroup `usage_usec`.
Either signal refreshes liveness. Reattachment resets the baseline to the current
time, so daemon downtime does not produce an immediate stall. Exited state is
processed before timeouts. Missing CPU data does not represent zero progress;
persistent observation failure uses bounded infrastructure recovery. Both stagnant
signals after `stall_timeout_secs` produce `STALLED/infra`, followed by confirmed
stop and cleanup before retry.

Infrastructure and semantic failures allow an initial attempt plus two automatic
retries per task, stage, class and retry generation. Policy failures allow none.
Backoff is `min(15 * 2^(failure_index - 1), 300)` seconds and persists across
restarts. Exhaustion opens a decision. Manual “Retry stage” advances the generation
and reset epoch, clears backoff and resumes only that stage.

Schema-valid CHANGES_REQUESTED reviews have separate plan/PR rework counters,
with two rework cycles each; they do not spend failure retries or impose failure
backoff. Rework invalidates the affected downstream approvals. Additional rework
requires its own decision action. Decisions validate their offered choice, record
actor/note once, and never apply a blanket Blocked-to-Ready transition.

Human approvals bind the current SHA and review generation. Local completion waits
for `ws-task stage ... --actor <human> --sha <bound SHA>` acknowledgment. Reject,
Abort task and Cancel / Block do not implicitly invoke remote cancellation.

## Governance publication and merge recovery

`lifecycle_ops` is a durable ordered outbox with stable operation IDs, optional
attempt/decision IDs, structured arguments, evidence body-file paths, dependencies,
retry deadlines and acknowledgment/error receipts. Intent precedes each subprocess;
publication acknowledgment and the local task transition commit together. An
interrupted IN_FLIGHT publication becomes pending on restart and uses the same
idempotency key. Start recovery uses synchronized readback and only the supported
same-executor `--resume` path. Its canonical branch/worktree receipt is applied
directly. Exports cannot replace Zach's active scope, network policy, weight,
plan, branch, worktree, retry state, checkpoints or human waits.

Exports run with `--sync --json` every `ZACH_SYNC_INTERVAL_SECS` (default 30).
`last_sync_epoch` is distinct from the coordinator heartbeat. Socket status also
reports active units, occupied repositories, task slots, backoff tasks, pending
write-backs and reconciliation faults.

Publication order is start, candidate plan, plan-review, human-plan-approval (L),
impl after checks/commit/push, pr-review, human-merge-approval (L), and close.
Every revised candidate is published before its review. PR review evidence retains
the complete five-column `AC | Criterion | Evidence | Test | Result` table,
validated citations and bound SHA, rather than the bounded attempt summary.

Merge workers execute one checkpointed phase at a time: merge default branch,
gate checks, reviewed-diff verification/parity publication, push, exact-SHA CI,
match-head merge, post-merge verification and close. CI observation has a persisted
time budget. Changed task files or unavailable evidence require actual re-review.
For a clean merge-induced SHA change, parity publication carries forward the
existing validated evidence and explicitly states that no reviewer reran. Only
its acknowledgment updates reviewed_sha; L also requires new human approval at
the target SHA before push/merge continues.

MERGE_PENDING is durable before the merge side effect. Recovery queries PR state
before merging; a merged PR resumes from its merge receipt. After post-merge CI,
CLOSE_PENDING retains the PR/target/merge SHA and verification receipt. Close failure
opens a close-specific decision and never marks Done or offers Retry merge.
Only close acknowledgment (or synchronized terminal readback of the saved close
receipt) releases the lane and emits MERGE_COMPLETED.

Governance has no `block` command. Supported board transitions use start/stage/
close with executor=zach. Internal Ready, retry backoff, queued merge and decision
waits remain durable local supervision states; exact board mirroring would require
a separately owned Governance API extension.

## Shutdown and host verification

SIGTERM/SIGINT stop new dispatch and persist ownership release without stopping
detached stage workers or deleting their required resources. Optional NOTIFY_SOCKET
supports pathname and Linux abstract addresses for READY, WATCHDOG and STOPPING;
watchdog delivery stays on the responsive socket thread.

The persistent system service, slice restart policy and host rollout belong to a
separate INF task. Its service must preserve `zach-workers.slice` across daemon
restarts. This change installs no service or host policy, adds no Cargo dependency,
and assumes no ZACH-034 delivery table.

Run the inference-free host contract test explicitly:

```sh
ZACH_RUN_HOST_SUPERVISION_TEST=1 cargo test --locked --test daemon_supervision host_supervision_retained_exit_restart_proxy_rebind_and_ordered_cleanup -- --ignored --nocapture
cargo run -- doctor --json
```

The test verifies retained exit-0 harvesting, manifest-based reattachment, an actual
proxy-owner SIGKILL leaving a stale socket, a live sandbox reconnecting through a
rebound directory-mounted proxy socket, unchanged
InvocationID/directory inode, and stop-before-auth/net-cleanup ordering.
