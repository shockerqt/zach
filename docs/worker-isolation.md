# Worker isolation

ZACH-024 separates resource supervision from containment. On the audited host,
`systemd-run --user` accepted `InaccessiblePaths`, `PrivateNetwork` and
`IPAddressDeny` without preventing credential reads or outbound HTTPS. These
properties are not a security boundary for unprivileged user units.

Every worker and `worker_checks` command now runs through `/usr/bin/bwrap` inside
a transient user unit in `zach-workers.slice`. systemd retains memory, CPU, task,
runtime and process-tree limits. Bubblewrap supplies mount, PID, IPC, user and
network namespaces, a new session and parent-death cleanup. Units retain the
`zach-stage-*` naming convention for orphan reconciliation.

## Filesystem boundary

The OS is mounted read-only. `/home` and `/root` are masked, and `/tmp`, `/run`
and `/var/tmp` are private tmpfs mounts. Only the governed worktree, explicit
read-only toolchains, Git metadata, and the selected provider's staged auth are
introduced again. The Gemini plugin is mounted separately when needed. PATH
uses stable fnm locations; the host's runtime directory and environment secrets
are not forwarded into the sandbox. XDG_RUNTIME_DIR is `/tmp/xdg-runtime`, mode
0700. Bubblewrap clears the inherited environment before installing its own map.

`plan`, `plan-review` and `pr-review` worktrees are read-only. `impl` and worker
checks can write their worktree. `.git` is always overlaid read-only, including
pointer files, canonical linked-worktree metadata and the primary common Git
directory. Workers cannot replace the pointer or change host Git configuration.

The worktree is walked without following directory symlinks. Regular `.env*`
files are covered with read-only `/dev/null` mounts. Exact `.env.example`,
`.env.sample`, `.env.template`, `.env.dist` and `.env.schema` templates remain
visible. Any `.env*` symlink, including template names, rejects preparation.
Directories such as `.env.d` remain directories and their contents are scanned.
Review schemas under the host attempt directory receive exact read-only file
mounts after all masks. The attempt directory and other artifacts are not shared.
Prompts still arrive through stdin, and the bridge inherits all three stdio FDs.

## Authentication and lifetimes

Per-attempt Codex state contains only a writable copy of `auth.json`. Gemini
state copies only the five approved OAuth/config files. Staged directories are
0700 and files are 0600. Sources and staging paths reject symlinks; file opens
use O_NOFOLLOW. Token refresh changes the staged copies, not operator files.
Host sessions, history, conversations, gh, SSH, gcloud, workspace-actions and
Zach's database/socket remain hidden. Worker checks receive no provider auth.

`PreparedResources` owns staged directories and `ProxyHandle` owns the listener,
active clients and listener/tunnel threads. Preparation failures clean up their
resources. Once launch intent is durable, the daemon supervisor retains ownership
through harvest and confirmed stop; dropping the registry preserves staged auth
and the mounted network directory for restart recovery. Proxy listeners can be
rebound at the same socket pathname without replacing that directory. Protected
detached artifacts remain until their publication/merge receipts permit cleanup.
Resource discovery/preparation is separate from the pure argv builder; dry-run
planning performs no staging, filesystem inspection or listener creation.
Its declarative argv is completed with discovered mounts during execution.
See [daemon supervision](daemon-supervision.md) for the retained-unit lifecycle.
The configured daemon state directory must be outside the worker worktree so the
worktree bind cannot expose daemon state or other attempts' staged credentials.

## Network boundary

All workers keep an isolated network namespace. `context_pack.network` accepts
`none` or `provider-api`; omission preserves provider API access for model
stages. Invalid declarations reject only that task, not the board export. Plans
may narrow access and cannot widen an existing offline declaration. Worker
checks are always offline regardless of the model-stage declaration.

Offline stages have no proxy socket. Provider stages receive a directory mount
`<attempt>/net` at `/run/zach-net`, with the host socket at
`<attempt>/net/proxy.sock`. Binding through a directory file descriptor avoids
Linux sockaddr_un path length limits without moving the socket. The executable
is mounted separately at `/run/zach-bridge/bridge`, after masking `/run`. The
bridge listens on sandbox-local loopback and sets proxy variables for its child.
`NO_PROXY=localhost,127.0.0.1,::1` allows Gemini's internal local language server;
host loopback and direct external TCP remain unreachable.

The host proxy verifies SO_PEERCRED UID and accepts only HTTP CONNECT to port
443 on the exact case-insensitive provider hostname list:

| Family | Hosts |
| --- | --- |
| OpenAI | api.openai.com, chatgpt.com, auth.openai.com, auth.api.openai.org |
| Gemini | daily-cloudcode-pa.googleapis.com, cloudcode-pa.googleapis.com, aicode.googleapis.com, generativelanguage.googleapis.com, aiplatform.googleapis.com, oauth2.googleapis.com, accounts.google.com, play.googleapis.com |

IP literals, other methods/ports, URL syntax and suffix matches are rejected.
Every DNS answer must be public, including unwrapped IPv4-mapped IPv6 addresses.
The connection uses the validated SocketAddr directly, preventing a second DNS
lookup from rebinding to a private endpoint. Headers are limited to 8 KiB, header
reading has an absolute deadline, DNS caller waits and connections are bounded,
and there are at most 32 active tunnels per proxy. Resolver threads have a global
32-thread cap because the stdlib resolver itself cannot be cancelled. CONNECT
payloads remain encrypted; the proxy does not inspect TLS contents.

## Doctor and fail-closed startup

Run `cargo run -- doctor --json` or `zach doctor --worktree <PATH>`. The optional
path selects the parent for a private disposable probe repository; the selected
repository's Git state is not modified. Doctor creates an empty synthetic Git
history and a linked worktree only inside that disposable directory, injects a
synthetic secret, and runs real transient systemd+bwrap units. It checks both Git
metadata forms and read-only/read-write stages, schema visibility, credential
path hiding, write containment, host loopback/external TCP denial, proxy 403s and
provider CONNECT reachability, plus staged-auth node/Codex/Gemini CLI readiness.
It never makes an inference request or prints staged credentials.

Any failed probe returns nonzero. Daemon startup and non-dry-run `zach run` refuse
to dispatch after `ISOLATION_PREFLIGHT_FAILED`; the executor also checks an
injectable, process-cached preflight before stages and worker checks. This error
is classified as infrastructure failure even if diagnostic text mentions a
policy. Dry runs do not require a working user systemd manager or credentials.

`gate_checks` remain trusted host operations, dispatched separately from worker
checks, including the existing merge queue driver. Keep `cargo run -- doctor
--json` in `verification_commands`, not worker/gate checks: it is a host probe,
not a nested sandbox check.

The trust boundary includes the kernel, bubblewrap/AppArmor profile, systemd,
operator-owned toolchains and the orchestrator. This is not isolation from a
malicious process already running as the operator on the host. OS files outside
the masked home/runtime trees remain readable through the read-only OS mount;
operator secrets must stay in the masked stores, not system-readable locations.
Existing `.env*` protection does not classify arbitrary secret filenames or
secrets newly supplied by an external host process during a running attempt.
Network allowlisting grants encrypted tunnels to provider endpoints, not a
request-level API authorization policy. No new users, system services, host
configuration, dependencies or infrastructure changes are included; future
persistent supervision belongs to the separate INF task (ADR-013).
