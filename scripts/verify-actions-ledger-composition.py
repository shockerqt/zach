"""Local composition verification with real Rust/Git and synthetic remote facts.

Usage: python3 scripts/verify-actions-ledger-composition.py \
    --governance-mirror /absolute/local/governance-mirror

No network, credentials or source refs are used or changed. Publication Git
objects are independently computed in a disposable clone; refs and authenticated
comment metadata are synthetic in-memory fixtures. This is NOT online evidence.
The configured Zach binaries must already be built; this script never builds.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import zipfile


BASE = "7f7af5752ef2e016ffe7116f84648b3350fe507f"
REPOSITORY = "shockerqt/workspace-governance"
REPOSITORY_ID = 1260920764
BRANCH = "task/GOV-041-workspace-command-fast-path"
WORKFLOW_REVISION = "d" * 40
TOOL_REVISION = "e" * 40
ACCEPTED_AT = "2026-10-11T02:00:00Z"
RUN_ID = "GOV-041-20260905-030554-actions-ledger-lifecycle"


class VerificationError(AssertionError):
    def __init__(self, message):
        self.code = re.sub(r"[^a-z0-9]+", "_", message.lower())[:80]
        super().__init__(self.code)


def require(value, message):
    if not value:
        raise VerificationError(message)


def git(repository, *args, data=None, index=None):
    environment = {
        "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_AUTHOR_NAME": "Synthetic verifier", "GIT_AUTHOR_EMAIL": "synthetic@example.invalid",
        "GIT_COMMITTER_NAME": "Synthetic verifier", "GIT_COMMITTER_EMAIL": "synthetic@example.invalid",
        "GIT_AUTHOR_DATE": "2026-10-11T02:10:00Z", "GIT_COMMITTER_DATE": "2026-10-11T02:10:00Z",
    }
    if index is not None:
        environment["GIT_INDEX_FILE"] = str(index)
    result = subprocess.run(("/usr/bin/git", "-C", str(repository), *args), input=data,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=environment, timeout=30, check=False)
    require(result.returncode == 0, "local Git fixture command failed")
    return result.stdout


class SyntheticApi:
    """No HTTP transport exists here. Git writes target only disposable objects."""

    def __init__(self, fixtures, store, index, run_id, base, publisher_identity):
        self.fixtures, self.store, self.index = fixtures, store, index
        self.journal = fixtures.UnifiedFakeApi()
        self.branch_head, self.run_id = base, run_id
        self.publisher_identity = publisher_identity
        self.task_patches = 0
        self.object_writes = 0
        self.downloads = 0
        self.patch_mode = "ok"
        self.interrupt_readback = False
        self.fail_next_task_read = False
        self.archive = None
        self.artifact = None
        self.candidate_bytes = None
        self.calls = []

    def install_artifact(self, path):
        raw = Path(path).read_bytes()
        require(0 < len(raw) <= 262144, "candidate fixture bound")
        self.candidate_bytes = raw
        stream = io.BytesIO()
        with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("candidate.json", raw)
        self.archive = stream.getvalue()
        self.artifact = {
            "id": self.run_id * 10 + 1, "name": f"workspace-ledger-candidate-{self.run_id}-1",
            "expired": False, "size_in_bytes": len(self.archive),
            "digest": "sha256:" + hashlib.sha256(self.archive).hexdigest(),
            "created_at": "2026-10-11T02:00:30Z", "updated_at": "2026-10-11T02:00:30Z",
            "expires_at": "2026-10-12T02:00:00Z",
            "workflow_run": {"id": self.run_id, "repository_id": REPOSITORY_ID,
                "head_repository_id": REPOSITORY_ID, "head_sha": WORKFLOW_REVISION,
                "head_branch": "master"},
        }

    def public_zach_get(self, path):
        require(path == "/repos/shockerqt/zach/git/ref/heads/main", "unexpected public observation")
        self.calls.append(("public-GET", path))
        return {"ref": "refs/heads/main", "object": {"type": "commit", "sha": TOOL_REVISION}}

    def download_artifact(self, repository, artifact_id):
        require(repository == REPOSITORY and artifact_id == self.artifact["id"], "artifact identity")
        self.downloads += 1
        return self.archive

    def control(self, method, path, body=None):
        require(path.startswith(f"/repos/{REPOSITORY}/issues/"), "Control attempted Git/journal access")
        return self._request(method, path, body, publisher=False)

    def __call__(self, method, path, body=None):
        return self._request(method, path, body, publisher=True)

    def _request(self, method, path, body, *, publisher):
        self.calls.append((method, path))
        require(path == f"/repos/{REPOSITORY}" or path.startswith(f"/repos/{REPOSITORY}/"), "authenticated namespace")
        tail = path.removeprefix(f"/repos/{REPOSITORY}").lstrip("/")
        if "/issues/" in path:
            result = self.journal.request(method, path, body)
            if method == "POST" and publisher:
                result["user"] = {"id": self.publisher_identity.bot_user_id, "type": "Bot"}
                result["performed_via_github_app"] = {"id": self.publisher_identity.app_id}
            return result
        require(publisher, "Control attempted privileged API")
        if tail.startswith(("git/ref/heads/automation/requests", "git/refs/heads/automation/requests", "compare/", "contents/")):
            return self.journal.request(method, path, body)
        if method == "GET" and tail == "":
            return {"id": REPOSITORY_ID, "full_name": REPOSITORY, "default_branch": "master"}
        if method == "GET" and tail == "actions/workflows/30001":
            return {"id": 30001, "path": ".github/workflows/workspace-ledger-pilot.yml", "state": "active"}
        if method == "GET" and tail == "git/ref/heads/master":
            return {"ref": "refs/heads/master", "object": {"type": "commit", "sha": WORKFLOW_REVISION}}
        if method == "GET" and tail == f"actions/runs/{self.run_id}/attempts/1":
            repository = {"id": REPOSITORY_ID, "full_name": REPOSITORY}
            return {"id": self.run_id, "run_attempt": 1, "workflow_id": 30001,
                "path": ".github/workflows/workspace-ledger-pilot.yml", "event": "issues",
                "head_sha": WORKFLOW_REVISION, "head_branch": "master",
                "actor": {"id": 2001}, "repository": repository, "head_repository": repository}
        if method == "GET" and tail == f"actions/runs/{self.run_id}/attempts/1/jobs?per_page=100&page=1":
            return {"total_count": 1, "jobs": [{"id": self.run_id * 100, "run_id": self.run_id,
                "run_attempt": 1, "name": "control", "head_sha": WORKFLOW_REVISION,
                "status": "completed", "conclusion": "success", "started_at": "2026-10-11T02:00:10Z",
                "completed_at": "2026-10-11T02:01:00Z"}]}
        if method == "GET" and tail == f"actions/runs/{self.run_id}/artifacts?per_page=100&page=1":
            return {"total_count": 1, "artifacts": [self.artifact]}
        if method == "GET" and tail == f"actions/artifacts/{self.run_id * 10 + 1}":
            return self.artifact
        if method == "GET" and tail == f"git/ref/heads/{BRANCH}":
            if self.fail_next_task_read:
                self.fail_next_task_read = False
                raise self.fixtures.ApiError(500, "synthetic_interrupted_readback")
            return {"ref": f"refs/heads/{BRANCH}", "object": {"type": "commit", "sha": self.branch_head}}
        if method == "PATCH" and tail == f"git/refs/heads/{BRANCH}":
            require(body["force"] is False and self.task_patches == 0, "duplicate/forced task ref effect")
            publication = self.pending_publication()
            require(publication is not None and publication["commit_sha"] == body["sha"], "no authenticated intent before effect")
            self.task_patches += 1
            self.branch_head = body["sha"]  # Only this in-memory ref changes.
            self.fail_next_task_read = self.interrupt_readback
            if self.patch_mode == "lost-response":
                raise self.fixtures.ApiError(500, "synthetic_lost_patch_response")
            return {"ref": f"refs/heads/{BRANCH}", "object": {"type": "commit", "sha": self.branch_head}}
        if method == "POST" and tail == "git/blobs":
            raw = base64.b64decode(body["content"], validate=True)
            sha = git(self.store, "hash-object", "-w", "--stdin", data=raw).decode().strip()
            if self.candidate_bytes is not None and sha in {
                change["blob_sha"] for change in json.loads(self.candidate_bytes)["candidate"]["changes"]
                if change["operation"] == "upsert"
            }:
                self.object_writes += 1
            # Journal and publication blobs have the same real Git identity.
            result = self.journal.request(method, path, body)
            require(result["sha"] == sha, "blob identity disagreement")
            return result
        if method == "POST" and tail == "git/trees":
            if body["base_tree"] in self.journal.trees:
                return self.journal.request(method, path, body)
            self.object_writes += 1
            git(self.store, "read-tree", body["base_tree"], index=self.index)
            for entry in body["tree"]:
                require(entry["mode"] == "100644" and entry["type"] == "blob", "tree mode")
                if entry["sha"] is None:
                    git(self.store, "update-index", "--force-remove", "--", entry["path"], index=self.index)
                else:
                    git(self.store, "update-index", "--add", "--cacheinfo",
                        f"100644,{entry['sha']},{entry['path']}", index=self.index)
            return {"sha": git(self.store, "write-tree", index=self.index).decode().strip()}
        if method == "POST" and tail == "git/commits":
            if body["tree"] in self.journal.trees:
                return self.journal.request(method, path, body)
            self.object_writes += 1
            require(len(body["parents"]) == 1, "publication must have one parent")
            sha = git(self.store, "commit-tree", body["tree"], "-p", body["parents"][0],
                      data=(body["message"] + "\n").encode()).decode().strip()
            return {"sha": sha}
        if method == "GET" and tail.startswith("git/commits/"):
            sha = tail.rsplit("/", 1)[1]
            if sha in self.journal.commits:
                return self.journal.request(method, path, body)
            headers = git(self.store, "cat-file", "commit", sha).decode().split("\n\n", 1)[0].splitlines()
            return {"sha": sha, "tree": {"sha": next(line[5:] for line in headers if line.startswith("tree "))},
                    "parents": [{"sha": line[7:]} for line in headers if line.startswith("parent ")]}
        if method == "GET" and tail.startswith("git/trees/"):
            sha = tail.rsplit("/", 1)[1]
            if sha in self.journal.trees:
                return self.journal.request(method, path, body)
            entries = []
            for raw in git(self.store, "ls-tree", "-z", sha).split(b"\0"):
                if raw:
                    header, name = raw.decode().split("\t", 1)
                    mode, kind, oid = header.split()
                    entries.append({"path": name, "mode": mode, "type": kind, "sha": oid})
            return {"sha": sha, "tree": entries, "truncated": False}
        if method == "GET" and tail.startswith("git/blobs/"):
            sha = tail.rsplit("/", 1)[1]
            raw = git(self.store, "cat-file", "blob", sha)
            return {"sha": sha, "encoding": "base64", "size": len(raw), "content": base64.b64encode(raw).decode()}
        raise AssertionError("unexpected synthetic API route")

    def pending_publication(self):
        for comment in self.journal.comments.values():
            if "publisher-publication:v1:" in comment["body"]:
                require(comment["user"]["id"] == self.publisher_identity.bot_user_id
                        and comment["performed_via_github_app"]["id"] == self.publisher_identity.app_id,
                        "intent identity")
                return json.loads(comment["body"].split("```json\n", 1)[1].split("\n```", 1)[0])["publication"]
        return None


def run(args):
    root = Path(args.zach_root)
    mirror = Path(args.governance_mirror)
    require(root.is_absolute() and root.is_dir() and mirror.is_absolute() and mirror.is_dir(), "absolute local directories required")
    sys.path.insert(0, str(root / "scripts"))
    from actions_journal_coordinator import ActionsJournalCoordinator, TrustedIssuePolicy
    from actions_request_handler import PublisherPhase, ControlPhase, TrustedReceiptPolicy, ActionsHandlerError
    from actions_ledger_runtime import LedgerCandidateRuntime, LedgerPublisherRuntime
    from actions_ledger_producer import LedgerProducerPolicy
    from actions_ledger_publication import LedgerPublicationPolicy
    journal_cli = root / "target/debug/zach-actions"
    candidate_cli = root / "target/debug/zach-ledger-candidate"
    require(all(path.is_file() and os.access(path, os.X_OK) for path in (journal_cli, candidate_cli)), "build Zach binaries before verification")
    spec = importlib.util.spec_from_file_location("synthetic_handler_fixtures", root / "scripts/test-actions-request-handler.py")
    fixtures = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(fixtures)
    fixtures.TRUSTED_POLICY = TrustedIssuePolicy(REPOSITORY_ID, REPOSITORY, (2001,))
    control_identity = fixtures.TRUSTED_RECEIPT_POLICY
    publisher_identity = TrustedReceiptPolicy(app_id=9877, bot_user_id=54322)
    checks = []
    with tempfile.TemporaryDirectory(prefix="zach-ledger-composition-") as directory:
        work = Path(directory)
        store = work / "objects.git"
        git(work, "clone", "--quiet", "--mirror", "--no-hardlinks", str(mirror), str(store))
        require(git(store, "cat-file", "-t", BASE).strip() == b"commit", "pinned Governance object missing")
        source_refs = git(mirror, "show-ref")
        producer_policy = LedgerProducerPolicy(30001, WORKFLOW_REVISION, TOOL_REVISION)
        publication_policy = LedgerPublicationPolicy("GOV-041", "tasks/GOV-041-workspace-command-fast-path.md", BRANCH)

        def scenario(label, number, base=BASE, *, operation="run.record_evidence", arguments=None, ready=True):
            case = work / label
            case.mkdir()
            api = SyntheticApi(fixtures, store, case / "index", number, base, publisher_identity)
            clock = ["2026-10-11T02:10:00Z"]
            candidate_runtime = LedgerCandidateRuntime(str(candidate_cli), str(store), str(case / "candidate.json"))
            publisher_runtime = LedgerPublisherRuntime(api, producer_policy, publication_policy,
                str(candidate_cli), str(store), clock=lambda: clock[0])
            counts = {"candidate": 0, "publisher": 0}
            def candidate(bundle):
                counts["candidate"] += 1
                handoff = candidate_runtime(bundle)
                api.install_artifact(case / "candidate.json")
                return handoff
            def publish(publisher, bundle, handoff):
                counts["publisher"] += 1
                return publisher_runtime(publisher, bundle, handoff)
            coordinator = ActionsJournalCoordinator(str(journal_cli), api)
            publisher = PublisherPhase(coordinator, fixtures.TRUSTED_POLICY, control_identity, api,
                publisher_identity, ledger_publisher=publish)
            control = ControlPhase(api.control, control_identity, ledger_candidate=candidate)
            parameters = {"base_sha": base, "operation": operation, "parameters": arguments if arguments is not None else {
                "run_id": RUN_ID, "evidence_id": "actions-ledger-composition-synthetic",
                "kind": "validation", "summary": "Synthetic local composition verification; no online or production effect.",
                "reference": None}}
            event = fixtures.make_event(request_id=f"local-ledger-{label}-01", operation="governance.ledger",
                parameters=parameters, repo_id=REPOSITORY_ID, repo_full_name=REPOSITORY)
            bundle = publisher.prepare(event, f"{number}-1", ACCEPTED_AT, WORKFLOW_REVISION).bundle
            require(bundle is not None, "real journal claim missing")
            handoff = control.execute(bundle)
            require(handoff.terminal_state == ("candidate_ready" if ready else "rejected"), "real candidate derivation unexpected state")
            require(coordinator.load_record(bundle.request_id)[1]["state"] == "executing", "candidate terminalized before publication")
            return api, clock, counts, coordinator, publisher, control, bundle, handoff, parameters

        api, clock, counts, journal, publisher, control, bundle, handoff, parameters = scenario("success", 101)
        receipt = publisher.finalize(bundle)
        require(receipt.terminal_code == "ledger_published" and journal.load_record(bundle.request_id)[1]["state"] == "succeeded", "publication did not terminalize")
        published_commit = api.branch_head
        derived = json.loads(api.candidate_bytes)["candidate"]
        published_tree = git(store, "rev-parse", published_commit + "^{tree}").decode().strip()
        require(published_tree == derived["validated_tree_sha"] == receipt.envelope["publication"]["tree_sha"],
                "independent Git tree does not match candidate and publication")
        evidence_verified = False
        for change in derived["changes"]:
            require(change["operation"] == "upsert", "unexpected evidence change operation")
            actual = git(store, "show", published_commit + ":" + change["path"])
            require(actual == change["content"].encode("utf-8"), "published path bytes differ from candidate")
            require(git(store, "rev-parse", published_commit + ":" + change["path"]).decode().strip() == change["blob_sha"],
                    "published blob differs from candidate")
            evidence_verified |= ("id: " + RUN_ID in actual.decode()
                                  and "`actions-ledger-composition-synthetic`" in actual.decode())
        require(evidence_verified, "synthetic evidence was not added to the exact canonical run")
        require(api.task_patches == 1 and counts == {"candidate": 1, "publisher": 1}, "unexpected effect count")
        require(control.execute(bundle).replayed and publisher.finalize(bundle).replayed, "phase replay missing")
        require(api.task_patches == 1 and counts == {"candidate": 1, "publisher": 1}, "replay repeated an effect")
        changed = dict(parameters, base_sha="f" * 40)
        conflict = fixtures.make_event(request_id=bundle.request_id, operation="governance.ledger", parameters=changed,
                                      repo_id=REPOSITORY_ID, repo_full_name=REPOSITORY)
        try:
            publisher.prepare(conflict, "101-1", ACCEPTED_AT, WORKFLOW_REVISION)
            raise AssertionError("conflicting request accepted")
        except ActionsHandlerError:
            pass
        clock[0] = "2026-10-11T03:10:00Z"
        before = (api.object_writes, api.task_patches, api.downloads)
        result = publisher._ledger_publisher(publisher, bundle, handoff.envelope["result"])
        require(result["replayed"] and before == (api.object_writes, api.task_patches, api.downloads), "expired intent recovery wrote/fetched a new effect")
        checks.extend(("real-candidate-publication-and-terminalization", "idempotent-phase-replay", "conflicting-request", "expired-record-read-only-recovery"))

        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario("noop", 102, published_commit)
        require(publisher.finalize(bundle).terminal_code == "ledger_no_change", "real existing-evidence no-op failed")
        require(api.task_patches == 0 and api.object_writes == 0, "no-op wrote Git effect")
        checks.append("real-idempotent-evidence-no-op")

        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario("stale", 103)
        api.branch_head = git(store, "rev-parse", BASE + "^").decode().strip()
        try:
            publisher.finalize(bundle)
            raise AssertionError("stale ref accepted")
        except ActionsHandlerError as error:
            require(error.code == "ledger_ref_conflict", "unexpected stale-ref failure")
        require(api.task_patches == 0 and api.object_writes == 0 and api.pending_publication() is None, "stale ref produced new intent/effect")
        checks.append("stale-ref-before-effect")

        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario("lost", 104)
        api.patch_mode = "lost-response"
        require(publisher.finalize(bundle).terminal_code == "ledger_published" and api.task_patches == 1, "lost PATCH response did not reconcile exact effect")
        checks.append("lost-patch-response-exact-readback")

        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario("interrupted", 105)
        api.interrupt_readback = True
        try:
            publisher.finalize(bundle)
            raise AssertionError("interrupted readback terminalized")
        except ActionsHandlerError:
            pass
        require(journal.load_record(bundle.request_id)[1]["state"] == "ambiguous" and api.task_patches == 1, "interruption lost intent/ambiguity")
        clock[0] = "2026-10-11T03:10:00Z"
        api.artifact["expired"] = True
        before = (api.object_writes, api.task_patches, api.downloads)
        receipt = publisher.reconcile_request(bundle.request_id)
        require(receipt.terminal_state == "succeeded" and receipt.reconciled and receipt.replayed,
                "recorded effect recovery failed")
        require(before == (api.object_writes, api.task_patches, api.downloads) and counts["candidate"] == 1,
                "interrupted/expired recovery repeated candidate or effect")
        checks.append("interrupted-publication-expired-read-only-effect-recovery")

        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario("expired", 106)
        clock[0] = "2026-10-11T03:10:00Z"
        try:
            publisher.finalize(bundle)
            raise AssertionError("expired candidate published")
        except ActionsHandlerError as error:
            require(error.code == "ledger_request_expired", "unexpected expiry failure")
        require(api.task_patches == 0 and api.object_writes == 0 and api.pending_publication() is None, "expired candidate created intent/effect")
        checks.append("expired-new-effect-rejected")

        # These are real candidate/lifecycle decisions on synthetic local data,
        # not a new online admission profile or a claim about connector reads.
        failed_args = {"run_id": RUN_ID, "target_status": "failed"}
        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "run-failed", 107, operation="run.transition_status", arguments=failed_args)
        require(publisher.finalize(bundle).terminal_code == "ledger_published", "run transition did not publish")
        failed_commit = api.branch_head
        raw = git(store, "show", failed_commit + ":runs/GOV-041/20260905-030554-actions-ledger-lifecycle.md")
        require(b"status: failed\n" in raw and api.task_patches == 1, "run failed state missing")
        require(publisher.finalize(bundle).replayed and api.task_patches == 1, "run transition replay duplicated effect")
        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "run-failed-noop", 108, failed_commit, operation="run.transition_status", arguments=failed_args)
        require(publisher.finalize(bundle).terminal_code == "ledger_no_change" and api.task_patches == 0,
                "same terminal run transition was not no-op")
        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "run-conflict", 109, failed_commit, operation="run.transition_status",
            arguments={"run_id": RUN_ID, "target_status": "cancelled"}, ready=False)
        require(publisher.finalize(bundle).terminal_state == "rejected" and api.task_patches == 0,
                "conflicting terminal transition produced effect")
        checks.extend(("real-run-terminal-transition-and-replay", "real-run-terminal-no-op", "real-run-terminal-conflict-rejected"))

        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "task-blocked", 110, operation="task.transition_status",
            arguments={"task_id": "GOV-041", "target_status": "blocked"})
        require(publisher.finalize(bundle).terminal_code == "ledger_published" and api.task_patches == 1,
                "noncompletion task transition failed")
        raw = git(store, "show", api.branch_head + ":tasks/GOV-041-workspace-command-fast-path.md")
        require(b"status: blocked\n" in raw and publisher.finalize(bundle).replayed,
                "blocked task state or replay missing")
        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "task-closure", 111, operation="task.transition_status",
            arguments={"task_id": "GOV-041", "target_status": "completed"}, ready=False)
        require(publisher.finalize(bundle).terminal_state == "rejected" and api.task_patches == 0,
                "unverified task closure produced effect")
        checks.extend(("real-task-noncompletion-transition", "real-task-completion-rejected"))

        # Build a valid active remote-run fixture in disposable Git objects only.
        # This deliberately has no publication/terminal evidence. The synthetic
        # startup declarations confer no real remote or agent-read authority.
        remote_id = "GOV-041-20261011-020000-synthetic-startup"
        remote_path = "runs/GOV-041/20261011-020000-synthetic-startup.md"
        startup = {"schema_version": 2, "run_id": remote_id, "execution_profile": "github-connector",
            "stage": "startup", "repository": {"name": "governance", "default_branch": "master", "base_sha": BASE},
            "branch": {"name": BRANCH, "starting_sha": BASE},
            "reads": ["AGENTS.md", "STACK.md", "contracts/governance-lifecycle.yaml",
                ".agents/skills/governance-task/SKILL.md", ".agents/skills/governance-run/SKILL.md",
                "tasks/GOV-041-workspace-command-fast-path.md"],
            "capabilities": {"available": ["github_repository_read", "github_git_write", "github_nonforced_ref_update",
                "github_pull_request", "github_actions_via_operations"],
                "unavailable": ["clone", "shell", "worktree", "hooks", "local_tests"]},
            "reuse": {"branch": True, "run": False, "pull_request": False}}
        remote = (f"---\nkind: run\nschema_version: 1\nid: {remote_id}\ntask: GOV-041\nstatus: active\n"
            f"status_history: [active]\nstarted: {ACCEPTED_AT}\nrun_type: execution\nexecution_profile: github-connector\n"
            f"preflight: remote\nrepository: governance\nbranch: {BRANCH}\nworktree: none\n"
            "provenance: {operator: shockerqt, actor: chatgpt, environment: web}\n---\n\n"
            "# Synthetic local fixture only\n\n## Remote preflight\n\n```yaml\n" + json.dumps(startup) + "\n```\n").encode()
        fixture_index = work / "remote-fixture-index"
        git(store, "read-tree", BASE, index=fixture_index)
        blob = git(store, "hash-object", "-w", "--stdin", data=remote).decode().strip()
        git(store, "update-index", "--add", "--cacheinfo", f"100644,{blob},{remote_path}", index=fixture_index)
        fixture_tree = git(store, "write-tree", index=fixture_index).decode().strip()
        fixture_base = git(store, "commit-tree", fixture_tree, "-p", BASE, data=b"Synthetic remote startup fixture\n").decode().strip()
        link_args = {"task_id": "GOV-041", "run_id": remote_id}
        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "append-run", 112, fixture_base, operation="task.append_run", arguments=link_args)
        require(publisher.finalize(bundle).terminal_code == "ledger_published" and api.task_patches == 1,
                "run linking did not publish")
        linked_commit = api.branch_head
        require(("../" + remote_path).encode() in git(store, "show", linked_commit + ":tasks/GOV-041-workspace-command-fast-path.md"),
                "exact run link absent")
        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "append-run-noop", 113, linked_commit, operation="task.append_run", arguments=link_args)
        require(publisher.finalize(bundle).terminal_code == "ledger_no_change" and api.task_patches == 0,
                "run link replay was not no-op")
        api, clock, counts, journal, publisher, control, bundle, handoff, _ = scenario(
            "remote-terminal-missing", 114, linked_commit, operation="run.transition_status",
            arguments={"run_id": remote_id, "target_status": "completed"}, ready=False)
        require(publisher.finalize(bundle).terminal_state == "rejected" and api.task_patches == 0,
                "remote completion without terminal evidence produced effect")
        checks.extend(("real-task-run-link", "real-task-run-link-no-op", "real-missing-remote-terminal-evidence-rejected"))
        require(git(mirror, "show-ref") == source_refs, "source mirror refs changed")
    return {"kind": "synthetic-local-ledger-composition-verification", "checks": checks,
            "real_rust_and_git_objects": True, "remote_metadata": "synthetic", "online_proof": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--governance-mirror", required=True)
    parser.add_argument("--zach-root", default=str(Path(__file__).resolve().parents[1]))
    args = parser.parse_args()
    try:
        print(json.dumps(run(args), sort_keys=True))
    except Exception as error:
        # Never dump journal/candidate data, stderr, paths or raw remote payloads.
        code = getattr(error, "code", type(error).__name__)
        if type(code) is not str or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{0,127}", code):
            code = "verification_failed"
        print("local-composition-verification-failed: " + code, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
