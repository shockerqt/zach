"""Synthetic source tests; receipt authentication and Rust semantics are seams.

ExecutionBundle and frozen context validation, ZIP reads and digests are real.
No network or journal/Git publication is performed and no online proof is claimed.
"""
import copy
import hashlib
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch
import zipfile

import actions_ledger_evidence as module
import actions_ledger_startup as startup
from actions_request_handler import ActionsHandlerError, ExecutionBundle, _validate_execution_bundle


BASE, COMMIT, TREE, POLICY = (character * 40 for character in "abcd")
BRANCH = "task/GOV-041-workspace-command-fast-path"
TASK = "tasks/GOV-041-workspace-command-fast-path.md"
RUN = "GOV-041-20261020-020000-evidence-start"


def bundle(request_id, parameters, execution_id="123-1", accepted_at="2026-10-20T02:00:00Z"):
    request = {"request_id": request_id, "schema_version": 1, "operation": "governance.ledger", "parameters": parameters}
    canonical = json.dumps(request, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode()).hexdigest()
    record = {"request_id": request_id, "request_digest": digest, "operation": "governance.ledger",
        "repository_id": module.REPOSITORY_ID, "repository_full_name": module.REPOSITORY,
        "issue_id": 400, "issue_number": 42, "execution_id": execution_id, "state": "executing",
        "accepted_at": accepted_at, "policy_revision": POLICY, "sender_id": 2001,
        "author_id": 2001, "canonical_request": canonical}
    result = ExecutionBundle(request_id, digest, "governance.ledger", module.REPOSITORY_ID, module.REPOSITORY,
        400, 42, execution_id, json.dumps(record), "1" * 40, "2" * 40, parameters)
    _validate_execution_bundle(result)
    return result


class Api:
    def __init__(self, archive):
        self.archive, self.calls = archive, []
        self.rows = []
        self.detail = None

    def download_artifact(self, repository, identifier):
        assert (repository, identifier) == (module.REPOSITORY, 201)
        self.calls.append(("download", identifier))
        return self.archive

    def __call__(self, method, path, body=None):
        assert method == "GET" and body is None
        self.calls.append((method, path))
        if path == f"/repos/{module.REPOSITORY}/git/commits/{COMMIT}":
            return {"sha": COMMIT, "tree": {"sha": TREE}, "parents": [{"sha": BASE}], "message": "chore(ledger): apply original-startup"}
        if "/pulls?state=all&head=" in path:
            assert "shockerqt%3Atask%2FGOV-041-workspace-command-fast-path" in path
            page = int(path.rsplit("=", 1)[1])
            return self.rows if page == 1 else []
        if path == f"/repos/{module.REPOSITORY}/pulls/55":
            return self.detail
        raise AssertionError(path)


class Tests(unittest.TestCase):
    def setUp(self):
        declaration = {"schema_version": 1,
            "reads": [{"path": path, "commit_sha": BASE, "blob_sha": "e" * 40} for path in sorted(startup.REQUIRED_READS | {TASK})],
            "capabilities": {"available": sorted(startup.CORE | {"github_actions_via_operations"}), "unavailable": sorted(startup.LOCAL)}}
        self.original = bundle("original-startup", {"base_sha": BASE, "operation": "task.start_run",
            "parameters": {"task_id": "GOV-041", "slug": "evidence-start"}, "agent_declaration": declaration})
        binding = {"kind": "actions.startup.context", "schema_version": 1,
            "request_id": self.original.request_id, "outer_request_digest": self.original.request_digest,
            "accepted_revision": self.original.accepted_revision, "claim_revision": self.original.claim_revision,
            "policy_revision": POLICY, "actor_id": 2001, "governance_sha": BASE,
            "task_path": TASK, "task_blob_sha": "e" * 40, "declaration": declaration,
            "repository": {"alias": "governance", "id": module.REPOSITORY_ID, "full_name": module.REPOSITORY, "default_branch": "master", "base_sha": BASE},
            "branch": {"name": BRANCH, "starting_sha": BASE},
            "run": {"id": RUN, "path": "runs/GOV-041/20261020-020000-evidence-start.md", "exists": False}, "open_pull_requests": []}
        self.startup = {"remote_preflight": startup._normalized(binding, declaration)}
        startup.validate_startup_context(self.startup, self.original)
        self.raw = json.dumps({"trusted_context": self.startup}).encode()
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive: archive.writestr("candidate.json", self.raw)
        self.api = Api(buffer.getvalue())
        self.publication = {"repository_id": module.REPOSITORY_ID, "repository_full_name": module.REPOSITORY,
            "branch": BRANCH, "base_sha": BASE, "tree_sha": TREE, "commit_sha": COMMIT,
            "artifact_reference": {"repository_id": module.REPOSITORY_ID, "repository_full_name": module.REPOSITORY,
                "run_id": 123, "run_attempt": 1, "artifact_id": 201,
                "archive_sha256": hashlib.sha256(self.api.archive).hexdigest(), "content_sha256": hashlib.sha256(self.raw).hexdigest()}}
        self.current = bundle("evidence-current", {"base_sha": COMMIT, "operation": "run.record_remote_evidence",
            "parameters": {"run_id": RUN, "stage": "publication"},
            "publication_source": {"issue_number": 42, "execution_id": "123-1", "request_id": "original-startup"}}, "124-1", "2026-10-20T02:30:00Z")
        self.receipt = SimpleNamespace(bundle=self.original, publication=self.publication, comment_id=301, terminal_journal_sha="f" * 40)
        self.ci_policy = module.CiInspectionPolicy("governance", module.REPOSITORY, module.REPOSITORY_ID, 71, ".github/workflows/ci.yml")

    def collect(self, **seams):
        # Real ZIP/digest/startup validation; loader/producer/semantic derivation
        # are intentionally injected fixtures and confer no source authority.
        with patch.object(module, "load_durable_published_receipt", return_value=self.receipt, **seams.get("loader", {})) as loader, \
             patch.object(module, "observe_ledger_producer", return_value={"stable": True}, **seams.get("observer", {})) as observer, \
             patch.object(module, "derive_bound_candidate", return_value=b"synthetic independent", **seams.get("derive", {})) as derive, \
             patch.object(module, "validate_bound_candidate", return_value={}) as validate:
            self.loader, self.observer, self.derive, self.validate = loader, observer, derive, validate
            return module.collect_evidence_context(self.api, self.current, object(), object(), self.ci_policy, "/trusted/cli", "/trusted/mirror")

    def test_publication_real_zip_digest_and_pure_reconstruction(self):
        context = self.collect()
        value = context["remote_evidence"]
        self.assertEqual(value["run_id"], RUN)
        self.assertEqual(value["stage"], "publication")
        self.assertEqual(value["publication"]["readback_ref_sha"], COMMIT)
        self.assertEqual(value["publication"]["validated_tree_sha"], TREE)
        self.assertEqual(value["publication"]["logical_commit_count"], 1)
        self.assertFalse(value["publication"]["forced"])
        self.assertNotIn("terminal", value)
        self.assertEqual(value["source_binding"]["published_comment_id"], 301)
        self.derive.assert_called_once_with(self.original, "/trusted/cli", "/trusted/mirror", self.startup)
        self.validate.assert_called_once_with(self.raw, b"synthetic independent", self.original, self.startup)
        calls = list(self.api.calls)
        self.assertEqual(module.validate_evidence_context(context, self.current), context)
        self.assertEqual(self.api.calls, calls)

    def test_missing_intent_or_unverified_journal_source_fails_before_producer(self):
        # These loader errors stand for separately tested authenticated source
        # rejection, not a replacement implementation of the journal loader.
        for code in ("publisher_published_receipt_missing", "publisher_intent_not_effect", "publisher_journal_mismatch"):
            self.api.calls.clear()
            with self.subTest(code=code), self.assertRaises(module.EvidenceContextError):
                self.collect(loader={"side_effect": ActionsHandlerError(code)})
            self.observer.assert_not_called()
            self.derive.assert_not_called()
            self.assertEqual(self.api.calls, [])

    def test_original_producer_failure_precedes_download_or_parse(self):
        with patch.object(module, "_json") as parse, self.assertRaises(module.EvidenceContextError):
            self.collect(observer={"side_effect": RuntimeError("untrusted source")})
        parse.assert_not_called()
        self.derive.assert_not_called()
        self.assertEqual(self.api.calls, [])

    def test_absent_loader_result_and_semantic_rejection_cannot_become_evidence(self):
        self.receipt = None
        with self.assertRaises(module.EvidenceContextError): self.collect()
        self.observer.assert_not_called()
        self.assertEqual(self.api.calls, [])
        self.setUp()
        with self.assertRaises(module.EvidenceContextError):
            self.collect(derive={"side_effect": RuntimeError("candidate rejected")})
        self.validate.assert_not_called()
        self.assertEqual(self.api.calls, [("download", 201)])

    def test_archive_and_content_digests_cannot_be_substituted(self):
        original = self.api.archive
        self.api.archive = b"invalid archive"
        with self.assertRaises(module.EvidenceContextError): self.collect()
        self.derive.assert_not_called()
        self.api.archive = original
        self.publication["artifact_reference"]["content_sha256"] = "0" * 64
        with patch.object(module, "_json") as parse, self.assertRaises(module.EvidenceContextError): self.collect()
        parse.assert_not_called()
        self.derive.assert_not_called()

    def test_source_locators_frozen_digest_and_unknown_fields_reject(self):
        context = self.collect()
        for key, value in (("outer_request_digest", "9" * 64), ("claim_revision", "9" * 40),
                           ("request_id", "another-request"), ("extra", True)):
            changed = copy.deepcopy(context)
            changed["remote_evidence"]["source_binding"][key] = value
            with self.subTest(key=key), self.assertRaises(module.EvidenceContextError): module.validate_evidence_context(changed, self.current)
        for key, value in (("issue_number", 99), ("execution_id", "999-1"), ("request_id", "different-original")):
            params = copy.deepcopy(self.current.parameters)
            params["publication_source"][key] = value
            other = bundle("evidence-current", params, "124-1", "2026-10-20T02:30:00Z")
            with self.subTest(locator=key), self.assertRaises(module.EvidenceContextError): module.validate_evidence_context(context, other)
        params = copy.deepcopy(self.current.parameters)
        params["publication_source"]["success"] = True
        with self.assertRaises(module.EvidenceContextError): module._request(bundle("evidence-current", params, "124-1"))
        changed = copy.deepcopy(context)
        changed["remote_evidence"]["success"] = True
        with self.assertRaises(module.EvidenceContextError): module.validate_evidence_context(changed, self.current)

    def test_only_same_new_governance_run_is_owned(self):
        context = self.collect()
        changed = copy.deepcopy(context)
        source = changed["remote_evidence"]["source_binding"]["startup_context"]["remote_preflight"]
        source["source_binding"]["run"]["exists"] = True
        source["reuse"]["run"] = True
        with self.assertRaises(module.EvidenceContextError): module.validate_evidence_context(changed, self.current)
        changed = copy.deepcopy(context)
        preflight = changed["remote_evidence"]["source_binding"]["startup_context"]["remote_preflight"]
        preflight["source_binding"]["repository"].update(alias="zach", id=1342354297, full_name="shockerqt/zach", default_branch="main")
        preflight["repository"].update(name="zach", default_branch="main")
        with self.assertRaises(module.EvidenceContextError): module.validate_evidence_context(changed, self.current)
        params = copy.deepcopy(self.current.parameters)
        params["parameters"]["run_id"] = RUN.replace("evidence-start", "unrelated-run")
        other = bundle("evidence-current", params, "124-1")
        changed = copy.deepcopy(context)
        changed["remote_evidence"]["source_binding"].update(outer_request_digest=other.request_digest, run_id=params["parameters"]["run_id"])
        with self.assertRaises(module.EvidenceContextError): module.validate_evidence_context(changed, other)
        params["parameters"]["run_id"] = RUN.replace("GOV-041", "ZACH-003")
        with self.assertRaises(module.EvidenceContextError): module._request(bundle("evidence-current", params, "124-1"))

    def terminal(self):
        params = copy.deepcopy(self.current.parameters)
        params["parameters"]["stage"] = "terminal"
        self.current = bundle("evidence-current", params, "124-1", "2026-10-20T02:30:00Z")
        repo = {"id": module.REPOSITORY_ID, "full_name": module.REPOSITORY}
        pr = {"id": 501, "number": 55, "state": "closed", "html_url": f"https://github.com/{module.REPOSITORY}/pull/55",
            "head": {"ref": BRANCH, "sha": COMMIT, "repo": repo}, "base": {"ref": "master", "repo": dict(repo)}}
        self.api.rows, self.api.detail = [pr], copy.deepcopy(pr)
        return {"result": "found", "selected_run": {"id": 601, "attempt": 1, "status": "completed", "conclusion": "success", "html_url": f"https://github.com/{module.REPOSITORY}/actions/runs/601"}}

    def test_terminal_exact_ci_and_closed_original_pr_reconstruction(self):
        observed = self.terminal()
        with patch.object(module, "inspect_ci", return_value=observed) as inspect:
            context = self.collect()
        inspect.assert_called_once_with({"repository": "governance", "source_sha": COMMIT}, self.ci_policy, self.api)
        value = context["remote_evidence"]
        self.assertEqual(value["terminal"]["implementation_sha"], COMMIT)
        self.assertEqual(value["terminal"]["ci_sha"], COMMIT)
        self.assertEqual(value["source_binding"]["pull_request"]["state"], "closed")
        self.assertEqual(module.validate_evidence_context(context, self.current), context)
        for field, key, wrong in (("ci", "sha", BASE), ("ci", "conclusion", "failure"),
                                   ("ci", "workflow_path", ".github/workflows/wrong.yml"),
                                   ("pull_request", "head_sha", BASE), ("pull_request", "base_branch", "main"),
                                   ("pull_request", "repository_id", 1342354297)):
            changed = copy.deepcopy(context)
            changed["remote_evidence"]["source_binding"][field][key] = wrong
            with self.subTest(field=field, key=key), self.assertRaises(module.EvidenceContextError): module.validate_evidence_context(changed, self.current)

    def test_original_pr_missing_ambiguous_or_changed_detail_rejects(self):
        self.terminal()
        valid = copy.deepcopy(self.api.rows[0])
        for fault in ("missing", "ambiguous", "detail", "wrong_sha"):
            self.api.rows, self.api.detail = [copy.deepcopy(valid)], copy.deepcopy(valid)
            if fault == "missing": self.api.rows = []
            if fault == "ambiguous": self.api.rows.append(dict(copy.deepcopy(valid), id=502, number=56))
            if fault == "detail": self.api.detail["head"]["sha"] = BASE
            if fault == "wrong_sha": self.api.rows[0]["head"]["sha"] = BASE
            with self.subTest(fault=fault), self.assertRaises(module.EvidenceContextError): module._source_pr(self.api, self.publication)


if __name__ == "__main__":
    unittest.main()
