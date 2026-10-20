"""Synthetic read-only source observations, not online or authentication proof.

The bundle-validation seam is patched explicitly. Real journal and pinned
mutator composition are independently verified by the coordinator.
"""
import base64
import copy
import hashlib
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import actions_ledger_startup as module


BASE, BLOB, DEFAULT, START = (character * 40 for character in "abcd")
TASK = "tasks/ZACH-003-run-typed-operations-in-actions.md"
BRANCH = "task/ZACH-003-run-typed-operations-in-actions"
HEADER = ("---\nkind: task\nschema_version: 1\nid: ZACH-003\nstatus: active\n"
          f"target_repository: zach\nbranch: {BRANCH}\n---\n# Task\n")


def blob_sha(raw):
    return hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()


class Api:
    def __init__(self):
        self.header = HEADER
        self.entries = [{"path": path, "mode": "100644", "type": "blob", "sha": BLOB}
                        for path in sorted(module.REQUIRED_READS)]
        self.task = {"path": TASK, "mode": "100644", "type": "blob", "sha": blob_sha(HEADER.encode())}
        self.entries.append(self.task)
        self.calls = []
        self.metadata = {"id": 1342354297, "full_name": "shockerqt/zach", "default_branch": "main"}
        self.pages = [[]]
        self.ref_fault = None
        self.truncated = False

    def __call__(self, method, path, body=None):
        assert method == "GET" and body is None
        self.calls.append(path)
        if path == f"/repos/{module.GOVERNANCE}/git/trees/{BASE}?recursive=1":
            return {"sha": "e" * 40, "truncated": self.truncated, "tree": self.entries}
        if path == f"/repos/{module.GOVERNANCE}/git/blobs/{self.task['sha']}":
            raw = self.header.encode()
            return {"sha": self.task["sha"], "encoding": "base64", "size": len(raw), "content": base64.b64encode(raw).decode()}
        if path == "/repos/shockerqt/zach":
            return self.metadata
        if path.startswith("/repos/shockerqt/zach/git/ref/heads/"):
            branch = path.split("/heads/", 1)[1]
            if self.ref_fault == "missing":
                return {"message": "Not Found"}
            return {"ref": "refs/heads/" + ("wrong" if self.ref_fault == "name" else branch),
                    "object": {"type": "tag" if self.ref_fault == "type" else "commit", "sha": DEFAULT if branch == "main" else START}}
        if path.startswith("/repos/shockerqt/zach/pulls?state=open&head=shockerqt%3Atask%2FZACH-003-run-typed-operations-in-actions&per_page=100&page="):
            return self.pages[int(path.rsplit("=", 1)[1]) - 1]
        raise AssertionError(path)

    def pr(self, identifier=10):
        repo = {"id": 1342354297, "full_name": "shockerqt/zach"}
        return {"id": identifier, "number": identifier, "state": "open", "head": {"ref": BRANCH, "sha": START, "repo": repo}, "base": {"repo": dict(repo)}}


class Tests(unittest.TestCase):
    def setUp(self):
        self.api = Api()
        self.declaration = {"schema_version": 1,
            "reads": [{"path": entry["path"], "commit_sha": BASE, "blob_sha": entry["sha"]} for entry in self.api.entries],
            "capabilities": {"available": sorted(module.CORE | {"github_actions_via_operations"}), "unavailable": sorted(module.LOCAL)}}
        self.bundle = SimpleNamespace(operation="governance.ledger", request_id="startup-001", request_digest="1" * 64,
            repository_full_name=module.GOVERNANCE, repository_id=1260920764,
            accepted_revision="2" * 40, claim_revision="3" * 40,
            parameters={"base_sha": BASE, "operation": "task.start_run", "parameters": {"task_id": "ZACH-003", "slug": "source-check"}, "agent_declaration": self.declaration})
        self.record = {"sender_id": 2001, "author_id": 9999, "policy_revision": "4" * 40, "accepted_at": "2026-10-20T00:48:00.123456789Z"}
        self.patcher = patch.object(module, "_validate_execution_bundle", return_value=self.record)
        self.validate_bundle = self.patcher.start()
        self.addCleanup(self.patcher.stop)

    def collect(self):
        return module.collect_startup_context(self.api, self.bundle)

    def test_exact_schema_frozen_sources_and_pure_revalidation(self):
        context = self.collect()
        value = context["remote_preflight"]
        binding = value["source_binding"]
        self.assertEqual(value["schema_version"], 2)
        self.assertEqual(value["repository"], {"name": "zach", "default_branch": "main", "base_sha": DEFAULT})
        self.assertEqual(value["branch"], {"name": BRANCH, "starting_sha": START})
        self.assertEqual(value["reuse"], {"branch": True, "run": False, "pull_request": False})
        self.assertEqual(value["run_id"], "ZACH-003-20261020-004800-source-check")
        self.assertEqual(binding["actor_id"], 2001)
        self.assertEqual(binding["declaration"], self.declaration)
        self.assertEqual(binding["governance_sha"], BASE)
        calls = list(self.api.calls)
        self.assertEqual(module.validate_startup_context(context, self.bundle), context)
        self.assertEqual(self.api.calls, calls)
        self.assertEqual(context["remote_preflight"]["reads"], [item["path"] for item in self.declaration["reads"]])

    def test_execution_run_create_and_existing_run_and_pr(self):
        self.bundle.parameters.update(operation="run.create")
        self.bundle.parameters["parameters"].update(run_type="execution", execution_profile="github-connector")
        self.api.entries.append({"path": "runs/ZACH-003/20261020-004800-source-check.md", "mode": "100644", "type": "blob", "sha": BLOB})
        self.api.pages = [[self.api.pr()]]
        context = self.collect()["remote_preflight"]
        self.assertEqual(context["reuse"], {"branch": True, "run": True, "pull_request": True})
        self.assertEqual(context["source_binding"]["open_pull_requests"], [{"id": 10, "number": 10, "head_sha": START}])

    def test_unsupported_operation_and_definition_fail_before_api(self):
        for operation in ("task.create", "run.record_remote_evidence", "task.complete", "run.record_evidence"):
            with self.subTest(operation=operation):
                self.bundle.parameters["operation"] = operation
                with self.assertRaises(module.StartupContextError): self.collect()
                self.assertEqual(self.api.calls, [])
        self.bundle.parameters["operation"] = "run.create"
        self.bundle.parameters["parameters"].update(run_type="definition", execution_profile=None)
        with self.assertRaises(module.StartupContextError): self.collect()

    def test_declaration_bounds_exact_keys_paths_and_capabilities(self):
        original = copy.deepcopy(self.declaration)
        mutations = [lambda d: d.update(extra=True), lambda d: d.update(schema_version=True),
            lambda d: d["reads"].append(copy.deepcopy(d["reads"][0])),
            lambda d: d["reads"][0].update(path="../AGENTS.md"),
            lambda d: d["reads"][0].update(commit_sha="0" * 40),
            lambda d: d["reads"][0].update(blob_sha="0" * 40),
            lambda d: d.update(reads=d["reads"][:-1]),
            lambda d: d["capabilities"]["available"].append("github_ref_compare_and_swap"),
            lambda d: d["capabilities"]["available"].append("shell"),
            lambda d: d["capabilities"]["available"].append("github_unknown"),
            lambda d: d["capabilities"]["available"].append(d["capabilities"]["available"][0]),
            lambda d: d["capabilities"].update(unavailable=[]),
            lambda d: d.update(reads=d["reads"] * 6)]
        for mutate in mutations:
            with self.subTest(mutation=mutations.index(mutate)):
                declaration = copy.deepcopy(original)
                mutate(declaration)
                self.bundle.parameters["agent_declaration"] = declaration
                with self.assertRaises(module.StartupContextError): self.collect()

    def test_tree_bounds_duplicate_task_and_regular_blob_requirements(self):
        original = copy.deepcopy(self.api.entries)
        for fault in ("truncated", "duplicate", "second-task", "symlink", "many", "unsafe"):
            with self.subTest(fault=fault):
                self.api.entries = copy.deepcopy(original)
                self.api.truncated = fault == "truncated"
                if fault == "duplicate": self.api.entries.append(copy.deepcopy(original[0]))
                if fault == "second-task": self.api.entries.append(dict(self.api.task, path="tasks/ZACH-003-other.md"))
                if fault == "symlink": self.api.entries[-1]["mode"] = "120000"
                if fault == "many": self.api.entries *= 1000
                if fault == "unsafe": self.api.entries[0]["path"] = "../outside"
                with self.assertRaises(module.StartupContextError): self.collect()

    def test_wrong_metadata_ids_names_and_defaults(self):
        for key, wrong in (("id", 12), ("id", True), ("full_name", "other/zach"), ("default_branch", "master")):
            with self.subTest(key=key, wrong=wrong):
                original = self.api.metadata[key]
                self.api.metadata[key] = wrong
                with self.assertRaises(module.StartupContextError): self.collect()
                self.api.metadata[key] = original

    def test_missing_wrong_or_noncommit_refs_fail_closed(self):
        for fault in ("missing", "name", "type"):
            with self.subTest(fault=fault):
                self.api.ref_fault = fault
                with self.assertRaises(module.StartupContextError): self.collect()

    def test_task_blob_content_must_match_immutable_identity(self):
        # Keep the declared/tree identity fixed while changing returned bytes.
        self.api.header = HEADER + "tampered\n"
        with self.assertRaises(module.StartupContextError): self.collect()

    def test_source_declaration_limit_and_agent_fields_cannot_route(self):
        self.bundle.parameters["repository"] = "other/repository"
        with self.assertRaises(module.StartupContextError): self.collect()
        self.assertEqual(self.api.calls, [])
        del self.bundle.parameters["repository"]
        self.declaration["reads"][0]["path"] = "x" * 17000
        with self.assertRaises(module.StartupContextError): self.collect()
        self.assertEqual(self.api.calls, [])

    def test_pagination_query_is_scoped_and_full_pages_cannot_hide_conflicts(self):
        # The endpoint is already exact-head scoped. A second matching record
        # makes uniqueness impossible without needing a replacement snapshot.
        self.api.pages = [[self.api.pr(identifier) for identifier in range(1, 101)]]
        with self.assertRaises(module.StartupContextError): self.collect()
        self.assertTrue(self.api.calls[-1].endswith("&per_page=100&page=1"))
        self.assertIn("head=shockerqt%3Atask%2FZACH-003-run-typed-operations-in-actions", self.api.calls[-1])

    def test_hashed_unsupported_yaml_and_namespace_fail_closed(self):
        for header in (HEADER.replace("target_repository: zach", "target_repository: balance"),
                       HEADER.replace("branch: task/ZACH-003", "branch: task/GOV-041"),
                       HEADER.replace("branch:", '"branch":'),
                       HEADER.replace("status: active", "status: active\nbranch: wrong"),
                       HEADER.replace("status: active", "status: active\n<<: {branch: wrong}"),
                       HEADER.replace("target_repository: zach", "target_repository: &route zach")):
            with self.subTest(header=header):
                self.api.header = header
                sha = blob_sha(header.encode())
                self.api.task["sha"] = sha
                self.declaration["reads"][-1]["blob_sha"] = sha
                with self.assertRaises(module.StartupContextError): self.collect()

    def test_pull_requests_must_be_exact_unique_and_complete(self):
        bad = self.api.pr()
        bad["head"]["repo"]["id"] = 12
        for values in ([bad], [self.api.pr(), self.api.pr(11)], [dict(self.api.pr(), state="closed")], [{}], [self.api.pr()] * 101):
            with self.subTest(size=len(values)):
                self.api.pages = [values]
                with self.assertRaises(module.StartupContextError): self.collect()

    def test_frozen_binding_and_normalization_conflicts(self):
        context = self.collect()
        for key, value in (("actor_id", 9999), ("claim_revision", "9" * 40), ("governance_sha", "9" * 40), ("task_blob_sha", "9" * 40), ("request_id", "other")):
            with self.subTest(key=key):
                changed = copy.deepcopy(context)
                changed["remote_preflight"]["source_binding"][key] = value
                with self.assertRaises(module.StartupContextError): module.validate_startup_context(changed, self.bundle)
        for key, value in (("run_id", "other"), ("reuse", {"branch": 1, "run": False, "pull_request": False}), ("source_binding", {}), ("success", True)):
            changed = copy.deepcopy(context)
            changed["remote_preflight"][key] = value
            with self.assertRaises(module.StartupContextError): module.validate_startup_context(changed, self.bundle)
        self.bundle.parameters["agent_declaration"]["capabilities"]["available"].append("github_actions")
        with self.assertRaises(module.StartupContextError): module.validate_startup_context(context, self.bundle)


if __name__ == "__main__":
    unittest.main()
