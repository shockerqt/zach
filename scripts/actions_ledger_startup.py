"""Bounded startup source facts; declarations do not prove agent comprehension.

Collection uses read-only GitHub observations. Pure validation is usable only
after the caller authenticates the existing producer and immutable artifact.
This module grants no authority and does not decide ledger lifecycle validity.
"""
import base64
import copy
from datetime import datetime
import hashlib
import json
import re
from urllib.parse import quote

from actions_github_api import TRUSTED_REPOSITORIES
from actions_request_handler import _validate_execution_bundle


GOVERNANCE = "shockerqt/workspace-governance"
REPOSITORIES = {
    "governance": (1260920764, GOVERNANCE, "master"),
    "zach": (1342354297, "shockerqt/zach", "main"),
    "ui-design-sandbox": (1324116785, "shockerqt/ui-design-sandbox", "main"),
    "infrastructure": (1336587610, "shockerqt/infrastructure", "main"),
}
REQUIRED_READS = frozenset({"AGENTS.md", "STACK.md", "contracts/governance-lifecycle.yaml",
    ".agents/skills/governance-task/SKILL.md", ".agents/skills/governance-run/SKILL.md"})
CORE = frozenset({"github_repository_read", "github_git_write", "github_nonforced_ref_update", "github_pull_request"})
ACTIONS = frozenset({"github_actions", "github_actions_via_operations"})
LOCAL = frozenset({"clone", "shell", "worktree", "hooks", "local_tests"})


class StartupContextError(Exception):
    def __init__(self, code="startup_context_invalid"):
        self.code = code
        super().__init__(code)


def _require(condition, code="startup_context_invalid"):
    if not condition:
        raise StartupContextError(code)


def _sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _positive(value):
    return type(value) is int and 0 < value <= 2**53 - 1


def _keys(value, keys):
    _require(type(value) is dict and set(value) == set(keys))


def _path(value):
    return type(value) is str and len(value) <= 256 and re.fullmatch(r"[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)*", value) is not None and not any(part in {".", ".."} for part in value.split("/"))


def _declaration(value, base):
    _keys(value, {"schema_version", "reads", "capabilities"})
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1)
    try:
        _require(len(json.dumps(value, ensure_ascii=False, allow_nan=False).encode("utf-8")) <= 16384)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise StartupContextError() from None
    reads = value["reads"]
    _require(type(reads) is list and 6 <= len(reads) <= 32)
    paths = set()
    for read in reads:
        _keys(read, {"path", "commit_sha", "blob_sha"})
        _require(_path(read["path"]) and read["path"] not in paths and read["commit_sha"] == base and _sha(read["blob_sha"]))
        paths.add(read["path"])
    _require(REQUIRED_READS <= paths)
    capabilities = value["capabilities"]
    _keys(capabilities, {"available", "unavailable"})
    for name in ("available", "unavailable"):
        items = capabilities[name]
        _require(type(items) is list and len(items) <= 12 and all(type(item) is str and len(item) <= 64 for item in items))
        _require(len(set(items)) == len(items))
    available, unavailable = set(capabilities["available"]), set(capabilities["unavailable"])
    _require(CORE <= available <= CORE | ACTIONS and bool(available & ACTIONS))
    _require(LOCAL <= unavailable <= LOCAL | CORE | ACTIONS and not available & unavailable)
    return copy.deepcopy(value)


def _request(bundle):
    record = _validate_execution_bundle(bundle)
    _require(bundle.operation == "governance.ledger", "startup_operation_unavailable")
    _require(bundle.repository_full_name == GOVERNANCE and bundle.repository_id == 1260920764
             and type(bundle.repository_id) is int, "startup_repository_mismatch")
    _require(_sha(bundle.accepted_revision) and _sha(bundle.claim_revision) and _sha(record.get("policy_revision")))
    _require(type(bundle.request_digest) is str and re.fullmatch(r"[0-9a-f]{64}", bundle.request_digest) is not None)
    outer = bundle.parameters
    _keys(outer, {"base_sha", "operation", "parameters", "agent_declaration"})
    _require(type(outer["operation"]) is str and outer["operation"] in {"run.create", "task.start_run"}, "startup_operation_unavailable")
    params = outer["parameters"]
    _require(type(params) is dict)
    if outer["operation"] == "run.create":
        _require(params.get("run_type") == "execution" and params.get("execution_profile") == "github-connector", "startup_operation_unavailable")
    task_id, slug = params.get("task_id"), params.get("slug")
    _require(type(task_id) is str and re.fullmatch(r"[A-Z]+-[0-9]{3}", task_id) is not None)
    _require(type(slug) is str and len(slug) <= 96 and re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug) is not None)
    _require(_sha(outer["base_sha"]) and _positive(record.get("sender_id")))
    accepted = record.get("accepted_at")
    _require(type(accepted) is str and re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,14})?Z", accepted) is not None)
    try:
        stamp = datetime.strptime(accepted[:19], "%Y-%m-%dT%H:%M:%S").strftime("%Y%m%d-%H%M%S")
    except ValueError:
        raise StartupContextError() from None
    declaration = _declaration(outer["agent_declaration"], outer["base_sha"])
    return record, declaration, task_id, f"{task_id}-{stamp}-{slug}", f"runs/{task_id}/{stamp}-{slug}.md"


def _get(api, repository, path):
    _require(repository in TRUSTED_REPOSITORIES)
    return api("GET", f"/repos/{repository}" + ("/" + path if path else ""), body=None)


def _tree(api, base):
    value = _get(api, GOVERNANCE, f"git/trees/{base}?recursive=1")
    _require(type(value) is dict and _sha(value.get("sha")) and value.get("truncated") is False and type(value.get("tree")) is list and len(value["tree"]) <= 5000)
    entries = {}
    for item in value["tree"]:
        _require(type(item) is dict and _path(item.get("path")) and item["path"] not in entries and _sha(item.get("sha")))
        entries[item["path"]] = item
    return entries


def _blob(api, sha):
    value = _get(api, GOVERNANCE, f"git/blobs/{sha}")
    _require(type(value) is dict and value.get("sha") == sha and value.get("encoding") == "base64" and type(value.get("size")) is int and 0 < value["size"] <= 16384 and type(value.get("content")) is str and len(value["content"]) <= 32768)
    try:
        raw = base64.b64decode("".join(value["content"].split()), validate=True)
        _require(len(raw) == value["size"] and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == sha)
        return raw.decode("utf-8")
    except (ValueError, UnicodeError):
        raise StartupContextError() from None


def _routing(text, task_id):
    # Conservative root scalar extraction, not a general YAML/lifecycle parser.
    _require(text.startswith("---\n") and "\n---\n" in text[4:])
    header = text[4:].split("\n---\n", 1)[0]
    _require(re.search(r"(?:^|\s)[&*!][^\s]*", header) is None)
    values = {}
    for line in header.splitlines():
        if not line or line[0].isspace() or line.startswith(("#", "- ")):
            continue
        match = re.fullmatch(r"([a-z_][a-z0-9_]*):(.*)", line)
        _require(match is not None and match[1] not in values)
        values[match[1]] = match[2].strip()
    def scalar(name):
        value = values.get(name, "")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        _require(re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None)
        return value
    _require(scalar("kind") == "task" and scalar("schema_version") == "1" and scalar("id") == task_id)
    alias, branch = scalar("target_repository"), scalar("branch")
    _require(alias in REPOSITORIES and re.fullmatch(r"task/" + re.escape(task_id) + r"-[a-z0-9]+(?:-[a-z0-9]+)*", branch) is not None)
    return alias, branch


def _ref(api, repository, branch):
    value = _get(api, repository, "git/ref/heads/" + quote(branch, safe="/"))
    _require(type(value) is dict and value.get("ref") == "refs/heads/" + branch and type(value.get("object")) is dict and value["object"].get("type") == "commit" and _sha(value["object"].get("sha")))
    return value["object"]["sha"]


def _pull_requests(api, repository, identifier, branch):
    result, seen = [], set()
    owner = repository.split("/", 1)[0]
    for page in range(1, 12):
        values = _get(api, repository, f"pulls?state=open&head={quote(owner + ':' + branch, safe='')}&per_page=100&page={page}")
        _require(type(values) is list and len(values) <= 100)
        for value in values:
            _require(type(value) is dict and _positive(value.get("id")) and _positive(value.get("number")) and value["id"] not in seen and value.get("state") == "open")
            seen.add(value["id"])
            _require(len(seen) <= 1000)
            head, base = value.get("head"), value.get("base")
            _require(type(head) is dict and type(base) is dict and head.get("ref") == branch and _sha(head.get("sha")))
            for part in (head, base):
                repo = part.get("repo")
                _require(type(repo) is dict and repo.get("full_name") == repository and type(repo.get("id")) is int and repo["id"] == identifier)
            result.append({"id": value["id"], "number": value["number"], "head_sha": head["sha"]})
            _require(len(result) <= 1)
        if len(values) < 100:
            return result
    raise StartupContextError()


def _normalized(binding, declaration):
    return {"schema_version": 2, "execution_profile": "github-connector", "stage": "startup",
        "run_id": binding["run"]["id"],
        "repository": {"name": binding["repository"]["alias"], "default_branch": binding["repository"]["default_branch"], "base_sha": binding["repository"]["base_sha"]},
        "branch": copy.deepcopy(binding["branch"]), "reads": [item["path"] for item in declaration["reads"]],
        "capabilities": copy.deepcopy(declaration["capabilities"]),
        "reuse": {"branch": True, "run": binding["run"]["exists"], "pull_request": bool(binding["open_pull_requests"])},
        "source_binding": copy.deepcopy(binding)}


def collect_startup_context(api, bundle):
    """Observe registered repositories only; no ref creation or live clock."""
    record, declaration, task_id, run_id, run_path = _request(bundle)
    entries = _tree(api, bundle.parameters["base_sha"])
    paths = [path for path in entries if re.fullmatch(r"tasks/" + re.escape(task_id) + r"-[a-z0-9]+(?:-[a-z0-9]+)*\.md", path)]
    _require(len(paths) == 1)
    task_path = paths[0]
    task = entries[task_path]
    _require(task.get("mode") == "100644" and task.get("type") == "blob")
    _require(task_path in {item["path"] for item in declaration["reads"]})
    for read in declaration["reads"]:
        entry = entries.get(read["path"], {})
        _require(entry.get("mode") == "100644" and entry.get("type") == "blob" and entry.get("sha") == read["blob_sha"])
    alias, branch = _routing(_blob(api, task["sha"]), task_id)
    identifier, repository, default = REPOSITORIES[alias]
    metadata = _get(api, repository, "")
    _require(type(metadata) is dict and type(metadata.get("id")) is int and metadata["id"] == identifier and metadata.get("full_name") == repository and metadata.get("default_branch") == default)
    base_sha, starting_sha = _ref(api, repository, default), _ref(api, repository, branch)
    if run_path in entries:
        _require(entries[run_path].get("mode") == "100644" and entries[run_path].get("type") == "blob")
    binding = {"kind": "actions.startup.context", "schema_version": 1,
        "request_id": bundle.request_id, "outer_request_digest": bundle.request_digest,
        "accepted_revision": bundle.accepted_revision, "claim_revision": bundle.claim_revision,
        "policy_revision": record["policy_revision"], "actor_id": record["sender_id"],
        "governance_sha": bundle.parameters["base_sha"], "task_path": task_path, "task_blob_sha": task["sha"],
        "declaration": declaration,
        "repository": {"alias": alias, "id": identifier, "full_name": repository, "default_branch": default, "base_sha": base_sha},
        "branch": {"name": branch, "starting_sha": starting_sha},
        "run": {"id": run_id, "path": run_path, "exists": run_path in entries},
        "open_pull_requests": _pull_requests(api, repository, identifier, branch)}
    return validate_startup_context({"remote_preflight": _normalized(binding, declaration)}, bundle)


def validate_startup_context(context, bundle):
    """Pure frozen-fact validation AFTER existing producer/artifact authentication.

    Equality checks cannot authenticate a fabricated source snapshot. Callers
    must establish its provenance; this function never refreshes observations.
    """
    record, declaration, task_id, run_id, run_path = _request(bundle)
    _keys(context, {"remote_preflight"})
    value = context["remote_preflight"]
    _require(type(value) is dict)
    _require(type(value.get("schema_version")) is int and value["schema_version"] == 2)
    reuse = value.get("reuse")
    _keys(reuse, {"branch", "run", "pull_request"})
    _require(all(type(item) is bool for item in reuse.values()))
    binding = value.get("source_binding")
    _keys(binding, {"kind", "schema_version", "request_id", "outer_request_digest", "accepted_revision", "claim_revision", "policy_revision", "actor_id", "governance_sha", "task_path", "task_blob_sha", "declaration", "repository", "branch", "run", "open_pull_requests"})
    expected = {"kind": "actions.startup.context", "schema_version": 1, "request_id": bundle.request_id,
        "outer_request_digest": bundle.request_digest, "accepted_revision": bundle.accepted_revision,
        "claim_revision": bundle.claim_revision, "policy_revision": record["policy_revision"],
        "actor_id": record["sender_id"], "governance_sha": bundle.parameters["base_sha"], "declaration": declaration}
    _require(all(binding[key] == wanted for key, wanted in expected.items()) and type(binding["schema_version"]) is int and _positive(binding["actor_id"]))
    _require(type(binding["task_path"]) is str and re.fullmatch(r"tasks/" + re.escape(task_id) + r"-[a-z0-9]+(?:-[a-z0-9]+)*\.md", binding["task_path"]) is not None and _sha(binding["task_blob_sha"]))
    _require(any(read["path"] == binding["task_path"] and read["blob_sha"] == binding["task_blob_sha"] for read in declaration["reads"]))
    repository, branch, run = binding["repository"], binding["branch"], binding["run"]
    _keys(repository, {"alias", "id", "full_name", "default_branch", "base_sha"})
    _require(type(repository["alias"]) is str and repository["alias"] in REPOSITORIES)
    identifier, full_name, default = REPOSITORIES[repository["alias"]]
    _require(type(repository["id"]) is int and (repository["id"], repository["full_name"], repository["default_branch"]) == (identifier, full_name, default) and _sha(repository["base_sha"]))
    _keys(branch, {"name", "starting_sha"})
    _require(type(branch["name"]) is str and re.fullmatch(r"task/" + re.escape(task_id) + r"-[a-z0-9]+(?:-[a-z0-9]+)*", branch["name"]) is not None and _sha(branch["starting_sha"]))
    _keys(run, {"id", "path", "exists"})
    _require(run["id"] == run_id and run["path"] == run_path and type(run["exists"]) is bool)
    prs = binding["open_pull_requests"]
    _require(type(prs) is list and len(prs) <= 1)
    for pr in prs:
        _keys(pr, {"id", "number", "head_sha"})
        _require(_positive(pr["id"]) and _positive(pr["number"]) and _sha(pr["head_sha"]))
    _require(value == _normalized(binding, declaration))
    return copy.deepcopy(context)
