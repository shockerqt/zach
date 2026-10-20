"""Initial Governance-only evidence from the existing isolated Publisher.

Snapshot validation is not authentication. Control authenticates original sources;
Publisher must authenticate the current producer/artifact before consuming them.
Native connector publication history and project ref writers are unsupported.
"""
import copy
import hashlib
import re
from urllib.parse import quote

from actions_ci_inspect import CiInspectionPolicy, inspect_ci
from actions_ledger_candidate import _json, derive_bound_candidate, read_candidate_archive, validate_bound_candidate
from actions_ledger_producer import ArtifactReference, REPOSITORY, REPOSITORY_ID, observe_ledger_producer
from actions_ledger_startup import validate_startup_context
from actions_request_handler import ExecutionBundle, _validate_execution_bundle, _validate_ledger_publication, load_durable_published_receipt


class EvidenceContextError(Exception):
    def __init__(self, code="ledger_evidence_invalid"):
        self.code = code
        super().__init__(code)


def _require(ok, code="ledger_evidence_invalid"):
    if not ok:
        raise EvidenceContextError(code)


def _keys(value, keys):
    _require(type(value) is dict and set(value) == set(keys))


def _id(value):
    return type(value) is int and 0 < value <= 2**53 - 1


def _sha(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _request(bundle):
    record = _validate_execution_bundle(bundle)
    _require(bundle.operation == "governance.ledger" and bundle.repository_full_name == REPOSITORY
             and type(bundle.repository_id) is int and bundle.repository_id == REPOSITORY_ID)
    outer = bundle.parameters
    _keys(outer, {"base_sha", "operation", "parameters", "publication_source"})
    _require(outer["operation"] == "run.record_remote_evidence" and _sha(outer["base_sha"]))
    params, source = outer["parameters"], outer["publication_source"]
    _keys(params, {"run_id", "stage"})
    _require(type(params["run_id"]) is str and re.fullmatch(r"GOV-[0-9]{3}-[0-9]{8}-[0-9]{6}-[a-z0-9]+(?:-[a-z0-9]+)*", params["run_id"]) is not None)
    _require(type(params["stage"]) is str and params["stage"] in {"publication", "terminal"})
    _keys(source, {"issue_number", "execution_id", "request_id"})
    _require(_id(source["issue_number"]) and type(source["execution_id"]) is str
             and re.fullmatch(r"[1-9][0-9]{0,15}-1", source["execution_id"]) is not None
             and int(source["execution_id"][:-2]) <= 2**53 - 1
             and type(source["request_id"]) is str and re.fullmatch(r"[A-Za-z0-9_-]{8,128}", source["request_id"]) is not None
             and source["request_id"] != bundle.request_id)
    return record, params, source


def _get(api, path):
    value = api("GET", f"/repos/{REPOSITORY}/{path}", body=None)
    _require(type(value) is dict)
    return value


def _normal(binding, bundle):
    record, params, locator = _request(bundle)
    _keys(binding, {"kind", "schema_version", "request_id", "outer_request_digest", "accepted_revision", "claim_revision", "policy_revision", "governance_sha", "run_id", "stage", "original_bundle", "published_comment_id", "terminal_journal_sha", "publication", "startup_context", "commit", "ci", "pull_request"})
    expected = {"kind": "actions.remote-evidence.context", "schema_version": 1,
        "request_id": bundle.request_id, "outer_request_digest": bundle.request_digest,
        "accepted_revision": bundle.accepted_revision, "claim_revision": bundle.claim_revision,
        "policy_revision": record["policy_revision"], "governance_sha": bundle.parameters["base_sha"],
        "run_id": params["run_id"], "stage": params["stage"]}
    _require(type(binding["schema_version"]) is int and all(binding[k] == v for k, v in expected.items()))
    original = ExecutionBundle.from_dict(binding["original_bundle"])
    original_record = _validate_execution_bundle(original)
    _require(original.repository_full_name == REPOSITORY and type(original.repository_id) is int
             and original.repository_id == REPOSITORY_ID and original.issue_number == locator["issue_number"]
             and original.execution_id == locator["execution_id"] and original.request_id == locator["request_id"]
             and original_record["policy_revision"] == record["policy_revision"])
    preflight = validate_startup_context(binding["startup_context"], original)["remote_preflight"]
    _require(preflight["run_id"] == params["run_id"] and preflight["repository"]["name"] == "governance"
             and preflight["reuse"]["run"] is False)
    publication, commit = binding["publication"], binding["commit"]
    _validate_ledger_publication(original, publication)
    _require(publication["repository_id"] == REPOSITORY_ID and publication["repository_full_name"] == REPOSITORY
             and publication["branch"] == preflight["branch"]["name"]
             and publication["base_sha"] == preflight["branch"]["starting_sha"]
             and publication["commit_sha"] != publication["base_sha"]
             and _id(binding["published_comment_id"]) and _sha(binding["terminal_journal_sha"]))
    _keys(commit, {"sha", "parent_sha", "tree_sha", "message"})
    _require(commit == {"sha": publication["commit_sha"], "parent_sha": publication["base_sha"],
        "tree_sha": publication["tree_sha"], "message": f"chore(ledger): apply {original.request_id}"})
    # These historical flags are authorized ONLY by the authenticated original
    # isolated-Publisher protocol, never inferred from this commit comparison.
    normalized = {key: copy.deepcopy(preflight[key]) for key in ("schema_version", "execution_profile", "run_id", "repository", "branch", "reads", "capabilities", "reuse")}
    normalized.update(stage=params["stage"], publication={"method": "non-forced-single-parent-readback",
        "observed_before_sha": publication["base_sha"], "published_after_sha": publication["commit_sha"],
        "parent_sha": publication["base_sha"], "validated_tree_sha": publication["tree_sha"],
        "readback_tree_sha": publication["tree_sha"], "readback_ref_sha": publication["commit_sha"],
        "forced": False, "default_branch_updated": False, "logical_commit_count": 1,
        "conventional_commit": True, "concurrent_head_handling": "unchanged"})
    if params["stage"] == "publication":
        _require(binding["ci"] is None and binding["pull_request"] is None)
    else:
        ci, pr = binding["ci"], binding["pull_request"]
        _keys(ci, {"id", "attempt", "sha", "workflow_id", "workflow_path", "status", "conclusion", "html_url"})
        _keys(pr, {"id", "number", "head_sha", "head_branch", "base_branch", "repository_id", "html_url", "state"})
        _require(all(_id(ci[k]) for k in ("id", "attempt", "workflow_id"))
                 and ci["sha"] == publication["commit_sha"] and ci["workflow_path"] == ".github/workflows/ci.yml"
                 and ci["status"] == "completed" and ci["conclusion"] == "success"
                 and ci["html_url"] == f"https://github.com/{REPOSITORY}/actions/runs/{ci['id']}")
        _require(_id(pr["id"]) and _id(pr["number"]) and type(pr["repository_id"]) is int
                 and pr["repository_id"] == REPOSITORY_ID and pr["head_sha"] == publication["commit_sha"]
                 and pr["head_branch"] == publication["branch"] and pr["base_branch"] == "master"
                 and type(pr["state"]) is str and pr["state"] in {"open", "closed"}
                 and pr["html_url"] == f"https://github.com/{REPOSITORY}/pull/{pr['number']}")
        normalized["terminal"] = {"implementation_sha": publication["commit_sha"], "ci_sha": ci["sha"],
            "ci_conclusion": "success", "ci_run_url": ci["html_url"], "pull_request_url": pr["html_url"],
            "pull_request_head_sha": pr["head_sha"], "unavailable_validations": ["local tests unavailable in github-connector profile"]}
    normalized["source_binding"] = copy.deepcopy(binding)
    return {"remote_evidence": normalized}


def validate_evidence_context(context, bundle):
    """Pure exact reconstruction AFTER current producer/artifact authentication."""
    _keys(context, {"remote_evidence"})
    _require(type(context["remote_evidence"]) is dict)
    expected = _normal(context["remote_evidence"].get("source_binding"), bundle)
    _require(context == expected)
    return copy.deepcopy(expected)


def _source_pr(api, publication):
    # A subsequent bookkeeping commit may follow a merged implementation PR.
    # Select the original exact head, never the task branch's newest/open PR.
    matches, seen = [], set()
    for page in range(1, 11):
        rows = api("GET", f"/repos/{REPOSITORY}/pulls?state=all&head={quote('shockerqt:' + publication['branch'], safe='')}&per_page=100&page={page}", body=None)
        _require(type(rows) is list and len(rows) <= 100)
        for row in rows:
            _require(type(row) is dict and _id(row.get("id")) and _id(row.get("number")) and row["id"] not in seen)
            seen.add(row["id"])
            for field in ("head", "base"):
                part = row.get(field)
                _require(type(part) is dict and type(part.get("repo")) is dict
                         and type(part["repo"].get("id")) is int and part["repo"]["id"] == REPOSITORY_ID
                         and part["repo"].get("full_name") == REPOSITORY)
            _require(row["head"].get("ref") == publication["branch"] and _sha(row["head"].get("sha")))
            if row["head"]["sha"] == publication["commit_sha"]:
                matches.append(row)
        if len(rows) < 100:
            break
        _require(page < 10)
    _require(len(matches) == 1)
    selected = matches[0]
    detail = _get(api, f"pulls/{selected['number']}")
    _require(all(detail.get(key) == selected.get(key) for key in ("id", "number", "head", "base", "html_url", "state")))
    return {"id": detail["id"], "number": detail["number"], "head_sha": detail["head"]["sha"],
        "head_branch": detail["head"]["ref"], "base_branch": detail["base"].get("ref"),
        "repository_id": REPOSITORY_ID, "html_url": detail.get("html_url"), "state": detail.get("state")}


def collect_evidence_context(api, bundle, publisher_policy, producer_policy, ci_policy, cli_path, mirror):
    """GET-only source collection; derivation uses the existing secret-free bridge."""
    try:
        record, params, locator = _request(bundle)
        receipt = load_durable_published_receipt(api, publisher_policy, **locator)
        original, publication = receipt.bundle, receipt.publication
        _require(_validate_execution_bundle(original)["policy_revision"] == record["policy_revision"])
        reference = ArtifactReference(**publication["artifact_reference"])
        now = record["accepted_at"]
        first = observe_ledger_producer(api, original, reference, producer_policy, now)
        raw = read_candidate_archive(api.download_artifact(REPOSITORY, reference.artifact_id), reference.archive_sha256)
        _require(hashlib.sha256(raw).hexdigest() == reference.content_sha256)
        encoded = _json(raw)
        _require(type(encoded) is dict)
        startup = validate_startup_context(encoded.get("trusted_context"), original)
        independent = derive_bound_candidate(original, cli_path, mirror, startup)
        validate_bound_candidate(raw, independent, original, startup)
        _require(first == observe_ledger_producer(api, original, reference, producer_policy, now), "ledger_evidence_source_unstable")
        commit = _get(api, f"git/commits/{publication['commit_sha']}")
        _require(commit.get("sha") == publication["commit_sha"] and type(commit.get("tree")) is dict
                 and type(commit.get("parents")) is list and len(commit["parents"]) == 1
                 and type(commit["parents"][0]) is dict)
        # The original effect must be represented by the new immutable base.
        if publication["commit_sha"] != bundle.parameters["base_sha"]:
            comparison = _get(api, f"compare/{publication['commit_sha']}...{bundle.parameters['base_sha']}")
            _require(comparison.get("status") == "ahead"
                     and comparison.get("base_commit", {}).get("sha") == publication["commit_sha"]
                     and comparison.get("merge_base_commit", {}).get("sha") == publication["commit_sha"])
        ci, pr = None, None
        if params["stage"] == "terminal":
            _require(isinstance(ci_policy, CiInspectionPolicy) and ci_policy.repository_alias == "governance"
                     and ci_policy.repository_full_name == REPOSITORY and ci_policy.repository_id == REPOSITORY_ID)
            observed = inspect_ci({"repository": "governance", "source_sha": publication["commit_sha"]}, ci_policy, api)
            selected = observed.get("selected_run")
            _require(observed.get("result") == "found" and type(selected) is dict)
            ci = {"id": selected["id"], "attempt": selected["attempt"], "sha": publication["commit_sha"],
                "workflow_id": ci_policy.workflow_id, "workflow_path": ci_policy.workflow_path,
                "status": selected["status"], "conclusion": selected["conclusion"], "html_url": selected["html_url"]}
            pr = _source_pr(api, publication)
        binding = {"kind": "actions.remote-evidence.context", "schema_version": 1,
            "request_id": bundle.request_id, "outer_request_digest": bundle.request_digest,
            "accepted_revision": bundle.accepted_revision, "claim_revision": bundle.claim_revision,
            "policy_revision": record["policy_revision"], "governance_sha": bundle.parameters["base_sha"],
            "run_id": params["run_id"], "stage": params["stage"], "original_bundle": original.to_dict(),
            "published_comment_id": receipt.comment_id, "terminal_journal_sha": receipt.terminal_journal_sha,
            "publication": copy.deepcopy(publication), "startup_context": startup,
            "commit": {"sha": commit["sha"], "parent_sha": commit["parents"][0].get("sha"),
                "tree_sha": commit["tree"].get("sha"), "message": commit.get("message")}, "ci": ci, "pull_request": pr}
        return _normal(binding, bundle)
    except EvidenceContextError:
        raise
    except Exception:
        raise EvidenceContextError() from None
