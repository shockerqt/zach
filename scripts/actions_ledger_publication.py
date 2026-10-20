"""Strict ledger effect mechanics within the existing isolated Publisher.

This is not a journal, authentication service or alternate request transport.
The phase caller authenticates the immutable bundle and Control receipt first.
This module verifies the producer/data/owner, records the exact effect using
Publisher's authenticated checkpoint, and never terminalizes the journal.
"""
from dataclasses import asdict, dataclass
from datetime import datetime
import base64
import hashlib
import re

from actions_ledger_candidate import derive_bound_candidate, read_candidate_archive, validate_bound_candidate, _json
from actions_ledger_startup import validate_startup_context
from actions_ledger_evidence import validate_evidence_context
from actions_ledger_producer import REPOSITORY, REPOSITORY_ID, observe_ledger_producer
from actions_request_handler import _validate_execution_bundle


# Shared composition gate only. Parameter and lifecycle decisions belong to
# the compiled pinned candidate, including task completion/terminal evidence.
EMPTY_CONTEXT_LEDGER_OPERATIONS = frozenset({
    "run.record_evidence", "run.transition_status", "task.append_run",
    "task.transition_status",
})
STARTUP_LEDGER_OPERATIONS = frozenset({"run.create", "task.start_run"})
EVIDENCE_LEDGER_OPERATIONS = frozenset({"run.record_remote_evidence"})


class LedgerPublicationError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class LedgerPublicationPolicy:
    # Routing is workflow configuration, never Issue/candidate input.
    owner_task_id: str
    owner_task_path: str
    branch: str


def _require(value, code):
    if not value:
        raise LedgerPublicationError(code)


def _sha(value):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{40}", value) is not None


def _request_time(value):
    # Frozen Rust timestamps may have more than Python's six fractional digits.
    # Compare exactly without silently rounding an expiration boundary.
    _require(type(value) is str and len(value) <= 35, "ledger_time_invalid")
    match = re.fullmatch(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2})(?:\.([0-9]{1,14}))?Z", value)
    _require(match is not None, "ledger_time_invalid")
    try:
        whole = datetime.strptime(match[1], "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise LedgerPublicationError("ledger_time_invalid") from None
    return whole, (match[2] or "").ljust(14, "0")


def _fresh_request(artifact, clock):
    _require(callable(clock), "ledger_clock_invalid")
    inner = artifact["inner_request"]
    _require(_request_time(inner["created_at"]) <= _request_time(clock())
             < _request_time(inner["expires_at"]), "ledger_request_expired")


def _get(api, path):
    value = api("GET", f"/repos/{REPOSITORY}/{path}", body=None)
    _require(type(value) is dict, "ledger_response_invalid")
    return value


def _head(api, branch):
    value = _get(api, f"git/ref/heads/{branch}")
    _require(value.get("ref") == f"refs/heads/{branch}" and value.get("object", {}).get("type") == "commit"
             and _sha(value.get("object", {}).get("sha")), "ledger_ref_invalid")
    return value["object"]["sha"]


def _commit(api, sha):
    value = _get(api, f"git/commits/{sha}")
    _require(value.get("sha") == sha and _sha(value.get("tree", {}).get("sha"))
             and type(value.get("parents")) is list
             and all(type(parent) is dict and _sha(parent.get("sha")) for parent in value["parents"]),
             "ledger_commit_invalid")
    return value


def _owner(api, tree, policy):
    """Read only bounded canonical routing scalars, never execute base content.

    Unsupported YAML routing syntax fails closed to the strict/manual path.
    Canonical normal plain/single-quoted/double-quoted scalar forms are supported.
    Full ledger validation remains the independently rederived pinned mutator.
    """
    for index, component in enumerate(policy.owner_task_path.split("/")):
        response = _get(api, f"git/trees/{tree}")
        _require(response.get("sha") == tree and response.get("truncated") is False
                 and type(response.get("tree")) is list, "ledger_owner_unavailable")
        entries = [item for item in response["tree"] if type(item) is dict and item.get("path") == component]
        _require(len(entries) == 1 and _sha(entries[0].get("sha")), "ledger_owner_unavailable")
        entry = entries[0]
        if index == 0:
            _require(entry.get("mode") == "040000" and entry.get("type") == "tree", "ledger_owner_invalid")
            tree = entry["sha"]
            continue
        _require(entry.get("mode") == "100644" and entry.get("type") == "blob", "ledger_owner_invalid")
        blob = _get(api, f"git/blobs/{entry['sha']}")
        _require(blob.get("sha") == entry["sha"] and blob.get("encoding") == "base64"
                 and type(blob.get("size")) is int and 0 < blob["size"] <= 16384
                 and type(blob.get("content")) is str and len(blob["content"]) <= 32768,
                 "ledger_owner_invalid")
        raw = base64.b64decode("".join(blob["content"].split()), validate=True)
        _require(len(raw) == blob["size"] and hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == entry["sha"], "ledger_owner_invalid")
        text = raw.decode("utf-8")
        _require(text.startswith("---\n") and "\n---\n" in text[4:], "ledger_owner_invalid")
        header = text[4:].split("\n---\n", 1)[0]
        # Do not confuse a lexical match with YAML meaning: quoted/decorated
        # keys, merges and duplicate keys could override those apparent values.
        # This reader supports canonical plain keys only; other valid YAML must
        # take the strict/manual path rather than being interpreted differently.
        seen = set()
        for line in header.splitlines():
            if not line or line[0].isspace() or line.startswith(("#", "- ")):
                continue
            match = re.fullmatch(r"([a-z_][a-z0-9_]*):(?:.*)", line)
            _require(match is not None and match.group(1) not in seen, "ledger_owner_ambiguous")
            seen.add(match.group(1))
        expected = {"kind": "task", "schema_version": "1", "id": policy.owner_task_id,
                    "status": "active", "project": "governance", "target_repository": "governance", "branch": policy.branch}
        for key, wanted in expected.items():
            values = re.findall(r"^" + key + r": *([^\n]+)$", header, flags=re.M)
            _require(len(values) == 1 and values[0] in (wanted, "'" + wanted + "'", '"' + wanted + '"'), "ledger_owner_mismatch")


def _policy(policy):
    _require(isinstance(policy, LedgerPublicationPolicy)
             and type(policy.owner_task_id) is str and re.fullmatch(r"GOV-[0-9]{3}", policy.owner_task_id)
             and type(policy.owner_task_path) is str
             and re.fullmatch(r"tasks/" + re.escape(policy.owner_task_id) + r"-[a-z0-9]+(?:-[a-z0-9]+)*\.md", policy.owner_task_path)
             and type(policy.branch) is str
             and re.fullmatch(r"task/" + re.escape(policy.owner_task_id) + r"-[a-z0-9]+(?:-[a-z0-9]+)*", policy.branch), "ledger_policy_invalid")


def _readback(api, publication):
    commit = _commit(api, publication["commit_sha"])
    _require(commit["tree"]["sha"] == publication["tree_sha"], "ledger_effect_mismatch")
    if publication["commit_sha"] != publication["base_sha"]:
        _require([parent["sha"] for parent in commit["parents"]] == [publication["base_sha"]], "ledger_effect_mismatch")
    _require(_head(api, publication["branch"]) == publication["commit_sha"], "ledger_publication_ambiguous")


def publish_ledger_candidate(api, publisher, bundle, reference, producer_policy,
                             policy, cli_path, mirror, now, *, clock):
    """Return a proven publication, or fail closed without terminalizing.

    Compose the shared empty-context operation profile. The pinned candidate
    decides parameter and lifecycle validity; other profiles remain unavailable.
    Recovery loads the authenticated effect first and makes no new write.
    """
    try:
        _policy(policy)
        record = _validate_execution_bundle(bundle)
        _require(bundle.operation == "governance.ledger" and record["policy_revision"] == producer_policy.workflow_revision,
                 "ledger_bundle_mismatch")
        operation = bundle.parameters.get("operation")
        _require(operation in EMPTY_CONTEXT_LEDGER_OPERATIONS | STARTUP_LEDGER_OPERATIONS | EVIDENCE_LEDGER_OPERATIONS, "ledger_context_profile_unavailable")
        if operation in STARTUP_LEDGER_OPERATIONS:
            _require(type(bundle.parameters.get("agent_declaration")) is dict,
                     "ledger_context_profile_unavailable")
        else:
            _require("agent_declaration" not in bundle.parameters, "ledger_context_profile_unavailable")
        if operation in EVIDENCE_LEDGER_OPERATIONS:
            _require(type(bundle.parameters.get("publication_source")) is dict, "ledger_context_profile_unavailable")
        else:
            _require("publication_source" not in bundle.parameters, "ledger_context_profile_unavailable")
        checkpoint = publisher.load_ledger_publication_checkpoint(bundle)
        if checkpoint is not None:
            publication = checkpoint.publication
            _require(publication["branch"] == policy.branch and publication["artifact_reference"] == asdict(reference), "ledger_checkpoint_conflict")
            _readback(api, publication)
            return {"publication": publication, "checkpoint_comment_id": checkpoint.comment_id, "replayed": True}

        first = observe_ledger_producer(api, bundle, reference, producer_policy, now)
        archive = api.download_artifact(REPOSITORY, reference.artifact_id)
        raw = read_candidate_archive(archive, reference.archive_sha256)
        _require(hashlib.sha256(raw).hexdigest() == reference.content_sha256, "ledger_content_digest_mismatch")
        # Producer/job and archive/content identity are authenticated above.
        # Context bytes alone are never evidence. Reuse that exact trusted
        # producer snapshot; do not recollect mutable project refs with Publisher.
        context = {}
        if operation in STARTUP_LEDGER_OPERATIONS | EVIDENCE_LEDGER_OPERATIONS:
            encoded = _json(raw)
            _require(type(encoded) is dict, "ledger_startup_context_invalid")
            validate_context = validate_startup_context if operation in STARTUP_LEDGER_OPERATIONS else validate_evidence_context
            context = validate_context(encoded.get("trusted_context"), bundle)
        independent = derive_bound_candidate(bundle, cli_path, mirror, context)
        artifact = validate_bound_candidate(raw, independent, bundle, context)
        _fresh_request(artifact, clock)
        candidate = artifact["candidate"]
        base = candidate["base_sha"]
        _require(_head(api, policy.branch) == base, "ledger_ref_conflict")
        base_commit = _commit(api, base)
        _owner(api, base_commit["tree"]["sha"], policy)
        _require(first == observe_ledger_producer(api, bundle, reference, producer_policy, now), "ledger_producer_observation_unstable")
        tree_entries = []
        for change in candidate["changes"]:
            sha = None
            if change["operation"] == "upsert":
                content = base64.b64encode(change["content"].encode("utf-8")).decode("ascii")
                blob = api("POST", f"/repos/{REPOSITORY}/git/blobs", body={"content": content, "encoding": "base64"})
                _require(type(blob) is dict and blob.get("sha") == change["blob_sha"], "ledger_blob_mismatch")
                sha = change["blob_sha"]
            tree_entries.append({"path": change["path"], "mode": "100644", "type": "blob", "sha": sha})
        commit_sha = base
        if tree_entries:
            tree = api("POST", f"/repos/{REPOSITORY}/git/trees", body={"base_tree": base_commit["tree"]["sha"], "tree": tree_entries})
            _require(type(tree) is dict and tree.get("sha") == candidate["validated_tree_sha"], "ledger_tree_mismatch")
            commit = api("POST", f"/repos/{REPOSITORY}/git/commits", body={"message": f"chore(ledger): apply {bundle.request_id}",
                         "tree": candidate["validated_tree_sha"], "parents": [base]})
            _require(type(commit) is dict and _sha(commit.get("sha")), "ledger_commit_invalid")
            commit_sha = commit["sha"]
            checked = _commit(api, commit_sha)
            _require(checked["tree"]["sha"] == candidate["validated_tree_sha"] and [item["sha"] for item in checked["parents"]] == [base], "ledger_commit_mismatch")
        else:
            _require(candidate["validated_tree_sha"] == base_commit["tree"]["sha"], "ledger_tree_mismatch")
        publication = {"repository_id": REPOSITORY_ID, "repository_full_name": REPOSITORY,
                       "branch": policy.branch, "base_sha": base, "tree_sha": candidate["validated_tree_sha"],
                       "commit_sha": commit_sha, "artifact_reference": asdict(reference)}
        checkpoint = publisher.checkpoint_ledger_publication(bundle, publication)
        recovered = publisher.load_ledger_publication_checkpoint(bundle)
        _require(recovered is not None and recovered.publication == publication, "ledger_checkpoint_conflict")
        _require(_head(api, policy.branch) == base, "ledger_ref_conflict")
        _fresh_request(artifact, clock)
        if commit_sha != base:
            try:
                api("PATCH", f"/repos/{REPOSITORY}/git/refs/heads/{policy.branch}", body={"sha": commit_sha, "force": False})
            except Exception:
                pass  # Reconcile exactly the recorded effect, never retry PATCH.
        _readback(api, publication)
        return {"publication": publication, "checkpoint_comment_id": checkpoint.comment_id, "replayed": False}
    except LedgerPublicationError:
        raise
    except Exception as error:
        code = getattr(error, "code", "ledger_publication_failed")
        if not isinstance(code, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,127}", code):
            code = "ledger_publication_failed"
        raise LedgerPublicationError(code) from None
