"""Opt-in verified closure using the existing Actions journal and Publisher.

The trusted read-only observer may receive Control's token. Candidate derivation
never does. Immutable observation bytes are not self-authenticating.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import tempfile

from actions_journal_coordinator import ActionsJournalCoordinator
from actions_ledger_candidate import _json, _regular_read, derive_bound_candidate, read_integration_archive, validate_bound_candidate
from actions_ledger_producer import IntegrationProducerPolicy, REPOSITORY, REPOSITORY_ID, observe_integration_producer, _time
from actions_ledger_publication import LedgerPublicationError, _policy, _recover_publication, _publish_validated_candidate
from actions_ledger_runtime import _artifact_reference
from actions_request_handler import _validate_execution_bundle, _validate_ledger_handoff


def _require(ok, code="integration_context_invalid"):
    if not ok:
        raise LedgerPublicationError(code)


def _request(bundle):
    record = _validate_execution_bundle(bundle)
    _require(bundle.operation == "governance.ledger" and type(bundle.repository_id) is int
             and bundle.repository_id == REPOSITORY_ID and bundle.repository_full_name == REPOSITORY)
    outer = bundle.parameters
    _require(type(outer) is dict and set(outer) == {"base_sha", "operation", "parameters"}
             and outer["operation"] == "task.complete_verified" and type(outer["base_sha"]) is str
             and re.fullmatch(r"[0-9a-f]{40}", outer["base_sha"]) is not None)
    params = outer["parameters"]
    _require(type(params) is dict and set(params) == {"task_id", "run_id"}
             and type(params["task_id"]) is str and re.fullmatch(r"[A-Z]+-[0-9]{3}", params["task_id"]) is not None
             and type(params["run_id"]) is str and len(params["run_id"]) <= 160
             and re.fullmatch(re.escape(params["task_id"]) + r"-[A-Za-z0-9-]+", params["run_id"]) is not None)
    _require(type(bundle.execution_id) is str and re.fullmatch(r"[1-9][0-9]{0,15}-1", bundle.execution_id) is not None
             and int(bundle.execution_id[:-2]) <= 2**53 - 1)
    return record, params


def _observations(raw, bundle, policy):
    record, params = _request(bundle)
    _require(type(raw) is bytes and 0 < len(raw) <= 32768)
    value = _json(raw)
    _require(type(value) is dict and set(value) == {"schema_version", "task_id", "run_id", "repository", "branch", "request_id", "request_digest", "accepted_journal_sha", "policy_revision", "tool_revision", "verified_at", "implementation", "integration"})
    _require(type(value["schema_version"]) is int and value["schema_version"] == 1
             and value["task_id"] == params["task_id"] and value["run_id"] == params["run_id"]
             and value["request_id"] == bundle.request_id and value["request_digest"] == bundle.request_digest
             and value["accepted_journal_sha"] == bundle.accepted_revision
             and value["policy_revision"] == record["policy_revision"] == policy.workflow_revision
             and value["tool_revision"] == policy.tool_revision)
    _require(type(value["implementation"]) is dict and set(value["implementation"]) == {"sha", "ci_sha", "ci_run_url", "pr_url", "pr_head_sha"})
    integration = value["integration"]
    _require(type(integration) is dict and set(integration) == {"merge_commit_sha", "merged_at", "post_merge_ci_sha", "post_merge_ci_run_url", "post_merge_ci_conclusion", "pull_request_merged", "implementation_represented", "cleanup"})
    _require(type(integration["cleanup"]) is dict and set(integration["cleanup"]) == {"remote_branch", "local_worktree", "local_branch"}
             and integration["cleanup"]["local_worktree"] == "not-applicable" and integration["cleanup"]["local_branch"] == "not-applicable"
             and integration["cleanup"]["remote_branch"] in ("retained", "deleted"))
    canonical = json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    _require(raw == canonical, "integration_observation_bytes_mismatch")
    _time(value["verified_at"])
    # Complete canonical task/run/CI/PR/envelope semantics are checked by the
    # existing pinned neutral verifier/mutator after producer authentication.
    return value


class IntegrationObservationRuntime:
    def __init__(self, observer_cli, output_path, token, policy, *, clock=None):
        _require(isinstance(policy, IntegrationProducerPolicy)
                 and all(type(path) is str and os.path.isabs(path) for path in (observer_cli, output_path))
                 and os.path.isfile(observer_cli) and os.access(observer_cli, os.X_OK), "integration_configuration_invalid")
        self.observer_cli, self.output_path, self.token, self.policy = observer_cli, output_path, token, policy
        self.clock = clock or (lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def __call__(self, bundle):
        record, params = _request(bundle)
        _require(record["policy_revision"] == self.policy.workflow_revision)
        value = {"request": {"governance_sha": bundle.parameters["base_sha"], "task_id": params["task_id"],
            "run_id": params["run_id"], "request_id": bundle.request_id},
            "bindings": {"accepted_journal_sha": bundle.accepted_revision, "request_digest": bundle.request_digest,
                "policy_revision": record["policy_revision"], "tool_revision": self.policy.tool_revision, "verified_at": self.clock()}}
        with tempfile.TemporaryDirectory(prefix="zach-integration-observe-") as directory:
            source = ActionsJournalCoordinator._write_private(directory, "input.json", json.dumps(value).encode("utf-8"))
            destination = os.path.join(directory, "integration-observation.json")
            result = ActionsJournalCoordinator._run_observer_subprocess((self.observer_cli, "--input", source, "--output", destination), self.token)
            _require(result.returncode == 0 and not result.stdout, "integration_observer_failed")
            raw = _regular_read(destination)
            _observations(raw, bundle, self.policy)
        # Only the authenticated job's bounded data artifact leaves this process.
        fd = os.open(self.output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
        run = int(bundle.execution_id[:-2])
        return {"stage": "integration-observed", "producer_run_id": run, "producer_run_attempt": 1,
            "artifact_name": f"workspace-integration-observation-{run}-1", "content_sha256": hashlib.sha256(raw).hexdigest()}


class IntegrationPublisherRuntime:
    def __init__(self, api, producer_policy, publication_policy, cli_path, mirror, *, clock=None):
        _require(isinstance(producer_policy, IntegrationProducerPolicy) and callable(api)
                 and callable(getattr(api, "download_artifact", None))
                 and all(type(path) is str and os.path.isabs(path) for path in (cli_path, mirror)), "integration_configuration_invalid")
        _policy(publication_policy)
        self.api, self.producer_policy, self.publication_policy = api, producer_policy, publication_policy
        self.cli_path, self.mirror = cli_path, mirror
        self.clock = clock or (lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def __call__(self, publisher, bundle, handoff):
        try:
            _request(bundle)
            _validate_ledger_handoff(handoff, bundle)
            reference = _artifact_reference(self.api, publisher, bundle, handoff)
            recovered = _recover_publication(self.api, publisher, bundle, reference, self.publication_policy)
            if recovered is not None:
                return recovered
            now = self.clock()
            first = observe_integration_producer(self.api, bundle, reference, self.producer_policy, now)
            raw = read_integration_archive(self.api.download_artifact(REPOSITORY, reference.artifact_id), reference.archive_sha256)
            _require(hashlib.sha256(raw).hexdigest() == reference.content_sha256, "integration_observation_digest_mismatch")
            observations = _observations(raw, bundle, self.producer_policy)
            _require(_time(first["producer_started_at"]) <= _time(observations["verified_at"]) <= _time(first["producer_completed_at"]), "integration_observation_time_mismatch")
            envelope = {"schema_version": 1, "kind": "governance-integration-attestation", "observations": observations,
                "verification": {"repository": REPOSITORY, "workflow_path": self.producer_policy.workflow_path,
                    "workflow_revision": self.producer_policy.workflow_revision, "workflow_run_id": reference.run_id,
                    "run_attempt": reference.run_attempt, "job_id": first["producer_job_id"], "job_conclusion": "success",
                    "artifact_id": reference.artifact_id, "artifact_sha256": reference.archive_sha256,
                    "observation_sha256": hashlib.sha256(raw).hexdigest()}}
            context = {"integration_attestation": envelope}
            # Credentials are absent from this existing candidate subprocess.
            candidate_raw = derive_bound_candidate(bundle, self.cli_path, self.mirror, context, integration_closure=True)
            artifact = validate_bound_candidate(candidate_raw, candidate_raw, bundle, context)
            def recheck():
                _require(first == observe_integration_producer(self.api, bundle, reference, self.producer_policy, now), "integration_producer_observation_unstable")
            return _publish_validated_candidate(self.api, publisher, bundle, reference,
                self.publication_policy, artifact, self.clock, recheck)
        except LedgerPublicationError:
            raise
        except Exception:
            raise LedgerPublicationError("integration_publication_failed") from None
