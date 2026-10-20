"""Typed configuration wiring for existing Control and Publisher ledger phases.

Configuration is reviewed workflow policy. No Issue supplies an executable,
mirror, output path, publication branch, producer policy or current clock.
This composition supports the shared empty-context operation profile; it does
not activate the workflow or replace required context and closure collectors.
"""
from datetime import datetime, timezone
import hashlib
import os
import re

from actions_ledger_candidate import derive_bound_candidate
from actions_ledger_producer import ArtifactReference, LedgerProducerPolicy, REPOSITORY
from actions_ledger_publication import EMPTY_CONTEXT_LEDGER_OPERATIONS, STARTUP_LEDGER_OPERATIONS, EVIDENCE_LEDGER_OPERATIONS, LedgerPublicationPolicy, LedgerPublicationError, publish_ledger_candidate
from actions_ledger_startup import collect_startup_context
from actions_ledger_evidence import collect_evidence_context
from actions_request_handler import _validate_execution_bundle


def _require(value, code):
    if not value:
        raise LedgerPublicationError(code)


def _handoff(bundle, value):
    _require(type(value) is dict and set(value) == {
        "stage", "producer_run_id", "producer_run_attempt", "artifact_name", "content_sha256"},
        "ledger_handoff_invalid")
    run = value["producer_run_id"]
    _require(type(run) is int and 0 < run <= 2**53 - 1
             and type(value["producer_run_attempt"]) is int and value["producer_run_attempt"] == 1
             and bundle.execution_id == f"{run}-1" and value["stage"] == "candidate-ready"
             and value["artifact_name"] == f"workspace-ledger-candidate-{run}-1"
             and type(value["content_sha256"]) is str
             and re.fullmatch(r"[0-9a-f]{64}", value["content_sha256"]), "ledger_handoff_invalid")
    return value


class LedgerCandidateRuntime:
    def __init__(self, cli_path, mirror, output_path, *, api=None, publisher_policy=None, producer_policy=None, ci_policy=None):
        _require(all(type(path) is str and os.path.isabs(path) for path in (cli_path, mirror, output_path)), "ledger_configuration_invalid")
        self.cli_path, self.mirror, self.output_path = cli_path, mirror, output_path
        _require(api is None or callable(api), "ledger_configuration_invalid")
        self.api = api
        self.publisher_policy, self.producer_policy, self.ci_policy = publisher_policy, producer_policy, ci_policy

    def __call__(self, bundle):
        _validate_execution_bundle(bundle)
        operation = bundle.parameters.get("operation")
        _require(bundle.operation == "governance.ledger" and operation in EMPTY_CONTEXT_LEDGER_OPERATIONS | STARTUP_LEDGER_OPERATIONS | EVIDENCE_LEDGER_OPERATIONS, "ledger_context_profile_unavailable")
        match = re.fullmatch(r"([1-9][0-9]{0,15})-1", bundle.execution_id)
        _require(match is not None and int(match[1]) <= 2**53 - 1, "ledger_execution_invalid")
        run = int(match[1])
        context = {}
        if operation in STARTUP_LEDGER_OPERATIONS:
            _require(self.api is not None, "ledger_context_profile_unavailable")
            context = collect_startup_context(self.api, bundle)
        elif operation in EVIDENCE_LEDGER_OPERATIONS:
            _require(self.api is not None and self.publisher_policy is not None
                     and self.producer_policy is not None, "ledger_context_profile_unavailable")
            context = collect_evidence_context(self.api, bundle, self.publisher_policy,
                self.producer_policy, self.ci_policy, self.cli_path, self.mirror)
        else:
            _require("agent_declaration" not in bundle.parameters, "ledger_context_profile_unavailable")
            _require("publication_source" not in bundle.parameters, "ledger_context_profile_unavailable")
        raw = derive_bound_candidate(bundle, self.cli_path, self.mirror, context)
        descriptor = -1
        try:
            descriptor = os.open(self.output_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                descriptor = -1
                handle.write(raw)
        except OSError:
            raise LedgerPublicationError("ledger_candidate_output_failed") from None
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return {"stage": "candidate-ready", "producer_run_id": run, "producer_run_attempt": 1,
                "artifact_name": f"workspace-ledger-candidate-{run}-1", "content_sha256": hashlib.sha256(raw).hexdigest()}


def _artifact_reference(api, publisher, bundle, handoff):
    """Resolve an already validated handoff through existing checkpoint/lookup."""
    checkpoint = publisher.load_ledger_publication_checkpoint(bundle)
    if checkpoint is not None:
        # Authenticate the recorded artifact before trying a fresh lookup or
        # download. Expiration cannot authorize replacing a prior effect.
        reference = ArtifactReference(**checkpoint.publication["artifact_reference"])
        _require(reference.repository_full_name == REPOSITORY and reference.repository_id == 1260920764
                 and reference.run_id == handoff["producer_run_id"] and reference.run_attempt == 1
                 and reference.content_sha256 == handoff["content_sha256"], "ledger_checkpoint_conflict")
    else:
        matches, seen, total = [], set(), None
        for page in range(1, 11):
            response = api("GET", f"/repos/{REPOSITORY}/actions/runs/{handoff['producer_run_id']}/artifacts?per_page=100&page={page}", body=None)
            _require(type(response) is dict and type(response.get("total_count")) is int
                     and 0 <= response["total_count"] <= 1000 and type(response.get("artifacts")) is list
                     and len(response["artifacts"]) <= 100
                     and (total is None or total == response["total_count"]), "ledger_artifact_lookup_invalid")
            total = response["total_count"]
            for artifact in response["artifacts"]:
                _require(type(artifact) is dict and type(artifact.get("id")) is int
                         and 0 < artifact["id"] <= 2**53 - 1 and artifact["id"] not in seen, "ledger_artifact_lookup_invalid")
                seen.add(artifact["id"])
                if artifact.get("name") == handoff["artifact_name"]:
                    matches.append(artifact)
            _require(len(seen) <= total, "ledger_artifact_lookup_invalid")
            if len(seen) == total:
                break
            _require(len(response["artifacts"]) == 100 and page < 10, "ledger_artifact_lookup_incomplete")
        _require(len(matches) == 1 and type(matches[0].get("digest")) is str
                 and re.fullmatch(r"sha256:[0-9a-f]{64}", matches[0]["digest"]), "ledger_artifact_lookup_ambiguous")
        reference = ArtifactReference(1260920764, REPOSITORY, handoff["producer_run_id"], 1,
                    matches[0]["id"], matches[0]["digest"][7:], handoff["content_sha256"])
    return reference


class LedgerPublisherRuntime:
    def __init__(self, api, producer_policy, publication_policy, cli_path, mirror, *, clock=None):
        _require(isinstance(producer_policy, LedgerProducerPolicy)
                 and isinstance(publication_policy, LedgerPublicationPolicy)
                 and callable(api) and callable(getattr(api, "download_artifact", None))
                 and all(type(path) is str and os.path.isabs(path) for path in (cli_path, mirror)), "ledger_configuration_invalid")
        _require(clock is None or callable(clock), "ledger_configuration_invalid")
        self.api, self.producer_policy, self.publication_policy = api, producer_policy, publication_policy
        self.cli_path, self.mirror = cli_path, mirror
        self.clock = clock or (lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"))

    def __call__(self, publisher, bundle, value):
        _validate_execution_bundle(bundle)
        handoff = _handoff(bundle, value)
        reference = _artifact_reference(self.api, publisher, bundle, handoff)
        return publish_ledger_candidate(self.api, publisher, bundle, reference,
                    self.producer_policy, self.publication_policy, self.cli_path, self.mirror,
                    self.clock(), clock=self.clock)
