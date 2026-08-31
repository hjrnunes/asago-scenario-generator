#!/usr/bin/env python3
"""Independent subprocess QA for the Phase 4 Task 1 resolver."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from acceptance.qa.qa_harness import QARunner  # noqa: E402

_SEARCH_PATH = f"/opt/homebrew/bin:/usr/local/bin:{os.environ.get('PATH', '')}"
_UV = shutil.which("uv", path=_SEARCH_PATH) or "uv"

# This child deliberately imports the source package only after the parent
# process has established a clean, opt-out environment.  Digest checking is
# repeated below from the serialized result, rather than trusting a model
# helper to assert its own digest.
_CHILD = r"""
import hashlib
import json
import socket
import sys
from unittest.mock import patch

sys.path.insert(0, "acceptance")

from runtime_features.phase4_task1_hybrid_projection import _fixture
from tests.test_hybrid_coverage_assessment import (
    _proposal_set,
    _stpa_input,
    _taxonomy_input,
)
from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CorrespondenceAdjudication,
    ProposalSet,
)
from asago_scenario_generator.pipeline.correspondence import reconcile_correspondence
from asago_scenario_generator.pipeline.hybrid_coverage import assess_hybrid_coverage
from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    build_hybrid_correspondence_attestation,
    resolve_hybrid_projection_units,
)


def canonical(value):
    if hasattr(value, "model_dump"):
        return canonical(value.model_dump(mode="json"))
    if isinstance(value, str):
        import unicodedata
        return unicodedata.normalize("NFC", value)
    if isinstance(value, dict):
        return {canonical(str(key)): canonical(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [canonical(item) for item in value]
    return value


def framed_digest(domain, payload):
    body = json.dumps(
        canonical(payload),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(domain.encode("utf-8") + b"\0" + body).hexdigest()


def confirmed(plan, resource_map, *, relation_kind="same_mechanism"):
    proposal_set, candidate = _proposal_set(
        plan, resource_map, relation_kind=relation_kind
    )
    proposal = proposal_set.proposals[0]
    reconciliation = reconcile_correspondence(
        resource_map,
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="external QA exact authority",
                    adjudicated_by="qa",
                ),
            )
        ),
    )
    assessment = assess_hybrid_coverage(
        plan,
        resource_map,
        reconciliation,
        _taxonomy_input(plan, candidate),
        _stpa_input(),
    )
    correspondence = build_hybrid_correspondence_attestation(
        proposal_set, reconciliation, assessment
    )
    relation = correspondence.accepted_relations[0]
    return proposal_set, reconciliation, assessment, correspondence, relation


def main():
    events = []

    def blocked_provider(_self, *_args, **_kwargs):
        events.append("provider")
        raise AssertionError("provider construction was attempted")

    def blocked_socket(*_args, **_kwargs):
        events.append("socket")
        raise AssertionError("socket construction was attempted")

    from asago_scenario_generator.llm.client import LLMClient as TaxonomyLLMClient
    from asago_scenario_generator.stpa.infra.llm import LLMClient as StpaLLMClient

    with (
        patch.object(TaxonomyLLMClient, "__init__", blocked_provider),
        patch.object(StpaLLMClient, "__init__", blocked_provider),
        patch.object(socket, "socket", side_effect=blocked_socket),
        patch.object(socket, "create_connection", side_effect=blocked_socket),
    ):
        inputs, fixture_relation, fixture_candidate = _fixture()
        resolved = resolve_hybrid_projection_units(inputs)
        resolved.assert_integrity()
        result_data = resolved.model_dump(mode="json")
        digest_payload = dict(result_data)
        digest_payload.pop("semantic_digest", None)
        expected_digest = framed_digest(
            "asago.hybrid-projection-resolution.v1", digest_payload
        )
        artifact_ids = {
            item["pin"]["artifact_id"]
            for item in result_data["source_pins"]
            if item.get("kind") == "artifact"
        }

        _, _, related_assessment, related_correspondence, related_relation = confirmed(
            inputs.obligation_plan,
            inputs.resource_map_validation,
            relation_kind="related_but_not_coverage",
        )
        related_inputs = inputs.model_copy(
            update={
                "phase2_assessment": related_assessment,
                "correspondence": related_correspondence,
                "confirmed_reviews": (),
                "bridge_links": (),
                "requested_relation_ids": (related_relation.relation_id,),
            }
        )
        related = resolve_hybrid_projection_units(related_inputs)

        proposal_set, reconciliation, assessment, _correspondence, _relation = confirmed(
            inputs.obligation_plan,
            inputs.resource_map_validation,
        )
        proposal = proposal_set.proposals[0]
        replaced = proposal.model_copy(update={"confidence": 0.5})
        substituted_set = ProposalSet(
            resource_map_semantic_digest=proposal_set.resource_map_semantic_digest,
            capability_snapshot_digest=proposal_set.capability_snapshot_digest,
            authority=proposal_set.authority,
            proposals=(replaced,),
        )
        try:
            build_hybrid_correspondence_attestation(
                substituted_set, reconciliation, assessment
            )
        except Exception as exc:
            cross_pair_error = str(exc)
        else:
            cross_pair_error = ""

        copied = inputs.correspondence.model_copy(update={"semantic_digest": None})
        copied = type(copied).model_validate(copied.model_dump(mode="python"))
        copied_inputs = inputs.model_copy(update={"correspondence": copied})
        try:
            resolve_hybrid_projection_units(copied_inputs)
        except Exception as exc:
            copied_error = str(exc)
        else:
            copied_error = ""

    print(
        json.dumps(
            {
                "units": len(resolved.units),
                "exclusions": len(resolved.exclusions),
                "identity": [
                    resolved.units[0].relation_id,
                    resolved.units[0].obligation_id,
                    resolved.units[0].selected_candidate_id,
                    resolved.units[0].ica_id,
                    resolved.units[0].exec_candidate_id,
                ],
                "fixture_identity": [
                    fixture_relation.relation_id,
                    fixture_relation.obligation_id,
                    fixture_candidate.candidate_id,
                    fixture_relation.ica_id,
                    fixture_relation.exec_candidate_id,
                ],
                "digest": result_data["semantic_digest"],
                "expected_digest": expected_digest,
                "artifact_ids": sorted(artifact_ids),
                "related_units": len(related.units),
                "related_exclusions": len(related.exclusions),
                "related_reason": related.exclusions[0].reason,
                "cross_pair_error": cross_pair_error,
                "copied_error": copied_error,
                "events": events,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
"""


def main() -> int:
    """Run the child process and report independent Task 1 checks."""
    qa = QARunner()
    environment = dict(os.environ)
    environment.pop("ASAGO_SCENARIO_GENERATOR_QA_PIPELINE", None)
    child = subprocess.run(
        [_UV, "run", "python", "-c", _CHILD],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    if child.returncode != 0:
        qa.record(
            "Task 1 subprocess completed",
            False,
            child.stderr.strip() or child.stdout.strip(),
        )
        return qa.summary()
    qa.record("Task 1 subprocess completed", True)
    try:
        observed = json.loads(child.stdout)
    except json.JSONDecodeError as exc:
        qa.record("Task 1 subprocess returned JSON", False, str(exc))
        return qa.summary()

    qa.check(
        "canonical resolution digest matches an independent recomputation",
        observed["digest"] == observed["expected_digest"],
        f"{observed['digest']} != {observed['expected_digest']}",
    )
    qa.check(
        "one accepted unit retains the exact five-part identity",
        observed["units"] == 1
        and observed["exclusions"] == 0
        and observed["identity"] == observed["fixture_identity"],
        str(observed["identity"]),
    )
    required = {
        "taxonomy-candidate-materialization-set",
        "capability-fact-attestation",
        "pinned-stpa-projection-attestation",
        "hybrid-correspondence-attestation",
    }
    qa.check(
        "resolution retains wrapper source pins",
        required.issubset(set(observed["artifact_ids"]))
        and any(
            item.startswith("confirmed-coverage-review:")
            for item in observed["artifact_ids"]
        ),
        str(observed["artifact_ids"]),
    )
    qa.check(
        "related-only correspondence remains a typed exclusion",
        observed["related_units"] == 0
        and observed["related_exclusions"] == 1
        and observed["related_reason"] == "relation_not_coverage",
        str(observed["related_reason"]),
    )
    qa.check(
        "cross-paired authorities fail with the exact diagnostic",
        "proposal set and reconciliation proposal content do not match"
        in observed["cross_pair_error"],
        observed["cross_pair_error"],
    )
    qa.check(
        "copied attestations cannot cross the factory boundary",
        "verified artifact factory" in observed["copied_error"],
        observed["copied_error"],
    )
    qa.check(
        "the resolver constructs no provider and makes no socket call",
        observed["events"] == [],
        str(observed["events"]),
    )
    return qa.summary()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # noqa: BLE001 - executable QA boundary
        print(f"phase4 Task 1 external QA: FAIL: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
