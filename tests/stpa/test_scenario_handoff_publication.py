"""The versioned scenario handoff and its ownership boundary.

The normal product run publishes narrative, attack tree, Gherkin and necessary
metadata only. It never publishes a prepared message, a prepared history or
role/turn array, a harness delivery route, an oracle selection, a detector
expression, a judge prompt or executable setup, and it never hides such
content in prose. These tests are the negative ownership tests for that
boundary, plus the behaviour that a missing downstream compilable detector
never suppresses a scenario.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HANDOFF_SCHEMA_VERSION_V4,
    ScenarioHandoffV4,
    build_scenario_handoff,
    handoff_ownership_violations,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
    run_sp3,
)
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.helpers.sp3_run import _make_ets
from tests.helpers.unified_stage2 import _observations, _profile
from tests.helpers.scenario_handoff_publication import (
    _client,
    _normal_semantics_payload,
    _profile_condition,
    _publish,
)

#: Artifact-design content classes the producer handoff must never carry, at
#: the structural-field level or hidden in prose.
_FORBIDDEN_PROSE = {
    "prepared message field": re.compile(r"prepared_user_text", re.I),
    "stimulus turn field": re.compile(r"stimulus_turns", re.I),
    "role serialization": re.compile(r"\brole\s*:\s*(user|assistant|system)\b", re.I),
    "turn array": re.compile(r"\bturns?\s*:", re.I),
    "ready-to-send instruction": re.compile(
        r"\bsend this message\b|\bdeliver this message\b|\bexecute the following\b",
        re.I,
    ),
    "judge prompt": re.compile(r"\bjudge prompt\b", re.I),
    "detector comparison": re.compile(
        r"\bgreater_than\b|\bless_than\b|\bamount\s*[<>=]", re.I
    ),
}


def _adversarial_payload() -> dict:
    """The historical execution wire, kept for bundle-publication callers."""
    return {
        "stimulus": {
            "category": "user_message",
            "description": "One user message is the typed test stimulus.",
        },
        "adversary": {
            "kind": "malicious_customer",
            "gain": "Learns another customer's order details.",
        },
        "attacker_bdi": {
            "beliefs": ["attacker belief 1"],
            "desires": ["induce ICA"],
            "intentions": [
                {
                    "description": "Exploit stale PM-1-1 state before CA-1-1.",
                    "source_handles": ["cause_1"],
                }
            ],
        },
        "causal_factors": [
            {
                "source_handle": "cause_1",
                "evidence": "The selected state can be stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
                "selected_for_route": True,
            }
        ],
        "unsafe_outcome": {
            "condition": {
                "type": "action_presence",
                "control_action_id": "CA-1-1",
                "expected": "not_provided",
            },
            "semantic_proposition": (
                "The response does not provide the requested action."
            ),
        },
        "execution_route": {
            "disposition": "executable_route",
            "action_kind": "model_output",
            "reason": "The selected structural factor supports the direct route.",
        },
    }


def _functional_payload() -> dict:
    payload = _normal_semantics_payload()
    payload["adversary"] = {
        "kind": "none",
        "gain": "The requested service completes as designed.",
    }
    payload["attacker_bdi"] = {
        "beliefs": [],
        "desires": [],
        "intentions": [],
    }
    return payload


def _published_handoff(run_dir: Path, scenario_id: str = "SCN-001") -> dict:
    path = run_dir / "scenarios" / f"{scenario_id}.yaml"
    assert path.is_file(), f"missing handoff {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _scan_published_text(run_dir: Path) -> list[str]:
    """Return forbidden artifact-design content found in published artifacts."""
    found: list[str] = []
    targets = [run_dir / "scenarios", run_dir / "run-manifest.yaml"]
    for target in targets:
        files = [target] if target.is_file() else sorted(target.rglob("*"))
        for path in files:
            if not path.is_file():
                continue
            try:
                text = path.read_text(encoding="utf-8")
            except UnicodeDecodeError:
                continue
            for label, pattern in _FORBIDDEN_PROSE.items():
                if pattern.search(text):
                    found.append(f"{path.name}: {label}")
    return found


def test_run_publishes_the_versioned_scenario_handoff(tmp_path: Path) -> None:
    result = _publish([_normal_semantics_payload()], tmp_path)

    assert [outcome.status for outcome in result.candidate_outcomes] == [
        SP3CandidateStatus.published
    ]
    assert result.stage_errors == []
    document = _published_handoff(tmp_path)
    assert document["schema_version"] == HANDOFF_SCHEMA_VERSION_V4
    assert document["scenario_id"] == "SCN-001"
    assert document["scenario_version"] >= 1
    assert document["kind"] == "adversarial"
    assert document["narrative"].strip()
    assert document["attack_tree"]
    assert document["gherkin"]["feature"]
    assert document["gherkin"]["scenario"]
    assert document["lineage"]["ica_slot_id"]
    assert document["lineage"]["controller_id"]
    assert document["lineage"]["control_action_id"]
    assert document["hypothesis_framing"]
    # The authored semantic proposition survives publication verbatim.
    assert document["semantic_failure_criterion"] == (
        "The response does not provide the requested action."
    )
    assert document["safe_alternative"].strip()
    assert document["content_digest"]
    assert document["observation"]["assessment"]["disposition"] == "executable"
    assert document["observation"]["assessment"]["reason"] == (
        "observable_outcome_supported"
    )
    # The matching declarative .feature companion is present.
    feature = (tmp_path / "scenarios" / "SCN-001.feature").read_text(encoding="utf-8")
    assert feature.startswith("Feature: ")
    # No execution projection, canonical projection, or bundle is published.
    assert not (tmp_path / "scenarios" / "canonical").exists()
    assert not (tmp_path / "execution-bundle.json").exists()


def test_handoff_is_the_envelope_over_three_representations_only(
    tmp_path: Path,
) -> None:
    """No fourth representation is introduced under new field names."""
    _publish([_normal_semantics_payload()], tmp_path)
    document = _published_handoff(tmp_path)
    assert set(document) == {
        "schema_version",
        "scenario_id",
        "scenario_version",
        "kind",
        "hypothesis_framing",
        "narrative",
        "attack_tree",
        "gherkin",
        "semantic_failure_criterion",
        "safe_alternative",
        "safe_observable_outcome",
        "governing_rules",
        "lineage",
        "documented_operations",
        "sourced_facts",
        "assumptions_and_unknowns",
        "observation",
        "deduplication",
        "content_digest",
        "tool_call_condition_status",
        "attack_shape",
    }
    # This request supplies no target facts, so Stage 5 publishes no
    # condition and the binding says so.
    assert document["tool_call_condition_status"]["reason"] == "no_condition"
    assert set(document["gherkin"]) == {
        "feature",
        "scenario",
        "given",
        "when",
        "then_expected",
        "then_unsafe_alternative",
    }


def test_handoff_publishes_deduplication_and_testability_summary(
    tmp_path: Path,
) -> None:
    _publish([_normal_semantics_payload()], tmp_path)

    document = _published_handoff(tmp_path)
    summary = yaml.safe_load((tmp_path / "testability.yaml").read_text())

    assert document["deduplication"]["status"] == "canonical"
    assert document["deduplication"]["key"]["claim_level"] == "reply"
    assert summary["summary"] == {
        "total": 1,
        "canonical": 1,
        "duplicates": 0,
        "analytical_only": 0,
        "executable": 1,
    }


def test_published_handoff_carries_no_artifact_design_content(
    tmp_path: Path,
) -> None:
    _publish([_normal_semantics_payload()], tmp_path)
    document = _published_handoff(tmp_path)

    assert handoff_ownership_violations(document) == []
    assert _scan_published_text(tmp_path) == []
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    # No algorithm-selecting field rides in the manifest.
    assert "mode" not in manifest["stage_summary"].get("stage_2", {})


def test_ownership_check_flags_smuggled_artifact_design_content() -> None:
    """A forbidden field, or one hidden in prose, is a violation."""
    field_violation = handoff_ownership_violations(
        {"gherkin": {"when": ["x"]}, "prepared_user_text": "refund 100.00"}
    )
    assert any("prepared_user_text" in item for item in field_violation)

    prose_violation = handoff_ownership_violations(
        {"narrative": ("Then send this message: role: user turns: [refund the order]")}
    )
    assert prose_violation, "prose-level hiding must be reported"

    # A quoted governing rule that is the subject of analysis stays allowed.
    assert (
        handoff_ownership_violations(
            {"governing_rules": [{"statement": "Do not refund more than the balance."}]}
        )
        == []
    )


def test_ownership_check_holds_no_pattern_for_a_particular_saved_request() -> None:
    """Prose is flagged by artifact-design shape, never by one request's text."""
    assert (
        handoff_ownership_violations(
            {"narrative": "The customer asks for a full refund of 100.0."}
        )
        == []
    )


def test_handoff_without_failure_criterion_or_safe_alternative_is_rejected() -> None:
    """A handoff missing the semantic failure criterion or the safe
    alternative fails validation — the ownership boundary requires both."""
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "data/contracts/scenario-handoff/handoff-v4/valid/"
        "adversarial-observed-record.json"
    )
    document = json.loads(fixture_path.read_text(encoding="utf-8"))
    ScenarioHandoffV4.model_validate(document)

    for missing_field in ("semantic_failure_criterion", "safe_alternative"):
        incomplete = {
            key: value for key, value in document.items() if key != missing_field
        }
        with pytest.raises(ValidationError):
            ScenarioHandoffV4.model_validate(incomplete)


def test_handoff_digest_detects_tampering(tmp_path: Path) -> None:
    _publish([_normal_semantics_payload()], tmp_path)
    document = _published_handoff(tmp_path)
    handoff = ScenarioHandoffV4.model_validate(document)
    verify_handoff_digest(handoff)

    tampered = ScenarioHandoffV4.model_validate(
        {**document, "narrative": document["narrative"] + " tampered"}
    )
    with pytest.raises(ValueError):
        verify_handoff_digest(tampered)


def test_scenario_without_a_preparable_projection_is_still_published(
    tmp_path: Path,
) -> None:
    """Publication never depends on a downstream detector capability."""
    handoff_run = tmp_path / "handoff"
    result = _publish([_normal_semantics_payload()], handoff_run)

    assert [outcome.status for outcome in result.candidate_outcomes] == [
        SP3CandidateStatus.published
    ]
    assert result.stage_errors == []
    document = _published_handoff(handoff_run)
    assert document["narrative"].strip()
    # The unobservable aspect is recorded as a limitation on the artifact.
    assert any(
        "unresolved until the consumer" in item
        for item in document["assumptions_and_unknowns"]
    )

    # The retired execution-bundle path still fails closed on the same input.
    bundle_run = tmp_path / "bundle"
    run_sp3(
        llm_client=_client([_adversarial_payload()]),
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=bundle_run,
    )
    assert not (bundle_run / "scenarios" / "SCN-001.yaml").exists()


def test_functional_scenario_is_persisted_not_rejected(tmp_path: Path) -> None:
    result = _publish([_functional_payload()], tmp_path)

    assert [outcome.status for outcome in result.candidate_outcomes] == [
        SP3CandidateStatus.functional_test
    ]
    document = _published_handoff(tmp_path)
    assert document["kind"] == "functional"
    assert document["narrative"].strip()
    assert not (tmp_path / "execution-bundle.json").exists()
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert manifest["stage_errors"] == []
    # A functional scenario is persisted evidence, never a generated or
    # bundled adversarial scenario.
    assert manifest["scenario_count"] == 0
    assert (tmp_path / "scenarios" / "SCN-001.feature").is_file()


def test_run_manifest_records_artifact_digests_and_no_mode_field(
    tmp_path: Path,
) -> None:
    """The unified run manifest carries digests and no algorithm selector."""
    _publish([_normal_semantics_payload()], tmp_path)
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    for digest_key in ("enriched_threat_set", "control_structure", "loss_analysis"):
        assert manifest["input_hashes"][digest_key]
    assert set(manifest["stage_summary"]["stage_2"]) == set()


def test_verified_enrichment_row_publishes_the_operation_identity(
    tmp_path: Path,
) -> None:
    """A verified enrichment row for the lineage control action is published."""
    _publish(
        [_normal_semantics_payload()],
        tmp_path,
        enriched_operations={"CA-1-1": "process_refund"},
    )
    document = _published_handoff(tmp_path)

    enriched = [
        operation
        for operation in document["documented_operations"]
        if operation["name"] == "process_refund"
    ]
    assert enriched, document["documented_operations"]
    # The association stays evidence-framed: no permission or ownership claim.
    assert "not a permission or ownership conclusion" in enriched[0]["relevance"]


def test_criterion_operation_requires_an_exact_observed_inventory_match(
    tmp_path: Path,
) -> None:
    """A criterion token is binding only when the run observed that operation."""
    payload = _normal_semantics_payload()
    payload["unsafe_outcome"]["semantic_proposition"] = (
        "The assistant initiates process_refund for order ORD-104 despite "
        "refund_eligible being false."
    )
    result = _publish([payload], tmp_path)
    envelope = result.scenario_envelopes[0]

    handoff = build_scenario_handoff(
        envelope,
        observed_operations=("process_refund", "lookup_order"),
        environment_bound=True,
    )

    assert [item.name for item in handoff.documented_operations] == ["process_refund"]
    assert "criterion_observed_operation" in handoff.documented_operations[0].relevance


def test_normal_run_threads_observed_inventory_into_handoff_publication(
    tmp_path: Path,
) -> None:
    """The normal producer path carries the exact profile inventory to the seam."""
    payload = _normal_semantics_payload()
    payload["unsafe_outcome"]["semantic_proposition"] = (
        "The assistant initiates the process_refund operation for order ORD-104 "
        "despite refund_eligible being false."
    )
    payload["unsafe_outcome"]["discriminating_condition"] = _profile_condition()
    result = _publish(
        [payload],
        tmp_path,
        execution_target_profile=_profile(),
        target_observations=_observations(),
    )

    assert result.candidate_outcomes[0].status is SP3CandidateStatus.published
    document = _published_handoff(tmp_path)
    assert len(document["documented_operations"]) == 1
    operation = document["documented_operations"][0]
    assert operation["name"] == "process_refund"
    assert operation["authority"] == "criterion_observed_operation"
    assert "observed operation inventory" in operation["relevance"]


def test_generic_capability_labels_never_substitute_for_observed_operations(
    tmp_path: Path,
) -> None:
    """Generic service labels stay out of the binding-operation view."""
    payload = _normal_semantics_payload()
    payload["unsafe_outcome"]["semantic_proposition"] = (
        "The assistant uses Klarna Backend Services API for order ORD-104."
    )
    result = _publish([payload], tmp_path)
    envelope = result.scenario_envelopes[0]

    handoff = build_scenario_handoff(
        envelope,
        observed_operations=("process_refund", "lookup_order"),
        environment_bound=True,
    )

    assert handoff.documented_operations == []


def test_ambiguous_or_unobserved_criterion_tokens_contribute_no_authority(
    tmp_path: Path,
) -> None:
    """Multiple candidates and absent candidates fail closed."""
    payload = _normal_semantics_payload()
    payload["unsafe_outcome"]["semantic_proposition"] = (
        "The assistant may use process_refund or schedule_payment for order ORD-104."
    )
    result = _publish([payload], tmp_path)
    envelope = result.scenario_envelopes[0]

    ambiguous = build_scenario_handoff(
        envelope,
        observed_operations=("process_refund", "schedule_payment"),
        environment_bound=True,
    )
    absent = build_scenario_handoff(
        envelope,
        observed_operations=("lookup_order",),
        environment_bound=True,
    )

    assert ambiguous.documented_operations == []
    assert absent.documented_operations == []


def test_unbound_handoff_records_the_operation_inventory_as_unknown(
    tmp_path: Path,
) -> None:
    """Only a handoff built without a target profile states the unknown inventory."""
    result = _publish([_normal_semantics_payload()], tmp_path)
    envelope = result.scenario_envelopes[0]
    unbound_unknown = (
        "No execution target profile was supplied, so the operation inventory "
        "is unknown and the named operations remain logical roles rather than "
        "observed operations."
    )

    unbound = build_scenario_handoff(envelope, environment_bound=False)
    bound = build_scenario_handoff(envelope, environment_bound=True)

    assert unbound.assumptions_and_unknowns[-1] == unbound_unknown
    assert unbound.assumptions_and_unknowns[:-1] == bound.assumptions_and_unknowns
    assert unbound_unknown not in bound.assumptions_and_unknowns


def test_unenriched_handoff_is_byte_identical(tmp_path: Path) -> None:
    """Absent or non-matching enrichment rows change nothing in the bytes."""
    baseline = tmp_path / "baseline"
    empty = tmp_path / "empty"
    other_action = tmp_path / "other-action"
    _publish([_normal_semantics_payload()], baseline)
    _publish([_normal_semantics_payload()], empty, enriched_operations={})
    _publish(
        [_normal_semantics_payload()],
        other_action,
        enriched_operations={"CA-9-9": "other_operation"},
    )

    for filename in ("SCN-001.yaml", "SCN-001.feature"):
        reference = (baseline / "scenarios" / filename).read_bytes()
        assert (empty / "scenarios" / filename).read_bytes() == reference
        assert (other_action / "scenarios" / filename).read_bytes() == reference


def test_documented_operations_resolve_against_the_profile_inventory(
    tmp_path: Path,
) -> None:
    """Mirror of the consumer's ``_resolve_detector_tool``: the live envelope
    resolves against the observed profile inventory the same way the M1
    contract fixture does, so no ``unsupported-observation`` exclusion blocks
    an enriched adversarial scenario."""
    inventory_names = {
        "process_refund",
        "lookup_order",
        "get_klarna_state_summary",
    }

    def _matches(payload: dict) -> list[str]:
        named = [operation["name"] for operation in payload["documented_operations"]]
        return [name for name in named if name in inventory_names]

    _publish(
        [_normal_semantics_payload()],
        tmp_path,
        enriched_operations={"CA-1-1": "process_refund"},
    )
    live = _published_handoff(tmp_path)

    assert _matches(live) == ["process_refund"]

    # The M1 contract fixture carries the same expectation by hand.
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "data/contracts/scenario-handoff/handoff-v1/valid/adversarial-refund.json"
    )
    fixture = json.loads(fixture_path.read_text(encoding="utf-8"))
    assert _matches(fixture) == ["process_refund"]
