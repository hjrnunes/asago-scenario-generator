from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.eval.runner import run_evaluation
from asago_scenario_generator.eval.scorecard import (
    MetricResult,
    MetricStatus,
    QUALIFICATION_GATE_PATHS,
    REQUIRED_QUALIFICATION_GATE_IDS,
    ScorecardV1,
    aggregate_qualification,
    ratio_metric,
)
from asago_scenario_generator.eval.versioned_metrics import (
    _admission_evidence_metric,
    _admission_gate_failure_metrics,
    canonical_entry_point_sets,
    evaluate_v3_scorecard,
    inventory_identity_mismatches,
    title_duplicate_components,
)
from asago_scenario_generator.manifest import ArtifactRole, ManifestIntegrityError
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    InventoryCompleteness,
)
from asago_scenario_generator.pipeline.finalization_gates import AdmissionEvidenceId
from asago_scenario_generator.pipeline.persistence import (
    CoveragePlanV2,
    FinalizationInventoryV1,
    GateResultRecord,
)
from asago_scenario_generator.report.scorecard import build_scorecard_section
from tests.manifest_helpers import build_test_run_dir


@dataclass
class _Entry:
    role: ArtifactRole
    path: str
    scenario_id: str | None = None


class _Resolver:
    def __init__(self, *, confirmed: bool = False) -> None:
        self.manifest = SimpleNamespace(
            manifest_version="3",
            run_id="20260101T000000_abcdef0123456789abcdef0123456789",
        )
        self.plan = CoveragePlanV2(
            schema_version="2",
            completeness="confirmed_complete" if confirmed else "not_applicable",
            evidence_refs=["operator-review:test"] if confirmed else [],
            targets=[],
            selection_limitation_target_ids=[],
        )
        self.final = FinalizationInventoryV1(
            schema_version="1",
            run_id=self.manifest.run_id,
            coverage_plan_sha256="a" * 64,
            candidate_attempts=[],
            stage_attempts=[],
            transitions=[],
            repairs=[],
            admission_decisions=[],
            admitted_inventory=[],
            quarantine_inventory=[],
        )
        self.profile = CapabilityProfile(
            zones_active=["input"],
            entry_points=[EntryPoint(name="prompt", direction="input")],
            confidence=ConfidenceLevel.medium,
            kc_subcodes=["KC1.1"],
            entry_point_completeness=(
                InventoryCompleteness.operator_confirmed_complete
                if confirmed
                else InventoryCompleteness.inferred_partial
            ),
            entry_point_evidence=["operator-review:test"] if confirmed else [],
        )
        self.entries = {
            ArtifactRole.COVERAGE_PLAN: _Entry(
                ArtifactRole.COVERAGE_PLAN, "coverage-plan.json"
            ),
            ArtifactRole.FINALIZATION_INVENTORY: _Entry(
                ArtifactRole.FINALIZATION_INVENTORY, "finalization-inventory.json"
            ),
            ArtifactRole.CAPABILITY_PROFILE: _Entry(
                ArtifactRole.CAPABILITY_PROFILE, "capability-profile.yaml"
            ),
        }

    def entry_by_role(self, role: ArtifactRole) -> _Entry | None:
        return self.entries.get(role)

    def read_text(self, entry: _Entry) -> str:
        value = self.plan if entry.role is ArtifactRole.COVERAGE_PLAN else self.final
        return value.model_dump_json()

    def read_yaml(self, entry: _Entry) -> dict[str, Any]:
        assert entry.role is ArtifactRole.CAPABILITY_PROFILE
        return self.profile.model_dump(mode="json")

    def scenario_yaml_entries(self) -> list[_Entry]:
        return []

    def scenario_feature_entries(self) -> list[_Entry]:
        return []


def test_empty_denominator_is_not_applicable_and_has_no_value() -> None:
    result = ratio_metric(0, 0, evidence=["mutually empty projected sets"])
    assert result.status is MetricStatus.NOT_APPLICABLE
    assert result.value is None
    assert result.numerator == result.denominator == 0


def test_metric_values_are_bounded_and_exact() -> None:
    assert ratio_metric(1, 2, evidence=["test"]).value == 0.5
    with pytest.raises(ValueError, match="value must equal"):
        MetricResult(
            status=MetricStatus.PASS,
            numerator=1,
            denominator=2,
            value=0.75,
            evidence=["test"],
            affected_ids=[],
        )
    with pytest.raises(ValueError, match="pass metric is below threshold"):
        MetricResult(
            status=MetricStatus.PASS,
            threshold=1.0,
            numerator=1,
            denominator=2,
            value=0.5,
            evidence=["forged"],
            affected_ids=[],
        )
    with pytest.raises(ValueError, match="fail metric is at or above threshold"):
        MetricResult(
            status=MetricStatus.FAIL,
            threshold=0.5,
            numerator=1,
            denominator=2,
            value=0.5,
            evidence=["forged"],
            affected_ids=[],
        )


def test_aggregate_excludes_na_and_surfaces_errors() -> None:
    result = aggregate_qualification(
        {
            "pass": ratio_metric(1, 1, evidence=["x"]),
            "na": ratio_metric(0, 0, evidence=["x"]),
            "error": MetricResult(
                status=MetricStatus.ERROR,
                evidence=["broken source"],
                affected_ids=["s1"],
            ),
        }
    )
    assert result.status is MetricStatus.ERROR
    assert result.applicable_gate_count == 2
    assert result.passed_gate_count == 1
    assert result.not_applicable_gate_ids == ["na"]


def test_required_na_blocks_but_optional_na_does_not() -> None:
    passed = ratio_metric(1, 1, evidence=["required evidence"])
    not_applicable = ratio_metric(0, 0, evidence=["optional evidence"])
    result = aggregate_qualification(
        {"required": passed, "optional": not_applicable},
        required_gate_ids=frozenset({"required"}),
    )
    assert result.status is MetricStatus.PASS
    assert result.blocking_not_applicable_gate_ids == []

    blocked = aggregate_qualification(
        {"required": not_applicable, "optional": not_applicable},
        required_gate_ids=frozenset({"required"}),
    )
    assert blocked.status is MetricStatus.FAIL
    assert blocked.blocking_not_applicable_gate_ids == ["required"]


def test_admitted_artifact_with_empty_required_sets_cannot_qualify() -> None:
    result = aggregate_qualification(
        {
            "nonempty_admitted_inventory": MetricResult(
                status=MetricStatus.PASS,
                numerator=0,
                evidence=["one admitted artifact"],
                affected_ids=[],
            ),
            "pinned_technique_recall": ratio_metric(
                0, 0, evidence=["admitted artifact has no pinned techniques"]
            ),
            "projected_step_recall": ratio_metric(
                0, 0, evidence=["admitted artifact has no projected steps"]
            ),
        },
        required_gate_ids=frozenset(
            {
                "nonempty_admitted_inventory",
                "pinned_technique_recall",
                "projected_step_recall",
            }
        ),
    )
    assert result.status is MetricStatus.FAIL
    assert result.blocking_not_applicable_gate_ids == [
        "pinned_technique_recall",
        "projected_step_recall",
    ]


def test_exact_title_duplicates_differ_from_near_components() -> None:
    exact, near = title_duplicate_components(
        {
            "a": "Prompt Injection Attack!",
            "b": "prompt injection attack",
            "c": "Prompt Injection Attack via API",
            "d": "Unrelated memory poisoning",
        }
    )
    assert exact == [["a", "b"]]
    assert near == [["a", "b", "c"]]


def test_components_are_deterministic_across_input_order() -> None:
    first = {
        "a": "alpha beta gamma delta",
        "b": "alpha beta gamma delta x",
        "c": "alpha beta gamma delta x y",
    }
    second = dict(reversed(list(first.items())))
    assert title_duplicate_components(first) == title_duplicate_components(second)


def test_entry_point_coverage_uses_canonical_identity_only() -> None:
    covered, unknown = canonical_entry_point_sets(
        [
            {
                "initial_entry_point_id": "ep:v1:11111111111111111111111111111111",
                "narrative": {"entry_point": "misleading display name"},
            },
            {
                "initial_entry_point_id": "ep:v1:99999999999999999999999999999999",
                "narrative": {"entry_point": "known display name"},
            },
        ],
        {"ep:v1:11111111111111111111111111111111"},
    )
    assert covered == {"ep:v1:11111111111111111111111111111111"}
    assert unknown == {"ep:v1:99999999999999999999999999999999"}


@pytest.mark.parametrize(
    ("yaml_ids", "feature_ids", "receipt_ids", "expected"),
    [
        ({"A", "B"}, {"A", "B"}, {"A"}, {"B"}),
        ({"A"}, {"A"}, {"A", "B"}, {"B"}),
        ({"A"}, {"B"}, {"A"}, {"A", "B"}),
    ],
)
def test_inventory_coherence_is_symmetric(
    yaml_ids: set[str],
    feature_ids: set[str],
    receipt_ids: set[str],
    expected: set[str],
) -> None:
    assert inventory_identity_mismatches(yaml_ids, feature_ids, receipt_ids) == expected


def test_profile_completeness_controls_closed_world_gates() -> None:
    partial = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    complete = evaluate_v3_scorecard(_Resolver(confirmed=True))  # type: ignore[arg-type]
    assert (
        partial.release_qualification.metrics["capability_grounding"].status
        is MetricStatus.NOT_APPLICABLE
    )
    assert (
        complete.release_qualification.metrics["capability_grounding"].status
        is MetricStatus.NOT_APPLICABLE
    )
    assert "capability_grounding" not in (
        complete.qualification.blocking_not_applicable_gate_ids
    )


def test_empty_authoritative_sets_do_not_inflate_qualification() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    assert (
        scorecard.cross_artifact_agreement.metrics["pinned_technique_recall"].status
        is MetricStatus.NOT_APPLICABLE
    )
    assert (
        scorecard.cross_artifact_agreement.metrics["projected_step_recall"].status
        is MetricStatus.NOT_APPLICABLE
    )
    assert "pinned_technique_recall" in scorecard.qualification.not_applicable_gate_ids
    assert scorecard.qualification.status is MetricStatus.FAIL
    assert {
        "scenario_schema_validity",
        "pinned_technique_recall",
        "projected_step_recall",
        "tree_behavior_correspondence",
    } <= set(scorecard.qualification.blocking_not_applicable_gate_ids)
    assert "nonempty_admitted_inventory" in scorecard.qualification.failed_gate_ids


def test_scorecard_rejects_forged_qualification_aggregate() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    raw = scorecard.model_dump(mode="json")
    raw["qualification"]["passed_gate_count"] += 1
    with pytest.raises(ValueError, match="canonical scorecard gates"):
        ScorecardV1.model_validate(raw)


@pytest.mark.parametrize(
    ("gate_id", "mutation", "message"),
    [
        (
            "zero_quarantine",
            {"status": "pass", "numerator": 1},
            "forged status",
        ),
        (
            "pinned_technique_recall",
            {"threshold": 0.5},
            "requires threshold 1",
        ),
        (
            "capability_grounding",
            {
                "status": "pass",
                "numerator": 1,
                "denominator": 1,
                "value": 1.0,
                "threshold": 0.5,
            },
            "requires threshold 1",
        ),
    ],
)
def test_scorecard_rejects_forged_gate_semantics(
    gate_id: str, mutation: dict[str, Any], message: str
) -> None:
    scorecard = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    raw = scorecard.model_dump(mode="json")
    section, metric_id = QUALIFICATION_GATE_PATHS[gate_id]
    raw[section]["metrics"][metric_id].update(mutation)
    gates = {
        candidate_gate_id: MetricResult.model_validate(
            raw[candidate_section]["metrics"][candidate_metric_id]
        )
        for candidate_gate_id, (
            candidate_section,
            candidate_metric_id,
        ) in QUALIFICATION_GATE_PATHS.items()
    }
    raw["qualification"] = aggregate_qualification(
        gates, required_gate_ids=REQUIRED_QUALIFICATION_GATE_IDS
    ).model_dump(mode="json")
    with pytest.raises(ValueError, match=message):
        ScorecardV1.model_validate(raw)


def test_missing_gate_evidence_never_becomes_category_pass() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver(confirmed=True))  # type: ignore[arg-type]
    for metric_id in (
        "actor_attack_complexity",
        "capability_grounding",
        "tool_integration_grounding",
        "data_access_grounding",
        "catalog_taxonomy_pin_validity",
        "resource_binding_validity",
        "execution_requirement_drift",
        "zero_schema_identifier_phantom_parsimony_failures",
    ):
        assert (
            scorecard.release_qualification.metrics[metric_id].status
            is MetricStatus.NOT_APPLICABLE
        )
    assert not REQUIRED_QUALIFICATION_GATE_IDS.intersection(
        {
            "actor_attack_complexity",
            "capability_grounding",
            "tool_integration_grounding",
            "data_access_grounding",
        }
    )


def test_persisted_gate_identifier_rejects_arbitrary_strings() -> None:
    with pytest.raises(ValueError):
        GateResultRecord(
            gate="admission_gate_0",
            passed=True,
            violations=[],
            diagnostics=[],
            applicable=True,
        )


def test_admission_evidence_taxonomy_covers_every_cmps8_category() -> None:
    assert {
        AdmissionEvidenceId.actor_attack_complexity,
        AdmissionEvidenceId.capability_grounding,
        AdmissionEvidenceId.tool_integration_grounding,
        AdmissionEvidenceId.data_access_grounding,
        AdmissionEvidenceId.catalog_taxonomy_pin_validity,
        AdmissionEvidenceId.resource_binding_validity,
        AdmissionEvidenceId.execution_requirement_drift,
        AdmissionEvidenceId.identifier_validity,
    } <= set(AdmissionEvidenceId)


@pytest.mark.parametrize(
    ("records", "expected"),
    [
        ([True], MetricStatus.PASS),
        ([False], MetricStatus.FAIL),
        ([], MetricStatus.NOT_APPLICABLE),
        ([True, True], MetricStatus.NOT_APPLICABLE),
    ],
)
def test_category_metrics_require_one_exact_non_vacuous_outcome(
    records: list[bool], expected: MetricStatus
) -> None:
    gates = [
        GateResultRecord(
            gate=AdmissionEvidenceId.actor_attack_complexity,
            passed=passed,
            applicable=True,
            violations=[]
            if passed
            else [
                {
                    "code": "capability_complexity",
                    "detail": "failed",
                    "owner": "tree",
                    "retryable": True,
                }
            ],
            diagnostics=[],
        )
        for passed in records
    ]
    final = SimpleNamespace(
        admission_decisions=[
            SimpleNamespace(
                # A failed gate is a rejected postbehavior decision; missing
                # and duplicate evidence exercise malformed persistence-like
                # records without inventing an admitted+failed state.
                admitted=all(records),
                candidate_id="candidate-1",
                gate_results=gates,
            )
        ]
    )
    metric = _admission_evidence_metric(  # type: ignore[arg-type]
        final,
        (AdmissionEvidenceId.actor_attack_complexity,),
        evidence=["test"],
    )
    assert metric.status is expected


def test_admission_gate_failure_rate_counts_outcomes_in_both_units() -> None:
    failed_gate = GateResultRecord(
        gate=AdmissionEvidenceId.actor_attack_complexity,
        passed=False,
        applicable=True,
        violations=[
            {
                "code": "capability_complexity",
                "detail": "failed",
                "owner": "tree",
                "retryable": True,
            }
        ],
        diagnostics=[],
    )
    final = SimpleNamespace(
        admission_decisions=[
            SimpleNamespace(candidate_id=candidate_id, gate_results=[failed_gate])
            for candidate_id in ("candidate-1", "candidate-2")
        ]
    )
    metric = _admission_gate_failure_metrics(final)[  # type: ignore[arg-type]
        "admission_gate_failure_rate:actor_attack_complexity"
    ]
    assert metric.numerator == 2
    assert metric.denominator == 2
    assert metric.affected_ids == ["candidate-1", "candidate-2"]


def test_checked_in_schema_has_exact_generated_parity() -> None:
    path = (
        Path(__file__).resolve().parents[1]
        / "src/asago_scenario_generator/data/schemas/eval-scorecard-v1.schema.json"
    )
    assert json.loads(path.read_text()) == ScorecardV1.model_json_schema()


def test_report_renders_status_denominator_evidence_and_failures() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver()).model_dump(mode="json")  # type: ignore[arg-type]
    html = build_scorecard_section(scorecard)
    assert "Presence / Coverage" in html
    assert "Numerator / Denominator" in html
    assert "not_applicable" in html
    assert "Evidence" in html
    assert "Qualification failures" in html


def test_universal_kill_chain_metrics_are_explicit() -> None:
    scorecard = evaluate_v3_scorecard(_Resolver())  # type: ignore[arg-type]
    agreement = scorecard.cross_artifact_agreement.metrics
    release = scorecard.release_qualification.metrics
    assert {
        "projection_conditional_decision_coverage",
        "projection_mapping_coverage",
        "projected_step_recall",
        "exact_tree_behavior_correspondence",
    } <= agreement.keys()
    assert {
        "catalog_taxonomy_pin_validity",
        "resource_binding_validity",
        "execution_requirement_drift",
        "kill_chain_quarantine_reasons",
    } <= release.keys()


def test_normal_evaluation_rejects_legacy_manifest_without_writes(
    tmp_path: Path,
) -> None:
    run_dir = build_test_run_dir(tmp_path / "run")
    before = {
        path.relative_to(run_dir): path.read_bytes()
        for path in run_dir.rglob("*")
        if path.is_file()
    }
    with pytest.raises(ManifestIntegrityError, match="Unsupported manifest version"):
        run_evaluation(run_dir)
    after = {
        path.relative_to(run_dir): path.read_bytes()
        for path in run_dir.rglob("*")
        if path.is_file()
    }
    assert after == before
