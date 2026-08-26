"""Adversarial branch tests for architect-split validation and evaluation leaves."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.eval.versioned_metrics import (
    _V3ScenarioCounters,
    _accumulate_v3_conditional_stats,
    _accumulate_v3_projection_mappings,
    _accumulate_v3_zone_differences,
    _build_v3_agreement_metrics,
    _build_v3_diagnostics,
    _build_v3_presence_metrics,
    _build_v3_validity_metrics,
    _collect_v3_admission_failures,
    _collect_v3_quarantine_reasons,
    _collect_v3_scenario_items,
    _evidence_outcome,
    _malformed_evidence_decision,
    _resolver_orphan_fact,
    _v3_receipt_pair_stats,
    _v3_structural_signature_match,
)
from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
)
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline import finalization_prebehavior
from asago_scenario_generator.pipeline.finalization_gate_contracts import (
    AdmissionEvidenceId,
    GateCode,
    GateResult,
)
from asago_scenario_generator.pipeline.finalization_prebehavior import (
    _ambiguous_postcondition_violation,
    _build_prebehavior_block,
    _complexity_gate_violation,
    _conflicting_owner,
    _diagnostic_gates,
    _narrative_duplicate_violation,
    _narrative_realization_gate_violations,
    _tree_realization_gate_violations,
    _tree_realization_violation,
    run_prebehavior_gates,
)
from tests.helpers.realization_helper import make_realizations


def _narrative(
    *projected_step_ids: str,
    realization: NarrativeAccessRealization | None = None,
    step_count: int = 1,
) -> NarrativeLayer:
    if not projected_step_ids:
        projected_step_ids = ("step.1",)
    steps = [
        NarrativeStep(
            step_number=index,
            zone="input",
            action=f"action-{index}",
            effect=f"effect-{index}",
            projected_step_ids=(
                projected_step_ids if index == 1 else (f"step.{index}",)
            ),
        )
        for index in range(1, step_count + 1)
    ]
    return NarrativeLayer(
        title="Test",
        summary="A test scenario.",
        entry_point="user prompts",
        zone_sequence=["input"],
        steps=steps,
        access_realization=realization,
    )


def _actor(access: ActorAccessProvenance) -> ActorProfile:
    return ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=["observed"],
        desires=["impact"],
        intentions=["inject"],
        resources=["access"],
        access=access,
    )


def _indirect_access(**updates: object) -> ActorAccessProvenance:
    values: dict[str, object] = {
        "initial_entry_point_id": "ep:v1:initial",
        "ingress_mode": "indirect",
        "access_class": "supply_chain",
        "influence_source": "ep:v1:source",
        "influence_mechanism": "poisoning",
        "trust_boundary_id": "tb:v1:boundary",
    }
    values.update(updates)
    return ActorAccessProvenance(**values)


def _leaf_tree() -> AttackTree:
    leaf = AttackTreeNode(
        id="n1",
        label="Perform action",
        gate=GateType.LEAF,
        zone="input",
        action=AiSystemAction(),
        projected_step_ids=("step.1",),
        realizations=make_realizations(("step.1",)),
    )
    return AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="change the target",
        root=leaf,
    )


def test_conflicting_owner_distinguishes_same_and_different_steps() -> None:
    postcondition = SimpleNamespace(postcondition_id="pc")
    same_step = SimpleNamespace(step_id="step-1")
    other_step = SimpleNamespace(step_id="step-2")

    assert _conflicting_owner({"pc": "step-1"}, postcondition, same_step) is None
    assert _conflicting_owner({"pc": "step-1"}, postcondition, other_step) == "step-1"


def test_ambiguous_postcondition_is_rejected_across_selected_steps() -> None:
    postcondition = SimpleNamespace(postcondition_id="pc")
    candidate = SimpleNamespace(
        projection=SimpleNamespace(
            selected_step_ids=("step-1", "step-2"),
            source_chain=SimpleNamespace(
                steps=[
                    SimpleNamespace(
                        step_id="step-1",
                        observable_postconditions=(postcondition,),
                    ),
                    SimpleNamespace(
                        step_id="step-2",
                        observable_postconditions=(postcondition,),
                    ),
                ]
            ),
        )
    )

    violation = _ambiguous_postcondition_violation(candidate)

    assert violation is not None
    assert violation.code is GateCode.candidate_identity
    assert "ambiguous owners" in violation.detail


def test_prebehavior_helpers_cover_duplicate_and_reordered_realizations() -> None:
    narrative = SimpleNamespace(
        steps=[
            SimpleNamespace(
                step_number=1,
                projected_step_ids=("step.1", "step.1"),
            )
        ]
    )
    assert _narrative_duplicate_violation(narrative) is not None

    tree = _leaf_tree()
    assert _tree_realization_violation(tree) is None
    duplicate = SimpleNamespace(
        id="n1",
        children=None,
        projected_step_ids=("step.1", "step.1"),
        realizations=(),
    )
    assert _tree_realization_violation(SimpleNamespace(root=duplicate)) is not None

    reordered = SimpleNamespace(
        id="n1",
        children=None,
        projected_step_ids=("step.1", "step.2"),
        realizations=(
            SimpleNamespace(projected_step_id="step.2"),
            SimpleNamespace(projected_step_id="step.1"),
        ),
    )
    assert _tree_realization_violation(SimpleNamespace(root=reordered)) is not None


def test_prebehavior_block_translates_builder_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    def fail(*_args: object, **_kwargs: object) -> object:
        raise ValueError("broken projection")

    monkeypatch.setattr(finalization_prebehavior, "_block", fail)
    result = _build_prebehavior_block(None, None, None, None)  # type: ignore[arg-type]

    assert isinstance(result, GateResult)
    assert result.violations[0].code is GateCode.tree_realization
    assert "broken projection" in result.violations[0].detail


def test_prebehavior_early_gate_and_optional_complexity_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    early = GateResult(AdmissionEvidenceId.structural_validity)
    monkeypatch.setattr(finalization_prebehavior, "_structural_prechecks", lambda *args: early)

    assert run_prebehavior_gates(None, None, None, None, None) is early  # type: ignore[arg-type]
    assert _complexity_gate_violation(None, None, None, False) is None  # type: ignore[arg-type]


def test_tree_and_narrative_empty_realization_gates_are_explicit() -> None:
    external_tree = AttackTree(
        id="tree-AP-T7-01",
        seed_id="AP-T7-01",
        goal="prepare access",
        root=AttackTreeNode(
            id="n1",
            label="Prepare externally",
            gate=GateType.LEAF,
            action=ExternalPreconditionAction(),
        ),
    )
    tree_codes = {
        item.code for item in _tree_realization_gate_violations(external_tree)
    }
    assert tree_codes == {
        GateCode.no_security_actions,
        GateCode.empty_realization,
    }

    candidate = SimpleNamespace(projection=SimpleNamespace(selected_step_ids=()))
    narrative_codes = {
        item.code
        for item in _narrative_realization_gate_violations(
            SimpleNamespace(steps=[SimpleNamespace(projected_step_ids=())]),
            candidate,
        )
    }
    assert GateCode.empty_realization in narrative_codes


def test_diagnostic_gates_report_zone_and_count_differences() -> None:
    diagnostics = _diagnostic_gates(_narrative("step.1", step_count=4), _leaf_tree())
    codes = {item.code for item in diagnostics}

    assert codes == {
        GateCode.heuristic_correspondence,
    }


@pytest.mark.parametrize(
    ("realization_kind", "access_kind"),
    [
        ("entry_point", None),
        (None, "entry_point"),
    ],
)
def test_narrative_source_kind_mismatch_does_not_disappear_on_empty_fallback(
    realization_kind: str | None,
    access_kind: str | None,
) -> None:
    access = _indirect_access(influence_source_kind=access_kind)
    realization = NarrativeAccessRealization(
        initial_entry_point_id=access.initial_entry_point_id,
        influence_source=access.influence_source,
        influence_source_kind=realization_kind,
        trust_boundary_id=access.trust_boundary_id,
        responsible_step_number=1,
    )

    violations = finalization_prebehavior.validate_narrative_access_realization(
        _narrative(realization=realization), _actor(access)
    )

    assert any(item.rule == "realization_influence_source_mismatch" for item in violations)


def test_narrative_typed_source_id_takes_precedence_over_legacy_fallback() -> None:
    access = _indirect_access(
        influence_source=None,
        influence_source_id="ep:v1:source",
    )
    realization = NarrativeAccessRealization(
        initial_entry_point_id=access.initial_entry_point_id,
        influence_source_id="ep:v1:source",
        trust_boundary_id=access.trust_boundary_id,
        responsible_step_number=1,
    )

    violations = finalization_prebehavior.validate_narrative_access_realization(
        _narrative(realization=realization), _actor(access)
    )

    assert violations == []


@pytest.mark.parametrize(
    ("realization_boundary", "access_boundary"),
    [
        ("tb:v1:boundary", None),
        (None, "tb:v1:boundary"),
    ],
)
def test_narrative_trust_boundary_mismatch_does_not_disappear_on_empty_fallback(
    realization_boundary: str | None,
    access_boundary: str | None,
) -> None:
    access = _indirect_access(trust_boundary_id=access_boundary)
    realization = NarrativeAccessRealization(
        initial_entry_point_id=access.initial_entry_point_id,
        influence_source=access.influence_source,
        trust_boundary_id=realization_boundary,
        responsible_step_number=1,
    )

    violations = finalization_prebehavior.validate_narrative_access_realization(
        _narrative(realization=realization), _actor(access)
    )

    assert any(item.rule == "realization_trust_boundary_mismatch" for item in violations)


def test_direct_narrative_access_rejects_indirect_source_reference() -> None:
    access = ActorAccessProvenance(
        initial_entry_point_id="ep:v1:initial",
        ingress_mode="direct",
        access_class="public",
    )
    realization = NarrativeAccessRealization(
        initial_entry_point_id=access.initial_entry_point_id,
        influence_source="ep:v1:source",
        trust_boundary_id="tb:v1:boundary",
        responsible_step_number=1,
    )

    violations = finalization_prebehavior.validate_narrative_access_realization(
        _narrative(realization=realization), _actor(access)
    )

    assert any(item.rule == "direct_realization_has_indirect_ref" for item in violations)


def test_narrative_access_realization_requires_an_existing_step() -> None:
    access = ActorAccessProvenance(
        initial_entry_point_id="ep:v1:initial",
        ingress_mode="direct",
        access_class="public",
    )
    realization = NarrativeAccessRealization(
        initial_entry_point_id=access.initial_entry_point_id,
        responsible_step_number=99,
    )

    violations = finalization_prebehavior.validate_narrative_access_realization(
        _narrative(realization=realization), _actor(access)
    )

    assert any(item.rule == "realization_step_not_found" for item in violations)


def test_metrics_use_default_non_strict_orphan_policy() -> None:
    result = _resolver_orphan_fact(SimpleNamespace(), evidence="orphan check")

    assert result.status.value == "not_applicable"


def test_malformed_evidence_checks_not_applicable_after_expected_flag() -> None:
    records = {
        AdmissionEvidenceId.actor_attack_complexity: [
            SimpleNamespace(applicable=False)
        ]
    }

    assert _malformed_evidence_decision(records, None) is True


def test_evidence_outcome_can_be_a_non_admitted_no_pass() -> None:
    decision = SimpleNamespace(admitted=False)
    records = {
        AdmissionEvidenceId.actor_attack_complexity: [
            SimpleNamespace(passed=True)
        ]
    }

    assert _evidence_outcome(decision, records) == "no_pass"


def test_metrics_collect_decision_and_gate_failure_categories() -> None:
    decision_violation = SimpleNamespace(code="decision-failure")
    gate_violation = SimpleNamespace(code="gate-failure")
    diagnostic = SimpleNamespace(code="diagnostic")
    decisions = [
        SimpleNamespace(
            candidate_id="candidate-1",
            admitted=False,
            violations=[decision_violation],
            gate_results=[
                SimpleNamespace(
                    violations=[gate_violation],
                    diagnostics=[diagnostic],
                )
            ],
        ),
        SimpleNamespace(
            candidate_id="candidate-2",
            admitted=True,
            violations=[],
            gate_results=[
                SimpleNamespace(
                    violations=[],
                    diagnostics=[SimpleNamespace(code="admitted-diagnostic")],
                )
            ],
        ),
    ]
    final = SimpleNamespace(admission_decisions=decisions)

    failures, diagnostic_failures = _collect_v3_admission_failures(final)
    quarantine = _collect_v3_quarantine_reasons(final)

    assert failures == {
        "decision-failure": {"candidate-1"},
        "gate-failure": {"candidate-1"},
    }
    assert diagnostic_failures == {
        "diagnostic": {"candidate-1"},
        "admitted-diagnostic": {"candidate-2"},
    }
    assert quarantine == {"decision-failure": {"candidate-1"}}


def test_presence_metrics_cover_unknown_and_bad_receipt_pairs() -> None:
    resolver = SimpleNamespace(
        check_orphans=True,
        scenario_feature_entries=lambda: [
            SimpleNamespace(scenario_id="scenario-a")
        ],
    )
    plan = SimpleNamespace(
        completeness="confirmed_complete",
        targets=[SimpleNamespace(entry_point_id="ep:v1:a")],
    )
    final = SimpleNamespace(
        admitted_inventory=[
            SimpleNamespace(scenario_id="scenario-a"),
            SimpleNamespace(scenario_id="scenario-a"),
            SimpleNamespace(scenario_id="scenario-b"),
        ]
    )
    metrics = _build_v3_presence_metrics(
        resolver,
        SimpleNamespace(run_id="run-1"),
        plan,
        final,
        [
            ("scenario-a", {"initial_entry_point_id": "ep:v1:a"}),
            ("scenario-b", {"initial_entry_point_id": "ep:v1:unknown"}),
        ],
    )

    assert metrics["canonical_entry_point_coverage"].numerator == 1
    assert metrics["unknown_entry_point_count"].numerator == 1
    assert metrics["missing_pair_count"].numerator == 2
    assert metrics["stale_or_orphan_artifact_count"].status.value == "pass"


def test_scenario_collection_handles_dict_and_non_dict_payloads() -> None:
    first = SimpleNamespace(scenario_id="scenario-a", path="a.yaml")
    second = SimpleNamespace(scenario_id=None, path="b.yaml")
    resolver = SimpleNamespace(
        scenario_yaml_entries=lambda: [first, second],
        read_yaml=lambda entry: {} if entry is first else [],
    )

    items, errors = _collect_v3_scenario_items(resolver)

    assert items == [("scenario-a", {})]
    assert errors == ["scenario-a", "b.yaml"]


def test_receipt_pair_stats_exposes_bad_and_present_scenario_ids() -> None:
    final = SimpleNamespace(
        admitted_inventory=[
            SimpleNamespace(scenario_id="scenario-a"),
            SimpleNamespace(scenario_id=None),
        ]
    )

    assert _v3_receipt_pair_stats(final) == (["scenario-a"], {"scenario-a"})


def test_validity_metrics_include_decision_gate_and_quarantine_categories() -> None:
    violation = SimpleNamespace(code="quarantine-code")
    gate = SimpleNamespace(
        gate=AdmissionEvidenceId.actor_attack_complexity,
        passed=False,
    )
    final = SimpleNamespace(
        admission_decisions=[
            SimpleNamespace(
                candidate_id="candidate-1",
                admitted=False,
                violations=[violation],
                gate_results=[gate],
            )
        ]
    )

    metrics = _build_v3_validity_metrics(
        [("scenario-1", {})],
        ["schema-error"],
        final,
        {"decision-code": {"candidate-1"}},
        {"diagnostic-code": {"candidate-1"}},
    )

    assert "admission_failure_rate:decision-code" in metrics
    assert "admission_failure_rate:diagnostic-code" in metrics
    assert "admission_gate_failure_rate:actor_attack_complexity" in metrics
    assert "kill_chain_quarantine_reason:quarantine-code" in metrics


def test_agreement_metrics_emit_status_metrics_for_each_mapping_decision() -> None:
    counters = _V3ScenarioCounters([("scenario-1", {})])
    counters.pinned_total = 1
    counters.pinned_found = 1
    counters.projected_total = 1
    counters.projected_all_found = 1
    counters.tree_behavior_matches = 1
    counters.conditional_total = 1
    counters.conditional_decided = 1
    counters.projection_mappings.update({"exact": 1, "unknown": 1})

    metrics = _build_v3_agreement_metrics(counters)

    assert "projection_mapping_status:exact" in metrics
    assert "projection_mapping_status:unknown" in metrics


def test_conditional_and_mapping_counters_record_negative_paths() -> None:
    counters = _V3ScenarioCounters([])
    _accumulate_v3_conditional_stats(
        counters,
        "scenario-1",
        {
            "projection": {
                "projection": {
                    "source_chain": {
                        "steps": [
                            {"step_id": "conditional", "requirement": "conditional"}
                        ]
                    },
                    "condition_results": [],
                }
            }
        },
    )
    _accumulate_v3_projection_mappings(
        counters,
        {"projection": {"projected_mappings": [{"mapping": {}}]}},
    )
    _accumulate_v3_zone_differences(
        counters,
        "scenario-1",
        {
            "narrative": {"steps": [{"zone": "input"}]},
            "attack_tree": {"root": {"zone": "memory"}},
        },
    )

    assert counters.conditional_problem_ids == ["scenario-1"]
    assert counters.projection_mappings["unknown"] == 1
    assert counters.zone_difference_ids == ["scenario-1"]


def test_diagnostics_include_title_structural_and_zone_components() -> None:
    counters = _V3ScenarioCounters(
        [("a", {}), ("b", {}), ("c", {}), ("d", {})]
    )
    counters.titles = {
        "a": "Prompt Injection Attack!",
        "b": "prompt injection attack",
        "c": "Prompt Injection Attack via API",
        "d": "Unrelated memory poisoning",
    }
    counters.structures = {
        "a": ("step.1",),
        "b": ("step.1",),
        "c": (),
        "d": ("step.2",),
    }
    counters.zone_difference_ids = ["c"]
    counters.zone_difference_sizes.update({0: 3, 1: 1})

    metrics = _build_v3_diagnostics(counters)

    assert metrics["exact_normalized_title_duplicate_count"].numerator == 1
    assert metrics["structural_graph_component_count"].numerator == 1
    assert metrics["narrative_tree_zone_difference_size:1"].numerator == 1


def test_empty_structural_signatures_are_not_duplicate_components() -> None:
    structures = {"empty-a": (), "empty-b": ()}

    assert _v3_structural_signature_match(structures, "empty-a", "empty-b") is False
