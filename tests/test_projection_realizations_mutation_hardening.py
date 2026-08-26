"""Focused adversarial coverage for projection-realization helpers."""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.models.attack_pattern import ToolResourceReference
from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    ExternalPreconditionAction,
)
from asago_scenario_generator.models.projection_envelope import (
    ArtifactRealizationMapping,
    ArtifactStage,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.pipeline.projection_realizations import (
    _check_order_preservation,
    _check_tool_integration_requirement,
    _integration_ids_satisfy,
    _invalid_technique_node_violations,
    _order_violation_for_pair,
    _security_bearing_leaf,
    _tool_binding_matches,
    _valid_atlas_technique_ids,
)


HEX32 = "a" * 32
TOOL_ID = f"tool:v1:{HEX32}"
INTEGRATION_ID = f"int:v1:{HEX32}"


def _mapping(
    *,
    decision: str = "exact",
    taxonomy: str = "ATLAS",
    ids: tuple[str, ...] = ("AML.T0001",),
) -> SimpleNamespace:
    return SimpleNamespace(
        mapping=SimpleNamespace(decision=decision, taxonomy=taxonomy, ids=ids)
    )


def _violation_codes(violations: list) -> list[ProjectionTraceabilityViolationCode]:
    return [violation.code for violation in violations]


def test_valid_atlas_ids_require_exact_atlas_mapping() -> None:
    block = SimpleNamespace(
        projected_mappings=(
            _mapping(ids=("AML.T0001",)),
            _mapping(taxonomy="LAAF", ids=("LAAF.T1",)),
            _mapping(decision="approximate", ids=("AML.T0002",)),
        )
    )

    assert _valid_atlas_technique_ids(block) == {"AML.T0001"}


def test_valid_atlas_ids_skip_mapping_without_decision() -> None:
    block = SimpleNamespace(
        projected_mappings=(
            SimpleNamespace(
                mapping=SimpleNamespace(taxonomy="ATLAS", ids=("AML.T0001",))
            ),
        )
    )

    assert _valid_atlas_technique_ids(block) == set()


def test_invalid_technique_check_flags_only_unmapped_nodes() -> None:
    tree = SimpleNamespace(
        root=SimpleNamespace(
            id="root",
            technique_id=None,
            children=[
                SimpleNamespace(id="valid", technique_id="AML.T0001", children=None),
                SimpleNamespace(id="invalid", technique_id="AML.T9999", children=None),
            ],
        )
    )
    violations = []

    _invalid_technique_node_violations(tree, {"AML.T0001"}, violations)

    assert len(violations) == 1
    assert violations[0].element_id == "invalid"
    assert (
        violations[0].code
        == ProjectionTraceabilityViolationCode.invalid_technique_mapping
    )


def test_tool_binding_requires_typed_matching_tool_reference() -> None:
    action = SimpleNamespace(tool_id=TOOL_ID)
    matching_ref = ToolResourceReference(kind="tool", tool_id=TOOL_ID)

    assert _tool_binding_matches(action, {"tool": matching_ref}, {"tool"})
    # A duck-typed object with a matching attribute is not a valid binding.
    assert not _tool_binding_matches(
        action,
        {"tool": SimpleNamespace(tool_id=TOOL_ID)},
        {"tool"},
    )
    assert not _tool_binding_matches(
        action,
        {"tool": ToolResourceReference(kind="tool", tool_id=f"tool:v1:{'b' * 32}")},
        {"tool"},
    )


def test_integration_requirement_requires_every_mapped_step() -> None:
    assert _integration_ids_satisfy(INTEGRATION_ID, {}) is True
    assert (
        _integration_ids_satisfy(
            INTEGRATION_ID,
            {"step.1": {INTEGRATION_ID}, "step.2": {INTEGRATION_ID}},
        )
        is False
    )
    assert (
        _integration_ids_satisfy(
            INTEGRATION_ID,
            {"step.1": {INTEGRATION_ID}, "step.2": {"int:v1:" + "b" * 32}},
        )
        is True
    )


def test_tool_integration_requirement_distinguishes_missing_valid_and_invalid() -> None:
    leaf = SimpleNamespace(id="leaf")
    mapped_steps = ("step.1",)

    missing = []
    _check_tool_integration_requirement(
        leaf,
        SimpleNamespace(integration_id=None),
        {"step.1": {INTEGRATION_ID}},
        mapped_steps,
        missing,
    )
    assert _violation_codes(missing) == [
        ProjectionTraceabilityViolationCode.incorrect_resource_binding
    ]

    no_requirement = []
    _check_tool_integration_requirement(
        leaf,
        SimpleNamespace(integration_id=None),
        {},
        mapped_steps,
        no_requirement,
    )
    assert no_requirement == []

    valid = []
    _check_tool_integration_requirement(
        leaf,
        SimpleNamespace(integration_id=INTEGRATION_ID),
        {"step.1": {INTEGRATION_ID}},
        mapped_steps,
        valid,
    )
    assert valid == []

    invalid = []
    _check_tool_integration_requirement(
        leaf,
        SimpleNamespace(integration_id="int:v1:" + "b" * 32),
        {"step.1": {INTEGRATION_ID}},
        mapped_steps,
        invalid,
    )
    assert _violation_codes(invalid) == [
        ProjectionTraceabilityViolationCode.incorrect_resource_binding
    ]


def test_external_precondition_is_not_security_bearing() -> None:
    external = SimpleNamespace(
        action=ExternalPreconditionAction(access_provenance="phishing")
    )
    attacker_action = SimpleNamespace(action=AiSystemAction())
    actionless = SimpleNamespace(action=None)

    assert _security_bearing_leaf(external) is False
    assert _security_bearing_leaf(attacker_action) is True
    assert _security_bearing_leaf(actionless) is False


def test_order_equality_boundary_is_not_a_reorder() -> None:
    elements = [
        ("first", 1, 2, ("step.1", "step.2")),
        ("second", 2, 3, ("step.3",)),
    ]

    assert (
        _order_violation_for_pair(
            elements,
            0,
            1,
            ProjectionTraceabilityStage.narrative,
            "narrative",
        )
        is None
    )


def test_order_check_does_not_compare_a_realization_with_itself() -> None:
    realizations = (
        ArtifactRealizationMapping(
            artifact_stage=ArtifactStage.narrative,
            element_id="1",
            projected_step_ids=("step.1", "step.2"),
        ),
    )

    assert (
        _check_order_preservation(
            realizations,
            {"step.1": 1, "step.2": 2},
            ProjectionTraceabilityStage.narrative,
            "narrative",
        )
        == []
    )


def test_order_check_flags_a_disjoint_reverse_pair() -> None:
    realizations = (
        ArtifactRealizationMapping(
            artifact_stage=ArtifactStage.narrative,
            element_id="first",
            projected_step_ids=("step.2",),
        ),
        ArtifactRealizationMapping(
            artifact_stage=ArtifactStage.narrative,
            element_id="second",
            projected_step_ids=("step.1",),
        ),
    )

    violations = _check_order_preservation(
        realizations,
        {"step.1": 1, "step.2": 2},
        ProjectionTraceabilityStage.narrative,
        "narrative",
    )

    assert [violation.element_id for violation in violations] == ["second"]
