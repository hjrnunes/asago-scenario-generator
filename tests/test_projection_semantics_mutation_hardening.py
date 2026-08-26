"""Focused adversarial coverage for projection-semantic helpers."""

from __future__ import annotations

import re
from types import SimpleNamespace

from asago_scenario_generator.models.attack_pattern import ToolResourceReference
from asago_scenario_generator.models.attack_tree import (
    ImpactAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionTraceabilityViolationCode,
)
from asago_scenario_generator.pipeline.projection_semantics import (
    _behavior_leaf_kind,
    _behavior_leaf_keywords,
    _boundary_zone_summary,
    _check_action_texts_present,
    _check_assertion_texts_present,
    _check_leaf_boundary_compat,
    _check_leaf_resource_bindings,
    _check_leaf_tool_binding,
    _check_tree_leaf_external_precondition,
    _extract_step_text,
    _external_precondition_mapping_invalid,
    _gherkin_step_texts,
)
from tests.helpers.realization_helper import make_realizations


HEX32 = "a" * 32
TOOL_ID = f"tool:v1:{HEX32}"
ZONE_PATTERN = re.compile(r"\s*\([^)]*\)\s*$")


def _codes(violations: list) -> list[ProjectionTraceabilityViolationCode]:
    return [violation.code for violation in violations]


def _step(*, boundary_position: str = "inside") -> SimpleNamespace:
    return SimpleNamespace(
        step_id="step.1",
        boundary_position=boundary_position,
        action_kind="prepare",
        executor_role="attacker",
        produced=[],
        resource_links=[],
    )


def test_external_precondition_rejects_either_forbidden_payload() -> None:
    no_ids = SimpleNamespace(projected_step_ids=(), realizations=make_realizations(("x",)))
    no_realizations = SimpleNamespace(
        projected_step_ids=("step.1",), realizations=()
    )

    assert _external_precondition_mapping_invalid(no_ids, {}) is True
    assert _external_precondition_mapping_invalid(no_realizations, {}) is True
    assert (
        _external_precondition_mapping_invalid(
            SimpleNamespace(projected_step_ids=(), realizations=()),
            {},
        )
        is False
    )


def test_external_precondition_validator_reports_forbidden_payload() -> None:
    leaf = SimpleNamespace(
        id="external",
        action=SimpleNamespace(kind="external_precondition"),
        projected_step_ids=("step.1",),
        realizations=(),
    )
    violations = []

    _check_tree_leaf_external_precondition(leaf, {"step.1": "inside"}, violations)

    assert _codes(violations) == [
        ProjectionTraceabilityViolationCode.incorrect_resource_binding
    ]


def test_boundary_zone_summary_preserves_values_and_empty_sentinel() -> None:
    assert _boundary_zone_summary({"input", None}) == ["input"]
    assert _boundary_zone_summary(set()) == "None"


def test_external_impact_boundary_check_requires_outside_step() -> None:
    leaf = SimpleNamespace(id="impact", zone=None)
    action = ImpactAction(boundary="external", target="outside")

    valid = []
    _check_leaf_boundary_compat(leaf, action, _step(boundary_position="outside"), valid)
    assert valid == []

    invalid = []
    _check_leaf_boundary_compat(leaf, action, _step(boundary_position="inside"), invalid)
    assert _codes(invalid) == [
        ProjectionTraceabilityViolationCode.incorrect_resource_binding
    ]


def test_tool_binding_rejects_typed_mismatch_but_ignores_untyped_reference() -> None:
    leaf = SimpleNamespace(id="tool")
    action = ToolInvocationAction(tool_id=TOOL_ID)
    step = _step()
    link = SimpleNamespace(role="tool_fixture", slot_id="tool")
    typed_mismatch = ToolResourceReference(
        kind="tool", tool_id=f"tool:v1:{'b' * 32}"
    )

    mismatch = []
    _check_leaf_tool_binding(
        leaf, action, step, link, typed_mismatch, mismatch
    )
    assert _codes(mismatch) == [
        ProjectionTraceabilityViolationCode.incorrect_resource_binding
    ]

    untyped_mismatch = []
    _check_leaf_tool_binding(
        leaf,
        action,
        step,
        link,
        SimpleNamespace(tool_id=typed_mismatch.tool_id),
        untyped_mismatch,
    )
    assert untyped_mismatch == []


def test_resource_binding_checks_non_none_references() -> None:
    leaf = SimpleNamespace(id="tool")
    action = ToolInvocationAction(tool_id=TOOL_ID)
    link = SimpleNamespace(role="tool_fixture", slot_id="tool")
    step = SimpleNamespace(step_id="step.1", resource_links=[link])
    binding = ToolResourceReference(kind="tool", tool_id=f"tool:v1:{'b' * 32}")
    violations = []

    _check_leaf_resource_bindings(
        leaf,
        action,
        step,
        {"tool": binding},
        violations,
    )

    assert _codes(violations) == [
        ProjectionTraceabilityViolationCode.incorrect_resource_binding
    ]


def test_behavior_leaf_kind_handles_missing_and_actionless_sources() -> None:
    assert _behavior_leaf_kind({}, "missing") is None
    assert (
        _behavior_leaf_kind(
            {"leaf": SimpleNamespace(action=None)},
            "leaf",
        )
        is None
    )
    assert (
        _behavior_leaf_kind(
            {"leaf": SimpleNamespace(action=SimpleNamespace(kind="impact"))},
            "leaf",
        )
        == "impact"
    )


def test_behavior_leaf_keywords_cover_all_action_categories() -> None:
    assert _behavior_leaf_keywords("external_precondition") == {"Given"}
    assert _behavior_leaf_keywords("impact") == {"Then"}
    assert _behavior_leaf_keywords("tool_invocation") == {"When"}
    assert _behavior_leaf_keywords(None) == set()


def test_extract_step_text_removes_keyword_and_zone() -> None:
    assert _extract_step_text("When do thing (reasoning)", ZONE_PATTERN) == "do thing"
    assert _extract_step_text("Feature: ignored", ZONE_PATTERN) is None


def test_gherkin_step_texts_ignores_blank_and_non_step_lines() -> None:
    assert _gherkin_step_texts(
        "\nFeature: title\n  When do thing (reasoning)\n  # comment\n",
        ZONE_PATTERN,
    ) == ["do thing"]


def test_action_text_check_distinguishes_exact_substring_and_missing() -> None:
    actions = (
        SimpleNamespace(action_id="exact", text="do thing"),
        SimpleNamespace(action_id="substring", text="danger"),
        SimpleNamespace(action_id="missing", text="absent"),
    )
    violations = []

    _check_action_texts_present(
        actions,
        ["do thing", "perform danger now"],
        ZONE_PATTERN,
        violations,
    )

    assert [violation.element_id for violation in violations] == ["missing"]


def test_assertion_text_check_distinguishes_exact_substring_and_missing() -> None:
    assertions = (
        SimpleNamespace(assertion_id="exact", text="safe"),
        SimpleNamespace(assertion_id="substring", text="state"),
        SimpleNamespace(assertion_id="missing", text="absent"),
    )
    violations = []

    _check_assertion_texts_present(
        assertions,
        ["safe", "state is preserved"],
        violations,
    )

    assert [violation.element_id for violation in violations] == ["missing"]
