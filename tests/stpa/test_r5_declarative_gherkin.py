"""R5 regressions for declarative, semantics-only Gherkin publication."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.scenario_context import DescribedElement
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
    AttackerBDI,
)
from asago_scenario_generator.stpa.scenario_prod.handoff import HandoffGherkin
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_summary,
)
from tests.helpers.stpa_producer_seams import _spec


def _refund_spec():
    return _spec().model_copy(
        update={
            "unsafe_outcome_semantic_proposition": (
                "The assistant issues a refund command for the selected order."
            )
        }
    )


def _action_description(spec) -> str:
    context = spec.scenario_context
    assert context is not None
    return context.target_control_path.control_action.description


def test_r5_gherkin_derives_trigger_from_selected_action_and_keeps_safe_sequence():
    spec = _refund_spec()
    _narrative, _tree, gherkin = render_scenario_summary(spec)

    expected = f"When the actor requests {_action_description(spec).rstrip('.')}"
    assert gherkin.when == [expected]
    assert all(not step.lower().startswith("but ") for step in gherkin.then_expected)
    native = gherkin.to_feature_text()
    assert expected in native
    assert "  But " not in native
    assert "# Unsafe alternative (non-executable):" in native


@pytest.mark.parametrize(
    "criterion",
    (
        "The assistant issues a refund command for the selected order.",
        "The clinician commits the clinical record to the EHR.",
        "The assistant changes the selected reservation.",
        "The assistant renews a loan for a suspended library member.",
    ),
)
def test_r5_gherkin_trigger_does_not_depend_on_criterion_vocabulary(criterion: str):
    baseline = render_scenario_summary(_spec())[2].when
    spec = _spec().model_copy(update={"unsafe_outcome_semantic_proposition": criterion})

    _narrative, _tree, gherkin = render_scenario_summary(spec)

    assert gherkin.when == baseline
    assert gherkin.when == [
        f"When the actor requests {_action_description(spec).rstrip('.')}"
    ]


_STEP_KEYWORDS = ("Given", "When", "Then", "And")


def _feature_problems(feature_text: str, trigger: str) -> list[str]:
    """Return the structural defects of a rendered feature file.

    This mirrors what the downstream Gherkin parser requires of the published
    text: one Feature, one Scenario, only Given/When/Then/And steps (no But),
    and the trigger as a When step.
    """
    lines = [line.strip() for line in feature_text.splitlines() if line.strip()]
    problems: list[str] = []
    if not lines or not lines[0].startswith("Feature:"):
        problems.append("the first line is not a Feature line")
    scenarios = [i for i, line in enumerate(lines) if line.startswith("Scenario:")]
    if len(scenarios) != 1:
        problems.append(f"expected one Scenario line, found {len(scenarios)}")
    steps: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line.startswith(("Scenario:", "Background:", "#")):
            continue
        keyword, _, text = line.partition(" ")
        if keyword not in _STEP_KEYWORDS or not text:
            problems.append(f"not a step line: {line!r}")
        else:
            steps.append((keyword, text))
    if ("When", trigger) not in steps:
        problems.append(f"no When step carries the trigger {trigger!r}")
    return problems


def test_r5_native_feature_is_structurally_well_formed():
    _narrative, _tree, gherkin = render_scenario_summary(_refund_spec())
    trigger = gherkin.when[0].removeprefix("When ")

    assert _feature_problems(gherkin.to_feature_text(), trigger) == []


_WELL_FORMED = """Feature: Refunds
  Background:
    Given an order exists
  Scenario: Refund request
    When the actor requests a refund
    Then the order stays unchanged
    # Unsafe alternative (non-executable): But the refund is issued
"""


@pytest.mark.parametrize(
    ("feature_text", "expected_problem"),
    (
        pytest.param(
            _WELL_FORMED.replace("Feature: Refunds", "Refunds"),
            "the first line is not a Feature line",
            id="no-feature-line",
        ),
        pytest.param(
            _WELL_FORMED.replace("  Scenario: Refund request\n", ""),
            "expected one Scenario line, found 0",
            id="no-scenario-line",
        ),
        pytest.param(
            _WELL_FORMED.replace("Then the order", "But the order"),
            "not a step line: 'But the order stays unchanged'",
            id="but-step",
        ),
        pytest.param(
            _WELL_FORMED.replace(
                "When the actor requests a refund", "the actor requests a refund"
            ),
            "not a step line: 'the actor requests a refund'",
            id="step-without-keyword",
        ),
        pytest.param(
            _WELL_FORMED.replace("requests a refund", "requests a cancellation"),
            "no When step carries the trigger 'the actor requests a refund'",
            id="trigger-missing",
        ),
        pytest.param(
            _WELL_FORMED.replace("When the", "Then the", 1),
            "no When step carries the trigger 'the actor requests a refund'",
            id="trigger-not-a-when-step",
        ),
    ),
)
def test_r5_feature_check_rejects_broken_features(
    feature_text: str, expected_problem: str
):
    trigger = "the actor requests a refund"

    assert _feature_problems(_WELL_FORMED, trigger) == []
    assert expected_problem in _feature_problems(feature_text, trigger)


def test_r5_multiple_preconditions_are_separate_and_hypothesized():
    spec = _refund_spec()
    context = spec.scenario_context
    assert context is not None
    path = context.target_control_path.model_copy(
        update={
            "process_model_parts": (
                *context.target_control_path.process_model_parts,
                DescribedElement(
                    element_id="PM-1-2",
                    description="The selected order remains eligible",
                ),
            )
        }
    )
    spec = spec.model_copy(
        update={
            "scenario_context": context.model_copy(update={"target_control_path": path})
        }
    )

    _narrative, _tree, gherkin = render_scenario_summary(spec)

    assert len(gherkin.given) == 2
    assert "PM-1-1" in gherkin.given[0]
    assert "PM-1-2" in gherkin.given[1]
    assert all("hypothesis" in step.lower() for step in gherkin.given)
    assert all("Constraint" not in step for step in gherkin.given)


def test_r5_functional_gherkin_keeps_structural_context_without_attacker():
    spec = _refund_spec().model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.none,
                gain="The requested service completes as designed.",
                reaches_target_via=None,
            ),
            "attacker_bdi": AttackerBDI(beliefs=[], desires=[], intentions=[]),
        }
    )

    _narrative, _tree, gherkin = render_scenario_summary(spec)
    native = gherkin.to_feature_text().lower()

    assert "refund" in native
    assert "attacker" not in native
    assert "# unsafe alternative (non-executable):" in native


def test_r5_constraint_text_keeps_exact_two_sentence_boundary():
    spec = _refund_spec()
    context = spec.scenario_context
    assert context is not None
    statement = f"{'A' * 190}. {'B' * 8}"
    constraints = tuple(
        item.model_copy(update={"description": statement})
        for item in context.constraints
    )
    spec = spec.model_copy(
        update={
            "scenario_context": context.model_copy(update={"constraints": constraints})
        }
    )

    _narrative, _tree, gherkin = render_scenario_summary(spec)

    assert gherkin.then_expected == [
        f"Then the system should preserve SC-1: {statement}"
    ]


def test_r5_constraint_text_truncates_long_first_sentence():
    spec = _refund_spec()
    context = spec.scenario_context
    assert context is not None
    first_sentence = "A" * 220
    statement = f"{first_sentence}. The second sentence is omitted."
    constraints = tuple(
        item.model_copy(update={"description": statement})
        for item in context.constraints
    )
    spec = spec.model_copy(
        update={
            "scenario_context": context.model_copy(update={"constraints": constraints})
        }
    )

    _narrative, _tree, gherkin = render_scenario_summary(spec)

    assert gherkin.then_expected == [
        f"Then the system should preserve SC-1: {'A' * 200}"
    ]


def test_r5_handoff_rendering_keeps_unsafe_alternatives_non_executable():
    gherkin = HandoffGherkin(
        feature="Safe orchestration",
        scenario="SCN-001",
        given=["Given PM-1-1 is a hypothesis"],
        when=["When the customer requests a refund"],
        then_expected=["Then the system should reject the request"],
        then_unsafe_alternative=["But the system approves the request"],
    )

    assert gherkin.to_feature_text() == (
        "Feature: Safe orchestration\n"
        "  Background:\n"
        "    Given PM-1-1 is a hypothesis\n"
        "  Scenario: SCN-001\n"
        "    When the customer requests a refund\n"
        "    Then the system should reject the request\n"
        "    # Unsafe alternative (non-executable): But the system approves the request\n"
    )
