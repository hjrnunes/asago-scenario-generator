"""R5 regressions for declarative, semantics-only Gherkin publication."""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
from tempfile import TemporaryDirectory

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
from asago_scenario_generator.stpa.scenario_prod.validators import (
    validate_gherkin_correspondence,
    validate_gherkin_structure,
)
from tests.stpa.test_stpa_execution_bundle_producer import _spec


def _refund_spec():
    return _spec().model_copy(
        update={
            "unsafe_outcome_semantic_proposition": (
                "The assistant issues a refund command for the selected order."
            )
        }
    )


def test_r5_gherkin_uses_actual_refund_trigger_and_safe_expected_sequence():
    _narrative, _tree, gherkin = render_scenario_summary(_refund_spec())

    assert gherkin.when == [
        "When the customer requests a refund for the selected order"
    ]
    assert all(not step.lower().startswith("but ") for step in gherkin.then_expected)
    native = gherkin.to_feature_text()
    assert "When the customer requests a refund for the selected order" in native
    assert "  But " not in native
    assert "# Unsafe alternative (non-executable):" in native


@pytest.mark.parametrize(
    ("criterion", "trigger"),
    (
        (
            "The clinician commits the clinical record to the EHR.",
            "When the clinician requests that the clinical record be committed to the EHR",
        ),
        (
            "The assistant changes the selected reservation.",
            "When the actor requests authorization to modify the selected booking",
        ),
    ),
)
def test_r5_gherkin_uses_domain_trigger_for_clinical_and_booking(
    criterion: str, trigger: str
):
    spec = _spec().model_copy(update={"unsafe_outcome_semantic_proposition": criterion})

    _narrative, _tree, gherkin = render_scenario_summary(spec)

    assert gherkin.when == [trigger]


def test_r5_native_rendering_corresponds_to_structured_executable_steps():
    _narrative, _tree, gherkin = render_scenario_summary(_refund_spec())

    result = validate_gherkin_correspondence(gherkin, gherkin.to_feature_text())

    assert result.passed, result.errors


def test_r5_native_feature_parses_with_pinned_gherkin_parser():
    _narrative, _tree, gherkin = render_scenario_summary(_refund_spec())
    aps_root = Path(
        os.environ.get(
            "ASAGO_SCENARIO_GENERATOR_APS_ROOT",
            "/Users/hjrnunes/workspace/redhat/hjrnunes/asago-scenario-generator/"
            ".cache/acceptance-pipeline-specification",
        )
    )
    if not aps_root.is_dir() or not shutil.which("bb"):
        pytest.skip("pinned APS parser is unavailable")

    with TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        feature_path = tmp / "scenario.feature"
        ir_path = tmp / "scenario.json"
        feature_path.write_text(gherkin.to_feature_text(), encoding="utf-8")
        subprocess.run(
            ["bb", "gherkin-parser", str(feature_path), str(ir_path)],
            cwd=aps_root,
            check=True,
            capture_output=True,
            text=True,
        )
        parsed = json.loads(ir_path.read_text(encoding="utf-8"))

    steps = parsed["scenarios"][0]["steps"]
    assert any(
        step["text"] == "the customer requests a refund for the selected order"
        for step in steps
    )
    assert all(step["keyword"].lower() != "but" for step in steps)


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


def test_r5_native_validation_rejects_blank_heading_names():
    native = """Feature:
Scenario: Safe orchestration
  Given PM-1-1 is a hypothesis
  When the customer requests a refund
  Then the system should reject the request
  # Unsafe alternative (non-executable): But the system approves the request
"""

    result = validate_gherkin_structure(native)

    assert not result.passed
    assert any("non-empty names" in error for error in result.errors)


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
        "Scenario: SCN-001\n"
        "  Given PM-1-1 is a hypothesis\n"
        "  When the customer requests a refund\n"
        "  Then the system should reject the request\n"
        "  # Unsafe alternative (non-executable): But the system approves the request\n"
    )
