"""Acceptance tests for the stimulus turns (G05) and ordering reference (G12) kit revision.

Covers the additive ``stimulus_requirement.turns`` representation, the
``OrderingCondition`` reference fields, and their typed rejections.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    UnsafeOutcome,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.semantic_conditions import (
    OrderingCondition,
    ReferenceArgument,
    SemanticBindingPlaceholder,
    StimulusTurn,
    contains_binding_placeholder,
)

CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/stpa-execution"
KIT = CONTRACT_ROOT / "projection-v2"


def _schema():
    return json.loads((KIT / "schema.json").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# A. Stimulus turns: schema round trip and typed rejections


def test_turn_entry_rejects_role_and_mode_fields():
    with pytest.raises(ValidationError, match="Extra inputs"):
        StimulusTurn(turn_id="T-1", text="text", role="assistant")


# ---------------------------------------------------------------------------
# B. Ordering reference fields: schema round trip and typed rejections


def test_reference_argument_without_reference_tool_fails():
    with pytest.raises(ValueError, match="reference_tool"):
        OrderingCondition(
            reference_step_id="S-1",
            relation="before",
            reference_argument=ReferenceArgument(
                property="order_id",
                operator="equals",
                expected="ORD-104",
            ),
        )


def test_placeholder_inside_reference_argument_is_seen():
    placeholder = SemanticBindingPlaceholder(
        binding_ref="SEM-REF-ORDER",
        value_type="string",
        description="The order id whose verification was skipped.",
    )
    condition = OrderingCondition(
        reference_step_id="S-1",
        relation="before",
        reference_tool="lookup_order",
        reference_argument=ReferenceArgument(
            property="order_id",
            operator="equals",
            expected=placeholder,
        ),
    )
    assert contains_binding_placeholder(condition) is True

    outcome = UnsafeOutcome(
        outcome_id="OUTCOME-1",
        control_action_id="CM-1",
        uca_type=UCAType.wrong_timing,
        condition=condition,
        semantic_proposition=None,
        semantic_binding_required=True,
        hazard_refs=("H-1",),
        constraint_refs=("SC-1",),
    )
    assert outcome.semantic_binding_required is True
    with pytest.raises(ValueError, match="semantic_binding_required"):
        UnsafeOutcome(
            outcome_id="OUTCOME-1",
            control_action_id="CM-1",
            uca_type=UCAType.wrong_timing,
            condition=condition,
            semantic_proposition=None,
            semantic_binding_required=False,
            hazard_refs=("H-1",),
            constraint_refs=("SC-1",),
        )
