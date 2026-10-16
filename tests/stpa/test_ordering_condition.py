"""Tests for the ordering reference (G12) value objects.

Covers the ``OrderingCondition`` reference fields with their typed rejections.
"""

from __future__ import annotations


import pytest

from asago_scenario_generator.stpa.models.semantic_conditions import (
    OrderingCondition,
    ReferenceArgument,
    SemanticBindingPlaceholder,
    contains_binding_placeholder,
)

# ---------------------------------------------------------------------------
# Ordering reference fields: typed rejections


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
