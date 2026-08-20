"""Tests for projection-aware projected step-ID echo normalization.

Covers the accepted transport shapes, order preservation, stable
ValueError rejection of unknown/ambiguous/non-string shapes, and
duplicate canonical identity detection (taxonomy step-ID transport
normalization).
"""

from __future__ import annotations

import pytest

from asago_scenario_generator.pipeline.generate.step_ids import (
    normalize_projected_step_ids,
)

CANONICAL = ("step.1", "attacker.prepare", "system.transform")


# ---------------------------------------------------------------------------
# Accepted echo shapes (feature 01)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("echo_item", "canonical_step_id"),
    [
        ("attacker.prepare", "attacker.prepare"),
        ({"step_id": "attacker.prepare"}, "attacker.prepare"),
        ("step_id: attacker.prepare", "attacker.prepare"),
        ("step.attacker.prepare", "attacker.prepare"),
        ("step.1", "step.1"),
        ("step.step.1", "step.1"),
    ],
)
def test_normalizes_each_accepted_echo_shape(echo_item, canonical_step_id):
    normalized = normalize_projected_step_ids([echo_item], CANONICAL)
    assert normalized == (canonical_step_id,)


def test_preserves_mixed_shape_order():
    items = [
        "step.system.transform",
        "step_id: attacker.prepare",
        "step.1",
    ]
    assert normalize_projected_step_ids(items, CANONICAL) == (
        "system.transform",
        "attacker.prepare",
        "step.1",
    )


# ---------------------------------------------------------------------------
# Duplicate canonical identities (feature 03)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "echo_items",
    [
        ["attacker.prepare", {"step_id": "attacker.prepare"}],
        ["step.attacker.prepare", "step_id: attacker.prepare"],
    ],
)
def test_rejects_duplicate_canonical_identity(echo_items):
    with pytest.raises(ValueError, match="duplicate canonical step ID") as excinfo:
        normalize_projected_step_ids(echo_items, CANONICAL)
    assert "attacker.prepare" in str(excinfo.value)
    assert not isinstance(excinfo.value, TypeError)


# ---------------------------------------------------------------------------
# Unknown / ambiguous / malformed shapes (feature 04)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("echo_item", "rejection"),
    [
        ("unknown.step", "unknown canonical ID"),
        ("step.unknown.step", "unknown canonical ID"),
        ("step_id: step.attacker.prepare", "ambiguous prefix shape"),
        ({"step_id": 7}, "non-string step_id"),
        ({"id": "attacker.prepare"}, "unknown object shape"),
        (["attacker.prepare"], "nested sequence shape"),
        (7, "non-string item"),
    ],
)
def test_rejects_unknown_or_ambiguous_echo_shapes(echo_item, rejection):
    with pytest.raises(ValueError, match=rejection) as excinfo:
        normalize_projected_step_ids([echo_item], CANONICAL)
    assert not isinstance(excinfo.value, TypeError)


def test_rejection_identifies_the_concrete_unknown_id():
    with pytest.raises(ValueError, match="unknown canonical ID 'unknown.step'"):
        normalize_projected_step_ids(["unknown.step"], CANONICAL)


def test_duplicate_detection_raises_before_any_publish():
    """A duplicate canonical identity must be a stable ValueError and never
    produce a finalized tuple of projected IDs."""
    with pytest.raises(ValueError):
        normalize_projected_step_ids(["attacker.prepare", "step.attacker.prepare"], CANONICAL)


def test_empty_items_returns_empty_tuple():
    assert normalize_projected_step_ids([], CANONICAL) == ()
