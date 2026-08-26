"""Focused adversarial coverage for semantic narrative helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.generate.narrative_semantics import (
    _beat_boundary_violations,
    _beat_zone_violations,
    _narrative_access_realization,
    _narrative_handle_literal,
    _resolved_entry_point,
)


def test_narrative_handle_literal_rejects_empty_and_duplicate_handles() -> None:
    with pytest.raises(ValueError, match="non-empty"):
        _narrative_handle_literal(())
    with pytest.raises(ValueError, match="unique"):
        _narrative_handle_literal(("step.1", "step.1"))


def test_beat_zone_violations_report_one_based_beat_number() -> None:
    context = SimpleNamespace(
        projected_steps={
            "input": SimpleNamespace(zone="input"),
            "reasoning": SimpleNamespace(zone="reasoning"),
        }
    )
    beats = [SimpleNamespace(step_handles=["input", "reasoning"])]

    violations = _beat_zone_violations(beats, context)

    assert len(violations) == 1
    assert "causal beat 1" in violations[0].detail


def test_beat_boundary_violations_report_one_based_beat_number() -> None:
    context = SimpleNamespace(
        projected_steps={
            "outside": SimpleNamespace(
                realization=SimpleNamespace(boundary_position="outside")
            ),
            "inside": SimpleNamespace(
                realization=SimpleNamespace(boundary_position="inside")
            ),
        }
    )
    beats = [SimpleNamespace(step_handles=["outside", "inside"])]

    violations = _beat_boundary_violations(beats, context)

    assert len(violations) == 1
    assert "causal beat 1" in violations[0].detail


def test_resolved_entry_point_only_resolves_string_ingress_ids() -> None:
    profile = SimpleNamespace(
        resolve_entry_point=lambda _entry_point_id: SimpleNamespace(name="Resolved")
    )

    assert _resolved_entry_point(None, "ep:v1:abc", profile) == "Resolved"
    assert _resolved_entry_point("Pinned", None, profile) == "Pinned"
    assert _resolved_entry_point("", None, profile) == ""


def test_narrative_access_realization_requires_an_access_profile() -> None:
    access = SimpleNamespace(
        initial_entry_point_id="ep:v1:" + "a" * 32,
        influence_source="document",
        influence_source_kind="integration",
        influence_source_id="source:v1:" + "b" * 32,
        trust_boundary_id="tb:v1:" + "c" * 32,
    )

    assert _narrative_access_realization(None) is None
    assert _narrative_access_realization(SimpleNamespace(access=None)) is None

    realization = _narrative_access_realization(SimpleNamespace(access=access))
    assert realization is not None
    assert realization.initial_entry_point_id == access.initial_entry_point_id
    assert realization.responsible_step_number == 1
