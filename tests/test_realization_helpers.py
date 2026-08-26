"""Focused unit tests for the decomposed realization derivation helpers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.models.attack_pattern import (
    AgentInternalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)
from asago_scenario_generator.models.realization import (
    _consumed_ref_ids,
    _outcome_link_pc_ids,
    _postcondition_ids,
    _produced_effect_ids,
    _produced_ref_ids,
    _realization_cover_error,
    _resource_ref_ids,
    derive_step_realization,
    extract_resource_id,
)

_EP = "ep:v1:" + "ab" * 16
_TOOL = "tool:v1:" + "cd" * 16
_INT = "int:v1:" + "ef" * 16
_TB = "tb:v1:" + "01" * 16
_OUT = "ep:v1:" + "23" * 16


class TestExtractResourceId:
    """Typed opaque resource-ID extraction for every reference subtype."""

    @pytest.mark.parametrize(
        ("ref", "expected"),
        (
            (EntryPointResourceReference(kind="entry_point", entry_point_id=_EP), _EP),
            (ToolResourceReference(kind="tool", tool_id=_TOOL), _TOOL),
            (
                IntegrationResourceReference(kind="integration", integration_id=_INT),
                _INT,
            ),
            (
                TrustBoundaryResourceReference(
                    kind="trust_boundary", trust_boundary_id=_TB
                ),
                _TB,
            ),
            (
                OutputSurfaceResourceReference(kind="output_surface", entry_point_id=_OUT),
                _OUT,
            ),
            (AgentInternalResourceReference(kind="agent_internal"), "agent_internal"),
        ),
    )
    def test_extracts_typed_id(self, ref: Any, expected: str) -> None:
        assert extract_resource_id(ref) == expected

    def test_raises_for_unsupported_type(self) -> None:
        with pytest.raises(TypeError, match="Unsupported resource reference type"):
            extract_resource_id(object())


def _step(**overrides: Any) -> SimpleNamespace:
    """Minimal duck-typed canonical chain step for the ID-tuple helpers."""
    base: dict[str, Any] = {
        "step_id": "st1",
        "action_kind": "deliver",
        "executor_role": "attacker",
        "boundary_position": "crossing",
        "resource_links": (
            SimpleNamespace(slot_id="s1"),
            SimpleNamespace(slot_id="s2"),
            SimpleNamespace(slot_id="s3"),
        ),
        "consumed": (
            SimpleNamespace(ref_id="c1"),
            SimpleNamespace(ref_id="c2"),
        ),
        "produced": (
            SimpleNamespace(ref_id="p1", kind="effect"),
            SimpleNamespace(ref_id="p2", kind="artifact"),
        ),
        "observable_outcome_links": (SimpleNamespace(postcondition_id="o1"),),
        "observable_postconditions": (
            SimpleNamespace(postcondition_id="pc1"),
            SimpleNamespace(postcondition_id="pc2"),
        ),
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class TestIdTupleHelpers:
    """Per-field reference-ID tuple derivation."""

    def test_resource_ref_ids_in_link_order(self) -> None:
        binding_by_slot = {
            "s1": EntryPointResourceReference(kind="entry_point", entry_point_id=_EP),
            "s2": ToolResourceReference(kind="tool", tool_id=_TOOL),
            "s3": IntegrationResourceReference(kind="integration", integration_id=_INT),
        }
        assert _resource_ref_ids(_step(), binding_by_slot) == (_EP, _TOOL, _INT)

    def test_resource_ref_ids_skips_unbound_slots(self) -> None:
        binding_by_slot = {
            "s1": EntryPointResourceReference(kind="entry_point", entry_point_id=_EP)
        }
        assert _resource_ref_ids(_step(), binding_by_slot) == (_EP,)

    def test_consumed_ref_ids_preserves_order(self) -> None:
        assert _consumed_ref_ids(_step()) == ("c1", "c2")

    def test_produced_ref_ids_preserves_order(self) -> None:
        assert _produced_ref_ids(_step()) == ("p1", "p2")

    def test_produced_effect_ids_filters_non_effects(self) -> None:
        assert _produced_effect_ids(_step()) == ("p1",)

    def test_outcome_link_pc_ids(self) -> None:
        assert _outcome_link_pc_ids(_step()) == ("o1",)

    def test_postcondition_ids_preserves_order(self) -> None:
        assert _postcondition_ids(_step()) == ("pc1", "pc2")


class TestDeriveStepRealization:
    """End-to-end canonical realization derivation."""

    def test_assembles_full_record(self) -> None:
        binding_by_slot = {
            "s1": EntryPointResourceReference(kind="entry_point", entry_point_id=_EP),
            "s2": ToolResourceReference(kind="tool", tool_id=_TOOL),
        }
        record = derive_step_realization(_step(), binding_by_slot)
        assert record.projected_step_id == "st1"
        assert record.action_kind == "deliver"
        assert record.executor_role == "attacker"
        assert record.boundary_position == "crossing"
        assert record.resource_ref_ids == (_EP, _TOOL)
        assert record.consumed_ref_ids == ("c1", "c2")
        assert record.produced_ref_ids == ("p1", "p2")
        assert record.produced_effect_ids == ("p1",)
        assert record.outcome_link_pc_ids == ("o1",)
        assert record.postcondition_ids == ("pc1", "pc2")

    def test_agent_internal_binding_yields_fixed_literal(self) -> None:
        binding_by_slot = {"s1": AgentInternalResourceReference(kind="agent_internal")}
        record = derive_step_realization(
            _step(resource_links=(SimpleNamespace(slot_id="s1"),)),
            binding_by_slot,
        )
        assert record.resource_ref_ids == ("agent_internal",)


def test_realization_cover_rejects_same_count_with_different_ids() -> None:
    error = _realization_cover_error(
        [SimpleNamespace(projected_step_id="actual")],
        ["expected"],
        "narrative step 1",
    )

    assert error is not None
    assert "do not match" in error
