"""Focused unit tests for the decomposed projection ingress helpers."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from asago_scenario_generator.models.attack_pattern import EntryPointResourceReference
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
    ProjectionTraceabilityResult,
    ProjectionTraceabilityStage,
    ProjectionTraceabilityViolation,
    ProjectionTraceabilityViolationCode,
    _ingress_binding,
    _is_entry_point_binding,
    _matches_canonical_ingress,
)

_EP = "ep:v1:" + "ab" * 16
_OTHER_EP = "ep:v1:" + "cd" * 16


def _ep(entry_point_id: str = _EP) -> EntryPointResourceReference:
    return EntryPointResourceReference(kind="entry_point", entry_point_id=entry_point_id)


def _binding(slot_id: str, resource_ref: Any) -> SimpleNamespace:
    return SimpleNamespace(slot_id=slot_id, resource_ref=resource_ref)


def _fake_block(
    resource_ref: Any, canonical_ingress: Any = None
) -> SimpleNamespace:
    """Duck-typed envelope exposing only the fields the validator touches."""
    return SimpleNamespace(
        projection=SimpleNamespace(
            source_chain=SimpleNamespace(initial_ingress_slot_id="s1"),
            bindings=[_binding("s1", resource_ref)],
        ),
        canonical_ingress=(
            canonical_ingress
            if canonical_ingress is not None
            else _ep()
        ),
    )


class TestIngressBinding:
    """Projection ingress-binding lookup."""

    def test_returns_matching_binding(self) -> None:
        projection = SimpleNamespace(
            bindings=[_binding("s1", object()), _binding("s2", object())]
        )
        assert _ingress_binding(projection, "s2").slot_id == "s2"

    def test_raises_stop_iteration_when_missing(self) -> None:
        projection = SimpleNamespace(bindings=[_binding("s9", object())])
        with pytest.raises(StopIteration):
            _ingress_binding(projection, "s1")


class TestIngressPredicates:
    """Entry-point typing and canonical-ingress equality checks."""

    def test_is_entry_point_binding_true_for_entry_point_ref(self) -> None:
        binding = _binding("s1", _ep())
        assert _is_entry_point_binding(binding) is True

    def test_is_entry_point_binding_false_for_other_refs(self) -> None:
        assert _is_entry_point_binding(_binding("s1", object())) is False

    def test_matches_canonical_ingress_true_when_equal(self) -> None:
        binding = _binding("s1", _ep())
        canonical = _ep()
        assert _matches_canonical_ingress(binding, canonical) is True

    def test_matches_canonical_ingress_false_when_different(self) -> None:
        binding = _binding("s1", _ep())
        canonical = _ep(_OTHER_EP)
        assert _matches_canonical_ingress(binding, canonical) is False


class TestIngressMatchesProjection:
    """ProjectionEnvelopeBlock._ingress_matches_projection validator."""

    def test_accepts_matching_entry_point_ingress(self) -> None:
        block = _fake_block(_ep())
        assert ProjectionEnvelopeBlock._ingress_matches_projection(block) is block

    def test_raises_type_error_for_non_entry_point_binding(self) -> None:
        block = _fake_block(object())
        with pytest.raises(TypeError, match="entry-point reference"):
            ProjectionEnvelopeBlock._ingress_matches_projection(block)

    def test_raises_value_error_for_canonical_mismatch(self) -> None:
        block = _fake_block(_ep(), canonical_ingress=_ep(_OTHER_EP))
        with pytest.raises(ValueError, match="does not match the projection"):
            ProjectionEnvelopeBlock._ingress_matches_projection(block)


class TestPostconditionAccessors:
    """Postcondition accessors retain selected-step and security boundaries."""

    @staticmethod
    def _block() -> SimpleNamespace:
        return SimpleNamespace(
            projection=SimpleNamespace(
                source_chain=SimpleNamespace(
                    steps=(
                        SimpleNamespace(
                            step_id="s1",
                            observable_postconditions=(
                                SimpleNamespace(
                                    postcondition_id="pc1",
                                    security_relevant=True,
                                ),
                                SimpleNamespace(
                                    postcondition_id="pc2",
                                    security_relevant=False,
                                ),
                            ),
                        ),
                        SimpleNamespace(
                            step_id="s2",
                            observable_postconditions=(
                                SimpleNamespace(
                                    postcondition_id="pc3",
                                    security_relevant=True,
                                ),
                            ),
                        ),
                    )
                ),
                selected_step_ids=("s1", "s2"),
            )
        )

    def test_postconditions_for_step_returns_owned_ids(self) -> None:
        block = self._block()

        assert ProjectionEnvelopeBlock.postconditions_for_step(block, "s1") == (
            "pc1",
            "pc2",
        )
        assert ProjectionEnvelopeBlock.postconditions_for_step(block, "missing") == ()

    def test_security_relevant_postconditions_excludes_unselected_steps(self) -> None:
        block = self._block()
        block.projection.selected_step_ids = ("s1",)

        assert ProjectionEnvelopeBlock.security_relevant_postconditions(block) == {
            "s1": ["pc1"]
        }


class TestTraceabilityValidity:
    """Traceability validity is forced false whenever violations are present."""

    def test_violations_override_true_valid_flag(self) -> None:
        violation = ProjectionTraceabilityViolation(
            code=ProjectionTraceabilityViolationCode.omitted_projected_step,
            stage=ProjectionTraceabilityStage.narrative,
            detail="projected step was omitted",
        )

        result = ProjectionTraceabilityResult(valid=True, violations=[violation])

        assert result.valid is False

    def test_explicit_false_without_violations_remains_false(self) -> None:
        assert ProjectionTraceabilityResult(valid=False).valid is False
