"""Focused adversarial coverage for narrative access helpers."""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.pipeline.generate.narrative_access import (
    _direct_source_violation,
    _source_identity,
)


def test_source_identity_prefers_typed_id_over_legacy_name() -> None:
    assert _source_identity("integration:v1:canonical", "legacy CRM") == (
        "integration:v1:canonical"
    )
    assert _source_identity(None, "legacy CRM") == "legacy CRM"
    assert _source_identity(None, None) is None


def test_direct_access_rejects_an_influence_source_reference() -> None:
    realization = SimpleNamespace(
        influence_source="uploaded document",
        influence_source_id=None,
        trust_boundary_id=None,
    )
    access = SimpleNamespace(ingress_mode="direct")

    violation = _direct_source_violation(realization, access)

    assert violation is not None
    assert violation.rule == "direct_realization_has_indirect_ref"
