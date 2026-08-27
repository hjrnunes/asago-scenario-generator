"""Focused adversarial coverage for coverage-universe construction."""

from __future__ import annotations

from types import SimpleNamespace

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
)
from asago_scenario_generator.pipeline import coverage_planning_universe as universe


def test_classify_exclusion_preserves_reason_precedence() -> None:
    active_zones = {"input"}
    cases = (
        (
            SimpleNamespace(
                direction="output",
                effective_controllability="direct",
                effective_ingress_zone="input",
            ),
            universe.CoverageExclusionReason.OUTPUT_ONLY,
        ),
        (
            SimpleNamespace(
                direction="input",
                effective_controllability="system",
                effective_ingress_zone="input",
            ),
            universe.CoverageExclusionReason.SYSTEM_CONTROLLED,
        ),
        (
            SimpleNamespace(
                direction="input",
                effective_controllability="direct",
                effective_ingress_zone=None,
            ),
            universe.CoverageExclusionReason.NO_INGRESS_ZONE,
        ),
        (
            SimpleNamespace(
                direction="input",
                effective_controllability="direct",
                effective_ingress_zone="inactive",
            ),
            universe.CoverageExclusionReason.INACTIVE_ZONE,
        ),
    )

    for entry_point, expected in cases:
        assert universe._classify_exclusion(entry_point, active_zones) is expected


def test_build_universe_defaults_missing_exclusion_reason(
    monkeypatch,
) -> None:
    profile = CapabilityProfile(
        zones_active=["input"],
        entry_points=[
            EntryPoint(name="prompt", direction="input", controllability="direct")
        ],
        confidence=ConfidenceLevel.medium,
        kc_subcodes=["KC1.1"],
    )
    monkeypatch.setattr(
        universe,
        "is_attacker_accessible_ingress",
        lambda _entry_point, _active_zones: False,
    )
    monkeypatch.setattr(universe, "_classify_exclusion", lambda _ep, _zones: None)

    result = universe.build_coverage_universe(profile)

    assert len(result.excluded_targets) == 1
    assert (
        result.excluded_targets[0].reason
        is universe.CoverageExclusionReason.NO_INGRESS_ZONE
    )
