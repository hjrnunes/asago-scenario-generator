from __future__ import annotations

from asago_scenario_generator.models.attack_pattern import AttackPattern
from asago_scenario_generator.pipeline.projection import (
    ProjectionReadinessReport,
    ProjectionReadinessError,
    _available_resource_categories,
    capture_capability_snapshot,
    check_projection_readiness,
    ensure_projection_readiness,
)
from tests.helpers.projection_factory import (
    _evidence,
    _pattern,
    _profile,
)


def test_missing_architecture_categories_stop_projection_with_guidance() -> None:
    pattern = AttackPattern.model_validate(_pattern())
    profile = _profile().model_copy(
        update={"external_integrations": None, "trust_boundaries": None}
    )
    snapshot = capture_capability_snapshot(profile, (_evidence(),))

    try:
        ensure_projection_readiness([pattern], snapshot)
    except ProjectionReadinessError as exc:
        message = str(exc)
    else:  # pragma: no cover - assertion makes the red phase explicit
        raise AssertionError("expected projection readiness to fail")

    assert "external_integrations" in message
    assert "trust_boundaries" in message
    assert "--profile" in message
    assert "enrichment workflow" in message


def test_authoritative_fact_reading_makes_projection_ready() -> None:
    pattern = AttackPattern.model_validate(_pattern())
    snapshot = capture_capability_snapshot(_profile(), (_evidence(),))

    report = ensure_projection_readiness([pattern], snapshot)

    assert report.ready is True
    assert report.missing_resource_categories == ()


def test_readiness_error_describes_missing_resources_and_facts() -> None:
    error = ProjectionReadinessError(
        ProjectionReadinessReport(
            ready=False,
            missing_resource_categories=("entry_points",),
            missing_facts=("mode",),
        )
    )

    assert str(error) == (
        "Projection readiness failed before projection: "
        "missing resource categories entry_points; supply a reviewed architecture "
        "with '--profile'; missing qualification facts mode; supply authoritative "
        "readings with '--qualification-facts'. No architecture enrichment "
        "workflow was launched."
    )


def test_available_resources_distinguish_outputs_and_agent_internal_zone() -> None:
    available = _available_resource_categories(_profile())

    assert available["output_surfaces"] is False
    assert available["agent_internal"] is True


def test_readiness_reports_absent_and_unknown_facts() -> None:
    pattern = AttackPattern.model_validate(_pattern())

    absent = check_projection_readiness(
        [pattern], capture_capability_snapshot(_profile(), ())
    )
    assert absent.missing_facts == ("mode",)
    assert absent.ready is False

    unknown = _evidence().model_copy(update={"status": "unknown", "value": None})
    report = check_projection_readiness(
        [pattern], capture_capability_snapshot(_profile(), (unknown,))
    )
    assert report.missing_facts == ("mode",)
    assert report.ready is False
