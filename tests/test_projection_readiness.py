from __future__ import annotations

from asago_scenario_generator.models.attack_pattern import AttackPattern
from asago_scenario_generator.pipeline.projection import (
    ProjectionReadinessError,
    capture_capability_snapshot,
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
