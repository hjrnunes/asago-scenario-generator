"""Tests for the target-scoped finalization contract value objects."""

from __future__ import annotations

import pytest

from asago_scenario_generator.pipeline.finalization_contracts import (
    GeneratedStage,
    LifecycleViolation,
)


@pytest.mark.parametrize("owner", [*GeneratedStage, None])
@pytest.mark.parametrize("retryable", [True, False])
def test_only_retryable_generated_owners_can_retry_generation(
    owner: GeneratedStage | None,
    retryable: bool,
) -> None:
    violation = LifecycleViolation(detail="x", owner=owner, retryable=retryable)

    assert violation.can_retry_generation is (retryable and owner is not None)
