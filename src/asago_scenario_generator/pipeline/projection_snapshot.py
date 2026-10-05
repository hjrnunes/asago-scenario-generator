"""Immutable capability and qualification snapshot construction."""

from __future__ import annotations

from asago_scenario_generator.pipeline.projection_contracts import (  # noqa: F401
    CapabilityFactSnapshot,
    _assert_snapshot_facts_uniquely_sorted,
    _compute_snapshot_digest,
    _snapshot_resource_payload,
    _sorted_by,
    _sorted_canonical,
    capture_capability_snapshot,
)
