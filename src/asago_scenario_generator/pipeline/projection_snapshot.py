"""Immutable capability and qualification snapshot construction."""

from __future__ import annotations

# Import a model submodule before the contract façade.  Python initializes the
# models package while resolving this import; doing it in the opposite order
# would let models.projection_envelope observe a partially initialized
# projection_contracts module.
from asago_scenario_generator.models.attack_pattern_chain import (  # noqa: F401
    AttackPattern as _ModelImportOrderGuard,
)

from asago_scenario_generator.pipeline.projection_contracts import (  # noqa: F401
    CapabilityFactSnapshot,
    _assert_snapshot_facts_uniquely_sorted,
    _compute_snapshot_digest,
    _snapshot_resource_payload,
    _sorted_by,
    _sorted_canonical,
    capture_capability_snapshot,
)
