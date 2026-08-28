"""Shared test helper for building a small valid SystemResourceMap.

Used by correspondence proposal and reconciliation tests that need a
resource map with one resource, one control action, one loss link, and one
trust boundary, but do not need the full representative map.
"""

from __future__ import annotations

from asago_scenario_generator.models.system_resource_map import (
    ControlActionEntry,
    LossLinkEntry,
    SystemResourceEntry,
    SystemResourceMap,
    TrustBoundaryEntry,
)


def make_test_resource_map() -> SystemResourceMap:
    """Build the canonical small resource map used by correspondence tests."""
    return SystemResourceMap(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        system_resources=[
            SystemResourceEntry(
                element_id="SR-1",
                taxonomy_ref="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            )
        ],
        control_actions=[
            ControlActionEntry(
                element_id="CA-1-1",
                controller_id="RESP-1",
                process_id="CP-2",
                action_name="Issue Payment",
            )
        ],
        loss_links=[
            LossLinkEntry(
                element_id="LL-1",
                loss_id="L-1",
                hazard_id="H-1",
            )
        ],
        trust_boundaries=[
            TrustBoundaryEntry(
                element_id="TB-1",
                resource_ids=["SR-1"],
                taxonomy_ref="tb:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            )
        ],
    )
