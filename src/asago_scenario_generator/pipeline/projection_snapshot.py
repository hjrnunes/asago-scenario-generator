"""Immutable capability and qualification snapshot construction."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from asago_scenario_generator.models.attack_pattern import (
    AuthoritativeFactReference,
    CanonicalResourceReference,
    EvaluatedFactEvidence,
    ResourceSlot,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from pydantic import model_validator

from asago_scenario_generator.pipeline.projection import (
    Digest,
    ProjectionModel,
    _canonical_json,
    _digest,
    _fact_key,
    _resource_contained,
)


def _assert_snapshot_facts_uniquely_sorted(
    facts: tuple[EvaluatedFactEvidence, ...],
) -> None:
    """Require snapshot facts to be uniquely sorted by fact reference."""
    keys = [_fact_key(item.fact) for item in facts]
    if keys != sorted(keys) or len(keys) != len(set(keys)):
        raise ValueError("snapshot facts must be uniquely sorted by reference")


class CapabilityFactSnapshot(ProjectionModel):
    """One immutable, content-addressed pre-LLM profile/fact reading."""

    profile: CapabilityProfile
    facts: tuple[EvaluatedFactEvidence, ...]
    snapshot_digest: Digest

    @property
    def capability_fact_snapshot_digest(self) -> str:
        """Implement the merged :class:`CapabilitySnapshotResolver` pin."""
        self.assert_integrity()
        return self.snapshot_digest

    def assert_integrity(self) -> None:
        """Fail closed if a nested mutable profile was changed after capture."""
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("capability/fact snapshot changed after capture")

    def fact(
        self, reference: AuthoritativeFactReference
    ) -> EvaluatedFactEvidence | None:
        self.assert_integrity()
        return {_fact_key(item.fact): item for item in self.facts}.get(
            _fact_key(reference)
        )

    def contains_resource(self, reference: CanonicalResourceReference) -> bool:
        self.assert_integrity()
        return _resource_contained(reference, self.profile)

    def resource_matches_slot(
        self, reference: CanonicalResourceReference, slot: ResourceSlot
    ) -> bool:
        self.assert_integrity()
        from asago_scenario_generator.pipeline.projection import _references_for_slot

        return reference in _references_for_slot(
            slot,
            self,
            initial_ingress=slot.purpose == "initial_ingress",
        )

    @model_validator(mode="after")
    def coherent_digest(self) -> "CapabilityFactSnapshot":
        _assert_snapshot_facts_uniquely_sorted(self.facts)
        if self.snapshot_digest != _compute_snapshot_digest(self.profile, self.facts):
            raise ValueError("snapshot_digest does not match capability/fact content")
        return self


def _snapshot_resource_payload(profile: CapabilityProfile) -> dict[str, Any]:
    return {
        "zones_active": sorted(set(profile.zones_active)),
        "kc_subcodes": sorted(set(profile.kc_subcodes)),
        "entry_points": _sorted_by(profile.entry_points, "entry_point_id"),
        "tools": _sorted_by(profile.tool_inventory or (), "tool_id"),
        "tool_types": _sorted_canonical(profile.tool_types or ()),
        "integrations": _sorted_by(
            profile.external_integrations or (), "integration_id"
        ),
        "trust_boundaries": _sorted_by(
            profile.trust_boundaries or (), "trust_boundary_id"
        ),
    }


def _sorted_by(items: Iterable[Any], key_field: str) -> list[dict[str, Any]]:
    """Dump items to JSON and order them by a stable top-level field."""
    return sorted(
        (item.model_dump(mode="json") for item in items),
        key=lambda item: item[key_field],
    )


def _sorted_canonical(items: Iterable[Any]) -> list[dict[str, Any]]:
    """Dump items to JSON and order them by canonical JSON bytes."""
    return sorted(
        (item.model_dump(mode="json") for item in items),
        key=lambda item: _canonical_json(item),
    )


def _compute_snapshot_digest(
    profile: CapabilityProfile, facts: tuple[EvaluatedFactEvidence, ...]
) -> str:
    return _digest(
        "asago-scenario-generator:capability-fact-snapshot:v1",
        {
            "profile": _snapshot_resource_payload(profile),
            "facts": [item.model_dump(mode="json") for item in facts],
        },
    )


def capture_capability_snapshot(
    profile: CapabilityProfile,
    facts: Iterable[EvaluatedFactEvidence] = (),
) -> CapabilityFactSnapshot:
    """Capture a deterministic resolver snapshot before any LLM stage."""
    by_reference: dict[str, EvaluatedFactEvidence] = {}
    for item in facts:
        key = _fact_key(item.fact)
        previous = by_reference.get(key)
        if previous is not None and previous != item:
            raise ValueError("conflicting authoritative readings for one fact")
        by_reference[key] = item
    ordered = tuple(by_reference[key] for key in sorted(by_reference))
    captured_profile = profile.model_copy(deep=True)
    return CapabilityFactSnapshot(
        profile=captured_profile,
        facts=ordered,
        snapshot_digest=_compute_snapshot_digest(captured_profile, ordered),
    )
