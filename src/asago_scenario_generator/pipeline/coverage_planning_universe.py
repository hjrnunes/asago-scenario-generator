"""Coverage-universe construction from an authoritative capability profile."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    EntryPoint,
    is_attacker_accessible_ingress,
)

logger = logging.getLogger(__name__)


class CoverageExclusionReason(str, Enum):
    """Typed reason for excluding an entry point from the coverage universe."""

    OUTPUT_ONLY = "output_only"
    SYSTEM_CONTROLLED = "system_controlled"
    INACTIVE_ZONE = "inactive_zone"
    NO_INGRESS_ZONE = "no_ingress_zone"


class CoverageCompleteness(str, Enum):
    """Whether the entry-point inventory is known to be complete.

    Derived from :attr:`CapabilityProfile.is_entry_point_inventory_complete`:
    ``confirmed_complete`` only when the operator has confirmed the inventory
    is exhaustive with evidence; ``not_applicable`` otherwise (inferred-partial
    inventory — completeness cannot be claimed).
    """

    NOT_APPLICABLE = "not_applicable"
    CONFIRMED_COMPLETE = "confirmed_complete"


@dataclass(frozen=True)
class CoverageTarget:
    """A feasible coverage target — an attacker-accessible ingress entry point.

    Carries the canonical ``entry_point_id``, display name, direction, and
    effective controllability. Direction is always ``input`` or
    ``bidirectional``; controllability is always ``direct`` or ``indirect``.
    """

    entry_point_id: str
    name: str
    direction: str
    controllability: str


@dataclass(frozen=True)
class ExcludedTarget:
    """An entry point excluded from the coverage universe with a typed reason."""

    entry_point_id: str
    name: str
    direction: str
    controllability: str
    reason: CoverageExclusionReason


@dataclass
class CoverageUniverse:
    """The complete coverage universe: feasible targets plus typed exclusions.

    ``completeness`` is derived from the profile's
    ``is_entry_point_inventory_complete`` property — never from free-form
    input. ``evidence_refs`` carries the operator-confirmed evidence sources
    when completeness is ``confirmed_complete``.
    """

    feasible_targets: list[CoverageTarget] = field(default_factory=list)
    excluded_targets: list[ExcludedTarget] = field(default_factory=list)
    completeness: CoverageCompleteness = CoverageCompleteness.NOT_APPLICABLE
    evidence_refs: list[str] = field(default_factory=list)

    @property
    def feasible_target_ids(self) -> set[str]:
        """Set of entry_point_ids for all feasible targets."""
        return {target.entry_point_id for target in self.feasible_targets}

    def to_dict(self) -> dict:
        return {
            "feasible_targets": [
                {
                    "entry_point_id": target.entry_point_id,
                    "name": target.name,
                    "direction": target.direction,
                    "controllability": target.controllability,
                }
                for target in self.feasible_targets
            ],
            "excluded_targets": [
                {
                    "entry_point_id": excluded.entry_point_id,
                    "name": excluded.name,
                    "direction": excluded.direction,
                    "controllability": excluded.controllability,
                    "reason": excluded.reason.value,
                }
                for excluded in self.excluded_targets
            ],
            "completeness": self.completeness.value,
            "evidence_refs": list(self.evidence_refs),
        }


def _classify_exclusion(
    ep: EntryPoint,
    active_zones: set[str],
) -> CoverageExclusionReason | None:
    """Return the typed exclusion reason for a non-feasible entry point."""
    if ep.direction == "output":
        return CoverageExclusionReason.OUTPUT_ONLY
    if ep.effective_controllability == "system":
        return CoverageExclusionReason.SYSTEM_CONTROLLED
    zone = ep.effective_ingress_zone
    if zone is None:
        return CoverageExclusionReason.NO_INGRESS_ZONE
    if zone not in active_zones:
        return CoverageExclusionReason.INACTIVE_ZONE
    return None


def _target_from_entry(ep: EntryPoint) -> CoverageTarget:
    """Build a feasible :class:`CoverageTarget` from a profile entry point."""
    return CoverageTarget(
        entry_point_id=ep.entry_point_id,
        name=ep.name,
        direction=ep.direction,
        controllability=ep.effective_controllability,
    )


def _exclusion_from_entry(
    ep: EntryPoint,
    reason: CoverageExclusionReason,
) -> ExcludedTarget:
    """Build a typed :class:`ExcludedTarget` from a profile entry point."""
    return ExcludedTarget(
        entry_point_id=ep.entry_point_id,
        name=ep.name,
        direction=ep.direction,
        controllability=ep.effective_controllability,
        reason=reason,
    )


def _universe_completeness(
    profile: CapabilityProfile,
) -> tuple[CoverageCompleteness, list[str]]:
    """Derive completeness and evidence refs from the profile."""
    if profile.is_entry_point_inventory_complete:
        evidence = [e for e in profile.entry_point_evidence if e and e.strip()]
        return CoverageCompleteness.CONFIRMED_COMPLETE, evidence
    return CoverageCompleteness.NOT_APPLICABLE, []


def build_coverage_universe(
    profile: CapabilityProfile,
) -> CoverageUniverse:
    """Build the coverage universe from the capability profile.

    Entry points with an attacker-accessible ingress in an active zone are
    feasible targets. All others are excluded with a typed reason.
    Completeness is derived from the operator-confirmed profile property.
    """
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    feasible: list[CoverageTarget] = []
    excluded: list[ExcludedTarget] = []

    for ep in profile.entry_points:
        if is_attacker_accessible_ingress(ep, active_zones):
            feasible.append(_target_from_entry(ep))
        else:
            reason = _classify_exclusion(ep, active_zones)
            if reason is None:
                reason = CoverageExclusionReason.NO_INGRESS_ZONE
            excluded.append(_exclusion_from_entry(ep, reason))

    completeness, evidence_refs = _universe_completeness(profile)
    universe = CoverageUniverse(
        feasible_targets=feasible,
        excluded_targets=excluded,
        completeness=completeness,
        evidence_refs=evidence_refs,
    )
    logger.info(
        "Coverage universe: %d feasible target(s), %d excluded, completeness=%s",
        len(feasible),
        len(excluded),
        completeness.value,
    )
    return universe


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T11:32:57Z","module_hash":"84c81ee8ea6e3102cc8d3a37aa75c81f0a360bdc545bca549af6a0a5effedaa7","source_sha256":"e05f579d65679d32ceba1393414e2f2d24e3b91808eeed75937a281a850892f5","functions":[{"id":"func/CoverageUniverse.feasible_target_ids","name":"feasible_target_ids","line":82,"end_line":84,"hash":"50fbd6bd79b6baca47bd8c216a4fc6fa6d3a59b5a3f5eb164a8e42309eadf0b3"},{"id":"func/CoverageUniverse.to_dict","name":"to_dict","line":86,"end_line":109,"hash":"4b4fbd0d64f28333b7de678ed61f184874b275fef8c7c40f61161a258b875768"},{"id":"func/_classify_exclusion","name":"_classify_exclusion","line":112,"end_line":126,"hash":"0cf0c2783350b64b88af3fb5f78377f071a0c2202e986b123b556a40ba00e8e5"},{"id":"func/_target_from_entry","name":"_target_from_entry","line":129,"end_line":136,"hash":"0b5a9d07c865179b6dc3a832d36a6ada56d570d117d9de849c221cd13552f5c2"},{"id":"func/_exclusion_from_entry","name":"_exclusion_from_entry","line":139,"end_line":150,"hash":"8f51ae36305e56f2bd319670214fc80c7fd67c1ad15b7c5ae2bf09edb2e41d86"},{"id":"func/_universe_completeness","name":"_universe_completeness","line":153,"end_line":160,"hash":"75d4476c08942a786fa19cdf000cb0aead4b789ef25a918f6d6424fc2c239817"},{"id":"func/build_coverage_universe","name":"build_coverage_universe","line":163,"end_line":198,"hash":"11b2142345cfbe243dae2bc6d28535285473deec6ef2cd5f8cb9d5ffef35e9dd"}]}
# mutate4py-manifest-end
