"""Closed input envelope for the Phase 4 authority resolver.

This module contains only domain models.  Outer pipeline adapters are
responsible for converting current mutable pipeline/STPA values into the
neutral attestations before this envelope is assembled.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import Field, model_validator

from asago_scenario_generator.models.closed_loop_stpa import ClosedLoopStpaRun
from asago_scenario_generator.models.hybrid_coverage import HybridCoverageAssessment
from asago_scenario_generator.models.hybrid_scenario_projection import (
    BridgeLink,
    CapabilityFactAttestation,
    ConfirmedCoverageReview,
    HybridCorrespondenceAttestation,
    PinnedStpaProjectionAttestation,
    _ProjectionModel,
    _require_unique,
)
from asago_scenario_generator.models.candidate_materialization import (
    CandidateMaterializationSet,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMapValidation,
)


HYBRID_PROJECTION_INPUTS_SCHEMA_VERSION = "hybrid-projection-inputs-v1"

_TYPED_NESTED_FIELDS = (
    "obligation_plan",
    "capability_facts",
    "candidate_materializations",
    "phase2_assessment",
    "correspondence",
    "resource_map_validation",
    "stpa_projection_authority",
    "closed_loop_run",
)
_SEQUENCE_NESTED_FIELDS = ("confirmed_reviews", "bridge_links")


def _reject_mapping_nested_values(
    value: dict[str, Any], fields: tuple[str, ...]
) -> None:
    """Reject a raw mapping in each field that requires a typed authority."""
    for field_name in fields:
        if isinstance(value.get(field_name), dict):
            raise TypeError(f"{field_name} must be a validated typed value")


def _reject_sequence_nested_values(
    value: dict[str, Any], fields: tuple[str, ...]
) -> None:
    """Reject raw mapping members in typed authority sequences."""
    for field_name in fields:
        nested = value.get(field_name, ())
        if any(isinstance(item, dict) for item in nested):
            raise TypeError(f"{field_name} must contain validated typed values")


class HybridProjectionInputs(_ProjectionModel):
    """One closed, exact-authority input graph for Phase 4 Task 1."""

    schema_version: Literal[HYBRID_PROJECTION_INPUTS_SCHEMA_VERSION] = (
        HYBRID_PROJECTION_INPUTS_SCHEMA_VERSION
    )
    obligation_plan: TaxonomyObligationPlan
    capability_facts: CapabilityFactAttestation
    candidate_materializations: CandidateMaterializationSet
    phase2_assessment: HybridCoverageAssessment
    correspondence: HybridCorrespondenceAttestation
    resource_map_validation: SystemResourceMapValidation
    stpa_projection_authority: PinnedStpaProjectionAttestation
    confirmed_reviews: tuple[ConfirmedCoverageReview, ...] = ()
    bridge_links: tuple[BridgeLink, ...]
    requested_relation_ids: tuple[str, ...] = Field(min_length=1)
    evidence_class: Literal[
        "normative_bookkeeping_fixture", "reviewed_semantic_evidence"
    ]
    closed_loop_run: ClosedLoopStpaRun | None = None

    @model_validator(mode="before")
    @classmethod
    def reject_untyped_nested_values(cls, value: Any) -> Any:
        """Reject raw mappings that would otherwise be silently coerced."""
        if not isinstance(value, dict):
            return value
        _reject_mapping_nested_values(value, _TYPED_NESTED_FIELDS)
        _reject_sequence_nested_values(value, _SEQUENCE_NESTED_FIELDS)
        return value

    @model_validator(mode="after")
    def canonicalize_and_validate(self) -> "HybridProjectionInputs":
        _require_unique(
            self.requested_relation_ids,
            "requested relation IDs must be unique",
        )
        _require_unique(
            (item.relation_id for item in self.confirmed_reviews),
            "confirmed reviews must contain one record per relation",
        )
        _require_unique(
            (item.bridge_id for item in self.bridge_links),
            "bridge IDs must be unique",
        )
        object.__setattr__(
            self,
            "requested_relation_ids",
            tuple(sorted(self.requested_relation_ids)),
        )
        object.__setattr__(
            self,
            "confirmed_reviews",
            tuple(sorted(self.confirmed_reviews, key=lambda item: item.relation_id)),
        )
        object.__setattr__(
            self,
            "bridge_links",
            tuple(
                sorted(
                    self.bridge_links,
                    key=lambda item: (
                        item.relation_id,
                        item.bridge_kind,
                        item.bridge_id,
                    ),
                )
            ),
        )
        return self


__all__ = ["HYBRID_PROJECTION_INPUTS_SCHEMA_VERSION", "HybridProjectionInputs"]
