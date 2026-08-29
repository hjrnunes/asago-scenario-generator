"""Closed input contract for the source-spec §8.7 hybrid facade."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    ProposalSet,
)
from asago_scenario_generator.models.hybrid_coverage import (
    InventoryStatus,
    StpaScenarioObservation,
    TaxonomyCoverageInput,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMapValidation,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis

_ARTIFACT_TYPES = {
    "obligation_plan": TaxonomyObligationPlan,
    "loss_analysis": LossAnalysis,
    "control_structure": ControlStructure,
    "ica_enumeration": ICAEnumeration,
    "resource_map_validation": SystemResourceMapValidation,
    "correspondence_proposals": ProposalSet,
    "adjudications": AdjudicationSet,
    "taxonomy_scenarios": TaxonomyCoverageInput,
}


def _require_input_mapping(value: Any) -> Mapping[str, Any]:
    """Select only the typed mapping boundary used by Pydantic construction."""
    if not isinstance(value, Mapping):
        raise ValueError("hybrid reconciliation inputs must be a typed mapping")
    return value


def _require_artifact_types(value: Mapping[str, Any]) -> None:
    """Reject free-form mappings in place of upstream artifact models."""
    for field_name, expected_type in _ARTIFACT_TYPES.items():
        field_value = value.get(field_name)
        if field_value is not None and not isinstance(field_value, expected_type):
            raise ValueError(f"{field_name} must be a {expected_type.__name__}")


def _require_scenario_types(value: Mapping[str, Any]) -> None:
    """Reject untyped legacy STPA scenario observations."""
    scenarios = value.get("stpa_scenarios", ())
    is_sequence = isinstance(scenarios, (tuple, list))
    has_typed_items = is_sequence and all(
        isinstance(item, StpaScenarioObservation) for item in scenarios
    )
    if not has_typed_items:
        raise ValueError(
            "stpa_scenarios must contain typed StpaScenarioObservation records"
        )


class HybridReconciliationInputs(BaseModel):
    """Exact upstream artifacts consumed by deterministic hybrid orchestration."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    obligation_plan: TaxonomyObligationPlan
    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    ica_enumeration: ICAEnumeration
    resource_map_validation: SystemResourceMapValidation
    correspondence_proposals: ProposalSet
    adjudications: AdjudicationSet = Field(default_factory=AdjudicationSet)
    taxonomy_scenarios: TaxonomyCoverageInput = Field(
        default_factory=TaxonomyCoverageInput
    )
    stpa_scenarios: tuple[StpaScenarioObservation, ...] = ()
    structural_inventory_status: InventoryStatus = "complete"

    @model_validator(mode="before")
    @classmethod
    def require_typed_artifacts(cls, value: Any) -> Any:
        """Reject free-form mappings in place of closed upstream artifacts."""
        if isinstance(value, cls):
            return value
        mapping = _require_input_mapping(value)
        _require_artifact_types(mapping)
        _require_scenario_types(mapping)
        return mapping


__all__ = ["HybridReconciliationInputs"]
