"""Deterministic orchestration facade for hybrid taxonomy/STPA assessment."""

from __future__ import annotations

from asago_scenario_generator.models.correspondence import CorrespondenceAuthority
from asago_scenario_generator.models.hybrid_coverage import (
    HybridCoverageAssessment,
    StpaCoverageInput,
)
from asago_scenario_generator.models.hybrid_reconciliation import (
    HybridReconciliationInputs,
)
from asago_scenario_generator.models.system_resource_map import SystemResourceMap
from asago_scenario_generator.pipeline.correspondence import reconcile_correspondence
from asago_scenario_generator.pipeline.hybrid_coverage import assess_hybrid_coverage


def _is_valid_attestation(inputs: HybridReconciliationInputs) -> bool:
    """Return whether the closed validation result authorizes map consumption."""
    validation = inputs.resource_map_validation
    has_valid_result = validation.is_valid and not validation.violations
    has_canonical_map = validation.canonical_map is not None
    return has_valid_result and has_canonical_map


def _validated_map(inputs: HybridReconciliationInputs) -> SystemResourceMap:
    """Fail closed unless the facade received a successful map attestation."""
    validation = inputs.resource_map_validation
    if not _is_valid_attestation(inputs):
        raise ValueError(
            "resource_map_validation must be a valid resource-map attestation"
        )
    validation.canonical_map.assert_integrity()
    return validation.canonical_map


def _require_exact_proposal_authority(
    inputs: HybridReconciliationInputs, resource_map: SystemResourceMap
) -> None:
    """Bind proposals to the exact artifacts supplied to this orchestration call."""
    expected = CorrespondenceAuthority.from_artifacts(
        resource_map,
        inputs.obligation_plan,
        inputs.control_structure,
        inputs.ica_enumeration,
        inputs.loss_analysis,
        inventory_complete=_inventory_complete(inputs.structural_inventory_status),
    )
    if inputs.correspondence_proposals.authority != expected:
        raise ValueError(
            "proposal authority does not match the supplied hybrid artifacts"
        )


def _inventory_complete(status: str) -> bool:
    """Project the closed structural inventory status into authority's v1 flag."""
    return status == "complete"


def reconcile_taxonomy_and_stpa(
    inputs: HybridReconciliationInputs,
) -> HybridCoverageAssessment:
    """Validate, reconcile, and assess exact typed artifacts without inference or IO."""
    if not isinstance(inputs, HybridReconciliationInputs):
        raise TypeError("inputs must be a HybridReconciliationInputs")
    resource_map = _validated_map(inputs)
    _require_exact_proposal_authority(inputs, resource_map)
    reconciliation = reconcile_correspondence(
        inputs.resource_map_validation,
        inputs.correspondence_proposals,
        inputs.adjudications,
    )
    stpa = StpaCoverageInput.from_ica_enumeration(
        inputs.ica_enumeration,
        scenarios=inputs.stpa_scenarios,
        inventory_status=inputs.structural_inventory_status,
    )
    return assess_hybrid_coverage(
        inputs.obligation_plan,
        inputs.resource_map_validation,
        reconciliation,
        inputs.taxonomy_scenarios,
        stpa,
    )


__all__ = ["reconcile_taxonomy_and_stpa"]
