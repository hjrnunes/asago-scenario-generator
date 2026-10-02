"""Environment-basis resolution for one STPA semantic execution contract."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionResourceRequirement,
    RequestedEnvironmentBasis,
)


def resolve_contract_environment_request(
    requirements: tuple[ExecutionResourceRequirement, ...],
    requested: RequestedEnvironmentBasis | None,
) -> RequestedEnvironmentBasis | None:
    """Resolve the canonical contract basis from resources and caller intent.

    Resource-free routes are executable against the model/runtime surface and
    therefore normalize every requested basis to ``target_agnostic``.  A
    resource-bearing route may retain an omitted basis while it remains
    parameterized; an explicit target or simulation request is preserved for
    later profile matching.  ``target_agnostic`` is invalid when semantic
    resources are present.
    """
    if not requirements:
        return RequestedEnvironmentBasis.target_agnostic
    if requested is RequestedEnvironmentBasis.target_agnostic:
        raise ValueError("target_agnostic contracts cannot require domain resources")
    return requested


__all__ = ["resolve_contract_environment_request"]
