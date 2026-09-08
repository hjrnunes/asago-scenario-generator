"""Deterministic zero-call interpreter for target-derived structures.

Phase 2 of the target-grounded scenario generation spec.  When the Stage 2
control structure was derived from the observed target, the exact
resource/operation binding for every tool action was already recorded in the
pinned ``target-derived-structure.yaml`` sidecar.  This interpreter replays
those bindings through the ordinary target-realization seam with zero model
calls, so Stage 5 and the v2 execution projection receive the exact operation
through the same verified path as a model-assisted run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from asago_scenario_generator.models.target_realization import (
    TargetOperationReference,
    TargetRealizationDisposition,
    TargetRealizationProviderResponse,
    TargetRealizationVerification,
)
from asago_scenario_generator.stpa.models.target_derived_structure import (
    TargetDerivedStructure,
)

_BINDING_EVIDENCE_PREFIX = "target-derived-structure:binding"


class TargetDerivedIdentityInterpreter:
    """Replay the sidecar's exact bindings as realization responses."""

    def __init__(self, derived: TargetDerivedStructure) -> None:
        derived.assert_integrity()
        self._derived = derived
        self._bindings = {binding.ca_id: binding for binding in derived.actions}

    def _unmapped(self, control_action_id: str) -> Any:
        return TargetRealizationProviderResponse(
            control_action_id=control_action_id,
            disposition=TargetRealizationDisposition.unmapped,
            rationale=(
                "target-derived action carries no observed operation "
                "binding in the pinned sidecar"
            ),
        )

    def __call__(
        self,
        *,
        action: Mapping[str, Any],
        operations: Sequence[Mapping[str, Any]],
    ) -> Any:
        control_action_id = str(action.get("control_action_id", ""))
        binding = self._bindings.get(control_action_id)
        if binding is None:
            return self._unmapped(control_action_id)
        # ``respond`` and conditional non-tool actions have no observed
        # operation; the ordinary unmapped disposition keeps Stage 5's
        # model-output handling unchanged. ActionBinding guarantees
        # both-or-neither for resource_id/operation_id.
        if binding.resource_id is None:
            return self._unmapped(control_action_id)
        reference = TargetOperationReference(
            resource_id=binding.resource_id,
            operation_id=binding.operation_id,
        )
        evidence = (
            f"{_BINDING_EVIDENCE_PREFIX}:{control_action_id}:"
            f"{binding.resource_id}/{binding.operation_id}",
        )
        return TargetRealizationProviderResponse(
            control_action_id=control_action_id,
            disposition=TargetRealizationDisposition.supported,
            candidate_operations=(reference,),
            selected_operation=reference,
            evidence_refs=evidence,
            rationale=(
                "exact binding recorded during deterministic target-derived "
                "structure derivation"
            ),
            verifier=TargetRealizationVerification(
                status="verified",
                detail=(
                    "exact resource/operation pair copied from the pinned "
                    "target-derived structure sidecar"
                ),
                evidence_refs=evidence,
            ),
        )


__all__ = ["TargetDerivedIdentityInterpreter"]
