"""Deterministic temporal execution projection for one scenario.

Causal factors translate into executable temporal assertions and ordered
scenario steps without any LLM call.
"""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    predicate_for,
    step_kind_for,
    step_text_for,
)
from asago_scenario_generator.stpa.models.execution_envelope import (
    ScenarioStep,
    ScenarioStepKind,
    TemporalActionVector,
    TemporalAssertion,
    candidate_id_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.temporal_constraints import (
    UcaOutcomeConstraint,
    parse_declared_timing,
)

__all__ = ["derive_temporal_action_vector"]


def derive_temporal_action_vector(
    causal_factors: Sequence[CausalFactor],
    *,
    controller_id: str,
    control_action_id: str,
    uca_type: UCAType,
) -> TemporalActionVector:
    """Derive the deterministic temporal action vector for causal factors.

    Each causal factor maps to one executable temporal assertion and one
    ordered scenario step; a non-empty vector ends with the unsafe
    control action step for *control_action_id* and maps that final
    outcome explicitly through ``uca_constraint``.  The vector is linked
    to the canonical candidate identifier for the given controller,
    control action, and UCA type.

    Assertions carry typed temporal constraints derived only from each
    factor's declared timing: known timing selects its canonical variant
    with canonical units, while unknown timing yields ``constraint=None``
    and ``requires_binding``.  No causal inference and no runtime
    observations ever enter the vector.

    Empty *causal_factors* produce an empty vector — no assertions, no
    steps, and no outcome mapping are invented.

    Args:
        causal_factors: The mapped structural causal factors, in
            causal-factor order.
        controller_id: The owning responsibility identifier (RESP-N).
        control_action_id: The targeted control action (CA-X-Y).
        uca_type: The unsafe control action type.

    Returns:
        A :class:`TemporalActionVector` with canonical assertions and
        steps.
    """
    factors = list(causal_factors)
    assertions = [
        TemporalAssertion(
            assertion_id=f"TA-{index + 1}",
            order_index=index,
            kind=factor.kind,
            source_id=factor.source_id,
            predicate=predicate_for(factor.kind),
            constraint=parse_declared_timing(factor.declared_timing, factor.source_id),
        )
        for index, factor in enumerate(factors)
    ]
    steps = [
        ScenarioStep(
            step_id=f"S-{index + 1}",
            order_index=index,
            kind=step_kind_for(factor.kind),
            source_id=factor.source_id,
            text=step_text_for(factor.kind).format(
                source=factor.source_id,
                action=control_action_id,
            ),
        )
        for index, factor in enumerate(factors)
    ]
    uca_constraint: UcaOutcomeConstraint | None = None
    if factors:
        steps.append(
            ScenarioStep(
                step_id=f"S-{len(factors) + 1}",
                order_index=len(factors),
                kind=ScenarioStepKind.unsafe_control_action,
                source_id=control_action_id,
                text=(
                    f"Unsafe control action {control_action_id} executes "
                    f"with {uca_type.value}"
                ),
            )
        )
        uca_constraint = UcaOutcomeConstraint(
            control_action_id=control_action_id,
            uca_type=uca_type,
        )
    candidate_id = candidate_id_for(controller_id, control_action_id, uca_type)
    return TemporalActionVector(
        candidate_id=candidate_id,
        control_action_id=control_action_id,
        assertions=assertions,
        steps=steps,
        uca_constraint=uca_constraint,
    )
