"""Compile a hand-written Stage 5 draft at the compile seam, with no provider."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec
from asago_scenario_generator.stpa.scenario_prod.stage5.assemble import (
    ScenarioAssembly,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.compile import (
    compile_scenario_spec,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    _CausalSourceChoice,
)

PROPOSITION = "The response exhibits the selected unsafe action."


def handle_of(
    choices: Sequence[_CausalSourceChoice], kind: CausalFactorKind, source_id: str
) -> str:
    """Return the request-local handle bound to one structural source."""
    return next(
        choice.handle
        for choice in choices
        if choice.kind is kind and choice.source_id == source_id
    )


def factor(handle: str, evidence: str, **fields: Any) -> dict[str, Any]:
    """One wire causal factor; ``fields`` add or replace evidence fields."""
    return {
        "source_handle": handle,
        "evidence": evidence,
        "temporal_condition": None,
        "evidence_status": "structural_failure",
        **fields,
    }


def draft_payload(
    factors: Sequence[dict[str, Any]], *, proposition: str = PROPOSITION
) -> dict[str, Any]:
    """One normal-path draft whose intention cites every declared factor."""
    return {
        "adversary": {
            "kind": "malicious_customer",
            "gain": "Learns another customer's order details.",
        },
        "attacker_bdi": {
            "beliefs": ["b"],
            "desires": ["d"],
            "intentions": [
                {
                    "description": "Use the selected structural condition.",
                    "source_handles": [item["source_handle"] for item in factors],
                }
            ],
        },
        "causal_factors": list(factors),
        "unsafe_outcome": {"semantic_proposition": proposition},
    }


def compile_draft(
    payload: dict[str, Any],
    context: ScenarioGenerationContext,
    assembly: ScenarioAssembly,
    *,
    choices: Sequence[_CausalSourceChoice] | None = None,
) -> ScenarioSpec:
    """Compile ``payload`` against ``context`` and ``assembly``.

    ``choices`` defaults to the context's own causal sources; passing others
    binds a handle to a source the context does not offer.
    """
    bound = tuple(_causal_source_choices(context) if choices is None else choices)
    draft = _scenario_semantics_payload_type(len(bound)).model_validate(payload)
    return compile_scenario_spec(draft, bound, context, assembly)
