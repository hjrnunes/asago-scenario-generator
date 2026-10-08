"""Provider call for governance routing, bound to ``ObligationAwareLLMAdapter``."""

from __future__ import annotations

from functools import lru_cache
from typing import Annotated, Any, Literal

from pydantic import Field, create_model

from asago_scenario_generator.stpa.infra.call_log import (
    call_log_of,
    mark_call_published,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import _Model
from asago_scenario_generator.stpa.obligation_aware.governance_prompts import (
    project_governance_routing_context,
    render_governance_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    GovernancePlacement,
    GovernanceRoutingRequest,
    GovernanceRoutingResponse,
    GovernanceTarget,
)
from asago_scenario_generator.stpa.obligation_aware.payload_types import (
    exact_length_payload_type,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    obligation_prompt_template_hashes,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _SYNTHESIS_MAX_COMPLETION_TOKENS,
    _preflight,
    _with_correction_feedback,
)


class _WireTarget(_Model):
    target_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class _WirePlacement(_Model):
    risk_id: str
    targets: tuple[_WireTarget, ...]


@lru_cache(maxsize=16)
def governance_payload_type(risk_ids: tuple[str, ...]) -> type[_Model]:
    """Build the strict wire payload: one placement per supplied risk id."""
    if not risk_ids:
        raise ValueError("governance payload requires at least one risk id")
    placement = create_model(
        "_WirePlacementExact",
        __base__=_WirePlacement,
        risk_id=(Literal.__getitem__(risk_ids), ...),
    )
    return exact_length_payload_type(
        f"_GovernancePayload{len(risk_ids)}",
        _Model,
        "placements",
        Annotated[placement, Field()],
        len(risk_ids),
        module=__name__,
    )


def run_governance_routing(
    adapter: Any,
    request: GovernanceRoutingRequest,
    correction_feedback: str | None = None,
) -> GovernanceRoutingResponse:
    """Run the named governance-routing provider stage for one batch."""
    view = project_governance_routing_context(
        briefs=request.briefs,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
        slots=request.slots,
    )
    system_prompt, user_prompt = render_governance_routing_prompts(view)
    user_prompt = _with_correction_feedback(user_prompt, correction_feedback)
    stage = f"{adapter.stage_prefix}_governance_routing"
    risk_ids = tuple(item.risk_id for item in view.rows)
    _preflight(
        view=view,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        stage="governance-routing",
        handles=risk_ids,
        stage_max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
        client=adapter.llm_client,
        controls=request.controls,
        configured_budget=adapter.prompt_budget,
        output_schema=("placements", "risk_id", "targets", "target_id", "reason"),
        valid_example={"placements": [{"risk_id": "<risk_id>", "targets": []}]},
        run_dir=adapter.run_dir,
        call_stage=stage,
        step=request.batch_id,
    )
    outcome = call_with_policy(
        llm_client=adapter.llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=governance_payload_type(risk_ids),
        run_dir=adapter.run_dir,
        stage=stage,
        step=request.batch_id,
        # route_governance_rows owns the single bounded retry because it also
        # validates identifier closure after this schema parse.
        policy=CorrectionPolicy(
            validation_retries=0,
            feedback=" Return one placement for every supplied risk_id.",
        ),
        temperature=request.controls.temperature,
        max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
        prompt_template_hashes=obligation_prompt_template_hashes(),
    )
    if outcome.error is not None or outcome.value is None:
        raise ValueError(
            outcome.error or "governance routing provider returned no payload"
        )
    response = GovernanceRoutingResponse(
        request_digest=request.semantic_digest,
        placements=tuple(
            GovernancePlacement(
                risk_id=item.risk_id,
                targets=tuple(
                    GovernanceTarget(target_id=t.target_id, reason=t.reason)
                    for t in item.targets
                ),
            )
            for item in outcome.value.placements
        ),
        adapter_kind="provider",
        provider_calls=outcome.calls,
    )
    mark_call_published(
        adapter.run_dir, stage, request.batch_id, call_log_of(adapter.llm_client)
    )
    return response
