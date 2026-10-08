"""Place governance-only risks on control actions.

A governance risk has no attack pattern, so no pattern-specific mechanism can
ground it.  The model's only decision is which control actions the risk bears
on.  Code owns everything else: the hazard and constraint identities come from
the loss analysis, a control action expands to its slots, and every returned
identifier is checked against the slot inventory.  A risk the model places on
nothing is declined, never forced onto a path.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import ClassVar, Literal, Protocol

from pydantic import Field, model_validator

from asago_scenario_generator.models.artifact_pin import Digest
from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    SemanticDigestMixin,
)
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    RequestTally,
    count_requests,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.briefs import split_by_budget
from asago_scenario_generator.stpa.obligation_aware.calls import (
    call_evidence,
    call_with_feedback,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.governance_prompts import (
    build_governance_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    _default_controls,
    _routing_prompt_budget,
    _slot_inventory,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder

GOVERNANCE_REQUEST_SCHEMA_VERSION = "stpa-governance-routing-request-v1"
GOVERNANCE_REQUEST_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-governance-routing-request:v1"
)
GOVERNANCE_RESPONSE_DIGEST_DOMAIN = (
    "asago-scenario-generator:stpa-governance-routing-response:v1"
)
_ERROR_MAX_CHARS = 512


class GovernanceTarget(ClosedCanonicalModel):
    """One control action or slot a governance risk bears on."""

    target_id: str = Field(min_length=1)
    reason: str = Field(min_length=1)


class GovernancePlacement(ClosedCanonicalModel):
    """The control actions one governance risk bears on, possibly none."""

    risk_id: str = Field(min_length=1)
    targets: tuple[GovernanceTarget, ...] = ()


class GovernanceRoutingRequest(SemanticDigestMixin, ClosedCanonicalModel):
    """One canonical batch of governance risks sent to the routing model."""

    _digest_domain: ClassVar[str] = GOVERNANCE_REQUEST_DIGEST_DOMAIN

    schema_version: Literal[GOVERNANCE_REQUEST_SCHEMA_VERSION] = (
        GOVERNANCE_REQUEST_SCHEMA_VERSION
    )
    batch_id: str = Field(min_length=1)
    briefs: tuple[NeutralObligationBrief, ...] = Field(min_length=1)
    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    slots: tuple[SlotPlaceholder, ...] = ()
    controls: AnalysisControls
    semantic_digest: Digest | None = None

    @model_validator(mode="after")
    def canonicalize_and_verify(self) -> "GovernanceRoutingRequest":
        if any(item.kind != "governance" for item in self.briefs):
            raise ValueError("governance routing accepts only governance briefs")
        briefs = tuple(sorted(self.briefs, key=lambda item: item.risk_ref.risk_id))
        if len({item.risk_ref.risk_id for item in briefs}) != len(briefs):
            raise ValueError("governance routing briefs must name distinct risks")
        object.__setattr__(self, "briefs", briefs)
        slots = tuple(sorted(self.slots, key=lambda item: item.slot_id))
        object.__setattr__(self, "slots", slots)
        self._attest_semantic_digest(
            "governance request semantic_digest does not match"
        )
        return self


class GovernanceRoutingResponse(ClosedCanonicalModel):
    """Provider-local response: one placement per requested risk."""

    request_digest: Digest
    placements: tuple[GovernancePlacement, ...] = ()
    adapter_kind: Literal["fake", "provider"] = "fake"
    provider_calls: int = Field(default=0, ge=0, strict=True)


class GovernancePath(Protocol):
    """The hazards and constraints code attaches to a governance risk."""

    hazard_ids: tuple[str, ...]
    constraint_ids: tuple[str, ...]


@dataclass(frozen=True)
class GovernanceRoutingResult:
    """Routes for the placed risks and the reason every other risk has none."""

    routes: tuple[ObligationRoute, ...] = ()
    routed_briefs: tuple[NeutralObligationBrief, ...] = ()
    requests: tuple[GovernanceRoutingRequest, ...] = ()
    call_evidence: tuple[ConsiderationCallEvidence, ...] = ()
    declined: tuple[str, ...] = ()
    unresolved: dict[str, str] = field(default_factory=dict)
    diagnostics: tuple[str, ...] = ()


@dataclass
class _BatchOutcome:
    accepted: dict[str, GovernancePlacement] = field(default_factory=dict)
    errors: dict[str, str] = field(default_factory=dict)
    response: GovernanceRoutingResponse | None = None
    attempts: int = 0


def _clip(text: object) -> str:
    detail = " ".join(str(text).split())
    if len(detail) > _ERROR_MAX_CHARS:
        detail = detail[:_ERROR_MAX_CHARS].rstrip() + "..."
    return detail


def _governance_batches(
    briefs: Sequence[NeutralObligationBrief],
    *,
    max_batch_size: int,
    budget: PromptBudget | None,
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    slots: Sequence[SlotPlaceholder],
) -> tuple[tuple[NeutralObligationBrief, ...], ...]:
    """Split risks by batch size and, when a budget exists, rendered prompt size."""
    ordered = sorted(briefs, key=lambda item: item.risk_ref.risk_id)

    def fits(values: Sequence[NeutralObligationBrief]) -> bool:
        if budget is None:
            return True
        system, user = build_governance_routing_prompts(
            briefs=values,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            slots=slots,
        )
        return budget.count(f"{system}\n{user}") <= budget.usable_input_tokens

    return split_by_budget(ordered, max_batch_size, fits)


def _target_slots(slots: Sequence[SlotPlaceholder]) -> dict[str, tuple[str, ...]]:
    """Map every selectable identifier to the slots it covers."""
    covers: dict[str, set[str]] = {}
    for slot in slots:
        covers.setdefault(slot.slot_id, set()).add(slot.slot_id)
        covers.setdefault(slot.control_action, set()).add(slot.slot_id)
    return {key: tuple(sorted(value)) for key, value in covers.items()}


def _placement_error(
    placement: GovernancePlacement, covers: Mapping[str, tuple[str, ...]]
) -> str | None:
    unknown = sorted(
        {item.target_id for item in placement.targets if item.target_id not in covers}
    )
    if not unknown:
        return None
    return (
        f"risk_id {placement.risk_id}: target_id {', '.join(unknown)} is not an id "
        "in the index's control_actions or slots lists; use only listed ids"
    )


def _check_response(
    response: GovernanceRoutingResponse,
    request: GovernanceRoutingRequest,
    covers: Mapping[str, tuple[str, ...]],
) -> tuple[dict[str, GovernancePlacement], dict[str, str]]:
    """Split a response into valid placements and per-risk errors."""
    expected = [item.risk_ref.risk_id for item in request.briefs]
    if response.request_digest != request.semantic_digest:
        return {}, dict.fromkeys(expected, "response request_digest does not match")
    returned = [item.risk_id for item in response.placements]
    if sorted(returned) != expected:
        detail = (
            "return exactly one placement for every supplied risk_id "
            f"({', '.join(expected)}); received {', '.join(sorted(returned)) or 'none'}"
        )
        return {}, dict.fromkeys(expected, detail)
    accepted: dict[str, GovernancePlacement] = {}
    errors: dict[str, str] = {}
    for placement in response.placements:
        error = _placement_error(placement, covers)
        if error is None:
            accepted[placement.risk_id] = placement
        else:
            errors[placement.risk_id] = error
    return accepted, errors


def _feedback(errors: Mapping[str, str]) -> str:
    lines = " ".join(f"{error}." for _, error in sorted(errors.items()))
    return (
        "The previous response failed local validation. Correct only the invalid "
        f"placements. {lines} Return exactly one placement for every supplied "
        "risk_id, copy each risk_id unchanged, and use only ids listed in the index."
    )


def _attempt(
    adapter,
    request: GovernanceRoutingRequest,
    covers: Mapping[str, tuple[str, ...]],
    feedback: str | None,
) -> tuple[
    GovernanceRoutingResponse | None,
    dict[str, GovernancePlacement],
    dict[str, str],
]:
    """Make one call; a malformed answer fails every risk, a budget error escapes."""
    try:
        response = call_with_feedback(adapter.route_governance, request, feedback)
        if not isinstance(response, GovernanceRoutingResponse):
            raise TypeError("governance adapter returned an unsupported response")
        accepted, errors = _check_response(response, request, covers)
    except PromptBudgetExceeded:
        raise
    except (TypeError, ValueError) as exc:
        return None, {}, dict.fromkeys(_risk_ids(request), _clip(exc))
    return response, accepted, errors


def _run_batch(
    adapter,
    request: GovernanceRoutingRequest,
    covers: Mapping[str, tuple[str, ...]],
) -> _BatchOutcome:
    """Call the model, then repair invalid placements within the retry bound."""
    outcome = _BatchOutcome()
    sent = RequestTally()
    feedback: str | None = None
    for attempt in range(request.controls.validation_retries + 1):
        try:
            with count_requests(sent):
                response, accepted, errors = _attempt(
                    adapter, request, covers, feedback
                )
        except PromptBudgetExceeded as exc:
            pending = [
                item for item in _risk_ids(request) if item not in outcome.accepted
            ]
            outcome.errors = dict.fromkeys(pending, _clip(exc))
            break
        outcome.response = response or outcome.response
        outcome.accepted.update(accepted)
        outcome.errors = {k: v for k, v in errors.items() if k not in outcome.accepted}
        if not outcome.errors:
            break
        feedback = _feedback(outcome.errors)
    outcome.attempts = sent.requests
    return outcome


def _risk_ids(request: GovernanceRoutingRequest) -> list[str]:
    return [item.risk_ref.risk_id for item in request.briefs]


def _evidence(
    request: GovernanceRoutingRequest, outcome: _BatchOutcome
) -> ConsiderationCallEvidence:
    return call_evidence(
        f"stpa-governance-route:{request.batch_id}",
        outcome.attempts,
        "unresolved" if outcome.errors else "accepted",
        request_digest=request.semantic_digest,
        controls=request.controls,
        response=outcome.response,
        digest_domain=GOVERNANCE_RESPONSE_DIGEST_DOMAIN,
    )


def _route_for(
    brief: NeutralObligationBrief,
    placement: GovernancePlacement,
    path: GovernancePath,
    covers: Mapping[str, tuple[str, ...]],
    slots_by_id: Mapping[str, SlotPlaceholder],
    call_id: str,
) -> ObligationRoute:
    slot_ids = sorted(
        {slot for item in placement.targets for slot in covers[item.target_id]}
    )
    actions = {slots_by_id[slot].control_action for slot in slot_ids}
    evidence = dict.fromkeys(
        f"{item.target_id}: {item.reason}" for item in placement.targets
    )
    return ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=tuple(slot_ids),
        control_action_ids=tuple(sorted(actions)),
        hazard_ids=tuple(path.hazard_ids),
        constraint_ids=tuple(path.constraint_ids),
        rationale="; ".join(dict.fromkeys(item.reason for item in placement.targets)),
        evidence=tuple(evidence),
        model_call_refs=(call_id,),
    )


def route_governance_rows(
    adapter,
    *,
    briefs: Sequence[NeutralObligationBrief],
    paths: Mapping[str, GovernancePath],
    loss_analysis: LossAnalysis,
    control_structure: ControlStructure,
    controls: AnalysisControls | None = None,
    slots: Sequence[SlotPlaceholder] | None = None,
) -> GovernanceRoutingResult:
    """Route each governance brief to the slots of the actions it bears on."""
    if not briefs:
        return GovernanceRoutingResult()
    max_batch_size = controls.max_batch_size if controls is not None else 8
    effective = _default_controls(controls, max_batch_size)
    inventory = _slot_inventory(control_structure, slots)
    covers = _target_slots(inventory)
    slots_by_id = {item.slot_id: item for item in inventory}
    batches = _governance_batches(
        briefs,
        max_batch_size=max_batch_size,
        budget=_routing_prompt_budget(adapter, effective),
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        slots=inventory,
    )
    tally = _Tally(
        by_risk={item.risk_ref.risk_id: item for item in briefs},
        paths=paths,
        covers=covers,
        slots_by_id=slots_by_id,
    )
    for index, batch in enumerate(batches):
        request = GovernanceRoutingRequest(
            batch_id=f"governance-batch-{index + 1}",
            briefs=batch,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            slots=inventory,
            controls=effective,
        )
        tally.add(request, _run_batch(adapter, request, covers))
    return tally.result(briefs)


@dataclass
class _Tally:
    """Accumulates what each batch routed, declined, and could not place."""

    by_risk: Mapping[str, NeutralObligationBrief]
    paths: Mapping[str, GovernancePath]
    covers: Mapping[str, tuple[str, ...]]
    slots_by_id: Mapping[str, SlotPlaceholder]
    requests: list[GovernanceRoutingRequest] = field(default_factory=list)
    evidence: list[ConsiderationCallEvidence] = field(default_factory=list)
    routes: list[ObligationRoute] = field(default_factory=list)
    declined: list[str] = field(default_factory=list)
    unresolved: dict[str, str] = field(default_factory=dict)
    diagnostics: list[str] = field(default_factory=list)

    def add(self, request: GovernanceRoutingRequest, outcome: _BatchOutcome) -> None:
        call = _evidence(request, outcome)
        self.requests.append(request)
        self.evidence.append(call)
        for risk_id, placement in sorted(outcome.accepted.items()):
            if placement.targets:
                self.routes.append(
                    _route_for(
                        self.by_risk[risk_id],
                        placement,
                        self.paths[risk_id],
                        self.covers,
                        self.slots_by_id,
                        call.call_id,
                    )
                )
            else:
                self.declined.append(risk_id)
        for risk_id, error in sorted(outcome.errors.items()):
            self.unresolved[risk_id] = error
            self.diagnostics.append(f"{request.batch_id} exhausted validation: {error}")

    def result(
        self, briefs: Sequence[NeutralObligationBrief]
    ) -> GovernanceRoutingResult:
        ordered = tuple(sorted(self.routes, key=lambda item: item.obligation_id))
        routed = {item.obligation_id for item in ordered}
        return GovernanceRoutingResult(
            routes=ordered,
            routed_briefs=tuple(
                sorted(
                    (item for item in briefs if item.obligation_id in routed),
                    key=lambda item: item.obligation_id,
                )
            ),
            requests=tuple(self.requests),
            call_evidence=tuple(self.evidence),
            declined=tuple(sorted(self.declined)),
            unresolved=self.unresolved,
            diagnostics=tuple(sorted(self.diagnostics)),
        )
