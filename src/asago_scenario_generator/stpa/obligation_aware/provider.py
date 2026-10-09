"""Provider adapter for the named obligation-aware STPA stages.

The adapter is deliberately thin: prompt construction, bounded retries, and
call logging use the existing STPA infrastructure while deterministic routing,
revision compilation, and slot/reference validation remain local pure seams.
"""

from __future__ import annotations

from collections.abc import Iterable
from functools import lru_cache, partial
from pathlib import Path
from typing import Annotated, Any, Literal, Mapping, Sequence, Union

from pydantic import Field, create_model, model_validator

from asago_scenario_generator.models.artifact_pin import ObligationId
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
    ObligationIcaConsideration,
    ObligationSemanticAssessment,
    StructuralConceptKind,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.call_log import (
    call_log_of,
    mark_call_published,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    ExactFeedbackError,
    call_with_policy,
    log_llm_call_failure,
    parse_llm_result,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptAudit,
    audit_prompt_contract as preflight_prompt_contract,
    enforce_prompt_audit,
    resolve_prompt_budget,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICASlot,
    classify_ica_semantics,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    DEVIATION_FIELD_BY_UCA_TYPE,
    AnalysisControls,
    DraftControlAction,
    DraftControlledProcess,
    DraftCoordinationLink,
    DraftFeedbackChannel,
    DraftHazard,
    DraftLoss,
    DraftProcessModelPart,
    DraftResponsibility,
    DraftSecurityConstraint,
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    ObligationRoute,
    RevisionDraft,
    RevisionGapDecision,
    StructuralRevisionRequest,
    StructuralRevisionResponse,
    StructuralRoutingRequest,
    StructuralRoutingResponse,
    SynthesisSlotRequest,
    SynthesisSlotResponse,
    SlotIcaDraft,
    _Model,
)
from asago_scenario_generator.stpa.obligation_aware.context_coverage import (
    CONTEXT_COVERAGE_STAGE_SUFFIX,
    build_context_coverage_prompts,
    context_coverage_gaps,
    merge_supplement,
    validate_supplement_entries,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationRequest,
    IcaHazardVerificationCorrection,
    IcaHazardVerificationVerdict,
    absence_evidence_defects,
    requires_absence_evidence,
    unproven_absence_verdict,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    PROHIBITED_PROMPT_KEYS,
    PROHIBITED_PROMPT_WORDS,
    audit_prompt_contract,
    build_ica_hazard_correction_prompts,
    build_ica_hazard_verification_prompts,
    build_mechanism_verification_prompts,
    local_obligation_handles,
    mapping_strength_for_brief,
    obligation_prompt_template_hashes,
    project_obligation_routing_context,
    project_ica_target_context,
    project_revision_context,
    render_structural_revision_prompts,
    render_structural_routing_prompts,
    render_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _draft_considerations,
    _finding_context,
    _slot_authority,
    _validate_finding_semantics,
    compile_slot_provider_entry,
)
from asago_scenario_generator.stpa.obligation_aware.payload_types import (
    exact_length_payload_type,
    require_non_negative_count,
    require_positive_count,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    StpaIndex,
    build_stpa_index,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import SlotPlaceholder

_SYNTHESIS_MAX_COMPLETION_TOKENS = 8192
_ICA_VERIFICATION_REPAIRS = 1
_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS = 8192
_MECHANISM_VERIFICATION_MAX_COMPLETION_TOKENS = 1024
_MECHANISM_VERIFICATION_REPAIRS = 1


def _reference_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    """Collect explained ``id``/``description`` pairs from a prompt view."""
    pairs: dict[str, str] = {}
    _visit_reference_pairs(value, pairs)
    return tuple(sorted(pairs.items()))


def _visit_reference_pairs(item: Any, pairs: dict[str, str]) -> None:
    """Walk one closed prompt view and retain its explained identities."""
    if hasattr(item, "model_dump"):
        _visit_reference_pairs(item.model_dump(mode="python"), pairs)
        return
    if isinstance(item, dict):
        _record_reference_pair(item, pairs)
        children = item.values()
    elif isinstance(item, (list, tuple, set, frozenset)):
        children = item
    else:
        return
    for child in children:
        _visit_reference_pairs(child, pairs)


def _record_reference_pair(item: dict, pairs: dict[str, str]) -> None:
    """Retain one non-empty ID/description pair when present."""
    identifier = item.get("id")
    description = item.get("description")
    if (
        isinstance(identifier, str)
        and isinstance(description, str)
        and identifier
        and description.strip()
    ):
        pairs.setdefault(identifier, description)


def _routing_prompt_handles(view: Any) -> tuple[str, ...]:
    """Return opaque obligation handles from one routing prompt view."""
    return tuple(item.obligation_handle for item in view.obligation_questions)


def _slot_prompt_handles(
    target_id: str,
    questions: tuple[Any, ...],
    routes: tuple[Any, ...],
) -> tuple[str, ...]:
    """Return every opaque handle copied by one ICA target prompt."""
    return (
        target_id,
        *dict.fromkeys(
            (
                *(item.obligation_handle for item in questions),
                *(item.route_handle for item in routes),
            )
        ),
    )


def _resolve_slot_handles(payload: _Model, by_local: Mapping[str, str]) -> _Model:
    """Replace each local obligation handle in a slot payload with its identity.

    A handle outside the request's set stays as written, so the exact-pair
    validation rejects it and the repair names it.
    """
    return payload.model_copy(
        update={
            "filled_slots": tuple(
                value.model_copy(
                    update={
                        "consideration_results": tuple(
                            result.model_copy(
                                update={
                                    "obligation_handle": by_local.get(
                                        result.obligation_handle,
                                        result.obligation_handle,
                                    )
                                }
                            )
                            for result in value.consideration_results
                        )
                    }
                )
                for value in payload.filled_slots
            )
        }
    )


def _require_known_slot_handles(payload: _Model, by_local: Mapping[str, str]) -> None:
    """Name every obligation handle the prompt never showed, and the valid ones."""
    unknown = sorted(
        {
            result.obligation_handle
            for value in payload.filled_slots
            for result in value.consideration_results
            if result.obligation_handle not in by_local
        }
    )
    if unknown:
        raise ExactFeedbackError(
            f"unknown obligation_handle: {', '.join(unknown)}; copy one of the "
            f"supplied handles: {', '.join(sorted(by_local, key=_handle_order))}"
        )


def _localized_slot_error(message: str, request: SynthesisSlotRequest) -> str:
    """Say each route and obligation identity in a message as its local handle."""
    handles = local_obligation_handles(request.routed_routes)
    for route in request.routed_routes:
        handle = handles[route.obligation_id]
        if route.route_id:
            message = message.replace(route.route_id, handle)
        message = message.replace(route.obligation_id, handle)
    return message


def _with_correction_feedback(prompt: str, feedback: str | None) -> str:
    """Append one bounded routing correction when supplied."""
    return prompt if not feedback else f"{prompt}\nValidation correction:\n{feedback}\n"


def _preflight(
    *,
    view: Any,
    system_prompt: str,
    user_prompt: str,
    stage: str,
    handles: tuple[str, ...],
    stage_max_completion_tokens: int,
    client: Any,
    controls: AnalysisControls,
    configured_budget: PromptBudget | None,
    output_schema: tuple[str, ...],
    valid_example: dict[str, Any],
    run_dir: Path,
    call_stage: str,
    step: str,
) -> None:
    """Run the local view audit and the repository-wide prompt preflight."""
    prompt_audit: PromptAudit | None = None
    try:
        audit_prompt_contract(
            view,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            stage=stage,
            opaque_handles=handles,
        ).assert_valid()
        pairs = _reference_pairs(view)
        prompt_audit = preflight_prompt_contract(
            stage=stage,
            prompt_view=view,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            expected_view_type=type(view),
            input_handles=handles,
            accounted_handles=handles,
            selectable_references=pairs,
            authoritative_references=pairs,
            prohibited_fields=PROHIBITED_PROMPT_WORDS,
            prohibited_exact_keys=PROHIBITED_PROMPT_KEYS,
            output_schema=output_schema,
            valid_example=valid_example,
            budget=resolve_prompt_budget(
                client,
                controls,
                configured_budget,
                maximum_completion_tokens=stage_max_completion_tokens,
            ),
            raise_on_error=False,
        )
        enforce_prompt_audit(prompt_audit)
    except Exception as exc:
        # This preflight runs before ``call_with_policy`` and therefore otherwise
        # leaves no durable record for a routed target that never dispatches.
        # Keep the exact audit (including rendered size and contract errors)
        # beside the request-bound failure without pretending a provider call
        # occurred.
        log_llm_call_failure(
            str(getattr(client, "model", "unknown")),
            run_dir,
            call_stage,
            step,
            f"{type(exc).__name__}: {exc}",
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            prompt_audit=prompt_audit,
            call_log=call_log_of(client),
        )
        raise


class _RoutingProviderPayload(_Model):
    """Provider-only response body; request identity is attached locally.

    The provider must return at least one semantic route.  Exact batch
    cardinality is supplied by :func:`_routing_provider_payload_type` because
    the provider schema is built per request.  Route and gap identities are
    intentionally absent here: those are content-addressed from the returned
    semantic fields by the authoritative models after the response is parsed.
    """

    routes: tuple["_RoutingProviderRouteUnion", ...] = Field(min_length=1)


class _RoutingProviderMissingConcept(_Model):
    """Provider-facing gap semantics without the derived ``gap_id``."""

    concept_type: StructuralConceptKind
    description: str = Field(min_length=1)
    concept_id: str | None = None
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    obligation_id: ObligationId | None = None


class _RoutingProviderSemanticAssessment(_Model):
    """Provider-only semantic assessment.

    ``mapping_strength`` is derived from the pinned mapping evidence by the
    local adapter.  It is deliberately not part of this wire model, so a
    provider cannot choose or copy a durable classification.
    """

    mechanism_assessment: Literal[
        "plausible_in_system", "absent_from_system", "insufficient_evidence"
    ]
    risk_alignment: Literal["supported", "mismatch", "insufficient_evidence"]
    mechanism_rationale: str = Field(min_length=1)
    risk_alignment_rationale: str = Field(min_length=1)


class _RoutingProviderRouteBase(_Model):
    """Fields shared by each disposition-specific routing branch."""

    obligation_id: ObligationId
    semantic_assessment: _RoutingProviderSemanticAssessment
    rationale: str = Field(min_length=1)
    evidence: tuple[str, ...] = Field(min_length=1)


class _RoutingProviderRoute(_RoutingProviderRouteBase):
    """Provider-facing targeted route semantics without derived identity.

    The historical private name is retained because deterministic callers
    inspect the provider schema by definition name.  The payload uses this
    model as one branch of a discriminated union.
    """

    disposition: Literal["targeted"]
    slot_ids: tuple[str, ...] = Field(min_length=1)
    controller_ids: tuple[str, ...] = ()
    control_action_ids: tuple[str, ...] = ()
    responsibility_ids: tuple[str, ...] = ()
    process_model_part_ids: tuple[str, ...] = ()
    feedback_channel_ids: tuple[str, ...] = ()
    controlled_process_ids: tuple[str, ...] = ()
    coordination_link_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = Field(min_length=1)
    constraint_ids: tuple[str, ...] = Field(min_length=1)


class _RoutingProviderNotApplicableRoute(_RoutingProviderRouteBase):
    """Provider-facing proposed non-applicability route."""

    disposition: Literal["proposed_not_applicable"]


class _RoutingProviderUpstreamGapRoute(_RoutingProviderRouteBase):
    """Provider-facing route identifying a missing structural concept."""

    disposition: Literal["upstream_gap"]
    missing_concepts: tuple[_RoutingProviderMissingConcept, ...] = Field(min_length=1)


class _RoutingProviderUnresolvedRoute(_RoutingProviderRouteBase):
    """Provider-facing route whose supplied evidence cannot decide."""

    disposition: Literal["unresolved"]


_RoutingProviderRouteUnion = Annotated[
    _RoutingProviderRoute
    | _RoutingProviderNotApplicableRoute
    | _RoutingProviderUpstreamGapRoute
    | _RoutingProviderUnresolvedRoute,
    Field(discriminator="disposition"),
]


_RoutingProviderPayload.model_rebuild()


@lru_cache(maxsize=16)
def _routing_provider_payload_type(
    route_count: int, *, obligation_ids: tuple[str, ...] = ()
) -> type[_Model]:
    """Build a strict provider payload for exactly one route per brief.

    ``ObligationRoute`` owns the derived route/gap IDs and its conditional
    domain validation.  This provider-only shape asks the model for the
    semantic decision and exact authority references while leaving those
    content-addressed identities to local code.  A per-batch constrained list
    makes an otherwise-valid empty/default response impossible at the native
    structured-output boundary.
    """
    require_positive_count(route_count, "route_count")
    return exact_length_payload_type(
        f"_RoutingProviderPayload{route_count}",
        _RoutingProviderPayload,
        "routes",
        _routing_exact_identity_union(obligation_ids),
        route_count,
        module=__name__,
    )


def _routing_exact_identity_union(obligation_ids: tuple[str, ...]) -> object:
    """Give guided decoding the exact supplied IDs, never digest-shaped guesses."""
    if not obligation_ids:
        return _RoutingProviderRouteUnion
    variants = tuple(
        create_model(
            base.__name__,
            __base__=base,
            obligation_id=(Literal.__getitem__(obligation_ids), ...),
        )
        for base in (
            _RoutingProviderRoute,
            _RoutingProviderNotApplicableRoute,
            _RoutingProviderUpstreamGapRoute,
            _RoutingProviderUnresolvedRoute,
        )
    )
    return Annotated[Union[variants], Field(discriminator="disposition")]


def _materialize_routing_route(
    value: _RoutingProviderRouteUnion,
    *,
    mapping_strength: str,
) -> ObligationRoute:
    """Derive authoritative route and gap IDs from provider semantics."""
    data = value.model_dump(mode="python")
    assessment = dict(data["semantic_assessment"])
    assessment["mapping_strength"] = mapping_strength
    data["semantic_assessment"] = assessment
    data["missing_concepts"] = tuple(
        concept.model_dump(mode="python")
        for concept in getattr(value, "missing_concepts", ())
    )
    return ObligationRoute.model_validate(data)


class _MechanismVerdict(_Model):
    """One narrow mechanism-to-selected-path judgement."""

    item_handle: str = Field(min_length=1)
    relationship: Literal[
        "mechanism_specific", "adjacent_control", "insufficient_evidence"
    ]
    rationale: str = Field(min_length=1)


class _MechanismVerdictPayload(_Model):
    """Provider payload whose exact cardinality is supplied per request."""

    verdicts: tuple[_MechanismVerdict, ...] = Field(min_length=1)


class _IcaHazardProviderVerdict(_Model):
    """Separate semantic judgements; the aggregate and binding belong to code."""

    review_ref: str = Field(min_length=1)
    rationale: str = Field(min_length=1, max_length=2000)
    action_state: Literal[
        "absent",
        "performed_unsafe",
        "wrong_timing",
        "wrong_duration",
        "different_action",
        "undetermined",
    ]
    hazard_path: Literal["supported", "contradictory", "insufficient_evidence"]
    absence_loss_ids: tuple[str, ...] = ()
    absence_consequence: str = ""

    def verdict_for(self, uca_type: str) -> str:
        """Compare independently described behaviour to the compiler-owned slot."""
        return classify_ica_semantics(
            uca_type, action_state=self.action_state, hazard_path=self.hazard_path
        )


class _IcaHazardProviderPayload(_Model):
    """Provider payload with one semantic judgement per supplied ICA."""

    verdicts: tuple[_IcaHazardProviderVerdict, ...] = Field(min_length=1)


def _ica_review_requests(
    requests: Sequence[IcaHazardVerificationRequest],
) -> dict[str, IcaHazardVerificationRequest]:
    """Bind blind review references without allowing duplicate source identities."""
    if len({item.ica_id for item in requests}) != len(requests):
        raise ValueError("ICA hazard verification requests must have unique ICA IDs")
    return {f"review-{index}": request for index, request in enumerate(requests, 1)}


def _compile_ica_review_payload(
    payload: _IcaHazardProviderPayload,
    requests: Mapping[str, IcaHazardVerificationRequest],
) -> tuple[IcaHazardVerificationVerdict, ...]:
    """Require exact review accounting and restore only compiler-owned identities."""
    refs = tuple(item.review_ref for item in payload.verdicts)
    if set(refs) != set(requests) or len(refs) != len(requests):
        raise ValueError(
            "ICA hazard verification must account for every supplied ICA exactly once"
        )
    ordered = sorted(
        payload.verdicts, key=lambda item: requests[item.review_ref].ica_id
    )
    return tuple(_bound_ica_review(item, requests[item.review_ref]) for item in ordered)


def _bound_ica_review(
    item: _IcaHazardProviderVerdict, request: IcaHazardVerificationRequest
) -> IcaHazardVerificationVerdict:
    """Retain the observed state as actionable bounded-correction feedback.

    A supported hazardous absence that still lacks valid evidence is not
    supported: it becomes the downgraded verdict, and the others stand.
    """
    verdict = item.verdict_for(request.uca_type)
    rationale = (
        f"Observed action state: {item.action_state}; proposed category: "
        f"{request.uca_type.value}. {item.rationale}"
    )
    evidence: dict[str, Any] = {}
    if requires_absence_evidence(request, verdict):
        loss_ids = tuple(dict.fromkeys(item.absence_loss_ids))
        consequence = item.absence_consequence.strip()
        defects = absence_evidence_defects(
            request, loss_ids=loss_ids, consequence=consequence
        )
        if defects:
            return unproven_absence_verdict(
                request, rationale=rationale, defects=defects
            )
        evidence = {"absence_loss_ids": loss_ids, "absence_consequence": consequence}
    return IcaHazardVerificationVerdict(
        ica_id=request.ica_id,
        request_digest=request.semantic_digest,
        verdict=verdict,
        rationale=rationale,
        **evidence,
    )


class _AbsenceEvidenceRepair:
    """Spend the one repair on missing absence evidence, then take the response.

    The correction policy repairs a response only while its validator raises,
    so the validator has to stop raising on the response that follows the
    repair; the response is then compiled with the unproven absences
    downgraded. The parser counts the responses, so a response that failed its
    schema also leaves the evidence check its one repair.
    """

    def __init__(
        self,
        requests: Mapping[str, IcaHazardVerificationRequest],
        payload_type: type[_IcaHazardProviderPayload],
        repairs: int,
    ) -> None:
        self._requests = requests
        self._payload_type = payload_type
        self._repairs = repairs
        self._responses = 0

    def parse(
        self, result: Any, cleanup: list[dict[str, Any]]
    ) -> _IcaHazardProviderPayload:
        self._responses += 1
        return parse_llm_result(
            result, self._payload_type, cleanup_transformations=cleanup
        )

    def validate(self, payload: _IcaHazardProviderPayload) -> None:
        if self._responses <= self._repairs:
            _validate_ica_absence_evidence(payload, self._requests)


def _validate_ica_absence_evidence(
    payload: _IcaHazardProviderPayload,
    requests: Mapping[str, IcaHazardVerificationRequest],
) -> None:
    """Ask for exactly the missing absence evidence, one line per defect."""
    lines = []
    for item in payload.verdicts:
        request = requests.get(item.review_ref)
        if request is None or not requires_absence_evidence(
            request, item.verdict_for(request.uca_type)
        ):
            continue
        defects = absence_evidence_defects(
            request,
            loss_ids=item.absence_loss_ids,
            consequence=item.absence_consequence,
        )
        lines.extend(f"- {item.review_ref}: {defect}" for defect in defects)
    if lines:
        raise ExactFeedbackError(
            "A review whose action_state is absent and whose hazard_path is "
            "supported must fill absence_loss_ids and absence_consequence:\n"
            + "\n".join(lines)
        )


class _IcaHazardCorrectionPayload(_Model):
    """Provider-only correction envelope."""

    correction: IcaHazardVerificationCorrection


@lru_cache(maxsize=16)
def _mechanism_verdict_payload_type(verdict_count: int) -> type[_Model]:
    """Build a strict verifier payload for every selected route."""
    require_positive_count(verdict_count, "verdict_count")
    return exact_length_payload_type(
        f"_MechanismVerdictPayload{verdict_count}",
        _MechanismVerdictPayload,
        "verdicts",
        _MechanismVerdict,
        verdict_count,
        module=__name__,
    )


@lru_cache(maxsize=16)
def _ica_hazard_provider_payload_type(verdict_count: int) -> type[_Model]:
    """Build a strict provider payload for an exact ICA batch cardinality."""
    require_positive_count(verdict_count, "verdict_count")
    return exact_length_payload_type(
        f"_IcaHazardProviderPayload{verdict_count}",
        _IcaHazardProviderPayload,
        "verdicts",
        _IcaHazardProviderVerdict,
        verdict_count,
        module=__name__,
    )


def _structural_descriptions(request: StructuralRoutingRequest) -> dict[str, str]:
    """Index only exact structural descriptions available to the verifier.

    Responsibility constraints and losses stay out: the verifier has no
    description for them.
    """
    index = build_stpa_index(request.control_structure, request.loss_analysis)
    return {
        identity: record.description
        for records in (
            index.responsibilities,
            index.control_actions,
            index.process_model_parts,
            index.feedback_channels,
            index.coordination_links,
            index.coordination_mechanisms,
            index.controlled_processes,
            index.hazards,
            index.security_constraints,
        )
        for identity, record in records.items()
    }


def _verification_handles(routes: Sequence[ObligationRoute]) -> dict[str, str]:
    """Name each verified route ``R1``..``Rn`` in the order it is shown."""
    return {route.obligation_id: f"R{index}" for index, route in enumerate(routes, 1)}


def _mechanism_verification_items(
    request: StructuralRoutingRequest,
    routes: Sequence[ObligationRoute],
) -> tuple[dict[str, Any], ...]:
    """Project each credited route without capability or mapping distractions."""
    brief_by_id = {item.obligation_id: item for item in request.briefs}
    descriptions = _structural_descriptions(request)
    handles = _verification_handles(routes)
    items: list[dict[str, Any]] = []
    for route in routes:
        brief = brief_by_id[route.obligation_id]
        selected_ids = list(
            (
                *route.controller_ids,
                *route.responsibility_ids,
                *route.control_action_ids,
                *route.process_model_part_ids,
                *route.feedback_channel_ids,
                *route.controlled_process_ids,
                *route.coordination_link_ids,
                *route.hazard_ids,
                *route.constraint_ids,
            )
        )
        selected_ids.extend(_slot_path_ids(request, route))
        items.append(
            {
                "item_handle": handles[route.obligation_id],
                "distinctive_mechanism": {
                    "name": brief.attack_pattern_name,
                    "description": brief.attack_pattern_description,
                },
                "selected_structural_path": [
                    {"id": identity, "description": descriptions[identity]}
                    for identity in dict.fromkeys(selected_ids)
                ],
            }
        )
    return tuple(items)


def _slot_path_ids(
    request: StructuralRoutingRequest, route: ObligationRoute
) -> tuple[str, ...]:
    """Resolve verifier context from authoritative slots, not optional echoes."""
    index = build_stpa_index(request.control_structure)
    selected_slots = _selected_verifier_slots(request, route)
    return tuple(
        identity
        for slot in selected_slots
        for identity in _one_slot_path_ids(slot, index)
    )


def _selected_verifier_slots(
    request: StructuralRoutingRequest, route: ObligationRoute
) -> tuple[Any, ...]:
    """Select the exact slot records named by one route."""
    return tuple(slot for slot in request.slots if slot.slot_id in route.slot_ids)


def _one_slot_path_ids(slot: Any, index: StpaIndex) -> tuple[str, ...]:
    """Dispatch one selected slot to its authoritative path projector."""
    if slot.responsibility is not None:
        return _responsibility_slot_path_ids(
            index.responsibilities[slot.responsibility], slot.control_action
        )
    return _optional_coordination_slot_path_ids(slot, index)


def _optional_coordination_slot_path_ids(
    slot: Any, index: StpaIndex
) -> tuple[str, ...]:
    """Project a coordination slot, or no path for a malformed placeholder."""
    if slot.coordination_link is None:
        return ()
    return _coordination_slot_path_ids(index.coordination_links[slot.coordination_link])


def _responsibility_slot_path_ids(
    responsibility: Any, control_action_id: str
) -> tuple[str, ...]:
    """Return the authoritative context owned by one responsibility slot."""
    action = next(
        item
        for item in responsibility.control_actions
        if item.ca_id == control_action_id
    )
    target_ids = () if action.target is None else (action.target.id,)
    return (
        control_action_id,
        responsibility.resp_id,
        *(item.pm_id for item in responsibility.process_model_parts),
        *(item.fb_id for item in responsibility.feedback_channels),
        *target_ids,
    )


def _coordination_slot_path_ids(link: Any) -> tuple[str, ...]:
    """Return the authoritative context owned by one coordination slot."""
    return (
        link.coordination_mechanism.cm_id,
        link.link_id,
        link.source,
        link.target,
        link.shared_pm,
    )


def _unsubstantiated_route(
    route: ObligationRoute,
    relationship: str,
    rationale: str,
) -> ObligationRoute:
    """Keep the STPA path while removing unsupported mechanism credit."""
    assessment = route.semantic_assessment
    if assessment is None:
        return route
    updated_assessment = ObligationSemanticAssessment.model_validate(
        {
            **assessment.model_dump(mode="python"),
            "mechanism_assessment": "insufficient_evidence",
            "mechanism_rationale": rationale,
        }
    )
    diagnostic = ConsiderationDiagnostic(
        code="mechanism_path_unsubstantiated",
        detail=(f"selected STPA path relationship is {relationship}: {rationale}"),
        obligation_ids=(route.obligation_id,),
        refs=(route.route_id,),
    )
    payload = route.model_dump(mode="python", exclude={"route_id"})
    payload["semantic_assessment"] = updated_assessment
    payload["diagnostics"] = (*route.diagnostics, diagnostic)
    return ObligationRoute.model_validate(payload)


def _apply_verdict(
    route: ObligationRoute, verdict: _MechanismVerdict | None
) -> ObligationRoute:
    """Apply one verdict without changing any structural selection.

    A route without a verdict loses mechanism credit but keeps its STPA path.
    """
    if verdict is None:
        return _unsubstantiated_route(
            route,
            "insufficient_evidence",
            "the focused mechanism-path verification did not complete",
        )
    if verdict.relationship == "mechanism_specific":
        return route
    return _unsubstantiated_route(route, verdict.relationship, verdict.rationale)


def _verification_key(item: Mapping[str, Any]) -> tuple:
    """Identify a verifier request by its content, not by its handle."""
    mechanism = item["distinctive_mechanism"]
    path = sorted(
        (entry["id"], entry["description"])
        for entry in item["selected_structural_path"]
    )
    return (mechanism["name"], mechanism["description"], tuple(path))


def _verdict_map(
    handles: Iterable[str], verdicts: Sequence[_MechanismVerdict]
) -> dict[str, _MechanismVerdict]:
    """Validate exact verifier cardinality and return its handle map."""
    expected = set(handles)
    actual = [item.item_handle for item in verdicts]
    if set(actual) != expected or len(actual) != len(expected):
        raise ExactFeedbackError(
            "mechanism verifier must return exactly one verdict for each item "
            f"handle (expected={sorted(expected, key=_handle_order)}, "
            f"returned={sorted(actual)})"
        )
    return {item.item_handle: item for item in verdicts}


def _require_verdict_handles(
    handles: Iterable[str], payload: _MechanismVerdictPayload
) -> None:
    """Reject a verdict set that does not answer each item handle once."""
    _verdict_map(handles, payload.verdicts)


def _handle_order(handle: str) -> tuple[int, str]:
    """Order ``R2`` before ``R10`` when listing handles in feedback."""
    return (len(handle), handle)


def _verification_candidates(
    routes: Sequence[ObligationRoute],
) -> tuple[ObligationRoute, ...]:
    """Select only routes that could otherwise receive obligation credit."""
    return tuple(
        route
        for route in routes
        if route.disposition == "targeted"
        and route.semantic_assessment is not None
        and route.semantic_assessment.risk_alignment == "supported"
    )


def _merge_verified_routes(
    routes: Sequence[ObligationRoute], verified: Sequence[ObligationRoute]
) -> tuple[ObligationRoute, ...]:
    """Replace only the verifier candidates in their original order."""
    verified_by_id = {item.obligation_id: item for item in verified}
    return tuple(verified_by_id.get(route.obligation_id, route) for route in routes)


def _run_mechanism_verifier(
    adapter: "ObligationAwareLLMAdapter",
    request: StructuralRoutingRequest,
    candidates: Sequence[ObligationRoute],
) -> tuple[tuple[ObligationRoute, ...], bool]:
    """Judge each distinct request once per run and return whether a call published.

    Two routes with the same mechanism and the same selected path are one
    request, so they share one verdict even when they sit in different
    batches. A request whose verification failed is not remembered.
    """
    key_of = {
        route.obligation_id: _verification_key(
            _mechanism_verification_items(request, (route,))[0]
        )
        for route in candidates
    }
    known = adapter.mechanism_verdicts
    pending: dict[tuple, ObligationRoute] = {}
    for route in candidates:
        key = key_of[route.obligation_id]
        if key not in known:
            pending.setdefault(key, route)
    published = False
    if pending:
        asked = tuple(pending.values())
        answered = _ask_mechanism_verifier(adapter, request, asked)
        if answered is not None:
            published = True
            handles = _verification_handles(asked)
            for key, route in pending.items():
                known[key] = answered[handles[route.obligation_id]]
    verified = tuple(
        _apply_verdict(route, known.get(key_of[route.obligation_id]))
        for route in candidates
    )
    return verified, published


def _ask_mechanism_verifier(
    adapter: "ObligationAwareLLMAdapter",
    request: StructuralRoutingRequest,
    asked: Sequence[ObligationRoute],
) -> dict[str, _MechanismVerdict] | None:
    """Send one compact verifier call; return verdicts by item handle or None."""
    system_prompt, user_prompt = build_mechanism_verification_prompts(
        _mechanism_verification_items(request, asked)
    )
    handles = _verification_handles(asked).values()
    outcome = call_with_policy(
        llm_client=adapter.llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=_mechanism_verdict_payload_type(len(asked)),
        run_dir=adapter.run_dir,
        stage=f"{adapter.stage_prefix}_mechanism_verification",
        step=request.batch_id,
        policy=CorrectionPolicy(
            validation_retries=_MECHANISM_VERIFICATION_REPAIRS,
            feedback=" Return one verdict for each item handle, copied unchanged.",
        ),
        temperature=0.0,
        max_completion_tokens=_MECHANISM_VERIFICATION_MAX_COMPLETION_TOKENS,
        result_validator=partial(_require_verdict_handles, handles),
        prompt_template_hashes=obligation_prompt_template_hashes(),
    )
    if outcome.error is not None or outcome.value is None:
        return None
    return _verdict_map(handles, outcome.value.verdicts)


class _RevisionProviderPayload(_Model):
    """Provider-only additive draft response body."""

    status: Literal["completed", "rejected"] = "completed"
    draft: "_RevisionProviderDraft"
    gap_decisions: tuple[RevisionGapDecision, ...]


class _RevisionProviderDraft(_Model):
    """Request-local revision fields without legacy final-gap identities."""

    losses: tuple[DraftLoss, ...] = ()
    hazards: tuple[DraftHazard, ...] = ()
    security_constraints: tuple[DraftSecurityConstraint, ...] = ()
    responsibilities: tuple[DraftResponsibility, ...] = ()
    controlled_processes: tuple[DraftControlledProcess, ...] = ()
    process_model_parts: tuple[DraftProcessModelPart, ...] = ()
    control_actions: tuple[DraftControlAction, ...] = ()
    feedback_channels: tuple[DraftFeedbackChannel, ...] = ()
    coordination_links: tuple[DraftCoordinationLink, ...] = ()
    rationale: str = ""


_RevisionProviderPayload.model_rebuild()


class _SlotProviderPayload(_Model):
    """Provider-only normative slot-draft response body.

    Historical final ``ICASlot`` values and top-level considerations remain
    accepted by the outer deterministic slot adapter, but are deliberately
    absent from the model-facing schema.  Giving a model two representations
    for the same decision produced mixed envelopes that could not be resolved
    safely.
    """

    filled_slots: tuple["_SlotProviderDraft", ...] = Field(min_length=1)


class _SlotProviderFindingDraft(_Model):
    """Model-authored ICA semantics without a model-selected UCA category."""

    deviation: str = Field(min_length=1)
    hazardous_context: str = Field(min_length=1)
    loss_consequence: str = Field(min_length=1)
    related_hazard_ids: tuple[str, ...] = Field(min_length=1)
    related_constraint_ids: tuple[str, ...] = Field(min_length=1, max_length=1)
    process_model_refs: tuple[str, ...] = ()
    feedback_refs: tuple[str, ...] = ()
    context_row: str | None = None


class _SlotProviderDraft(_Model):
    """One request-local slot whose exact UCA type comes from the request."""

    slot_id: str = Field(min_length=1)
    is_na: bool
    na_rationale: str | None = None
    findings: tuple[_SlotProviderFindingDraft, ...] = ()
    consideration_results: tuple[ObligationIcaDraft, ...] = ()

    @model_validator(mode="after")
    def validate_na_and_findings(self) -> "_SlotProviderDraft":
        if self.is_na:
            _validate_na_slot_draft(self)
        else:
            _validate_finding_slot_draft(self)
        return self


def _validate_na_slot_draft(value: _SlotProviderDraft) -> None:
    """Require the closed N/A shape."""
    if value.findings:
        raise ValueError("N/A ICA draft cannot contain findings")
    if not value.na_rationale or not value.na_rationale.strip():
        raise ValueError("N/A ICA draft requires a non-empty na_rationale")


def _validate_finding_slot_draft(value: _SlotProviderDraft) -> None:
    """Require at least one finding for a non-N/A slot."""
    if not value.findings:
        raise ValueError("non-N/A ICA draft requires at least one finding")


_SlotProviderPayload.model_rebuild()


class _ContextSupplementEntry(_Model):
    """The model's assessment of one context gap."""

    gap_id: str = Field(min_length=1)
    findings: tuple[_SlotProviderFindingDraft, ...] = ()
    rationale: str = Field(min_length=1)


class _ContextSupplementPayload(_Model):
    """Provider-only response body of the context-coverage supplement."""

    entries: tuple[_ContextSupplementEntry, ...] = Field(min_length=1)


@lru_cache(maxsize=16)
def _slot_provider_payload_type(
    slot_count: int,
    required_pair_count: int,
    *,
    constraint_ids: tuple[str, ...] = (),
) -> type[_Model]:
    """Build a provider payload constrained to one request's exact counts."""
    require_positive_count(slot_count, "slot_count")
    require_non_negative_count(required_pair_count, "required_pair_count")
    return exact_length_payload_type(
        f"_SlotProviderPayload{slot_count}Pairs{required_pair_count}",
        _SlotProviderPayload,
        "filled_slots",
        _slot_exact_constraint_type(constraint_ids),
        slot_count,
        module=__name__,
    )


def _slot_exact_constraint_type(constraint_ids: tuple[str, ...]) -> type[_Model]:
    """Constrain one governing-constraint choice to actual supplied identities."""
    if not constraint_ids:
        return _SlotProviderDraft
    finding = create_model(
        _SlotProviderFindingDraft.__name__,
        __base__=_SlotProviderFindingDraft,
        related_constraint_ids=(
            Annotated[
                tuple[Literal.__getitem__(constraint_ids), ...],
                Field(min_length=1, max_length=1),
            ],
            ...,
        ),
    )
    return create_model(
        _SlotProviderDraft.__name__,
        __base__=_SlotProviderDraft,
        findings=(tuple[finding, ...], ()),
    )


def _required_pair_keys(
    request: SynthesisSlotRequest,
) -> frozenset[tuple[str, str, str]]:
    """Return exact routed pair identities required by one slot request."""
    slot_ids = {slot.slot_id for slot in request.slots}
    return frozenset(
        (route.route_id or "", route.obligation_id, slot_id)
        for route in request.routed_routes
        for slot_id in set(route.slot_ids).intersection(slot_ids)
    )


def _validate_slot_provider_payload(
    payload: _Model,
    *,
    expected_slot_ids: frozenset[str],
    expected_pair_keys: frozenset[tuple[str, str, str]],
    request: SynthesisSlotRequest,
) -> None:
    """Require exact identities and compile-safe slot/pair semantics.

    This is deliberately a validation-only pass.  The provider boundary used
    to call ``_compile_slot_payload`` here and then call it again after the
    bounded retry returned.  Besides doing unnecessary work, that meant a
    compiler-owned prefix could be mistaken for model-authored safeguard
    prose on a later legacy pass.  Validate the model's fields and references
    here; the successful response is compiled exactly once below.
    """
    actual_slot_ids = frozenset(slot.slot_id for slot in payload.filled_slots)
    _require_exact_id_set(
        actual_slot_ids,
        expected_slot_ids,
        "slot response must contain exactly the supplied slot IDs",
    )
    actual_pair_keys = _provider_pair_keys(payload, expected_pair_keys)
    _require_exact_id_set(
        actual_pair_keys,
        expected_pair_keys,
        "slot response must contain exactly the required routed pair keys",
    )
    _validate_slot_payload_semantics(payload, request)


def _validate_slot_payload_semantics(
    payload: _Model,
    request: SynthesisSlotRequest,
) -> None:
    """Validate provider findings without constructing canonical ICAs.

    The strict provider schema already owns the closed slot shape.  This
    additional pass checks the semantic rules that are normally enforced by
    ``compile_ica_slot_draft`` while leaving canonical text/IDs to the one
    compilation performed after the provider call succeeds.
    """
    expected_by_id = {slot.slot_id: slot for slot in request.slots}
    route_by_pair = {
        (route.obligation_id, slot_id): route
        for route in request.routed_routes
        for slot_id in route.slot_ids
    }
    index = build_stpa_index(request.control_structure)
    for value in payload.filled_slots:
        expected = expected_by_id.get(value.slot_id)
        if expected is None:
            raise ValueError(f"slot response references unknown slot {value.slot_id}")
        draft = _materialize_slot_draft(value, expected)
        # Resolve owner/action authority before validating findings.  This is
        # the same deterministic source used by the compiler, but does not
        # create an ICA or alter the model's prose.
        _owner, action, _target_process, process_models, feedback = _slot_authority(
            expected, index
        )
        for finding in draft.findings:
            _validate_finding_semantics(
                finding,
                slot=expected,
                action_description=action,
                valid_process_models=process_models,
                valid_feedback=feedback,
                loss_analysis=request.loss_analysis,
            )
            _finding_context(
                finding, slot=expected, control_structure=request.control_structure
            )
        for result in draft.consideration_results:
            _validate_consideration_result(result, draft, route_by_pair)


def _validate_consideration_result(
    result: Any, draft: SlotIcaDraft, route_by_pair: dict[tuple[str, str], Any]
) -> None:
    if route_by_pair.get((result.obligation_handle, draft.slot_id)) is None:
        raise ValueError(
            "structured consideration references an obligation/slot "
            "that is not routed to this target"
        )
    if result.disposition == "finding":
        if draft.is_na:
            raise ValueError("finding consideration requires a non-N/A slot draft")
        if any(index >= len(draft.findings) for index in result.finding_indexes):
            raise ValueError(
                "structured consideration finding index is outside its slot"
            )
    elif result.disposition == "proposed_not_applicable" and not draft.is_na:
        raise ValueError("proposed non-applicability requires an N/A slot draft")


def _provider_pair_keys(
    payload: _Model,
    expected_pair_keys: frozenset[tuple[str, str, str]],
) -> frozenset[tuple[str, str, str]]:
    """Resolve provider-local obligation handles to supplied route identities."""
    route_by_pair = {
        (obligation_id, slot_id): route_id
        for route_id, obligation_id, slot_id in expected_pair_keys
    }
    actual: set[tuple[str, str, str]] = set()
    for entry in payload.filled_slots:
        for result in entry.consideration_results:
            route_id = route_by_pair.get((result.obligation_handle, entry.slot_id))
            if route_id is not None:
                actual.add((route_id, result.obligation_handle, entry.slot_id))
    return frozenset(actual)


def _require_exact_id_set(actual: frozenset, expected: frozenset, message: str) -> None:
    """Raise one stable diagnostic for a closed identity-set mismatch."""
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        raise ValueError(f"{message} (missing={missing}, unexpected={unexpected})")


def _materialize_slot_draft(
    value: _SlotProviderDraft,
    expected: SlotPlaceholder,
) -> SlotIcaDraft:
    """Bind provider prose to the authoritative UCA type of one exact slot."""
    field_name = DEVIATION_FIELD_BY_UCA_TYPE[expected.uca_type]
    findings = tuple(
        IcaFindingDraft(
            deviation=IcaDeviationDraft.model_validate({field_name: finding.deviation}),
            hazardous_context=finding.hazardous_context,
            loss_consequence=finding.loss_consequence,
            related_hazard_ids=finding.related_hazard_ids,
            related_constraint_ids=finding.related_constraint_ids,
            process_model_refs=finding.process_model_refs,
            feedback_refs=finding.feedback_refs,
            context_row=finding.context_row,
        )
        for finding in value.findings
    )
    return SlotIcaDraft(
        slot_id=value.slot_id,
        is_na=value.is_na,
        na_rationale=value.na_rationale,
        findings=findings,
        consideration_results=value.consideration_results,
    )


def _compile_slot_payload(
    payload: _Model,
    request: SynthesisSlotRequest,
) -> tuple[dict[str, ICASlot], tuple[ObligationIcaConsideration, ...]]:
    """Compile one validated provider payload at the retry boundary."""
    slots: dict[str, ICASlot] = {}
    drafts: list[SlotIcaDraft] = []
    for value in payload.filled_slots:
        expected = next(
            (item for item in request.slots if item.slot_id == value.slot_id),
            None,
        )
        if expected is None:
            raise ValueError(f"slot response references unknown slot {value.slot_id}")
        draft = _materialize_slot_draft(value, expected)
        drafts.append(draft)
        slots[value.slot_id] = compile_slot_provider_entry(
            draft,
            slot=expected,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
        )
    considerations = _draft_considerations(
        sorted(drafts, key=lambda item: item.slot_id),
        request,
        slots,
    )
    return slots, considerations


def _routing_response(
    request: StructuralRoutingRequest, payload: Any, *, calls: int
) -> StructuralRoutingResponse:
    """Materialize one parsed provider payload into the canonical response."""
    brief_by_id = {brief.obligation_id: brief for brief in request.briefs}
    unknown_ids = sorted(
        {
            route.obligation_id
            for route in payload.routes
            if route.obligation_id not in brief_by_id
        }
    )
    if unknown_ids:
        raise ValueError(
            "structural routing provider returned unknown obligation IDs: "
            + ", ".join(unknown_ids)
        )
    return StructuralRoutingResponse(
        request_digest=request.semantic_digest,
        routes=tuple(
            _materialize_routing_route(
                route,
                mapping_strength=mapping_strength_for_brief(
                    brief_by_id[route.obligation_id]
                ),
            )
            for route in payload.routes
        ),
        adapter_kind="provider",
        provider_calls=calls,
        request_ref=f"memory://{request.batch_id}/request",
        response_ref=f"memory://{request.batch_id}/response",
    )


class ObligationAwareLLMAdapter:
    """Provider-capable adapter implementing the three named analysis stages."""

    def __init__(
        self,
        llm_client: LLMClient,
        *,
        run_dir: Path,
        controls: AnalysisControls,
        stage_prefix: str = "synthesis_obligation_aware",
        prompt_budget: PromptBudget | None = None,
    ) -> None:
        self.llm_client = llm_client
        self.run_dir = Path(run_dir)
        self.controls = controls
        self.stage_prefix = stage_prefix
        self.prompt_budget = prompt_budget
        self.mechanism_verdicts: dict[tuple, _MechanismVerdict] = {}
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def route(
        self,
        request: StructuralRoutingRequest,
        *,
        correction_feedback: str | None = None,
    ) -> StructuralRoutingResponse:
        """Run the named structural-routing provider stage."""
        routing_view = project_obligation_routing_context(
            briefs=request.briefs,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
            slots=request.slots,
        )
        system_prompt, user_prompt = render_structural_routing_prompts(
            routing_view, loss_analysis=request.loss_analysis
        )
        user_prompt = _with_correction_feedback(user_prompt, correction_feedback)
        _preflight(
            view=routing_view,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            stage="obligation-routing",
            handles=_routing_prompt_handles(routing_view),
            stage_max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
            client=self.llm_client,
            controls=request.controls,
            configured_budget=self.prompt_budget,
            output_schema=(
                "routes",
                "obligation_id",
                "disposition",
                "slot_ids",
                "hazard_ids",
                "constraint_ids",
                "rationale",
                "evidence",
            ),
            valid_example={
                "routes": [
                    {
                        "obligation_id": "<obligation_handle>",
                        "disposition": "unresolved",
                        "semantic_assessment": {
                            "mechanism_assessment": "insufficient_evidence",
                            "risk_alignment": "insufficient_evidence",
                            "mechanism_rationale": "the required path is not supplied",
                            "risk_alignment_rationale": "alignment is not established",
                        },
                        "rationale": "the required path is not supplied",
                        "evidence": ["insufficient system-specific evidence"],
                    }
                ]
            },
            run_dir=self.run_dir,
            call_stage=f"{self.stage_prefix}_routing",
            step=request.batch_id,
        )
        response_format = _routing_provider_payload_type(
            len(request.briefs),
            obligation_ids=tuple(brief.obligation_id for brief in request.briefs),
        )
        outcome = call_with_policy(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_routing",
            step=request.batch_id,
            # route_obligations owns the single bounded retry because it also
            # validates exact obligation/reference closure after this schema
            # parse.  Keeping this policy at zero retries prevents a malformed
            # provider response from being retried once here and once again
            # by the structural router.
            policy=CorrectionPolicy(
                validation_retries=0,
                feedback=(
                    " Return one route for every supplied obligation ID using exact IDs."
                ),
            ),
            temperature=request.controls.temperature,
            max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
            prompt_template_hashes=obligation_prompt_template_hashes(),
        )
        if outcome.error is not None or outcome.value is None:
            raise ValueError(
                outcome.error or "structural routing provider returned no payload"
            )
        response = _routing_response(request, outcome.value, calls=outcome.calls)
        mark_call_published(
            self.run_dir,
            f"{self.stage_prefix}_routing",
            request.batch_id,
            call_log_of(self.llm_client),
        )
        return response

    def route_governance(
        self,
        request: Any,
        *,
        correction_feedback: str | None = None,
    ) -> Any:
        """Run the governance-routing provider stage for one batch."""
        # Imported here: the governance module imports this one for its helpers.
        from asago_scenario_generator.stpa.obligation_aware.governance_provider import (
            run_governance_routing,
        )

        return run_governance_routing(self, request, correction_feedback)

    def verify_mechanisms(
        self,
        request: StructuralRoutingRequest,
        routes: Sequence[ObligationRoute],
    ) -> tuple[ObligationRoute, ...]:
        """Check credited routes against a compact mechanism-only prompt."""
        candidates = _verification_candidates(routes)
        if not candidates:
            return tuple(routes)
        verified, published = _run_mechanism_verifier(self, request, candidates)
        if published:
            mark_call_published(
                self.run_dir,
                f"{self.stage_prefix}_mechanism_verification",
                request.batch_id,
                call_log_of(self.llm_client),
            )
        return _merge_verified_routes(routes, verified)

    def verify_ica_hazards(
        self,
        requests: Sequence[IcaHazardVerificationRequest],
        *,
        correction_feedback: Mapping[str, str] | None = None,
    ) -> tuple[IcaHazardVerificationVerdict, ...]:
        """Independently verify every supplied final ICA in one bounded call.

        The request projection and prompt builder contain only STPA semantic
        context.  A correction call is explicit and is initiated by the
        deterministic orchestration seam.  This adapter sends one repair
        request, with the exact feedback, when a response fails its schema or
        omits the losses and consequence a hazardous absence must name. An
        absence still unproven after that repair is returned downgraded, not
        raised: the other verdicts of the batch stand.
        """
        requests = tuple(requests)
        if not requests:
            return ()
        request_by_ref = _ica_review_requests(requests)
        system_prompt, user_prompt = build_ica_hazard_verification_prompts(requests)
        step = "correction" if correction_feedback else "initial"
        payload_type = _ica_hazard_provider_payload_type(len(requests))
        repair = _AbsenceEvidenceRepair(
            request_by_ref, payload_type, _ICA_VERIFICATION_REPAIRS
        )
        outcome = call_with_policy(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=payload_type,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_ica_hazard_verification",
            step=step,
            policy=CorrectionPolicy(validation_retries=_ICA_VERIFICATION_REPAIRS),
            response_parser=repair.parse,
            result_validator=repair.validate,
            temperature=self.controls.temperature,
            max_completion_tokens=min(
                _SYNTHESIS_MAX_COMPLETION_TOKENS,
                max(_MECHANISM_VERIFICATION_MAX_COMPLETION_TOKENS, 256 * len(requests)),
            ),
            prompt_template_hashes=obligation_prompt_template_hashes(),
        )
        if outcome.error is not None or outcome.value is None:
            raise ValueError(
                outcome.error or "ICA hazard verification provider returned no payload"
            )
        result = _compile_ica_review_payload(outcome.value, request_by_ref)
        mark_call_published(
            self.run_dir,
            f"{self.stage_prefix}_ica_hazard_verification",
            step,
            call_log_of(self.llm_client),
        )
        return result

    def correct_ica_hazard(
        self,
        request: IcaHazardVerificationRequest,
        verdict: IcaHazardVerificationVerdict,
    ) -> IcaHazardVerificationCorrection:
        """Perform one bounded request-local ICA correction."""
        system_prompt, user_prompt = build_ica_hazard_correction_prompts(
            request, verdict
        )
        outcome = call_with_policy(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=_IcaHazardCorrectionPayload,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_ica_hazard_correction",
            step=request.ica_id,
            policy=CorrectionPolicy(),
            temperature=self.controls.temperature,
            max_completion_tokens=_MECHANISM_VERIFICATION_MAX_COMPLETION_TOKENS,
            prompt_template_hashes=obligation_prompt_template_hashes(),
        )
        payload = outcome.value
        if outcome.error is not None or payload is None:
            raise ValueError(
                outcome.error or "ICA hazard correction provider returned no payload"
            )
        correction_value = (
            payload.correction
            if isinstance(payload, _IcaHazardCorrectionPayload)
            else getattr(payload, "correction", payload)
        )
        correction = (
            correction_value
            if isinstance(correction_value, IcaHazardVerificationCorrection)
            else IcaHazardVerificationCorrection.model_validate(correction_value)
        )
        if correction.ica_id != request.ica_id:
            raise ValueError("ICA correction provider changed the ICA identity")
        mark_call_published(
            self.run_dir,
            f"{self.stage_prefix}_ica_hazard_correction",
            request.ica_id,
            call_log_of(self.llm_client),
        )
        return correction

    def revise(self, request: StructuralRevisionRequest) -> StructuralRevisionResponse:
        """Run the single named additive-revision provider stage."""
        revision_view = project_revision_context(
            gaps=request.gaps,
            loss_analysis=request.baseline_loss_analysis,
            control_structure=request.baseline_control_structure,
        )
        system_prompt, user_prompt = render_structural_revision_prompts(revision_view)
        _preflight(
            view=revision_view,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            stage="obligation-revision",
            handles=tuple(item.gap_handle for item in revision_view.gaps),
            stage_max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
            client=self.llm_client,
            controls=request.controls,
            configured_budget=self.prompt_budget,
            output_schema=("draft", "gap_decisions"),
            valid_example={
                "draft": {},
                "gap_decisions": [],
            },
            run_dir=self.run_dir,
            call_stage=f"{self.stage_prefix}_revision",
            step="bounded_revision",
        )
        outcome = call_with_policy(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=_RevisionProviderPayload,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_revision",
            step="bounded_revision",
            policy=CorrectionPolicy(
                validation_retries=request.controls.validation_retries,
                feedback=" Return only additive request-local handles.",
            ),
            temperature=request.controls.temperature,
            max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
            prompt_template_hashes=obligation_prompt_template_hashes(),
        )
        payload = outcome.value
        if outcome.error is not None or payload is None:
            raise ValueError(
                outcome.error or "structural revision provider returned no payload"
            )
        draft = RevisionDraft.model_validate(
            payload.draft.model_dump(mode="python")
        ).model_copy(update={"gap_decisions": payload.gap_decisions})
        response = StructuralRevisionResponse(
            status=payload.status,
            request_digest=request.semantic_digest,
            draft=draft,
            adapter_kind="provider",
            provider_calls=outcome.calls,
        )
        mark_call_published(
            self.run_dir,
            f"{self.stage_prefix}_revision",
            "bounded_revision",
            call_log_of(self.llm_client),
        )
        return response

    def fill(self, request: SynthesisSlotRequest) -> SynthesisSlotResponse:
        """Run the named target-scoped ICA slot provider stage."""
        expected_slot_ids = frozenset(slot.slot_id for slot in request.slots)
        expected_pair_keys = _required_pair_keys(request)
        projection = project_ica_target_context(
            target_id=request.target_id,
            slots=request.slots,
            routed_briefs=request.routed_briefs,
            routed_routes=request.routed_routes,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
        )
        system_prompt, user_prompt = render_synthesis_slot_prompts(
            projection, target_id=request.target_id, slots=request.slots
        )
        target_view, target_questions, target_routes = projection
        # The target index is the typed view; obligation and route handles are
        # independently checked in the rendered prompt as copy-only values.
        _preflight(
            view=target_view,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            stage="obligation-ica",
            handles=_slot_prompt_handles(
                request.target_id, target_questions, target_routes
            ),
            stage_max_completion_tokens=_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS,
            client=self.llm_client,
            controls=request.controls,
            configured_budget=self.prompt_budget,
            output_schema=("filled_slots", "consideration_results"),
            valid_example={
                "filled_slots": [
                    {
                        "slot_id": "<slot_id>",
                        "is_na": True,
                        "na_rationale": "No complete structural property applies.",
                        "findings": [],
                        "consideration_results": [],
                    }
                ],
            },
            run_dir=self.run_dir,
            call_stage=f"{self.stage_prefix}_icas",
            step=request.target_id,
        )
        response_format = _slot_provider_payload_type(
            len(request.slots),
            len(expected_pair_keys),
            constraint_ids=tuple(
                item.constraint_id
                for item in request.loss_analysis.security_constraints
            ),
        )
        by_local = {
            handle: obligation_id
            for obligation_id, handle in local_obligation_handles(
                request.routed_routes
            ).items()
        }

        def validate(value: _Model) -> None:
            _require_known_slot_handles(value, by_local)
            try:
                _validate_slot_provider_payload(
                    _resolve_slot_handles(value, by_local),
                    expected_slot_ids=expected_slot_ids,
                    expected_pair_keys=expected_pair_keys,
                    request=request,
                )
            except ValueError as exc:
                raise ValueError(_localized_slot_error(str(exc), request)) from None

        outcome = call_with_policy(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_icas",
            step=request.target_id,
            policy=CorrectionPolicy(
                validation_retries=request.controls.validation_retries,
                feedback=(
                    " Return every exact slot identity once and every required "
                    "route/obligation/slot pair exactly once. For each slot, set "
                    "is_na=false only with a non-empty findings array and no "
                    "na_rationale; set is_na=true only with an empty findings array "
                    "and a non-empty na_rationale. Return one plain deviation string "
                    "for each finding, and correct the exact semantic "
                    "validation error reported above."
                ),
            ),
            temperature=request.controls.temperature,
            max_completion_tokens=_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS,
            result_validator=validate,
            prompt_template_hashes=obligation_prompt_template_hashes(),
        )
        if outcome.error is not None or outcome.value is None:
            raise ValueError(outcome.error or "slot provider returned no payload")
        payload, supplement_calls = self._supplement_context_coverage(
            _resolve_slot_handles(outcome.value, by_local), request
        )
        # The payload is provider-local and deliberately permits no arbitrary
        # object: pair values are validated into the authoritative model here,
        # after derived identities are attached from the exact supplied slots.
        slots, considerations = _compile_slot_payload(payload, request)
        response = SynthesisSlotResponse(
            request_digest=request.semantic_digest,
            filled_slots=tuple(slots.values()),
            considerations=considerations,
            adapter_kind="provider",
            provider_calls=outcome.calls + supplement_calls,
        )
        mark_call_published(
            self.run_dir,
            f"{self.stage_prefix}_icas",
            request.target_id,
            call_log_of(self.llm_client),
        )
        return response

    def _supplement_context_coverage(
        self, payload: _Model, request: SynthesisSlotRequest
    ) -> tuple[_Model, int]:
        """Ask once about source contexts the reply slots left unanalyzed.

        The supplement only adds findings.  A failed or invalid supplement
        keeps the validated slot payload, so the check never costs a slot.
        Return the payload and the number of supplement requests sent.
        """
        gaps = context_coverage_gaps(payload.filled_slots, request)
        if not gaps:
            return payload, 0
        stage = f"{self.stage_prefix}_icas{CONTEXT_COVERAGE_STAGE_SUFFIX}"
        system_prompt, user_prompt = build_context_coverage_prompts(
            target_id=request.target_id,
            gaps=gaps,
            filled_slots=payload.filled_slots,
            request=request,
        )

        def merged(entries: Sequence[_ContextSupplementEntry]) -> _Model:
            return payload.model_copy(
                update={
                    "filled_slots": merge_supplement(
                        payload.filled_slots, entries, gaps
                    )
                }
            )

        def validate(value: _ContextSupplementPayload) -> None:
            validate_supplement_entries(value.entries, gaps)
            _validate_slot_payload_semantics(merged(value.entries), request)

        outcome = call_with_policy(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=_ContextSupplementPayload,
            run_dir=self.run_dir,
            stage=stage,
            step=request.target_id,
            policy=CorrectionPolicy(
                validation_retries=request.controls.validation_retries,
                feedback=(
                    " Return exactly one entry per gap_id. Each finding must cite one "
                    "of that gap's listed context rows and only its constraint_id; "
                    "correct the exact validation error reported above."
                ),
            ),
            temperature=request.controls.temperature,
            max_completion_tokens=_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS,
            result_validator=validate,
            prompt_template_hashes=obligation_prompt_template_hashes(),
        )
        if outcome.error is not None or outcome.value is None:
            return payload, outcome.calls
        mark_call_published(
            self.run_dir, stage, request.target_id, call_log_of(self.llm_client)
        )
        return merged(outcome.value.entries), outcome.calls


__all__ = [
    "ObligationAwareLLMAdapter",
]
