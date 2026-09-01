"""Provider adapter for the named obligation-aware STPA stages.

The adapter is deliberately thin: prompt construction, bounded retries, and
call logging use the existing STPA infrastructure while deterministic routing,
revision compilation, and slot/reference validation remain local pure seams.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

from pydantic import Field, conlist, create_model

from asago_scenario_generator.models.hybrid_coverage import (
    ObligationId,
    TraceReference,
)
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationDiagnostic,
    ObligationIcaConsideration,
    ObligationRouteDisposition,
    StructuralConceptKind,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient, effective_temperature
from asago_scenario_generator.stpa.infra.llm_helpers import (
    log_llm_call_failure,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
    PromptContractError,
    PromptAudit,
    audit_prompt_contract as preflight_prompt_contract,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICASlot
from asago_scenario_generator.stpa.obligation_aware.contracts import (
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
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    audit_prompt_contract,
    build_structural_revision_prompts,
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
    project_obligation_routing_context,
    project_ica_target_context,
    project_revision_context,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _draft_considerations,
    compile_slot_provider_entry,
)

_SYNTHESIS_MAX_COMPLETION_TOKENS = 8192
_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS = 8192
_PROMPT_PROHIBITED_FIELDS = (
    "digest",
    "pin",
    "score",
    "mapping",
    "mitigation",
    "provider_call",
    "schema_name",
    "source_path",
    "artifact_path",
)


def _reference_pairs(value: Any) -> tuple[tuple[str, str], ...]:
    """Collect explained ``id``/``description`` pairs from a prompt view."""
    pairs: dict[str, str] = {}

    def visit(item: Any) -> None:
        if hasattr(item, "model_dump"):
            visit(item.model_dump(mode="python"))
            return
        if isinstance(item, dict):
            identifier = item.get("id")
            description = item.get("description")
            if (
                isinstance(identifier, str)
                and isinstance(description, str)
                and identifier
                and description.strip()
            ):
                pairs.setdefault(identifier, description)
            for child in item.values():
                visit(child)
            return
        if isinstance(item, (list, tuple, set, frozenset)):
            for child in item:
                visit(child)

    visit(value)
    return tuple(sorted(pairs.items()))


def _prompt_budget(
    client: Any,
    controls: AnalysisControls,
    stage_max_completion_tokens: int,
    configured: PromptBudget | None,
) -> PromptBudget | None:
    """Resolve model-aware input capacity without requiring legacy fakes."""
    context_window = controls.context_window
    if context_window is None and configured is not None:
        context_window = configured.context_window
    if context_window is None:
        context_window = getattr(client, "context_window", None)
    if context_window is None:
        context_window = getattr(client, "model_context_window", None)
    if context_window is None:
        return None
    completion = min(
        stage_max_completion_tokens,
        controls.maximum_completion_tokens or stage_max_completion_tokens,
    )
    safety_margin = controls.safety_margin
    if safety_margin is None and configured is not None:
        safety_margin = configured.safety_margin
    if safety_margin is None:
        safety_margin = getattr(client, "safety_margin", None)
    return PromptBudget(
        context_window=int(context_window),
        maximum_completion_tokens=completion,
        safety_margin=safety_margin,
    )


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
            prohibited_fields=_PROMPT_PROHIBITED_FIELDS,
            output_schema=output_schema,
            valid_example=valid_example,
            budget=_prompt_budget(
                client,
                controls,
                stage_max_completion_tokens,
                configured_budget,
            ),
            raise_on_error=False,
        )
        if not prompt_audit.ok:
            if (
                prompt_audit.usable_input_tokens is not None
                and prompt_audit.input_tokens > prompt_audit.usable_input_tokens
            ):
                raise PromptBudgetExceeded(
                    input_tokens=prompt_audit.input_tokens,
                    usable_input_tokens=prompt_audit.usable_input_tokens,
                    context_window=prompt_audit.context_window or 0,
                    maximum_completion_tokens=(
                        prompt_audit.maximum_completion_tokens or 0
                    ),
                    safety_margin=prompt_audit.safety_margin or 0,
                )
            raise PromptContractError(*prompt_audit.errors)
    except Exception as exc:
        # This preflight runs before ``safe_llm_call`` and therefore otherwise
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

    routes: tuple["_RoutingProviderRoute", ...] = Field(min_length=1)


class _RoutingProviderMissingConcept(_Model):
    """Provider-facing gap semantics without the derived ``gap_id``."""

    concept_type: StructuralConceptKind
    description: str = Field(min_length=1)
    concept_id: str | None = None
    evidence_refs: tuple[str, ...] = Field(min_length=1)
    obligation_id: ObligationId | None = None


class _RoutingProviderRoute(_Model):
    """Provider-facing route semantics without derived route identity."""

    obligation_id: ObligationId
    disposition: ObligationRouteDisposition
    slot_ids: tuple[str, ...] = ()
    controller_ids: tuple[str, ...] = ()
    control_action_ids: tuple[str, ...] = ()
    responsibility_ids: tuple[str, ...] = ()
    process_model_part_ids: tuple[str, ...] = ()
    feedback_channel_ids: tuple[str, ...] = ()
    controlled_process_ids: tuple[str, ...] = ()
    coordination_link_ids: tuple[str, ...] = ()
    hazard_ids: tuple[str, ...] = ()
    constraint_ids: tuple[str, ...] = ()
    missing_concepts: tuple[_RoutingProviderMissingConcept, ...] = ()
    rationale: str | None = None
    evidence: tuple[str, ...] = Field(min_length=1)
    model_call_refs: tuple[str, ...] = ()
    trace_refs: tuple[TraceReference, ...] = ()
    diagnostics: tuple[ConsiderationDiagnostic, ...] = ()


_RoutingProviderPayload.model_rebuild()


@lru_cache(maxsize=16)
def _routing_provider_payload_type(route_count: int) -> type[_Model]:
    """Build a strict provider payload for exactly one route per brief.

    ``ObligationRoute`` owns the derived route/gap IDs and its conditional
    domain validation.  This provider-only shape asks the model for the
    semantic decision and exact authority references while leaving those
    content-addressed identities to local code.  A per-batch constrained list
    makes an otherwise-valid empty/default response impossible at the native
    structured-output boundary.
    """
    if type(route_count) is not int or route_count <= 0:
        raise ValueError("route_count must be a positive integer")
    routes = conlist(
        _RoutingProviderRoute,
        min_length=route_count,
        max_length=route_count,
    )
    return create_model(
        f"_RoutingProviderPayload{route_count}",
        __base__=_RoutingProviderPayload,
        routes=(routes, ...),
    )


def _materialize_routing_route(value: _RoutingProviderRoute) -> ObligationRoute:
    """Derive authoritative route and gap IDs from provider semantics."""
    data = value.model_dump(mode="python")
    data["missing_concepts"] = tuple(
        concept.model_dump(mode="python") for concept in value.missing_concepts
    )
    return ObligationRoute.model_validate(data)


class _RevisionProviderPayload(_Model):
    """Provider-only additive draft response body."""

    status: Literal["completed", "rejected"] = "completed"
    draft: "_RevisionProviderDraft"
    gap_decisions: tuple[RevisionGapDecision, ...] = ()


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
    gap_decisions: tuple[RevisionGapDecision, ...] = ()
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

    filled_slots: tuple[SlotIcaDraft, ...] = Field(min_length=1)


@lru_cache(maxsize=16)
def _slot_provider_payload_type(
    slot_count: int,
    required_pair_count: int,
) -> type[_Model]:
    """Build a provider payload constrained to one request's exact counts."""
    if type(slot_count) is not int or slot_count <= 0:
        raise ValueError("slot_count must be a positive integer")
    if type(required_pair_count) is not int or required_pair_count < 0:
        raise ValueError("required_pair_count must be a non-negative integer")
    filled_slots = conlist(SlotIcaDraft, min_length=slot_count, max_length=slot_count)
    return create_model(
        f"_SlotProviderPayload{slot_count}Pairs{required_pair_count}",
        __base__=_SlotProviderPayload,
        filled_slots=(filled_slots, ...),
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
    """Require exact identities and compile-safe slot/pair semantics."""
    actual_slot_ids = {slot.slot_id for slot in payload.filled_slots}
    if actual_slot_ids != expected_slot_ids:
        missing = sorted(expected_slot_ids - actual_slot_ids)
        unexpected = sorted(actual_slot_ids - expected_slot_ids)
        raise ValueError(
            "slot response must contain exactly the supplied slot IDs"
            f" (missing={missing}, unexpected={unexpected})"
        )
    actual_pair_keys: set[tuple[str, str, str]] = set()
    # Strict structured slot drafts carry obligation decisions beside their
    # findings. Resolve those request-local handles to the exact route key
    # supplied to this target; the provider never supplies a derived route ID
    # in that nested shape.
    route_by_pair = {
        (obligation_id, slot_id): route_id
        for route_id, obligation_id, slot_id in expected_pair_keys
    }
    for entry in payload.filled_slots:
        if not isinstance(entry, SlotIcaDraft):
            continue
        for result in entry.consideration_results:
            route_id = route_by_pair.get((result.obligation_handle, entry.slot_id))
            if route_id is not None:
                actual_pair_keys.add(
                    (route_id, result.obligation_handle, entry.slot_id)
                )
    if actual_pair_keys != expected_pair_keys:
        missing = sorted(expected_pair_keys - actual_pair_keys)
        unexpected = sorted(actual_pair_keys - expected_pair_keys)
        raise ValueError(
            "slot response must contain exactly the required routed pair keys"
            f" (missing={missing}, unexpected={unexpected})"
        )
    _compile_slot_payload(payload, request)


def _compile_slot_payload(
    payload: _Model,
    request: SynthesisSlotRequest,
) -> tuple[dict[str, ICASlot], tuple[ObligationIcaConsideration, ...]]:
    """Compile one validated provider payload at the retry boundary."""
    slots: dict[str, ICASlot] = {}
    for value in payload.filled_slots:
        expected = next(
            (item for item in request.slots if item.slot_id == value.slot_id),
            None,
        )
        if expected is None:
            raise ValueError(f"slot response references unknown slot {value.slot_id}")
        slots[value.slot_id] = compile_slot_provider_entry(
            value,
            slot=expected,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
        )
    structured_response = SynthesisSlotResponse(
        request_digest=request.semantic_digest,
        filled_slots=tuple(payload.filled_slots),
    )
    considerations = _draft_considerations(
        structured_response,
        request,
        slots,
    )
    return slots, considerations


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
        self.run_dir.mkdir(parents=True, exist_ok=True)

    def route(
        self,
        request: StructuralRoutingRequest,
        *,
        correction_feedback: str | None = None,
    ) -> StructuralRoutingResponse:
        """Run the named structural-routing provider stage."""
        system_prompt, user_prompt = build_structural_routing_prompts(
            briefs=request.briefs,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
            slots=request.slots,
        )
        routing_view = project_obligation_routing_context(
            briefs=request.briefs,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
            slots=request.slots,
        )
        if correction_feedback:
            user_prompt += f"\nValidation correction:\n{correction_feedback}\n"
        _preflight(
            view=routing_view,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            stage="obligation-routing",
            handles=tuple(
                item.obligation_handle for item in routing_view.obligation_questions
            ),
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
                "evidence",
            ),
            valid_example={
                "routes": [
                    {
                        "obligation_id": "<obligation_handle>",
                        "disposition": "unresolved",
                        "evidence": ["insufficient system-specific evidence"],
                    }
                ]
            },
            run_dir=self.run_dir,
            call_stage=f"{self.stage_prefix}_routing",
            step=request.batch_id,
        )
        response_format = _routing_provider_payload_type(len(request.briefs))
        payload, _result, error = safe_llm_call(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_routing",
            step=request.batch_id,
            temperature=request.controls.temperature,
            max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
            # route_obligations owns the single bounded retry because it also
            # validates exact obligation/reference closure after this schema
            # parse.  Keeping safe_llm_call at zero prevents a malformed
            # provider response from being retried once here and once again
            # by the structural router.
            validation_retries=0,
            validation_retry_feedback=(
                " Return one route for every supplied obligation ID using exact IDs."
            ),
        )
        if error is not None or payload is None:
            raise ValueError(error or "structural routing provider returned no payload")
        return StructuralRoutingResponse(
            request_digest=request.semantic_digest,
            routes=tuple(_materialize_routing_route(route) for route in payload.routes),
            adapter_kind="provider",
            provider_calls=1,
            request_ref=f"memory://{request.batch_id}/request",
            response_ref=f"memory://{request.batch_id}/response",
        )

    def revise(self, request: StructuralRevisionRequest) -> StructuralRevisionResponse:
        """Run the single named additive-revision provider stage."""
        system_prompt, user_prompt = build_structural_revision_prompts(
            gaps=request.gaps,
            loss_analysis=request.baseline_loss_analysis,
            control_structure=request.baseline_control_structure,
        )
        revision_view = project_revision_context(
            gaps=request.gaps,
            loss_analysis=request.baseline_loss_analysis,
            control_structure=request.baseline_control_structure,
        )
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
        payload, _result, error = safe_llm_call(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=_RevisionProviderPayload,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_revision",
            step="bounded_revision",
            temperature=request.controls.temperature,
            max_completion_tokens=_SYNTHESIS_MAX_COMPLETION_TOKENS,
            validation_retries=request.controls.validation_retries,
            validation_retry_feedback=" Return only additive request-local handles.",
        )
        if error is not None or payload is None:
            raise ValueError(
                error or "structural revision provider returned no payload"
            )
        draft = RevisionDraft.model_validate(payload.draft.model_dump(mode="python"))
        if payload.gap_decisions:
            draft = draft.model_copy(
                update={
                    "gap_decisions": tuple(
                        (*draft.gap_decisions, *payload.gap_decisions)
                    )
                }
            )
        return StructuralRevisionResponse(
            status=payload.status,
            request_digest=request.semantic_digest,
            draft=draft,
            adapter_kind="provider",
            provider_calls=1,
        )

    def fill(self, request: SynthesisSlotRequest) -> SynthesisSlotResponse:
        """Run the named target-scoped ICA slot provider stage."""
        expected_slot_ids = frozenset(slot.slot_id for slot in request.slots)
        expected_pair_keys = _required_pair_keys(request)
        system_prompt, user_prompt = build_synthesis_slot_prompts(
            target_id=request.target_id,
            slots=request.slots,
            routed_briefs=request.routed_briefs,
            routed_routes=request.routed_routes,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
        )
        target_view, target_questions, target_routes = project_ica_target_context(
            target_id=request.target_id,
            slots=request.slots,
            routed_briefs=request.routed_briefs,
            routed_routes=request.routed_routes,
            loss_analysis=request.loss_analysis,
            control_structure=request.control_structure,
        )
        # The target index is the typed view; obligation and route handles are
        # independently checked in the rendered prompt as copy-only values.
        _preflight(
            view=target_view,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            stage="obligation-ica",
            handles=(
                request.target_id,
                *(item.obligation_handle for item in target_questions),
                *(item.route_handle for item in target_routes),
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
            len(request.slots), len(expected_pair_keys)
        )
        payload, _result, error = safe_llm_call(
            llm_client=self.llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            run_dir=self.run_dir,
            stage=f"{self.stage_prefix}_icas",
            step=request.target_id,
            temperature=request.controls.temperature,
            max_completion_tokens=_SYNTHESIS_SLOT_MAX_COMPLETION_TOKENS,
            validation_retries=request.controls.validation_retries,
            result_validator=lambda value: _validate_slot_provider_payload(
                value,
                expected_slot_ids=expected_slot_ids,
                expected_pair_keys=expected_pair_keys,
                request=request,
            ),
            validation_retry_feedback=(
                " Return every exact slot identity once and every required "
                "route/obligation/slot pair exactly once. For each slot, set "
                "is_na=false only with a non-empty findings array and no "
                "na_rationale; set is_na=true only with an empty findings array "
                "and a non-empty na_rationale. Use exactly the deviation field "
                "named for that slot's UCA type, and correct the exact semantic "
                "validation error reported above."
            ),
        )
        if error is not None or payload is None:
            raise ValueError(error or "slot provider returned no payload")
        # The payload is provider-local and deliberately permits no arbitrary
        # object: pair values are validated into the authoritative model here,
        # after derived identities are attached from the exact supplied slots.
        slots, considerations = _compile_slot_payload(payload, request)
        return SynthesisSlotResponse(
            request_digest=request.semantic_digest,
            filled_slots=tuple(slots.values()),
            considerations=considerations,
            adapter_kind="provider",
            provider_calls=1,
        )


def make_obligation_aware_adapter(
    *,
    llm_client: LLMClient,
    run_dir: Path,
    model_profile: str,
    model_name: str | None = None,
    deadline_seconds: float = 300.0,
    temperature: float | None = None,
    max_batch_size: int = 8,
    validation_retries: int = 1,
) -> ObligationAwareLLMAdapter:
    """Construct a provider adapter with explicit named-stage controls."""
    effective = effective_temperature(llm_client, temperature)
    controls = AnalysisControls(
        model_profile=model_profile,
        model_name=model_name or llm_client.model,
        deadline_seconds=deadline_seconds,
        temperature=effective,
        validation_retries=validation_retries,
        max_batch_size=max_batch_size,
    )
    return ObligationAwareLLMAdapter(llm_client, run_dir=run_dir, controls=controls)


def adapter_from_synthesis_inputs(
    *,
    inputs: Any,
    output_dir: Path,
    controls: AnalysisControls | None = None,
) -> ObligationAwareLLMAdapter:
    """Resolve the configured SP2 provider for production synthesis seams."""
    from asago_scenario_generator.stpa.pipeline.llm_config import resolve_llm_client

    profile_name = getattr(inputs, "sp2_profile", None) or getattr(
        inputs, "profile", None
    )
    profiles_file = str(getattr(inputs, "profiles_file", "config/model-profiles.yaml"))
    client, resolved_name = resolve_llm_client(profile_name, None, profiles_file)
    if controls is None:
        controls = AnalysisControls(
            model_profile=resolved_name or "environment",
            model_name=client.model,
            deadline_seconds=300.0,
            temperature=effective_temperature(
                client, getattr(inputs, "temperature", None)
            ),
            max_batch_size=getattr(inputs, "max_batch_size", None) or 8,
        )
    return ObligationAwareLLMAdapter(
        client,
        run_dir=Path(output_dir),
        controls=controls,
    )


__all__ = [
    "ObligationAwareLLMAdapter",
    "adapter_from_synthesis_inputs",
    "make_obligation_aware_adapter",
]
