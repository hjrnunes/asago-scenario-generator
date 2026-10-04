"""Narrow LLM adapter for mapping systemic actions to observed operations."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import Field

from asago_scenario_generator.models.canonical import ClosedCanonicalModel
from asago_scenario_generator.models.target_realization import (
    TargetDerivedICAFinding,
    TargetDerivedICAProviderResponse,
    TargetDerivedICARequest,
    TargetRealizationExtensionOutcome,
    TargetOperationReference,
    TargetRealizationDisposition,
    TargetRealizationExtensionProviderResponse,
    TargetRealizationExtensionRequest,
    TargetRealizationProviderResponse,
    TargetRealizationVerification,
    target_operation_action_description,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    ExactFeedbackError,
    _compact_validation_error,
    _decode_llm_content,
    _transformation,
    _validation_retry_prompt,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.ica_enumeration import (
    classify_ica_semantics,
)


PROMPTS_DIR = Path(__file__).with_name("prompts")
TARGET_REALIZATION_MAX_COMPLETION_TOKENS = 4096
TARGET_EXTENSION_RETRY_FEEDBACK = """\
Your previous target-extension response failed validation. Return exactly one
outcome for every listed operation: either an accepted outcome with the
minimum new action, or a rejected outcome with a rationale. Do not omit an
operation because no additive action is justified. Every accepted outcome
must include a non-empty evidence_refs array citing the exact observed
operation and at least one named systemic record. Every rejected outcome must
include a non-empty, one-sentence rationale grounded in the supplied evidence.
Provide a rationale for every operation named in the validation feedback as
missing a rationale. ICA slot suggestions are optional because the compiler enumerates
every eligible ordinary STPA UCA category itself. When supplied, use only the
four literal uca_type values stated in the system instructions. When a target
names an existing element, set target_new_controlled_process to false (or omit
it); set it true only when target is null. Verification is performed by a
separate compact pass; do not include a verification field in this response.
Return only the corrected structured response.
"""

TARGET_DERIVED_ICA_STEP = "enumerate_target_derived_icas"
TARGET_DERIVED_ICA_CORRECTION_STEP = "enumerate_target_derived_icas_correction"
TARGET_DERIVED_ICA_DUPLICATE_FEEDBACK = (
    "\n\nCorrection request: the prior target-derived ICA response named the "
    "same reference more than once in one finding. Return the complete "
    "corrected response: every finding from the prior response, in the same "
    "order, with each finding's related_hazards and related_constraints "
    "listing each ID at most once. For each repeated entry named below, "
    "remove the repeat, or replace it with the exact ID of the different "
    "baseline record it was meant to name. Write each reference exactly as "
    "the frozen baseline writes it: hazard IDs (for example H-1) in "
    "related_hazards and constraint IDs (for example SC-1) in "
    "related_constraints; never a description or an invented ID. Keep every "
    "other field of every finding unchanged."
)


class TargetRealizationDraft(ClosedCanonicalModel):
    """Closed provider response before independent verification."""

    control_action_id: str = Field(min_length=1)
    disposition: TargetRealizationDisposition
    candidate_operations: tuple[TargetOperationReference, ...] = ()
    selected_operation: TargetOperationReference | None = None
    evidence_refs: tuple[str, ...] = ()
    rationale: str = ""


class TargetRealizationVerificationDecision(ClosedCanonicalModel):
    """Independent judgment over one proposed exact relationship.

    The aggregate decision is deliberately not sufficient for baseline
    correspondence.  The verifier must account for the action's immediate
    effect, recipient, and whether the operation's documented successful
    invocation completes that effect.  Keeping these as closed axes makes a
    prerequisite, trigger, validation signal, or acknowledgement
    distinguishable from the completed operation it may precede.
    """

    decision: Literal["verified", "rejected", "unverified"]
    detail: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = ()
    effect_match: Literal["exact", "prerequisite_only", "different", "unknown"]
    recipient_match: Literal["exact", "different", "not_applicable", "unknown"]
    completion_match: Literal["established", "not_established", "unknown"]


class TargetDerivedICADraft(ClosedCanonicalModel):
    """One target-derived ICA before its independent verification."""

    slot_id: str = Field(min_length=1)
    ica_id: str = Field(min_length=1)
    ica_text: str = Field(min_length=1)
    deviation: str | None = Field(default=None, min_length=1)
    hazardous_context: str = Field(min_length=1)
    loss_scenario: str = Field(min_length=1)
    related_hazards: tuple[str, ...] = ()
    related_constraints: tuple[str, ...] = ()
    quality_warnings: tuple[str, ...] = ()


class TargetDerivedICADraftResponse(ClosedCanonicalModel):
    """Closed batch of proposed findings for deterministic compilation."""

    findings: tuple[TargetDerivedICADraft, ...] = ()


class TargetDerivedICAVerificationItem(ClosedCanonicalModel):
    """Independent semantic review for one exact target-derived ICA identity.

    The verifier describes the observed action state and the hazard path as
    separate required axes.  The slot's UCA category is compiler-owned, so
    the final ``verified``/``rejected``/``unverified`` disposition is derived
    locally from those axes.
    """

    ica_id: str = Field(min_length=1)
    detail: str = Field(min_length=1)
    evidence_refs: tuple[str, ...] = ()
    action_state: Literal[
        "absent",
        "performed_unsafe",
        "wrong_timing",
        "wrong_duration",
        "different_action",
        "undetermined",
    ]
    hazard_path: Literal["supported", "contradictory", "insufficient_evidence"]


class TargetDerivedICAVerificationResponse(ClosedCanonicalModel):
    """Closed independent-verifier response for a proposed ICA batch."""

    decisions: tuple[TargetDerivedICAVerificationItem, ...] = ()


class TargetRealizationLlmInterpreter:
    """Perform one bounded mapping call and one compact verifier call."""

    def __init__(
        self,
        llm_client: LLMClient,
        run_dir: Path,
        *,
        temperature: float,
        call_variant: str = "target_realization",
        loader: TemplateLoader | None = None,
    ) -> None:
        self._client = llm_client
        self._run_dir = Path(run_dir)
        self._temperature = temperature
        self._call_variant = call_variant
        self._loader = loader or TemplateLoader(PROMPTS_DIR)

    def __call__(
        self,
        *,
        action: Mapping[str, Any],
        operations: Sequence[Mapping[str, Any]],
    ) -> TargetRealizationProviderResponse:
        """Return one immediately validated and independently checked row."""
        action_view = dict(action)
        operation_views = tuple(dict(item) for item in operations)
        draft = self._map_action(action_view, operation_views)
        selected_operation_views = _selected_operation_view(operation_views, draft)
        # There is no action-operation claim to verify for an unmapped,
        # ambiguous, or contradictory draft.  Skipping the verifier here keeps
        # provider accounting honest and avoids spending a second call on a
        # non-existent selected relationship.
        verification = (
            self._verify(
                action_view,
                selected_operation_views,
            )
            if draft.disposition is TargetRealizationDisposition.supported
            and draft.selected_operation is not None
            and selected_operation_views
            else None
        )
        return _compile_mapping_response(draft, verification)

    def _map_action(
        self,
        action: Mapping[str, Any],
        operations: Sequence[Mapping[str, Any]],
    ) -> TargetRealizationDraft:
        system_prompt, user_prompt = self._mapping_prompts(action, operations)
        result, error = self._call(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=TargetRealizationDraft,
            step="map_control_action",
            slot_id=str(action["control_action_id"]),
        )
        return _require_provider_result(
            result,
            error,
            "target realization provider failed",
        )

    def _mapping_prompts(
        self,
        action: Mapping[str, Any],
        operations: Sequence[Mapping[str, Any]],
    ) -> tuple[str, str]:
        return (
            self._loader.render_prompt("realize_system.j2"),
            self._loader.render_prompt(
                "realize_user.j2",
                action_yaml=_yaml(action),
                operations_yaml=_yaml(operations),
            ),
        )

    def _verify(
        self,
        action: Mapping[str, Any],
        operations: Sequence[Mapping[str, Any]],
        *,
        semantic_context: Mapping[str, Any] | None = None,
    ) -> TargetRealizationVerificationDecision:
        system_prompt, user_prompt = self._verification_prompts(
            action, operations, semantic_context=semantic_context
        )
        result, error = self._call(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=TargetRealizationVerificationDecision,
            step="verify_control_action_mapping",
            slot_id=str(action["control_action_id"]),
        )
        return _verification_result(result, error)

    def _verification_prompts(
        self,
        action: Mapping[str, Any],
        operations: Sequence[Mapping[str, Any]],
        *,
        semantic_context: Mapping[str, Any] | None = None,
    ) -> tuple[str, str]:
        return (
            self._loader.render_prompt("verify_system.j2"),
            self._loader.render_prompt(
                "verify_user.j2",
                action_yaml=_yaml(action),
                operations_yaml=_yaml(operations),
                semantic_context_yaml=_yaml(semantic_context or {}),
            ),
        )

    def _call(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        response_format: type[ClosedCanonicalModel],
        step: str,
        slot_id: str,
    ) -> tuple[Any, Any]:
        result, _call, error = safe_llm_call(
            llm_client=self._client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            run_dir=self._run_dir,
            stage="target_realization",
            step=f"{self._call_variant}:{step}",
            slot_id=slot_id,
            temperature=self._temperature,
            max_completion_tokens=TARGET_REALIZATION_MAX_COMPLETION_TOKENS,
        )
        return result, error

    def extend(
        self,
        request: TargetRealizationExtensionRequest,
    ) -> TargetRealizationExtensionProviderResponse:
        """Perform the single bounded additive target-extension call."""
        system_prompt, user_prompt = self._extension_prompts(request)
        result, _call, error = safe_llm_call(
            llm_client=self._client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=TargetRealizationExtensionProviderResponse,
            run_dir=self._run_dir,
            stage="target_realization",
            step="extend_uncovered_operations",
            temperature=self._temperature,
            max_completion_tokens=TARGET_REALIZATION_MAX_COMPLETION_TOKENS,
            validation_retries=1,
            validation_retry_feedback=TARGET_EXTENSION_RETRY_FEEDBACK,
            validation_retry_include_schema=False,
            validation_retry_include_response=True,
            result_parser_with_cleanup=_parse_extension_response,
            result_validator=lambda value: _validate_extension_response(value, request),
        )
        if result is None and _call is not None:
            # safe_llm_call returns the final raw result, rather than the
            # parsed model, when a result validator rejects the last attempt.
            # First recover a parseable response that only failed completeness.
            recovery_transformations: list[dict[str, Any]] = []
            try:
                result = _parse_extension_response(
                    _call,
                    recovery_transformations,
                )
            except Exception:
                # A malformed individual outcome must not discard valid
                # siblings.  The salvage path validates each outcome on its
                # own and leaves omitted/invalid operations for compilation
                # diagnostics.
                result = _salvage_extension_response(
                    _call,
                    validation_error=error,
                )
                error = None
            else:
                error = None
        response = _require_provider_result(
            result, error, "target extension provider failed"
        )
        return self._verify_extension_outcomes(request, response)

    def _verify_extension_outcomes(
        self,
        request: TargetRealizationExtensionRequest,
        response: TargetRealizationExtensionProviderResponse,
    ) -> TargetRealizationExtensionProviderResponse:
        """Independently verify each accepted action/operation relationship.

        Extension output is a proposal, not an authority.  Reuse the compact
        mapping verifier with one exact operation view per accepted proposal;
        the verifier never sees the full inventory or the provider's
        extension rationale.  Invalid/non-observed references remain
        unverified and are rejected by the deterministic compiler.
        """
        operations_by_identity = {
            item.reference.identity: item for item in request.operations
        }
        outcomes = []
        for outcome in response.outcomes:
            if outcome.disposition.value != "accepted":
                outcomes.append(outcome.model_copy(update={"verification": None}))
                continue
            operation = operations_by_identity.get(outcome.operation.identity)
            if operation is None or outcome.control_action is None:
                verification = TargetRealizationVerification(
                    status="unverified",
                    detail="extension selected an operation outside its request",
                )
            else:
                operation_view = operation.model_dump(mode="json")
                action_view = _extension_action_view(
                    outcome,
                    operation,
                    request.baseline,
                )
                decision = self._verify(
                    action_view,
                    (operation_view,),
                    semantic_context=_extension_semantic_context(
                        request.baseline, outcome
                    ),
                )
                verification = _compile_mapping_verification(decision)
                if verification is None:  # pragma: no cover - decision is present
                    verification = TargetRealizationVerification(
                        status="unverified",
                        detail="extension verifier returned no decision",
                    )
            outcomes.append(outcome.model_copy(update={"verification": verification}))
        return TargetRealizationExtensionProviderResponse(
            outcomes=tuple(outcomes)
        ).with_provider_diagnostics(response.provider_diagnostics)

    def _extension_prompts(
        self,
        request: TargetRealizationExtensionRequest,
    ) -> tuple[str, str]:
        return (
            self._loader.render_prompt("extension_system.j2"),
            self._loader.render_prompt(
                "extension_user.j2",
                request_yaml=_yaml(_extension_prompt_view(request)),
            ),
        )


class TargetDerivedICALlmFinder:
    """Generate target-derived ICAs and verify them in a separate call."""

    def __init__(
        self,
        llm_client: LLMClient,
        run_dir: Path,
        *,
        temperature: float,
        loader: TemplateLoader | None = None,
    ) -> None:
        self._client = llm_client
        self._run_dir = Path(run_dir)
        self._temperature = temperature
        self._loader = loader or TemplateLoader(PROMPTS_DIR)

    def __call__(
        self,
        request: TargetDerivedICARequest,
    ) -> TargetDerivedICAProviderResponse:
        """Return only findings paired with an exact verifier decision."""
        draft = self._draft(request)
        decisions = self._decisions(request, draft)
        findings = _compile_derived_findings(
            draft,
            decisions,
            request.target_derived_ica_slots,
            request.target_operation_context,
        )
        return TargetDerivedICAProviderResponse(findings=findings)

    def _draft(
        self,
        request: TargetDerivedICARequest,
    ) -> TargetDerivedICADraftResponse:
        system_prompt = self._loader.render_prompt("derived_ica_system.j2")
        user_prompt = self._loader.render_prompt(
            "derived_ica_user.j2",
            request_yaml=_yaml(_derived_ica_prompt_view(request)),
        )
        result, raw, error = self._call_draft(
            system_prompt, user_prompt, step=TARGET_DERIVED_ICA_STEP
        )
        if error is not None or result is None:
            raise ValueError(f"target-derived ICA provider failed: {error}")
        repeats = _repeated_draft_references(result)
        if repeats:
            result = self._correct_repeated_references(
                system_prompt, user_prompt, raw, repeats
            )
        return _bind_draft_identities(result)

    def _call_draft(
        self, system_prompt: str, user_prompt: str, *, step: str
    ) -> tuple[TargetDerivedICADraftResponse | None, LLMResult | None, Any]:
        return safe_llm_call(
            llm_client=self._client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=TargetDerivedICADraftResponse,
            run_dir=self._run_dir,
            stage="target_realization",
            step=step,
            temperature=self._temperature,
            max_completion_tokens=TARGET_REALIZATION_MAX_COMPLETION_TOKENS,
        )

    def _correct_repeated_references(
        self,
        system_prompt: str,
        user_prompt: str,
        prior: LLMResult | None,
        repeats: list[str],
    ) -> TargetDerivedICADraftResponse:
        """Spend the one correction call a repeated reference is allowed.

        A failed call or a correction that still repeats a reference raises
        a plain ``ValueError``, which target-derived ICA realization records
        as a provider failure; a repeat never fails the run.
        """
        correction_prompt = _validation_retry_prompt(
            original_prompt=user_prompt,
            feedback=TARGET_DERIVED_ICA_DUPLICATE_FEEDBACK,
            error=ExactFeedbackError(
                "target-derived ICA draft repeats references:\n" + "\n".join(repeats)
            ),
            response_format=TargetDerivedICADraftResponse,
            include_schema=False,
            prior_result=prior,
            include_prior_response=True,
        )
        corrected, _raw, error = self._call_draft(
            system_prompt, correction_prompt, step=TARGET_DERIVED_ICA_CORRECTION_STEP
        )
        if error is not None or corrected is None:
            raise ValueError(f"target-derived ICA correction failed: {error}")
        remaining = _repeated_draft_references(corrected)
        if remaining:
            raise ValueError(
                "target-derived ICA correction still repeats references: "
                + "; ".join(remaining)
            )
        return corrected

    def _decisions(
        self,
        request: TargetDerivedICARequest,
        draft: TargetDerivedICADraftResponse,
    ) -> dict[str, TargetDerivedICAVerificationItem]:
        """Collect one verifier decision per draft finding.

        A failed call or an omitted finding is a technical gap, not a
        semantic rejection, so the omitted findings get one more verifier
        call. Findings still undecided after it stay unverified.
        """
        decisions = _verification_decisions(self._verify(request, draft))
        _require_known_decision_ids(decisions, draft.findings)
        omitted = tuple(item for item in draft.findings if item.ica_id not in decisions)
        if not omitted:
            return decisions
        retry = _verification_decisions(
            self._verify(
                request,
                TargetDerivedICADraftResponse(findings=omitted),
                step="verify_target_derived_icas_retry",
            )
        )
        _require_known_decision_ids(retry, omitted)
        return {**decisions, **retry}

    def _verify(
        self,
        request: TargetDerivedICARequest,
        draft: TargetDerivedICADraftResponse,
        *,
        step: str = "verify_target_derived_icas",
    ) -> TargetDerivedICAVerificationResponse:
        system_prompt, user_prompt = self._derived_verification_prompts(request, draft)
        result, _call, error = safe_llm_call(
            llm_client=self._client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=TargetDerivedICAVerificationResponse,
            run_dir=self._run_dir,
            stage="target_realization",
            step=step,
            temperature=self._temperature,
            max_completion_tokens=TARGET_REALIZATION_MAX_COMPLETION_TOKENS,
        )
        if error is not None or result is None:
            return TargetDerivedICAVerificationResponse()
        return result

    def _derived_verification_prompts(
        self,
        request: TargetDerivedICARequest,
        draft: TargetDerivedICADraftResponse,
    ) -> tuple[str, str]:
        return (
            self._loader.render_prompt("derived_verify_system.j2"),
            self._loader.render_prompt(
                "derived_verify_user.j2",
                baseline_yaml=_yaml(_systemic_baseline_prompt_view(request.baseline)),
                actions_yaml=_yaml(
                    [
                        item.model_dump(mode="json")
                        for item in request.target_derived_control_actions
                    ]
                ),
                slots_yaml=_yaml(_derived_verification_slot_views(request)),
                operations_yaml=_yaml(
                    [
                        item.model_dump(mode="json")
                        for item in request.target_operation_context
                    ]
                ),
                findings_yaml=_yaml(draft.model_dump(mode="json")),
            ),
        )


def _compile_mapping_response(
    draft: TargetRealizationDraft,
    verification: TargetRealizationVerificationDecision | None,
) -> TargetRealizationProviderResponse:
    payload = draft.model_dump(mode="python")
    if (
        draft.disposition is TargetRealizationDisposition.supported
        and draft.selected_operation is not None
        and not draft.candidate_operations
    ):
        payload["candidate_operations"] = (draft.selected_operation,)
    return TargetRealizationProviderResponse(
        **payload,
        verifier=_compile_mapping_verification(verification),
    )


def _compile_mapping_verification(
    decision: TargetRealizationVerificationDecision | None,
) -> TargetRealizationVerification | None:
    """Require independent semantic axes before crediting a mapping.

    A positive aggregate verdict with contradictory semantic axes is retained
    as a rejection; missing or unknown axes remain unverified.  Neither case
    is repaired from the provider's rationale or operation name.
    """
    if decision is None:
        return None

    detail = _mapping_verification_detail(decision)
    if decision.decision == "rejected":
        status: Literal["verified", "rejected", "unverified"] = "rejected"
    elif decision.decision == "unverified":
        status = "unverified"
    elif _mapping_axes_support_verification(decision):
        status = "verified"
    elif _mapping_axes_contradict_verification(decision):
        status = "rejected"
    else:
        status = "unverified"
    return TargetRealizationVerification(
        status=status,
        detail=detail,
        evidence_refs=decision.evidence_refs,
    )


def _mapping_axes_support_verification(
    decision: TargetRealizationVerificationDecision,
) -> bool:
    return (
        decision.effect_match == "exact"
        and decision.recipient_match in {"exact", "not_applicable"}
        and decision.completion_match == "established"
    )


def _mapping_axes_contradict_verification(
    decision: TargetRealizationVerificationDecision,
) -> bool:
    return (
        decision.effect_match in {"prerequisite_only", "different"}
        or decision.recipient_match == "different"
        or decision.completion_match == "not_established"
    )


def _mapping_verification_detail(
    decision: TargetRealizationVerificationDecision,
) -> str:
    return (
        f"{decision.detail} "
        "[effect_match="
        f"{decision.effect_match}; recipient_match={decision.recipient_match}; "
        f"completion_match={decision.completion_match}]"
    )


def _selected_operation_view(
    operations: Sequence[Mapping[str, Any]], draft: TargetRealizationDraft
) -> tuple[Mapping[str, Any], ...]:
    """Return only the exact operation claimed by a supported draft."""
    selected = draft.selected_operation
    if selected is None:
        return ()
    return tuple(
        operation
        for operation in operations
        if (
            operation.get("resource_id") == selected.resource_id
            and operation.get("operation_id") == selected.operation_id
        )
    )


def _extension_action_view(
    outcome: Any,
    operation: Any,
    baseline: Any,
) -> dict[str, Any]:
    """Build verifier input from compiler-owned operation facts.

    The extension wire deliberately has no provider-authored action
    description.  The verifier therefore checks the remaining semantic
    proposal against the exact observed operation instead of validating a
    model-generated recopy that could silently name a safeguard.
    """
    proposal = outcome.control_action
    if proposal is None:  # pragma: no cover - caller guards accepted outcomes
        raise ValueError("accepted target extension requires control_action")
    description = _operation_action_description(operation)
    target = _extension_target_prompt_view(baseline, outcome)
    controller = _controller_prompt_view(baseline, proposal.controller_id)
    return {
        "control_action_id": (
            f"TARGET_EXTENSION:{operation.resource_id}:{operation.operation_id}"
        ),
        "controller_id": proposal.controller_id,
        "controller": controller,
        "description": description,
        "effect_kind": "tool_call",
        "temporality": "instantaneous",
        "target": target,
        "target_new_controlled_process": proposal.target_new_controlled_process,
        "observed_operation": {
            "resource_id": operation.resource_id,
            "operation_id": operation.operation_id,
            "description": operation.description,
            "input_schema": operation.model_dump(mode="json")["input_schema"],
            "argument_names": list(operation.argument_names),
            "effect": operation.effect,
            "state_effect": operation.state_effect,
        },
    }


def _controller_prompt_view(baseline: Any, controller_id: str) -> dict[str, Any]:
    """Return controller identity with only baseline authority meaning."""
    return {
        "id": controller_id,
        "description": baseline.control_structure.element_description(
            "responsibility", controller_id
        ),
    }


def _extension_target_prompt_view(baseline: Any, outcome: Any) -> dict[str, Any] | None:
    """Resolve an extension target from exact authority or its process proposal."""
    proposal = outcome.control_action
    if proposal is None:  # pragma: no cover - caller guards accepted outcomes
        return None
    if proposal.target_new_controlled_process:
        process = outcome.controlled_process
        return {
            "type": "controlled_process",
            "id": None,
            "description": process.description if process is not None else None,
        }
    target = proposal.target
    if target is None:
        return None
    return {
        "type": target.type,
        "id": target.id,
        "description": baseline.control_structure.element_description(
            target.type, target.id
        ),
    }


def _extension_semantic_context(
    baseline: Any,
    outcome: Any,
) -> dict[str, Any]:
    """Provide independent systemic authority for extension relevance checks."""
    proposal = outcome.control_action
    controller_id = proposal.controller_id if proposal is not None else None
    controller = next(
        (
            item
            for item in baseline.control_structure.responsibilities
            if item.resp_id == controller_id
        ),
        None,
    )
    return {
        "selected_controller": (
            {
                "resp_id": controller.resp_id,
                "description": controller.description,
                "security_constraint_refs": list(controller.security_constraint_refs),
                "responsibility_constraints": [
                    item.model_dump(mode="json")
                    for item in controller.responsibility_constraints
                ],
            }
            if controller is not None
            else None
        ),
        "hazards": [
            item.model_dump(mode="json") for item in baseline.loss_analysis.hazards
        ],
        "security_constraints": [
            item.model_dump(mode="json")
            for item in baseline.loss_analysis.security_constraints
        ],
        "proposed_uca_categories": [item.uca_type for item in outcome.ica_slots],
    }


def _operation_action_description(operation: Any) -> str:
    """Render an exact observed operation meaning for verifier context."""
    return target_operation_action_description(operation)


def _require_provider_result(
    result: Any,
    error: Any,
    message: str,
) -> Any:
    if error is not None or result is None:
        raise ValueError(f"{message}: {error}")
    return result


def _parse_extension_response(
    result: LLMResult,
    cleanup_transformations: list[dict[str, Any]],
) -> TargetRealizationExtensionProviderResponse:
    """Normalize known target-extension contradictions before model validation."""
    payload = _decode_llm_content(
        result,
        cleanup_transformations=cleanup_transformations,
    )
    normalized_payload, diagnostics = _normalize_extension_payload(
        payload,
        cleanup_transformations,
    )
    response = TargetRealizationExtensionProviderResponse.model_validate(
        normalized_payload
    )
    return response.with_provider_diagnostics(diagnostics)


def _normalize_extension_payload(
    payload: Any,
    cleanup_transformations: list[dict[str, Any]],
) -> tuple[Mapping[str, Any], tuple[str, ...]]:
    """Apply only the explicit existing-target contradiction correction."""
    if not isinstance(payload, Mapping):
        raise TypeError("target extension response must be one JSON object")
    raw_outcomes = payload.get("outcomes", ())
    if not isinstance(raw_outcomes, (list, tuple)):
        raise TypeError("target extension outcomes must be an array")

    normalized_outcomes: list[Any] = []
    diagnostics: list[str] = []
    for raw_outcome in raw_outcomes:
        if not isinstance(raw_outcome, Mapping):
            normalized_outcomes.append(raw_outcome)
            continue
        control_action = raw_outcome.get("control_action")
        if not isinstance(control_action, Mapping):
            normalized_outcomes.append(raw_outcome)
            continue
        target = control_action.get("target")
        if (
            target is None
            or control_action.get("target_new_controlled_process") is not True
        ):
            normalized_outcomes.append(raw_outcome)
            continue

        normalized_action = dict(control_action)
        normalized_action["target_new_controlled_process"] = False
        normalized_outcome = dict(raw_outcome)
        normalized_outcome["control_action"] = normalized_action
        operation_label = _raw_extension_operation_label(raw_outcome)
        target_label = _raw_extension_target_label(target)
        cleanup_transformations.append(
            _transformation(
                "target_extension_existing_target_precedence",
                raw_outcome,
                normalized_outcome,
                detail=(
                    "kept the non-null existing target and cleared "
                    "target_new_controlled_process"
                ),
            )
        )
        diagnostics.append(
            "target extension normalized target_new_controlled_process for "
            f"{operation_label}: existing target {target_label} kept"
        )
        normalized_outcomes.append(normalized_outcome)

    normalized_payload = dict(payload)
    normalized_payload["outcomes"] = normalized_outcomes
    return normalized_payload, tuple(diagnostics)


def _raw_extension_operation_label(value: Any) -> str:
    """Format an operation identity from an unvalidated provider row."""
    operation = value.get("operation") if isinstance(value, Mapping) else None
    if not isinstance(operation, Mapping):
        return "<unknown operation>"
    resource_id = operation.get("resource_id", "<unknown resource>")
    operation_id = operation.get("operation_id", "<unknown operation>")
    return f"{resource_id}/{operation_id}"


def _raw_extension_target_label(value: Any) -> str:
    """Format an existing target identity from an unvalidated provider row."""
    if not isinstance(value, Mapping):
        return str(value)
    target_id = value.get("id")
    target_type = value.get("type")
    if target_type and target_id:
        return f"{target_type} {target_id}"
    return str(target_id or target_type or value)


def _salvage_extension_response(
    result: LLMResult,
    *,
    validation_error: str | None,
) -> TargetRealizationExtensionProviderResponse:
    """Keep individually valid outcomes after a final aggregate parse failure."""
    cleanup_transformations: list[dict[str, Any]] = []
    payload = _decode_llm_content(
        result,
        cleanup_transformations=cleanup_transformations,
    )
    normalized_payload, normalization_diagnostics = _normalize_extension_payload(
        payload,
        cleanup_transformations,
    )
    raw_outcomes = normalized_payload.get("outcomes", ())
    valid_outcomes: list[TargetRealizationExtensionOutcome] = []
    diagnostics = list(normalization_diagnostics)
    if validation_error:
        diagnostics.append(
            "target extension retained individually valid outcomes after final "
            f"response validation failed: {validation_error}"
        )
    seen_identities: set[tuple[str, str]] = set()
    for raw_outcome in raw_outcomes:
        try:
            outcome = TargetRealizationExtensionOutcome.model_validate(raw_outcome)
        except Exception as exc:  # noqa: BLE001 - isolate one provider outcome
            diagnostics.append(
                "target extension dropped invalid outcome for "
                f"{_raw_extension_operation_label(raw_outcome)}: "
                f"{_compact_validation_error(exc)}"
            )
            continue
        if outcome.operation.identity in seen_identities:
            diagnostics.append(
                "target extension dropped duplicate outcome for "
                f"{_format_operation_identity(outcome.operation.identity)}"
            )
            continue
        seen_identities.add(outcome.operation.identity)
        valid_outcomes.append(outcome)

    response = TargetRealizationExtensionProviderResponse(
        outcomes=tuple(valid_outcomes)
    )
    return response.with_provider_diagnostics(diagnostics)


def _validate_extension_response(
    response: TargetRealizationExtensionProviderResponse,
    request: TargetRealizationExtensionRequest,
) -> None:
    """Require complete outcomes and rationales for rejected operations."""
    requested = {item.reference.identity for item in request.operations}
    returned = {item.operation.identity for item in response.outcomes}
    missing_rationales = sorted(
        outcome.operation.identity
        for outcome in response.outcomes
        if outcome.disposition.value == "rejected" and not outcome.rationale.strip()
    )
    problems = (
        ("missing operation ids: ", sorted(requested - returned)),
        ("outcomes for operations outside request: ", sorted(returned - requested)),
        ("rejected outcomes missing a rationale: ", missing_rationales),
    )
    details = [
        label + ", ".join(_format_operation_identity(identity) for identity in found)
        for label, found in problems
        if found
    ]
    if not details:
        return
    raise ValueError(
        "target extension must return exactly one outcome for every requested "
        "operation and a rationale for every rejection; " + "; ".join(details)
    )


def _format_operation_identity(identity: tuple[str, str]) -> str:
    """Format one exact operation identity for model-facing validation text."""
    return f"{identity[0]}/{identity[1]}"


def _verification_result(
    result: Any,
    error: Any,
) -> TargetRealizationVerificationDecision:
    if error is not None or result is None:
        return TargetRealizationVerificationDecision(
            decision="unverified",
            detail=f"target realization verification failed: {error}",
            effect_match="unknown",
            recipient_match="unknown",
            completion_match="unknown",
        )
    return result


def _verification_decisions(
    response: TargetDerivedICAVerificationResponse,
) -> dict[str, TargetDerivedICAVerificationItem]:
    decisions = {item.ica_id: item for item in response.decisions}
    if len(decisions) != len(response.decisions):
        raise ValueError("target-derived ICA verifier returned duplicate IDs")
    return decisions


def _compile_derived_findings(
    draft: TargetDerivedICADraftResponse,
    decisions: Mapping[str, TargetDerivedICAVerificationItem],
    slots: Sequence[Any],
    operation_context: Sequence[Any] = (),
) -> tuple[TargetDerivedICAFinding, ...]:
    slot_categories = {item.slot_id: item.uca_type for item in slots}
    slot_actions = {item.slot_id: item.control_action for item in slots}
    context_actions = {item.control_action_id for item in operation_context}
    return tuple(
        _compile_derived_finding(
            item,
            decisions.get(item.ica_id),
            slot_categories.get(item.slot_id),
            has_operation_context=(slot_actions.get(item.slot_id) in context_actions),
        )
        for item in draft.findings
    )


def _compile_derived_finding(
    item: TargetDerivedICADraft,
    decision: TargetDerivedICAVerificationItem | None,
    slot_uca_type: str | None,
    *,
    has_operation_context: bool = True,
) -> TargetDerivedICAFinding:
    verification = _finding_verification(
        decision,
        slot_uca_type,
        has_operation_context=has_operation_context,
    )
    return TargetDerivedICAFinding(
        **item.model_dump(mode="python"),
        verification=verification,
    )


def _finding_verification(
    decision: TargetDerivedICAVerificationItem | None,
    slot_uca_type: str | None = None,
    *,
    has_operation_context: bool = True,
) -> TargetRealizationVerification:
    if decision is None:
        return TargetRealizationVerification(
            status="unverified",
            detail="independent verifier omitted this finding, including on retry",
        )

    semantic_decision = _semantic_verification_decision(decision, slot_uca_type)
    detail = decision.detail
    if semantic_decision == "verified" and not has_operation_context:
        semantic_decision = "unverified"
        detail = (
            "Exact target-operation context is missing; positive review is not sufficient. "
            + detail
        )
    return TargetRealizationVerification(
        status=semantic_decision,
        detail=detail,
        evidence_refs=decision.evidence_refs,
    )


def _semantic_verification_decision(
    decision: TargetDerivedICAVerificationItem,
    slot_uca_type: str | None,
) -> Literal["verified", "rejected", "unverified"]:
    """Bind independent action/harm axes to the compiler-owned UCA category.

    This reuses the same three-axis rule used by the systemic ICA verifier: the
    provider describes what happened to the named action and whether the
    supplied facts establish a hazard path; deterministic code compares that
    description with the fixed slot category.  In particular, an ``absent``
    action cannot be credited to an ``INCORRECT`` slot, and a path lacking
    concrete supplied support cannot become a verified finding merely because
    the provider returned a positive aggregate decision.
    """
    if slot_uca_type not in {
        "NOT_PROVIDED",
        "INCORRECT",
        "WRONG_TIMING",
        "WRONG_DURATION",
    }:
        return "unverified"
    semantic = classify_ica_semantics(
        slot_uca_type,
        action_state=decision.action_state,
        hazard_path=decision.hazard_path,
    )
    return {
        "supported": "verified",
        "contradictory": "rejected",
        "insufficient_evidence": "unverified",
    }[semantic]


def _require_known_decision_ids(
    decisions: Mapping[str, TargetDerivedICAVerificationItem],
    findings: Sequence[TargetDerivedICADraft],
) -> None:
    known_ids = {item.ica_id for item in findings}
    unknown_ids = set(decisions) - known_ids
    if unknown_ids:
        raise ValueError(
            "target-derived ICA verifier returned unknown IDs: "
            + ", ".join(sorted(unknown_ids))
        )


def _yaml(value: object) -> str:
    return yaml.safe_dump(value, sort_keys=True, allow_unicode=True)


def _extension_prompt_view(
    request: TargetRealizationExtensionRequest,
) -> dict[str, Any]:
    """Return only the systemic facts needed to assess uncovered operations."""
    return {
        "baseline": _systemic_baseline_prompt_view(request.baseline),
        "operations": [item.model_dump(mode="json") for item in request.operations],
    }


def _derived_ica_prompt_view(request: TargetDerivedICARequest) -> dict[str, Any]:
    """Return the accepted additions and exact slots the provider may fill."""
    return {
        "baseline": _systemic_baseline_prompt_view(request.baseline),
        "target_derived_control_actions": [
            item.model_dump(mode="json")
            for item in request.target_derived_control_actions
        ],
        "target_derived_ica_slots": [
            item.model_dump(mode="json") for item in request.target_derived_ica_slots
        ],
        "target_operation_context": [
            item.model_dump(mode="json") for item in request.target_operation_context
        ],
    }


def _derived_verification_slot_views(
    request: TargetDerivedICARequest,
) -> list[dict[str, Any]]:
    """Hide the proposed UCA category while retaining exact slot identity.

    The verifier must describe the named action and hazard path independently;
    it should not be able to turn a provider-supplied category into a
    confirmation merely by repeating that label.  Deterministic compilation
    restores the category from this request's immutable slot authority.
    """
    return [
        {
            key: value
            for key, value in item.model_dump(mode="json").items()
            if key != "uca_type"
        }
        for item in request.target_derived_ica_slots
    ]


def _systemic_baseline_prompt_view(baseline: Any) -> dict[str, Any]:
    """Return the compact authoritative systemic context needed by target analysis."""
    return {
        "baseline_id": baseline.baseline_id,
        "baseline_digest": baseline.baseline_digest,
        "losses": [
            item.model_dump(mode="json")
            for item in (
                *baseline.loss_analysis.risk_card_losses,
                *baseline.loss_analysis.use_case_losses,
            )
        ],
        "hazards": [
            item.model_dump(mode="json") for item in baseline.loss_analysis.hazards
        ],
        "security_constraints": [
            item.model_dump(mode="json")
            for item in baseline.loss_analysis.security_constraints
        ],
        "responsibilities": [
            {
                "resp_id": item.resp_id,
                "description": item.description,
                "control_actions": [
                    action.model_dump(mode="json") for action in item.control_actions
                ],
            }
            for item in baseline.control_structure.responsibilities
        ],
        "controlled_processes": [
            item.model_dump(mode="json")
            for item in baseline.control_structure.controlled_processes
        ],
    }


def _bind_draft_identities(
    response: TargetDerivedICADraftResponse,
) -> TargetDerivedICADraftResponse:
    """Replace provider-authored ICA IDs with compiler-owned slot identities."""
    slot_counts: dict[str, int] = {}
    findings = []
    for item in response.findings:
        suffix = slot_counts.get(item.slot_id, 0) + 1
        slot_counts[item.slot_id] = suffix
        findings.append(item.model_copy(update={"ica_id": f"{item.slot_id}:{suffix}"}))
    return TargetDerivedICADraftResponse(findings=tuple(findings))


def _repeated_draft_references(response: TargetDerivedICADraftResponse) -> list[str]:
    """Name each finding that lists a hazard or constraint more than once.

    Findings are named by position and the provider's own ``ica_id`` because
    the correction request shows the response as the provider wrote it.
    """
    problems = []
    for index, item in enumerate(response.findings):
        for field_name in ("related_hazards", "related_constraints"):
            references = getattr(item, field_name)
            repeated = sorted({ref for ref in references if references.count(ref) > 1})
            if repeated:
                problems.append(
                    f"findings[{index}] (ica_id '{item.ica_id}', slot "
                    f"{item.slot_id}): {field_name} repeats " + ", ".join(repeated)
                )
    return problems


__all__ = [
    "TargetDerivedICADraft",
    "TargetDerivedICADraftResponse",
    "TargetDerivedICALlmFinder",
    "TargetDerivedICAVerificationItem",
    "TargetDerivedICAVerificationResponse",
    "TargetRealizationDraft",
    "TargetRealizationLlmInterpreter",
    "TargetRealizationVerificationDecision",
]
