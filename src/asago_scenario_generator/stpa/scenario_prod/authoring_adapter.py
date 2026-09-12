"""Deterministic adapter from the current authoring wire to the legacy draft.

The adapter is the only place where provider-selected handles become durable
paths, source quotations, obligation references, and fixed action names.  It
does not accept :class:`AuthoringResponse` as an input: historical decoding
and current provider calls remain separate seams.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import ValidationError

from asago_scenario_generator.stpa.scenario_prod.authoring_types import (
    AuthoringResponse,
    AuthoredAdversary,
    AuthoredClaimUnderTest,
    AuthoredConditionEntry,
    AuthoredScenarioDraft,
    AuthoredStimulus,
    AuthoredTriggerEvidence,
    AuthoredTurn,
    AuthoredUnsafeObservation,
    stimulus_user_texts,
)
from asago_scenario_generator.stpa.scenario_prod.authoring_context import (
    AdmissibleCheck,
    AuthoringContext,
    AuthoringContextError,
    SourceHandle,
)
from asago_scenario_generator.stpa.scenario_prod.authoring_wire import (
    CurrentAuthoringResponse,
    CurrentCondition,
    CurrentConversation,
    CurrentEvidence,
    CurrentObservationCondition,
    CurrentObservationEvidence,
    CurrentResponseClaimCheck,
    CurrentScenarioDraft,
    CurrentStateFactCondition,
    CurrentStateFactEvidence,
    CurrentStimulusCondition,
    CurrentStimulusEvidence,
    CurrentToolAbsentCheck,
    CurrentToolArgumentCheck,
    CurrentToolOrderCheck,
    CurrentUserMessage,
)


class CurrentAuthoringAdapterError(ValueError):
    """A current response selected an unknown or semantically invalid handle."""

    def __init__(
        self,
        detail: str,
        *,
        reason: str = "current_authoring_adapter_error",
    ) -> None:
        self.reason = reason
        self.detail = detail
        super().__init__(detail)


@dataclass(frozen=True)
class CurrentDraftAdapterFailure:
    """Per-draft adapter rejection with the provider response preserved."""

    draft_index: int
    reason: str
    detail: str
    raw_draft: dict[str, Any]

    def as_payload(self) -> dict[str, Any]:
        """Return a durable, JSON/YAML-safe rejection record."""
        return {
            "draft_index": self.draft_index,
            "reason": self.reason,
            "detail": self.detail,
            "raw_draft": self.raw_draft,
        }


@dataclass(frozen=True)
class AdaptedCurrentDraft:
    """One legacy draft plus source binding metadata used by validation."""

    draft: Any
    selected_numeric_source: SourceHandle | None = None
    # ``literal`` remains an explicit current-wire choice for operators whose
    # contract permits it (for example equality).  Current numeric comparison
    # branches require a supplied source handle; historical drafts retain
    # their own read-only compatibility behavior elsewhere.
    numeric_operand_source: str | None = None


@dataclass(frozen=True)
class CurrentAuthoringAdaptation:
    """Adapted response and per-draft source metadata."""

    drafts: tuple[AdaptedCurrentDraft, ...]
    failures: tuple[CurrentDraftAdapterFailure, ...]
    no_scenario_reason: str | None

    @property
    def response(self) -> Any:
        """Build the historical response envelope for compatibility callers."""
        return AuthoringResponse(
            scenarios=tuple(item.draft for item in self.drafts),
            no_scenario_reason=self.no_scenario_reason,
        )


def _source(
    context: AuthoringContext, handle: str, kind: str | None = None
) -> SourceHandle:
    try:
        return context.source(handle, kind=kind)
    except AuthoringContextError as exc:
        raise CurrentAuthoringAdapterError(
            str(exc), reason="source_handle_unknown"
        ) from exc


def _check(context: AuthoringContext, handle: str, kind: str) -> AdmissibleCheck:
    try:
        choice = context.check(handle, kind=kind)
    except AuthoringContextError as exc:
        raise CurrentAuthoringAdapterError(
            str(exc), reason="choice_handle_unknown"
        ) from exc
    if choice.kind != kind:
        raise CurrentAuthoringAdapterError(
            f"choice handle {handle!r} is for {choice.kind!r}, not {kind!r}",
            reason="choice_handle_wrong_kind",
        )
    return choice


def _reference_tool(
    context: AuthoringContext, choice: AdmissibleCheck, handle: str
) -> Any:
    try:
        reference = context.reference_tool(handle)
    except AuthoringContextError as exc:
        raise CurrentAuthoringAdapterError(
            str(exc), reason="reference_tool_handle_unknown"
        ) from exc
    if all(item.handle != handle for item in choice.reference_tools):
        raise CurrentAuthoringAdapterError(
            f"reference-tool handle {handle!r} is not admissible for choice {choice.handle!r}",
            reason="reference_tool_unavailable",
        )
    return reference


def _stimulus(context: AuthoringContext, stimulus: Any) -> Any:
    if isinstance(stimulus, CurrentUserMessage):
        return AuthoredStimulus(kind="user_message", text=stimulus.text)
    if isinstance(stimulus, CurrentConversation):
        if not context.conversation_allowed:
            raise CurrentAuthoringAdapterError(
                "conversation stimulus is unavailable for this action: no "
                "accepted subject argument role is declared",
                reason="conversation_stimulus_unavailable",
            )
        return AuthoredStimulus(
            kind="conversation",
            turns=tuple(
                AuthoredTurn(role="user", text=text) for text in stimulus.turns
            ),
        )
    raise CurrentAuthoringAdapterError(
        f"unsupported current stimulus type {type(stimulus).__name__}"
    )


def _add_source(selected: set[str], source: SourceHandle) -> None:
    if source.kind == "state_fact":
        selected.add(source.handle)


def _operand_value(
    context: AuthoringContext,
    operand: Any,
    *,
    choice: AdmissibleCheck,
    operator: str,
    selected: set[str],
) -> tuple[Any, SourceHandle | None, str]:
    """Resolve a typed operand and retain its exact source binding."""
    source_name = getattr(operand, "source", None)
    if source_name not in choice.operand_sources:
        raise CurrentAuthoringAdapterError(
            f"operand source {source_name!r} is not admissible for choice "
            f"{choice.handle!r}",
            reason="operand_source_unavailable",
        )
    if operator in {"greater_than", "less_than"} and source_name == "literal":
        raise CurrentAuthoringAdapterError(
            "numeric comparison requires a selected numeric source handle; "
            "a literal threshold is not admissible",
            reason="numeric_source_required",
        )
    if operator == "owner_differs_from_session" and source_name != "literal":
        raise CurrentAuthoringAdapterError(
            "owner_differs_from_session requires the literal record address; "
            "a selected state_fact is an owner/value leaf, not the address",
            reason="owner_record_address_required",
        )
    if operator == "owner_differs_from_session" and not isinstance(operand.value, str):
        raise CurrentAuthoringAdapterError(
            "owner_differs_from_session requires a string literal record address",
            reason="owner_record_address_required",
        )
    if source_name == "literal":
        return operand.value, None, "literal"
    if source_name == "state_fact":
        source = _source(context, operand.fact_handle, "state_fact")
    elif source_name == "observation":
        source = _source(context, operand.observation_handle, "observation")
    else:
        raise CurrentAuthoringAdapterError(
            f"unsupported operand source {source_name!r} for operator {operator!r}"
        )
    _add_source(selected, source)
    return source.value, source, source.kind


def _evidence(
    context: AuthoringContext,
    evidence: CurrentEvidence,
    stimulus: Any,
    *,
    selected: set[str],
) -> Any:
    if isinstance(evidence, CurrentStimulusEvidence):
        texts = stimulus_user_texts(stimulus)
        if evidence.turn > len(texts):
            raise CurrentAuthoringAdapterError(
                f"stimulus evidence turn {evidence.turn} is beyond the supplied "
                f"{len(texts)} user turn(s)"
            )
        quote = texts[evidence.turn - 1]
        if not quote:
            raise CurrentAuthoringAdapterError(
                f"stimulus evidence turn {evidence.turn} is empty"
            )
        return AuthoredTriggerEvidence(
            source="stimulus",
            turn=evidence.turn,
            quote=quote,
            meaning=evidence.meaning,
        )
    if isinstance(evidence, CurrentStateFactEvidence):
        source = _source(context, evidence.fact_handle, "state_fact")
        _add_source(selected, source)
        return AuthoredTriggerEvidence(
            source="state_fact",
            state_path=source.path,
            quote=source.canonical_value,
            meaning=evidence.meaning,
        )
    if isinstance(evidence, CurrentObservationEvidence):
        source = _source(context, evidence.observation_handle, "observation")
        if source.observation_ref is None or source.observation_content is None:
            raise CurrentAuthoringAdapterError(
                f"observation handle {source.handle!r} has no source content"
            )
        quote = source.canonical_value
        # Preserve a lexical JSON value when the source string contains
        # escaped characters.  Plain strings stay unquoted when they already
        # occur verbatim in the supplied observation, which keeps the
        # compiler-owned citation concise while remaining an exact substring.
        if quote not in source.observation_content:
            encoded = source.display_value
            if encoded in source.observation_content:
                quote = encoded
        return AuthoredTriggerEvidence(
            source="observation",
            observation_ref=source.observation_ref,
            quote=quote,
            meaning=evidence.meaning,
            observation_path=source.path,
        )
    raise CurrentAuthoringAdapterError(
        f"unsupported current evidence type {type(evidence).__name__}"
    )


def _conditions(
    context: AuthoringContext,
    entries: tuple[CurrentCondition, ...],
    *,
    selected: set[str],
) -> tuple[Any, ...]:
    result: list[Any] = []
    for entry in entries:
        if isinstance(entry, CurrentStimulusCondition):
            result.append(
                AuthoredConditionEntry(
                    condition=entry.condition,
                    by="stimulus",
                    ref=None,
                    note=entry.meaning,
                )
            )
        elif isinstance(entry, CurrentStateFactCondition):
            source = _source(context, entry.fact_handle, "state_fact")
            _add_source(selected, source)
            result.append(
                AuthoredConditionEntry(
                    condition=entry.condition,
                    by="state_fact",
                    ref=source.path,
                    note=entry.meaning,
                )
            )
        elif isinstance(entry, CurrentObservationCondition):
            source = _source(context, entry.observation_handle, "observation")
            if source.observation_ref is None:
                raise CurrentAuthoringAdapterError(
                    f"observation handle {source.handle!r} has no observation reference"
                )
            result.append(
                AuthoredConditionEntry(
                    condition=entry.condition,
                    by="observation",
                    ref=(source.observation_ref, *source.path),
                    note=entry.meaning,
                )
            )
        else:
            raise CurrentAuthoringAdapterError(
                f"unsupported current condition type {type(entry).__name__}"
            )
    return tuple(result)


def _claims(
    context: AuthoringContext,
    entries: tuple[Any, ...],
    *,
    selected: set[str],
) -> tuple[Any, ...]:
    result: list[Any] = []
    for entry in entries:
        source = _source(context, entry.fact_handle, "state_fact")
        _add_source(selected, source)
        result.append(
            AuthoredClaimUnderTest(
                turn=entry.turn,
                state_path=source.path,
                note=entry.meaning,
            )
        )
    return tuple(result)


def _unsafe_observation(
    context: AuthoringContext,
    draft: CurrentScenarioDraft,
    *,
    selected: set[str],
) -> tuple[Any, SourceHandle | None, str | None]:
    observation = draft.unsafe_observation
    choice = _check(context, observation.choice_handle, observation.kind)
    selected_numeric: SourceHandle | None = None
    numeric_source_kind: str | None = None
    if isinstance(observation, CurrentToolArgumentCheck):
        if observation.argument not in context.candidate.action_binding.argument_names:
            raise CurrentAuthoringAdapterError(
                f"argument {observation.argument!r} is not admissible for "
                f"choice {choice.handle!r}"
            )
        if observation.operator not in choice.operators:
            raise CurrentAuthoringAdapterError(
                f"operator {observation.operator!r} is not admissible for "
                f"choice {choice.handle!r}"
            )
        value, selected_numeric, numeric_source_kind = _operand_value(
            context,
            observation.operand,
            choice=choice,
            operator=observation.operator,
            selected=selected,
        )
        if observation.operator in {"greater_than", "less_than"} and (
            not isinstance(value, (int, float)) or isinstance(value, bool)
        ):
            # Keep this as a typed provider-semantic rejection rather than
            # converting policy prose into a threshold.
            raise CurrentAuthoringAdapterError(
                f"numeric operator {observation.operator!r} selected a non-numeric "
                f"source value {value!r}"
            )
        return (
            AuthoredUnsafeObservation(
                kind="tool_argument",
                tool=choice.action_name,
                argument=observation.argument,
                operator=observation.operator,
                value=value,
            ),
            selected_numeric,
            numeric_source_kind,
        )
    if isinstance(observation, CurrentToolOrderCheck):
        if observation.argument not in context.candidate.action_binding.argument_names:
            raise CurrentAuthoringAdapterError(
                f"argument {observation.argument!r} is not admissible for "
                f"choice {choice.handle!r}"
            )
        if observation.operator not in choice.operators:
            raise CurrentAuthoringAdapterError(
                f"operator {observation.operator!r} is not admissible for "
                f"choice {choice.handle!r}"
            )
        value, selected_numeric, numeric_source_kind = _operand_value(
            context,
            observation.operand,
            choice=choice,
            operator=observation.operator,
            selected=selected,
        )
        if observation.operator in {"greater_than", "less_than"} and (
            not isinstance(value, (int, float)) or isinstance(value, bool)
        ):
            raise CurrentAuthoringAdapterError(
                f"numeric operator {observation.operator!r} selected a non-numeric "
                f"source value {value!r}"
            )
        reference_choice = _reference_tool(
            context, choice, observation.reference_tool_handle
        )
        if observation.argument not in reference_choice.shared_arguments:
            raise CurrentAuthoringAdapterError(
                f"argument {observation.argument!r} is not shared by reference "
                f"tool {reference_choice.tool!r} for choice {choice.handle!r}",
                reason="reference_argument_unavailable",
            )
        return (
            AuthoredUnsafeObservation(
                kind="tool_order",
                tool=choice.action_name,
                argument=observation.argument,
                operator=observation.operator,
                value=value,
                reference_tool=reference_choice.tool,
            ),
            selected_numeric,
            numeric_source_kind,
        )
    if isinstance(observation, CurrentToolAbsentCheck):
        stimulus = _stimulus(context, draft.stimulus)
        evidence = tuple(
            _evidence(context, item, stimulus, selected=selected)
            for item in observation.trigger_evidence
        )
        return (
            AuthoredUnsafeObservation(
                kind="tool_absent",
                tool=choice.action_name,
                trigger=observation.trigger,
                trigger_evidence=evidence,
            ),
            None,
            None,
        )
    if isinstance(observation, CurrentResponseClaimCheck):
        return (
            AuthoredUnsafeObservation(
                kind="response_claim",
                proposition=observation.proposition,
            ),
            None,
            None,
        )
    raise CurrentAuthoringAdapterError(
        f"unsupported current unsafe observation type {type(observation).__name__}"
    )


def _adapt_draft(
    context: AuthoringContext, draft: CurrentScenarioDraft
) -> AdaptedCurrentDraft:
    selected: set[str] = set()
    stimulus = _stimulus(context, draft.stimulus)
    conditions = _conditions(context, draft.conditions_established, selected=selected)
    claims = _claims(context, draft.claims_under_test, selected=selected)
    unsafe, numeric_source, numeric_source_kind = _unsafe_observation(
        context, draft, selected=selected
    )
    choice = _check(
        context,
        draft.unsafe_observation.choice_handle,
        draft.unsafe_observation.kind,
    )
    # The current wire's choice is the sole source of the obligation reference;
    # no model-authored copy can detach it from the reviewed action binding.
    paths = tuple(
        source.path for source in context.state_handles if source.handle in selected
    )
    try:
        legacy = AuthoredScenarioDraft(
            adversary=AuthoredAdversary(
                kind=draft.adversary.kind, gain=draft.adversary.gain
            ),
            stimulus=stimulus,
            state_facts_used=paths,
            unsafe_observation=unsafe,
            conditions_established=conditions,
            claims_under_test=claims,
            safe_behaviors=draft.safe_behaviors,
            obligation_ref=choice.obligation_ref,
        )
    except (ValidationError, ValueError, TypeError) as exc:
        raise CurrentAuthoringAdapterError(
            f"current authoring draft could not be adapted to the historical "
            f"draft contract: {exc}"
        ) from exc
    return AdaptedCurrentDraft(
        draft=legacy,
        selected_numeric_source=numeric_source,
        numeric_operand_source=numeric_source_kind,
    )


def adapt_current_response_with_bindings(
    response: CurrentAuthoringResponse,
    context: AuthoringContext,
) -> CurrentAuthoringAdaptation:
    """Adapt one parsed current response and retain exact source bindings."""
    if not isinstance(response, CurrentAuthoringResponse):
        raise CurrentAuthoringAdapterError(
            "current authoring adapter accepts only CurrentAuthoringResponse; "
            "historical AuthoringResponse must use its read-only compatibility seam"
        )
    drafts: list[AdaptedCurrentDraft] = []
    failures: list[CurrentDraftAdapterFailure] = []
    for index, draft in enumerate(response.scenarios):
        try:
            drafts.append(_adapt_draft(context, draft))
        except (
            CurrentAuthoringAdapterError,
            ValidationError,
            TypeError,
            ValueError,
        ) as exc:
            if isinstance(exc, CurrentAuthoringAdapterError):
                reason = exc.reason
                detail = exc.detail
            else:
                reason = "current_authoring_adapter_error"
                detail = str(exc)
            failures.append(
                CurrentDraftAdapterFailure(
                    draft_index=index,
                    reason=reason,
                    detail=detail,
                    raw_draft=draft.model_dump(mode="json"),
                )
            )
    return CurrentAuthoringAdaptation(
        drafts=tuple(drafts),
        failures=tuple(failures),
        no_scenario_reason=response.no_scenario_reason,
    )


def adapt_current_response(
    response: CurrentAuthoringResponse,
    context: AuthoringContext,
) -> Any:
    """Return the historical draft envelope for compatibility callers.

    Only a ``CurrentAuthoringResponse`` is accepted, so this function cannot
    become a runtime fallback for the historical provider format.
    """
    return adapt_current_response_with_bindings(response, context).response


__all__ = [
    "AdaptedCurrentDraft",
    "CurrentAuthoringAdaptation",
    "CurrentAuthoringAdapterError",
    "CurrentDraftAdapterFailure",
    "adapt_current_response",
    "adapt_current_response_with_bindings",
]
