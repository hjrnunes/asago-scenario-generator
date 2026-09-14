"""Stage 2 — target-derived control structure (single-controller targets).

Phase 2 of the target-grounded scenario generation spec.  When an observed
execution target profile is supplied and the capability profile says
``multi_agent: false``, the control structure is derived deterministically
from the target (spec 2.1/2.2) instead of being invented by the four
target-blind Stage 2 calls:

- one ``ASSISTANT`` controller,
- one tool-call action per observed tool operation (name, description, and
  argument schema copied verbatim),
- one ``respond`` model-output action,
- conditional actions only when the capability profile justifies them,
- one controlled process per tool plus the customer-facing interface,
- one model call naming domain beliefs (bounded to five), and
- one model call deciding constraint-to-action relevance (spec 2.3).

Losses, hazards, and constraints stay target-blind: only the structure that
must be exercisable through a real surface is derived from the target.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, ConfigDict, Field, StrictStr

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    _decode_llm_content,
    StageError,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlActionTemporality,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.target_derived_structure import (
    CONSTRAINT_ACTION_RELEVANCE_FILENAME,
    TARGET_DERIVED_STRUCTURE_FILENAME,
    ActionBinding,
    BeliefRecord,
    ConstraintActionRelevance,
    ConstraintRelevanceRow,
    ControllerPurpose,
    ProcessModelRecord,
    RelevantAction,
    ReviewedObligationBinding,
    TargetDerivedStructure,
    UnconstrainedAction,
    control_structure_content_digest,
    loss_analysis_content_digest,
    validate_reviewed_obligation_bindings,
)
from asago_scenario_generator.stpa.models.target_subject_model import (
    SessionSubject,
    SubjectModelError,
    TargetSubjectModel,
    resolve_session_subject,
    verify_target_subject_model,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
    classify_constraint,
    load_behavior_classes,
)

if TYPE_CHECKING:
    # The observation snapshot is an already-validated scenario_prod value;
    # system_model receives it through this seam without a runtime dependency.
    from asago_scenario_generator.stpa.scenario_prod.target_observations import (
        TargetObservationSnapshot,
    )

_UNCLASSIFIED = "unclassified"

STAGE = "stage_2"
FILE_OUTPUT_KC_SUBCODE = "KC6.5"
_TEXT_SEARCH_ROLE = "text_search"
_MAX_BELIEFS = 5
_PURPOSE_GROUNDING_SHARE = 0.5

_IDENTIFIER_TOKEN_RE = re.compile(r"[a-z0-9]+(?:_[a-z0-9]+)+")
_WORD_RE = re.compile(r"[a-z]+")

# Classes whose constraints can always be violated through the reply action
# (spec 2.3 deterministic rule 1).
_RESPOND_RELEVANT_CLASSES = frozenset(
    {
        "disclosure",
        "wrong_information",
        "harmful_or_discriminatory_output",
        "manipulation",
    }
)


@dataclass(frozen=True)
class TargetDerivedStage2Result:
    """Named Stage 2 result for the target-derived derivation path."""

    loss_analysis: LossAnalysis
    control_structure: ControlStructure
    derived: TargetDerivedStructure
    relevance: ConstraintActionRelevance
    warnings: list[str] = field(default_factory=list)


def target_derived_stage2_mode(
    capability_profile: CapabilityProfile | None,
    execution_target_profile: ExecutionTargetProfile | None,
) -> str:
    """Return the single unified Stage 2 analysis mode.

    There is one adaptive STPA analysis. Supplying an observed profile,
    tool definitions, policies or state observations enriches that analysis;
    it never selects a different generation algorithm. This function is kept
    as the named seam so callers record the decision in one place, and it
    always reports the target-blind adaptive derivation.
    """
    return "target_blind"


class _ToolFact:
    """One observed tool flattened for deterministic structure derivation."""

    def __init__(
        self,
        *,
        tool_name: str,
        resource_id: str,
        operation_id: str,
        description: str,
        argument_names: tuple[str, ...],
        is_escalation: bool,
        is_text_search: bool,
    ) -> None:
        self.tool_name = tool_name
        self.resource_id = resource_id
        self.operation_id = operation_id
        self.description = description
        self.argument_names = argument_names
        self.is_escalation = is_escalation
        self.is_text_search = is_text_search


class _BeliefSelection(BaseModel):
    """Current provider wire: belief text and feedback are one record."""

    model_config = ConfigDict(extra="forbid")

    text: StrictStr = Field(min_length=1)
    feedback_tool: StrictStr | None = None


class _BeliefFeedbackEntry(BaseModel):
    """Historical positional belief-feedback wire, kept for decoding only."""

    model_config = ConfigDict(extra="forbid")

    belief_index: int
    tool_name: StrictStr | None = None


class _BeliefsResponse(BaseModel):
    """Provider response for the one bounded domain-beliefs call."""

    model_config = ConfigDict(extra="forbid")

    controller_purpose: StrictStr = Field(min_length=1)
    beliefs: list[_BeliefSelection] = Field(
        default_factory=list, max_length=_MAX_BELIEFS
    )


class _LegacyBeliefsResponse(BaseModel):
    """Explicit compatibility decoder for the retired positional wire."""

    model_config = ConfigDict(extra="forbid")

    controller_purpose: StrictStr = Field(min_length=1)
    beliefs: list[StrictStr] = Field(default_factory=list, max_length=_MAX_BELIEFS)
    belief_feedback: list[_BeliefFeedbackEntry] = Field(default_factory=list)


class _RelevanceActionChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: StrictStr
    reason: StrictStr = Field(min_length=1)


class _RelevanceRow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    constraint_id: StrictStr
    actions: list[_RelevanceActionChoice] = Field(default_factory=list)
    # The typed honest outcome for a constraint no supplied action can
    # violate; deterministic code accepts it only for unclassified
    # constraints and rejects it for classified ones.
    no_relevant_action_reason: StrictStr | None = Field(default=None, min_length=1)


class _UnconstrainedChoice(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: StrictStr
    reason: StrictStr = Field(min_length=1)


class _RelevanceResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relevance: list[_RelevanceRow] = Field(min_length=1)
    unconstrained_actions: list[_UnconstrainedChoice] = Field(default_factory=list)


def _flatten_tools(profile: ExecutionTargetProfile) -> list[_ToolFact]:
    """Flatten observed resources/operations into deterministic tool facts."""
    escalations = {
        item.resource_id
        for item in profile.interpretations
        if item.likely_effect.value == "escalate"
    }
    text_searches = {
        item.resource_id
        for item in profile.interpretations
        if _TEXT_SEARCH_ROLE in item.semantic_roles
    }
    facts: list[_ToolFact] = []
    for resource in profile.resources:
        tool_name = resource.tool_name or resource.resource_id
        description = resource.description or ""
        argument_names = set(resource.argument_names)
        # MCP profiles carry exactly one operation per resource; a
        # multi-operation resource derives one action per operation so no
        # observed operation is silently dropped.
        for operation in resource.operations:
            argument_names.update(operation.argument_names)
            facts.append(
                _ToolFact(
                    tool_name=tool_name,
                    resource_id=resource.resource_id,
                    operation_id=operation.operation_id,
                    description=description,
                    argument_names=tuple(sorted(argument_names)),
                    is_escalation=resource.resource_id in escalations,
                    is_text_search=resource.resource_id in text_searches,
                )
            )
    facts.sort(key=lambda item: (item.resource_id, item.operation_id))
    if not facts:
        raise ValueError("target-derived structure requires observed tool operations")
    return facts


def _deterministic_controller_description(tools: list[_ToolFact]) -> str:
    names = ", ".join(tool.tool_name for tool in tools)
    return (
        "Language-model assistant that replies to the user and can invoke "
        f"{len(tools)} observed tools: {names}."
    )


def _content_words(text: str) -> list[str]:
    from asago_scenario_generator.stpa.system_model.loss_analysis_gates import (
        _STOPWORDS,
    )

    return [
        word
        for word in _WORD_RE.findall(text.casefold())
        if len(word) >= 4 and word not in _STOPWORDS
    ]


def _purpose_grounding_share(purpose: str, use_case_text: str) -> float:
    """Return the share of the purpose's content words grounded in the use case."""
    purpose_words = _content_words(purpose)
    if not purpose_words:
        return 0.0
    use_case_words = set(_content_words(use_case_text))
    grounded = sum(1 for word in purpose_words if word in use_case_words)
    return grounded / len(purpose_words)


def _session_identity_record(
    observations: TargetObservationSnapshot | None,
    session_path: tuple[str, ...] | None = None,
) -> tuple[ProcessModelRecord, SessionSubject]:
    """Derive the session_identity process-model record from the target state.

    The record stores only the session-subject observation (correction spec
    2026-09-12, section 1.1): the observed TARGET-STATE string and its path
    under the single declared/discovered precedence rule, never an
    authorization claim.  The returned ``SessionSubject`` lets the caller
    record an ``ambiguous`` discovery as a structure warning.
    """
    decoded: Any = None
    if observations is not None:
        state = next(
            (
                item
                for item in observations.observations
                if item.observation_ref == "TARGET-STATE"
            ),
            None,
        )
        if state is not None and state.content_format == "json":
            try:
                decoded = json.loads(state.content)
            except json.JSONDecodeError:
                decoded = None
    session = resolve_session_subject(decoded, session_path)
    if session.observed:
        return (
            ProcessModelRecord(
                pm_id="PM-1-1",
                description=(
                    "Session identity: TARGET-STATE records the session "
                    f"subject string {session.value!r} at path "
                    f"{list(session.path or ())} ({session.rule} rule)."
                ),
                source="session_identity",
                observed_path=session.path,
            ),
            session,
        )
    # Spec section 1.1: state that no unique session-subject string was
    # observed and whether the rule was declared or discovered; never quote
    # an ambiguous candidate key or value.
    description = (
        "Session identity: no unique session-subject string was observed "
        f"in the supplied target state ({session.rule} rule)."
    )
    if session.status == "ambiguous":
        description += " The session subject is ambiguous."
    return (
        ProcessModelRecord(
            pm_id="PM-1-1",
            description=description,
            source="session_identity",
            observed_path=None,
        ),
        session,
    )


def _known_identifier_names(tools: list[_ToolFact]) -> set[str]:
    """Return tool and argument names a belief may legitimately name."""
    known: set[str] = set()
    for tool in tools:
        known.add(tool.tool_name)
        known.update(tool.argument_names)
    return known


def _classify_belief(text: str, known_names: set[str]) -> str | None:
    """Return a rejection reason for an unacceptable belief, else ``None``."""
    stripped = text.strip()
    if not stripped:
        return "empty belief text"
    if any(char.isdigit() for char in stripped):
        return "belief states a numeric threshold or value"
    for token in _IDENTIFIER_TOKEN_RE.findall(stripped.casefold()):
        if token not in known_names:
            return f"belief names unknown identifier {token!r}"
    return None


def _build_belief_records(
    response: _BeliefsResponse | None,
    tools: list[_ToolFact],
    next_pm_number: int,
) -> tuple[tuple[BeliefRecord, ...], int, list[str]]:
    """Compile provider beliefs into typed records with acceptance decisions.

    Only accepted beliefs consume process-model identity; rejected beliefs
    are retained as evidence without claiming a structural slot.
    """
    if response is None:
        return (
            (),
            next_pm_number,
            [
                "Beliefs call failed; the process model carries only "
                "deterministic entries."
            ],
        )
    known_names = _known_identifier_names(tools)
    tool_names = {tool.tool_name for tool in tools}
    warnings: list[str] = []
    decisions: list[tuple[str, str | None, str | None]] = []
    for selection in response.beliefs:
        feedback_tool = selection.feedback_tool
        if feedback_tool is not None and feedback_tool not in tool_names:
            warnings.append(
                f"Belief feedback names unknown tool {feedback_tool!r}; "
                "treated as unattached."
            )
            feedback_tool = None
        decisions.append(
            (
                selection.text,
                _classify_belief(selection.text, known_names),
                feedback_tool,
            )
        )
    records: list[BeliefRecord] = []
    seen: set[str] = set()
    next_number = next_pm_number
    for index, (text, reason, feedback_tool) in enumerate(decisions):
        if reason is not None:
            records.append(
                BeliefRecord(
                    pm_id=f"rejected-{index + 1}",
                    text=text,
                    accepted=False,
                    reason=reason,
                )
            )
            continue
        folded = " ".join(text.split()).casefold()
        if folded in seen:
            records.append(
                BeliefRecord(
                    pm_id=f"rejected-{index + 1}",
                    text=text,
                    accepted=False,
                    reason="duplicate of an earlier accepted belief",
                )
            )
            continue
        seen.add(folded)
        records.append(
            BeliefRecord(
                pm_id=f"PM-1-{next_number}",
                text=text,
                accepted=True,
                feedback_tool=feedback_tool,
            )
        )
        next_number += 1
    return tuple(records), next_number, warnings


def _parse_beliefs_response(result: Any) -> _BeliefsResponse:
    """Parse only the current nested provider wire."""

    payload = _decode_llm_content(result)
    if not isinstance(payload, dict):
        raise TypeError("beliefs response must be one JSON object")
    return _BeliefsResponse.model_validate(payload)


def decode_legacy_beliefs_response(
    result: Any,
    legacy_warnings: list[str] | None = None,
) -> _BeliefsResponse:
    """Decode the retired positional beliefs wire for explicit offline callers.

    The live beliefs call never invokes this adapter.  A caller handling a
    historical artifact must opt in and receives the same nested current model
    before materialization.  Duplicate indexes keep the first selection and
    are reported, while out-of-range entries are reported and unattached.
    """

    if isinstance(result, dict):
        payload = result
    else:
        payload = _decode_llm_content(result)
    if not isinstance(payload, dict):
        raise TypeError("legacy beliefs response must be one JSON object")
    legacy = _LegacyBeliefsResponse.model_validate(payload)
    feedback_by_index: dict[int, str | None] = {}
    for entry in legacy.belief_feedback:
        if entry.belief_index < 0 or entry.belief_index >= len(legacy.beliefs):
            if legacy_warnings is not None:
                legacy_warnings.append(
                    "Belief feedback names out-of-range belief index "
                    f"{entry.belief_index}; treated as unattached."
                )
            continue
        if entry.belief_index in feedback_by_index:
            if legacy_warnings is not None:
                legacy_warnings.append(
                    "Belief feedback repeats belief index "
                    f"{entry.belief_index}; kept the first selection."
                )
            continue
        feedback_by_index[entry.belief_index] = entry.tool_name
    return _BeliefsResponse.model_validate(
        {
            "controller_purpose": legacy.controller_purpose,
            "beliefs": [
                {
                    "text": text,
                    "feedback_tool": feedback_by_index.get(index),
                }
                for index, text in enumerate(legacy.beliefs)
            ],
        }
    )


def _call_beliefs(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    tools: list[_ToolFact],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
) -> tuple[_BeliefsResponse | None, list[str]]:
    """Run the one bounded beliefs call; a provider failure is nonfatal."""
    system_prompt = loader.render_prompt(
        "stage2_target_beliefs_system.j2", max_beliefs=_MAX_BELIEFS
    )
    user_prompt = loader.render_prompt(
        "stage2_target_beliefs_user.j2",
        use_case_text=use_case_text,
        tools=[
            {
                "name": tool.tool_name,
                "description": tool.description,
                "argument_names": list(tool.argument_names),
            }
            for tool in tools
        ],
        max_beliefs=_MAX_BELIEFS,
    )
    result, _, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=_BeliefsResponse,
        run_dir=run_dir,
        stage=STAGE,
        step="target_beliefs",
        temperature=temperature,
        json_decode_retries=1,
        validation_retries=1,
        validation_retry_feedback=(
            " Return one closed JSON object with fields controller_purpose "
            f"(one grounded sentence) and beliefs (at most {_MAX_BELIEFS} "
            "objects, each with text and feedback_tool or null)."
        ),
        validation_retry_include_schema=False,
        validation_retry_include_response=True,
        result_parser=_parse_beliefs_response,
    )
    if error is not None or result is None:
        return None, [f"Beliefs call failed: {error}"]
    return result, []


def _validate_relevance_response(
    response: _RelevanceResponse,
    constraint_ids: tuple[str, ...],
    action_names: tuple[str, ...],
) -> None:
    """Reject unknown identities or incomplete constraint coverage."""
    known_constraints = set(constraint_ids)
    known_actions = set(action_names)
    seen: set[str] = set()
    for row in response.relevance:
        if row.constraint_id not in known_constraints:
            raise ValueError(
                f"relevance row names unknown constraint {row.constraint_id!r}"
            )
        if row.constraint_id in seen:
            raise ValueError(f"relevance table repeats constraint {row.constraint_id}")
        seen.add(row.constraint_id)
        if not row.actions and row.no_relevant_action_reason is None:
            raise ValueError(
                f"relevance row {row.constraint_id} has an empty actions list "
                "and must either name an action or carry "
                "no_relevant_action_reason"
            )
        if row.actions and row.no_relevant_action_reason is not None:
            raise ValueError(
                f"relevance row {row.constraint_id} names actions and must "
                "not carry no_relevant_action_reason"
            )
        for choice in row.actions:
            if choice.action not in known_actions:
                raise ValueError(
                    f"relevance row {row.constraint_id} names unknown action "
                    f"{choice.action!r}"
                )
    missing = known_constraints - seen
    if missing:
        raise ValueError(
            "relevance table must cover every constraint exactly once; "
            "missing: " + ", ".join(sorted(missing))
        )
    for choice in response.unconstrained_actions:
        if choice.action not in known_actions:
            raise ValueError(
                f"unconstrained_actions names unknown action {choice.action!r}"
            )


def _relevance_call(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    action_summaries: list[dict[str, Any]],
    constraint_ids: tuple[str, ...],
    action_names: tuple[str, ...],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    failure_feedback: list[str] | None = None,
) -> tuple[_RelevanceResponse | None, str | None]:
    """Run one relevance provider attempt with closed-schema validation."""
    system_prompt = loader.render_prompt("stage2_target_relevance_system.j2")
    user_prompt = loader.render_prompt(
        "stage2_target_relevance_user.j2",
        use_case_text=use_case_text,
        constraints=[
            {
                "id": constraint.constraint_id,
                "description": constraint.description,
            }
            for constraint in loss_analysis.security_constraints
        ],
        actions=action_summaries,
    )
    if failure_feedback:
        user_prompt += (
            "\n\nThe prior relevance response failed deterministic "
            "validation and is not reproduced here. Return a complete "
            "replacement table (every constraint, every row) that resolves "
            "exactly these defects while keeping all other rows valid: "
            + "; ".join(failure_feedback)
            + "\n\nEvery constraint must either name at least one supplied "
            "action that could violate it, or carry an empty `actions` list "
            "with a `no_relevant_action_reason` explaining why no supplied "
            "action applies. Do not invent a violating action."
        )
    result, _, error = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=_RelevanceResponse,
        run_dir=run_dir,
        stage=STAGE,
        step="target_relevance",
        temperature=temperature,
        json_decode_retries=1,
        validation_retries=0,
        result_validator=lambda value: _validate_relevance_response(
            value, constraint_ids, action_names
        ),
    )
    if error is not None or result is None:
        return None, error or "relevance provider returned no result"
    return result, None


def _augment_relevance(
    response: _RelevanceResponse,
    loss_analysis: LossAnalysis,
    tools: list[_ToolFact],
    action_kinds: dict[str, str],
    warnings_out: list[str],
) -> tuple[list[ConstraintRelevanceRow], list[UnconstrainedAction]]:
    """Apply the deterministic spec-2.3 post-rules to the provider table."""
    table = load_behavior_classes()
    escalation_tools = [tool.tool_name for tool in tools if tool.is_escalation]
    rows_by_constraint: dict[str, dict[str, RelevantAction]] = {}
    reasons_by_constraint: dict[str, str] = {}
    model_supplied: set[str] = set()
    for row in response.relevance:
        rows_by_constraint[row.constraint_id] = {
            choice.action: RelevantAction(
                action=choice.action, reason=choice.reason, origin="model"
            )
            for choice in row.actions
        }
        if row.actions:
            model_supplied.add(row.constraint_id)
        if row.no_relevant_action_reason is not None:
            reasons_by_constraint[row.constraint_id] = row.no_relevant_action_reason
    for constraint in loss_analysis.security_constraints:
        merged = rows_by_constraint.setdefault(constraint.constraint_id, {})
        behavior_class = classify_constraint(constraint.description, table)
        if behavior_class in _RESPOND_RELEVANT_CLASSES and "respond" not in merged:
            merged["respond"] = RelevantAction(
                action="respond",
                reason=(
                    f"the reply action can violate a {behavior_class} constraint "
                    "directly in its response text"
                ),
                origin="rule",
            )
        if behavior_class == "missed_escalation":
            for tool_name in escalation_tools:
                if tool_name not in merged:
                    merged[tool_name] = RelevantAction(
                        action=tool_name,
                        reason=(
                            "the escalation tool can satisfy a "
                            "missed_escalation constraint"
                        ),
                        origin="rule",
                    )
    for constraint in loss_analysis.security_constraints:
        # A post-rule may fill a row the model asserted empty with a typed
        # reason.  Keep the model's reason as recorded evidence instead of
        # discarding it silently; the row itself is filled by the rule.
        if (
            constraint.constraint_id in reasons_by_constraint
            and constraint.constraint_id not in model_supplied
            and rows_by_constraint.get(constraint.constraint_id)
        ):
            warnings_out.append(
                f"relevance post-rule added actions to the typed empty row "
                f"for {constraint.constraint_id}; the model's "
                f"no_relevant_action_reason was superseded: "
                f"{reasons_by_constraint[constraint.constraint_id]}"
            )
    rows = []
    for constraint in loss_analysis.security_constraints:
        actions = tuple(
            sorted(
                rows_by_constraint.get(constraint.constraint_id, {}).values(),
                key=lambda item: item.action,
            )
        )
        rows.append(
            ConstraintRelevanceRow(
                constraint_id=constraint.constraint_id,
                actions=actions,
                # A reason is only meaningful for an empty row; the closed
                # model rejects the combination with actions.
                no_relevant_action_reason=(
                    reasons_by_constraint.get(constraint.constraint_id)
                    if not actions
                    else None
                ),
            )
        )
    constrained_actions = {item.action for row in rows for item in row.actions}
    declared_unconstrained = {
        choice.action: choice.reason for choice in response.unconstrained_actions
    }
    unconstrained: list[UnconstrainedAction] = []
    for action_name in sorted(action_kinds):
        if action_name in constrained_actions:
            continue
        reason = declared_unconstrained.get(action_name)
        if reason is None:
            reason = (
                "no supplied security constraint names a violation through this action"
            )
        unconstrained.append(UnconstrainedAction(action=action_name, reason=reason))
    return rows, unconstrained


def _relevance_defects(
    rows: list[ConstraintRelevanceRow],
    loss_analysis: LossAnalysis,
    tools: list[_ToolFact],
    action_kinds: dict[str, str],
) -> list[str]:
    """Return the failing deterministic spec-2.3 rules, if any."""
    defects: list[str] = []
    rows_by_id = {row.constraint_id: row for row in rows}
    table = load_behavior_classes()
    escalation_tools = [tool.tool_name for tool in tools if tool.is_escalation]
    for constraint in loss_analysis.security_constraints:
        row = rows_by_id.get(constraint.constraint_id)
        if row is None or (not row.actions and row.no_relevant_action_reason is None):
            defects.append(
                f"{constraint.constraint_id} has no relevant action; every "
                "constraint must name at least one action"
            )
            continue
        if not row.actions:
            # Typed honest outcome: the model asserts no supplied action can
            # violate this constraint.  Accepted only for unclassified
            # constraints; a classified constraint has post-rules that must
            # be able to name an action.
            if classify_constraint(constraint.description, table) != _UNCLASSIFIED:
                defects.append(
                    f"{constraint.constraint_id} is a classified constraint "
                    "and must name at least one action"
                )
            continue
        behavior_class = classify_constraint(constraint.description, table)
        if behavior_class == "unauthorized_write" and not any(
            action_kinds.get(item.action) == "tool_call" for item in row.actions
        ):
            defects.append(
                f"{constraint.constraint_id} is an unauthorized_write "
                "constraint and must name at least one tool_call action"
            )
        if behavior_class == "missed_escalation" and escalation_tools:
            if not any(item.action in escalation_tools for item in row.actions):
                defects.append(
                    f"{constraint.constraint_id} is a missed_escalation "
                    "constraint and must name the escalation tool "
                    f"{', '.join(escalation_tools)}"
                )
    return defects


def _build_relevance(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    tools: list[_ToolFact],
    action_kinds: dict[str, str],
    action_summaries: list[dict[str, Any]],
    control_structure_digest: str,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    warnings: list[str],
) -> tuple[ConstraintActionRelevance, int]:
    """Run the relevance call, post-rules, and one bounded repair retry."""
    constraint_ids = tuple(
        constraint.constraint_id for constraint in loss_analysis.security_constraints
    )
    action_names = tuple(sorted(action_kinds))
    call_kwargs: dict[str, Any] = dict(
        llm_client=llm_client,
        use_case_text=use_case_text,
        loss_analysis=loss_analysis,
        action_summaries=action_summaries,
        constraint_ids=constraint_ids,
        action_names=action_names,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )
    call_count = 0
    # _relevance_call collapses any provider failure to a None response with
    # the exact error text, so a None response is the only failure signal.
    response, error = _relevance_call(**call_kwargs)
    call_count += 1
    failures: list[str] | None = None
    if response is None:
        failures = [error or "relevance provider returned no result"]
    else:
        rows, unconstrained = _augment_relevance(
            response, loss_analysis, tools, action_kinds, warnings
        )
        defects = _relevance_defects(rows, loss_analysis, tools, action_kinds)
        if defects:
            failures = defects
    if failures is not None:
        # One bounded revision attempt carrying the exact failing rules or
        # schema defects; a second failure is a fatal stage error (Phase 1
        # convention).
        warnings.append(
            "Relevance response failed deterministic checks; requesting one "
            f"bounded revision: {'; '.join(failures)}"
        )
        revised, revision_error = _relevance_call(
            **call_kwargs, failure_feedback=failures
        )
        call_count += 1
        if revision_error is not None:
            raise StageError(
                stage=STAGE,
                step="target_relevance",
                message="target-derived relevance failed twice: "
                + (revision_error or "relevance provider returned no result"),
            )
        rows, unconstrained = _augment_relevance(
            revised, loss_analysis, tools, action_kinds, warnings
        )
        defects = _relevance_defects(rows, loss_analysis, tools, action_kinds)
        if defects:
            raise StageError(
                stage=STAGE,
                step="target_relevance",
                message="relevance table failed deterministic rules twice: "
                + "; ".join(defects),
            )
    relevance = ConstraintActionRelevance(
        loss_analysis_digest=loss_analysis_content_digest(loss_analysis),
        control_structure_digest=control_structure_digest,
        relevance=tuple(rows),
        unconstrained_actions=tuple(unconstrained),
        model_call_count=call_count,
    )
    return relevance, call_count


def derive_target_structure(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis,
    capability_profile: CapabilityProfile,
    execution_target_profile: ExecutionTargetProfile,
    target_observations: TargetObservationSnapshot | None = None,
    reviewed_obligation_bindings: tuple[ReviewedObligationBinding, ...] = (),
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = 0.4,
    target_subject_model: TargetSubjectModel | None = None,
) -> TargetDerivedStage2Result:
    """Derive the Stage 2 control structure from the observed target.

    Spec 2.1 through 2.3.  Steps 1-5 (controller, actions, conditional
    actions, controlled processes, deterministic process model) need no model
    call; the beliefs call and the relevance call are each bounded provider
    attempts with deterministic validation.

    ``target_subject_model`` is the accepted subject-model companion when
    one rides with the run (correction spec 2026-09-12): its declared
    ``session_path`` drives the session-subject rule, and its content
    digest plus reviewer stamps are recorded on the sidecar.
    """
    if target_subject_model is not None:
        if target_observations is None:
            raise SubjectModelError(
                "subject_model_invalid",
                "an accepted target subject model requires paired target "
                "observations and an execution target profile",
            )
        verify_target_subject_model(
            target_subject_model,
            observations=target_observations,
            profile=execution_target_profile,
        )
    session_path = (
        target_subject_model.session_path if target_subject_model is not None else None
    )
    loader = template_loader or TemplateLoader(PROMPTS_DIR)
    warnings: list[str] = []
    tools = _flatten_tools(execution_target_profile)

    # Deterministic controller purpose; replaced by the grounded provider
    # sentence when the beliefs call supplies one.
    controller = ControllerPurpose(
        description=_deterministic_controller_description(tools),
        source="deterministic_fallback",
        evidence=None,
    )

    # --- Controlled processes: one per tool, conditionals, then interface.
    processes: list[ControlledProcess] = []
    process_records: list[ProcessModelRecord] = []
    tool_cp_by_tool: dict[str, str] = {}
    for index, tool in enumerate(tools, start=1):
        cp_id = f"CP-{index}"
        processes.append(
            ControlledProcess(
                cp_id=cp_id,
                description=(
                    f"System behind tool {tool.tool_name}: {tool.description}".strip()
                ),
            )
        )
        tool_cp_by_tool[tool.tool_name] = cp_id
    next_cp = len(tools) + 1
    conditional_actions: list[tuple[str, str, str, ControlActionEffectKind]] = []
    if capability_profile.has_persistent_memory:
        cp_id = f"CP-{next_cp}"
        next_cp += 1
        processes.append(
            ControlledProcess(
                cp_id=cp_id,
                description="Persistent memory store behind the assistant.",
            )
        )
        conditional_actions.append(
            (
                "memory_write",
                "Write to persistent memory between sessions.",
                "capability profile has_persistent_memory "
                f"(kc_subcodes={sorted(capability_profile.kc_subcodes)})",
                ControlActionEffectKind.state_change,
            )
        )
    if FILE_OUTPUT_KC_SUBCODE in capability_profile.kc_subcodes:
        cp_id = f"CP-{next_cp}"
        next_cp += 1
        processes.append(
            ControlledProcess(
                cp_id=cp_id,
                description="File output destination behind the assistant.",
            )
        )
        conditional_actions.append(
            (
                "file_output",
                "Produce a file output for the caller.",
                f"capability profile declares {FILE_OUTPUT_KC_SUBCODE} "
                "(PC / filesystem operations)",
                ControlActionEffectKind.environment_action,
            )
        )
    interface_cp = f"CP-{next_cp}"
    processes.append(
        ControlledProcess(
            cp_id=interface_cp,
            description=(
                "Customer-facing conversation interface presented to the user."
            ),
        )
    )

    # --- Control actions: one per tool operation, conditionals, then respond.
    actions: list[ControlAction] = []
    bindings: list[ActionBinding] = []
    action_kinds: dict[str, str] = {}
    action_description_by_ca: dict[str, str] = {}
    for index, tool in enumerate(tools, start=1):
        ca_id = f"CA-1-{index}"
        description = f"{tool.tool_name}: {tool.description}".strip()
        actions.append(
            ControlAction(
                ca_id=ca_id,
                description=description,
                target=ElementRef(
                    type=ReferenceType.controlled_process,
                    id=tool_cp_by_tool[tool.tool_name],
                ),
                effect_kind=ControlActionEffectKind.tool_call,
                temporality=ControlActionTemporality.discrete,
            )
        )
        bindings.append(
            ActionBinding(
                ca_id=ca_id,
                name=tool.tool_name,
                kind="tool_call",
                resource_id=tool.resource_id,
                operation_id=tool.operation_id,
                argument_names=tuple(sorted(tool.argument_names)),
                justification=(
                    "observed target profile operation "
                    f"{tool.resource_id}/{tool.operation_id}"
                ),
            )
        )
        action_kinds[tool.tool_name] = "tool_call"
        action_description_by_ca[ca_id] = description
    next_ca = len(tools) + 1
    for name, description, justification, kind in conditional_actions:
        ca_id = f"CA-1-{next_ca}"
        next_ca += 1
        # Each conditional action's process was appended immediately before
        # this loop, so the last process is its target.
        actions.append(
            ControlAction(
                ca_id=ca_id,
                description=description,
                target=ElementRef(
                    type=ReferenceType.controlled_process, id=processes[-1].cp_id
                ),
                effect_kind=kind,
                temporality=ControlActionTemporality.discrete,
            )
        )
        bindings.append(
            ActionBinding(
                ca_id=ca_id,
                name=name,
                kind=str(kind.value),
                justification=justification,
            )
        )
        action_kinds[name] = str(kind.value)
        action_description_by_ca[ca_id] = description
    respond_ca = f"CA-1-{next_ca}"
    respond_description = (
        "Reply to the user with a model-authored message. Every "
        "language-model agent has this action."
    )
    actions.append(
        ControlAction(
            ca_id=respond_ca,
            description=respond_description,
            target=ElementRef(type=ReferenceType.controlled_process, id=interface_cp),
            effect_kind=ControlActionEffectKind.model_output,
            temporality=ControlActionTemporality.instantaneous,
        )
    )
    bindings.append(
        ActionBinding(
            ca_id=respond_ca,
            name="respond",
            kind="model_output",
            justification="every language-model agent can reply to the user",
        )
    )
    action_kinds["respond"] = "model_output"
    action_description_by_ca[respond_ca] = respond_description

    # --- Deterministic process model (spec 2.2).
    session_record, session = _session_identity_record(
        target_observations, session_path
    )
    process_records.append(session_record)
    if session.status == "ambiguous":
        warnings.append(
            "Session subject discovery is ambiguous: TARGET-STATE carries "
            "multiple authenticated_*_id keys "
            f"({', '.join(session.candidates)}); no session subject is "
            "recorded."
        )
    process_records.append(
        ProcessModelRecord(
            pm_id="PM-1-2",
            description=(
                "Conversation history: the user and assistant messages of the "
                "current session."
            ),
            source="conversation_history",
        )
    )
    text_search_tools = [tool for tool in tools if tool.is_text_search]
    if text_search_tools:
        process_records.append(
            ProcessModelRecord(
                pm_id="PM-1-3",
                description=(
                    "Retrieved policy: text returned by the "
                    f"{', '.join(tool.tool_name for tool in text_search_tools)} "
                    "tool."
                ),
                source="retrieved_policy",
            )
        )
    tool_result_pm: dict[str, str] = {}
    next_pm = len(process_records) + 1
    for tool in tools:
        pm_id = f"PM-1-{next_pm}"
        next_pm += 1
        tool_result_pm[tool.tool_name] = pm_id
        process_records.append(
            ProcessModelRecord(
                pm_id=pm_id,
                description=(
                    f"Result of the {tool.tool_name} tool, updated by that "
                    "tool's feedback."
                ),
                source="tool_result",
            )
        )

    # --- Beliefs call (one bounded attempt; failure is nonfatal).
    beliefs_response, belief_warnings = _call_beliefs(
        llm_client=llm_client,
        use_case_text=use_case_text,
        tools=tools,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
    )
    warnings.extend(belief_warnings)
    belief_records, next_pm, belief_compile_warnings = _build_belief_records(
        beliefs_response, tools, next_pm
    )
    warnings.extend(belief_compile_warnings)
    process_records.extend(
        ProcessModelRecord(
            pm_id=record.pm_id,
            description=f"Assistant belief: {record.text}",
            source="belief",
        )
        for record in belief_records
        if record.accepted
    )

    # Grounded purpose replaces the deterministic fallback only when it
    # grounds in the use case.
    if beliefs_response is not None:
        share = _purpose_grounding_share(
            beliefs_response.controller_purpose, use_case_text
        )
        if share >= _PURPOSE_GROUNDING_SHARE:
            controller = ControllerPurpose(
                description=beliefs_response.controller_purpose,
                source="grounded_model",
                evidence=f"{share:.0%} of content words grounded in the use case",
            )
        else:
            warnings.append(
                "Provider controller purpose was not grounded in the use "
                f"case ({share:.0%} content-word overlap); retained the "
                "deterministic summary."
            )

    # --- Feedback channels.
    feedback: list[FeedbackChannel] = []
    fb_number = 1
    feedback.append(
        FeedbackChannel(
            fb_id=f"FB-1-{fb_number}",
            description=(
                "Session establishment updates the session identity from the "
                "authenticated session token."
            ),
            updates="PM-1-1",
            source=ElementRef(type=ReferenceType.controlled_process, id=interface_cp),
        )
    )
    fb_number += 1
    feedback.append(
        FeedbackChannel(
            fb_id=f"FB-1-{fb_number}",
            description="Each user message updates the conversation history.",
            updates="PM-1-2",
            source=ElementRef(type=ReferenceType.controlled_process, id=interface_cp),
        )
    )
    fb_number += 1
    if text_search_tools:
        feedback.append(
            FeedbackChannel(
                fb_id=f"FB-1-{fb_number}",
                description=(
                    "The "
                    f"{', '.join(tool.tool_name for tool in text_search_tools)} "
                    "result updates retrieved policy."
                ),
                updates="PM-1-3",
                source=ElementRef(
                    type=ReferenceType.controlled_process,
                    id=tool_cp_by_tool[text_search_tools[0].tool_name],
                ),
            )
        )
        fb_number += 1
    for tool in tools:
        feedback.append(
            FeedbackChannel(
                fb_id=f"FB-1-{fb_number}",
                description=(
                    f"The {tool.tool_name} result updates its tool_result "
                    "process-model entry."
                ),
                updates=tool_result_pm[tool.tool_name],
                source=ElementRef(
                    type=ReferenceType.controlled_process,
                    id=tool_cp_by_tool[tool.tool_name],
                ),
            )
        )
        fb_number += 1
    for record in belief_records:
        if not record.accepted:
            continue
        source_cp = (
            tool_cp_by_tool[record.feedback_tool]
            if record.feedback_tool is not None
            else interface_cp
        )
        source_label = (
            f"the {record.feedback_tool} result"
            if record.feedback_tool is not None
            else "the user conversation"
        )
        feedback.append(
            FeedbackChannel(
                fb_id=f"FB-1-{fb_number}",
                description=(
                    f"Feedback from {source_label} updates the assistant "
                    f"belief {record.pm_id}."
                ),
                updates=record.pm_id,
                source=ElementRef(type=ReferenceType.controlled_process, id=source_cp),
            )
        )
        fb_number += 1

    # --- The single ASSISTANT controller.
    responsibility = Responsibility(
        resp_id="RESP-1",
        description=controller.description,
        responsibility_constraints=[
            ResponsibilityConstraint(
                rc_id=f"RC-1-{index}",
                description=constraint.description,
            )
            for index, constraint in enumerate(
                loss_analysis.security_constraints, start=1
            )
        ],
        security_constraint_refs=[
            constraint.constraint_id
            for constraint in loss_analysis.security_constraints
        ],
        process_model_parts=[
            ProcessModelPart(pm_id=record.pm_id, description=record.description)
            for record in process_records
        ],
        control_actions=actions,
        feedback_channels=feedback,
    )
    control_structure = ControlStructure(
        responsibilities=[responsibility],
        controlled_processes=processes,
        coordination_links=[],
    )
    structure_digest = control_structure_content_digest(control_structure)

    # --- Relevance call (spec 2.3).
    action_summaries = [
        {
            "name": binding.name,
            "kind": binding.kind,
            "description": action_description_by_ca[binding.ca_id],
        }
        for binding in bindings
    ]
    relevance, relevance_call_count = _build_relevance(
        llm_client=llm_client,
        use_case_text=use_case_text,
        loss_analysis=loss_analysis,
        tools=tools,
        action_kinds=action_kinds,
        action_summaries=action_summaries,
        control_structure_digest=structure_digest,
        run_dir=run_dir,
        loader=loader,
        temperature=temperature,
        warnings=warnings,
    )

    # Reviewed obligation bindings are reviewed inputs, not derived content:
    # validate them offline against the loss analysis and the derived
    # actions, then embed them so the sidecar digest pins the exact set in
    # force for this run.
    validate_reviewed_obligation_bindings(
        reviewed_obligation_bindings, loss_analysis, tuple(bindings)
    )
    # The accepted subject model's stamps ride on the sidecar (correction
    # spec section 4.4); a model without a reviewed acceptance envelope
    # stamps nothing, so a digest is never recorded as accepted without
    # the reviewer stamps.
    acceptance = (
        target_subject_model.acceptance
        if target_subject_model is not None
        and target_subject_model.acceptance is not None
        and target_subject_model.acceptance.reviewed
        else None
    )
    derived = TargetDerivedStructure(
        target_id=execution_target_profile.target_id,
        profile_digest=execution_target_profile.semantic_digest,
        control_structure_digest=structure_digest,
        controller=controller,
        actions=tuple(bindings),
        process_model=tuple(process_records),
        beliefs=belief_records,
        # The beliefs call is always attempted; the relevance call reports
        # its own attempt count including any bounded revision.
        model_call_count=1 + relevance_call_count,
        warnings=tuple(warnings),
        reviewed_obligation_bindings=reviewed_obligation_bindings,
        target_subject_model_digest=(
            target_subject_model.compute_content_digest()
            if acceptance is not None
            else None
        ),
        target_subject_model_reviewed_by=(
            acceptance.reviewed_by if acceptance is not None else None
        ),
        target_subject_model_reviewed_on=(
            acceptance.reviewed_on if acceptance is not None else None
        ),
    )

    # Persist exactly the artifacts the target-blind path would publish.
    write_yaml(loss_analysis, run_dir / "loss-analysis.yaml")
    write_yaml(control_structure, run_dir / "control-structure.yaml")
    write_yaml(derived, run_dir / TARGET_DERIVED_STRUCTURE_FILENAME)
    write_yaml(relevance, run_dir / CONSTRAINT_ACTION_RELEVANCE_FILENAME)

    return TargetDerivedStage2Result(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        derived=derived,
        relevance=relevance,
        warnings=warnings,
    )


__all__ = [
    "TargetDerivedStage2Result",
    "derive_target_structure",
    "target_derived_stage2_mode",
]
