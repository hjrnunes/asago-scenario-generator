"""Risk-card scope classification before Stage 1a.

A bounded classification applies the STPA boundary test to the risk class of
every card: can this system's own actions (its replies, its tool calls, or the
data it stores or retrieves) produce harm of this class to someone?  Yes or
partly makes the card ``actionable``; otherwise it is ``outside_boundary`` or
``not_applicable``.

The request shows the class (id, name, taxonomy, and the class description)
and the system's own context, but not the card's threat and consequence.
Policies often tell a class through one organizational story, such as staff
pasting data into an external tool, and a model shown that story judges the
story instead of the class.  The story is kept as provenance in the record
only.  An actionable reply names the system action and the affected
stakeholder, so the decision rests on a concrete action; a reply that
contradicts its own fields goes to the retry.

Scope is recorded, not used as a filter: every card reaches loss derivation,
and obligation accounting carries each card's scope.  Wrongly including a
card costs some analysis effort, while wrongly excluding one removes it from
the loss analysis, so the classification leans toward ``actionable``.

Every card receives a decision and reason in ``risk-actionability.yaml``.  A
card the model leaves unclassified after one retry stays actionable with a
warning, so a provider omission never hides a card.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    is_provider_failure,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.system_model.target_evidence import (
    TargetEvidence,
)

STAGE = "stage_1a"
STEP = "risk_actionability"
STEP_RETRY = "risk_actionability_retry"
SYSTEM_TEMPLATE = "stage1a_actionability_system.j2"
USER_TEMPLATE = "stage1a_actionability_user.j2"
ARTIFACT_FILENAME = "risk-actionability.yaml"
# v2 entries meet the decision/field invariant (see RiskActionabilityRecord);
# v1 records predate the action fields and still load.
SCHEMA_VERSION = "risk-actionability-v2"
MAX_CARDS_PER_CALL = 40
MAX_COMPLETION_TOKENS = 8192


class ActionabilityDecision(str, Enum):
    """Outcome of the STPA boundary test for one risk card."""

    actionable = "actionable"
    outside_boundary = "outside_boundary"
    not_applicable = "not_applicable"


class RiskActionabilityDecision(BaseModel):
    """One risk's decision. system_action and affected_stakeholder are text for
    an actionable decision and null for the other decisions."""

    model_config = ConfigDict(extra="forbid")

    risk_id: str = Field(min_length=1)
    system_action: str | None
    affected_stakeholder: str | None
    decision: ActionabilityDecision
    reason: str = Field(min_length=1)


class RiskActionabilityResponse(BaseModel):
    """Provider wire shape: one decision per requested card."""

    model_config = ConfigDict(extra="forbid")

    decisions: list[RiskActionabilityDecision]


class RiskActionabilityEntry(BaseModel):
    """One card's recorded decision.

    ``source`` says who decided.  ``model`` is a decision the model returned.
    ``fallback`` marks a card the model left unclassified after the retry: its
    ``actionable`` decision is the default that keeps the card in scope, not a
    judgement, so it names no system action or stakeholder.
    """

    model_config = ConfigDict(extra="forbid")

    risk_id: str
    decision: ActionabilityDecision
    reason: str
    source: Literal["model", "fallback"]
    system_action: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    affected_stakeholder: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    # The card's own threat and consequence: provenance only, never shown to
    # the classification.
    stated_threat: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    stated_consequence: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )


class RiskActionabilityRecord(BaseModel):
    """Persisted classification of every supplied risk card."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["risk-actionability-v1", "risk-actionability-v2"] = (
        SCHEMA_VERSION
    )
    status: Literal["completed", "partial", "empty"]
    call_count: int = Field(ge=0)
    counts: dict[str, int]
    entries: list[RiskActionabilityEntry]
    warnings: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def entries_meet_the_field_invariant(self) -> "RiskActionabilityRecord":
        """Check every v2 entry's decision against its action fields."""
        if self.schema_version == SCHEMA_VERSION:
            for entry in self.entries:
                problem = _entry_problem(entry)
                if problem is not None:
                    raise ValueError(f"entry '{entry.risk_id}': {problem}")
        return self


@dataclass
class RiskActionabilityOutcome:
    """Classification result: the persisted record of every card's scope."""

    record: RiskActionabilityRecord


def classify_risk_actionability(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: Sequence[RiskCard],
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    target_evidence: TargetEvidence | None = None,
) -> RiskActionabilityOutcome:
    """Classify every card's scope and persist the record.

    Cards are sent in batches of at most :data:`MAX_CARDS_PER_CALL`.  A batch
    whose reply fails or omits cards receives one retry for its missing cards;
    a provider or transport failure receives none.  Cards still missing stay
    actionable (``source: fallback``).  The call never raises: a failed call
    is recorded as a warning.
    """
    cards = list(risk_cards)
    if not cards:
        record = _record([], call_count=0, warnings=[])
        write_yaml(record, run_dir / ARTIFACT_FILENAME)
        return RiskActionabilityOutcome(record=record)

    system_prompt = template_loader.render_prompt(SYSTEM_TEMPLATE)
    decided: dict[str, RiskActionabilityDecision] = {}
    warnings: list[str] = []
    call_count = 0
    for start in range(0, len(cards), MAX_CARDS_PER_CALL):
        call_count += _classify_with_retry(
            cards[start : start + MAX_CARDS_PER_CALL],
            decided=decided,
            warnings=warnings,
            llm_client=llm_client,
            system_prompt=system_prompt,
            use_case_text=use_case_text,
            target_evidence=target_evidence,
            template_loader=template_loader,
            run_dir=run_dir,
            temperature=temperature,
        )

    entries = _actionability_entries(cards, decided, warnings)
    record = _record(entries, call_count=call_count, warnings=warnings)
    write_yaml(record, run_dir / ARTIFACT_FILENAME)
    return RiskActionabilityOutcome(record=record)


def _classify_with_retry(
    batch: Sequence[RiskCard],
    *,
    decided: dict[str, RiskActionabilityDecision],
    warnings: list[str],
    llm_client: LLMClient,
    system_prompt: str,
    use_case_text: str,
    target_evidence: TargetEvidence | None,
    template_loader: TemplateLoader,
    run_dir: Path,
    temperature: float,
) -> int:
    """Classify *batch*, retrying its missing cards once.

    A provider or transport failure ends the batch without the retry: the
    client already made the one retry such a failure earns.  Return the
    number of requests sent, JSON-decode retries included and requests the
    prompt preflight blocked excluded.
    """
    call_count = 0
    for step in (STEP, STEP_RETRY):
        pending = [card for card in batch if card.risk_id not in decided]
        if not pending:
            break
        decisions, error, sent, provider_failed = _classify_batch(
            llm_client=llm_client,
            system_prompt=system_prompt,
            user_prompt=template_loader.render_prompt(
                USER_TEMPLATE,
                use_case_text=use_case_text,
                target_evidence=target_evidence,
                risk_cards=pending,
            ),
            run_dir=run_dir,
            temperature=temperature,
            step=step,
        )
        call_count += sent
        if error is not None:
            warnings.append(f"{step}: {error}")
            if provider_failed:
                break
            continue
        _accept_requested_decisions(
            decisions, pending, decided=decided, warnings=warnings, step=step
        )
    return call_count


def _accept_requested_decisions(
    decisions: Sequence[RiskActionabilityDecision],
    pending: Sequence[RiskCard],
    *,
    decided: dict[str, RiskActionabilityDecision],
    warnings: list[str],
    step: str,
) -> None:
    """Record the first consistent decision for each requested card.

    A decision for an unrequested card, or one whose action fields contradict
    it, is left out with a warning; its card stays pending for the retry.
    """
    expected = {card.risk_id for card in pending}
    for item in decisions:
        if item.risk_id not in expected:
            warnings.append(
                f"{step}: ignored decision for unrequested card '{item.risk_id}'"
            )
            continue
        problem = _decision_problem(item)
        if problem is not None:
            warnings.append(
                f"{step}: rejected decision for '{item.risk_id}': {problem}"
            )
            continue
        decided.setdefault(item.risk_id, item)


def _decision_problem(
    item: RiskActionabilityDecision | RiskActionabilityEntry,
) -> str | None:
    """Name the contradiction between a decision and its action fields."""
    named = [
        bool((value or "").strip())
        for value in (item.system_action, item.affected_stakeholder)
    ]
    if item.decision is ActionabilityDecision.actionable:
        if not all(named):
            return "an actionable decision names no system action or stakeholder"
        return None
    if any(named):
        return (
            f"the {item.decision.value} decision names a system action or stakeholder"
        )
    return None


def _entry_problem(entry: RiskActionabilityEntry) -> str | None:
    """Name what breaks the field invariant of one recorded entry.

    A model entry meets the reply invariant.  A fallback entry is the
    in-scope default: ``actionable`` with no action fields.
    """
    if entry.source == "model":
        return _decision_problem(entry)
    if entry.decision is not ActionabilityDecision.actionable:
        return "a fallback entry keeps the card actionable"
    if entry.system_action is not None or entry.affected_stakeholder is not None:
        return "a fallback entry names no system action or stakeholder"
    return None


def _actionability_entries(
    cards: Sequence[RiskCard],
    decided: dict[str, RiskActionabilityDecision],
    warnings: list[str],
) -> list[RiskActionabilityEntry]:
    """Build one entry per card, keeping unclassified cards actionable."""
    entries: list[RiskActionabilityEntry] = []
    for card in cards:
        provenance = {
            "stated_threat": card.threat,
            "stated_consequence": card.consequence,
        }
        item = decided.get(card.risk_id)
        if item is None:
            warnings.append(
                f"'{card.risk_id}' was not classified after one retry; kept "
                "as actionable"
            )
            entries.append(
                RiskActionabilityEntry(
                    risk_id=card.risk_id,
                    decision=ActionabilityDecision.actionable,
                    reason=(
                        "Not classified by the model after one retry; kept in "
                        "scope by default."
                    ),
                    source="fallback",
                    **provenance,
                )
            )
        else:
            entries.append(
                RiskActionabilityEntry(
                    risk_id=card.risk_id,
                    decision=item.decision,
                    reason=item.reason.strip(),
                    source="model",
                    system_action=_stripped(item.system_action),
                    affected_stakeholder=_stripped(item.affected_stakeholder),
                    **provenance,
                )
            )
    return entries


def _stripped(value: str | None) -> str | None:
    """Return *value* without surrounding whitespace, or None when blank."""
    text = (value or "").strip()
    return text or None


def _classify_batch(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    temperature: float,
    step: str,
) -> tuple[list[RiskActionabilityDecision], str | None, int, bool]:
    """Return the decisions, the error, the number of requests sent, and
    whether the call ended in a provider or transport failure."""
    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=RiskActionabilityResponse,
        run_dir=run_dir,
        stage=STAGE,
        step=step,
        policy=CorrectionPolicy(json_retries=1),
        temperature=temperature,
        max_completion_tokens=MAX_COMPLETION_TOKENS,
    )
    if outcome.error is not None or outcome.value is None:
        return (
            [],
            outcome.error or "no response",
            outcome.calls,
            is_provider_failure(outcome.failure),
        )
    return list(outcome.value.decisions), None, outcome.calls, False


def _record(
    entries: list[RiskActionabilityEntry],
    *,
    call_count: int,
    warnings: list[str],
) -> RiskActionabilityRecord:
    counts = {decision.value: 0 for decision in ActionabilityDecision}
    for entry in entries:
        counts[entry.decision.value] += 1
    counts["fallback"] = sum(1 for entry in entries if entry.source == "fallback")
    if not entries:
        status: Literal["completed", "partial", "empty"] = "empty"
    elif counts["fallback"]:
        status = "partial"
    else:
        status = "completed"
    return RiskActionabilityRecord(
        status=status,
        call_count=call_count,
        counts=counts,
        entries=entries,
        warnings=warnings,
    )


__all__ = [
    "ARTIFACT_FILENAME",
    "ActionabilityDecision",
    "RiskActionabilityEntry",
    "RiskActionabilityOutcome",
    "RiskActionabilityRecord",
    "RiskActionabilityResponse",
    "classify_risk_actionability",
]
