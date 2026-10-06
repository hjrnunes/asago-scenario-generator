"""Risk-card actionability classification before Stage 1a.

Owner decision (2026-09-29 STPA review, recommendation 8): risk cards stay
the only input for losses, but only actionable cards feed loss derivation.
A bounded classification applies the STPA boundary test to every card: can a
controller inside the analysis boundary realize the card's threat through a
control action it takes or omits, with a consequence that reaches a
stakeholder of this system?

Every card receives a decision and reason in ``risk-actionability.yaml``.
Together with the Stage 1a risk dispositions (which cover the actionable
cards) that record accounts for every supplied card.  A card the model
leaves unclassified after one retry stays actionable with a warning, so a
provider omission never silently removes coverage.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
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
SCHEMA_VERSION = "risk-actionability-v1"
MAX_CARDS_PER_CALL = 40
MAX_COMPLETION_TOKENS = 8192


class ActionabilityDecision(str, Enum):
    """Outcome of the STPA boundary test for one risk card."""

    actionable = "actionable"
    outside_boundary = "outside_boundary"
    not_applicable = "not_applicable"


class RiskActionabilityDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    risk_id: str = Field(min_length=1)
    decision: ActionabilityDecision
    reason: str = Field(min_length=1)


class RiskActionabilityResponse(BaseModel):
    """Provider wire shape: one decision per requested card."""

    model_config = ConfigDict(extra="forbid")

    decisions: list[RiskActionabilityDecision]


class RiskActionabilityEntry(BaseModel):
    """One card's recorded decision."""

    model_config = ConfigDict(extra="forbid")

    risk_id: str
    decision: ActionabilityDecision
    reason: str
    source: Literal["model", "fallback"]


class RiskActionabilityRecord(BaseModel):
    """Persisted classification of every supplied risk card."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["risk-actionability-v1"] = SCHEMA_VERSION
    status: Literal["completed", "partial", "empty"]
    call_count: int = Field(ge=0)
    counts: dict[str, int]
    entries: list[RiskActionabilityEntry]
    warnings: list[str] = Field(default_factory=list)


@dataclass
class RiskActionabilityOutcome:
    """Classification result: the record and the cards Stage 1a receives."""

    record: RiskActionabilityRecord
    actionable_cards: list[RiskCard] = field(default_factory=list)


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
    """Classify every card, persist the record, and return actionable cards.

    Cards are sent in batches of at most :data:`MAX_CARDS_PER_CALL`.  A batch
    whose call fails or omits cards receives one retry for its missing cards;
    cards still missing stay actionable (``source: fallback``).  The call
    never raises: a failed call is recorded as a warning.
    """
    cards = list(risk_cards)
    if not cards:
        record = _record([], call_count=0, warnings=[])
        write_yaml(record, run_dir / ARTIFACT_FILENAME)
        return RiskActionabilityOutcome(record=record, actionable_cards=[])

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
    actionable_ids = {
        entry.risk_id
        for entry in entries
        if entry.decision is ActionabilityDecision.actionable
    }
    return RiskActionabilityOutcome(
        record=record,
        actionable_cards=[card for card in cards if card.risk_id in actionable_ids],
    )


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

    Return the number of requests sent, JSON-decode retries included and
    requests the prompt preflight blocked excluded.
    """
    call_count = 0
    for step in (STEP, STEP_RETRY):
        pending = [card for card in batch if card.risk_id not in decided]
        if not pending:
            break
        decisions, error, sent = _classify_batch(
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
    """Record the first decision for each requested card; warn on the others."""
    expected = {card.risk_id for card in pending}
    for item in decisions:
        if item.risk_id not in expected:
            warnings.append(
                f"{step}: ignored decision for unrequested card '{item.risk_id}'"
            )
            continue
        decided.setdefault(item.risk_id, item)


def _actionability_entries(
    cards: Sequence[RiskCard],
    decided: dict[str, RiskActionabilityDecision],
    warnings: list[str],
) -> list[RiskActionabilityEntry]:
    """Build one entry per card, keeping unclassified cards actionable."""
    entries: list[RiskActionabilityEntry] = []
    for card in cards:
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
                    reason="Not classified by the model; kept in scope.",
                    source="fallback",
                )
            )
        else:
            entries.append(
                RiskActionabilityEntry(
                    risk_id=card.risk_id,
                    decision=item.decision,
                    reason=item.reason.strip(),
                    source="model",
                )
            )
    return entries


def _classify_batch(
    *,
    llm_client: LLMClient,
    system_prompt: str,
    user_prompt: str,
    run_dir: Path,
    temperature: float,
    step: str,
) -> tuple[list[RiskActionabilityDecision], str | None, int]:
    """Return the decisions, the error, and the number of requests sent."""
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
        return [], outcome.error or "no response", outcome.calls
    return list(outcome.value.decisions), None, outcome.calls


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
