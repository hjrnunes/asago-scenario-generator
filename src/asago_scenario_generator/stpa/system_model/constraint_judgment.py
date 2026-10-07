"""Judgment of each derived security constraint against the supplied rules.

Stage 1a derives constraints from risk cards and the use case.  Some state a
procedure the use case never asks for, or one it assigns to another party.
This step sends one bounded request per constraint of the gated graph and
records a verdict:

``supported``
    A stated rule requires or implies the constraint, or the rules are silent.
``contradicts``
    A stated rule or system fact says otherwise.
``exceeds``
    A stated rule governs the same behavior and the constraint demands more.

The rule text is the use-case description, the stated-rule quotes, and, when
supplied, the observed operation descriptions and policy text.  A drop verdict
(``contradicts`` or ``exceeds``) counts only when its ``quoted_rule`` occurs in
that text; code checks the quote and records the source's own wording.  An
unsubstantiated drop verdict becomes ``supported`` and is recorded.

An excluded constraint stays in the loss graph, so the hazard and density
gates keep their meaning; later scenario generation skips it.  The step is
advisory in the other direction as well: a provider error, an invalid
response, or a constraint that Stage 2 changed after its judgment keeps the
constraint and records a warning.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CallOutcome,
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleCoverageArtifact,
    StatedRuleRow,
    locate_quote,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    EvidenceOperation,
    TargetEvidence,
)

STAGE = "stage_1a"
STEP = "constraint_judgment"
SYSTEM_TEMPLATE = "stage1a_constraint_judgment_system.j2"
USER_TEMPLATE = "stage1a_constraint_judgment_user.j2"
ARTIFACT_FILENAME = "constraint-judgments.yaml"
SCHEMA_VERSION = "constraint-judgments-v1"
MAX_COMPLETION_TOKENS = 8192
# A shorter quote identifies no rule: two words occur in almost any text.
MIN_QUOTE_WORDS = 3

Verdict = Literal["supported", "contradicts", "exceeds"]
Outcome = Literal["judged", "unsubstantiated", "unavailable", "changed_after_judgment"]
DROP_VERDICTS: tuple[Verdict, ...] = ("contradicts", "exceeds")


class ConstraintJudgmentResponse(BaseModel):
    """Provider wire shape: one verdict for the requested constraint."""

    model_config = ConfigDict(extra="forbid")

    verdict: Verdict
    quoted_rule: str | None = Field(
        description=(
            "Exact contiguous passage of the supplied text that decides the "
            "verdict; required for contradicts and exceeds, null when none."
        )
    )
    reason: str = Field(
        min_length=1, description="One sentence naming the deciding fact."
    )


class ConstraintJudgmentRow(BaseModel):
    """One constraint's recorded judgment."""

    model_config = ConfigDict(extra="forbid")

    constraint_id: str
    text_digest: str
    verdict: Verdict = Field(description="The verdict code applies.")
    model_verdict: Verdict | None = Field(
        description="The verdict the model returned; null when none arrived."
    )
    quoted_rule: str | None = Field(
        description="The supplied text's own wording of the verified quote."
    )
    reason: str
    outcome: Outcome
    excluded: bool
    request_count: int = Field(ge=0)


class ConstraintJudgmentArtifact(BaseModel):
    """The persisted ``constraint-judgments.yaml``."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["constraint-judgments-v1"] = SCHEMA_VERSION
    status: Literal["completed", "partial", "empty"]
    request_count: int = Field(ge=0)
    excluded_constraint_ids: list[str] = Field(default_factory=list)
    rows: list[ConstraintJudgmentRow] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


@dataclass(frozen=True)
class RuleSources:
    """The text a drop verdict may quote."""

    use_case_text: str
    stated_rules: tuple[StatedRuleRow, ...] = ()
    operations: tuple[EvidenceOperation, ...] = ()
    policies: tuple[str, ...] = ()

    def locate(self, quote: str | None) -> str | None:
        """Return the source's own wording of *quote*, or ``None``."""
        if quote is None or len(quote.split()) < MIN_QUOTE_WORDS:
            return None
        for text in self._texts():
            excerpt = locate_quote(text, quote)
            if excerpt is not None:
                return excerpt
        return None

    def _texts(self) -> tuple[str, ...]:
        return (
            self.use_case_text,
            *(rule.quote for rule in self.stated_rules),
            *(operation.description for operation in self.operations),
            *self.policies,
        )


def rule_sources(
    use_case_text: str,
    stated_rules: StatedRuleCoverageArtifact | None,
    target_evidence: TargetEvidence | None,
) -> RuleSources:
    """Collect the rule text the run supplies."""
    rules = () if stated_rules is None else tuple(stated_rules.rules)
    evidence = target_evidence or TargetEvidence()
    return RuleSources(
        use_case_text=use_case_text,
        stated_rules=rules,
        operations=tuple(op for op in evidence.operations if op.description.strip()),
        policies=tuple(policy.text for policy in evidence.policies if policy.text),
    )


def constraint_digest(constraint: SecurityConstraint) -> str:
    """Digest the wording a verdict depends on: the rule and its conditions."""
    payload = json.dumps([constraint.rule, list(constraint.applies_when)])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def excluded_constraint_ids(
    artifact: ConstraintJudgmentArtifact | None,
) -> tuple[str, ...]:
    """Return the constraint ids later scenario generation skips."""
    if artifact is None:
        return ()
    return tuple(artifact.excluded_constraint_ids)


@dataclass(frozen=True)
class _Request:
    """What one judgment request needs besides its constraint."""

    llm_client: LLMClient
    loss_analysis: LossAnalysis
    sources: RuleSources
    system_prompt: str
    template_loader: TemplateLoader
    run_dir: Path
    temperature: float


def judge_constraints(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    stated_rules: StatedRuleCoverageArtifact | None,
    target_evidence: TargetEvidence | None,
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
) -> ConstraintJudgmentArtifact:
    """Judge every constraint of *loss_analysis* and persist the record.

    The call never raises for a failed request: that constraint stays and the
    artifact records a warning.
    """
    request = _Request(
        llm_client=llm_client,
        loss_analysis=loss_analysis,
        sources=rule_sources(use_case_text, stated_rules, target_evidence),
        system_prompt=template_loader.render_prompt(SYSTEM_TEMPLATE),
        template_loader=template_loader,
        run_dir=run_dir,
        temperature=temperature,
    )
    rows = [_judge(request, item) for item in loss_analysis.security_constraints]
    artifact = _artifact(rows)
    write_yaml(artifact, run_dir / ARTIFACT_FILENAME)
    return artifact


def reconcile_with_final_graph(
    artifact: ConstraintJudgmentArtifact,
    loss_analysis: LossAnalysis,
    run_dir: Path,
) -> ConstraintJudgmentArtifact:
    """Withdraw each exclusion whose constraint changed after its judgment.

    Stage 2 may reword a constraint; a verdict about the earlier wording does
    not carry over.  The artifact is rewritten only when a row changes.
    """
    current = {
        item.constraint_id: constraint_digest(item)
        for item in loss_analysis.security_constraints
    }
    rows = [
        _withdrawn(row)
        if row.excluded and current.get(row.constraint_id) != row.text_digest
        else row
        for row in artifact.rows
    ]
    if rows == artifact.rows:
        return artifact
    revised = _artifact(rows)
    write_yaml(revised, run_dir / ARTIFACT_FILENAME)
    return revised


def manifest_summary(artifact: ConstraintJudgmentArtifact) -> dict[str, Any]:
    """Return the run manifest's Stage 1a view of the judgments."""
    counts = {"supported": 0, "contradicts": 0, "exceeds": 0}
    for row in artifact.rows:
        counts[row.verdict] += 1
    return {
        "artifact": ARTIFACT_FILENAME,
        "status": artifact.status,
        "call_count": artifact.request_count,
        "counts": counts,
        "excluded_constraint_ids": list(artifact.excluded_constraint_ids),
    }


def _judge(request: _Request, constraint: SecurityConstraint) -> ConstraintJudgmentRow:
    outcome = call_with_policy(
        llm_client=request.llm_client,
        system_prompt=request.system_prompt,
        user_prompt=_user_prompt(request, constraint),
        response_format=ConstraintJudgmentResponse,
        run_dir=request.run_dir,
        stage=STAGE,
        step=STEP,
        policy=CorrectionPolicy(json_retries=1),
        temperature=request.temperature,
        max_completion_tokens=MAX_COMPLETION_TOKENS,
    )
    digest = constraint_digest(constraint)
    if outcome.error is not None or outcome.value is None:
        return _unavailable(constraint.constraint_id, digest, outcome)
    return _recorded(
        constraint.constraint_id,
        digest,
        outcome.value,
        request.sources,
        outcome.calls,
    )


def _user_prompt(request: _Request, constraint: SecurityConstraint) -> str:
    graph = request.loss_analysis
    linked = set(constraint.related_hazards)
    hazards = [item for item in graph.hazards if item.hazard_id in linked]
    loss_ids = {loss_id for item in hazards for loss_id in item.related_losses}
    losses = [
        item
        for item in (*graph.risk_card_losses, *graph.use_case_losses)
        if item.loss_id in loss_ids
    ]
    return request.template_loader.render_prompt(
        USER_TEMPLATE,
        use_case_text=request.sources.use_case_text,
        stated_rules=request.sources.stated_rules,
        operations=request.sources.operations,
        policies=request.sources.policies,
        constraint=constraint,
        hazards=hazards,
        losses=losses,
    )


def _unavailable(
    constraint_id: str, digest: str, outcome: CallOutcome[Any]
) -> ConstraintJudgmentRow:
    return ConstraintJudgmentRow(
        constraint_id=constraint_id,
        text_digest=digest,
        verdict="supported",
        model_verdict=None,
        quoted_rule=None,
        reason=f"No judgment arrived: {outcome.error or 'no response'}",
        outcome="unavailable",
        excluded=False,
        request_count=outcome.calls,
    )


def _recorded(
    constraint_id: str,
    digest: str,
    response: ConstraintJudgmentResponse,
    sources: RuleSources,
    request_count: int,
) -> ConstraintJudgmentRow:
    drops = response.verdict in DROP_VERDICTS
    excerpt = sources.locate(response.quoted_rule)
    substantiated = excerpt is not None or not drops
    return ConstraintJudgmentRow(
        constraint_id=constraint_id,
        text_digest=digest,
        verdict=response.verdict if substantiated else "supported",
        model_verdict=response.verdict,
        quoted_rule=excerpt,
        reason=response.reason.strip(),
        outcome="judged" if substantiated else "unsubstantiated",
        excluded=drops and substantiated,
        request_count=request_count,
    )


def _withdrawn(row: ConstraintJudgmentRow) -> ConstraintJudgmentRow:
    return row.model_copy(
        update={
            "verdict": "supported",
            "outcome": "changed_after_judgment",
            "excluded": False,
        }
    )


def _artifact(rows: list[ConstraintJudgmentRow]) -> ConstraintJudgmentArtifact:
    unavailable = any(row.outcome == "unavailable" for row in rows)
    status: Literal["completed", "partial", "empty"] = (
        "empty" if not rows else "partial" if unavailable else "completed"
    )
    return ConstraintJudgmentArtifact(
        status=status,
        request_count=sum(row.request_count for row in rows),
        excluded_constraint_ids=[row.constraint_id for row in rows if row.excluded],
        rows=rows,
        warnings=[text for row in rows if (text := _row_warning(row)) is not None],
    )


def _row_warning(row: ConstraintJudgmentRow) -> str | None:
    if row.outcome == "unavailable":
        return f"'{row.constraint_id}': {row.reason}; constraint kept"
    if row.outcome == "unsubstantiated":
        return (
            f"'{row.constraint_id}': {row.model_verdict} verdict is "
            "unsubstantiated (its quoted_rule does not occur in the supplied "
            "text); constraint kept"
        )
    if row.outcome == "changed_after_judgment":
        return (
            f"'{row.constraint_id}': constraint changed after its judgment; "
            "exclusion withdrawn"
        )
    return None


__all__ = [
    "ARTIFACT_FILENAME",
    "ConstraintJudgmentArtifact",
    "ConstraintJudgmentResponse",
    "ConstraintJudgmentRow",
    "RuleSources",
    "constraint_digest",
    "excluded_constraint_ids",
    "judge_constraints",
    "manifest_summary",
    "reconcile_with_final_graph",
    "rule_sources",
]
