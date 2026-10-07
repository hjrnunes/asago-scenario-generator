"""Phase 1.2 — deterministic gates on the loss-analysis hazard graph.

After the Stage 1a loss analysis is accepted, offline code checks that the
hazard graph is dense enough to tell scenarios apart:

1. every loss has at least one hazard;
2. every constraint has at least one hazard;
3. every hazard has at least one constraint;
4. every distinct behavior class present in the constraints has its own
   hazard, so two constraints in different classes never share their only
   hazard.
The fixed-rule subject-phrase check remains recorded evidence, but a mismatch
is advisory and does not block the structural gate.

A graph with a failing structural check receives a bounded revision request
that reports the exact failing checks; a response that fails validation gets
one correction call.  A valid revision that still fails a structural check
gets one further round on the revised graph, with the checks the first round
introduced labelled as such; a failure after that round is a fatal stage
error.  The reviewed Stage 2 graph gets the same kind of bounded correction
when the review breaks a structural check.  The gates never call a taxonomy
service or infer a taxonomy mechanism.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Collection, Sequence
from dataclasses import dataclass, field, replace
from pathlib import Path

import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.canonical_ids import allocate_canonical_ids
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    StageError,
    call_with_policy,
    count_requests,
    decode_content,
    parse_llm_result,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    BehaviorClass,
    Hazard,
    LossAnalysis,
    LossAnalysisDraft,
    SecurityConstraint,
    stamp_proposed_direction,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    STAGE1A_MAX_COMPLETION_TOKENS,
    STAGE,
    STEP_GAP,
    _disposition_loss_contradictions,
    _ProviderObligation,
    _RevisionConstraintEdit,
    _RevisionHazardEdit,
    _Stage1aRevisionPatch,
)
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    RepairRecord,
)
from asago_scenario_generator.stpa.system_model.rule_span_repair import (
    RuleSpanRepairRecord,
    record_rule_span_repairs,
    repair_obligation_models,
    rule_span_requirement,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleFinding,
    StatedRuleRevision,
    normalized_text,
)
from pydantic import BaseModel, Field, ValidationError

STEP_GRAPH_REVISION = "hazard_graph_revision"
GATES_ARTIFACT = "loss-analysis-gates.yaml"
REVISION_VALIDATION_RETRIES = 1
# A valid revision that still fails a structural check gets one further round
# on the revised graph; the gate stays fail-closed after the last round.
GRAPH_REVISION_ROUNDS = 2
_ROUND_FAILURE_PREFIX = {
    1: "revision still failing",
    2: "second revision still failing",
}
POST_REVIEW_CORRECTION_ROUNDS = 1
# (failing checks, hazard IDs, constraint IDs) -> re-reviewed loss graph.
ReviewCorrection = Callable[
    [tuple[str, ...], tuple[str, ...], tuple[str, ...]], LossAnalysis
]
# () -> (unresolved hazard IDs, unresolved constraint IDs) of the review in force.
UnresolvedReviewIds = Callable[[], tuple[frozenset[str], frozenset[str]]]
# Revised graph -> reason to reject the stated-rule revision, or None.
StatedRuleCheck = Callable[[LossAnalysis], "str | None"]
REVISION_CORRECTION_FEEDBACK = (
    "\n\nCorrection request: the prior graph revision response failed "
    "validation. Return the complete corrected revision patch: fix the exact "
    "error reported below and keep every other edit and addition unchanged. "
    + rule_span_requirement()
)


@dataclass
class _RevisionAttempt:
    """Evidence from one parsed graph-revision response."""

    warnings: list[str] = field(default_factory=list)
    span_repairs: list[RuleSpanRepairRecord] = field(default_factory=list)
    failed: bool = False
    # Why an addition-only revision rejected this response outright.  A
    # rejection is final: it gets no correction call.
    rejection: str | None = None


UNCLASSIFIED = "unclassified"
_SINGULAR_EXCEPTIONS = frozenset({"bias"})
# -ses plurals whose -es is part of the stem's sibilant ending, not an
# appended suffix: the default rule strips only the s.
_SES_EXCEPTIONS = {
    "losses": "loss",
    "biases": "bias",
    "statuses": "status",
    "processes": "process",
    "addresses": "address",
    "accesses": "access",
    "successes": "success",
    "discusses": "discuss",
    "misses": "miss",
    "kisses": "kiss",
    "glasses": "glass",
    "classes": "class",
    "analyses": "analysis",
    "bases": "basis",
}


# Fixed, dependency-free subject extraction.  The stopword list contains
# function words, common STPA verbs, and generic actors so that two texts
# never share a "subject" merely because both say "the system must ensure".
_STOPWORDS = frozenset(
    """
    the a an this that these those its their any all no such each every some
    and or but nor not of to in on at by for with from as via per into onto
    about after before between during through without within regarding including
    due because so also only other subsequently it its they them we our you your
    is are was were be been being must may might can could should would shall will
    do does did has have had when while if then than unless whether
    ai assistant system model llm
    ensure ensures ensuring prevent prevents preventing remain remains
    include includes included involve involves involving
    provide provides provided providing contain contains containing contained
    send sends sent sending generate generates generated generating
    cause causes caused causing lead leads leading result results resulting
    allow allows allowing permit permits permitted
    fail fails failed failing make makes made making give gives given take takes taken
    matches match
    """.split()
)

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class LossAnalysisGateError(StageError):
    """A loss-analysis gate failed after its bounded repair budget.

    ``gate`` names the failed check group (``risk_accounting`` or
    ``hazard_graph_density``) so the run manifest can report statuses without
    parsing the message text.
    """

    def __init__(
        self,
        *,
        stage: str,
        step: str,
        message: str,
        gate: str,
        failing_checks: tuple[str, ...] = (),
        revision_attempted: bool = False,
        revision_call_count: int = 0,
    ) -> None:
        super().__init__(stage=stage, step=step, message=message)
        self.gate = gate
        self.failing_checks = failing_checks
        self.revision_attempted = revision_attempted
        self.revision_call_count = revision_call_count


# ---------------------------------------------------------------------------
# Subject-phrase extraction (fixed rule, no NLP dependencies)
# ---------------------------------------------------------------------------


def _singularize(token: str) -> str:
    if token.endswith("ies") and len(token) > 4:
        return token[:-3] + "y"
    # Plurals whose stem ends in a sibilant that requires -es: boxes -> box,
    # matches -> match, dishes -> dish.  The ambiguous -ses ending is handled
    # by the explicit exception table (the stem of "exposes"/"phrases" keeps
    # its final e; "biases"/"statuses" lose the es).
    if token.endswith(("xes", "ches", "shes")) and len(token) > 4:
        return token[:-2]
    singular = _SES_EXCEPTIONS.get(token)
    if singular is not None:
        return singular
    # Closed set of s-final singulars that must stay intact (bias -> bia was
    # a live subject-phrase miss).
    if token in _SINGULAR_EXCEPTIONS:
        return token
    if (
        token.endswith("s")
        and not token.endswith(("ss", "us", "is"))
        and len(token) > 3
    ):
        return token[:-1]
    return token


def extract_subject_phrases(text: str) -> frozenset[str]:
    """Extract candidate subject noun phrases with the fixed rule.

    Tokens are lowercased and lightly singularized.  Candidates are all
    contiguous n-grams (n >= 2) inside each maximal run of non-stopword
    tokens, plus a unigram only when the unigram is an entire run on its
    own, so generic single verbs or actors never count as a subject.  A
    stopword token (checked before and after singularization, so inflected
    function words like "does" and "matches" are caught) ends the current
    run and never enters a phrase.
    """
    runs: list[list[str]] = []
    current: list[str] = []
    for raw in _TOKEN_RE.findall(text.casefold()):
        token = _singularize(raw)
        if raw in _STOPWORDS or token in _STOPWORDS:
            if current:
                runs.append(current)
                current = []
        else:
            current.append(token)
    if current:
        runs.append(current)
    candidates: set[str] = set()
    for run in runs:
        for i in range(len(run)):
            for j in range(i + 2, len(run) + 1):
                candidates.add(" ".join(run[i:j]))
        if len(run) == 1:
            candidates.add(run[0])
    return frozenset(candidates)


# ---------------------------------------------------------------------------
# Gate reports
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConstraintSubjectCheck:
    """Per-constraint-hazard-edge subject sharing evidence."""

    constraint_id: str
    hazard_id: str
    shared_phrases: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return bool(self.shared_phrases)


@dataclass(frozen=True)
class BehaviorClassOwnHazardCheck:
    """Per-behavior-class evidence that the class owns at least one hazard."""

    behavior_class: str
    owned_hazards: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return bool(self.owned_hazards)


@dataclass(frozen=True)
class HazardGraphDensityReport:
    """Typed result of the structural and advisory density checks."""

    losses_without_hazard: tuple[str, ...]
    constraints_without_hazard: tuple[str, ...]
    hazards_without_constraint: tuple[str, ...]
    subject_checks: tuple[ConstraintSubjectCheck, ...]
    class_own_hazard_checks: tuple[BehaviorClassOwnHazardCheck, ...]
    constraint_classes: tuple[tuple[str, str], ...]
    unclassified_constraints: tuple[str, ...]

    @property
    def passed(self) -> bool:
        return not self.failing_checks

    @property
    def failing_checks(self) -> tuple[str, ...]:
        problems: list[str] = []
        for loss_id in self.losses_without_hazard:
            problems.append(f"loss {loss_id} has no hazard")
        for constraint_id in self.constraints_without_hazard:
            problems.append(f"constraint {constraint_id} has no hazard")
        for hazard_id in self.hazards_without_constraint:
            problems.append(f"hazard {hazard_id} has no constraint")
        for check in self.class_own_hazard_checks:
            if not check.passed:
                problems.append(
                    f"behavior class {check.behavior_class} has no hazard of "
                    "its own; its constraints share another class's hazard"
                )
        return tuple(problems)

    @property
    def advisory_checks(self) -> tuple[str, ...]:
        """Return subject-phrase mismatches for reviewer visibility."""
        return tuple(
            f"constraint {check.constraint_id} and hazard "
            f"{check.hazard_id} share no subject phrase"
            for check in self.subject_checks
            if not check.passed
        )


@dataclass(frozen=True)
class RiskAccountingReport:
    """Artifact-level view of the 1.1 risk-accounting rules."""

    missing_dispositions: tuple[str, ...]
    unaccounted_risk_refs: tuple[str, ...]
    not_applicable_refs: tuple[str, ...]
    cited_refs: tuple[str, ...]
    contradictions: tuple[str, ...] = ()

    @property
    def passed(self) -> bool:
        return (
            not self.missing_dispositions
            and not self.unaccounted_risk_refs
            and not self.contradictions
        )


def check_risk_accounting(
    analysis: LossAnalysis,
    risk_cards: list[RiskCard],
) -> RiskAccountingReport:
    """Report which supplied risk cards the persisted analysis accounts for.

    A card is accounted for when a disposition names it, or when one of the
    analysis's own losses cites it in ``source_risk_cards``.  Cards that are
    neither disposed nor cited are unaccounted; this is the number that must
    reach zero before a run may continue.  A cited record and a loss citation
    must also agree: a not_applicable card may not be cited by any loss, and
    a cited disposition's loss_ids must match the citing risk-card losses.
    """
    supplied = [card.risk_id for card in risk_cards]
    disposed = {d.risk_ref for d in analysis.risk_dispositions}
    cited_via_losses = {
        risk_ref
        for loss in analysis.risk_card_losses + analysis.use_case_losses
        for risk_ref in loss.source_risk_cards
    }
    missing = tuple(card_id for card_id in supplied if card_id not in disposed)
    unaccounted = tuple(
        card_id for card_id in missing if card_id not in cited_via_losses
    )
    contradictions = _accounting_contradictions(analysis)
    return RiskAccountingReport(
        missing_dispositions=missing,
        unaccounted_risk_refs=unaccounted,
        not_applicable_refs=_refs_with_disposition(analysis, "not_applicable"),
        cited_refs=_refs_with_disposition(analysis, "cited"),
        contradictions=contradictions,
    )


def _refs_with_disposition(analysis: LossAnalysis, disposition: str) -> tuple[str, ...]:
    return tuple(
        d.risk_ref for d in analysis.risk_dispositions if d.disposition == disposition
    )


def _accounting_contradictions(analysis: LossAnalysis) -> tuple[str, ...]:
    """Detect citations that contradict a not_applicable disposition.

    Delegates to the shared rule used by the Call 1 provider validator: a
    not_applicable card is never cited by a loss (spec rule 1.1(4)).
    """
    return tuple(
        _disposition_loss_contradictions(
            [*analysis.risk_card_losses, *analysis.use_case_losses],
            analysis.risk_dispositions,
        )
    )


def check_hazard_graph_density(analysis: LossAnalysis) -> HazardGraphDensityReport:
    """Run structural checks and record subject mismatches as advisory evidence."""
    constraints_without_hazard, subject_checks, class_by_constraint, unclassified = (
        _classify_and_check_subjects(analysis)
    )
    return HazardGraphDensityReport(
        losses_without_hazard=_losses_without_hazard(analysis),
        constraints_without_hazard=tuple(constraints_without_hazard),
        hazards_without_constraint=_hazards_without_constraint(analysis),
        subject_checks=tuple(subject_checks),
        class_own_hazard_checks=tuple(
            _class_own_hazard_checks(analysis, class_by_constraint)
        ),
        constraint_classes=tuple(sorted(class_by_constraint.items())),
        unclassified_constraints=tuple(sorted(unclassified)),
    )


def _losses_without_hazard(analysis: LossAnalysis) -> tuple[str, ...]:
    """Return losses that no hazard references, in loss order."""
    hazards_referencing_loss: dict[str, set[str]] = {}
    for hazard in analysis.hazards:
        for loss_id in hazard.related_losses:
            hazards_referencing_loss.setdefault(loss_id, set()).add(hazard.hazard_id)
    losses = analysis.risk_card_losses + analysis.use_case_losses
    return tuple(
        loss.loss_id
        for loss in losses
        if not hazards_referencing_loss.get(loss.loss_id)
    )


def _hazards_without_constraint(analysis: LossAnalysis) -> tuple[str, ...]:
    """Check 3: return hazards that no constraint references.

    The other checks look from the constraint side; this is the reverse edge,
    without which a hazard yields no candidate and no scenario.
    """
    hazards_with_constraint = {
        hazard_id
        for constraint in analysis.security_constraints
        for hazard_id in constraint.related_hazards
    }
    return tuple(
        hazard.hazard_id
        for hazard in analysis.hazards
        if hazard.hazard_id not in hazards_with_constraint
    )


def _declared_class(constraint: SecurityConstraint) -> str:
    """Return the class the model declared, or ``UNCLASSIFIED``; never read the text."""
    return constraint.behavior_class or UNCLASSIFIED


def _classify_and_check_subjects(
    analysis: LossAnalysis,
) -> tuple[list[str], list[ConstraintSubjectCheck], dict[str, str], list[str]]:
    """Read each hazard-linked constraint's declared class and check its subjects.

    Returns constraints without a hazard, per-edge subject checks, the class of
    each hazard-linked constraint, and the unclassified constraints.
    """
    hazards_by_id = {hazard.hazard_id: hazard for hazard in analysis.hazards}
    phrases_by_hazard = {
        hazard.hazard_id: extract_subject_phrases(hazard.description)
        for hazard in analysis.hazards
    }
    phrases_by_constraint = {
        constraint.constraint_id: extract_subject_phrases(constraint.description)
        for constraint in analysis.security_constraints
    }
    constraints_without_hazard: list[str] = []
    subject_checks: list[ConstraintSubjectCheck] = []
    class_by_constraint: dict[str, str] = {}
    unclassified: list[str] = []
    for constraint in analysis.security_constraints:
        if not constraint.related_hazards:
            constraints_without_hazard.append(constraint.constraint_id)
            continue
        declared = _declared_class(constraint)
        class_by_constraint[constraint.constraint_id] = declared
        if declared == UNCLASSIFIED:
            unclassified.append(constraint.constraint_id)
        for hazard_id in constraint.related_hazards:
            if hazard_id not in hazards_by_id:
                # Reference validity is enforced by the LossAnalysis schema.
                continue
            shared = sorted(
                phrases_by_constraint[constraint.constraint_id]
                & phrases_by_hazard[hazard_id]
            )
            subject_checks.append(
                ConstraintSubjectCheck(
                    constraint_id=constraint.constraint_id,
                    hazard_id=hazard_id,
                    shared_phrases=tuple(shared),
                )
            )
    return constraints_without_hazard, subject_checks, class_by_constraint, unclassified


def _class_own_hazard_checks(
    analysis: LossAnalysis,
    class_by_constraint: dict[str, str],
) -> list[BehaviorClassOwnHazardCheck]:
    """Check 4: each present behavior class owns a hazard no other class references."""
    hazards_by_class: dict[str, set[str]] = {}
    referencing_constraints: dict[str, set[str]] = {}
    for constraint in analysis.security_constraints:
        for hazard_id in constraint.related_hazards:
            referencing_constraints.setdefault(hazard_id, set()).add(
                constraint.constraint_id
            )
    for constraint_id, behavior_class in class_by_constraint.items():
        constraint = next(
            c for c in analysis.security_constraints if c.constraint_id == constraint_id
        )
        for hazard_id in constraint.related_hazards:
            hazards_by_class.setdefault(behavior_class, set()).add(hazard_id)
    return [
        BehaviorClassOwnHazardCheck(
            behavior_class=behavior_class,
            owned_hazards=_owned_hazards(
                behavior_class,
                hazards_by_class.get(behavior_class, set()),
                referencing_constraints,
                class_by_constraint,
            ),
        )
        for behavior_class in dict.fromkeys(class_by_constraint.values())
        if behavior_class != UNCLASSIFIED
    ]


def _owned_hazards(
    behavior_class: str,
    hazard_ids: set[str],
    referencing_constraints: dict[str, set[str]],
    class_by_constraint: dict[str, str],
) -> tuple[str, ...]:
    """Return the hazards that no constraint of another class references."""
    return tuple(
        hazard_id
        for hazard_id in sorted(hazard_ids)
        if {
            class_by_constraint[c]
            for c in referencing_constraints.get(hazard_id, set())
            if c in class_by_constraint
        }
        <= {behavior_class}
    )


# ---------------------------------------------------------------------------
# Gate artifact
# ---------------------------------------------------------------------------


class _SubjectCheckRecord(BaseModel):
    constraint_id: str
    hazard_id: str
    shared_phrases: list[str]
    passed: bool


class _ClassOwnHazardRecord(BaseModel):
    behavior_class: str
    owned_hazards: list[str]
    passed: bool


class LossAnalysisGatesArtifact(BaseModel):
    """The persisted ``loss-analysis-gates.yaml`` evidence."""

    risk_accounting: dict = Field(description="Risk-accounting report fields.")
    hazard_graph_density: dict = Field(
        description="Density report fields, including shared subject phrases."
    )
    failing_checks: list[str] = Field(default_factory=list)
    advisory_checks: list[str] = Field(
        default_factory=list,
        description=(
            "Subject-phrase mismatches recorded for reviewers; these mismatches "
            "do not block the gate."
        ),
    )
    revision_attempted: bool = False
    revision_applied: bool = False
    revision_call_count: int = Field(
        default=0,
        description="Graph-revision provider calls, including a correction call.",
    )
    passed: bool = False
    normalization_warnings: list[str] = Field(
        default_factory=list,
        description="Deterministic accounting normalizations applied to the "
        "provider response, recorded for reviewer visibility.",
    )
    post_review_density: dict | None = Field(
        default=None,
        description="Density re-check recorded after the Stage 2 semantic review.",
    )
    revision_rounds: list[dict] = Field(
        default_factory=list,
        description=(
            "One entry per graph-revision round: the checks sent, the checks "
            "left afterwards, and the checks the round introduced."
        ),
    )
    post_review_corrections: list[dict] = Field(
        default_factory=list,
        description=(
            "One entry per post-review density correction round: the checks "
            "sent, the checks left afterwards, and the checks it introduced."
        ),
    )
    stated_rule_findings: list[str] = Field(
        default_factory=list,
        description=(
            "Stated use-case rules no constraint carried, sent to the graph "
            "revision.  Advisory: they never fail the gate."
        ),
    )
    stated_rule_revision: dict | None = Field(
        default=None,
        description="Trigger, outcome, and calls of the stated-rule revision.",
    )


# ---------------------------------------------------------------------------
# Revision call
# ---------------------------------------------------------------------------


def _verify_revision_preserves_prior(
    prior: LossAnalysis, revised: LossAnalysisDraft
) -> None:
    """Fail closed when an assembled revision drops or changes prior records."""
    _verify_losses_preserved(prior, revised)
    _verify_ids_kept(
        {h.hazard_id for h in prior.hazards},
        {h.hazard_id for h in revised.hazards},
        "hazards",
    )
    _verify_ids_kept(
        {c.constraint_id for c in prior.security_constraints},
        {c.constraint_id for c in revised.security_constraints},
        "security constraints",
    )


def _verify_losses_preserved(prior: LossAnalysis, revised: LossAnalysisDraft) -> None:
    prior_losses = {
        loss.loss_id: loss for loss in prior.risk_card_losses + prior.use_case_losses
    }
    revised_losses = {
        loss.loss_id: loss
        for loss in revised.risk_card_losses + revised.use_case_losses
    }
    if set(revised_losses) != set(prior_losses):
        raise ValueError(
            "graph revision must keep the loss registry exactly: "
            f"expected {sorted(prior_losses)}, got {sorted(revised_losses)}"
        )
    for loss_id, baseline in prior_losses.items():
        if revised_losses[loss_id].model_dump(mode="json") != baseline.model_dump(
            mode="json"
        ):
            raise ValueError(
                f"graph revision changed loss {loss_id}; losses are immutable"
            )


def _verify_ids_kept(prior_ids: set[str], revised_ids: set[str], label: str) -> None:
    missing = prior_ids - revised_ids
    if missing:
        raise ValueError(
            f"graph revision dropped {label}: " + ", ".join(sorted(missing))
        )


def _unknown_edit_targets(prior: LossAnalysis, decoded: object) -> str | None:
    """Name the edit targets of a decoded patch that the graph does not have.

    Runs before schema validation, so a non-canonical target such as
    ``SC-4_updated`` rejects an addition-only revision instead of earning a
    correction call.
    """
    if not isinstance(decoded, dict):
        return None
    known = {
        "hazard_edits": ("hazard_id", {h.hazard_id for h in prior.hazards}),
        "security_constraint_edits": (
            "constraint_id",
            {c.constraint_id for c in prior.security_constraints},
        ),
    }
    unknown: list[str] = []
    for collection, (key, ids) in known.items():
        records = decoded.get(collection)
        if not isinstance(records, list):
            continue
        unknown.extend(
            repr(record.get(key))
            for record in records
            if isinstance(record, dict) and record.get(key) not in ids
        )
    if not unknown:
        return None
    return "the revision edits ID(s) the graph does not have: " + ", ".join(unknown)


def _extends_rule(prior_rule: str, rule: str) -> bool:
    """Whether ``rule`` still contains ``prior_rule`` after normalization.

    The prior rule's closing punctuation may move when a clause is appended.
    """
    original = normalized_text(prior_rule).rstrip(".;:!")
    return original in normalized_text(rule)


# The revision request displays conditions under a count heading and with
# numbers; providers sometimes echo either into the condition text.
_ECHOED_CONDITION_PREFIX = re.compile(
    r"^(?:(?:>=|≥|at least)?\s*\d+\s+conditions?\s*:\s*|\d+[.)]\s+)",
    re.IGNORECASE,
)


def _echo_normalized_condition(condition: str) -> str:
    """A condition with an echoed count heading or number and extra spaces removed."""
    collapsed = " ".join(condition.split())
    return _ECHOED_CONDITION_PREFIX.sub("", collapsed, count=1)


def _same_conditions(prior: list[str], echoed: list[str]) -> bool:
    return [_echo_normalized_condition(c) for c in echoed] == [
        " ".join(c.split()) for c in prior
    ]


def _extended_obligations(prior: list[dict], echoed: list[dict]) -> list[dict] | None:
    """Prior obligations followed by the added ones, or ``None`` on a change.

    Every prior obligation must be echoed unchanged; an entry whose ID is not
    a prior ID is an addition.
    """
    prior_ids = {item["obligation_id"] for item in prior}
    if any(item not in echoed for item in prior):
        return None
    added = [item for item in echoed if item not in prior]
    if any(item["obligation_id"] in prior_ids for item in added):
        return None
    return [*prior, *added]


def _changed_hazard_problems(
    hazards: dict[str, Hazard], edits: list[_RevisionHazardEdit]
) -> list[str]:
    return [
        f"it changes hazard {edit.hazard_id}"
        for edit in edits
        if (
            edit.description != hazards[edit.hazard_id].description
            or edit.related_losses != hazards[edit.hazard_id].related_losses
        )
    ]


def _addition_only_patch(
    prior: LossAnalysis, patch: _Stage1aRevisionPatch
) -> tuple[_Stage1aRevisionPatch, str | None]:
    """Restrict a stated-rule revision to additions and rule extensions.

    An edit may extend an existing constraint's ``rule`` so it still
    contains the prior text and every prior obligation ``rule_span`` (read
    as the constraint validator reads it, ignoring case).  Its hazards must
    stay unchanged; its conditions must equal the prior ones once an echoed
    count heading, number, and extra whitespace are removed; its obligations,
    when returned, must repeat every prior obligation unchanged and may only
    add entries with new IDs.
    An edit of an existing hazard must repeat it unchanged.  Returns the
    patch with unchanged edits dropped and, on extended rules, the prior
    conditions and the prior obligations plus any additions, or the reason
    the whole revision is rejected.
    """
    hazards = {hazard.hazard_id: hazard for hazard in prior.hazards}
    constraints = {c.constraint_id: c for c in prior.security_constraints}
    problems = _changed_hazard_problems(hazards, patch.hazard_edits)
    kept_edits = [
        kept
        for edit in patch.security_constraint_edits
        if (
            kept := _addition_only_constraint_edit(
                constraints[edit.constraint_id], edit, problems
            )
        )
        is not None
    ]
    if problems:
        return patch, "the stated-rule revision may only add: " + "; ".join(problems)
    additions = [
        addition.model_copy(
            update={
                "applies_when": [
                    _echo_normalized_condition(c) for c in addition.applies_when
                ]
            }
        )
        for addition in patch.security_constraint_additions
    ]
    return (
        patch.model_copy(
            update={
                "hazard_edits": [],
                "security_constraint_edits": kept_edits,
                "security_constraint_additions": additions,
            }
        ),
        None,
    )


def _addition_only_constraint_edit(
    constraint: SecurityConstraint,
    edit: _RevisionConstraintEdit,
    problems: list[str],
) -> _RevisionConstraintEdit | None:
    """Check one constraint edit is an extension; return the edit to keep.

    Appends each violation to *problems*.  Returns ``None`` when the rule is
    rewritten or when the edit changes neither the rule nor the obligations.
    """
    cid = edit.constraint_id
    if not _extends_rule(constraint.rule, edit.rule):
        problems.append(f"it rewrites the rule of {cid} instead of extending it")
        return None
    if not _same_conditions(constraint.applies_when, edit.applies_when):
        problems.append(f"it changes the applies_when conditions of {cid}")
    if edit.related_hazards != constraint.related_hazards:
        problems.append(f"it changes the related_hazards of {cid}")
    prior_obligations = [
        obligation.model_dump(mode="json") for obligation in constraint.obligations
    ]
    obligations = _addition_only_obligations(cid, prior_obligations, edit, problems)
    problems.extend(
        f"obligation {cid}/{obligation.obligation_id} rule_span no longer "
        "occurs verbatim in the extended rule"
        for obligation in constraint.obligations
        if obligation.rule_span.casefold() not in edit.rule.casefold()
    )
    if edit.rule == constraint.rule and obligations == prior_obligations:
        return None
    return edit.model_copy(
        update={
            "applies_when": list(constraint.applies_when),
            "obligations": [
                _ProviderObligation.model_validate(item) for item in obligations
            ],
        }
    )


def _addition_only_obligations(
    cid: str,
    prior_obligations: list[dict],
    edit: _RevisionConstraintEdit,
    problems: list[str],
) -> list[dict]:
    """Return the prior obligations plus any additions the edit returns."""
    if edit.obligations is None:
        return prior_obligations
    extended = _extended_obligations(
        prior_obligations,
        [obligation.model_dump(mode="json") for obligation in edit.obligations],
    )
    if extended is None:
        problems.append(f"it changes the obligations of {cid}")
        return prior_obligations
    return extended


def _revised_analysis(prior: LossAnalysis, revised: LossAnalysisDraft) -> LossAnalysis:
    """Restamp and validate the assembled revision into final graph shape."""
    # A revision is a derived graph, even when an untouched prior constraint
    # carried reviewed stamps.  The reviewed authority belongs only to an
    # explicitly pinned graph; deterministic revision compilation clears those
    # stamps and marks entries with proposed authority.
    stamp_proposed_direction(revised)
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": revised.risk_card_losses,
            "use_case_losses": revised.use_case_losses,
            "hazards": revised.hazards,
            "security_constraints": revised.security_constraints,
            "risk_dispositions": prior.risk_dispositions,
        }
    )


def _revision_patch_to_draft(
    prior: LossAnalysis,
    patch: _Stage1aRevisionPatch,
    warnings_out: list[str],
    span_repairs_out: list[RuleSpanRepairRecord] | None = None,
) -> LossAnalysisDraft:
    """Assemble an explicit graph delta over an immutable prior graph.

    The provider returns only edited records and additions.  Existing records
    omitted from the patch are copied byte-for-byte; additions receive
    canonical IDs from sorted request-local handles.  All references are
    resolved against the prior graph plus additions before the ordinary domain
    validators run.  Obligation ``rule_span`` values that map unambiguously
    to verbatim rule text are repaired first and reported in
    ``span_repairs_out``.
    """
    prior_hazards = {hazard.hazard_id: hazard for hazard in prior.hazards}
    prior_constraints = {
        constraint.constraint_id: constraint
        for constraint in prior.security_constraints
    }
    _check_revision_edit_targets(patch, prior_hazards, prior_constraints)

    hazard_additions = _unique_revision_handles(
        patch.hazard_additions,
        label="hazard addition",
    )
    constraint_additions = _unique_revision_handles(
        patch.security_constraint_additions,
        label="security constraint addition",
    )

    assembled_hazards, hazard_handle_map = _assemble_revision_hazards(
        prior, patch, hazard_additions, warnings_out
    )

    constraint_handle_map = _allocate_revision_handles(
        constraint_additions,
        existing_ids=set(prior_constraints),
        kind="constraint",
    )
    existing_hazard_ids = set(prior_hazards)
    assembled_constraints = {
        constraint_id: constraint.model_copy(deep=True)
        for constraint_id, constraint in prior_constraints.items()
    }
    for edit in patch.security_constraint_edits:
        assembled_constraints[edit.constraint_id] = _edited_constraint(
            prior_constraints[edit.constraint_id],
            edit,
            existing_hazard_ids=existing_hazard_ids,
            hazard_handle_map=hazard_handle_map,
            warnings_out=warnings_out,
            span_repairs_out=span_repairs_out,
        )
    for addition in patch.security_constraint_additions:
        assembled_constraints[constraint_handle_map[addition.handle]] = (
            _build_constraint(
                constraint_id=constraint_handle_map[addition.handle],
                rule=addition.rule,
                applies_when=addition.applies_when,
                behavior_class=addition.behavior_class,
                related_hazards=addition.related_hazards,
                obligations=addition.obligations,
                existing_hazard_ids=existing_hazard_ids,
                hazard_handle_map=hazard_handle_map,
                span_repairs_out=span_repairs_out,
                addition_handle=addition.handle,
            )
        )

    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                loss.model_copy(deep=True) for loss in prior.risk_card_losses
            ],
            "use_case_losses": [
                loss.model_copy(deep=True) for loss in prior.use_case_losses
            ],
            "hazards": list(assembled_hazards.values()),
            "security_constraints": list(assembled_constraints.values()),
            "risk_dispositions": [
                disposition.model_copy(deep=True)
                for disposition in prior.risk_dispositions
            ],
        }
    )


def _edited_constraint(
    prior_constraint: SecurityConstraint,
    edit: _RevisionConstraintEdit,
    *,
    existing_hazard_ids: set[str],
    hazard_handle_map: dict[str, str],
    warnings_out: list[str],
    span_repairs_out: list[RuleSpanRepairRecord] | None,
) -> SecurityConstraint:
    """Apply one edit; an omitted obligations list or class keeps the prior one."""
    _check_constraint_edit(prior_constraint, edit, hazard_handle_map, warnings_out)
    obligations = (
        prior_constraint.obligations if edit.obligations is None else edit.obligations
    )
    return _build_constraint(
        constraint_id=edit.constraint_id,
        rule=edit.rule,
        applies_when=edit.applies_when,
        behavior_class=edit.behavior_class or prior_constraint.behavior_class,
        related_hazards=edit.related_hazards,
        obligations=obligations,
        existing_hazard_ids=existing_hazard_ids,
        hazard_handle_map=hazard_handle_map,
        span_repairs_out=span_repairs_out,
    )


def _check_revision_edit_targets(
    patch: _Stage1aRevisionPatch,
    prior_hazards: dict[str, Hazard],
    prior_constraints: dict[str, SecurityConstraint],
) -> None:
    """Reject duplicate edit targets and targets the prior graph lacks."""
    hazard_edits = _unique_revision_targets(
        patch.hazard_edits,
        target_field="hazard_id",
        label="hazard edit",
    )
    constraint_edits = _unique_revision_targets(
        patch.security_constraint_edits,
        target_field="constraint_id",
        label="security constraint edit",
    )
    for target in hazard_edits:
        if target not in prior_hazards:
            raise ValueError(f"unknown hazard edit target '{target}'")
    for target in constraint_edits:
        if target not in prior_constraints:
            raise ValueError(f"unknown security constraint edit target '{target}'")


def _assemble_revision_hazards(
    prior: LossAnalysis,
    patch: _Stage1aRevisionPatch,
    hazard_additions: list[object],
    warnings_out: list[str],
) -> tuple[dict[str, Hazard], dict[str, str]]:
    """Apply hazard edits and additions; return hazards and the handle map.

    A hazard addition that restates an existing hazard resolves to that
    hazard's ID instead of creating a duplicate.
    """
    prior_hazards = {hazard.hazard_id: hazard for hazard in prior.hazards}
    losses = {
        loss.loss_id for loss in (*prior.risk_card_losses, *prior.use_case_losses)
    }
    assembled_hazards = {
        hazard_id: hazard.model_copy(deep=True)
        for hazard_id, hazard in prior_hazards.items()
    }
    for edit in patch.hazard_edits:
        assembled_hazards[edit.hazard_id] = _build_hazard(
            hazard_id=edit.hazard_id,
            description=edit.description,
            related_losses=edit.related_losses,
            valid_loss_ids=losses,
        )
    restated = _restated_hazard_handles(hazard_additions, assembled_hazards)
    for handle, hazard_id in sorted(restated.items()):
        warnings_out.append(
            f"graph revision hazard addition '{handle}' restates existing "
            f"hazard {hazard_id}; its references resolve to {hazard_id}"
        )
    hazard_additions = [
        addition
        for addition in hazard_additions
        if str(getattr(addition, "handle")) not in restated
    ]
    hazard_handle_map = _allocate_revision_handles(
        hazard_additions,
        existing_ids=set(prior_hazards),
        kind="hazard",
    )
    hazard_handle_map.update(restated)
    for addition in hazard_additions:
        assembled_hazards[hazard_handle_map[addition.handle]] = _build_hazard(
            hazard_id=hazard_handle_map[addition.handle],
            description=addition.description,
            related_losses=addition.related_losses,
            valid_loss_ids=losses,
            addition_handle=addition.handle,
        )
    return assembled_hazards, hazard_handle_map


def _check_constraint_edit(
    prior_constraint: SecurityConstraint,
    edit: _RevisionConstraintEdit,
    hazard_handle_map: dict[str, str],
    warnings_out: list[str],
) -> None:
    """Reject an implicit rule change and warn about reviewer-visible edits."""
    resolved_edit_hazards = [
        hazard_handle_map.get(reference, reference)
        for reference in edit.related_hazards
    ]
    if (
        edit.rule != prior_constraint.rule
        or edit.applies_when != prior_constraint.applies_when
    ) and edit.obligations is None:
        raise ValueError(
            f"constraint {edit.constraint_id} changed rule or applicability "
            "without explicit obligations"
        )
    # Keep the prior review diagnostics for edits that are now explicit
    # enough to compile.  A condition-only change still deserves reviewer
    # visibility, while a rule that moves to a disjoint hazard set is a
    # semantic re-pointing even though the delta is structurally valid.
    if (
        prior_constraint.rule == edit.rule
        and prior_constraint.applies_when != edit.applies_when
    ):
        warnings_out.append(
            "graph revision changed the applies_when conditions of "
            f"constraint {edit.constraint_id} without changing its rule: "
            f"{prior_constraint.applies_when} -> {edit.applies_when}"
        )
    elif (
        prior_constraint.rule != edit.rule
        and set(prior_constraint.related_hazards) & set(resolved_edit_hazards) == set()
    ):
        # A rewritten rule on disjoint hazards is a semantic re-pointing;
        # preserve the old warning while explicit obligations prevent
        # stale interpretations from being carried forward.
        warnings_out.append(
            "graph revision changed the rule of constraint "
            f"{edit.constraint_id} and re-pointed it to hazards "
            f"{sorted(resolved_edit_hazards)} sharing none of its prior "
            f"hazards {sorted(prior_constraint.related_hazards)}"
        )


def _unique_revision_targets(
    records: list[object],
    *,
    target_field: str,
    label: str,
) -> set[str]:
    targets = [str(getattr(record, target_field)) for record in records]
    duplicates = sorted({target for target in targets if targets.count(target) > 1})
    if duplicates:
        raise ValueError(f"duplicate {label} target(s): {', '.join(duplicates)}")
    return set(targets)


def _with_repair_hint(
    rendered: str,
    check: str,
    density: HazardGraphDensityReport,
) -> str:
    """Append the edge a structural check needs to the rendered check."""
    for hazard_id in density.hazards_without_constraint:
        if check == f"hazard {hazard_id} has no constraint":
            return (
                f"{rendered}. Repair: return a constraint whose "
                f"`related_hazards` includes `{hazard_id}`, either a "
                "`security_constraint_additions` entry or a "
                f"`security_constraint_edits` entry that adds `{hazard_id}` "
                "to an existing constraint. A new hazard does not repair "
                f"this check, even one that restates {hazard_id}."
            )
    return rendered


def _restated_hazard_handles(
    additions: list[object],
    hazards: dict[str, Hazard],
) -> dict[str, str]:
    """Map each hazard addition that restates an existing hazard to its ID.

    A restatement has the same description (ignoring case and whitespace)
    and cites no loss the existing hazard lacks.  Adding it would create a
    duplicate hazard and leave the existing one exactly as it was.
    """

    def normalized(text: str) -> str:
        return " ".join(text.split()).casefold()

    by_description = {
        normalized(hazard.description): hazard for hazard in hazards.values()
    }
    restated: dict[str, str] = {}
    for addition in additions:
        existing = by_description.get(normalized(str(getattr(addition, "description"))))
        if existing is not None and set(getattr(addition, "related_losses")) <= set(
            existing.related_losses
        ):
            restated[str(getattr(addition, "handle"))] = existing.hazard_id
    return restated


def _unique_revision_handles(records: list[object], *, label: str) -> list[object]:
    handles = [str(getattr(record, "handle")) for record in records]
    duplicates = sorted({handle for handle in handles if handles.count(handle) > 1})
    if duplicates:
        raise ValueError(f"duplicate {label} handle(s): {', '.join(duplicates)}")
    return records


def _allocate_revision_handles(
    records: list[object],
    *,
    existing_ids: set[str],
    kind: str,
) -> dict[str, str]:
    """Allocate added-record IDs in stable local-handle order."""
    prefix = {"hazard": "H-", "constraint": "SC-"}[kind]
    handles = sorted(str(getattr(record, "handle")) for record in records)
    return allocate_canonical_ids(prefix, existing_ids, handles)


def _build_hazard(
    *,
    hazard_id: str,
    description: str,
    related_losses: list[str],
    valid_loss_ids: set[str],
    addition_handle: str | None = None,
) -> object:
    unknown = sorted(set(related_losses) - valid_loss_ids)
    if unknown:
        raise ValueError(
            f"hazard {hazard_id} references unknown loss ID(s): {', '.join(unknown)}"
        )
    repeated = sorted(
        {
            reference
            for reference in related_losses
            if related_losses.count(reference) > 1
        }
    )
    if repeated:
        raise ValueError(
            f"{_revision_record_label('hazard', hazard_id, addition_handle)} "
            f"references duplicate loss ID(s): {', '.join(repeated)}; list each "
            "loss once in related_losses"
        )
    from asago_scenario_generator.stpa.models.loss_analysis import Hazard

    return Hazard(
        hazard_id=hazard_id,
        description=description,
        related_losses=list(related_losses),
    )


def _build_constraint(
    *,
    constraint_id: str,
    rule: str,
    applies_when: list[str],
    behavior_class: BehaviorClass | None,
    related_hazards: list[str],
    obligations: list[object],
    existing_hazard_ids: set[str],
    hazard_handle_map: dict[str, str],
    span_repairs_out: list[RuleSpanRepairRecord] | None = None,
    addition_handle: str | None = None,
) -> SecurityConstraint:
    obligations, span_repairs = repair_obligation_models(
        constraint=constraint_id, rule=rule, obligations=list(obligations)
    )
    if span_repairs_out is not None:
        span_repairs_out.extend(span_repairs)
    resolved_hazards = [
        hazard_handle_map.get(reference, reference) for reference in related_hazards
    ]
    unknown = _unknown_hazard_references(
        related_hazards, existing_hazard_ids, hazard_handle_map
    )
    if unknown:
        raise ValueError(
            f"security constraint {constraint_id} references unknown hazard ID(s): "
            + ", ".join(unknown)
        )
    repeated = _repeated_resolved_references(related_hazards, resolved_hazards)
    if repeated:
        label = _revision_record_label(
            "security constraint", constraint_id, addition_handle
        )
        raise ValueError(
            f"{label} references duplicate hazard ID(s): {', '.join(repeated)}; "
            "list each hazard once in related_hazards"
        )
    try:
        return SecurityConstraint(
            constraint_id=constraint_id,
            rule=rule,
            applies_when=list(applies_when),
            behavior_class=behavior_class,
            related_hazards=resolved_hazards,
            obligations=list(obligations),
        )
    except ValidationError as exc:
        if addition_handle is None:
            raise
        raise _addition_validation_error(exc, constraint_id, addition_handle) from exc


def _unknown_hazard_references(
    related_hazards: list[str],
    existing_hazard_ids: set[str],
    hazard_handle_map: dict[str, str],
) -> list[str]:
    return sorted(
        {
            reference
            for reference in related_hazards
            if reference not in existing_hazard_ids
            and reference not in hazard_handle_map
        }
    )


def _addition_validation_error(
    exc: ValidationError, constraint_id: str, addition_handle: str
) -> ValidationError:
    # The provider never sees the compiler-assigned ID of an addition, so
    # the correction feedback must name the handle it wrote.
    prefix = (
        f"security constraint addition '{addition_handle}' (assigned {constraint_id}): "
    )
    return ValidationError.from_exception_data(
        exc.title,
        [
            {
                "type": "value_error",
                "loc": ("security_constraint_additions", addition_handle),
                "input": error.get("input"),
                "ctx": {
                    "error": ValueError(
                        prefix + str(error.get("ctx", {}).get("error", error["msg"]))
                    )
                },
            }
            for error in exc.errors()
        ],
    )


def _revision_record_label(
    kind: str, record_id: str, addition_handle: str | None
) -> str:
    """Name a revision record the way the provider wrote it.

    The provider never sees the compiler-assigned ID of an addition, so an
    addition is named by its handle as well.
    """
    if addition_handle is None:
        return f"{kind} {record_id}"
    return f"{kind} addition '{addition_handle}' (assigned {record_id})"


def _repeated_resolved_references(written: list[str], resolved: list[str]) -> list[str]:
    """Return each resolved ID cited twice, with its spellings when they differ.

    A hazard-addition handle that restates an existing hazard resolves to
    that hazard's ID, so two different written references can name one ID.
    """
    spellings: dict[str, list[str]] = {}
    for written_reference, resolved_reference in zip(written, resolved):
        spellings.setdefault(resolved_reference, []).append(written_reference)
    repeated = []
    for resolved_reference, references in sorted(spellings.items()):
        if len(references) < 2:
            continue
        if len(set(references)) == 1:
            repeated.append(resolved_reference)
            continue
        written_as = ", ".join(f"'{reference}'" for reference in sorted(references))
        repeated.append(f"{resolved_reference} (written as {written_as})")
    return repeated


@dataclass(frozen=True)
class LossAnalysisGateOutcome:
    """The complete gate result returned to the SP1 orchestrator."""

    loss_analysis: LossAnalysis
    accounting: RiskAccountingReport
    density: HazardGraphDensityReport
    revision_attempted: bool
    revision_applied: bool
    revision_call_count: int = 0
    stated_rule_revision: StatedRuleRevision = field(default_factory=StatedRuleRevision)

    @property
    def passed(self) -> bool:
        return self.accounting.passed and self.density.passed


def _density_report_dict(report: HazardGraphDensityReport) -> dict:
    """Serialize a density report for the gates artifact."""
    return {
        "losses_without_hazard": list(report.losses_without_hazard),
        "constraints_without_hazard": list(report.constraints_without_hazard),
        "hazards_without_constraint": list(report.hazards_without_constraint),
        "subject_checks": [
            _SubjectCheckRecord(
                constraint_id=check.constraint_id,
                hazard_id=check.hazard_id,
                shared_phrases=list(check.shared_phrases),
                passed=check.passed,
            ).model_dump(mode="json")
            for check in report.subject_checks
        ],
        "class_own_hazard_checks": [
            _ClassOwnHazardRecord(
                behavior_class=check.behavior_class,
                owned_hazards=list(check.owned_hazards),
                passed=check.passed,
            ).model_dump(mode="json")
            for check in report.class_own_hazard_checks
        ],
        "constraint_classes": [
            {"constraint_id": cid, "behavior_class": cls}
            for cid, cls in report.constraint_classes
        ],
        "unclassified_constraints": list(report.unclassified_constraints),
    }


def _write_gates_artifact(
    run_dir: Path,
    *,
    accounting: RiskAccountingReport,
    density: HazardGraphDensityReport,
    failing_checks: list[str],
    revision_attempted: bool,
    revision_applied: bool,
    normalization_warnings: list[str] | None = None,
    revision_call_count: int = 0,
    revision_rounds: list[dict] | None = None,
    stated_rule_findings: Sequence[StatedRuleFinding] = (),
    stated_rule_revision: StatedRuleRevision | None = None,
) -> None:
    """Persist structural failures and subject advisories before any failure."""
    artifact = LossAnalysisGatesArtifact(
        risk_accounting={
            "missing_dispositions": list(accounting.missing_dispositions),
            "unaccounted_risk_refs": list(accounting.unaccounted_risk_refs),
            "not_applicable_refs": list(accounting.not_applicable_refs),
            "cited_refs": list(accounting.cited_refs),
            "contradictions": list(accounting.contradictions),
            "passed": accounting.passed,
        },
        hazard_graph_density=_density_report_dict(density),
        failing_checks=failing_checks,
        advisory_checks=list(density.advisory_checks),
        revision_attempted=revision_attempted,
        revision_applied=revision_applied,
        revision_call_count=revision_call_count,
        passed=not failing_checks and accounting.passed,
        normalization_warnings=normalization_warnings or [],
        revision_rounds=revision_rounds or [],
        stated_rule_findings=[
            f"{finding.rule_id}: {finding.quote}" for finding in stated_rule_findings
        ],
        stated_rule_revision=(
            stated_rule_revision.model_dump(mode="json")
            if stated_rule_revision is not None
            else None
        ),
    )
    write_yaml(artifact, run_dir / GATES_ARTIFACT)


def _revision_round_record(
    round_number: int,
    *,
    before: HazardGraphDensityReport,
    after: HazardGraphDensityReport | None,
    original: HazardGraphDensityReport,
) -> dict:
    """Record one revision round; ``after`` is None when the call failed."""
    after_checks = list(after.failing_checks) if after is not None else []
    return {
        "round": round_number,
        "failing_checks_before": list(before.failing_checks),
        "failing_checks_after": after_checks,
        "introduced_checks": [
            check
            for check in after_checks
            if check not in before.failing_checks
            and check not in original.failing_checks
        ],
        "revision_valid": after is not None,
    }


def _correction_scope_constraints(
    report: HazardGraphDensityReport,
    draft: LossAnalysis,
    orphan_hazards: set[str],
) -> set[str]:
    failing_classes = {
        check.behavior_class
        for check in report.class_own_hazard_checks
        if not check.passed
    }
    constraints = set(report.constraints_without_hazard)
    constraints.update(
        constraint_id
        for constraint_id, behavior_class in report.constraint_classes
        if behavior_class in failing_classes
    )
    constraints.update(
        constraint.constraint_id
        for constraint in draft.security_constraints
        if orphan_hazards.intersection(constraint.related_hazards)
    )
    return constraints


def post_review_correction_scope(
    report: HazardGraphDensityReport,
    draft: LossAnalysis,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return the hazard and constraint IDs a post-review correction may touch.

    The scope is every record a failing structural check names, plus the
    constraints whose pre-review edges reached an orphaned hazard and the
    hazards those constraints reached before the review.  The review cannot
    change loss membership, so a loss without a hazard adds nothing.
    """
    orphan_hazards = set(report.hazards_without_constraint)
    constraints = _correction_scope_constraints(report, draft, orphan_hazards)
    hazards = set(orphan_hazards)
    hazards.update(
        hazard_id
        for constraint in draft.security_constraints
        if constraint.constraint_id in constraints
        for hazard_id in constraint.related_hazards
    )
    return (
        tuple(h.hazard_id for h in draft.hazards if h.hazard_id in hazards),
        tuple(
            c.constraint_id
            for c in draft.security_constraints
            if c.constraint_id in constraints
        ),
    )


def _exempt_unresolved(
    report: HazardGraphDensityReport,
    unresolved: UnresolvedReviewIds | None,
) -> tuple[HazardGraphDensityReport, tuple[str, ...]]:
    """Remove records the review explicitly marked unresolved from the checks.

    An unresolved record names a fact the sources lack, so it cannot carry a
    grounded edge.  Only that record is exempt: a kept record left without its
    partner is still a structural failure.
    """
    if unresolved is None:
        return report, ()
    hazards, constraints = unresolved()
    kept_hazards, exempt_hazards = _partition_unresolved(
        report.hazards_without_constraint,
        hazards,
        "hazard {} has no constraint; the review marked it unresolved",
    )
    kept_constraints, exempt_constraints = _partition_unresolved(
        report.constraints_without_hazard,
        constraints,
        "constraint {} has no hazard; the review marked it unresolved",
    )
    return (
        replace(
            report,
            hazards_without_constraint=kept_hazards,
            constraints_without_hazard=kept_constraints,
        ),
        exempt_hazards + exempt_constraints,
    )


def _partition_unresolved(
    ids: tuple[str, ...], unresolved: Collection[str], message: str
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split *ids* into those still checked and exemption notes for the rest."""
    return (
        tuple(item for item in ids if item not in unresolved),
        tuple(message.format(item) for item in ids if item in unresolved),
    )


def verify_reviewed_density(
    reviewed: LossAnalysis,
    *,
    run_dir: Path,
    draft: LossAnalysis | None = None,
    correct: ReviewCorrection | None = None,
    unresolved: UnresolvedReviewIds | None = None,
) -> LossAnalysis:
    """Re-run the offline density checks on the reviewed graph.

    The Stage 2 semantic review may reword hazards/constraints or replace
    constraint hazard edges, so the persisted reviewed graph is re-checked
    before it replaces the canonical ``loss-analysis.yaml``.  ``unresolved``
    returns the hazard and constraint IDs the review in force marks
    unresolved; a missing edge on exactly those records is recorded as a
    post-review advisory instead of a failure.  When the review
    breaks a structural check and the caller supplies the pre-review
    ``draft`` and ``correct``, the review gets
    :data:`POST_REVIEW_CORRECTION_ROUNDS` correction round: ``correct``
    receives the failing checks and the hazard and constraint IDs of
    :func:`post_review_correction_scope`, and returns the re-reviewed graph
    or raises :class:`StageError` when the correction cannot be made.  Every
    report and correction round is recorded in the gates artifact;
    structural failures left after the last round fail closed with the exact
    still-failing checks, while subject mismatches are recorded as
    post-review advisories.  Returns the graph that passed the checks.
    """
    report, exempted = _exempt_unresolved(
        check_hazard_graph_density(reviewed), unresolved
    )
    first_report = report
    corrections: list[dict] = []
    correction_error: str | None = None
    if not report.passed and correct is not None and draft is not None:
        reviewed, report, exempted, correction_error = _run_post_review_corrections(
            reviewed,
            report,
            exempted,
            draft=draft,
            correct=correct,
            unresolved=unresolved,
            corrections_out=corrections,
        )
    _record_post_review_density(
        run_dir / GATES_ARTIFACT,
        report=report,
        first_report=first_report,
        corrections=corrections,
        exempted=exempted,
    )
    if not report.passed:
        message = "hazard graph density gate failed after review: " + "; ".join(
            report.failing_checks
        )
        if corrections and report is not first_report:
            message += " (after one review correction round)"
        elif correction_error is not None:
            message += f" (review correction failed: {correction_error})"
        raise LossAnalysisGateError(
            stage="stage_2",
            step="semantic_review",
            message=message,
            gate="hazard_graph_density",
            failing_checks=report.failing_checks,
        )
    return reviewed


def _run_post_review_corrections(
    reviewed: LossAnalysis,
    report: HazardGraphDensityReport,
    exempted: tuple[str, ...],
    *,
    draft: LossAnalysis,
    correct: ReviewCorrection,
    unresolved: UnresolvedReviewIds | None,
    corrections_out: list[dict],
) -> tuple[LossAnalysis, HazardGraphDensityReport, tuple[str, ...], str | None]:
    """Run the bounded post-review correction rounds and record each one.

    Returns the latest graph, its report, its exempted checks, and the
    correction error when a round raised :class:`StageError`.
    """
    first_report = report
    for round_number in range(1, POST_REVIEW_CORRECTION_ROUNDS + 1):
        hazard_ids, constraint_ids = post_review_correction_scope(report, draft)
        if not hazard_ids and not constraint_ids:
            break
        try:
            corrected = correct(report.failing_checks, hazard_ids, constraint_ids)
        except StageError as exc:
            corrections_out.append(
                {
                    **_revision_round_record(
                        round_number,
                        before=report,
                        after=None,
                        original=first_report,
                    ),
                    "error": str(exc),
                }
            )
            return reviewed, report, exempted, str(exc)
        after, exempted = _exempt_unresolved(
            check_hazard_graph_density(corrected), unresolved
        )
        corrections_out.append(
            _revision_round_record(
                round_number,
                before=report,
                after=after,
                original=first_report,
            )
        )
        reviewed, report = corrected, after
        if report.passed:
            break
    return reviewed, report, exempted, None


def _record_post_review_density(
    artifact_path: Path,
    *,
    report: HazardGraphDensityReport,
    first_report: HazardGraphDensityReport,
    corrections: list[dict],
    exempted: tuple[str, ...],
) -> None:
    """Add the post-review report and corrections to an existing gates artifact."""
    if not artifact_path.is_file():
        return
    artifact = LossAnalysisGatesArtifact.model_validate(
        yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
    )
    artifact.post_review_density = _density_report_dict(report)
    artifact.post_review_corrections = corrections
    artifact.advisory_checks = (
        artifact.advisory_checks
        + [f"post-review: {check}" for check in report.advisory_checks]
        + [f"post-review unresolved: {check}" for check in exempted]
    )
    if report.failing_checks:
        artifact.failing_checks = artifact.failing_checks + [
            f"post-review regression: {check}" for check in first_report.failing_checks
        ]
        if corrections and report is not first_report:
            artifact.failing_checks += [
                f"post-review correction still failing: {check}"
                for check in report.failing_checks
            ]
        artifact.passed = False
    write_yaml(artifact, artifact_path)


@dataclass(frozen=True)
class _GateInputs:
    """Inputs that stay fixed across every revision round of one gate run."""

    llm_client: LLMClient
    use_case_text: str
    run_dir: Path
    template_loader: TemplateLoader
    temperature: float
    accounting: RiskAccountingReport
    accounting_normalization_warnings: list[str] | None
    repair_record: RepairRecord | None


@dataclass
class _GateProgress:
    """Gate state that the density and stated-rule revisions advance."""

    loss_analysis: LossAnalysis
    final_density: HazardGraphDensityReport
    failing: list[str]
    revision_attempted: bool = False
    revision_applied: bool = False
    revision_call_count: int = 0
    rounds: list[dict] = field(default_factory=list)
    revision_warnings: list[str] = field(default_factory=list)


def _revise_stated_rules(
    progress: _GateProgress,
    inputs: _GateInputs,
    findings: tuple[StatedRuleFinding, ...],
    stated_rule_check: StatedRuleCheck | None,
) -> tuple[tuple[StatedRuleFinding, ...], StatedRuleRevision]:
    """Return the findings sent to a revision and that revision's outcome.

    Stated-rule findings reach a revision only on a graph that passes
    density; a density failure stays exactly as fatal as it was without them.
    """
    if not findings or progress.failing:
        return (), StatedRuleRevision()
    return findings, _apply_stated_rule_revision(
        progress, inputs, findings, stated_rule_check
    )


def gate_loss_analysis(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    accounting_normalization_warnings: list[str] | None = None,
    repair_record: RepairRecord | None = None,
    stated_rule_findings: Sequence[StatedRuleFinding] = (),
    stated_rule_check: StatedRuleCheck | None = None,
) -> LossAnalysisGateOutcome:
    """Run the offline structural density gate with bounded revision rounds.

    ``stated_rule_findings`` are stated use-case rules that no constraint
    carries.  They never fail the gate and never reach the density revision,
    which runs exactly as it does without them.  Once the graph passes
    density (at once or after revision), the findings get one revision round
    of their own (trigger ``stated_rules``) that may only add records and
    extend constraint rules; see :func:`_run_stated_rule_revision`.  That
    round is non-fatal: any rejection keeps the graph that passed density.
    ``stated_rule_check`` receives an otherwise acceptable revised graph and
    returns a reason to reject it, or ``None``.

    The 1.1 risk-accounting gate already ran against the Call 1 response;
    this artifact-level report records its persisted outcome.  A failing
    structural graph receives a revision request that receives the exact
    failing checks; subject-phrase mismatches are recorded as advisory
    evidence and never trigger that request.  A revision response that fails
    validation gets one correction call.  A valid revision that still fails
    gets one more round (:data:`GRAPH_REVISION_ROUNDS`) on the revised graph;
    a structural failure after the last round raises
    :class:`LossAnalysisGateError` and keeps the unrevised graph.  The evidence artifact is written before
    any failure is raised, so a run never stops without its recorded evidence.
    Deterministic ``rule_span`` repairs are appended to ``repair_record``
    (kind ``rule_span_repaired``), which is rewritten to the run directory.
    """
    accounting = check_risk_accounting(loss_analysis, risk_cards)
    density = check_hazard_graph_density(loss_analysis)
    progress = _GateProgress(
        loss_analysis=loss_analysis,
        final_density=density,
        failing=list(density.failing_checks),
    )
    if not accounting.passed:
        _raise_accounting_failure(
            run_dir, accounting, density, accounting_normalization_warnings
        )
    inputs = _GateInputs(
        llm_client=llm_client,
        use_case_text=use_case_text,
        run_dir=run_dir,
        template_loader=template_loader,
        temperature=temperature,
        accounting=accounting,
        accounting_normalization_warnings=accounting_normalization_warnings,
        repair_record=repair_record,
    )
    if not density.passed:
        _run_density_revision(progress, inputs, density)

    sent_findings, rule_revision = _revise_stated_rules(
        progress, inputs, tuple(stated_rule_findings), stated_rule_check
    )

    if progress.revision_applied or rule_revision.applied:
        _warn_unclassified_constraints(progress)
    normalization = (
        list(accounting_normalization_warnings or []) + progress.revision_warnings
    )

    _write_gates_artifact(
        run_dir,
        accounting=accounting,
        density=progress.final_density,
        failing_checks=progress.failing,
        revision_attempted=progress.revision_attempted,
        revision_applied=progress.revision_applied,
        normalization_warnings=normalization,
        revision_call_count=progress.revision_call_count,
        revision_rounds=progress.rounds,
        stated_rule_findings=sent_findings,
        stated_rule_revision=rule_revision if sent_findings else None,
    )

    if progress.failing:
        raise LossAnalysisGateError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message="hazard graph density gate failed: " + "; ".join(progress.failing),
            gate="hazard_graph_density",
            failing_checks=tuple(progress.failing),
            revision_attempted=progress.revision_attempted,
            revision_call_count=progress.revision_call_count,
        )
    return LossAnalysisGateOutcome(
        loss_analysis=progress.loss_analysis,
        accounting=accounting,
        density=progress.final_density,
        revision_attempted=progress.revision_attempted,
        revision_applied=progress.revision_applied,
        revision_call_count=progress.revision_call_count,
        stated_rule_revision=rule_revision,
    )


def _raise_accounting_failure(
    run_dir: Path,
    accounting: RiskAccountingReport,
    density: HazardGraphDensityReport,
    accounting_normalization_warnings: list[str] | None,
) -> None:
    """Record the accounting failure and raise without any revision call."""
    _write_gates_artifact(
        run_dir,
        accounting=accounting,
        density=density,
        failing_checks=[],
        revision_attempted=False,
        revision_applied=False,
        normalization_warnings=accounting_normalization_warnings,
    )
    raise LossAnalysisGateError(
        stage=STAGE,
        step=STEP_GAP,
        message="risk accounting gate failed: "
        + "; ".join(
            dict.fromkeys(
                [
                    *accounting.missing_dispositions,
                    *accounting.unaccounted_risk_refs,
                ]
            )
        ),
        gate="risk_accounting",
        failing_checks=(
            *accounting.missing_dispositions,
            *accounting.unaccounted_risk_refs,
            *accounting.contradictions,
        ),
    )


def _run_density_revision(
    progress: _GateProgress,
    inputs: _GateInputs,
    density: HazardGraphDensityReport,
) -> None:
    """Run the bounded density revision rounds on a failing graph.

    Each round revises the previous round's valid graph.  A second round runs
    only when the first revision validated but left (or introduced)
    structural failures; a revision call that fails validation after its
    correction still stops the gate immediately.
    """
    progress.revision_attempted = True
    current = progress.loss_analysis
    current_density = density
    round_attempts: list[list[_RevisionAttempt]] = []
    for round_number in range(1, GRAPH_REVISION_ROUNDS + 1):
        attempts: list[_RevisionAttempt] = []
        round_attempts.append(attempts)
        prompt_checks = [
            _with_repair_hint(
                check
                if check in density.failing_checks
                else f"{check} (introduced by the previous revision)",
                check,
                current_density,
            )
            for check in current_density.failing_checks
        ]
        try:
            with count_requests() as sent:
                revised = _run_graph_revision_call(
                    llm_client=inputs.llm_client,
                    loss_analysis=current,
                    use_case_text=inputs.use_case_text,
                    failing_checks=prompt_checks,
                    run_dir=inputs.run_dir,
                    template_loader=inputs.template_loader,
                    temperature=inputs.temperature,
                    attempts_out=attempts,
                )
        except StageError as exc:
            # The revision itself failed (provider error or a response that
            # still failed validation after its correction).  Persist the
            # evidence, then stop the run with every failing check.
            progress.revision_call_count += sent.requests
            _record_failed_revision_round(
                exc,
                progress,
                inputs,
                round_attempts=round_attempts,
                round_number=round_number,
                before=current_density,
                original=density,
            )
            raise
        progress.revision_call_count += sent.requests
        current_density = _accept_revision_round(
            progress,
            inputs,
            revised,
            attempts=attempts,
            round_number=round_number,
            before=current_density,
            original=density,
        )
        current = revised
        if current_density.passed:
            break
    # Retain the unrevised graph on failure; the stage error carries every
    # still-failing check for the run manifest.
    progress.final_density = current_density
    for recorded in round_attempts:
        _record_revision_span_repairs(
            inputs.repair_record,
            inputs.run_dir,
            recorded,
            accepted=current_density.passed,
        )
    if current_density.passed:
        progress.revision_applied = True
        progress.loss_analysis = current
        progress.failing = []


def _record_failed_revision_round(
    exc: StageError,
    progress: _GateProgress,
    inputs: _GateInputs,
    *,
    round_attempts: list[list[_RevisionAttempt]],
    round_number: int,
    before: HazardGraphDensityReport,
    original: HazardGraphDensityReport,
) -> None:
    """Persist the evidence of a failed revision call and annotate the error."""
    progress.rounds.append(
        _revision_round_record(
            round_number,
            before=before,
            after=None,
            original=original,
        )
    )
    for recorded in round_attempts:
        _record_revision_span_repairs(
            inputs.repair_record, inputs.run_dir, recorded, accepted=False
        )
    _write_gates_artifact(
        inputs.run_dir,
        accounting=inputs.accounting,
        density=progress.final_density,
        failing_checks=progress.failing,
        revision_attempted=True,
        revision_applied=False,
        normalization_warnings=inputs.accounting_normalization_warnings,
        revision_call_count=progress.revision_call_count,
        revision_rounds=progress.rounds,
    )
    exc.revision_attempted = True  # type: ignore[attr-defined]
    exc.revision_call_count = progress.revision_call_count  # type: ignore[attr-defined]


def _accept_revision_round(
    progress: _GateProgress,
    inputs: _GateInputs,
    revised: LossAnalysis,
    *,
    attempts: list[_RevisionAttempt],
    round_number: int,
    before: HazardGraphDensityReport,
    original: HazardGraphDensityReport,
) -> HazardGraphDensityReport:
    """Record a valid revision round and return the revised graph's report."""
    accepted_attempt = attempts[-1]
    progress.revision_warnings.extend(accepted_attempt.warnings)
    progress.revision_warnings.extend(
        f"graph revision rule_span {record.constraint}/"
        f"{record.obligation_id} repaired by {record.repair.kind} match: "
        f"{record.repair.original!r} -> {record.repair.repaired!r}"
        for record in accepted_attempt.span_repairs
    )
    revised_density = check_hazard_graph_density(revised)
    progress.rounds.append(
        _revision_round_record(
            round_number,
            before=before,
            after=revised_density,
            original=original,
        )
    )
    progress.failing.extend(
        f"{_ROUND_FAILURE_PREFIX[round_number]}: {check}"
        for check in revised_density.failing_checks
    )
    return revised_density


def _apply_stated_rule_revision(
    progress: _GateProgress,
    inputs: _GateInputs,
    findings: tuple[StatedRuleFinding, ...],
    check: StatedRuleCheck | None,
) -> StatedRuleRevision:
    """Run the stated-rule revision round and fold its result into *progress*."""
    (
        progress.loss_analysis,
        rule_revision,
        rule_round,
        rule_warnings,
    ) = _run_stated_rule_revision(
        llm_client=inputs.llm_client,
        loss_analysis=progress.loss_analysis,
        use_case_text=inputs.use_case_text,
        findings=findings,
        density=progress.final_density,
        run_dir=inputs.run_dir,
        template_loader=inputs.template_loader,
        temperature=inputs.temperature,
        repair_record=inputs.repair_record,
        round_number=len(progress.rounds) + 1,
        check=check,
    )
    progress.revision_call_count += rule_revision.call_count
    progress.rounds.append(rule_round)
    progress.revision_warnings.extend(rule_warnings)
    return rule_revision


def _warn_unclassified_constraints(progress: _GateProgress) -> None:
    """Warn about revised constraints that declare no behavior class.

    The Phase 2 relevance flow records such constraints as non-actionable
    (typed empty row with a reason), so this is recorded evidence, not a gate
    failure.
    """
    unclassified_added = sorted(
        constraint.constraint_id
        for constraint in progress.loss_analysis.security_constraints
        if constraint.behavior_class is None
    )
    if unclassified_added:
        progress.revision_warnings.append(
            "graph revision left constraint(s) "
            + ", ".join(unclassified_added)
            + " without a behavior class; the Phase 2 relevance table "
            "records them as non-actionable"
        )


def _run_stated_rule_revision(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    findings: tuple[StatedRuleFinding, ...],
    density: HazardGraphDensityReport,
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    repair_record: RepairRecord | None,
    round_number: int = 1,
    check: StatedRuleCheck | None = None,
) -> tuple[LossAnalysis, StatedRuleRevision, dict, list[str]]:
    """Run one non-fatal revision round for stated-rule findings alone.

    The graph already passes the structural checks.  The round may add
    hazards and constraints and extend an existing constraint's ``rule``
    (see :func:`_addition_only_patch`).  A failed call, a response that
    changes an existing record or names a non-canonical ID, a revision that
    breaks a structural check, and a revision ``check`` rejects all keep the
    unrevised graph, so a stated-rule finding never turns a passing gate
    into a stage failure or damages an existing constraint.
    """
    attempts: list[_RevisionAttempt] = []
    warnings: list[str] = []

    def rejected(
        reason: str, record: dict, call_count: int, verb: str = "discarded"
    ) -> tuple[LossAnalysis, StatedRuleRevision, dict, list[str]]:
        return (
            loss_analysis,
            StatedRuleRevision(
                trigger="stated_rules",
                applied=False,
                call_count=call_count,
                error=reason,
            ),
            record,
            [f"stated-rule revision {verb}; kept the unrevised graph: {reason}"],
        )

    try:
        with count_requests() as sent:
            revised = _run_graph_revision_call(
                llm_client=llm_client,
                loss_analysis=loss_analysis,
                use_case_text=use_case_text,
                failing_checks=[],
                run_dir=run_dir,
                template_loader=template_loader,
                temperature=temperature,
                attempts_out=attempts,
                stated_rules=findings,
                addition_only=True,
            )
    except Exception as exc:  # noqa: BLE001 - this revision is advisory
        _record_revision_span_repairs(repair_record, run_dir, attempts, accepted=False)
        record = _revision_round_record(
            round_number, before=density, after=None, original=density
        )
        record["trigger"] = "stated_rules"
        return rejected(str(exc), record, sent.requests, "failed")
    call_count = sent.requests
    rejection = attempts[-1].rejection if attempts else None
    if rejection is not None:
        _record_revision_span_repairs(repair_record, run_dir, attempts, accepted=False)
        record = _revision_round_record(
            round_number, before=density, after=None, original=density
        )
        record["trigger"] = "stated_rules"
        return rejected(rejection, record, call_count)
    revised_density = check_hazard_graph_density(revised)
    record = _revision_round_record(
        round_number, before=density, after=revised_density, original=density
    )
    record["trigger"] = "stated_rules"
    reason: str | None = None
    if not revised_density.passed:
        reason = "revision broke structural checks: " + "; ".join(
            revised_density.failing_checks
        )
    elif check is not None:
        try:
            reason = check(revised)
        except Exception as exc:  # noqa: BLE001 - this revision is advisory
            reason = f"revision check failed: {type(exc).__name__}: {exc}"
    _record_revision_span_repairs(
        repair_record, run_dir, attempts, accepted=reason is None
    )
    if reason is not None:
        return rejected(reason, record, call_count)
    accepted_attempt = attempts[-1]
    warnings.extend(accepted_attempt.warnings)
    warnings.extend(
        f"graph revision rule_span {item.constraint}/"
        f"{item.obligation_id} repaired by {item.repair.kind} match: "
        f"{item.repair.original!r} -> {item.repair.repaired!r}"
        for item in accepted_attempt.span_repairs
    )
    return (
        revised,
        StatedRuleRevision(trigger="stated_rules", applied=True, call_count=call_count),
        record,
        warnings,
    )


def _record_revision_span_repairs(
    repair_record: RepairRecord | None,
    run_dir: Path,
    attempts: list[_RevisionAttempt],
    *,
    accepted: bool,
) -> None:
    """Record every attempt's span repairs.

    Repairs on the final attempt are ``applied`` when its revised graph is
    kept; every other attempt's repairs are ``discarded``.
    """
    if repair_record is None:
        return
    for number, attempt in enumerate(attempts, 1):
        applied = accepted and number == len(attempts)
        record_rule_span_repairs(
            repair_record,
            step=STEP_GRAPH_REVISION,
            attempt="first" if number == 1 else "correction",
            repairs=attempt.span_repairs,
            outcome="applied" if applied else "discarded",
        )
    repair_record.write(run_dir)


def gate_pinned_loss_analysis(
    *,
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
    run_dir: Path,
) -> None:
    """Run the offline Stage 1a gates on a caller-pinned analysis.

    A pinned loss analysis is accepted verbatim: the accounting and structural
    density checks run exactly as they do for a derived graph, subject-phrase
    mismatches are advisory, and any other failing check is immediately fatal
    because no bounded revision call exists.  The evidence artifact is written
    before any failure is raised.
    """
    accounting = check_risk_accounting(loss_analysis, risk_cards)
    density = check_hazard_graph_density(loss_analysis)
    if not accounting.passed:
        _write_gates_artifact(
            run_dir,
            accounting=accounting,
            density=density,
            failing_checks=[],
            revision_attempted=False,
            revision_applied=False,
        )
        raise LossAnalysisGateError(
            stage=STAGE,
            step=STEP_GAP,
            message="risk accounting gate failed: "
            + "; ".join(
                dict.fromkeys(
                    [
                        *accounting.missing_dispositions,
                        *accounting.unaccounted_risk_refs,
                    ]
                )
            ),
            gate="risk_accounting",
            failing_checks=(
                *accounting.missing_dispositions,
                *accounting.unaccounted_risk_refs,
                *accounting.contradictions,
            ),
        )
    if not density.passed:
        _write_gates_artifact(
            run_dir,
            accounting=accounting,
            density=density,
            failing_checks=list(density.failing_checks),
            revision_attempted=False,
            revision_applied=False,
        )
        raise LossAnalysisGateError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message="hazard graph density gate failed: "
            + "; ".join(density.failing_checks),
            gate="hazard_graph_density",
            failing_checks=density.failing_checks,
        )
    _write_gates_artifact(
        run_dir,
        accounting=accounting,
        density=density,
        failing_checks=[],
        revision_attempted=False,
        revision_applied=False,
    )


def _run_graph_revision_call(
    *,
    llm_client: LLMClient,
    loss_analysis: LossAnalysis,
    use_case_text: str,
    failing_checks: list[str],
    run_dir: Path,
    template_loader: TemplateLoader,
    temperature: float,
    attempts_out: list[_RevisionAttempt],
    stated_rules: Sequence[StatedRuleFinding] = (),
    addition_only: bool = False,
) -> LossAnalysis:
    """Make the bounded graph-revision call and validate its result.

    A caller counts the requests it sent, a correction included and a request
    the prompt preflight blocked excluded, with :func:`count_requests`.

    With ``addition_only``, a response that edits an existing record beyond
    extending a constraint rule, or targets an ID the graph does not have,
    is rejected at once: the attempt records the ``rejection`` and the call
    returns the unchanged graph without a correction request.

    The response is an explicit edit/add delta carrying the authored ``rule``
    + ``applies_when`` shape (Phase 1.3 as amended). Losses and risk
    dispositions come from the prior analysis and deterministic code carries
    omitted graph records forward, so the model cannot damage immutable
    records by echoing or omitting them.

    A response that fails parsing or validation receives one correction call
    carrying the exact validation error and the prior response.  Each parsed
    attempt is appended to ``attempts_out`` with its own warnings and
    ``rule_span`` repairs, so only the accepted attempt's evidence is applied.
    """
    system_prompt = template_loader.render_prompt(
        "stage1a_graph_revision_system.j2", stated_rules=bool(stated_rules)
    )
    user_prompt = template_loader.render_prompt(
        "stage1a_graph_revision_user.j2",
        use_case_text=use_case_text,
        losses=loss_analysis.risk_card_losses + loss_analysis.use_case_losses,
        hazards=loss_analysis.hazards,
        security_constraints=loss_analysis.security_constraints,
        failing_checks=failing_checks,
        stated_rules=list(stated_rules),
    )

    def parse_revision(result: LLMResult) -> LossAnalysisDraft:
        attempt = _RevisionAttempt()
        attempts_out.append(attempt)
        try:
            if addition_only:
                attempt.rejection = _unknown_edit_targets(
                    loss_analysis, decode_content(result)
                )
                if attempt.rejection is not None:
                    return _draft_from_analysis(loss_analysis)
            patch = parse_llm_result(result, _Stage1aRevisionPatch)
            if addition_only:
                patch, attempt.rejection = _addition_only_patch(loss_analysis, patch)
                if attempt.rejection is not None:
                    return _draft_from_analysis(loss_analysis)
            return _revision_patch_to_draft(
                loss_analysis,
                patch,
                attempt.warnings,
                span_repairs_out=attempt.span_repairs,
            )
        except Exception:
            attempt.failed = True
            raise

    def validate_revision(draft: LossAnalysisDraft) -> None:
        try:
            _verify_revision_preserves_prior(loss_analysis, draft)
            # In place on the draft, before validation, even when validation
            # then fails; the prior graph keeps its own constraint objects.
            stamp_proposed_direction(draft)
            _validate_revision(loss_analysis, draft)
        except Exception:
            attempts_out[-1].failed = True
            raise

    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=_Stage1aRevisionPatch,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_GRAPH_REVISION,
        policy=CorrectionPolicy(
            validation_retries=REVISION_VALIDATION_RETRIES,
            feedback=REVISION_CORRECTION_FEEDBACK,
            include_schema=False,
            include_response=True,
        ),
        temperature=temperature,
        max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
        result_parser=parse_revision,
        result_validator=validate_revision,
    )
    revised = outcome.value
    if outcome.error is not None or revised is None:
        raise StageError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message=f"graph revision call failed: {outcome.error}",
        )
    return _revised_analysis(loss_analysis, revised)


def _validate_revision(prior: LossAnalysis, draft: LossAnalysisDraft) -> None:
    """Raise when a stamped revision draft fails full validation.

    Validates a copy, so *draft* is left unchanged.
    """
    # Full schema validation, including cross-references and the
    # single-hazard-per-class invariants enforced by the model itself.
    _revised_analysis(prior, draft.model_copy(deep=True))


def _draft_from_analysis(analysis: LossAnalysis) -> LossAnalysisDraft:
    """Convert a merged analysis into the collection-patch draft baseline.

    The draft owns copies, so stamping or editing it leaves *analysis* intact.
    """
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                loss.model_copy(deep=True) for loss in analysis.risk_card_losses
            ],
            "use_case_losses": [
                loss.model_copy(deep=True) for loss in analysis.use_case_losses
            ],
            "hazards": [hazard.model_copy(deep=True) for hazard in analysis.hazards],
            "security_constraints": [
                constraint.model_copy(deep=True)
                for constraint in analysis.security_constraints
            ],
            "risk_dispositions": [
                disposition.model_copy(deep=True)
                for disposition in analysis.risk_dispositions
            ],
        }
    )
