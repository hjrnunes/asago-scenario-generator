"""Phase 1.2 — deterministic gates on the loss-analysis hazard graph.

After the Stage 1a loss analysis is accepted, offline code checks that the
hazard graph is dense enough to tell scenarios apart:

1. every loss has at least one hazard;
2. every constraint has at least one hazard;
3. every constraint's hazard shares a subject noun phrase with the
   constraint, computed by a fixed rule and recorded in the artifact;
4. every distinct behavior class present in the constraints has its own
   hazard, so two constraints in different classes never share their only
   hazard.

A failing graph receives exactly one bounded revision call that reports the
exact failing checks; a second failure is a fatal stage error.  The gates
never call a taxonomy service, never infer a taxonomy mechanism, and never
soften a check to make a run pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    parse_llm_result,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    LossAnalysisDraft,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    STAGE1A_MAX_COMPLETION_TOKENS,
    STAGE,
    STEP_GAP,
    _disposition_loss_contradictions,
    _Stage1aRevisionPatch,
)
from pydantic import BaseModel, Field

STEP_GRAPH_REVISION = "hazard_graph_revision"
GATES_ARTIFACT = "loss-analysis-gates.yaml"
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


def default_behavior_classes_path() -> Path:
    """Resolve the committed behavior-class table without a pipeline import.

    Mirrors the packaged-then-source-checkout fallback of the taxonomy data
    root: a bundled copy under the package wins (the wheel force-includes the
    repository ``data/`` tree under ``data/bundled/``), otherwise the
    repository's top-level ``data/`` tree supplies the committed table.
    """
    package = PROMPTS_DIR.parents[2]
    for candidate in (
        package / "data" / "loss-analysis" / "behavior-classes.yaml",
        package / "data" / "bundled" / "loss-analysis" / "behavior-classes.yaml",
    ):
        if candidate.is_file():
            return candidate
    return package.parents[1] / "data" / "loss-analysis" / "behavior-classes.yaml"


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
    ) -> None:
        super().__init__(stage=stage, step=step, message=message)
        self.gate = gate
        self.failing_checks = failing_checks
        self.revision_attempted = revision_attempted


# ---------------------------------------------------------------------------
# Behavior classes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class BehaviorClassTable:
    """The fixed keyword table used to classify constraint behavior classes."""

    classes: tuple[tuple[str, tuple[str, ...]], ...]


def load_behavior_classes(path: Path | None = None) -> BehaviorClassTable:
    """Load and validate the committed behavior-class keyword table."""
    classes_path = path or default_behavior_classes_path()
    payload = yaml.safe_load(classes_path.read_text(encoding="utf-8"))
    rows = payload.get("classes") if isinstance(payload, dict) else None
    if not isinstance(rows, list) or not rows:
        raise ValueError(
            f"behavior class table {classes_path} must contain a classes list"
        )
    classes: list[tuple[str, tuple[str, ...]]] = []
    seen: set[str] = set()
    for row in rows:
        if not isinstance(row, dict):
            raise ValueError(f"behavior class table row is not a mapping: {row!r}")
        name = row.get("name")
        keywords = row.get("keywords")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"behavior class row has an invalid name: {row!r}")
        if name in seen:
            raise ValueError(f"behavior class table repeats class '{name}'")
        seen.add(name)
        if (
            not isinstance(keywords, list)
            or not keywords
            or not all(isinstance(kw, str) and kw.strip() for kw in keywords)
        ):
            raise ValueError(f"behavior class '{name}' needs a non-empty keyword list")
        classes.append((name, tuple(kw.casefold() for kw in keywords)))
    return BehaviorClassTable(classes=tuple(classes))


def _keyword_hits(text: str, keyword: str) -> int:
    """Count occurrences of a table keyword in *text*.

    Without a trailing ``*`` the match is whole-word so 'intent' never
    matches 'intentionally'.  A trailing ``*`` marks a stem: it matches the
    stem plus any following word characters ('hallucinat*' matches
    'hallucinate' and 'hallucination').  Both the keyword tokens and the
    text tokens are singularized with the fixed rule before matching, so
    the table's singular keywords also match plural surface forms ("refund"
    matches "refunds") and plural keywords match singular text ("fees"
    matches "fee").
    """
    keyword_tokens = [_singularize(token) for token in re.findall(r"\w+", keyword)]
    text_tokens = [_singularize(token) for token in re.findall(r"\w+", text)]
    if not keyword_tokens:
        return 0
    if keyword.endswith("*"):
        # Stem keyword: the final token is a stem matching any continuation.
        stem = keyword_tokens[-1]
        remainder = keyword_tokens[:-1]
        hits = 0
        for start in range(len(text_tokens) - len(remainder)):
            if text_tokens[start : start + len(remainder)] != remainder:
                continue
            following = text_tokens[start + len(remainder)]
            if following.startswith(stem):
                hits += 1
        return hits
    n = len(keyword_tokens)
    return sum(
        1
        for start in range(len(text_tokens) - n + 1)
        if text_tokens[start : start + n] == keyword_tokens
    )


def classify_constraint(description: str, table: BehaviorClassTable) -> str:
    """Classify one constraint description by keyword hits, ties to file order."""
    text = description.casefold()
    best_name = UNCLASSIFIED
    best_hits = 0
    for name, keywords in table.classes:
        hits = sum(_keyword_hits(text, keyword) for keyword in keywords)
        if hits > best_hits:
            best_name = name
            best_hits = hits
    return best_name


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
    """Typed result of the five deterministic hazard-graph density checks."""

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
        for check in self.subject_checks:
            if not check.passed:
                problems.append(
                    f"constraint {check.constraint_id} and hazard "
                    f"{check.hazard_id} share no subject phrase"
                )
        for check in self.class_own_hazard_checks:
            if not check.passed:
                problems.append(
                    f"behavior class {check.behavior_class} has no hazard of "
                    "its own; its constraints share another class's hazard"
                )
        return tuple(problems)


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
        card_id
        for card_id in supplied
        if card_id not in disposed and card_id not in cited_via_losses
    )
    not_applicable = tuple(
        d.risk_ref
        for d in analysis.risk_dispositions
        if d.disposition == "not_applicable"
    )
    cited = tuple(
        d.risk_ref for d in analysis.risk_dispositions if d.disposition == "cited"
    )
    contradictions = _accounting_contradictions(analysis)
    return RiskAccountingReport(
        missing_dispositions=missing,
        unaccounted_risk_refs=unaccounted,
        not_applicable_refs=not_applicable,
        cited_refs=cited,
        contradictions=contradictions,
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


def check_hazard_graph_density(
    analysis: LossAnalysis,
    class_table: BehaviorClassTable,
) -> HazardGraphDensityReport:
    """Run the five deterministic density checks over the merged graph."""
    hazards_by_id = {hazard.hazard_id: hazard for hazard in analysis.hazards}
    hazards_referencing_loss: dict[str, set[str]] = {}
    for hazard in analysis.hazards:
        for loss_id in hazard.related_losses:
            hazards_referencing_loss.setdefault(loss_id, set()).add(hazard.hazard_id)

    losses = analysis.risk_card_losses + analysis.use_case_losses
    losses_without_hazard = tuple(
        loss.loss_id
        for loss in losses
        if not hazards_referencing_loss.get(loss.loss_id)
    )

    phrases_by_hazard = {
        hazard.hazard_id: extract_subject_phrases(hazard.description)
        for hazard in analysis.hazards
    }
    phrases_by_constraint = {
        constraint.constraint_id: extract_subject_phrases(constraint.description)
        for constraint in analysis.security_constraints
    }

    # Check 5: every hazard is referenced by at least one constraint.  The
    # other checks look from the constraint side; this is the reverse edge,
    # without which a hazard yields no candidate and no scenario.
    hazards_with_constraint = {
        hazard_id
        for constraint in analysis.security_constraints
        for hazard_id in constraint.related_hazards
    }
    hazards_without_constraint = tuple(
        hazard.hazard_id
        for hazard in analysis.hazards
        if hazard.hazard_id not in hazards_with_constraint
    )

    constraints_without_hazard: list[str] = []
    subject_checks: list[ConstraintSubjectCheck] = []
    class_by_constraint: dict[str, str] = {}
    unclassified: list[str] = []
    for constraint in analysis.security_constraints:
        if not constraint.related_hazards:
            constraints_without_hazard.append(constraint.constraint_id)
            continue
        class_by_constraint[constraint.constraint_id] = classify_constraint(
            constraint.description, class_table
        )
        if class_by_constraint[constraint.constraint_id] == UNCLASSIFIED:
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

    # Check 4: every behavior class present in the constraints owns at least
    # one hazard that no constraint of a different class references.
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
    class_checks: list[BehaviorClassOwnHazardCheck] = []
    for behavior_class in dict.fromkeys(class_by_constraint.values()):
        if behavior_class == UNCLASSIFIED:
            continue
        owned: list[str] = []
        for hazard_id in sorted(hazards_by_class.get(behavior_class, set())):
            classes_referencing = {
                class_by_constraint[c]
                for c in referencing_constraints.get(hazard_id, set())
                if c in class_by_constraint
            }
            if classes_referencing <= {behavior_class}:
                owned.append(hazard_id)
        class_checks.append(
            BehaviorClassOwnHazardCheck(
                behavior_class=behavior_class,
                owned_hazards=tuple(owned),
            )
        )

    return HazardGraphDensityReport(
        losses_without_hazard=losses_without_hazard,
        constraints_without_hazard=tuple(constraints_without_hazard),
        hazards_without_constraint=hazards_without_constraint,
        subject_checks=tuple(subject_checks),
        class_own_hazard_checks=tuple(class_checks),
        constraint_classes=tuple(sorted(class_by_constraint.items())),
        unclassified_constraints=tuple(sorted(unclassified)),
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
    revision_attempted: bool = False
    revision_applied: bool = False
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


# ---------------------------------------------------------------------------
# Revision call
# ---------------------------------------------------------------------------


def _verify_revision_preserves_prior(
    prior: LossAnalysis, revised: LossAnalysisDraft
) -> None:
    """Fail closed when a revision response drops or changes prior records."""
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
    revised_hazard_ids = {h.hazard_id for h in revised.hazards}
    prior_hazard_ids = {h.hazard_id for h in prior.hazards}
    missing_hazards = prior_hazard_ids - revised_hazard_ids
    if missing_hazards:
        raise ValueError(
            "graph revision dropped hazards: " + ", ".join(sorted(missing_hazards))
        )
    revised_constraint_ids = {c.constraint_id for c in revised.security_constraints}
    prior_constraint_ids = {c.constraint_id for c in prior.security_constraints}
    missing_constraints = prior_constraint_ids - revised_constraint_ids
    if missing_constraints:
        raise ValueError(
            "graph revision dropped security constraints: "
            + ", ".join(sorted(missing_constraints))
        )


def _revised_analysis(prior: LossAnalysis, revised: LossAnalysisDraft) -> LossAnalysis:
    """Validate the revised draft into the final LossAnalysis shape."""
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
) -> LossAnalysisDraft:
    """Convert a graph patch into a full draft the merge validators accept.

    Losses and risk dispositions come from the prior analysis.  Each patched
    constraint carries the authored ``rule`` + ``applies_when`` shape (Phase
    1.3 as amended) and code composes the description; nothing is carried
    over or re-derived.  A changed ``applies_when`` list on a constraint
    whose ``rule`` is unchanged is recorded as a warning, not a failure.
    """
    prior_by_id = {c.constraint_id: c for c in prior.security_constraints}
    constraints = []
    for constraint in patch.security_constraints:
        prior_constraint = prior_by_id.get(constraint.constraint_id)
        if (
            prior_constraint is not None
            and prior_constraint.rule == constraint.rule
            and prior_constraint.applies_when != constraint.applies_when
        ):
            warnings_out.append(
                f"graph revision changed the applies_when conditions of "
                f"constraint {constraint.constraint_id} without changing its "
                f"rule: {prior_constraint.applies_when} -> {constraint.applies_when}"
            )
        if (
            prior_constraint is not None
            and prior_constraint.rule != constraint.rule
            and set(prior_constraint.related_hazards) & set(constraint.related_hazards)
            == set()
        ):
            # A rewritten rule on disjoint hazards is a rename in effect: the
            # constraint now governs different hazards than the reviewed graph
            # authorized, so record it rather than merge silently.
            warnings_out.append(
                f"graph revision changed the rule of constraint "
                f"{constraint.constraint_id} and re-pointed it to hazards "
                f"{sorted(constraint.related_hazards)} sharing none of its prior "
                f"hazards {sorted(prior_constraint.related_hazards)}"
            )
        constraints.append(
            SecurityConstraint(
                constraint_id=constraint.constraint_id,
                rule=constraint.rule,
                applies_when=constraint.applies_when,
                related_hazards=constraint.related_hazards,
            )
        )
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": prior.risk_card_losses,
            "use_case_losses": prior.use_case_losses,
            "hazards": patch.hazards,
            "security_constraints": constraints,
            "risk_dispositions": prior.risk_dispositions,
        }
    )


@dataclass(frozen=True)
class LossAnalysisGateOutcome:
    """The complete gate result returned to the SP1 orchestrator."""

    loss_analysis: LossAnalysis
    accounting: RiskAccountingReport
    density: HazardGraphDensityReport
    revision_attempted: bool
    revision_applied: bool

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
) -> None:
    """Persist the gate evidence atomically before any failure is raised."""
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
        revision_attempted=revision_attempted,
        revision_applied=revision_applied,
        passed=not failing_checks and accounting.passed,
        normalization_warnings=normalization_warnings or [],
    )
    write_yaml(artifact, run_dir / GATES_ARTIFACT)


def verify_reviewed_density(reviewed: LossAnalysis, *, run_dir: Path) -> None:
    """Re-run the offline density checks on the reviewed graph (no model call).

    The Stage 2 semantic review may reword hazards/constraints or replace
    constraint hazard edges, so the persisted reviewed graph is re-checked
    before it replaces the canonical ``loss-analysis.yaml``.  The second
    report is recorded in the gates artifact; any regression fails closed
    with the exact still-failing checks.
    """
    report = check_hazard_graph_density(reviewed, load_behavior_classes())
    artifact_path = run_dir / GATES_ARTIFACT
    if artifact_path.is_file():
        artifact = LossAnalysisGatesArtifact.model_validate(
            yaml.safe_load(artifact_path.read_text(encoding="utf-8"))
        )
        artifact.post_review_density = _density_report_dict(report)
        if not report.passed:
            artifact.failing_checks = artifact.failing_checks + [
                f"post-review regression: {check}" for check in report.failing_checks
            ]
            artifact.passed = False
        write_yaml(artifact, artifact_path)
    if not report.passed:
        raise LossAnalysisGateError(
            stage="stage_2",
            step="semantic_review",
            message="hazard graph density gate failed after review: "
            + "; ".join(report.failing_checks),
            gate="hazard_graph_density",
            failing_checks=report.failing_checks,
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
) -> LossAnalysisGateOutcome:
    """Run the offline hazard-graph density gate with one bounded revision.

    The 1.1 risk-accounting gate already ran against the Call 1 response;
    this artifact-level report records its persisted outcome.  A failing
    density graph receives exactly one revision call that receives the exact
    failing checks; a second failure raises :class:`LossAnalysisGateError`.
    The evidence artifact is written before any failure is raised, so a run
    never stops without its recorded gate evidence.
    """
    class_table = load_behavior_classes()
    accounting = check_risk_accounting(loss_analysis, risk_cards)
    density = check_hazard_graph_density(loss_analysis, class_table)
    revision_attempted = False
    revision_applied = False
    final_density = density
    failing = list(density.failing_checks)

    if not accounting.passed:
        # Never spend the bounded revision call on an accounting failure.
        _write_gates_artifact(
            run_dir,
            accounting=accounting,
            density=final_density,
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

    revision_warnings: list[str] = []
    if not density.passed:
        revision_attempted = True
        try:
            revised = _run_graph_revision_call(
                llm_client=llm_client,
                loss_analysis=loss_analysis,
                use_case_text=use_case_text,
                failing_checks=failing,
                run_dir=run_dir,
                template_loader=template_loader,
                temperature=temperature,
                warnings_out=revision_warnings,
            )
        except StageError:
            # The revision itself failed (provider error or a response that
            # dropped prior records).  Persist the evidence, then stop the
            # run with the original failing checks.
            _write_gates_artifact(
                run_dir,
                accounting=accounting,
                density=final_density,
                failing_checks=failing,
                revision_attempted=True,
                revision_applied=False,
                normalization_warnings=accounting_normalization_warnings,
            )
            raise
        final_density = check_hazard_graph_density(revised, class_table)
        if final_density.passed:
            revision_applied = True
            loss_analysis = revised
            failing = []
        else:
            # Retain the unrevised graph; the stage error carries every
            # still-failing check for the run manifest.
            failing = list(density.failing_checks) + [
                f"revision still failing: {check}"
                for check in final_density.failing_checks
            ]

    if revision_applied:
        # The revision may add constraints that match no behavior class.  The
        # Phase 2 relevance flow records such constraints as non-actionable
        # (typed empty row with a reason), so this is recorded evidence, not
        # a gate failure.
        unclassified_added = sorted(
            constraint.constraint_id
            for constraint in loss_analysis.security_constraints
            if classify_constraint(constraint.description, class_table) == UNCLASSIFIED
        )
        if unclassified_added:
            revision_warnings.append(
                "graph revision left constraint(s) "
                + ", ".join(unclassified_added)
                + " without a behavior class; the Phase 2 relevance table "
                "records them as non-actionable"
            )
    normalization = list(accounting_normalization_warnings or []) + revision_warnings

    _write_gates_artifact(
        run_dir,
        accounting=accounting,
        density=final_density,
        failing_checks=failing,
        revision_attempted=revision_attempted,
        revision_applied=revision_applied,
        normalization_warnings=normalization,
    )

    if failing:
        raise LossAnalysisGateError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message="hazard graph density gate failed: " + "; ".join(failing),
            gate="hazard_graph_density",
            failing_checks=tuple(failing),
            revision_attempted=revision_attempted,
        )
    return LossAnalysisGateOutcome(
        loss_analysis=loss_analysis,
        accounting=accounting,
        density=final_density,
        revision_attempted=revision_attempted,
        revision_applied=revision_applied,
    )


def gate_pinned_loss_analysis(
    *,
    loss_analysis: LossAnalysis,
    risk_cards: list[RiskCard],
    run_dir: Path,
) -> None:
    """Run the offline Stage 1a gates on a caller-pinned analysis.

    A pinned loss analysis is accepted verbatim: the accounting and five
    density checks run exactly as they do for a derived graph, but a failing
    check is immediately fatal and no bounded revision call exists.  The
    evidence artifact is written before any failure is raised.
    """
    class_table = load_behavior_classes()
    accounting = check_risk_accounting(loss_analysis, risk_cards)
    density = check_hazard_graph_density(loss_analysis, class_table)
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
    warnings_out: list[str],
) -> LossAnalysis:
    """Make the single bounded graph-revision call and validate its result.

    The response is a graph patch carrying the authored ``rule`` +
    ``applies_when`` shape (Phase 1.3 as amended).  Losses and risk
    dispositions come from the prior analysis and deterministic code
    composes the persisted description, so the model cannot damage
    immutable records by echoing them.
    """
    system_prompt = template_loader.render_prompt("stage1a_graph_revision_system.j2")
    user_prompt = template_loader.render_prompt(
        "stage1a_graph_revision_user.j2",
        use_case_text=use_case_text,
        losses=loss_analysis.risk_card_losses + loss_analysis.use_case_losses,
        hazards=loss_analysis.hazards,
        security_constraints=loss_analysis.security_constraints,
        failing_checks=failing_checks,
    )

    def parse_revision(result: LLMResult) -> LossAnalysisDraft:
        patch = parse_llm_result(result, _Stage1aRevisionPatch)
        return _revision_patch_to_draft(loss_analysis, patch, warnings_out)

    def validate_revision(draft: LossAnalysisDraft) -> None:
        _verify_revision_preserves_prior(loss_analysis, draft)
        # Full schema validation, including cross-references and the
        # single-hazard-per-class invariants enforced by the model itself.
        _revised_analysis(loss_analysis, draft)

    revised, _, error_msg = safe_llm_call(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=_Stage1aRevisionPatch,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_GRAPH_REVISION,
        temperature=temperature,
        max_completion_tokens=STAGE1A_MAX_COMPLETION_TOKENS,
        result_parser=parse_revision,
        result_validator=validate_revision,
    )
    if error_msg is not None or revised is None:
        raise StageError(
            stage=STAGE,
            step=STEP_GRAPH_REVISION,
            message=f"graph revision call failed: {error_msg}",
        )
    return _revised_analysis(loss_analysis, revised)


def _draft_from_analysis(analysis: LossAnalysis) -> LossAnalysisDraft:
    """Convert a merged analysis into the collection-patch draft baseline."""
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": analysis.risk_card_losses,
            "use_case_losses": analysis.use_case_losses,
            "hazards": analysis.hazards,
            "security_constraints": analysis.security_constraints,
            "risk_dispositions": analysis.risk_dispositions,
        }
    )
