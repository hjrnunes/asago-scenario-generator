"""Pure checks on a persisted loss-analysis hazard graph.

The Stage 1a gate reads a graph and reports what is wrong with it before it
considers any model call.  These checks are that reading: a graph in, typed
reports out.  They import no LLM client, no template loader and no run
directory, so a test can exercise the whole check layer with no model and no
filesystem.

Two reports make up the findings:

1. risk accounting -- every supplied risk card has a disposition row, and the
   rows agree with the losses' own citations;
2. hazard-graph density -- every loss, constraint and hazard has a partner,
   and each declared behavior class owns a hazard that no other class cites.
   The fixed-rule subject-phrase mismatch is advisory evidence, never a
   failure.

:func:`check_loss_analysis_graph` composes both reports in the order the gate
escalates them: accounting first, then density.  A revision round calls
:func:`check_hazard_graph_density` alone on the revised graph, because the
accounting rows did not change.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    SecurityConstraint,
    account_for_risk_cards,
)

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
# Check reports
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

    @property
    def failing_checks(self) -> tuple[str, ...]:
        """Return every blocking accounting check, in escalation order."""
        return (
            *self.missing_dispositions,
            *self.unaccounted_risk_refs,
            *self.contradictions,
        )


@dataclass(frozen=True)
class LossAnalysisGraphFindings:
    """Both persisted-graph reports, in the order the gate escalates them."""

    accounting: RiskAccountingReport
    density: HazardGraphDensityReport

    @property
    def passed(self) -> bool:
        return self.accounting.passed and self.density.passed

    @property
    def failing_checks(self) -> tuple[str, ...]:
        """Return every blocking check: accounting first, then density."""
        return (*self.accounting.failing_checks, *self.density.failing_checks)

    @property
    def advisory_checks(self) -> tuple[str, ...]:
        """Return checks that inform the reviewer but never fail the gate."""
        return self.density.advisory_checks


# ---------------------------------------------------------------------------
# Checks
# ---------------------------------------------------------------------------


def check_risk_accounting(
    analysis: LossAnalysis,
    risk_cards: Sequence[RiskCard],
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
    accounting = account_for_risk_cards(
        [*analysis.risk_card_losses, *analysis.use_case_losses],
        analysis.risk_dispositions,
        supplied,
    )
    cited_via_losses = {
        risk_ref
        for loss in analysis.risk_card_losses + analysis.use_case_losses
        for risk_ref in loss.source_risk_cards
    }
    missing = accounting.missing
    unaccounted = tuple(
        card_id for card_id in missing if card_id not in cited_via_losses
    )
    return RiskAccountingReport(
        missing_dispositions=missing,
        unaccounted_risk_refs=unaccounted,
        not_applicable_refs=_refs_with_disposition(analysis, "not_applicable"),
        cited_refs=_refs_with_disposition(analysis, "cited"),
        contradictions=tuple(item.text() for item in accounting.contradictions),
    )


def _refs_with_disposition(analysis: LossAnalysis, disposition: str) -> tuple[str, ...]:
    return tuple(
        d.risk_ref for d in analysis.risk_dispositions if d.disposition == disposition
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
# Entry point
# ---------------------------------------------------------------------------


def check_loss_analysis_graph(
    analysis: LossAnalysis,
    risk_cards: Sequence[RiskCard] = (),
) -> LossAnalysisGraphFindings:
    """Report every Stage 1a check finding for ``analysis``.

    ``risk_cards`` are the cards the run supplied.  With none, the accounting
    check still reads the graph's own rows and loss citations, so a pinned
    graph can be checked on its own.
    """
    return LossAnalysisGraphFindings(
        accounting=check_risk_accounting(analysis, risk_cards),
        density=check_hazard_graph_density(analysis),
    )
