"""The Stage 1a graph-revision decisions, as values.

A revision round ends in one of six ways, and the gate used to encode each as
control flow: keep the response, ask once more for a reply that failed to
decode or validate, ask for another round on a graph that still fails, keep
the response without the records it broke, keep the prior graph, or stop the
run.  These frozen values name those outcomes, and the ``decide_*`` functions
are the gate's decision code: each one returns exactly one of them.

The payloads reuse the existing models: :class:`LossAnalysis` for the graph,
:class:`HazardGraphDensityReport` for the findings, and the gate artifact's
own record dicts for what a partial keep dropped.  A decision never writes an
artifact or calls a model; the runner does that from the value it receives.
"""

from __future__ import annotations

from dataclasses import dataclass

from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.loss_analysis_gate_checks import (
    HazardGraphDensityReport,
)


@dataclass(frozen=True)
class Accept:
    """Keep this graph: the response validated and passes its checks."""

    analysis: LossAnalysis


@dataclass(frozen=True)
class Correct:
    """Ask once more for a reply that failed decoding or validation.

    ``scope`` names what the correction may change; ``retries`` is the
    number of correction requests the failure earns.
    """

    scope: str
    retries: int


@dataclass(frozen=True)
class Revise:
    """Ask for another bounded round on a graph that still fails a check.

    ``round_number`` is the round that produced ``analysis``; ``findings``
    holds the checks the next round receives.
    """

    analysis: LossAnalysis
    findings: HazardGraphDensityReport
    round_number: int


@dataclass(frozen=True)
class KeepPartial:
    """Keep this graph without the records it broke.

    ``records`` are the gate artifact's dropped-record rows, so the caller
    can report what the partial keep cost.
    """

    analysis: LossAnalysis
    records: tuple[dict, ...] = ()


@dataclass(frozen=True)
class KeepPrior:
    """Keep the prior graph: the revision cannot be accepted."""

    reason: str


@dataclass(frozen=True)
class Stop:
    """Stop the run: nothing from the revision may be kept.

    ``reason`` words the failure; ``findings`` carries the checks that are
    still failing when the round itself validated.
    """

    reason: str
    findings: HazardGraphDensityReport | None = None


def decide_revision_call(
    revised: LossAnalysis | None,
    *,
    error: str | None = None,
    records: tuple[dict, ...] = (),
) -> Accept | KeepPartial | Stop:
    """Decide what one graph-revision call leaves the runner to do.

    *revised* is the call's graph, or the rebuild without its defective
    records, and ``None`` when the call produced nothing.  *records* are the
    records that rebuild dropped.
    """
    if revised is None:
        return Stop(reason=error or "the graph revision call produced no graph")
    if records:
        return KeepPartial(analysis=revised, records=records)
    return Accept(analysis=revised)


def decide_density_round(
    revised: LossAnalysis,
    findings: HazardGraphDensityReport,
    *,
    round_number: int,
    rounds: int,
) -> Accept | Revise | Stop:
    """Decide what the density gate does with one valid revision round.

    *findings* is the report on *revised*, ``round_number`` the round that
    produced it, and *rounds* the gate's bound on rounds.
    """
    if findings.passed:
        return Accept(analysis=revised)
    if round_number < rounds:
        return Revise(analysis=revised, findings=findings, round_number=round_number)
    return Stop(reason="; ".join(findings.failing_checks), findings=findings)


def decide_stated_rule_round(
    revised: LossAnalysis,
    *,
    rejection: str | None,
    records: tuple[dict, ...] = (),
) -> Accept | KeepPartial | KeepPrior:
    """Decide whether the non-fatal stated-rule round keeps its revision.

    *rejection* is why the round cannot be accepted, or ``None``; *records*
    are the records an acceptance leaves out.
    """
    if rejection is not None:
        return KeepPrior(reason=rejection)
    if records:
        return KeepPartial(analysis=revised, records=records)
    return Accept(analysis=revised)


def decide_correction(*, scope: str, retries: int) -> Correct | Stop:
    """Decide whether a failed reply earns a correction request.

    *scope* names what the correction may change; *retries* is the retry
    budget the caller's policy would grant.
    """
    if retries > 0:
        return Correct(scope=scope, retries=retries)
    return Stop(reason=f"{scope} earns no correction request")
