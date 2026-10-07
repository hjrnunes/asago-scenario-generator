"""Select the governance-only plan rows worth routing to control actions.

A governance-only row is a reviewed risk that resolved to no attack pattern.
Stage 1a already decided, for every risk it received, whether a loss cites it
or it does not apply to the system.  Only a cited risk can be placed on a
control action: the hazards of the losses that cite it give the route the
hazard and constraint identities a targeted route requires.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan

SKIP_NO_DISPOSITION = "no_risk_disposition"
SKIP_NOT_APPLICABLE = "not_applicable"
SKIP_NO_HAZARD_PATH = "no_hazard_path"


@dataclass(frozen=True)
class GovernancePath:
    """Hazards and governing constraints reached from a risk's cited losses."""

    hazard_ids: tuple[str, ...]
    constraint_ids: tuple[str, ...]


@dataclass(frozen=True)
class GovernanceSelection:
    """The governance risks to route and the reason every other one is not."""

    risk_ids: tuple[str, ...] = ()
    paths: dict[str, GovernancePath] = field(default_factory=dict)
    skipped: dict[str, str] = field(default_factory=dict)


def select_governance_risks(
    plan: TaxonomyObligationPlan, loss_analysis: Any
) -> GovernanceSelection:
    """Pick the governance-only risks that the final loss analysis cites."""
    dispositions = {item.risk_ref: item for item in loss_analysis.risk_dispositions}
    risk_ids: list[str] = []
    paths: dict[str, GovernancePath] = {}
    skipped: dict[str, str] = {}
    for row in plan.obligations:
        if row.scope_disposition != "governance_only":
            continue
        risk_id = row.risk_ref.risk_id
        reason = _skip_reason(dispositions.get(risk_id))
        path = None if reason else _path(dispositions[risk_id], loss_analysis)
        if reason is None and path is None:
            reason = SKIP_NO_HAZARD_PATH
        if reason is not None:
            skipped[risk_id] = reason
            continue
        risk_ids.append(risk_id)
        paths[risk_id] = path
    return GovernanceSelection(tuple(sorted(risk_ids)), paths, skipped)


def _skip_reason(disposition: Any) -> str | None:
    if disposition is None:
        return SKIP_NO_DISPOSITION
    if disposition.disposition == "not_applicable":
        return SKIP_NOT_APPLICABLE
    return None


def _path(disposition: Any, loss_analysis: Any) -> GovernancePath | None:
    losses = set(disposition.loss_ids)
    hazards = tuple(
        sorted(
            item.hazard_id
            for item in loss_analysis.hazards
            if losses.intersection(item.related_losses)
        )
    )
    constraints = tuple(
        sorted(
            item.constraint_id
            for item in loss_analysis.security_constraints
            if set(hazards).intersection(item.related_hazards)
        )
    )
    if not hazards or not constraints:
        return None
    return GovernancePath(hazards, constraints)
