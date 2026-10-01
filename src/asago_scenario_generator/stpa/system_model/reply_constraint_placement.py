"""Place reply-violated security constraints on a responsibility that replies.

Stage 1a records the channel through which each obligation is violated.  A
constraint with an obligation violated through the reply governs what the
system says, so Stage 3 can analyze it only in a slot of a reply action
(``effect_kind: model_output``).  Stage 2 sometimes cites such a constraint
only from a responsibility whose actions are tool calls, for example the
responsibility that retrieves the source the reply should follow, or from no
responsibility at all.  The constraint then reaches no reply slot and no
scenario tests the reply against it.

Code detects the misplacement from typed fields alone.  The existing Stage 2
revision receives one gap per misplaced constraint; after it runs, code
attaches a constraint that is still misplaced to the only responsibility
owning a reply action, and leaves it as a warning when there are several.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
)

WARNING_PREFIX = "stage_2/reply_constraint_placement"


def _reply_actions(responsibility: Responsibility) -> list[str]:
    return [
        action.ca_id
        for action in responsibility.control_actions
        if action.effect_kind == ControlActionEffectKind.model_output
    ]


def _reply_owners(cs: ControlStructure) -> list[Responsibility]:
    return [r for r in cs.responsibilities if _reply_actions(r)]


def _violated_via_reply(constraint: SecurityConstraint) -> bool:
    return any(
        obligation.violated_via == "reply" for obligation in constraint.obligations
    )


def misplaced_reply_constraints(
    cs: ControlStructure, loss_analysis: LossAnalysis
) -> list[str]:
    """Return reply-violated constraint IDs that no reply owner cites.

    A structure without any reply action has nowhere to place them, so it
    reports none.
    """
    owners = {r.resp_id for r in _reply_owners(cs)}
    if not owners:
        return []
    return [
        constraint.constraint_id
        for constraint in loss_analysis.security_constraints
        if _violated_via_reply(constraint)
        and not any(
            constraint.constraint_id in r.security_constraint_refs
            for r in cs.responsibilities
            if r.resp_id in owners
        )
    ]


def _citing(cs: ControlStructure, constraint_id: str) -> list[str]:
    return [
        r.resp_id
        for r in cs.responsibilities
        if constraint_id in r.security_constraint_refs
    ]


def reply_placement_gaps(
    cs: ControlStructure, loss_analysis: LossAnalysis
) -> list[CriticGap]:
    """Describe each misplaced reply constraint as a Stage 2 revision gap."""
    constraints = {c.constraint_id: c for c in loss_analysis.security_constraints}
    owners = _reply_owners(cs)
    reply_targets = ", ".join(
        f"{owner.resp_id} ({', '.join(_reply_actions(owner))})" for owner in owners
    )
    gaps: list[CriticGap] = []
    for constraint_id in misplaced_reply_constraints(cs, loss_analysis):
        rule = constraints[constraint_id].rule
        citing = _citing(cs, constraint_id)
        cited = (
            f"it is cited only by {', '.join(citing)}, whose actions are not replies"
            if citing
            else "no responsibility cites it"
        )
        gaps.append(
            CriticGap(
                gap_type="missing_pm_part",
                description=(
                    f"Deterministic placement check: security constraint "
                    f"{constraint_id} ({rule!r}) has an obligation violated "
                    f"through the system's reply, but {cited}. No reply action "
                    "is analyzed against it."
                ),
                related_attack_path=(
                    f"A reply that breaks {constraint_id} reaches the user through "
                    f"the reply action of {reply_targets}."
                ),
                suggested_remedy=(
                    f"Modify the responsibility that owns the reply action "
                    f"({reply_targets}): add {constraint_id} to its "
                    "security_constraint_refs and a responsibility constraint "
                    "that states the rule for that reply. When the rule limits "
                    "the reply to what a source supplies, also add a process-model "
                    "part for what that source supplies for the request, with one "
                    "value for an applicable answer and one for no applicable "
                    "answer, reference it from the reply action, and add the "
                    "feedback channel that updates it from the source. Keep every "
                    "existing security_constraint_refs entry."
                ),
            )
        )
    return gaps


def with_reply_placement_gaps(
    findings: CriticFindings, cs: ControlStructure, loss_analysis: LossAnalysis
) -> CriticFindings:
    """Append the placement gaps to the critic's gaps for the revision."""
    gaps = reply_placement_gaps(cs, loss_analysis)
    if not gaps:
        return findings
    return findings.model_copy(update={"gaps": [*findings.gaps, *gaps]})


def attach_to_sole_reply_responsibility(
    cs: ControlStructure, loss_analysis: LossAnalysis
) -> tuple[ControlStructure, list[str]]:
    """Cite each still-misplaced reply constraint from the only reply owner.

    The responsibility that owns the only reply action is the one place the
    reply can break the constraint, so the citation is unambiguous.  With
    several reply owners the choice is semantic; code reports it instead.
    """
    misplaced = misplaced_reply_constraints(cs, loss_analysis)
    if not misplaced:
        return cs, []
    owners = _reply_owners(cs)
    if len(owners) != 1:
        names = ", ".join(owner.resp_id for owner in owners)
        return cs, [
            f"{WARNING_PREFIX}: security constraint {constraint_id} is violated "
            "through the reply but no responsibility owning a reply action cites "
            f"it (reply owners: {names})"
            for constraint_id in misplaced
        ]
    [owner] = owners
    revised = cs.model_copy(deep=True)
    for responsibility in revised.responsibilities:
        if responsibility.resp_id == owner.resp_id:
            responsibility.security_constraint_refs = [
                *responsibility.security_constraint_refs,
                *misplaced,
            ]
    return revised, [
        f"{WARNING_PREFIX}: security constraint {constraint_id} is violated "
        "through the reply but no responsibility owning a reply action cited "
        f"it; code added it to {owner.resp_id}, the only one"
        for constraint_id in misplaced
    ]
