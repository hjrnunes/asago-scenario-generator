"""Context coverage for reply slots that depend on what a source supplies.

A reply limited to what a source supplies can break its constraint in two
contexts: the source supplies an applicable answer and the reply departs from
it, or the source supplies none and the reply states one anyway.  When a reply
action references a process-model variable that a source updates, its context
table already separates those contexts.  Models often analyze only one of them.

Code finds the gap from typed fields alone: an ``INCORRECT`` slot of a reply
action (``effect_kind: model_output``) whose findings for one constraint cite a
source-updated variable, yet no finding for that constraint cites a context row
holding some value of the variable.  One bounded supplement call then asks the
model to assess only the uncovered rows; its findings are appended to the
slot, and an empty or failed supplement leaves the slot unchanged.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    FeedbackSourceKind,
    Responsibility,
    control_action_context_rows,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    _TEMPLATE_LOADER,
    _yaml,
)

CONTEXT_COVERAGE_STAGE_SUFFIX = "_context_coverage"

# Only retrieved text is content a reply relays.  Operation results mostly
# carry record state such as ownership or permission, where every value is
# already a distinct authorization context the ordinary table covers.
_SOURCE_KINDS = frozenset({FeedbackSourceKind.retrieved_content})


@dataclass(frozen=True)
class ContextGap:
    """Source values a reply slot's findings for one constraint leave uncovered."""

    gap_id: str
    slot_id: str
    control_action: str
    constraint_id: str
    process_model_id: str
    uncovered_values: tuple[str, ...]
    row_ids: tuple[str, ...]


def _reply_action(
    request: Any, ca_id: str
) -> tuple[Responsibility, ControlAction] | None:
    for responsibility in request.control_structure.responsibilities:
        for action in responsibility.control_actions:
            if action.ca_id == ca_id:
                if action.effect_kind != ControlActionEffectKind.model_output:
                    return None
                return responsibility, action
    return None


def _source_variables(
    responsibility: Responsibility, action: ControlAction
) -> list[tuple[str, tuple[str, ...]]]:
    updated = {
        channel.updates
        for channel in responsibility.feedback_channels
        if channel.source_kind in _SOURCE_KINDS
    }
    parts = {part.pm_id: part for part in responsibility.process_model_parts}
    return [
        (ref, tuple(parts[ref].values))
        for ref in action.process_model_refs
        if ref in updated and ref in parts and len(parts[ref].values) > 1
    ]


def context_coverage_gaps(
    filled_slots: Sequence[Any], request: Any
) -> tuple[ContextGap, ...]:
    """Return the uncovered source contexts of the request's reply slots."""
    slots = {slot.slot_id: slot for slot in request.slots}
    gaps: list[ContextGap] = []
    for drafted in filled_slots:
        context = _reply_slot_context(drafted, slots, request)
        if context is None:
            continue
        slot, variables, rows = context
        for constraint_id in _finding_constraint_ids(drafted):
            findings = [
                f for f in drafted.findings if constraint_id in f.related_constraint_ids
            ]
            for pm_id, values in variables:
                gap = _uncovered_source_context(
                    slot,
                    constraint_id,
                    pm_id,
                    values,
                    findings,
                    rows,
                    gap_number=len(gaps) + 1,
                )
                if gap is not None:
                    gaps.append(gap)
    return tuple(gaps)


def _reply_slot_context(
    drafted: Any, slots: dict[str, Any], request: Any
) -> tuple[Any, list[tuple[str, tuple[str, ...]]], dict[str, dict[str, Any]]] | None:
    """Return a drafted INCORRECT reply slot's source variables and rows."""
    slot = slots.get(drafted.slot_id)
    if slot is None or drafted.is_na or slot.uca_type != UCAType.incorrect:
        return None
    owner = _reply_action(request, slot.control_action)
    if owner is None:
        return None
    variables = _source_variables(*owner)
    if not variables:
        return None
    rows = {
        row.row_id: dict(row.assignments)
        for row in control_action_context_rows(
            request.control_structure, slot.control_action
        )
    }
    return slot, variables, rows


def _finding_constraint_ids(drafted: Any) -> list[str]:
    return list(
        dict.fromkeys(
            constraint_id
            for finding in drafted.findings
            for constraint_id in finding.related_constraint_ids
        )
    )


def _uncovered_source_context(
    slot: Any,
    constraint_id: str,
    pm_id: str,
    values: tuple[str, ...],
    findings: list[Any],
    rows: dict[str, dict[str, Any]],
    *,
    gap_number: int,
) -> ContextGap | None:
    """Return the gap when findings cite ``pm_id`` but miss some of its values."""
    if not any(pm_id in f.process_model_refs for f in findings):
        return None
    covered = {
        rows[f.context_row].get(pm_id) for f in findings if f.context_row in rows
    }
    uncovered = tuple(v for v in values if v not in covered)
    row_ids = tuple(
        row_id
        for row_id, assignment in rows.items()
        if assignment.get(pm_id) in uncovered
    )
    if not (uncovered and row_ids):
        return None
    return ContextGap(
        gap_id=f"context-gap-{gap_number}",
        slot_id=slot.slot_id,
        control_action=slot.control_action,
        constraint_id=constraint_id,
        process_model_id=pm_id,
        uncovered_values=uncovered,
        row_ids=row_ids,
    )


def _gap_view(gap: ContextGap, drafted: Any, request: Any) -> dict[str, Any]:
    responsibility, action = _reply_action(request, gap.control_action)  # type: ignore[misc]
    slot = next(s for s in request.slots if s.slot_id == gap.slot_id)
    part = next(
        p for p in responsibility.process_model_parts if p.pm_id == gap.process_model_id
    )
    constraint = next(
        c
        for c in request.loss_analysis.security_constraints
        if c.constraint_id == gap.constraint_id
    )
    hazards = {h.hazard_id: h for h in request.loss_analysis.hazards}
    rows = {
        row.row_id: dict(row.assignments)
        for row in control_action_context_rows(
            request.control_structure, gap.control_action
        )
    }
    return {
        "gap_id": gap.gap_id,
        "slot_id": gap.slot_id,
        "uca_type": slot.uca_type.value,
        "control_action": {"id": action.ca_id, "description": action.description},
        "constraint_id": constraint.constraint_id,
        "constraint_rule": constraint.rule,
        "hazards": [
            {"id": hazard_id, "description": hazards[hazard_id].description}
            for hazard_id in constraint.related_hazards
            if hazard_id in hazards
        ],
        "source_variable": {
            "id": part.pm_id,
            "description": part.description,
            "uncovered_values": list(gap.uncovered_values),
        },
        "context_rows": [
            {"id": row_id, "assignments": rows[row_id]} for row_id in gap.row_ids
        ],
        "feedback_ids": [channel.fb_id for channel in responsibility.feedback_channels],
        "existing_findings": [
            {"deviation": f.deviation, "context_row": f.context_row}
            for f in drafted.findings
            if gap.constraint_id in f.related_constraint_ids
        ],
    }


def build_context_coverage_prompts(
    *,
    target_id: str,
    gaps: Sequence[ContextGap],
    filled_slots: Sequence[Any],
    request: Any,
) -> tuple[str, str]:
    """Render the supplement prompt for the gaps of one target."""
    drafted = {slot.slot_id: slot for slot in filled_slots}
    views = [_gap_view(gap, drafted[gap.slot_id], request) for gap in gaps]
    system = _TEMPLATE_LOADER.render_prompt("synthesis_ica_context_system.j2")
    user = _TEMPLATE_LOADER.render_prompt(
        "synthesis_ica_context_user.j2",
        target_id=target_id,
        gaps_yaml=_yaml(views),
        gap_count=len(views),
    )
    return system, user


def validate_supplement_entries(
    entries: Sequence[Any], gaps: Sequence[ContextGap]
) -> None:
    """Require one entry per gap and findings confined to the gap's rows."""
    by_id = {gap.gap_id: gap for gap in gaps}
    actual = [entry.gap_id for entry in entries]
    if sorted(actual) != sorted(by_id):
        raise ValueError(
            "context supplement must contain exactly one entry per gap_id "
            f"(expected={sorted(by_id)}, actual={sorted(actual)})"
        )
    for entry in entries:
        gap = by_id[entry.gap_id]
        for finding in entry.findings:
            if finding.context_row not in gap.row_ids:
                raise ValueError(
                    f"{gap.gap_id}: context_row {finding.context_row!r} is not one "
                    f"of the gap's rows {list(gap.row_ids)}"
                )
            if tuple(finding.related_constraint_ids) != (gap.constraint_id,):
                raise ValueError(
                    f"{gap.gap_id}: related_constraint_ids must be "
                    f"[{gap.constraint_id!r}]"
                )


def merge_supplement(
    filled_slots: Sequence[Any], entries: Sequence[Any], gaps: Sequence[ContextGap]
) -> tuple[Any, ...]:
    """Append each entry's findings to its gap's slot, keeping existing ones.

    Findings are appended so existing ``finding_indexes`` stay valid.
    """
    slot_by_gap = {gap.gap_id: gap.slot_id for gap in gaps}
    added: dict[str, list[Any]] = {}
    for entry in entries:
        added.setdefault(slot_by_gap[entry.gap_id], []).extend(entry.findings)
    return tuple(
        slot.model_copy(update={"findings": (*slot.findings, *added[slot.slot_id])})
        if added.get(slot.slot_id)
        else slot
        for slot in filled_slots
    )
