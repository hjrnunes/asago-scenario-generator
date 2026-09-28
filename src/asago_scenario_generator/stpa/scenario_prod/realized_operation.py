"""Resolve the exact target operation a realization selected for one action."""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetRealizationDisposition,
    TargetRealizationResult,
    TargetRealizationRow,
)


def realized_operation(
    realization: TargetRealizationResult | None,
    action_id: str,
) -> TargetOperationObservation | None:
    """Return the one exact operation already selected for ``action_id``.

    A supported baseline row wins; otherwise a supported target-derived
    operation record for the action is used. Conflicting selections raise.
    """
    if realization is None:
        return None
    row = supported_target_row(realization, action_id)
    if row is None:
        return target_derived_operation(realization, action_id)
    return operation_for_supported_row(realization, row)


def supported_target_row(
    realization: TargetRealizationResult,
    action_id: str,
) -> TargetRealizationRow | None:
    """Return the sole supported baseline row for one control action."""
    rows = tuple(
        row
        for row in realization.rows
        if row.control_action_id == action_id
        and row.disposition is TargetRealizationDisposition.supported
    )
    if not rows:
        return None
    if len(rows) != 1 or rows[0].selected_operation is None:
        raise ValueError("target realization has conflicting supported action rows")
    return rows[0]


def target_derived_operation(
    realization: TargetRealizationResult,
    action_id: str,
) -> TargetOperationObservation | None:
    """Resolve one exact operation for a target-derived control action."""
    derived = tuple(
        record.operation
        for record in realization.operation_records
        if record.target_derived_control_action_id == action_id
        and record.disposition is TargetRealizationDisposition.supported
    )
    if len(derived) > 1:
        raise ValueError("target-derived action has conflicting exact operations")
    if not derived:
        return None
    return derived[0]


def operation_for_supported_row(
    realization: TargetRealizationResult,
    row: TargetRealizationRow,
) -> TargetOperationObservation:
    """Resolve the operation record named by a supported baseline row."""
    selected = row.selected_operation
    if selected is None:  # pragma: no cover - guarded by supported_target_row
        raise ValueError("target realization has no selected supported operation")
    identity = selected.identity
    operations = tuple(
        record.operation
        for record in realization.operation_records
        if record.operation_ref.identity == identity
    )
    if len(operations) != 1:
        raise ValueError(
            "target realization selected operation is not uniquely recorded"
        )
    return operations[0]


__all__ = [
    "operation_for_supported_row",
    "realized_operation",
    "supported_target_row",
    "target_derived_operation",
]
