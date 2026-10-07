"""Typed validation issues for the Stage 5 draft checks.

A check that rejects a draft raises :class:`ValidationIssueError` with one
:class:`IssueCode`.  The correction request reads the codes from the error
that was raised, so it names guidance only for failures that happened.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm_helpers import ExactFeedbackError


class IssueCode(StrEnum):
    """Stable code of one Stage 5 validation failure."""

    missing_unsafe_proposition = "missing_unsafe_proposition"
    missing_temporal_branch_field = "missing_temporal_branch_field"
    incomplete_evidence_status_branch = "incomplete_evidence_status_branch"
    observation_command_attempt_operation_missing = (
        "observation_command_attempt_operation_missing"
    )
    observation_operation_not_in_inventory = "observation_operation_not_in_inventory"
    discriminating_condition_missing = "discriminating_condition_missing"
    discriminating_condition_check_failed = "discriminating_condition_check_failed"
    discriminating_condition_operand_mismatch = (
        "discriminating_condition_operand_mismatch"
    )
    discriminating_condition_literal_unsupported = (
        "discriminating_condition_literal_unsupported"
    )
    discriminating_condition_operation_mismatch = (
        "discriminating_condition_operation_mismatch"
    )
    discriminating_condition_order_unscoped = "discriminating_condition_order_unscoped"
    safe_outcome_record_ref_not_supplied = "safe_outcome_record_ref_not_supplied"
    safe_outcome_observability_mismatch = "safe_outcome_observability_mismatch"
    intention_handle_undeclared = "intention_handle_undeclared"
    mechanism_source_mismatch = "mechanism_source_mismatch"
    no_content_surface = "no_content_surface"


# The codes of a condition that failed a check, in the order the publication
# note prefers them when one attempt raised several.
CONDITION_FAILURE_CODES = (
    IssueCode.discriminating_condition_check_failed,
    IssueCode.discriminating_condition_operand_mismatch,
    IssueCode.discriminating_condition_literal_unsupported,
    IssueCode.discriminating_condition_operation_mismatch,
    IssueCode.discriminating_condition_order_unscoped,
)


@dataclass(frozen=True)
class ValidationIssue:
    """One failed check: its code and the exact detail for the model."""

    code: IssueCode
    detail: str

    def __str__(self) -> str:
        return f"{self.code.value}: {self.detail}"


class ValidationIssueError(ValueError):
    """A draft check failure that carries its :class:`ValidationIssue`."""

    def __init__(self, code: IssueCode, detail: str) -> None:
        self.issue = ValidationIssue(code, detail)
        super().__init__(str(self.issue))


class ExactIssueError(ValidationIssueError, ExactFeedbackError):
    """An issue whose itemized detail reaches the model with its line breaks."""


# Fields whose schema failure has its own repair guidance.  A response model
# rejects these through its discriminated unions, which no check code can
# annotate, so the field path in the error names the failure.
_SCHEMA_FIELD_CODES: dict[str | int, IssueCode] = {
    "temporal_condition": IssueCode.missing_temporal_branch_field,
    "evidence_status": IssueCode.incomplete_evidence_status_branch,
    "capability_refs": IssueCode.incomplete_evidence_status_branch,
    "access_refs": IssueCode.incomplete_evidence_status_branch,
    "bounded_assumption": IssueCode.incomplete_evidence_status_branch,
    "semantic_proposition": IssueCode.missing_unsafe_proposition,
}


def issues_of(error: BaseException | None) -> tuple[ValidationIssue, ...]:
    """Return the issues an error carries.

    A check error carries its own issue, also inside the model error that
    wraps it.  A model error on a field with repair guidance carries the
    issue of that field.
    """
    if isinstance(error, ValidationIssueError):
        return (error.issue,)
    if isinstance(error, ValidationError):
        found = (
            _issue_of_item(item)
            for item in error.errors(include_url=False, include_input=False)
        )
        return tuple(issue for issue in found if issue is not None)
    return ()


def _issue_of_item(item: dict) -> ValidationIssue | None:
    """Return the issue behind one model error item, if it has one."""
    cause = item.get("ctx", {}).get("error")
    if isinstance(cause, ValidationIssueError):
        return cause.issue
    for part in item["loc"]:
        if part in _SCHEMA_FIELD_CODES:
            return ValidationIssue(_SCHEMA_FIELD_CODES[part], item["msg"])
    return None
