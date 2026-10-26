"""Accounting for mechanism suggestions, kept apart from obligation coverage.

Every ``(mechanism, slot)`` pair of the mechanism library and the final slot
universe gets one row with the single reason it stopped.  A suggestion makes
no coverage claim, so this record never enters obligation accounting and an
obligation's coverage never counts a row of it.

Stop reasons, checked in this order:

1. ``not_proposed``: no join path, filtered or not, reaches the slot with
   this mechanism.
2. ``authority_filtered``: only the unfiltered join reaches it; the authority
   filter dropped every path (``detail`` names why).
3. ``slot_not_analyzed``: the filtered join reaches it, but structure alone
   decides the slot (an ineligible ``WRONG_DURATION``), so no request carries
   it.
4. ``verifier_rejected``: the mechanism verifier judged every path
   ``adjacent_control``.
5. ``verifier_unresolved``: no path was judged ``mechanism_specific``, and at
   least one was ``insufficient_evidence`` or got no verdict.
6. ``over_cap``: verified, but the slot already carried the most suggestions
   it may, earlier in library order.
7. ``prompt_budget_exceeded``: verified and within the cap, but the slot
   request could not carry it within its prompt budget.
8. ``slot_fill_unresolved``: slot filling left it unresolved (``detail``
   names the diagnostic when there is one).
9. ``slot_fill_not_applicable``: slot filling proposed it not applicable.
10. ``ica_verifier_rejected``: slot filling found it, but the independent ICA
    verifier excluded every ICA of the finding (``detail`` names the code).
11. ``finding``: a verified ICA expresses it (``ica_ids``).
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Literal, get_args

from pydantic import Field, model_validator

from asago_scenario_generator.models.canonical import (
    CanonicalYamlMixin,
    ClosedCanonicalModel,
)
from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismSuggestionPath,
)
from asago_scenario_generator.stpa.mechanism_library import (
    MechanismId,
    bundled_mechanism_library,
)

MECHANISM_SUGGESTION_ACCOUNTING_SCHEMA_VERSION = (
    "stpa-mechanism-suggestion-accounting-v1"
)
MECHANISM_SUGGESTION_ACCOUNTING_FILENAME = "mechanism-suggestion-accounting.yaml"

MechanismStopReason = Literal[
    "not_proposed",
    "authority_filtered",
    "slot_not_analyzed",
    "verifier_rejected",
    "verifier_unresolved",
    "over_cap",
    "prompt_budget_exceeded",
    "slot_fill_unresolved",
    "slot_fill_not_applicable",
    "ica_verifier_rejected",
    "finding",
]
STOP_REASONS: tuple[str, ...] = get_args(MechanismStopReason)

PathRelationship = Literal[
    "mechanism_specific", "adjacent_control", "insufficient_evidence", "no_verdict"
]


class MechanismPathVerdict(ClosedCanonicalModel):
    """The verifier's judgement of one proposed path; ``no_verdict`` if none."""

    path: MechanismSuggestionPath
    relationship: PathRelationship
    rationale: str = Field(min_length=1)


class MechanismSuggestionRow(ClosedCanonicalModel):
    """One ``(mechanism, slot)`` pair and the one reason it stopped."""

    mechanism_id: MechanismId
    slot_id: str = Field(min_length=1)
    stop_reason: MechanismStopReason
    suggestion_id: str | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    path_verdicts: tuple[MechanismPathVerdict, ...] = Field(
        default=(), exclude_if=lambda value: not value
    )
    ica_ids: tuple[str, ...] = Field(default=(), exclude_if=lambda value: not value)
    detail: str | None = Field(default=None, exclude_if=lambda value: value is None)


class MechanismSuggestionSummary(ClosedCanonicalModel):
    """Row counts: all rows, and per stop reason (every reason, zero included)."""

    rows: int = Field(ge=0, strict=True)
    stop_reasons: dict[MechanismStopReason, int]


def summarize_mechanism_rows(
    rows: tuple[MechanismSuggestionRow, ...],
) -> MechanismSuggestionSummary:
    """Count the rows by stop reason, in the reasons' fixed order."""
    counts = Counter(row.stop_reason for row in rows)
    return MechanismSuggestionSummary(
        rows=len(rows),
        stop_reasons={reason: counts.get(reason, 0) for reason in STOP_REASONS},
    )


class MechanismSuggestionAccounting(CanonicalYamlMixin, ClosedCanonicalModel):
    """Every ``(mechanism, slot)`` row, ordered by slot then library order."""

    schema_version: Literal["stpa-mechanism-suggestion-accounting-v1"] = (
        MECHANISM_SUGGESTION_ACCOUNTING_SCHEMA_VERSION
    )
    rows: tuple[MechanismSuggestionRow, ...] = ()
    summary: MechanismSuggestionSummary

    @model_validator(mode="after")
    def order_and_reconcile(self) -> "MechanismSuggestionAccounting":
        rank = {
            entry.id: index
            for index, entry in enumerate(bundled_mechanism_library().mechanisms)
        }
        ordered = tuple(
            sorted(self.rows, key=lambda row: (row.slot_id, rank[row.mechanism_id]))
        )
        keys = [(row.mechanism_id, row.slot_id) for row in ordered]
        if len(keys) != len(set(keys)):
            raise ValueError("mechanism accounting must name each pair once")
        object.__setattr__(self, "rows", ordered)
        self.assert_integrity()
        return self

    def assert_integrity(self) -> None:
        """Require the summary to match the rows."""
        if self.summary != summarize_mechanism_rows(self.rows):
            raise ValueError("mechanism suggestion summary does not reconcile")

    @classmethod
    def _load_checked(cls, data: dict[str, Any]) -> "MechanismSuggestionAccounting":
        if data.get("schema_version") != MECHANISM_SUGGESTION_ACCOUNTING_SCHEMA_VERSION:
            raise ValueError(
                f"Unsupported schema version: '{data.get('schema_version')}'"
            )
        return cls.model_validate(data)


__all__ = [
    "MECHANISM_SUGGESTION_ACCOUNTING_FILENAME",
    "MECHANISM_SUGGESTION_ACCOUNTING_SCHEMA_VERSION",
    "STOP_REASONS",
    "MechanismPathVerdict",
    "MechanismStopReason",
    "MechanismSuggestionAccounting",
    "MechanismSuggestionRow",
    "MechanismSuggestionSummary",
    "summarize_mechanism_rows",
]
