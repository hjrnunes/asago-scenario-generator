"""Targeted Stage 1a repair (owner authorization 2026-09-11, freeze exception).

The former bounded whole-object retry embedded the entire original prompt,
the prior structured object, and the validation feedback in one correction
prompt.  Measured on the two saved 2026-09-11 MiniOcciAI failures those
retry prompts reached 22,214 and 24,490 estimated input tokens against a
21,299-token budget, so the preflight blocked them before dispatch, and a
hypothetical response would also have replaced whole collections
(``list(correction) or list(prior)``), discarding valid rows wholesale.

This module replaces that retry with a narrowly scoped targeted repair for
exactly two approved failure classes:

1. missing or malformed ``risk_dispositions`` entries; and
2. malformed obligation entries within an otherwise preserved constraint.

Contract (owner authorization 2026-09-11):

- Deterministic code selects the repair identities and the permitted fields.
  The response wire carries nothing outside the repair scope, so a response
  cannot rewrite a constraint's rule, conditions, or hazard links, and every
  record outside the scope is preserved byte-identically.
- Duplicate, unknown, unexpected, or out-of-scope identities and edits are
  rejected with a typed reason before the merge.
- The repair prompt carries the evidence needed to decide the correction:
  the affected risk-card text, the declared loss meanings, the affected
  constraint text with its hazard links, and the use-case description.
- The merged draft is re-validated against the complete original inputs with
  the same stage validators that produced the failure; a partial or invalid
  repair is a recorded failure, never a silent partial acceptance.
- Exactly one repair call follows one failed first attempt, and the repair is
  never retried.  Failure classes outside the two approved scopes get an
  explicit typed outcome and no additional model call; this is not a general
  graph-rewriting mechanism.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Union

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    StageError,
    _decode_json_text,
    parse_llm_result,
    safe_llm_call,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysisDraft,
    Obligation,
    RiskDisposition,
    SecurityConstraint,
)

DISPOSITION_REPAIR_SYSTEM_TEMPLATE = "stage1a_disposition_repair_system.j2"
DISPOSITION_REPAIR_USER_TEMPLATE = "stage1a_disposition_repair_user.j2"
OBLIGATION_REPAIR_SYSTEM_TEMPLATE = "stage1a_obligation_repair_system.j2"
OBLIGATION_REPAIR_USER_TEMPLATE = "stage1a_obligation_repair_user.j2"

# Repair steps append this suffix in the durable call log so repair calls are
# individually countable without changing the first-attempt step names.
_REPAIR_STEP_SUFFIX = "_repair"


class RepairRejected(ValueError):
    """Deterministic rejection of an out-of-scope, duplicate, or partial repair.

    The message is the typed reason recorded with the failed repair call.
    """


# ---------------------------------------------------------------------------
# Closed repair wire
# ---------------------------------------------------------------------------


class RepairRiskDisposition(RiskDisposition):
    """One disposition row on the repair wire; no unexpected fields."""

    model_config = ConfigDict(extra="forbid")


class DispositionRepairResponse(BaseModel):
    """The complete risk-disposition repair wire.

    Only the identities deterministic code selected may appear, exactly once
    each; the merge enforces that and preserves every unselected row.
    """

    model_config = ConfigDict(extra="forbid")

    risk_dispositions: list[RepairRiskDisposition] = Field(min_length=1)


class RepairObligation(Obligation):
    """One obligation entry on the repair wire; no unexpected fields."""

    model_config = ConfigDict(extra="forbid")


class RepairObligationConstraint(BaseModel):
    """One selected constraint's obligations; nothing else is on the wire.

    The constraint's ``rule``, ``applies_when``, and ``related_hazards`` are
    deliberately absent, so a repair response cannot rewrite them.
    """

    model_config = ConfigDict(extra="forbid")

    constraint_id: str = Field(min_length=1)
    obligations: list[RepairObligation] = Field(default_factory=list)


class ObligationRepairResponse(BaseModel):
    """The complete obligation-entry repair wire.

    Only the constraints deterministic code selected may appear, exactly once
    each, with their complete obligations collection.
    """

    model_config = ConfigDict(extra="forbid")

    constraints: list[RepairObligationConstraint] = Field(min_length=1)


# ---------------------------------------------------------------------------
# Salvage: deterministic row-level recovery of a wire-invalid response
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SalvageReport:
    """What deterministic salvage kept and dropped from a failed response."""

    dropped_losses: tuple[str, ...] = ()
    dropped_hazards: tuple[str, ...] = ()
    dropped_constraint_fields: tuple[str, ...] = ()
    obligation_constraint_ids: tuple[str, ...] = ()
    dropped_dispositions: tuple[tuple[str, str], ...] = ()
    warnings: tuple[str, ...] = ()

    @property
    def out_of_scope_wire_failures(self) -> tuple[str, ...]:
        """Failures outside the two approved repair classes."""
        return (
            *self.dropped_losses,
            *self.dropped_hazards,
            *self.dropped_constraint_fields,
        )

    def dropped_disposition_reason(self, risk_ref: str) -> str | None:
        """Return the recorded salvage reason for one dropped row, if any."""
        for label, reason in self.dropped_dispositions:
            if label == risk_ref:
                return reason
        return None

    def dropped_disposition_warnings(self) -> tuple[str, ...]:
        """Render the dropped disposition rows as recorded warnings."""
        return tuple(
            f"dropped malformed risk_dispositions row for '{label}': {reason}"
            for label, reason in self.dropped_dispositions
        )


def _row_label(row: object, index: int, id_field: str) -> str:
    """Name a dropped row by its identity when present, else by position."""
    if isinstance(row, dict):
        identity = row.get(id_field)
        if isinstance(identity, str) and identity.strip():
            return identity
    return f"row {index}"


def _salvage_rows(
    rows: Iterable[object],
    model: type[BaseModel],
    id_field: str,
    dropped: list,
    *,
    label_pairs: bool = False,
) -> list[BaseModel]:
    """Keep the rows that validate individually; record the others.

    With ``label_pairs`` the caller receives ``(identity, reason)`` pairs
    (dispositions), so the repair plan can carry the exact salvage reason
    into the prompt; otherwise plain ``"identity: reason"`` strings.
    """
    kept: list[BaseModel] = []
    for index, row in enumerate(rows):
        try:
            kept.append(model.model_validate(row))
        except ValidationError as exc:
            reason = "; ".join(
                f"{'.'.join(str(part) for part in item.get('loc', ())) or 'row'}: "
                f"{item.get('msg', '')}"
                for item in exc.errors()[:3]
            )
            label = _row_label(row, index, id_field)
            if label_pairs:
                dropped.append((label, reason))
            else:
                dropped.append(f"{label}: {reason}")
    return kept


def salvage_provider_response(
    content: dict,
    *,
    constraint_wire_model: type[SecurityConstraint],
) -> tuple[LossAnalysisDraft, SalvageReport]:
    """Recover the valid rows of a wire-invalid Stage 1a response.

    Salvage is deterministic and touches no model: every row is validated
    independently against the same wire models the stage uses, valid rows are
    kept, and dropped rows are recorded with their typed reasons.  A
    constraint whose own fields fail is recorded as out of scope; a constraint
    whose failure is confined to its obligation entries keeps its valid
    entries and joins the obligation repair scope.
    """

    def _rows(name: str) -> list:
        value = content.get(name, [])
        return value if isinstance(value, list) else []

    dropped_losses: list[str] = []
    dropped_hazards: list[str] = []
    dropped_constraint_fields: list[str] = []
    dropped_dispositions: list[tuple[str, str]] = []
    obligation_ids: list[str] = []
    warnings: list[str] = []

    risk_losses = _salvage_rows(
        _rows("risk_card_losses"), Loss, "loss_id", dropped_losses
    )
    use_case_losses = _salvage_rows(
        _rows("use_case_losses"), Loss, "loss_id", dropped_losses
    )
    hazards = _salvage_rows(_rows("hazards"), Hazard, "hazard_id", dropped_hazards)
    dispositions = _salvage_rows(
        _rows("risk_dispositions"),
        RiskDisposition,
        "risk_ref",
        dropped_dispositions,
        label_pairs=True,
    )

    constraints: list[SecurityConstraint] = []
    for index, row in enumerate(_rows("security_constraints")):
        if not isinstance(row, dict):
            dropped_constraint_fields.append(f"row {index}: not an object")
            continue
        try:
            constraints.append(constraint_wire_model.model_validate(row))
            continue
        except ValidationError:
            pass
        # The full constraint failed.  When the constraint without its
        # obligation entries is valid, the failure is confined to the
        # entries and the constraint joins the obligation repair scope.
        bare = {key: value for key, value in row.items() if key != "obligations"}
        try:
            bare_constraint = constraint_wire_model.model_validate(bare)
        except ValidationError as exc:
            reason = "; ".join(
                f"{'.'.join(str(part) for part in item.get('loc', ())) or 'row'}: "
                f"{item.get('msg', '')}"
                for item in exc.errors()[:3]
            )
            dropped_constraint_fields.append(
                f"{_row_label(row, index, 'constraint_id')}: {reason}"
            )
            continue
        obligation_rows = row.get("obligations")
        obligation_rows = obligation_rows if isinstance(obligation_rows, list) else []
        kept_entries: list[Obligation] = []
        entry_reasons: list[str] = []
        for entry_index, entry in enumerate(obligation_rows):
            try:
                kept_entries.append(Obligation.model_validate(entry))
            except ValidationError as exc:
                first = exc.errors()[0]
                entry_reasons.append(
                    f"obligation entry {entry_index}: {first.get('msg', '')}"
                )
        payload = bare_constraint.model_dump(mode="json")
        payload["obligations"] = [
            entry.model_dump(mode="json") for entry in kept_entries
        ]
        try:
            salvaged = SecurityConstraint.model_validate(payload)
        except ValidationError:
            # The retained entries still violate a constraint-level rule
            # (for example duplicated obligation ids), so no entry survives.
            salvaged = SecurityConstraint.model_validate({**payload, "obligations": []})
            entry_reasons = [
                f"obligation entry {entry_index}: dropped; retained entries "
                "violated a constraint-level obligation rule"
                for entry_index in range(len(obligation_rows))
            ]
        constraints.append(salvaged)
        constraint_id = salvaged.constraint_id
        obligation_ids.append(constraint_id)
        warnings.append(
            f"salvaged constraint '{constraint_id}' with its valid obligation "
            f"entries retained and {len(entry_reasons)} malformed entr"
            f"{'y' if len(entry_reasons) == 1 else 'ies'} dropped: "
            + "; ".join(entry_reasons)
            if entry_reasons
            else f"salvaged constraint '{constraint_id}'"
        )

    draft = LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [item.model_dump(mode="json") for item in risk_losses],
            "use_case_losses": [
                item.model_dump(mode="json") for item in use_case_losses
            ],
            "hazards": [item.model_dump(mode="json") for item in hazards],
            "security_constraints": [
                item.model_dump(mode="json") for item in constraints
            ],
            "risk_dispositions": [
                item.model_dump(mode="json") for item in dispositions
            ],
        }
    )
    report = SalvageReport(
        dropped_losses=tuple(dropped_losses),
        dropped_hazards=tuple(dropped_hazards),
        dropped_constraint_fields=tuple(dropped_constraint_fields),
        obligation_constraint_ids=tuple(obligation_ids),
        dropped_dispositions=tuple(dropped_dispositions),
        warnings=tuple(warnings),
    )
    return draft, report


# ---------------------------------------------------------------------------
# Repair plans
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class UnsupportedRepair:
    """An explicit, documented outcome for failure classes outside the scope."""

    reason: str


@dataclass(frozen=True)
class DeterministicCleanup:
    """A salvaged draft that needs no model call.

    The failure reduced to rows deterministic code removed (out-of-contract
    disposition rows on the gap call, or rows referencing unsupplied risk
    cards); the caller re-validates the draft with the full stage validators
    before accepting it.
    """

    draft: LossAnalysisDraft
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class DispositionRepairPlan:
    """One targeted repair of missing or malformed risk-disposition entries."""

    prior: LossAnalysisDraft
    selected: tuple[str, ...]
    reasons: tuple[tuple[str, str], ...]
    removed_unknown: tuple[str, ...]
    salvage_warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class ObligationRepairPlan:
    """One targeted repair of malformed obligation entries."""

    prior: LossAnalysisDraft
    selected: tuple[str, ...]
    reasons: tuple[tuple[str, str], ...]
    salvage_warnings: tuple[str, ...] = ()


RepairPlan = Union[DispositionRepairPlan, ObligationRepairPlan]
RepairOutcome = Union[RepairPlan, UnsupportedRepair, DeterministicCleanup]


def select_disposition_repairs(
    draft: LossAnalysisDraft,
    risk_cards: list[RiskCard],
) -> tuple[tuple[str, ...], tuple[tuple[str, str], ...], tuple[str, ...]]:
    """Select the disposition identities deterministic code allows to change.

    Returns the selected card IDs in supplied order, one reason per selected
    ID, and the unsupplied risk references whose rows deterministic code
    removes.  A selected identity is a supplied card that is missing, double
    counted, or whose row cites losses the response never declared; the merge
    replaces exactly those rows and preserves every other row.
    """
    supplied_ids = [card.risk_id for card in risk_cards]
    supplied = set(supplied_ids)
    declared_losses = {
        loss.loss_id for loss in draft.risk_card_losses + draft.use_case_losses
    }
    counts: dict[str, int] = {}
    undeclared: dict[str, list[str]] = {}
    unknown: set[str] = set()
    for row in draft.risk_dispositions:
        if row.risk_ref not in supplied:
            unknown.add(row.risk_ref)
            continue
        counts[row.risk_ref] = counts.get(row.risk_ref, 0) + 1
        if row.disposition == "cited":
            missing = [
                loss_id for loss_id in row.loss_ids if loss_id not in declared_losses
            ]
            if missing:
                undeclared.setdefault(row.risk_ref, []).extend(missing)

    reasons: dict[str, list[str]] = {}
    for card_id in supplied_ids:
        if counts.get(card_id, 0) == 0:
            reasons.setdefault(card_id, []).append(
                "no risk_dispositions entry was returned for this supplied card"
            )
        elif counts[card_id] > 1:
            reasons.setdefault(card_id, []).append(
                f"{counts[card_id]} duplicate risk_dispositions entries were "
                "returned; exactly one is required"
            )
        if card_id in undeclared:
            reasons.setdefault(card_id, []).append(
                "the cited entry names losses the response never declared: "
                + ", ".join(sorted(set(undeclared[card_id])))
            )
    selected = tuple(card_id for card_id in supplied_ids if card_id in reasons)
    reason_pairs = tuple((card_id, "; ".join(reasons[card_id])) for card_id in selected)
    return selected, reason_pairs, tuple(sorted(unknown))


def _without_unknown_disposition_rows(
    draft: LossAnalysisDraft,
    risk_cards: list[RiskCard],
) -> LossAnalysisDraft:
    """Return a copy whose disposition rows all reference supplied cards.

    Rows referencing unsupplied risk cards are wire-valid but fail the
    deterministic accounting gate, so a cleanup that only records them would
    still fail re-validation.  The cleanup removes them, exactly as the
    disposition merge does for a repaired draft.
    """
    supplied = {card.risk_id for card in risk_cards}
    kept = [row for row in draft.risk_dispositions if row.risk_ref in supplied]
    if len(kept) == len(draft.risk_dispositions):
        return draft
    return draft.model_copy(
        update={"risk_dispositions": [row.model_copy(deep=True) for row in kept]}
    )


def build_repair_plan(
    *,
    step: str,
    response_format: type[LossAnalysisDraft],
    first_result: LLMResult | None,
    first_parse_failed: bool,
    failure_class: str,
    risk_cards: list[RiskCard],
    require_risk_accounting: bool,
    constraint_wire_model: type[SecurityConstraint],
) -> RepairOutcome:
    """Classify one failed Stage 1a attempt and select its repair plan.

    ``failure_class`` is the caller's typed label for the first failure:
    ``wire_schema`` (the response never parsed), ``risk_accounting`` (the
    deterministic accounting validator), ``draft_references``, or
    ``draft_semantics``.  Only the first two can produce a repair, and the
    wire path is further scoped by row-level salvage.
    """
    if first_result is None:
        return UnsupportedRepair("no provider response is available to repair")
    if first_parse_failed:
        content = first_result.content
        if isinstance(content, BaseModel):
            content = content.model_dump(mode="json")
        if isinstance(content, str):
            try:
                content = _decode_json_text(content)
            except ValueError as exc:
                return UnsupportedRepair(
                    f"the response body never decoded as JSON ({exc})"
                )
        if not isinstance(content, dict):
            return UnsupportedRepair(
                "the response body is not a JSON object, so no rows can be salvaged"
            )
        prior, report = salvage_provider_response(
            content, constraint_wire_model=constraint_wire_model
        )
        if report.out_of_scope_wire_failures:
            return UnsupportedRepair(
                "wire violation outside the approved repair scope: "
                + "; ".join(report.out_of_scope_wire_failures)
            )
        if report.obligation_constraint_ids and report.dropped_dispositions:
            return UnsupportedRepair(
                "the response mixes obligation-entry and risk-disposition "
                "wire failures; the targeted repair fixes one class per attempt"
            )
        if report.obligation_constraint_ids:
            selected = tuple(report.obligation_constraint_ids)
            reasons = tuple(
                (
                    constraint_id,
                    "the constraint is otherwise preserved; its malformed "
                    "obligation entries were dropped and must be returned "
                    "corrected",
                )
                for constraint_id in selected
            )
            return ObligationRepairPlan(
                prior=prior,
                selected=selected,
                reasons=reasons,
                salvage_warnings=report.warnings,
            )
        if report.dropped_dispositions:
            warnings = report.dropped_disposition_warnings()
            if step == "gap_analysis":
                # The gap call's contract carries no risk accounting; its
                # disposition rows are out of contract and are removed.
                return DeterministicCleanup(draft=prior, warnings=warnings)
            selected, reason_pairs, removed_unknown = select_disposition_repairs(
                prior, risk_cards
            )
            if not selected and not removed_unknown:
                return UnsupportedRepair(
                    "the salvaged response has no repairable disposition rows"
                )
            if not selected:
                return DeterministicCleanup(
                    draft=_without_unknown_disposition_rows(prior, risk_cards),
                    warnings=(
                        *warnings,
                        f"removed risk_dispositions rows for unsupplied risk "
                        f"references: {', '.join(removed_unknown)}",
                    ),
                )
            enriched_reasons = tuple(
                (
                    card_id,
                    (
                        f"{reason}; the returned row was dropped as malformed: "
                        f"{report.dropped_disposition_reason(card_id)}"
                        if report.dropped_disposition_reason(card_id)
                        else reason
                    ),
                )
                for card_id, reason in reason_pairs
            )
            return DispositionRepairPlan(
                prior=prior,
                selected=selected,
                reasons=enriched_reasons,
                removed_unknown=removed_unknown,
                salvage_warnings=warnings,
            )
        return UnsupportedRepair(
            "the wire failure is not confined to the approved repair scope"
        )

    if failure_class == "risk_accounting":
        if not require_risk_accounting:
            return UnsupportedRepair("risk accounting is not required for this call")
        prior = parse_llm_result(first_result, response_format)
        selected, reason_pairs, removed_unknown = select_disposition_repairs(
            prior, risk_cards
        )
        if not selected and not removed_unknown:
            return UnsupportedRepair(
                "the accounting failure named no repairable disposition rows"
            )
        if not selected:
            return DeterministicCleanup(
                draft=_without_unknown_disposition_rows(prior, risk_cards),
                warnings=(
                    f"removed risk_dispositions rows for unsupplied risk "
                    f"references: {', '.join(removed_unknown)}",
                ),
            )
        return DispositionRepairPlan(
            prior=prior,
            selected=selected,
            reasons=reason_pairs,
            removed_unknown=removed_unknown,
        )
    return UnsupportedRepair(
        f"the {failure_class} failure class is outside the approved repair "
        "scope; no repair call is made"
    )


# ---------------------------------------------------------------------------
# Merges
# ---------------------------------------------------------------------------


def merge_disposition_repair(
    plan: DispositionRepairPlan,
    rows: list[RepairRiskDisposition],
    *,
    risk_cards: list[RiskCard],
) -> LossAnalysisDraft:
    """Apply one validated disposition repair and preserve every other row.

    Rejects duplicate, unknown, out-of-scope, and incomplete responses with a
    typed reason, and rejects cited rows naming losses the prior draft never
    declared.  Unselected rows keep their exact payloads; rows for unsupplied
    risk references are removed deterministically.
    """
    selected = set(plan.selected)
    supplied_order = [card.risk_id for card in risk_cards]
    supplied = set(supplied_order)
    by_ref: dict[str, RepairRiskDisposition] = {}
    for row in rows:
        if row.risk_ref not in selected:
            raise RepairRejected(
                f"unknown or out-of-scope repair identity '{row.risk_ref}'; "
                "only the selected risk cards may be returned"
            )
        if row.risk_ref in by_ref:
            raise RepairRejected(
                f"duplicate repair row for '{row.risk_ref}'; return exactly "
                "one row per selected card"
            )
        by_ref[row.risk_ref] = row
    missing = [ref for ref in plan.selected if ref not in by_ref]
    if missing:
        raise RepairRejected(
            "incomplete repair; no row was returned for: " + ", ".join(missing)
        )
    declared_losses = {
        loss.loss_id
        for loss in plan.prior.risk_card_losses + plan.prior.use_case_losses
    }
    for ref, row in by_ref.items():
        if row.disposition == "cited":
            undeclared = [
                loss_id for loss_id in row.loss_ids if loss_id not in declared_losses
            ]
            if undeclared:
                raise RepairRejected(
                    f"the repair row for '{ref}' cites losses the response "
                    "never declared: " + ", ".join(undeclared)
                )
    kept = {
        row.risk_ref: row
        for row in plan.prior.risk_dispositions
        if row.risk_ref in supplied and row.risk_ref not in selected
    }
    ordered_rows = [
        (kept[card_id] if card_id in kept else by_ref[card_id]).model_copy(deep=True)
        for card_id in supplied_order
        if card_id in kept or card_id in by_ref
    ]
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                item.model_dump(mode="json") for item in plan.prior.risk_card_losses
            ],
            "use_case_losses": [
                item.model_dump(mode="json") for item in plan.prior.use_case_losses
            ],
            "hazards": [item.model_dump(mode="json") for item in plan.prior.hazards],
            "security_constraints": [
                item.model_dump(mode="json") for item in plan.prior.security_constraints
            ],
            "risk_dispositions": [
                item.model_dump(mode="json") for item in ordered_rows
            ],
        }
    )


def merge_obligation_repair(
    plan: ObligationRepairPlan,
    items: list[RepairObligationConstraint],
) -> LossAnalysisDraft:
    """Apply one validated obligation repair and preserve everything else.

    Rejects duplicate, unknown, out-of-scope, and incomplete responses with a
    typed reason.  Every previously valid obligation entry of a selected
    constraint must appear byte-identically, so a repair cannot silently
    rewrite or drop a preserved entry, and the constraint's own rule,
    conditions, and hazard links are never on the wire.
    """
    selected = set(plan.selected)
    by_id: dict[str, RepairObligationConstraint] = {}
    for item in items:
        if item.constraint_id not in selected:
            raise RepairRejected(
                f"unknown or out-of-scope repair identity "
                f"'{item.constraint_id}'; only the selected constraints may "
                "be returned"
            )
        if item.constraint_id in by_id:
            raise RepairRejected(
                f"duplicate repair entry for constraint '{item.constraint_id}'"
            )
        by_id[item.constraint_id] = item
    missing = [ref for ref in plan.selected if ref not in by_id]
    if missing:
        raise RepairRejected(
            "incomplete repair; no obligations were returned for: " + ", ".join(missing)
        )
    prior_by_id = {
        constraint.constraint_id: constraint
        for constraint in plan.prior.security_constraints
    }
    for constraint_id in plan.selected:
        prior_constraint = prior_by_id.get(constraint_id)
        if prior_constraint is None:
            raise RepairRejected(
                f"selected constraint '{constraint_id}' is not present in the "
                "prior draft"
            )
        repaired_payloads = [
            entry.model_dump(mode="json") for entry in by_id[constraint_id].obligations
        ]
        for preserved in prior_constraint.obligations:
            if preserved.model_dump(mode="json") not in repaired_payloads:
                raise RepairRejected(
                    f"the repair for constraint '{constraint_id}' altered or "
                    f"dropped the preserved obligation entry "
                    f"{preserved.obligation_id}; preserved entries must be "
                    "returned byte-identically"
                )
    merged_constraints: list[dict] = []
    for constraint in plan.prior.security_constraints:
        if constraint.constraint_id not in selected:
            merged_constraints.append(constraint.model_dump(mode="json"))
            continue
        payload = constraint.model_dump(mode="json")
        payload["obligations"] = [
            entry.model_dump(mode="json")
            for entry in by_id[constraint.constraint_id].obligations
        ]
        merged_constraints.append(payload)
    return LossAnalysisDraft.model_validate(
        {
            "risk_card_losses": [
                item.model_dump(mode="json") for item in plan.prior.risk_card_losses
            ],
            "use_case_losses": [
                item.model_dump(mode="json") for item in plan.prior.use_case_losses
            ],
            "hazards": [item.model_dump(mode="json") for item in plan.prior.hazards],
            "security_constraints": merged_constraints,
            "risk_dispositions": [
                item.model_dump(mode="json") for item in plan.prior.risk_dispositions
            ],
        }
    )


# ---------------------------------------------------------------------------
# One repair call
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _RepairValidation:
    """The callables one repaired draft must pass through before acceptance."""

    run_validators: Callable[[LossAnalysisDraft], None]
    normalizer: Callable[[LossAnalysisDraft], list[str]]
    authoritative_merge: Callable[[LossAnalysisDraft], LossAnalysisDraft] | None
    normalization_warnings: list[str] | None


def _record_warnings(
    warnings: Iterable[str],
    normalization_warnings: list[str] | None,
) -> None:
    for warning in warnings:
        if normalization_warnings is not None and warning not in normalization_warnings:
            normalization_warnings.append(warning)


def _finish_merged_draft(
    merged: LossAnalysisDraft,
    validation: _RepairValidation,
) -> LossAnalysisDraft:
    """Normalize, merge authority, and fully validate one repaired draft."""
    for warning in validation.normalizer(merged):
        _record_warnings((warning,), validation.normalization_warnings)
    if validation.authoritative_merge is not None:
        merged = validation.authoritative_merge(merged)
    validation.run_validators(merged)
    return merged


def run_targeted_repair(
    plan: RepairPlan,
    *,
    llm_client: LLMClient,
    loader: TemplateLoader,
    run_dir: Path,
    step: str,
    temperature: float,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_validators: Callable[[LossAnalysisDraft], None],
    normalizer: Callable[[LossAnalysisDraft], list[str]],
    authoritative_merge: Callable[[LossAnalysisDraft], LossAnalysisDraft] | None = None,
    normalization_warnings: list[str] | None = None,
    max_completion_tokens: int = 8192,
) -> LossAnalysisDraft:
    """Make exactly one targeted repair call and return the re-validated draft.

    The repair prompt is preflighted by the shared call wrapper, so an
    oversized repair fails closed before dispatch.  Any rejection or
    validation failure raises :class:`StageError`; the repair is never
    retried.
    """
    validation = _RepairValidation(
        run_validators=run_validators,
        normalizer=normalizer,
        authoritative_merge=authoritative_merge,
        normalization_warnings=normalization_warnings,
    )
    # The deterministic salvage that produced this plan is recorded evidence:
    # it names exactly which rows or entries were dropped before the repair.
    _record_warnings(plan.salvage_warnings, normalization_warnings)
    if isinstance(plan, DispositionRepairPlan):
        system_prompt = loader.render_prompt(DISPOSITION_REPAIR_SYSTEM_TEMPLATE)
        user_prompt = loader.render_prompt(
            DISPOSITION_REPAIR_USER_TEMPLATE,
            use_case_text=use_case_text,
            selected_cards=_selected_card_views(plan, risk_cards),
            declared_losses=_declared_loss_views(plan.prior),
            reasons=plan.reasons,
        )
        response_format: type[BaseModel] = DispositionRepairResponse

        def parse_disposition_repair(result: LLMResult) -> LossAnalysisDraft:
            response = parse_llm_result(result, DispositionRepairResponse)
            merged = merge_disposition_repair(
                plan, list(response.risk_dispositions), risk_cards=risk_cards
            )
            return _finish_merged_draft(merged, validation)

        draft, _, error_msg = safe_llm_call(
            llm_client=llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            run_dir=run_dir,
            stage="stage_1a",
            step=step + _REPAIR_STEP_SUFFIX,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
            result_parser=parse_disposition_repair,
        )
    else:
        system_prompt = loader.render_prompt(OBLIGATION_REPAIR_SYSTEM_TEMPLATE)
        user_prompt = loader.render_prompt(
            OBLIGATION_REPAIR_USER_TEMPLATE,
            use_case_text=use_case_text,
            selected_constraints=_selected_constraint_views(plan),
            reasons=plan.reasons,
        )
        response_format = ObligationRepairResponse

        def parse_obligation_repair(result: LLMResult) -> LossAnalysisDraft:
            response = parse_llm_result(result, ObligationRepairResponse)
            merged = merge_obligation_repair(plan, list(response.constraints))
            return _finish_merged_draft(merged, validation)

        draft, _, error_msg = safe_llm_call(
            llm_client=llm_client,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            response_format=response_format,
            run_dir=run_dir,
            stage="stage_1a",
            step=step + _REPAIR_STEP_SUFFIX,
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
            result_parser=parse_obligation_repair,
        )
    if error_msg is not None or draft is None:
        raise StageError(
            stage="stage_1a",
            step=step,
            message=f"targeted repair failed: {error_msg}",
        )
    return draft


def _selected_card_views(
    plan: DispositionRepairPlan,
    risk_cards: list[RiskCard],
) -> list[dict]:
    """The full text of every selected risk card, in supplied order."""
    selected = set(plan.selected)
    return [
        {
            "risk_id": card.risk_id,
            "risk_name": card.risk_name,
            "risk_description": card.risk_description,
            "consequence": card.consequence,
        }
        for card in risk_cards
        if card.risk_id in selected
    ]


def _declared_loss_views(draft: LossAnalysisDraft) -> list[dict]:
    """The declared loss registry with its meanings."""
    return [
        {
            "loss_id": loss.loss_id,
            "description": loss.description,
            "provenance": loss.provenance.value,
            "source_risk_cards": loss.source_risk_cards,
        }
        for loss in draft.risk_card_losses + draft.use_case_losses
    ]


def _selected_constraint_views(plan: ObligationRepairPlan) -> list[dict]:
    """The full text of every selected constraint with its loss meanings."""
    selected = set(plan.selected)
    losses_by_id = {
        loss.loss_id: loss
        for loss in plan.prior.risk_card_losses + plan.prior.use_case_losses
    }
    hazards_by_id = {hazard.hazard_id: hazard for hazard in plan.prior.hazards}
    views: list[dict] = []
    for constraint in plan.prior.security_constraints:
        if constraint.constraint_id not in selected:
            continue
        related_loss_meanings: list[dict] = []
        for hazard_id in constraint.related_hazards:
            hazard = hazards_by_id.get(hazard_id)
            if hazard is None:
                continue
            for loss_id in hazard.related_losses:
                loss = losses_by_id.get(loss_id)
                if loss is not None:
                    related_loss_meanings.append(
                        {
                            "loss_id": loss.loss_id,
                            "description": loss.description,
                            "via_hazard": hazard.hazard_id,
                        }
                    )
        views.append(
            {
                "constraint_id": constraint.constraint_id,
                "rule": constraint.rule,
                "applies_when": constraint.applies_when,
                "related_hazards": [
                    {
                        "hazard_id": hazard.hazard_id,
                        "description": hazard.description,
                    }
                    for hazard in (
                        hazards_by_id.get(hazard_id)
                        for hazard_id in constraint.related_hazards
                    )
                    if hazard is not None
                ],
                "related_loss_meanings": related_loss_meanings,
                "preserved_entries": [
                    entry.model_dump(mode="json", exclude_none=True)
                    for entry in constraint.obligations
                ],
            }
        )
    return views
