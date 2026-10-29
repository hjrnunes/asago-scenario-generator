"""Choose an ICA's condition-family hint from its stated reason.

An INCORRECT ICA says why the action is unsafe: its ``deviation`` (or, when
that is absent, its ICA text), usually one value of the context row it
cites. The hint for the ICA's Stage 5 candidates is chosen from that reason,
never by position in its slot, so several ICAs of one slot may get the same
family and an ICA whose reason names no family gets none. The model still
authors the condition and may decline the hint.

The reason variable is the cited row's variable whose value the reason
states (whole words, longest value first). ``REASON_FAMILY_RULES`` is the
mapping; the first rule that matches decides:

1. ``timing_slot``: a WRONG_TIMING ICA keeps the first ``prior_read``
   family whatever its reason (applied by the slot type, not here).
2. ``ownership_reason``: the reason variable is read from a ``session:``
   reference, or the reason names an owner, identity, actor, session, party,
   principal or membership term -> ``ownership``. When the operation offers
   no ownership family the ICA gets no hint; it does not fall through.
3. ``reason_variable_field``: the reason variable is read from a ``state:``
   field that a family of the operation cites -> that family's kind
   (``ownership``, ``flag``, ``bound``, ``state`` in that order).
4. ``reason_terms``: the reason names a limit term -> ``bound``; else an
   eligibility term -> ``flag``; else a lifecycle value -> ``state``.
5. ``no_match``: no hint; the ICA keeps one plain candidate. Intent reasons
   ("does not match authorized intent", "intent unknown", "unauthorized
   transaction") name no family term and take this path.

Context guard: ``ownership`` is never chosen when another variable of the
cited row already says the record belongs to the session principal: a
variable about the record's ownership (read from a ``state:`` field, and
either also from a ``session:`` reference or with an owner, belonging, party
or membership term in its description or value) whose value has no negation
term. An ownership test would contradict the ICA's own context, so the rules
continue without ownership and the ICA gets what rules 3-5 give, or no hint.
A variable that only describes the session principal ("authenticated actor
is the guest", "authorized for target records") does not guard.

The term lists below are the only lexical matching; everything else is exact
lookup.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from asago_scenario_generator.stpa.models.control_structure import (
    control_action_context_rows,
)

from .condition_index import record_field_label

if TYPE_CHECKING:
    from .condition_family import ConditionFamily, FamilyKind


@dataclass(frozen=True)
class ReasonRule:
    """One row of the reason-to-family mapping."""

    name: str
    kinds: tuple[str, ...]
    meaning: str


REASON_FAMILY_RULES: tuple[ReasonRule, ...] = (
    ReasonRule(
        "timing_slot",
        ("prior_read",),
        "A WRONG_TIMING ICA keeps the first prior-read family.",
    ),
    ReasonRule(
        "ownership_reason",
        ("ownership",),
        "The reason variable reads the session, or the reason names an "
        "ownership, identity, actor, session or party term.",
    ),
    ReasonRule(
        "reason_variable_field",
        ("ownership", "flag", "bound", "state"),
        "A family cites the state field the reason variable is read from.",
    ),
    ReasonRule(
        "reason_terms",
        ("bound", "flag", "state"),
        "The reason names a limit, eligibility or lifecycle term.",
    ),
    ReasonRule("no_match", (), "No rule matches: no hint."),
)

OWNERSHIP_TERMS = frozenset(
    {
        "owner",
        "owners",
        "owned",
        "owns",
        "ownership",
        "belong",
        "belongs",
        "belonging",
        "identity",
        "identities",
        "actor",
        "actors",
        "session",
        "authenticated",
        "unauthenticated",
        "party",
        "parties",
        "principal",
        "member",
        "membership",
    }
)
# The subset that names a record's relation to a principal, read by the
# context guard; identity and session words alone do not.
RELATION_TERMS = frozenset(
    {
        "owner",
        "owners",
        "owned",
        "owns",
        "ownership",
        "belong",
        "belongs",
        "belonging",
        "party",
        "parties",
        "member",
        "membership",
    }
)
_KIND_TERMS: tuple[tuple[FamilyKind, frozenset[str]], ...] = (
    (
        "bound",
        frozenset(
            {
                "amount",
                "amounts",
                "balance",
                "limit",
                "limits",
                "exceed",
                "exceeds",
                "exceeded",
                "exceeding",
                "greater",
                "less",
                "maximum",
                "minimum",
                "threshold",
                "quantity",
                "total",
                "remaining",
                "price",
            }
        ),
    ),
    (
        "flag",
        frozenset(
            {
                "allowed",
                "disallowed",
                "eligible",
                "ineligible",
                "eligibility",
                "enabled",
                "disabled",
                "permitted",
                "flag",
                "flagged",
            }
        ),
    ),
    (
        "state",
        frozenset(
            {
                "pending",
                "cancelled",
                "canceled",
                "completed",
                "closed",
                "expired",
                "archived",
                "shipped",
                "delivered",
                "refunded",
                "paid",
                "unpaid",
                "draft",
                "suspended",
                "inactive",
            }
        ),
    ),
)
NEGATION_TERMS = frozenset(
    {
        "not",
        "no",
        "non",
        "none",
        "neither",
        "nor",
        "another",
        "other",
        "different",
        "unknown",
        "unauthorized",
        "unauthorised",
        "unauthenticated",
        "unverified",
        "invalid",
        "mismatch",
        "mismatched",
        "without",
        "false",
        "unrelated",
        "unlinked",
        "unowned",
        "foreign",
        "outside",
    }
)
_SESSION_PREFIX = "session:"
_STATE_PREFIX = "state:"
_WORD = re.compile(r"[a-z0-9]+")


@dataclass(frozen=True)
class ContextVariable:
    """One process-model variable of a cited row and the value it holds."""

    pm_id: str
    description: str | None
    value: str
    evidence_refs: tuple[str, ...] = ()


@dataclass(frozen=True)
class CitedContextRow:
    """The context-table row an ICA cites, resolved by its ID."""

    row_id: str | None
    variables: tuple[ContextVariable, ...]

    def prompt_view(self) -> list[dict[str, object]]:
        """Return the exact row values for Stage 5, without bookkeeping IDs."""
        view = []
        for variable in self.variables:
            item: dict[str, object] = {}
            if variable.description is not None:
                item["variable"] = variable.description
            item["value"] = variable.value
            item["evidence_refs"] = list(variable.evidence_refs)
            view.append(item)
        return view


@dataclass(frozen=True)
class IcaReason:
    """An ICA's stated reason and the context row it cites."""

    reason: str
    row: CitedContextRow | None = None


@dataclass(frozen=True)
class ReasonFamilyChoice:
    """The family kind a reason selects, and the rule that selected it."""

    kind: FamilyKind | None
    rule: str
    reason_variable: str | None = None
    ownership_guarded: bool = False
    # Labels of the state fields the reason variable is read from; families
    # of the kind that cite one are preferred.
    field_labels: tuple[str, ...] = ()

    def as_log(self) -> dict[str, object]:
        """Return the plain mapping written to the family sidecar."""
        return {
            "kind": self.kind,
            "rule": self.rule,
            "reason_variable": self.reason_variable,
            "ownership_guarded": self.ownership_guarded,
        }


TIMING_CHOICE = ReasonFamilyChoice(kind="prior_read", rule="timing_slot")


def reason_terms(text: str) -> tuple[str, ...]:
    """Return the lower-case words of ``text``, in order."""
    return tuple(_WORD.findall(text.lower()))


def reason_variable(reason: str, row: CitedContextRow | None) -> ContextVariable | None:
    """Return the row variable whose value the reason states, if any."""
    if row is None:
        return None
    text = f" {' '.join(reason_terms(reason))} "
    best: ContextVariable | None = None
    best_length = 0
    for variable in row.variables:
        value = " ".join(reason_terms(variable.value))
        if value and f" {value} " in text and len(value) > best_length:
            best, best_length = variable, len(value)
    return best


def choose_reason_family(
    reason: IcaReason, families: Sequence[ConditionFamily]
) -> ReasonFamilyChoice:
    """Apply ``REASON_FAMILY_RULES`` 2-5 to one INCORRECT ICA."""
    variable = reason_variable(reason.reason, reason.row)
    pm_id = variable.pm_id if variable is not None else None
    labels = _field_labels(variable)
    terms = frozenset(reason_terms(reason.reason))
    guard = _row_says_session_owns(reason.row, variable)
    guarded = False

    if _reads_session(variable) or terms & OWNERSHIP_TERMS:
        if not guard:
            return ReasonFamilyChoice(
                "ownership", "ownership_reason", pm_id, False, labels
            )
        guarded = True
    for kind in ("ownership", "flag", "bound", "state"):
        if not any(
            family.kind == kind and set(family.field_paths) & set(labels)
            for family in families
        ):
            continue
        if kind == "ownership" and guard:
            guarded = True
            continue
        return ReasonFamilyChoice(kind, "reason_variable_field", pm_id, guarded, labels)
    for kind, words in _KIND_TERMS:
        if terms & words:
            return ReasonFamilyChoice(kind, "reason_terms", pm_id, guarded, labels)
    return ReasonFamilyChoice(None, "no_match", pm_id, guarded, labels)


def hinted_families(
    choice: ReasonFamilyChoice, families: Iterable[ConditionFamily]
) -> list[ConditionFamily]:
    """Return the chosen kind's families, narrowed to the reason's fields."""
    if choice.kind is None:
        return []
    of_kind = [family for family in families if family.kind == choice.kind]
    labels = set(choice.field_labels)
    cited = [family for family in of_kind if set(family.field_paths) & labels]
    return cited or of_kind


def ica_reasons(enumeration: Any, control_structure: Any) -> dict[str, IcaReason]:
    """Return each ICA's reason and cited row, keyed by ICA ID.

    The reason is the ICA's ``deviation``, else its ICA text. The row's
    values are the ICA's ``process_model_context``, else the row its
    ``context_row`` names in its control action's context table; each
    variable's description and evidence come from the controller's process
    model. An ICA that cites no row, or a row that table does not hold, has
    no row.
    """
    reasons: dict[str, IcaReason] = {}
    for slot in enumeration.slots:
        parts = _process_model_parts(control_structure, slot.control_action)
        rows: dict[str, tuple[tuple[str, str], ...]] | None = None
        for ica in slot.icas:
            assignments: tuple[tuple[str, str], ...] | None = None
            if ica.process_model_context:
                assignments = _ordered(ica.process_model_context, parts)
            elif ica.context_row is not None:
                if rows is None:
                    rows = {
                        row.row_id: row.assignments
                        for row in control_action_context_rows(
                            control_structure, slot.control_action
                        )
                    }
                assignments = rows.get(ica.context_row)
            row = (
                CitedContextRow(
                    row_id=ica.context_row,
                    variables=tuple(
                        _variable(pm_id, value, parts) for pm_id, value in assignments
                    ),
                )
                if assignments
                else None
            )
            reasons[ica.ica_id] = IcaReason(
                reason=ica.deviation or ica.ica_text, row=row
            )
    return reasons


def _process_model_parts(control_structure: Any, action_id: str) -> Mapping[str, Any]:
    """Return the process-model parts of the controller declaring the action."""
    for responsibility in control_structure.responsibilities:
        if any(action.ca_id == action_id for action in responsibility.control_actions):
            return {part.pm_id: part for part in responsibility.process_model_parts}
    return {}


def _ordered(
    context: Mapping[str, str], parts: Mapping[str, Any]
) -> tuple[tuple[str, str], ...]:
    """Order a process-model context like its controller's variables."""
    known = [(pm_id, context[pm_id]) for pm_id in parts if pm_id in context]
    extra = [(pm_id, value) for pm_id, value in context.items() if pm_id not in parts]
    return (*known, *extra)


def _variable(pm_id: str, value: str, parts: Mapping[str, Any]) -> ContextVariable:
    part = parts.get(pm_id)
    return ContextVariable(
        pm_id=pm_id,
        description=part.description if part is not None else None,
        value=value,
        evidence_refs=tuple(part.evidence_refs) if part is not None else (),
    )


def _reads_session(variable: ContextVariable | None) -> bool:
    return variable is not None and any(
        ref.startswith(_SESSION_PREFIX) for ref in variable.evidence_refs
    )


def _field_labels(variable: ContextVariable | None) -> tuple[str, ...]:
    """Return the record-field labels of the variable's ``state:`` evidence."""
    if variable is None:
        return ()
    labels = []
    for ref in variable.evidence_refs:
        if not ref.startswith(_STATE_PREFIX):
            continue
        collection, _, field_name = ref[len(_STATE_PREFIX) :].partition(".")
        if collection and field_name:
            labels.append(record_field_label(collection, field_name))
    return tuple(labels)


def _row_says_session_owns(
    row: CitedContextRow | None, reason_var: ContextVariable | None
) -> bool:
    """Return whether another row value affirms the session principal's record."""
    if row is None:
        return False
    for variable in row.variables:
        if variable is reason_var:
            continue
        words = frozenset(reason_terms(variable.value))
        about = words | frozenset(reason_terms(variable.description or ""))
        shaped = _field_labels(variable) != () and (
            _reads_session(variable) or bool(about & RELATION_TERMS)
        )
        if shaped and not words & NEGATION_TERMS:
            return True
    return False


__all__ = [
    "NEGATION_TERMS",
    "OWNERSHIP_TERMS",
    "RELATION_TERMS",
    "REASON_FAMILY_RULES",
    "TIMING_CHOICE",
    "CitedContextRow",
    "ContextVariable",
    "IcaReason",
    "ReasonFamilyChoice",
    "ReasonRule",
    "choose_reason_family",
    "hinted_families",
    "ica_reasons",
    "reason_terms",
    "reason_variable",
]
