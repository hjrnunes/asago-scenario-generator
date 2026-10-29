"""Recognize an INCORRECT tool-call ICA whose reason is the user's intent.

Stage 5 writes a tool-call scenario's discriminating condition over the
call's arguments, TARGET-STATE and TARGET-READ fact paths, and literals.
None of them represents what the user asked for, so a reason such as "the
request does not match the customer's authorized intent" or "the intent is
unknown" has no operand to test: the model tests eligibility, amount or
status instead. Code routes such an ICA before Stage 5 to a not-applicable
disposition: its candidate is kept and counted, Stage 5 is not asked, and
no scenario is written.

An ICA is routed only when all of these hold:

1. Its slot is INCORRECT and its control action is a ``tool_call`` (the
   typed effect kind of the control structure). An ICA of any other slot or
   effect kind keeps its path; a WRONG_TIMING ICA is never routed.
2. Its reason (``reason_family.ica_reasons``) states no ground Stage 5 can
   test: no ownership source (an ownership relation, a failed session or
   principal authorization, a failed comparison with the session or a
   principal), no limit failure, and no eligibility or lifecycle term. So
   session, actor, identity and bound reasons keep reaching Stage 5, and so
   does an intent comparison stated beside one of them.
3. The cited row's variable whose value the reason states, if any, has no
   target evidence (no ``state:``, ``session:``, ``argument:`` or
   ``operation:`` reference): a reason read from a target fact is grounded.
4. It is about intent, by one of two bases, the structural one first:

   - ``reason_variable``: that variable's description names the user's
     intent ("intent" or "intention").
   - ``reason_wording``: the reason itself states a failed comparison with
     an intent ("does not match the customer's authorized intent", "the
     customer's intent does not match", "deviates from the authorized
     intent") or an unknown intent ("the intent is unknown", "intent
     unknown"). "intended" and an intent the action produces ("the
     classified intent is incorrect") do not count.

The term lists below are the only lexical matching.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
)

from . import reason_family
from .reason_family import IcaReason, ica_reasons, reason_terms, reason_variable

INTENT_REASON_CODE = "intent_reason_not_groundable"
IntentBasis = Literal["reason_variable", "reason_wording"]

_INCORRECT = "INCORRECT"
_INTENT_NOUNS = frozenset({"intent", "intents", "intention", "intentions"})
# A comparison word that states the failure itself; the negated forms of
# ``reason_family.COMPARISON_TERMS`` ("does not match") count too.
_FAILED_COMPARISON_TERMS = frozenset(
    {
        "mismatch",
        "mismatches",
        "mismatched",
        "inconsistent",
        "different",
        "differs",
        "differ",
        "deviate",
        "deviates",
        "deviating",
    }
)
_UNKNOWN_TERMS = frozenset({"unknown", "unclear", "undetermined", "unconfirmed"})
_TARGET_EVIDENCE_PREFIXES = ("state:", "session:", "argument:", "operation:")
# Words before a comparison word that may negate it ("does not match").
_NEGATION_WINDOW = 3
# Words after a comparison word that may reach its intent noun ("does not
# match the customer's authorized intent": the, customer, s, authorized).
_AFTER_WINDOW = 6
# Words before a comparison word that may hold its intent noun ("the
# customer's intent does not match": intent, does, not).
_BEFORE_WINDOW = 5
_FLAG_TERMS = dict(reason_family._KIND_TERMS)["flag"]
_STATE_TERMS = dict(reason_family._KIND_TERMS)["state"]


@dataclass(frozen=True)
class NotApplicableDisposition:
    """Why code keeps an ICA's candidate out of Stage 5.

    ``reason_code`` is the machine-readable code; ``reason`` states it for a
    reader. ``basis`` names the rule that recognized the ICA and
    ``reason_variable`` the cited row's variable it read, if any.
    """

    reason_code: str
    reason: str
    basis: IntentBasis
    reason_variable: str | None = None

    def as_log(self) -> dict[str, object]:
        """Return the plain mapping written to the testability record."""
        return {
            "reason_code": self.reason_code,
            "basis": self.basis,
            "reason_variable": self.reason_variable,
            "reason": self.reason,
        }


def recognize_intent_reason(
    reason: IcaReason, *, effect_kind: ControlActionEffectKind | None
) -> NotApplicableDisposition | None:
    """Return the disposition of an intent-type INCORRECT ICA, else ``None``.

    ``reason`` is the ICA's reason and cited row, and ``effect_kind`` its
    control action's effect kind; the caller has checked the slot is
    INCORRECT.
    """
    if effect_kind is not ControlActionEffectKind.tool_call:
        return None
    words = reason_terms(reason.reason)
    if _states_another_ground(words):
        return None
    variable = reason_variable(reason.reason, reason.row)
    if variable is not None and _reads_target(variable):
        return None
    if variable is not None and _names_intent(variable):
        return _disposition(reason.reason, "reason_variable", variable.pm_id)
    if _failed_intent_comparison(words) or _unknown_intent(words):
        return _disposition(reason.reason, "reason_wording", None)
    return None


def intent_dispositions(
    enumeration: Any,
    control_structure: Any,
    reasons: Mapping[str, IcaReason] | None = None,
) -> dict[str, NotApplicableDisposition]:
    """Return the disposition of each intent-type INCORRECT ICA, keyed by ICA ID.

    ``reasons`` are the ICAs' reasons by ICA ID; when omitted they are read
    from ``enumeration`` and ``control_structure``.
    """
    if reasons is None:
        reasons = ica_reasons(enumeration, control_structure)
    dispositions: dict[str, NotApplicableDisposition] = {}
    for slot in enumeration.slots:
        if getattr(slot.uca_type, "value", slot.uca_type) != _INCORRECT:
            continue
        effect_kind = _effect_kind(control_structure, slot.control_action)
        for ica in slot.icas:
            reason = reasons.get(ica.ica_id) or IcaReason(reason=ica.ica_text)
            disposition = recognize_intent_reason(reason, effect_kind=effect_kind)
            if disposition is not None:
                dispositions[ica.ica_id] = disposition
    return dispositions


def _effect_kind(
    control_structure: Any, action_id: str
) -> ControlActionEffectKind | None:
    """Return the effect kind of the control action, if the structure declares it."""
    for responsibility in control_structure.responsibilities:
        for action in responsibility.control_actions:
            if action.ca_id == action_id:
                return action.effect_kind
    return None


def _disposition(
    reason: str, basis: IntentBasis, pm_id: str | None
) -> NotApplicableDisposition:
    stated = " ".join(reason.split())
    return NotApplicableDisposition(
        reason_code=INTENT_REASON_CODE,
        reason=(
            f"Not applicable: the reason '{stated}' is the user's intent, which "
            "no tool-call argument, TARGET-STATE or TARGET-READ fact represents, "
            "so no discriminating condition can tell this call from a safe one; "
            "the ICA is kept as analytical and not sent to Stage 5."
        ),
        basis=basis,
        reason_variable=pm_id,
    )


def _states_another_ground(words: Sequence[str]) -> bool:
    """Return whether the reason states a ground Stage 5 can test."""
    terms = frozenset(words)
    return (
        bool(terms & reason_family.OWNERSHIP_TERMS)
        or reason_family._principal_auth_failure(words)
        or reason_family._principal_comparison_failure(words)
        or reason_family._limit_failure(words)
        or bool(terms & _FLAG_TERMS)
        or bool(terms & _STATE_TERMS)
    )


def _reads_target(variable: reason_family.ContextVariable) -> bool:
    """Return whether the variable is read from a target fact."""
    return any(
        ref.startswith(_TARGET_EVIDENCE_PREFIXES) for ref in variable.evidence_refs
    )


def _names_intent(variable: reason_family.ContextVariable) -> bool:
    """Return whether the variable's description names the user's intent."""
    return bool(_INTENT_NOUNS & frozenset(reason_terms(variable.description or "")))


def _failed_intent_comparison(words: Sequence[str]) -> bool:
    """Return whether a failed comparison word has an intent noun beside it."""
    for index, word in enumerate(words):
        if word in reason_family.COMPARISON_TERMS:
            window = words[max(0, index - _NEGATION_WINDOW) : index]
            if not any(w in reason_family.NEGATION_TERMS for w in window):
                continue
        elif word not in _FAILED_COMPARISON_TERMS:
            continue
        after = words[index + 1 : index + 1 + _AFTER_WINDOW]
        before = words[max(0, index - _BEFORE_WINDOW) : index]
        if _INTENT_NOUNS & frozenset((*after, *before)):
            return True
    return False


def _unknown_intent(words: Sequence[str]) -> bool:
    """Return whether an intent noun is stated unknown ("intent is unknown")."""
    for index, word in enumerate(words):
        if word not in _INTENT_NOUNS:
            continue
        near = (*words[max(0, index - 1) : index], *words[index + 1 : index + 3])
        if _UNKNOWN_TERMS & frozenset(near):
            return True
    return False


__all__ = [
    "INTENT_REASON_CODE",
    "IntentBasis",
    "NotApplicableDisposition",
    "intent_dispositions",
    "recognize_intent_reason",
]
