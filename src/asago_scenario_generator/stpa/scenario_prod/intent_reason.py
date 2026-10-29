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
2. Its reason (``reason_family.ica_reasons``) states nothing but an intent
   ground. The check is positive and covers the whole reason: anything
   beside the intent (a bound, amount, currency, value, limit, timing or
   order, status, eligibility, ownership, session, actor, identity or
   transaction context) keeps the ICA on the Stage 5 path. As a second
   guard, a reason with an ownership source, a limit failure, or an
   eligibility or lifecycle term of ``reason_family`` is never routed.
3. When the reason states the value of a cited row's variable, that
   variable decides alone: it must have no target evidence (no ``state:``,
   ``session:``, ``argument:`` or ``operation:`` reference; a reason read
   from a target fact is grounded) and pass the ``reason_variable`` basis
   below. The wording basis applies only to a reason that states no row
   value.
4. It is about the user's intent, by one of two bases, the structural one
   first:

   - ``reason_variable``: that variable's description names an intent and
     no classifier output ("the classified intent produced by the
     classifier" is the action's output, not the user's intent); its value
     states a failure (a negation or "unknown": "does not match authorized
     intent", "intent unknown", "unauthorized transaction"); and the rest
     of the reason only names the request ("the request", "the requested
     operation is").
   - ``reason_wording``: the whole reason is one of ``_INTENT_ONLY_FORMS``,
     where the failed or unknown predicate applies to the intent itself: a
     request that does not match, or deviates from, an intent ("the
     request does not match the customer's authorized intent", "the
     customer's intent does not match the requested payment operation",
     "the refund is executed without matching the customer's authorized
     intent"), or an unknown intent ("the intent is unknown", "intent
     unknown"). "the intent matches but currency is different" and "the
     classified intent is incorrect" are no such form.

The term lists and forms below are the only lexical matching.
"""

from __future__ import annotations

import re
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
_UNKNOWN_TERMS = frozenset({"unknown", "unclear", "undetermined", "unconfirmed"})
# A description naming one of these is about an action's classification
# output, not the user's intent.
_CLASSIFIER_TERMS = frozenset(
    {
        "classified",
        "classification",
        "classifications",
        "classifier",
        "classifiers",
        "classify",
        "classifies",
        "categorized",
        "categorised",
        "category",
        "label",
        "labelled",
        "labeled",
        "predicted",
        "prediction",
        "detected",
        "detection",
        "inferred",
        "identified",
        "produced",
        "assigns",
        "assigned",
        "output",
    }
)
# The words a reason may add around an intent variable's value: they name
# only the request ("the request", "the requested operation is").
_FRAME_TERMS = frozenset(
    {
        "the",
        "a",
        "an",
        "this",
        "is",
        "are",
        "request",
        "requested",
        "operation",
        "call",
        "tool",
        "refund",
        "payment",
        "transaction",
        "action",
    }
)
_TARGET_EVIDENCE_PREFIXES = ("state:", "session:", "argument:", "operation:")
# The intent-only reason forms, over the reason's words joined by spaces
# (``reason_terms``: lower case, "n't" as "not", a possessive as "s").
_DET = r"(?:(?:the|a|an|this) )?"
_INTENT_PHRASE = (
    _DET
    + r"(?:(?:customer|user|requester|request) s )?"
    + r"(?:(?:authorized|authorised|actual|expressed|stated|original) )*"
    + r"(?:intent|intention)"
)
_REQUEST = (
    _DET
    + r"(?:requested )?(?:(?:refund|payment|tool) )?"
    + r"(?:request|operation|call|refund|payment|transaction|action)"
)
_FAILS_TO_MATCH = r"(?:does|do|did|is|are) not (?:match|correspond to|align with)"
_INTENT_ONLY_FORMS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(form)
    for form in (
        # "the request does not match the customer's authorized intent"
        rf"{_REQUEST} {_FAILS_TO_MATCH} {_INTENT_PHRASE}",
        # "the customer's intent does not match the requested payment operation"
        rf"{_INTENT_PHRASE} {_FAILS_TO_MATCH} {_REQUEST}",
        # "the request deviates from the customer's actual intent"
        rf"{_REQUEST} (?:deviates|differs) from {_INTENT_PHRASE}",
        # "the refund is executed without matching the customer's authorized intent"
        rf"{_REQUEST} (?:(?:is|are|was|were) )?"
        rf"(?:(?:executed|issued|made|performed|invoked|called) )?"
        rf"without matching {_INTENT_PHRASE}",
        # "the intent is unknown", "intent unknown"
        rf"{_INTENT_PHRASE} (?:(?:is|are) )?(?:unknown|unclear|undetermined|unconfirmed)",
    )
)
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
    if variable is not None:
        # The cited variable the reason states decides alone.
        if _reads_target(variable) or not _is_failed_user_intent(variable, words):
            return None
        return _disposition(reason.reason, "reason_variable", variable.pm_id)
    if _is_intent_only(words):
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


def _is_failed_user_intent(
    variable: reason_family.ContextVariable, words: Sequence[str]
) -> bool:
    """Return whether the reason states only a failed value of a user-intent variable.

    The description names an intent and no classifier output, the value
    states a failure, and the reason adds only words naming the request.
    """
    described = frozenset(reason_terms(variable.description or ""))
    if not described & _INTENT_NOUNS or described & _CLASSIFIER_TERMS:
        return False
    value = reason_terms(variable.value)
    if not frozenset(value) & (reason_family.NEGATION_TERMS | _UNKNOWN_TERMS):
        return False
    frame = _without_run(words, value)
    return frame is not None and frozenset(frame) <= _FRAME_TERMS


def _without_run(words: Sequence[str], run: Sequence[str]) -> tuple[str, ...] | None:
    """Return ``words`` without the first occurrence of ``run``, else ``None``."""
    width = len(run)
    for index in range(len(words) - width + 1):
        if tuple(words[index : index + width]) == tuple(run):
            return (*words[:index], *words[index + width :])
    return None


def _is_intent_only(words: Sequence[str]) -> bool:
    """Return whether the whole reason is one of ``_INTENT_ONLY_FORMS``."""
    text = " ".join(words)
    return any(form.fullmatch(text) for form in _INTENT_ONLY_FORMS)


__all__ = [
    "INTENT_REASON_CODE",
    "IntentBasis",
    "NotApplicableDisposition",
    "intent_dispositions",
    "recognize_intent_reason",
]
