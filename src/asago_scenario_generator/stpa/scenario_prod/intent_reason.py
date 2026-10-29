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
     classifier" is the action's output, not the user's intent); its value,
     as a whole, is one of ``_INTENT_ONLY_VALUE_FORMS``, a sole failed or
     unknown intent ("does not match authorized intent", "not aligned with
     authorized intent", "intent unknown", "unauthorized transaction"), so
     a value that adds a currency, a timing clause or a transaction context
     does not qualify; and the rest of the reason only names the request
     ("the request", "the requested operation is").
   - ``reason_wording``: the whole reason is one of ``_INTENT_ONLY_FORMS``,
     where the failed or unknown predicate applies to the intent itself: a
     request that does not match, is not aligned or consistent with, is
     inconsistent or misaligned with, or deviates from an intent ("the
     request does not match the customer's authorized intent", "the
     request is inconsistent with the customer's authorized intent", "the
     customer's intent does not match the requested payment operation",
     "the refund is executed without matching the customer's authorized
     intent"), or an unknown intent ("the intent is unknown", "the user
     intent is unknown", "intent unknown"). The intent may be qualified by
     its principal as a noun or a possessive ("the user intent", "the
     guest's intent"). "the intent matches but currency is different" and
     "the classified intent is incorrect" are no such form.

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
# The principals ``_INTENT_PHRASE`` lets qualify an intent, and the words
# that may stand between such a principal and the intent noun.
_INTENT_PRINCIPALS = frozenset({"customer", "user", "guest", "host", "requester"})
_PRINCIPAL_LINKS = frozenset(
    {"s", "authorized", "authorised", "actual", "expressed", "stated", "original"}
)
_TARGET_EVIDENCE_PREFIXES = ("state:", "session:", "argument:", "operation:")
# The intent-only reason forms, over the reason's words joined by spaces
# (``reason_terms``: lower case, "n't" as "not", a possessive as "s").
_DET = r"(?:(?:the|a|an|this) )?"
_INTENT_PHRASE = (
    _DET
    # the principal whose intent it is, as a noun or a possessive
    + r"(?:(?:customer|user|guest|host|requester) (?:s )?|request s )?"
    + r"(?:(?:authorized|authorised|actual|expressed|stated|original) )*"
    + r"(?:intent|intention)"
)
_REQUEST = (
    _DET
    + r"(?:requested )?(?:(?:refund|payment|tool) )?"
    + r"(?:request|operation|call|refund|payment|transaction|action)"
)
_BE = r"(?:(?:is|are|was|were) )?"
# A predicate that states the request and the intent fail to agree.
_MISMATCH = (
    r"(?:"
    + r"(?:(?:does|do|did) )?not (?:match|correspond to|align with|agree with)"
    + rf"|{_BE}not (?:aligned with|consistent with|in line with)"
    + rf"|{_BE}(?:inconsistent with|misaligned with)"
    + r"|(?:deviates|deviate|differs|differ) from"
    + rf"|{_BE}(?:(?:executed|issued|made|performed|invoked|called) )?without matching"
    + r")"
)
# A predicate that states the intent is unknown.
_UNKNOWN = rf"{_BE}(?:unknown|unclear|undetermined|unconfirmed|not known|not clear)"
_INTENT_ONLY_FORMS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(form)
    for form in (
        # "the request does not match the customer's authorized intent",
        # "the request is inconsistent with the customer's authorized intent"
        rf"{_REQUEST} {_MISMATCH} {_INTENT_PHRASE}",
        # "the customer's intent does not match the requested payment operation"
        rf"{_INTENT_PHRASE} {_MISMATCH} {_REQUEST}",
        # "the intent is unknown", "the user intent is unknown", "intent unknown"
        rf"{_INTENT_PHRASE} {_UNKNOWN}",
    )
)
# The forms a cited intent variable's value may take: a whole intent-only
# reason, its predicate alone ("does not match authorized intent"), or an
# unauthorized request, which the variable's description makes an intent.
_INTENT_ONLY_VALUE_FORMS: tuple[re.Pattern[str], ...] = (
    *_INTENT_ONLY_FORMS,
    re.compile(rf"{_MISMATCH} {_INTENT_PHRASE}"),
    re.compile(
        r"(?:(?:an?|the) )?unauthori[sz]ed "
        r"(?:transaction|request|operation|action|payment|refund)"
    ),
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
    """Return whether the reason states a ground Stage 5 can test.

    A principal word that only names whose intent it is ("the guest's
    intent") is no ownership ground; anywhere else it is.
    """
    words = _without_intent_principals(words)
    terms = frozenset(words)
    return (
        bool(terms & reason_family.OWNERSHIP_TERMS)
        or reason_family._principal_auth_failure(words)
        or reason_family._principal_comparison_failure(words)
        or reason_family._limit_failure(words)
        or bool(terms & _FLAG_TERMS)
        or bool(terms & _STATE_TERMS)
    )


def _without_intent_principals(words: Sequence[str]) -> tuple[str, ...]:
    """Return ``words`` without each principal that directly qualifies an intent.

    The principal stands right before the intent noun, or before it past a
    possessive "s" and intent modifiers ("the guest's stated intent").
    """
    kept: list[str] = []
    for index, word in enumerate(words):
        if word in _INTENT_PRINCIPALS:
            following = index + 1
            while following < len(words) and words[following] in _PRINCIPAL_LINKS:
                following += 1
            if following < len(words) and words[following] in _INTENT_NOUNS:
                continue
        kept.append(word)
    return tuple(kept)


def _reads_target(variable: reason_family.ContextVariable) -> bool:
    """Return whether the variable is read from a target fact."""
    return any(
        ref.startswith(_TARGET_EVIDENCE_PREFIXES) for ref in variable.evidence_refs
    )


def _is_failed_user_intent(
    variable: reason_family.ContextVariable, words: Sequence[str]
) -> bool:
    """Return whether the reason states only a failed value of a user-intent variable.

    The description names an intent and no classifier output, the whole
    value is a sole failed or unknown intent, and the reason adds only words
    naming the request.
    """
    described = frozenset(reason_terms(variable.description or ""))
    if not described & _INTENT_NOUNS or described & _CLASSIFIER_TERMS:
        return False
    value = reason_terms(variable.value)
    if not _matches_any(value, _INTENT_ONLY_VALUE_FORMS):
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
    return _matches_any(words, _INTENT_ONLY_FORMS)


def _matches_any(words: Sequence[str], forms: Sequence[re.Pattern[str]]) -> bool:
    """Return whether the words, joined by spaces, fully match one of ``forms``."""
    text = " ".join(words)
    return any(form.fullmatch(text) for form in forms)


__all__ = [
    "INTENT_REASON_CODE",
    "IntentBasis",
    "NotApplicableDisposition",
    "intent_dispositions",
    "recognize_intent_reason",
]
