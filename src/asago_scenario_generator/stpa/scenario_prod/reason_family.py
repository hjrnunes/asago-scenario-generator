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
2. ``ownership_reason`` -> ``ownership`` when the reason has an ownership
   source, whether or not it also states a limit failure. The sources are:
   an ownership relation (owner, owned, belongs, identity, party, member,
   relationship, association, guest, host); a failed authentication or
   authorization predicated of the session or a principal ("the actor is
   unauthorized", "not authorized for the session", "without an
   authenticated session", "the user is unauthenticated", but not "the
   customer's authorized intent" or "authorized by the customer's order",
   whose object is something else); a failed comparison of the record with
   the session or a principal ("does not match the session customer", "not
   present in the authenticated customer's orders", "other than the
   authenticated actor", "another customer's account", but not a comparison
   with the principal's intent or eligibility); or a failed authorization
   in a reason whose variable is read from a ``session:`` reference. A
   mention of the session or a principal alone is not a source, and neither
   is a missing user confirmation or "another user confirmation" (also
   past a consent modifier: "another user's explicit confirmation"), which
   is consent rather than authentication or a record of the principal's. When the operation offers no ownership family the ICA
   gets no hint; it does not fall through.
3. ``reason_variable_field``: the reason variable is read from a ``state:``
   field that a family of the operation cites -> that family's kind
   (``ownership``, ``flag``, ``bound``, ``state`` in that order). When the
   reason states a limit failure, only ``bound`` may be chosen here, so a
   cited row narrows the bound family but never changes the kind.
4. ``reason_terms``: the reason states a limit failure -> ``bound``; else
   an eligibility term -> ``flag``; else a lifecycle value -> ``state``.
5. ``no_match``: no hint; the ICA keeps one plain candidate. Intent reasons
   ("does not match authorized intent", "intent unknown", "unauthorized
   transaction") have no ownership source and no family term and take this
   path.

Precedence, the same on every rule path and with or without a cited row:
an ownership source wins over a stated limit failure ("the actor is
unauthorized and the amount exceeds the limit" and "the order does not
belong to the authenticated customer and the amount exceeds the balance"
get ``ownership``), because keeping the ownership, identity, actor or
session qualifier is the point and a wrongly withheld ownership hint costs
more. A limit failure (exceeds, over, above, beyond, greater, more, less,
maximum, minimum, limit, cap, remaining, insufficient, threshold...; not
the "over" of "take over") wins only over wording that is not an ownership
source: "the amount exceeds the
session spending limit", where the session merely owns the limit, gets
``bound``. A bare object noun (amount, plan, price) states no limit failure,
so "the requested amount or plan is not authorized by session", a failed
session authorization, takes ``ownership``: the amount and plan are what
was not authorized, not a limit that was broken.

Context guard (off unless a row value affirms ownership): ``ownership`` is
withheld only when another variable of the cited row is read from a
``state:`` field (the record) and its value itself states that the record is
the principal's: a possession statement (belongs to, owned by, owner,
member) naming the principal in the value or read from a ``session:``
reference, or a role statement (a principal "is" or "are" the guest, host,
owner, member or party). A negated value (a negation term, a contracted
"n't", or an un-, non- or dis- prefix such as "unowned") never guards, and
neither does one whose relation is not current: a non-current word (former,
previous, pending, prospective, claimed...) right before an ownership or
role word ("former owner", "pending owner verification", "prospective
member") or right after one, possibly past a verification-type noun ("owner
verification pending", "ownership pending"). The same word elsewhere ("the
requested record belongs to ...", "... as expected") does not qualify the
relation and does not stop the guard. The variable's description does not
count, so a value such as "pending", "unresolved" or "actor is a stranger"
never guards, whatever the variable is about. A wrongly withheld ownership hint costs more than a wrongly dealt
one, so the guard errs towards dealing. When it does withhold, an ownership
test would contradict the ICA's own context; the rules continue without
ownership and the ICA gets what rules 3-5 give, or no hint.

Reason against row: the ICA's reason wins over a guarding row only when the
reason itself denies ownership in one of four affirmative shapes, each
built from an auxiliary and "not" right before the relation (past allowed
adverbs), a role noun that heads its phrase, and a target phrase headed by
the principal: a negated relation ("does not currently belong to", "is not
the host", "not a party", "has no relationship to"); a role noun that is not
the principal ("the widget owner is not the authenticated user"); a
possession verb naming another owner ("belongs to another customer", "held
by someone other than the session customer"); or a record that does not
match or is not the principal ("the order does not match the authenticated
customer identity"), whose subject's head is a record noun, generic or named
by the ICA's row and families, and never a credential. Then the guard is off
and the reason's ownership source deals ``ownership``. Anything else leaves
the cited row in charge, the safe default: a role noun modifying another
noun ("without owner consent", "with no owner authorization"), a negated
requirement ("does not need to match"), a principal's thing as the target
("the authenticated customer's consent", "the user's identity"), a
credential subject ("the password does not match"), a failed authorization
("the actor is unauthorized"), or another principal's act ("edited by
someone other than the session user").

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
        "The reason states an ownership relation, a failed authentication or "
        "authorization of the session or a principal, a failed comparison "
        "with the session or a principal, or a failed authorization read "
        "from the session; this wins over a stated limit failure.",
    ),
    ReasonRule(
        "reason_variable_field",
        ("ownership", "flag", "bound", "state"),
        "A family cites the state field the reason variable is read from; "
        "with a stated limit failure, only a bound family.",
    ),
    ReasonRule(
        "reason_terms",
        ("bound", "flag", "state"),
        "The reason states a limit failure, or names an eligibility or lifecycle term.",
    ),
    ReasonRule("no_match", (), "No rule matches: no hint."),
)

# An ownership relation stated by a reason.
OWNERSHIP_TERMS = frozenset(
    {
        "owner",
        "owners",
        "owned",
        "owns",
        "ownership",
        "belong",
        "belongs",
        "belonged",
        "belonging",
        "identity",
        "identities",
        "party",
        "parties",
        "member",
        "membership",
        "relationship",
        "association",
        "guest",
        "host",
    }
)
SESSION_TERMS = frozenset({"session", "sessions"})
# Words naming the session or a principal a record may belong to.
PRINCIPAL_TERMS = frozenset(
    {
        "actor",
        "actors",
        "customer",
        "customers",
        "user",
        "users",
        "principal",
        "requester",
        "caller",
        "guest",
        "host",
        *SESSION_TERMS,
    }
)
# Authentication and authorization words; failed when negated or prefixed.
AUTH_TERMS = frozenset(
    {
        "authorized",
        "authorised",
        "authorization",
        "authorisation",
        "authenticated",
        "authentication",
        "verified",
        "verification",
    }
)
# A row value affirming the record is the principal's: possession wording,
# or a principal that "is" one of these roles.
POSSESSION_TERMS = frozenset(
    {
        "belong",
        "belongs",
        "belonged",
        "belonging",
        "owned",
        "owns",
        "owner",
        "owners",
        "member",
    }
)
ROLE_TERMS = frozenset({"guest", "host", "owner", "member", "party"})
_COPULAS = frozenset({"is", "are"})
# Words skipped between a failed authorization or comparison word and the
# principal it is predicated of: linking words and principal modifiers.
_LINKS = frozenset(
    {
        "for",
        "by",
        "to",
        "of",
        "with",
        "from",
        "in",
        "than",
        "the",
        "a",
        "an",
        "this",
        "that",
        "its",
        "current",
        "active",
        "authenticated",
        "existing",
    }
)
# Comparison words that fail when negated, and ones that state a failure.
COMPARISON_TERMS = frozenset(
    {
        "match",
        "matches",
        "matching",
        "matched",
        "correspond",
        "corresponds",
        "consistent",
        "present",
        "equal",
        "equals",
        "align",
        "aligns",
        "aligned",
    }
)
FAILED_COMPARISON_TERMS = frozenset(
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
        "other",
        "another",
    }
)
# A relation that is not current does not affirm ownership in the guard;
# these words count only next to an ownership or role word.
UNSETTLED_TERMS = frozenset(
    {
        "former",
        "previous",
        "prior",
        "past",
        "ex",
        "pending",
        "prospective",
        "proposed",
        "potential",
        "future",
        "expected",
        "requested",
        "claimed",
        "alleged",
    }
)
# A principal followed by one of these, past consent modifiers only, names
# the principal's act, not a record of theirs ("another user confirmation",
# "another user's explicit confirmation"): no compared record.
CONSENT_TERMS = frozenset(
    {"confirmation", "confirmations", "approval", "approvals", "consent", "consents"}
)
# Words that may qualify a consent noun between it and the principal
# ("another user's prior written approval"); any other word is the head of
# the principal's noun phrase, such as a record ("another user's account").
CONSENT_MODIFIERS = frozenset(
    {
        "explicit",
        "express",
        "prior",
        "advance",
        "written",
        "verbal",
        "formal",
        "informed",
    }
)
# What a comparison with the principal's intent names; such a reason is an
# intent reason, not an ownership one. A principal's eligibility is likewise
# an attribute, not a record of theirs (see _principal_comparison_failure).
INTENT_TERMS = frozenset({"intent", "intents", "intention", "intentions", "intended"})
_WINDOW = 3
_KIND_TERMS: tuple[tuple[FamilyKind, frozenset[str]], ...] = (
    (
        "bound",
        # A stated limit failure; a bare noun such as amount or price is not.
        frozenset(
            {
                "exceed",
                "exceeds",
                "exceeded",
                "exceeding",
                "over",
                "above",
                "beyond",
                "greater",
                "more",
                "less",
                "fewer",
                "below",
                "maximum",
                "max",
                "minimum",
                "min",
                "limit",
                "limits",
                "cap",
                "capped",
                "remaining",
                "insufficient",
                "threshold",
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
        "never",
    }
)
# An un-, non- or dis- prefix on one of these participles negates it.
_NEGATED_PREFIXES = ("un", "non", "dis")
_AFFIRMATIVE_STEMS = frozenset(
    {
        "owned",
        "authorized",
        "authorised",
        "authenticated",
        "verified",
        "related",
        "linked",
        "matched",
        "assigned",
        "associated",
        "affiliated",
        "confirmed",
    }
)
_SESSION_PREFIX = "session:"
_STATE_PREFIX = "state:"
_WORD = re.compile(r"[a-z0-9]+")
_CONTRACTED_NOT = re.compile(r"n['\u2019]t\b")
_CANNOT = re.compile(r"\bcannot\b")


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
    """Return the lower-case words of ``text``, in order.

    A contracted "n't" and "cannot" read as "not", so "doesn't" gives
    ``("does", "not")``.
    """
    text = _CANNOT.sub("can not", _CONTRACTED_NOT.sub(" not", text.lower()))
    return tuple(_WORD.findall(text))


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
    words = reason_terms(reason.reason)
    terms = frozenset(words)
    guard = _row_says_session_owns(reason.row, variable) and not (
        _reason_denies_ownership(words, _context_record_nouns(reason.row, families))
    )
    guarded = False

    ownership_source = (
        bool(terms & OWNERSHIP_TERMS)
        or _principal_auth_failure(words)
        or _principal_comparison_failure(words)
        or (_reads_session(variable) and _auth_failure(words))
    )
    if ownership_source:
        if not guard:
            return ReasonFamilyChoice(
                "ownership", "ownership_reason", pm_id, False, labels
            )
        guarded = True
    limit = _limit_failure(words)
    field_kinds = ("bound",) if limit else ("ownership", "flag", "bound", "state")
    for kind in field_kinds:
        if not any(
            family.kind == kind and set(family.field_paths) & set(labels)
            for family in families
        ):
            continue
        if kind == "ownership" and guard:
            guarded = True
            continue
        return ReasonFamilyChoice(kind, "reason_variable_field", pm_id, guarded, labels)
    for kind, kind_terms in _KIND_TERMS:
        if limit if kind == "bound" else terms & kind_terms:
            return ReasonFamilyChoice(kind, "reason_terms", pm_id, guarded, labels)
    return ReasonFamilyChoice(None, "no_match", pm_id, guarded, labels)


_LIMIT_TERMS = dict(_KIND_TERMS)["bound"]
# A form of "take" right before "over" names a takeover, not a limit.
_TAKE_FORMS = frozenset({"take", "takes", "taking", "took", "taken"})
_RELATION_WORDS = POSSESSION_TERMS | ROLE_TERMS | {"ownership", "membership"}
_RELATION_NOUNS = frozenset({"verification", "confirmation", "approval", "check"})
_ATTRIBUTE_TERMS = INTENT_TERMS | dict(_KIND_TERMS)["flag"]


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

    The reason is the ICA's ``deviation``, else its ICA text. An ICA with a
    ``context_row`` has a row: its values are the ICA's
    ``process_model_context``, else that row of its control action's context
    table; each variable's description and evidence come from the
    controller's process model. An ICA that cites no row ID (even one with a
    process-model context), or a row that table does not hold, has no row.
    """
    reasons: dict[str, IcaReason] = {}
    for slot in enumeration.slots:
        parts = _process_model_parts(control_structure, slot.control_action)
        rows: dict[str, tuple[tuple[str, str], ...]] | None = None
        for ica in slot.icas:
            # A process-model context alone cites no row.
            assignments: tuple[tuple[str, str], ...] | None = None
            if ica.context_row is not None and ica.process_model_context:
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
        if _field_labels(variable) and _affirms_ownership(variable):
            return True
    return False


def _affirms_ownership(variable: ContextVariable) -> bool:
    """Return whether the value itself states the record is the principal's."""
    words = reason_terms(variable.value)
    terms = frozenset(words)
    if _negated(terms) or _relation_not_current(words):
        return False
    if terms & POSSESSION_TERMS and (
        terms & PRINCIPAL_TERMS or _reads_session(variable)
    ):
        return True
    return any(
        word in PRINCIPAL_TERMS
        and index + 1 < len(words)
        and words[index + 1] in _COPULAS
        and bool(set(words[index + 2 : index + 2 + _WINDOW + 1]) & ROLE_TERMS)
        for index, word in enumerate(words)
    )


def _relation_not_current(words: Sequence[str]) -> bool:
    """Return whether a non-current word qualifies an ownership or role word.

    It stands right before the relation word ("former owner"), right after it
    ("guest, pending"), or after it past one verification-type noun ("owner
    verification pending").
    """
    for index, word in enumerate(words):
        if word not in _RELATION_WORDS:
            continue
        if index > 0 and words[index - 1] in UNSETTLED_TERMS:
            return True
        following = list(words[index + 1 : index + 3])
        if following[:1] and following[0] in UNSETTLED_TERMS:
            return True
        if (
            len(following) == 2
            and following[0] in _RELATION_NOUNS
            and following[1] in UNSETTLED_TERMS
        ):
            return True
    return False


def _reason_denies_ownership(
    words: Sequence[str], record_nouns: frozenset[str] = frozenset()
) -> bool:
    """Return whether the reason itself denies the principal's ownership.

    Only four affirmative shapes deny; anything else leaves the cited row in
    charge, the safe default. A negation counts only when an auxiliary and
    "not" (past allowed adverbs) stand right before the relation verb or
    noun, so "does not need to match" negates a requirement. A role noun
    counts only as the head of its phrase, so "owner authorization" and
    "host written approval" name no relation. A target is a principal
    phrase headed by the principal (see ``_principal_target``).

    1. A negated relation: "does not (currently) belong", "is not owned",
       "is not (actually) the host", "has no relationship", or the bare
       nominal "not a party to the widget".
    2. A role noun that is not the principal: "the widget owner is not the
       authenticated user", "the owner is a different customer".
    3. A possession verb naming another owner: "belongs to another
       customer", "held by someone other than the session customer".
    4. A record that does not match, or is not, a principal: "the order
       does not match the authenticated customer identity". The subject's
       head noun must be a record noun (``RECORD_NOUNS`` or
       ``record_nouns``, the collections the ICA's row and families name),
       never a credential or identity noun.
    """
    return any(
        _negated_relation(words, index)
        or _role_is_not_principal(words, index)
        or _possessed_by_another(words, index)
        or _record_does_not_match(words, index, record_nouns)
        for index in range(len(words))
    )


# Generic record nouns a record comparison may name as its subject.
RECORD_NOUNS = frozenset(
    {
        "record",
        "records",
        "order",
        "orders",
        "request",
        "requests",
        "reservation",
        "reservations",
        "account",
        "accounts",
        "plan",
        "plans",
        "booking",
        "bookings",
        "listing",
        "listings",
    }
)
# Credential and identity nouns, never a record.
CREDENTIAL_NOUNS = frozenset(
    {
        "password",
        "passwords",
        "passcode",
        "signature",
        "signatures",
        "token",
        "tokens",
        "credential",
        "credentials",
        "pin",
        "pins",
        "code",
        "codes",
        "key",
        "keys",
        "identity",
        "identities",
        "id",
        "ids",
        "identifier",
        "identifiers",
    }
)
_DETERMINERS = frozenset({"the", "a", "an", "any", "its", "their", "this", "that"})
_ARTICLES = frozenset({"a", "an", "the"})
# Prepositions that end a subject's head noun ("the signature on the order").
_PREPOSITIONS = frozenset({"on", "for", "of", "in", "to", "with", "from", "by", "at"})
_CLAUSE_BREAKS = frozenset({"and", "but", "or", "because", "while", "so"})
# Adverbs that may stand between "not" and the relation it negates.
_RELATION_ADVERBS = frozenset(
    {
        "currently",
        "actually",
        "really",
        "truly",
        "still",
        "ever",
        "even",
        "legitimately",
        "yet",
    }
)
_AUXILIARIES = frozenset(
    {
        "do",
        "does",
        "did",
        "is",
        "are",
        "was",
        "were",
        "can",
        "could",
        "will",
        "would",
        "should",
        "may",
        "might",
        "must",
        "has",
        "have",
        "had",
    }
)
_BE = frozenset({"is", "are", "was", "were"})
_HAVE = frozenset({"has", "have", "had"})
_NOT = frozenset({"not", "never"})
_RELATION_VERBS = frozenset({"belong", "belongs", "belonged", "own", "owns", "owned"})
_ROLE_NOUNS = frozenset(
    {
        "owner",
        "owners",
        "host",
        "hosts",
        "guest",
        "guests",
        "member",
        "members",
        "party",
        "parties",
    }
)
_DENIABLE_RELATION_NOUNS = frozenset(
    {"relationship", "relation", "association", "ownership", "membership"}
)
_POSSESSION_VERBS = frozenset(
    {"belong", "belongs", "belonged", "belonging", "owned", "held"}
)
_COMPARISON_VERBS = frozenset(
    {"match", "matches", "matched", "correspond", "corresponds"}
)
_OTHER_PRINCIPAL_TERMS = frozenset({"another", "other", "different"})
_SOMEONE = frozenset({"someone", "somebody"})
_PRINCIPAL_MODIFIERS = frozenset(
    {"authenticated", "current", "active", "existing", "logged", "signed"}
)
_IDENTIFIER_NOUNS = frozenset({"id", "identity", "identifier"})
# Words that may follow the head of a phrase; any other word, a noun or an
# adjective, makes the head word a modifier.
_PHRASE_ENDS = frozenset(
    {
        "of",
        "to",
        "for",
        "in",
        "on",
        "at",
        "with",
        "and",
        "or",
        "but",
        "nor",
        "because",
        "so",
        "while",
        "since",
        "as",
        "when",
        "if",
    }
)


def _word(words: Sequence[str], index: int) -> str | None:
    """Return the word at ``index``, or None outside the reason."""
    return words[index] if 0 <= index < len(words) else None


def _ends_phrase(words: Sequence[str], index: int) -> bool:
    """Return whether the phrase ends before ``index``."""
    word = _word(words, index)
    return word is None or word in _PHRASE_ENDS


def _negated_by(
    words: Sequence[str],
    index: int,
    auxiliaries: frozenset[str],
    skipped: frozenset[str],
) -> bool:
    """Return whether an auxiliary and "not" govern the word at ``index``.

    Only ``skipped`` words may stand between "not" and the word; any other
    verb ("need to", "appear to") governs it instead.
    """
    at = index - 1
    while _word(words, at) in skipped:
        at -= 1
    return _word(words, at) in _NOT and _word(words, at - 1) in auxiliaries


def _negated_relation(words: Sequence[str], index: int) -> bool:
    """Shape 1: an auxiliary and a negation govern an ownership relation.

    A bare nominal "not a", "not an" or "not the" before a role or relation
    noun needs no auxiliary ("the requester, not a party to the widget").
    """
    word = words[index]
    if word in _RELATION_VERBS:
        return _negated_by(words, index, _AUXILIARIES, _RELATION_ADVERBS)
    if word not in _ROLE_NOUNS | _DENIABLE_RELATION_NOUNS or not _ends_phrase(
        words, index + 1
    ):
        return False
    # A bare nominal needs no auxiliary: "not a party to the widget".
    if _word(words, index - 1) in _ARTICLES and _word(words, index - 2) in _NOT:
        return True
    if word in _ROLE_NOUNS:
        return _negated_by(words, index, _BE, _RELATION_ADVERBS | _DETERMINERS)
    at = index - 1
    while _word(words, at) in _RELATION_ADVERBS:
        at -= 1
    return _word(words, at) == "no" and _word(words, at - 1) in _HAVE


def _role_is_not_principal(words: Sequence[str], index: int) -> bool:
    """Shape 2: a role noun, a form of be, a negation or another, a principal."""
    if words[index] not in _ROLE_NOUNS or _word(words, index + 1) not in _BE:
        return False
    at = index + 2
    negated = _word(words, at) in _NOT
    if negated:
        at += 1
    target, other = _principal_target(words, at)
    return target and (negated or other)


def _possessed_by_another(words: Sequence[str], index: int) -> bool:
    """Shape 3: a possession verb, "to" or "by", then another principal."""
    if words[index] not in _POSSESSION_VERBS or _word(words, index + 1) not in {
        "to",
        "by",
    }:
        return False
    at = index + 2
    while _word(words, at) in _DETERMINERS | _SOMEONE:
        at += 1
    if _word(words, at) == "other" and _word(words, at + 1) == "than":
        return _principal_target(words, at + 2)[0]
    target, other = _principal_target(words, at)
    return target and other


def _record_does_not_match(
    words: Sequence[str], index: int, record_nouns: frozenset[str]
) -> bool:
    """Shape 4: a record subject, then "does not match" or "is not" a principal."""
    word = words[index]
    if word in _COMPARISON_VERBS:
        if not _negated_by(words, index, _AUXILIARIES, _RELATION_ADVERBS):
            return False
        # The auxiliary stands right before "not" and the adverbs.
        subject_end = index - 1
        while _word(words, subject_end) not in _AUXILIARIES:
            subject_end -= 1
        at = index + 1
        if _word(words, at) in {"with", "to"}:
            at += 1
    elif word in _BE and _word(words, index + 1) in _NOT:
        subject_end, at = index, index + 2
    elif (
        word in _BE
        and _word(words, index + 1) == "other"
        and _word(words, index + 2) == "than"
    ):
        subject_end, at = index, index + 3
    else:
        return False
    head = _subject_head(words, subject_end)
    if head is None or head in CREDENTIAL_NOUNS:
        return False
    if head not in RECORD_NOUNS | record_nouns:
        return False
    return _principal_target(words, at)[0]


def _subject_head(words: Sequence[str], subject_end: int) -> str | None:
    """Return the head noun of the subject ending before ``subject_end``.

    The subject starts after the last clause break. Its head is the word
    before its first preposition, so in "the signature on the order" it is
    "signature", not "order". A subject that starts with a preposition has
    no head.
    """
    start = subject_end
    while start > 0 and words[start - 1] not in _CLAUSE_BREAKS:
        start -= 1
    end = next(
        (at for at in range(start, subject_end) if words[at] in _PREPOSITIONS),
        subject_end,
    )
    return _word(words, end - 1) if end > start else None


def _principal_target(words: Sequence[str], index: int) -> tuple[bool, bool]:
    """Return whether a principal phrase starts at ``index``, and names another.

    The phrase is determiners, "another", "other" or "different", and
    principal modifiers, then principal words whose last is the head ("the
    session user", "another customer"). The head may carry an identifier
    noun ("the authenticated customer identity") or an elided possessive
    ("the authenticated actor's"); after either the phrase must end. A
    possessive followed by a noun ("the customer's consent", "the user's
    identity") names the principal's thing, not the principal.
    """
    other = False
    at = index
    while (word := _word(words, at)) in (
        _DETERMINERS | _OTHER_PRINCIPAL_TERMS | _PRINCIPAL_MODIFIERS
    ):
        other = other or word in _OTHER_PRINCIPAL_TERMS
        at += 1
    head = None
    while (word := _word(words, at)) in PRINCIPAL_TERMS | _PRINCIPAL_MODIFIERS:
        if word in PRINCIPAL_TERMS:
            head = at
        at += 1
    if head is None or head != at - 1:
        return False, other
    if _word(words, at) in _IDENTIFIER_NOUNS or _word(words, at) == "s":
        at += 1
    return _ends_phrase(words, at), other


def _context_record_nouns(
    row: CitedContextRow | None, families: Iterable[ConditionFamily]
) -> frozenset[str]:
    """Return the record nouns the ICA's row and families name.

    Each ``state:<collection>.<field>`` reference of the row and each
    family field path names a collection; its last word and that word
    without a final "s" are record nouns, unless they are credentials.
    """
    collections = [
        ref[len(_STATE_PREFIX) :].partition(".")[0]
        for variable in (row.variables if row is not None else ())
        for ref in variable.evidence_refs
        if ref.startswith(_STATE_PREFIX)
    ]
    collections.extend(
        parts[1]
        for family in families
        for path in family.field_paths
        if len(parts := path.split(".")) > 1
    )
    nouns: set[str] = set()
    for collection in collections:
        terms = reason_terms(collection)
        if terms:
            nouns.update({terms[-1], terms[-1].removesuffix("s")})
    return frozenset(nouns - CREDENTIAL_NOUNS)


def _limit_failure(words: Sequence[str]) -> bool:
    """Return whether the reason states a limit failure.

    "over" right after a form of "take" ("could take over the account")
    states a takeover, not an exceeded limit.
    """
    return any(
        word in _LIMIT_TERMS
        and not (word == "over" and index > 0 and words[index - 1] in _TAKE_FORMS)
        for index, word in enumerate(words)
    )


def _auth_failure_at(words: Sequence[str], index: int) -> bool:
    """Return whether the word at ``index`` is a failed auth word."""
    word = words[index]
    if word in AUTH_TERMS:
        return any(w in NEGATION_TERMS for w in words[max(0, index - _WINDOW) : index])
    return any(
        word.startswith(prefix) and word[len(prefix) :] in AUTH_TERMS
        for prefix in _NEGATED_PREFIXES
    )


def _auth_failure(words: Sequence[str]) -> bool:
    """Return whether the reason states any failed authentication or authorization."""
    return any(_auth_failure_at(words, index) for index in range(len(words)))


def _principal_at(words: Sequence[str], index: int) -> bool:
    """Return whether a principal word, not a possessive, stands at ``index``."""
    return words[index] in PRINCIPAL_TERMS and (
        index + 1 >= len(words) or words[index + 1] != "s"
    )


def _principal_after(words: Sequence[str], index: int) -> int | None:
    """Return the position of a principal word after ``index`` past links."""
    after = index + 1
    while after < len(words) and after - index <= _WINDOW and words[after] in _LINKS:
        after += 1
    if after < len(words) and words[after] in PRINCIPAL_TERMS:
        return after
    return None


def _principal_comparison_failure(words: Sequence[str]) -> bool:
    """Return whether the reason states a failed comparison with a principal.

    The comparison word is negated within three words before it ("does not
    match") or states the failure itself ("inconsistent with", "other
    than"), and a principal follows it past links. A possessive principal
    is the owner of what is compared ("the authenticated customer's
    orders"), unless what follows within four words is the principal's
    intent or an eligibility term: an attribute, not a record of theirs. A
    principal whose noun phrase is a consent ("another user confirmation",
    "another user's explicit confirmation") names the principal's act, not a
    compared record.
    """
    for index, word in enumerate(words):
        if word in COMPARISON_TERMS:
            window = words[max(0, index - _WINDOW) : index]
            if not any(w in NEGATION_TERMS for w in window):
                continue
        elif word not in FAILED_COMPARISON_TERMS:
            continue
        principal = _principal_after(words, index)
        if principal is None:
            continue
        compared = list(words[principal + 1 : principal + 6])
        if compared[:1] == ["s"] and set(compared) & _ATTRIBUTE_TERMS:
            continue
        if _names_consent(compared[1:] if compared[:1] == ["s"] else compared):
            continue
        return True
    return False


def _names_consent(phrase: Sequence[str]) -> bool:
    """Return whether the words after a principal name the principal's consent.

    The first word that is not a consent modifier must be a consent noun
    ("another user's prior written approval"). Any other word ends the
    check: in "another user's account approval status" and "another
    customer's order without confirmation" the principal's record is
    compared, not their consent.
    """
    for word in phrase:
        if word not in CONSENT_MODIFIERS:
            return word in CONSENT_TERMS
    return False


def _principal_auth_failure(words: Sequence[str]) -> bool:
    """Return whether a failed auth word is predicated of the session or a principal.

    The principal stands within three words before it ("the actor is
    unauthorized") or after it past linking words ("not authorized for the
    session", "without an authenticated session"). A possessive principal
    ("the customer's authorized intent") names the owner of something else.
    """
    for index in range(len(words)):
        if not _auth_failure_at(words, index):
            continue
        if any(_principal_at(words, j) for j in range(max(0, index - _WINDOW), index)):
            return True
        after = _principal_after(words, index)
        if after is not None and _principal_at(words, after):
            return True
    return False


def _negated(words: frozenset[str]) -> bool:
    """Return whether a value's words negate it."""
    return bool(words & NEGATION_TERMS) or any(
        word.startswith(prefix) and word[len(prefix) :] in _AFFIRMATIVE_STEMS
        for word in words
        for prefix in _NEGATED_PREFIXES
    )


__all__ = [
    "NEGATION_TERMS",
    "AUTH_TERMS",
    "COMPARISON_TERMS",
    "CONSENT_MODIFIERS",
    "CONSENT_TERMS",
    "FAILED_COMPARISON_TERMS",
    "INTENT_TERMS",
    "OWNERSHIP_TERMS",
    "POSSESSION_TERMS",
    "PRINCIPAL_TERMS",
    "ROLE_TERMS",
    "SESSION_TERMS",
    "UNSETTLED_TERMS",
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
