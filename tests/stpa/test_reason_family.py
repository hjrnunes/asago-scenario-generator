"""Tests for the reason-driven condition-family hint and the cited context row."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    estimate_prompt_tokens,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.condition_family import (
    FAN_OUT_KINDS,
    CandidateFamilyPlan,
    ConditionFamily,
    expand_family_candidates,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.schema import (
    _scenario_semantics_payload_type,
)
from asago_scenario_generator.stpa.scenario_prod.reason_family import (
    REASON_FAMILY_RULES,
    CitedContextRow,
    ContextVariable,
    IcaReason,
    choose_reason_family,
    hinted_families,
    ica_reasons,
    reason_terms,
    reason_variable,
)

from tests.helpers.discriminating_condition import STAGE5_PROMPT_TOKEN_BUDGET
from tests.helpers.normal_authoring_wire import _wrong_timing_context
from tests.helpers.sp3_run import _make_ets, _setup_mock_client, stage5_and_shape_calls
from tests.helpers.stpa_builders import make_cs, make_loss_analysis

from .condition_prompt_fixture import realistic_observations, realistic_profile

SLOT = "RESP-1:CA-1-1:INCORRECT"


def _family(kind: str, field: str | None = None, number: int = 0) -> ConditionFamily:
    return ConditionFamily(
        kind=kind,
        operation="edit_widget",
        argument=f"a{number}",
        field_paths=((f"TARGET-STATE.widgets.<record_key>.{field}",) if field else ()),
    )


OWNERSHIP = _family("ownership", "owner_id", 1)
SUBJECT = _family("ownership", None, 2)
LOCKED = _family("flag", "locked", 3)
ARCHIVED = _family("flag", "archived", 4)
PRICE = _family("bound", "price", 5)
STAGE = _family("state", "stage", 6)
READ = ConditionFamily(
    kind="prior_read", operation="edit_widget", prior_operation="read_widget"
)
FAMILIES = (OWNERSHIP, SUBJECT, LOCKED, ARCHIVED, PRICE, STAGE, READ)


def _var(
    pm_id: str, value: str, *refs: str, description: str = "A variable"
) -> ContextVariable:
    return ContextVariable(
        pm_id=pm_id, description=description, value=value, evidence_refs=refs
    )


def _row(*variables: ContextVariable) -> CitedContextRow:
    return CitedContextRow(row_id="CA-1-1:ctx-1", variables=variables)


ACTOR = _var(
    "PM-1-1",
    "actor is unauthorized",
    "session:authenticated_owner_id",
    "state:widgets.owner_id",
)
EDITABLE = _var("PM-1-2", "not allowed", "state:widgets.locked")
PRICED = _var("PM-1-3", "within price", "state:widgets.price")


@dataclass(frozen=True)
class _Threat:
    ica_slot_id: str
    ica_id: str
    ica_text: str = "Unsafe control action"


def _choose(reason: str, row: CitedContextRow | None = None, families=FAMILIES):
    return choose_reason_family(IcaReason(reason=reason, row=row), families)


# --- reason variable -------------------------------------------------------


def test_the_reason_variable_is_the_row_value_the_reason_states() -> None:
    row = _row(ACTOR, EDITABLE, PRICED)
    assert reason_variable("the actor is unauthorized", row) == ACTOR
    assert reason_variable("editing is not allowed for it", row) == EDITABLE


def test_the_longest_stated_value_names_the_reason_variable() -> None:
    short = _var("PM-1-1", "authorized")
    long = _var("PM-1-2", "not authorized by session")
    row = _row(short, long)
    assert reason_variable("the plan is not authorized by session", row) == long


def test_values_match_whole_words_after_normalising_separators() -> None:
    paid = _var("PM-1-1", "paid")
    ranged = _var("PM-1-2", "valid_range")
    row = _row(paid, ranged)
    assert reason_variable("the order is unpaid", row) is None
    assert reason_variable("the dates are a valid range", row) == ranged


def test_no_row_or_no_stated_value_names_no_reason_variable() -> None:
    assert reason_variable("the actor is unauthorized", None) is None
    assert reason_variable("something else entirely", _row(ACTOR)) is None


# --- the mapping -------------------------------------------------------------


def test_the_rules_cover_every_family_kind_and_end_in_no_match() -> None:
    kinds = {kind for rule in REASON_FAMILY_RULES for kind in rule.kinds}
    assert kinds == {*FAN_OUT_KINDS, "prior_read"}
    assert REASON_FAMILY_RULES[-1].name == "no_match"
    assert REASON_FAMILY_RULES[-1].kinds == ()


@pytest.mark.parametrize(
    "reason",
    [
        "the actor is unauthorized",
        "the order is not owned by the authenticated customer",
        "the record identity is unknown",
        "the request is not authorized for the session",
        "the booking belongs to another guest",
        "the caller is not a party to the reservation",
        "the order does not match the authenticated customer",
    ],
)
def test_ownership_identity_actor_and_session_reasons_get_ownership(reason) -> None:
    choice = _choose(reason)
    assert choice.kind == "ownership"
    assert choice.rule == "ownership_reason"


def test_a_session_evidenced_reason_variable_gets_ownership() -> None:
    variable = _var("PM-1-1", "unverified", "session:authenticated_owner_id")
    choice = _choose("the caller is unverified", _row(variable, EDITABLE))
    assert (choice.kind, choice.rule, choice.reason_variable) == (
        "ownership",
        "ownership_reason",
        "PM-1-1",
    )


def test_the_reason_variable_field_selects_the_family_citing_it() -> None:
    choice = _choose("editing is not allowed", _row(ACTOR, EDITABLE))
    assert (choice.kind, choice.rule, choice.reason_variable) == (
        "flag",
        "reason_variable_field",
        "PM-1-2",
    )


def test_the_field_rule_needs_a_family_citing_the_field() -> None:
    variable = _var("PM-1-2", "frozen", "state:widgets.colour")
    choice = _choose("the widget is frozen", _row(variable))
    assert (choice.kind, choice.rule) == (None, "no_match")


@pytest.mark.parametrize(
    ("reason", "kind"),
    [
        ("the requested amount exceeds the remaining balance", "bound"),
        ("the price is greater than the limit", "bound"),
        ("the refund is not eligible", "flag"),
        ("the change is not allowed", "flag"),
        ("the order is already cancelled", "state"),
        ("the widget is still pending", "state"),
    ],
)
def test_reason_terms_select_bound_flag_and_state(reason, kind) -> None:
    choice = _choose(reason)
    assert (choice.kind, choice.rule) == (kind, "reason_terms")


@pytest.mark.parametrize(
    "reason",
    [
        "the request does not match the customer's authorized intent",
        "the intent is unknown",
        "the authorization status is unauthorized transaction",
        "the refund is executed without matching the customer's authorized "
        "intent or transaction context",
    ],
)
def test_intent_reasons_take_the_no_match_path(reason) -> None:
    intent = _var("PM-1-1", "does not match authorized intent")
    eligible = _var("PM-1-2", "eligible", "state:widgets.locked")
    choice = _choose(reason, _row(intent, eligible))
    assert (choice.kind, choice.rule) == (None, "no_match")


@pytest.mark.parametrize(
    "reason",
    [
        "The requested amount exceeds the session spending limit",
        "the amount exceeds the authenticated customer's remaining balance",
        "the refund amount exceeds the remaining balance",
        "the requested quantity is above the maximum",
        "the balance is insufficient for the amount",
    ],
)
def test_a_stated_limit_failure_gives_bound(reason) -> None:
    choice = _choose(reason)
    assert (choice.kind, choice.rule) == ("bound", "reason_terms")


@pytest.mark.parametrize(
    "reason",
    [
        "the actor is unauthorized and the amount exceeds the limit",
        "the order does not belong to the authenticated customer and the amount "
        "exceeds the remaining balance",
        "the target identity does not match the authenticated customer and the "
        "amount exceeds limits",
        "the remaining session is unauthenticated",
        "the assistant helps take over another customer account",
    ],
)
def test_an_ownership_source_wins_over_a_limit_failure(reason) -> None:
    choice = _choose(reason)
    assert (choice.kind, choice.rule) == ("ownership", "ownership_reason")


LIMITED = _var("PM-1-3", "exceeds the limit", "state:widgets.price")


@pytest.mark.parametrize(
    "row", [None, _row(ACTOR), _row(LIMITED), _row(ACTOR, LIMITED)]
)
def test_ownership_with_a_limit_failure_holds_with_or_without_a_cited_row(row) -> None:
    choice = _choose("the actor is unauthorized and the amount exceeds the limit", row)
    assert (choice.kind, choice.rule) == ("ownership", "ownership_reason")


OWNER_FIELD_LIMIT = _var("PM-1-4", "exceeds the limit", "state:widgets.owner_id")


@pytest.mark.parametrize(
    ("row", "families"),
    [
        (None, [PRICE]),
        (_row(LIMITED), [PRICE]),
        (_row(OWNER_FIELD_LIMIT), [PRICE]),
    ],
)
def test_a_limit_reason_gives_bound_with_or_without_a_cited_row(row, families) -> None:
    choice = _choose("the price exceeds the limit", row)
    assert choice.kind == "bound"
    assert hinted_families(choice, FAMILIES) == families


@pytest.mark.parametrize(
    "reason",
    [
        "the session is unauthenticated when changing the amount",
        "the amount is requested without an authenticated session",
        "the plan is not authorized by session",
    ],
)
def test_an_authentication_failure_wins_over_a_bare_amount_noun(reason) -> None:
    choice = _choose(reason)
    assert (choice.kind, choice.rule) == ("ownership", "ownership_reason")


@pytest.mark.parametrize(
    "reason", ["the amount is wrong", "the plan price is incorrect"]
)
def test_a_bare_object_noun_is_not_a_limit_reason(reason) -> None:
    choice = _choose(reason)
    assert (choice.kind, choice.rule) == (None, "no_match")


@pytest.mark.parametrize(
    "reason",
    [
        "the session token is stale",
        "the refund parameters are not authorized by the customer's actual order",
        "the request does not match the customer's authorized intent",
    ],
)
def test_a_session_or_principal_mention_alone_is_not_ownership(reason) -> None:
    assert _choose(reason).kind is None


@pytest.mark.parametrize(
    "reason",
    [
        "the customer ID does not match the session customer ID",
        "the retrieved account details do not match the session customer",
        "the requested details are not present in the authenticated customer's orders",
        "the parameters are inconsistent with the authenticated user's valid orders",
        "the plan deviates from the authenticated user's authorized session",
        "the reservation belongs to a party other than the authenticated actor",
        "the target records are unauthorized for the current session",
    ],
)
def test_a_failed_comparison_with_the_principal_is_ownership(reason) -> None:
    choice = _choose(reason)
    assert (choice.kind, choice.rule) == ("ownership", "ownership_reason")


@pytest.mark.parametrize(
    "reason",
    [
        "another user confirmation is required",
        "the request lacks another customer approval",
    ],
)
def test_a_principals_consent_is_not_a_compared_record(reason) -> None:
    assert _choose(reason).kind is None


def test_a_failed_comparison_with_the_principals_intent_is_not_ownership() -> None:
    for reason in (
        "the request does not match the customer's authorized intent",
        "the refund is executed without matching the customer's intended order",
    ):
        assert _choose(reason).kind is None, reason


def test_a_failed_comparison_with_a_principals_attribute_is_not_ownership() -> None:
    choice = _choose(
        "the parameters do not align with the customer's eligibility or intent"
    )
    assert (choice.kind, choice.rule) == ("flag", "reason_terms")


@pytest.mark.parametrize(
    "reason",
    ["the user has not confirmed the escalation", "the caller is unconfirmed"],
)
def test_a_missing_confirmation_is_not_an_authentication_failure(reason) -> None:
    assert _choose(reason).kind is None


@pytest.mark.parametrize(
    "reason",
    [
        "the actor has no relationship to the listing",
        "the requester has no association with the booking",
    ],
)
def test_a_relationship_reason_is_ownership(reason) -> None:
    assert _choose(reason).kind == "ownership"


def test_amount_or_plan_not_authorized_by_session_is_a_session_failure() -> None:
    # The reason states a failed session authorization and no limit failure,
    # so it takes ownership; when its row says the record is the session
    # customer's, the guard withholds ownership and nothing else matches.
    reason = "the requested amount or plan is not authorized by session"
    assert _choose(reason).kind == "ownership"
    session = _var("PM-1-1", "not authorized by session", "session:x")
    guarded = _choose(reason, _row(session, BELONGS))
    assert guarded.ownership_guarded is True
    assert (guarded.kind, guarded.rule) == (None, "no_match")


def test_a_session_read_reason_variable_with_a_limit_term_gets_bound() -> None:
    limit = _var("PM-1-1", "over the session limit", "session:spending_limit")
    choice = _choose("the price is over the session limit", _row(limit))
    assert (choice.kind, choice.rule, choice.reason_variable) == (
        "bound",
        "reason_terms",
        "PM-1-1",
    )


@pytest.mark.parametrize(
    "reason",
    [
        "the actor is unauthorized",
        "the request is not authorized for the session",
        "the user is unauthenticated",
        "the amount belongs to another customer's order",
    ],
)
def test_ownership_and_session_authorization_reasons_keep_ownership(reason) -> None:
    choice = _choose(reason)
    assert (choice.kind, choice.rule) == ("ownership", "ownership_reason")


def test_an_ownership_reason_without_an_ownership_family_gets_no_hint() -> None:
    choice = _choose("the actor is unauthorized", families=(LOCKED, PRICE, STAGE))
    assert (choice.kind, choice.rule) == ("ownership", "ownership_reason")


@pytest.mark.parametrize(
    ("text", "words"),
    [
        ("Doesn't belong", ("does", "not", "belong")),
        ("isn\u2019t owned", ("is", "not", "owned")),
        ("cannot act", ("can", "not", "act")),
        ("won't match", ("wo", "not", "match")),
    ],
)
def test_contracted_negations_read_as_not(text, words) -> None:
    assert reason_terms(text) == words


def test_reason_terms_are_read_from_one_place() -> None:
    assert reason_terms("The Actor's amount; NOT allowed!") == (
        "the",
        "actor",
        "s",
        "amount",
        "not",
        "allowed",
    )


# --- context guard ----------------------------------------------------------


BELONGS = _var(
    "PM-1-2",
    "belongs to authenticated customer",
    "session:authenticated_owner_id",
    "state:widgets.owner_id",
)


def test_ownership_is_not_dealt_when_the_row_says_the_record_is_the_sessions() -> None:
    session_amount = _var(
        "PM-1-1", "not authorized by session", "session:authenticated_owner_id"
    )
    row = _row(session_amount, BELONGS)
    choice = _choose("the cancelled plan is not authorized by session", row)
    assert choice.ownership_guarded is True
    assert (choice.kind, choice.rule) == ("state", "reason_terms")


def test_a_guarded_reason_with_nothing_else_gets_no_hint() -> None:
    session = _var("PM-1-1", "not authorized by session", "session:x")
    choice = _choose("the plan is not authorized by session", _row(session, BELONGS))
    assert choice.ownership_guarded is True
    assert (choice.kind, choice.rule) == (None, "no_match")


@pytest.mark.parametrize(
    "value",
    [
        "belongs to another customer",
        "ownership unknown",
        "actor is neither",
        "actor is unauthorized",
    ],
)
def test_a_negated_ownership_value_does_not_guard(value) -> None:
    other = _var("PM-1-2", value, "session:authenticated_owner_id")
    choice = _choose("the request is not authorized for the session", _row(other))
    assert choice.ownership_guarded is False
    assert choice.kind == "ownership"


@pytest.mark.parametrize(
    ("value", "refs"),
    [
        ("belongs to authenticated customer", ("session:x", "state:widgets.owner_id")),
        ("owned by the session customer", ("state:widgets.owner_id",)),
        ("actor is the guest", ("state:widgets.owner_id",)),
        (
            "authenticated actor is the host of the widget",
            ("session:x", "state:widgets.owner_id"),
        ),
        ("requester is a member", ("state:widgets.owner_id",)),
        # A non-current word that qualifies the record or the sentence, not
        # the ownership relation, leaves the affirmation current.
        (
            "the requested record belongs to the session customer",
            ("session:x", "state:widgets.owner_id"),
        ),
        (
            "the record belongs to the session customer as expected",
            ("session:x", "state:widgets.owner_id"),
        ),
        (
            "the pending order is owned by the authenticated customer",
            ("session:x", "state:widgets.owner_id"),
        ),
    ],
)
def test_an_affirmative_ownership_value_guards(value, refs) -> None:
    other = _var("PM-1-2", value, *refs, description="Pending status")
    choice = _choose("the actor is unauthorized", _row(other))
    assert choice.ownership_guarded is True
    assert choice.kind is None


@pytest.mark.parametrize(
    "value",
    [
        "pending",
        "unresolved",
        "actor is a stranger",
        "actor is the former owner",
        "owner verification pending",
        "pending owner verification",
        "requester is the previous guest",
        "actor is a prospective member",
        "actor is the guest, pending",
        "belongs to the session customer, ownership pending",
    ],
)
def test_a_relationship_description_without_an_affirming_value_does_not_guard(
    value,
) -> None:
    other = _var(
        "PM-1-2",
        value,
        "session:authenticated_owner_id",
        "state:widgets.owner_id",
        description="Relationship of the session customer to the widget",
    )
    choice = _choose("the actor is unauthorized", _row(other))
    assert choice.ownership_guarded is False
    assert (choice.kind, choice.rule) == ("ownership", "ownership_reason")


@pytest.mark.parametrize(
    "variable",
    [
        _var(
            "PM-1-2",
            "authenticated actor is the guest",
            "session:authenticated_owner_id",
            description="The identity of the authenticated actor",
        ),
        _var(
            "PM-1-2",
            "authorized for target records",
            "session:authenticated_owner_id",
            description="Current session authorization scope",
        ),
        _var(
            "PM-1-2",
            "matches account owner",
            "session:authenticated_owner_id",
            description="Authenticated customer identity",
        ),
        _var("PM-1-2", "ownership verified", description="Ownership check status"),
        _var(
            "PM-1-2",
            "actor is unrelated",
            "session:authenticated_owner_id",
            "state:widgets.owner_id",
        ),
    ],
)
def test_a_value_that_only_identifies_the_session_does_not_guard(variable) -> None:
    choice = _choose("the actor is not a party to the booking", _row(variable))
    assert choice.ownership_guarded is False
    assert choice.kind == "ownership"


def test_state_and_session_evidence_alone_does_not_guard() -> None:
    limit = _var(
        "PM-1-2", "within limit", "session:spending_limit", "state:widgets.price"
    )
    choice = _choose("the actor is unauthorized", _row(limit))
    assert choice.ownership_guarded is False
    assert choice.kind == "ownership"


@pytest.mark.parametrize(
    "value",
    [
        "Doesn't belong to authenticated customer",
        "isn't owned by the authenticated customer",
        "never belonged to the session customer",
        "unowned by the authenticated customer",
        "non-member of the booking",
        "disassociated from the authenticated customer",
    ],
)
def test_contracted_and_prefixed_negatives_do_not_guard(value) -> None:
    other = _var(
        "PM-1-2", value, "session:authenticated_owner_id", "state:widgets.owner_id"
    )
    choice = _choose("the actor is unauthorized", _row(other))
    assert choice.ownership_guarded is False
    assert choice.kind == "ownership"


@pytest.mark.parametrize(
    "description",
    [
        "The actor's relationship to the reservation.",
        "Association of the actor with the reservation",
    ],
)
def test_a_relationship_statement_about_the_principal_guards(description) -> None:
    party = _var(
        "PM-1-1",
        "actor is guest",
        "session:authenticated_actor_id",
        "state:widgets.owner_id",
        description=description,
    )
    choice = _choose(
        "the actor is a guest but the widget is still pending", _row(party)
    )
    assert choice.ownership_guarded is True
    assert (choice.kind, choice.rule) == ("state", "reason_terms")


def test_an_ownership_statement_must_name_the_principal() -> None:
    record_only = _var("PM-1-2", "belongs to a listing", "state:widgets.owner_id")
    choice = _choose("the actor is unauthorized", _row(record_only))
    assert choice.ownership_guarded is False
    assert choice.kind == "ownership"


def test_the_reason_variable_itself_never_guards() -> None:
    reason = _var("PM-1-1", "owned by the session owner", "session:x")
    choice = _choose("it is owned by the session owner", _row(reason))
    assert choice.ownership_guarded is False
    assert choice.kind == "ownership"


# --- dealing -----------------------------------------------------------------


def _reasons(**by_index: tuple[str, CitedContextRow | None]) -> dict[str, IcaReason]:
    return {
        f"{SLOT}:{index[1:]}": IcaReason(reason=reason, row=row)
        for index, (reason, row) in by_index.items()
    }


def test_each_ica_gets_its_reasons_family_not_a_rotation() -> None:
    threats = [_Threat(SLOT, f"{SLOT}:{n}") for n in (1, 2)]
    reasons = _reasons(
        n1=("the modification is not allowed", _row(ACTOR, EDITABLE)),
        n2=("the actor is unauthorized", _row(ACTOR, EDITABLE)),
    )
    plan = expand_family_candidates(threats, lambda _: FAMILIES, reasons=reasons)

    assert [
        (t.ica_id[-1], c.family) for t, c in zip(plan.threats, plan.candidates)
    ] == [
        ("1", LOCKED),
        ("2", OWNERSHIP),
    ]
    assert plan.candidates[0].reason.rule == "reason_variable_field"
    assert plan.candidates[1].reason.rule == "ownership_reason"


def test_several_icas_in_a_slot_may_get_the_same_family() -> None:
    threats = [_Threat(SLOT, f"{SLOT}:{n}") for n in (1, 2, 3)]
    reasons = _reasons(
        n1=("the actor is unauthorized", None),
        n2=("the record identity is unknown", None),
        n3=("the order is not owned by the customer", None),
    )
    plan = expand_family_candidates(threats, lambda _: FAMILIES, reasons=reasons)
    assert {c.family for c in plan.candidates} == {OWNERSHIP, SUBJECT}
    assert len(plan.candidates) == 6


def test_a_kind_narrows_to_the_families_citing_the_reason_field() -> None:
    archived = _var("PM-1-2", "archived", "state:widgets.archived")
    threats = [_Threat(SLOT, f"{SLOT}:1")]
    reasons = _reasons(n1=("the widget is archived", _row(archived)))
    plan = expand_family_candidates(threats, lambda _: FAMILIES, reasons=reasons)
    assert [c.family for c in plan.candidates] == [ARCHIVED]


def test_a_no_match_ica_keeps_one_plain_candidate() -> None:
    threats = [_Threat(SLOT, f"{SLOT}:{n}") for n in (1, 2)]
    reasons = _reasons(
        n1=("the actor is unauthorized", None),
        n2=("the request does not match authorized intent", None),
    )
    plan = expand_family_candidates(threats, lambda _: FAMILIES, reasons=reasons)
    assert [
        (t.ica_id[-1], c.family) for t, c in zip(plan.threats, plan.candidates)
    ] == [
        ("1", OWNERSHIP),
        ("1", SUBJECT),
        ("2", None),
    ]
    assert plan.candidates[-1].reason.rule == "no_match"


def test_an_ica_without_a_supplied_reason_is_read_from_its_text() -> None:
    threats = [
        _Threat(SLOT, f"{SLOT}:1", "Edit widget because the actor is unauthorized.")
    ]
    plan = expand_family_candidates(threats, lambda _: FAMILIES)
    assert [c.family for c in plan.candidates] == [OWNERSHIP, SUBJECT]


def test_wrong_timing_keeps_the_prior_read_hint_whatever_the_reason() -> None:
    slot = "RESP-1:CA-1-1:WRONG_TIMING"
    threats = [_Threat(slot, f"{slot}:1")]
    reasons = {f"{slot}:1": IcaReason(reason="the actor is unauthorized", row=None)}
    plan = expand_family_candidates(threats, lambda _: FAMILIES, reasons=reasons)
    assert [c.family for c in plan.candidates] == [READ]


def test_every_candidate_carries_its_icas_cited_row() -> None:
    timing = "RESP-1:CA-1-1:WRONG_TIMING"
    threats = [
        _Threat(SLOT, f"{SLOT}:1"),
        _Threat(SLOT, f"{SLOT}:2"),
        _Threat(timing, f"{timing}:1"),
    ]
    row = _row(ACTOR, EDITABLE)
    reasons = {
        f"{SLOT}:1": IcaReason(reason="the actor is unauthorized", row=row),
        f"{SLOT}:2": IcaReason(reason="the intent is unknown", row=None),
        f"{timing}:1": IcaReason(reason="too early", row=row),
    }
    plan = expand_family_candidates(threats, lambda _: FAMILIES, reasons=reasons)
    assert [c.context_row for c in plan.candidates] == [row, None, row]


# --- ICA reasons from the enumeration ----------------------------------------


def _structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="Actor membership",
                        values=["actor is owner", "actor is unauthorized"],
                        evidence_refs=[
                            "session:authenticated_owner_id",
                            "state:widgets.owner_id",
                        ],
                    ),
                    ProcessModelPart(
                        pm_id="PM-1-2",
                        description="Editing eligibility",
                        values=["allowed", "not allowed"],
                        evidence_refs=["state:widgets.locked"],
                    ),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Edit a widget",
                        process_model_refs=["PM-1-1", "PM-1-2"],
                    )
                ],
            )
        ]
    )


def _ica(index: int, **values: Any) -> ICA:
    return ICA(
        ica_id=f"{SLOT}:{index}",
        ica_text="Edit a widget provides an unsafe value because the actor is unauthorized.",
        hazardous_context="Context",
        loss_scenario="Scenario",
        **values,
    )


def test_ica_reasons_resolve_the_cited_row_by_id() -> None:
    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=[
                    _ica(
                        1,
                        deviation="the actor is unauthorized",
                        context_row="CA-1-1:ctx-3",
                    ),
                    _ica(
                        2,
                        context_row="CA-1-1:ctx-1",
                        process_model_context={
                            "PM-1-1": "actor is owner",
                            "PM-1-2": "not allowed",
                        },
                    ),
                    _ica(3, context_row="CA-1-1:ctx-9"),
                    _ica(4),
                    _ica(
                        5,
                        process_model_context={
                            "PM-1-1": "actor is owner",
                            "PM-1-2": "allowed",
                        },
                    ),
                ],
            )
        ]
    )
    reasons = ica_reasons(enumeration, _structure())

    first = reasons[f"{SLOT}:1"]
    assert first.reason == "the actor is unauthorized"
    assert first.row == CitedContextRow(
        row_id="CA-1-1:ctx-3",
        variables=(
            ContextVariable(
                pm_id="PM-1-1",
                description="Actor membership",
                value="actor is unauthorized",
                evidence_refs=(
                    "session:authenticated_owner_id",
                    "state:widgets.owner_id",
                ),
            ),
            ContextVariable(
                pm_id="PM-1-2",
                description="Editing eligibility",
                value="allowed",
                evidence_refs=("state:widgets.locked",),
            ),
        ),
    )
    second = reasons[f"{SLOT}:2"]
    assert second.reason.startswith("Edit a widget provides")
    assert [v.value for v in second.row.variables] == ["actor is owner", "not allowed"]
    assert reasons[f"{SLOT}:3"].row is None
    assert reasons[f"{SLOT}:4"].row is None
    # A process-model context without a cited row ID is not a cited row.
    assert reasons[f"{SLOT}:5"].row is None


def test_the_cited_row_prompt_view_carries_exact_values_without_ids() -> None:
    row = _row(ACTOR, EDITABLE)
    assert row.prompt_view() == [
        {
            "variable": "A variable",
            "value": "actor is unauthorized",
            "evidence_refs": [
                "session:authenticated_owner_id",
                "state:widgets.owner_id",
            ],
        },
        {
            "variable": "A variable",
            "value": "not allowed",
            "evidence_refs": ["state:widgets.locked"],
        },
    ]
    bare = _row(_var("PM-1-9", "unknown"))
    assert bare.prompt_view() == [
        {"variable": "A variable", "value": "unknown", "evidence_refs": []}
    ]


# --- the cited row in the Stage 5 request ------------------------------------


KLARNA_SHAPED_ROW = CitedContextRow(
    row_id="CA-1-1:ctx-4",
    variables=(
        ContextVariable(
            pm_id="PM-1-1",
            description="Authorization of the requested amount",
            value="not authorized by session",
            evidence_refs=("session:authenticated_customer_id",),
        ),
        ContextVariable(
            pm_id="PM-1-2",
            description="Refund eligibility of the order",
            value="eligible",
            evidence_refs=("state:orders.refund_eligible",),
        ),
        ContextVariable(
            pm_id="PM-1-3",
            description="Execution status",
            value="pending",
            evidence_refs=(),
        ),
    ),
)


def _stage5_user(row: CitedContextRow | None, *, contract: bool = True) -> str:
    profile = realistic_profile()
    _, user = build_context_bdi_prompts(
        _wrong_timing_context(),
        TemplateLoader(PROMPTS_DIR),
        execution_target_profile=profile,
        target_observations=realistic_observations(profile),
        observation_contract=default_observation_contract() if contract else None,
        context_row=row,
    )
    return user


def test_the_request_renders_the_cited_row_with_its_exact_values() -> None:
    user = _stage5_user(KLARNA_SHAPED_ROW)
    block = user[
        user.index("## Cited context row") : user.index("## Observation contract")
    ]
    assert (
        "- variable: Authorization of the requested amount\n"
        "  value: not authorized by session\n"
        "  evidence_refs:\n"
        "  - session:authenticated_customer_id\n"
    ) in block
    assert (
        "- variable: Refund eligibility of the order\n"
        "  value: eligible\n"
        "  evidence_refs:\n"
        "  - state:orders.refund_eligible\n"
    ) in block
    assert (
        "- variable: Execution status\n  value: pending\n  evidence_refs: []\n"
    ) in block
    # Bookkeeping identities stay in code.
    for identity in ("CA-1-1:ctx-4", "PM-1-1", "PM-1-2"):
        assert identity not in block
    assert user.index("## Immutable Scenario Generation Context") < user.index(
        "## Cited context row"
    )


def test_every_reference_form_renders_verbatim_and_is_explained() -> None:
    row = CitedContextRow(
        row_id="CA-1-1:ctx-1",
        variables=(
            ContextVariable(
                pm_id="PM-1-1",
                description="Refund policy",
                value="refunds need review",
                evidence_refs=(
                    "policy:TARGET-READ-001",
                    "operation:process_refund",
                    "argument:process_refund.amount",
                ),
            ),
        ),
    )
    user = _stage5_user(row)
    block = user[
        user.index("## Cited context row") : user.index("## Observation contract")
    ]
    assert (
        "  evidence_refs:\n"
        "  - policy:TARGET-READ-001\n"
        "  - operation:process_refund\n"
        "  - argument:process_refund.amount\n"
    ) in block
    explained = " ".join(block.split())
    for form in (
        "`state:<collection>.<field>`",
        "`session:<name>`",
        "`argument:<operation>.<name>`",
        "`operation:<name>`",
        "`policy:<observation_ref>`",
    ):
        assert form in explained, form


def test_the_record_agreement_rule_renders_only_with_the_condition_request() -> None:
    with_condition = " ".join(_stage5_user(KLARNA_SHAPED_ROW).split())
    without = " ".join(_stage5_user(KLARNA_SHAPED_ROW, contract=False).split())
    rule = "select a record whose facts agree with every row value they show"
    assert rule in with_condition
    assert "## Cited context row" in without
    assert rule not in without


def test_an_ica_citing_no_row_renders_no_row_block() -> None:
    user = _stage5_user(None)
    assert "## Cited context row" not in user
    assert "context table" not in user


def test_the_request_with_a_row_and_a_hint_stays_within_the_token_budget() -> None:
    profile = realistic_profile()
    system, user = build_context_bdi_prompts(
        _wrong_timing_context(),
        TemplateLoader(PROMPTS_DIR),
        execution_target_profile=profile,
        target_observations=realistic_observations(profile),
        observation_contract=default_observation_contract(),
        condition_family=OWNERSHIP,
        context_row=KLARNA_SHAPED_ROW,
    )
    schema = _scenario_semantics_payload_type(
        4,
        duration_eligible=False,
        observation_criteria_required=True,
        condition_references_supplied=True,
    ).model_json_schema()
    total = estimate_prompt_tokens(system + user + json.dumps(schema))
    assert total <= STAGE5_PROMPT_TOKEN_BUDGET


def test_the_run_sends_each_candidates_cited_row_to_stage5(tmp_path) -> None:
    client = _setup_mock_client(2)
    run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
        condition_families=(
            CandidateFamilyPlan(context_row=KLARNA_SHAPED_ROW),
            CandidateFamilyPlan(),
        ),
    )
    first, second = [
        call.user_prompt
        for call in stage5_and_shape_calls(client)
        if "## Immutable Scenario Generation Context" in call.user_prompt
    ][:2]
    assert "## Cited context row" in first
    assert "value: not authorized by session" in first
    assert "## Cited context row" not in second
