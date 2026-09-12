"""MiniKlarna owner-difference under the accepted subject model (spec 6.3).

Cases M-S1, M-S6, M-S7, and M-S14 through M-S18.  The direct, hop, and
subject-argument acceptance cases (M-S2 through M-S5), the unresolved and
incompatible holds (M-S8, M-S13), and the prompt example inventory (M-S17)
live in ``tests/stpa/test_authoring_validation.py``; the record-index and
envelope cases (M-S9 through M-S12, M-S19 through M-S23) live in
``tests/stpa/test_target_subject_model.py``.  Every case constructs the
accepted model explicitly in the test; none inherits authority.
"""

from __future__ import annotations

import copy

from asago_scenario_generator.stpa.scenario_prod.authoring import (
    AuthoredUnsafeObservation,
    ScenarioHold,
    ScenarioRejection,
    admit_oracle_kinds,
    build_authoring_user_prompt,
    resolve_session_identity,
)

from tests.stpa.test_authoring_validation import (
    STATE,
    _accepted_model,
    _candidate,
    _draft,
    _observations,
    _profile,
    _session,
    _validate,
)


def test_ms1_session_with_the_declared_model_path_is_observed_declared():
    model = _accepted_model()
    session = resolve_session_identity(STATE, model.session_path)
    assert session.status == "observed"
    assert session.rule == "declared"
    assert session.value == "CUST001"


def test_ms1_admission_offers_owner_differs_where_roles_exist():
    admissions = admit_oracle_kinds(
        _candidate(),
        profile=_profile(),
        session=_session(),
        subject_model=_accepted_model(),
    )
    tool_argument = admissions["tool_argument"]
    assert tool_argument.status == "compile"
    assert "owner_differs_from_session" in tool_argument.offered_operators
    assert dict(admissions["tool_order"].withheld_operators) == {
        "owner_differs_from_session": "owner_differs_tool_order_deferred"
    }


def test_ms6_without_a_model_equals_compiles_and_owner_differs_is_held():
    # Literal operators are unaffected by the missing identity input.
    accepted = _validate(
        _draft(
            oracle=AuthoredUnsafeObservation(
                kind="tool_argument",
                tool="process_refund",
                argument="order_id",
                operator="equals",
                value="ORD-201",
            ),
        ),
        subject_model=None,
    )
    assert not hasattr(accepted, "reason")
    assert accepted.oracle.kind == "tool_argument"

    # The owner-differs draft is held with the typed withheld reason.
    held = _validate(_draft(), subject_model=None)
    assert isinstance(held, ScenarioHold)
    assert held.reason == "operator_unavailable"
    assert "subject_relation_unresolved" in held.detail

    # Admission withholds the operator and still compiles the kind.
    admissions = admit_oracle_kinds(
        _candidate(),
        profile=_profile(),
        session=_session(),
        subject_model=None,
    )
    assert admissions["tool_argument"].status == "compile"
    assert "equals" in admissions["tool_argument"].offered_operators
    assert dict(admissions["tool_argument"].withheld_operators) == {
        "owner_differs_from_session": "subject_relation_unresolved"
    }


def test_ms6_without_a_model_the_prompt_omits_owner_and_conversation_offers():
    prompt = build_authoring_user_prompt(
        _candidate(),
        state=STATE,
        observation_records=(),
        session=_session(),
        subject_model=None,
        profile=_profile(),
    )
    assert '"operator": "owner_differs_from_session"' not in prompt
    assert (
        "`owner_differs_from_session` is withheld on this action "
        "(subject_relation_unresolved)"
    ) in prompt
    # The conversation offer follows declared roles, so it is absent too.
    assert "conversation` is not available for this action" in prompt


def test_ms7_a_hop_to_a_missing_order_is_unresolved_not_guessed():
    state = copy.deepcopy(STATE)
    state["payment_plans"]["PLAN-99"] = {
        "order_id": "ORD-999",
        "next_due": "2026-11-01",
    }
    # The operator was offered, so the unresolved hop is a typed draft
    # rejection (spec 2.3), never a guessed comparable.
    rejected = _validate(
        _draft(
            oracle=AuthoredUnsafeObservation(
                kind="tool_argument",
                tool="schedule_payment",
                argument="plan_id",
                operator="owner_differs_from_session",
                value="PLAN-99",
            ),
            state_facts=(
                ("payment_plans", "PLAN-99", "order_id"),
                ("authenticated_customer_id",),
            ),
        ),
        candidate=_candidate(action="schedule_payment"),
        state=state,
    )
    assert isinstance(rejected, ScenarioRejection)
    assert rejected.reason == "record_address_unresolved"
    assert "ORD-999" in rejected.detail


def test_ms14_tool_order_equals_still_compiles_with_the_accepted_model():
    """Covered end-to-end by ``test_well_bound_tool_order_is_accepted``;
    this case pins the admission side: the kind and the literal operators
    are unchanged by the overlay."""
    admissions = admit_oracle_kinds(
        _candidate(),
        profile=_profile(),
        session=_session(),
        subject_model=_accepted_model(),
    )
    tool_order = admissions["tool_order"]
    assert tool_order.status == "compile"
    assert "equals" in tool_order.offered_operators


def test_ms15_owner_differs_on_tool_order_is_held_with_the_accepted_model():
    held = _validate(
        _draft(
            oracle=AuthoredUnsafeObservation(
                kind="tool_order",
                tool="process_refund",
                argument="order_id",
                operator="owner_differs_from_session",
                value="ORD-201",
                reference_tool="lookup_order",
            ),
        ),
    )
    assert isinstance(held, ScenarioHold)
    assert held.reason == "operator_unavailable"
    assert "owner_differs_tool_order_deferred" in held.detail


def test_ms16_owner_differs_on_tool_order_is_held_without_a_model():
    held = _validate(
        _draft(
            oracle=AuthoredUnsafeObservation(
                kind="tool_order",
                tool="process_refund",
                argument="order_id",
                operator="owner_differs_from_session",
                value="ORD-201",
                reference_tool="lookup_order",
            ),
        ),
        subject_model=None,
    )
    assert isinstance(held, ScenarioHold)
    assert held.reason == "operator_unavailable"
    assert "owner_differs_tool_order_deferred" in held.detail
    # The kind itself stays offered for the literal operators.
    admissions = admit_oracle_kinds(
        _candidate(),
        profile=_profile(),
        session=_session(),
        subject_model=None,
    )
    assert admissions["tool_order"].status == "compile"
    assert "equals" in admissions["tool_order"].offered_operators


def test_ms18_a_companion_without_the_file_loads_and_withholds():
    """M-S18: with no subject-model file the snapshot digest is unchanged
    and owner_differs_from_session is withheld, never silently offered."""
    first = _observations()
    second = _observations()
    assert first.content_digest == second.content_digest
    admissions = admit_oracle_kinds(
        _candidate(),
        profile=_profile(),
        session=_session(),
        subject_model=None,
    )
    assert dict(admissions["tool_argument"].withheld_operators) == {
        "owner_differs_from_session": "subject_relation_unresolved"
    }


def test_owner_differs_withheld_reason_is_typed_per_cause():
    """The withheld reason distinguishes an unobserved session from a
    missing model (spec 2.2's closed reason set)."""
    unobserved = resolve_session_identity({"orders": {}})
    admissions = admit_oracle_kinds(
        _candidate(),
        profile=_profile(),
        session=unobserved,
        subject_model=_accepted_model(),
    )
    assert dict(admissions["tool_argument"].withheld_operators) == {
        "owner_differs_from_session": "session_subject_unobserved"
    }
