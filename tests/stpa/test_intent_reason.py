"""Route an INCORRECT tool-call ICA whose reason is the user's intent before Stage 5.

Stage 5 cannot ground an intent reason: no tool-call argument, TARGET-STATE
or TARGET-READ fact represents what the user asked for. Code records such an
ICA as not applicable, with a reason code and a reason, and sends nothing to
Stage 5. Session, actor, identity, bound and timing reasons keep reaching
Stage 5.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
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
from asago_scenario_generator.stpa.scenario_prod.condition_family import (
    CandidateFamilyPlan,
    ConditionFamily,
    expand_family_candidates,
)
from asago_scenario_generator.stpa.scenario_prod.intent_reason import (
    INTENT_REASON_CODE,
    NotApplicableDisposition,
    intent_dispositions,
    recognize_intent_reason,
)
from asago_scenario_generator.stpa.scenario_prod.reason_family import (
    CitedContextRow,
    ContextVariable,
    IcaReason,
    ica_reasons,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    TESTABILITY_FILENAME,
    SP3CandidateStatus,
    run_sp3,
)
from tests.helpers.sp3_run import _make_ets, _setup_mock_client, stage5_and_shape_calls
from tests.helpers.stpa_builders import make_cs, make_loss_analysis

TOOL_CALL = ControlActionEffectKind.tool_call
SLOT = "RESP-1:CA-1-1:INCORRECT"


def _var(
    pm_id: str, value: str, *refs: str, description: str = "A variable"
) -> ContextVariable:
    return ContextVariable(
        pm_id=pm_id, description=description, value=value, evidence_refs=refs
    )


def _row(*variables: ContextVariable) -> CitedContextRow:
    return CitedContextRow(row_id="CA-1-1:ctx-1", variables=variables)


INTENT = _var(
    "PM-1-1",
    "does not match authorized intent",
    description="The alignment between the requested operation and the "
    "customer's authorized context/intent.",
)
INTENT_UNKNOWN = _var(
    "PM-1-1",
    "intent unknown",
    description="The alignment between the user's expressed intent and the "
    "authenticated session's authorized transaction scope.",
)
UNAUTHORIZED_TRANSACTION = _var(
    "PM-1-1",
    "unauthorized transaction",
    description="The alignment between the user's expressed intent and the "
    "authenticated session's authorized transaction scope.",
)
ELIGIBLE = _var(
    "PM-1-2",
    "eligible",
    "state:orders.refund_eligible",
    description="The eligibility status of the requested refund.",
)


def _recognize(
    reason: str,
    row: CitedContextRow | None = None,
    effect_kind: ControlActionEffectKind | None = TOOL_CALL,
) -> NotApplicableDisposition | None:
    return recognize_intent_reason(
        IcaReason(reason=reason, row=row), effect_kind=effect_kind
    )


# --- routed ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("reason", "variable"),
    [
        ("the request does not match authorized intent", INTENT),
        ("the requested operation does not match authorized intent", INTENT),
        ("intent unknown", INTENT_UNKNOWN),
        ("the request is an unauthorized transaction", UNAUTHORIZED_TRANSACTION),
    ],
)
def test_a_reason_variable_about_intent_without_target_evidence_is_routed(
    reason, variable
) -> None:
    disposition = _recognize(reason, _row(variable, ELIGIBLE))

    assert disposition is not None
    assert disposition.reason_code == INTENT_REASON_CODE
    assert disposition.basis == "reason_variable"
    assert disposition.reason_variable == "PM-1-1"
    assert reason in disposition.reason


@pytest.mark.parametrize(
    "reason",
    [
        "the request does not match the customer's authorized intent",
        "the requested operation does not match the customer's authorized intent",
        "the refund is executed without matching the customer's authorized intent",
        "the customer's intent does not match the requested payment operation",
        "the request deviates from the customer's actual intent",
        "the intent is unknown",
        "the request's intent is unknown",
        "the customer's intent is unknown",
    ],
)
def test_a_failed_intent_comparison_or_an_unknown_intent_is_routed_by_wording(
    reason,
) -> None:
    for row in (None, _row(ELIGIBLE)):
        disposition = _recognize(reason, row)
        assert disposition is not None, (reason, row)
        assert disposition.reason_code == INTENT_REASON_CODE
        assert disposition.basis == "reason_wording"
        assert disposition.reason_variable is None


def test_the_reason_states_why_no_condition_can_ground_it() -> None:
    disposition = _recognize("the intent is unknown")

    assert disposition is not None
    assert disposition.as_log() == {
        "reason_code": INTENT_REASON_CODE,
        "basis": "reason_wording",
        "reason_variable": None,
        "reason": disposition.reason,
    }
    text = " ".join(disposition.reason.split())
    assert "'the intent is unknown'" in text
    assert "tool-call argument" in text
    assert "TARGET-STATE" in text
    assert "TARGET-READ" in text


# --- not routed --------------------------------------------------------------


@pytest.mark.parametrize(
    "reason",
    [
        # session
        "the call is not authorized for the session",
        "the refund is issued without an authenticated session",
        # actor
        "the actor is unauthorized",
        "the actor is not the host or the guest",
        # identity
        "the record identity is unknown",
        "the target identity is unknown",
        "the order is not owned by the authenticated customer",
        # amount or plan bounds
        "the requested amount or plan is not authorized by session",
        "the refund amount exceeds the remaining balance",
        # timing
        "the refund is issued before the authorization status is confirmed",
    ],
)
def test_session_actor_identity_bound_and_timing_reasons_are_not_routed(
    reason,
) -> None:
    assert _recognize(reason) is None
    assert _recognize(reason, _row(INTENT, ELIGIBLE)) is None


@pytest.mark.parametrize(
    "reason",
    [
        # an intent comparison beside a ground Stage 5 can test
        "the request does not match the customer's authorized intent and the "
        "refund is ineligible",
        "the parameters do not align with the customer's eligibility or intent",
        "the request does not match the authenticated customer's intent and the "
        "order is not owned by the customer",
        # the intent matches; something else is wrong
        "the request matches authorized intent but the value is incorrect",
        # intent is the action's output, not the request's
        "the classified intent is incorrect",
        "the intent classification is incorrect",
        # "intended" is not the user's intent
        "the response includes sensitive info not intended for the session",
        "the tool is invoked with parameters outside intended operational bounds",
    ],
)
def test_a_reason_with_another_ground_or_no_failed_intent_is_not_routed(
    reason,
) -> None:
    assert _recognize(reason) is None


@pytest.mark.parametrize(
    "reason",
    [
        # a testable bound, amount, currency or value beside the intent
        "the request does not match authorized intent and the amount is negative",
        "the request does not match the customer's authorized intent and the "
        "currency is different",
        "the request does not match the customer's authorized intent or the "
        "refund value is wrong",
        # a timing or order ground beside the intent
        "intent unknown before the authorization status is confirmed",
        "the intent is unknown and the refund is issued before the authorization "
        "status is confirmed",
        # a status ground beside the intent
        "the request does not match the customer's authorized intent and the "
        "order status is shipped",
        # a context that is more than the intent
        "the request does not match the customer's authorized intent or "
        "transaction context",
        "the refund is executed without matching the customer's authorized "
        "intent or transaction context",
        # a session or a status frame around an intent value
        "the authorization status is intent unknown",
        "the authorization status is unauthorized transaction",
    ],
)
def test_a_reason_that_states_more_than_an_intent_ground_is_not_routed(
    reason,
) -> None:
    for row in (None, _row(ELIGIBLE), _row(INTENT, ELIGIBLE)):
        assert _recognize(reason, row) is None, (reason, row)
    for variable in (INTENT_UNKNOWN, UNAUTHORIZED_TRANSACTION):
        assert _recognize(reason, _row(variable)) is None, (reason, variable)


@pytest.mark.parametrize(
    "reason",
    [
        # the failure or the unknown applies to the currency, not the intent
        "the intent matches but currency is different",
        "the intent is known but currency differs",
        "the intent is confirmed but the amount is unknown",
        "the intent does not change but the currency does not match",
        # the comparison is with something other than the intent
        "the currency does not match the customer's intent",
        "the request matches the customer's authorized intent",
    ],
)
def test_the_failure_must_be_predicated_of_the_intent_itself(reason) -> None:
    assert _recognize(reason) is None
    assert _recognize(reason, _row(INTENT)) is None


def test_a_classifier_output_variable_is_not_the_users_intent() -> None:
    classified = _var(
        "PM-1-1",
        "incorrect",
        description="The classified intent produced by the classifier",
    )
    for reason in (
        "the classified intent is incorrect",
        "the intent is incorrect",
    ):
        assert _recognize(reason, _row(classified)) is None, reason


def test_a_classifier_variable_with_a_failure_value_is_not_routed() -> None:
    classified = _var(
        "PM-1-1",
        "does not match authorized intent",
        description="The intent classification the classifier assigns to the request",
    )
    reason = "the request does not match authorized intent"

    assert _recognize(reason, _row(classified)) is None


def test_an_intent_variable_whose_value_states_no_failure_is_not_routed() -> None:
    matching = _var(
        "PM-1-1", "matches authorized intent", description=INTENT.description
    )

    assert _recognize("the request matches authorized intent", _row(matching)) is None


def test_a_reason_variable_with_target_evidence_is_not_routed() -> None:
    evidenced = _var(
        "PM-1-1",
        "does not match authorized intent",
        "session:authenticated_customer_id",
        description="The alignment between the request and the customer's intent.",
    )
    reason = "the request does not match authorized intent"

    assert _recognize(reason, _row(evidenced)) is None


def test_a_reason_variable_that_is_not_about_intent_is_not_routed() -> None:
    content = _var(
        "PM-1-1",
        "not covered by any authorized source",
        description="The content's support status relative to authorized sources.",
    )
    reason = "the reply is not covered by any authorized source"

    assert _recognize(reason, _row(content)) is None


@pytest.mark.parametrize(
    "effect_kind",
    [
        None,
        ControlActionEffectKind.model_output,
        ControlActionEffectKind.agent_message,
        ControlActionEffectKind.state_change,
        ControlActionEffectKind.environment_action,
    ],
)
def test_an_action_that_is_not_a_tool_call_is_not_routed(effect_kind) -> None:
    reason = "the request does not match the customer's authorized intent"

    assert _recognize(reason, effect_kind=effect_kind) is None
    assert _recognize(reason, _row(INTENT), effect_kind=effect_kind) is None


# --- dispositions from the enumeration ---------------------------------------


def _structure(effect_kind: ControlActionEffectKind | None = TOOL_CALL):
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Refund controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description=INTENT.description,
                        values=[
                            "matches authorized intent",
                            "does not match authorized intent",
                        ],
                    ),
                    ProcessModelPart(
                        pm_id="PM-1-2",
                        description=ELIGIBLE.description,
                        values=["eligible", "ineligible"],
                        evidence_refs=["state:orders.refund_eligible"],
                    ),
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Issue a refund",
                        effect_kind=effect_kind,
                        operation="process_refund",
                        process_model_refs=["PM-1-1", "PM-1-2"],
                    )
                ],
            )
        ]
    )


def _ica(slot_id: str, index: int, deviation: str, **values: Any) -> ICA:
    return ICA(
        ica_id=f"{slot_id}:{index}",
        ica_text=f"Issue a refund provides an unsafe value because {deviation}.",
        deviation=deviation,
        hazardous_context="Context",
        loss_scenario="Scenario",
        **values,
    )


def _enumeration() -> ICAEnumeration:
    timing = "RESP-1:CA-1-1:WRONG_TIMING"
    return ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=[
                    # the cited row's intent variable carries no target evidence
                    _ica(
                        SLOT,
                        1,
                        "the request does not match authorized intent",
                        context_row="CA-1-1:ctx-3",
                    ),
                    _ica(
                        SLOT, 2, "the refund is not owned by the authenticated customer"
                    ),
                    _ica(SLOT, 3, "the customer's intent is unknown"),
                    _ica(
                        SLOT,
                        4,
                        "the requested amount or plan is not authorized by session",
                    ),
                ],
            ),
            ICASlot(
                slot_id=timing,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=[
                    _ica(
                        timing,
                        1,
                        "the refund is issued before the customer's intent is "
                        "confirmed, so the intent is unknown",
                    )
                ],
            ),
        ]
    )


def test_intent_dispositions_route_only_intent_icas_of_incorrect_tool_call_slots() -> (
    None
):
    enumeration, structure = _enumeration(), _structure()

    dispositions = intent_dispositions(
        enumeration, structure, ica_reasons(enumeration, structure)
    )

    assert sorted(dispositions) == [f"{SLOT}:1", f"{SLOT}:3"]
    assert dispositions[f"{SLOT}:1"].basis == "reason_variable"
    assert dispositions[f"{SLOT}:1"].reason_variable == "PM-1-1"
    assert dispositions[f"{SLOT}:3"].basis == "reason_wording"
    assert {item.reason_code for item in dispositions.values()} == {INTENT_REASON_CODE}


def test_intent_dispositions_read_the_reasons_when_none_are_supplied() -> None:
    enumeration, structure = _enumeration(), _structure()

    assert intent_dispositions(enumeration, structure) == intent_dispositions(
        enumeration, structure, ica_reasons(enumeration, structure)
    )


def test_a_message_action_routes_nothing() -> None:
    structure = _structure(ControlActionEffectKind.agent_message)

    assert intent_dispositions(_enumeration(), structure) == {}


# --- the family plan carries the disposition ---------------------------------


@dataclass(frozen=True)
class _Threat:
    ica_slot_id: str
    ica_id: str
    ica_text: str = "Unsafe control action"


OWNERSHIP = ConditionFamily(
    kind="ownership",
    operation="process_refund",
    argument="order_id",
    field_paths=("TARGET-STATE.orders.<record_key>.customer_id",),
)
FLAG = ConditionFamily(
    kind="flag",
    operation="process_refund",
    argument="order_id",
    field_paths=("TARGET-STATE.orders.<record_key>.refund_eligible",),
)


def _disposition(reason: str) -> NotApplicableDisposition:
    disposition = _recognize(reason)
    assert disposition is not None
    return disposition


def test_a_routed_ica_keeps_one_candidate_with_its_disposition_and_no_hint() -> None:
    threats = [_Threat(SLOT, f"{SLOT}:{n}") for n in (1, 2)]
    row = _row(INTENT, ELIGIBLE)
    reasons = {
        f"{SLOT}:1": IcaReason(reason="the actor is unauthorized", row=None),
        f"{SLOT}:2": IcaReason(
            reason="the request does not match authorized intent", row=row
        ),
    }
    routed = _disposition("the intent is unknown")

    plan = expand_family_candidates(
        threats,
        lambda _: (OWNERSHIP, FLAG),
        reasons=reasons,
        not_applicable={f"{SLOT}:2": routed},
    )

    assert [(t.ica_id, c.family) for t, c in zip(plan.threats, plan.candidates)] == [
        (f"{SLOT}:1", OWNERSHIP),
        (f"{SLOT}:2", None),
    ]
    assert plan.candidates[0].not_applicable is None
    assert plan.candidates[1] == CandidateFamilyPlan(
        context_row=row, not_applicable=routed
    )


def test_without_dispositions_the_plan_is_unchanged() -> None:
    threats = [_Threat(SLOT, f"{SLOT}:1")]
    reasons = {f"{SLOT}:1": IcaReason(reason="the intent is unknown", row=None)}

    plan = expand_family_candidates(threats, lambda _: (OWNERSHIP,), reasons=reasons)

    assert [c.not_applicable for c in plan.candidates] == [None]


# --- the run records the disposition and sends nothing to Stage 5 -----------


def _routed_run(tmp_path: Path, plans: tuple[CandidateFamilyPlan, ...]):
    client = _setup_mock_client(len(plans))
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=len(plans)),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
        condition_families=plans,
    )
    return client, result


def _stage5_requests(client) -> list[Any]:
    return [
        call
        for call in stage5_and_shape_calls(client)
        if "## Immutable Scenario Generation Context" in call.user_prompt
    ]


def test_a_not_applicable_candidate_is_recorded_and_sends_no_stage5_request(
    tmp_path: Path,
) -> None:
    routed = _disposition("the intent is unknown")
    client, result = _routed_run(
        tmp_path,
        (CandidateFamilyPlan(), CandidateFamilyPlan(not_applicable=routed)),
    )

    assert len(_stage5_requests(client)) == 1
    first, second = result.candidate_outcomes
    assert first.status is SP3CandidateStatus.published
    assert first.reason_code is None
    assert second.scenario_id == "SCN-002"
    assert second.status is SP3CandidateStatus.not_applicable
    assert second.reason_code == INTENT_REASON_CODE
    assert second.diagnostics == (routed.reason,)
    assert [spec.scenario_id for spec in result.scenario_specs] == ["SCN-001"]
    assert not (tmp_path / "scenarios" / "SCN-002.yaml").exists()
    assert not (tmp_path / "scenarios" / "SCN-002.feature").exists()


def test_the_testability_record_lists_each_not_applicable_candidate(
    tmp_path: Path,
) -> None:
    routed = _disposition("the request does not match the customer's authorized intent")
    _, result = _routed_run(
        tmp_path,
        (CandidateFamilyPlan(not_applicable=routed), CandidateFamilyPlan()),
    )

    testability = yaml.safe_load((tmp_path / TESTABILITY_FILENAME).read_text())
    assert testability["summary"]["not_applicable"] == 1
    assert testability["not_applicable"] == [
        {
            "scenario_id": "SCN-001",
            "ica_slot_id": "RESP-1:CA-1-1:NOT_PROVIDED",
            "ica_id": "RESP-1:CA-1-1:NOT_PROVIDED:1",
            "reason_code": INTENT_REASON_CODE,
            "basis": "reason_wording",
            "reason_variable": None,
            "reason": routed.reason,
        }
    ]
    # The scenario rows hold only the scenarios Stage 5 wrote.
    assert [row["scenario_id"] for row in testability["scenarios"]] == ["SCN-002"]
    assert testability["summary"]["total"] == 1
    assert [o.status for o in result.candidate_outcomes] == [
        SP3CandidateStatus.not_applicable,
        SP3CandidateStatus.published,
    ]


def test_a_run_without_routed_candidates_records_none(tmp_path: Path) -> None:
    _routed_run(tmp_path, (CandidateFamilyPlan(),))

    testability = yaml.safe_load((tmp_path / TESTABILITY_FILENAME).read_text())
    assert testability["summary"]["not_applicable"] == 0
    assert testability["not_applicable"] == []


def test_every_candidate_is_accounted_exactly_once(tmp_path: Path) -> None:
    routed = _disposition("the intent is unknown")
    plans = (
        CandidateFamilyPlan(not_applicable=routed),
        CandidateFamilyPlan(),
        CandidateFamilyPlan(not_applicable=routed),
    )
    _, result = _routed_run(tmp_path, plans)

    outcomes = result.candidate_outcomes
    assert [o.scenario_id for o in outcomes] == ["SCN-001", "SCN-002", "SCN-003"]
    by_status = {
        status: sum(o.status is status for o in outcomes)
        for status in SP3CandidateStatus
    }
    assert sum(by_status.values()) == len(plans)
    assert by_status[SP3CandidateStatus.not_applicable] == 2
    # Candidates in = scenarios written + not applicable + dropped.
    written = len(result.scenario_specs) + len(result.functional_test_specs)
    dropped = sum(
        by_status[status]
        for status in (
            SP3CandidateStatus.generation_failed,
            SP3CandidateStatus.rendering_failed,
            SP3CandidateStatus.publication_failed,
            SP3CandidateStatus.skipped,
        )
    )
    assert written + by_status[SP3CandidateStatus.not_applicable] + dropped == len(
        plans
    )
    testability = yaml.safe_load((tmp_path / TESTABILITY_FILENAME).read_text())
    summary = testability["summary"]
    assert summary["total"] + summary["not_applicable"] == len(plans) - dropped


# --- a circuit break keeps the routed dispositions ---------------------------


class LengthFinishReasonError(Exception):
    """Stands in for the SDK's structured-output length error by name."""


def test_a_circuit_break_keeps_each_routed_candidates_disposition(
    tmp_path: Path,
) -> None:
    from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
        _ContextScenarioSemanticsPayload,
    )
    from tests.stpa.sp1_helpers import MockLLMClient

    routed = _disposition("the intent is unknown")
    plans = (
        CandidateFamilyPlan(),
        CandidateFamilyPlan(not_applicable=routed),
        CandidateFamilyPlan(),
    )
    client = MockLLMClient()
    client.set_exception_for(
        _ContextScenarioSemanticsPayload,
        LengthFinishReasonError("structured response reached its length limit"),
    )

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=len(plans)),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
        condition_families=plans,
    )

    first, second, third = result.candidate_outcomes
    assert first.status is SP3CandidateStatus.generation_failed
    assert second.status is SP3CandidateStatus.not_applicable
    assert second.reason_code == INTENT_REASON_CODE
    assert second.diagnostics == (routed.reason,)
    assert third.status is SP3CandidateStatus.skipped
    assert third.reason_code is None
    # The abort names only the candidate it did not attempt.
    assert any(
        "Stage 5 aborted 1 remaining threats" in error for error in result.stage_errors
    )
    # The testability record agrees with the candidate outcomes.
    testability = yaml.safe_load((tmp_path / TESTABILITY_FILENAME).read_text())
    assert [entry["scenario_id"] for entry in testability["not_applicable"]] == [
        outcome.scenario_id
        for outcome in result.candidate_outcomes
        if outcome.status is SP3CandidateStatus.not_applicable
    ]


# --- the obligation accounting boundary --------------------------------------


def test_an_obligation_whose_only_finding_is_routed_is_still_generation_failed(
    tmp_path: Path,
) -> None:
    """Pin the current boundary: obligation accounting does not know the route.

    A routed ICA writes no scenario, so an addressed obligation whose only
    finding it is becomes ``generation_failed`` like any finding no scenario
    carries. Changing that is a separate accounting decision.
    """
    from asago_scenario_generator.pipeline.scenario_realization import (
        account_generation_failures,
    )
    from asago_scenario_generator.stpa.models.enriched_threat_set import (
        StructuralThreat,
    )
    from tests.helpers.sp3_run import threat_set_of
    from tests.stpa.sp1_helpers import MockLLMClient
    from tests.test_obligation_generation_failure import _recorded_row, _with_rows

    recorded = _recorded_row()
    [ica_id] = recorded.ica_ids
    [slot_id] = recorded.slot_ids
    threat = StructuralThreat(
        ica_slot_id=slot_id,
        ica_id=ica_id,
        ica_text="The reply is unsafe because the intent is unknown.",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    client = MockLLMClient()
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=threat_set_of([threat]),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
        condition_families=(
            CandidateFamilyPlan(not_applicable=_disposition("the intent is unknown")),
        ),
    )

    assert [o.status for o in result.candidate_outcomes] == [
        SP3CandidateStatus.not_applicable
    ]
    assert _stage5_requests(client) == []
    accounting = account_generation_failures(
        _with_rows(recorded),
        scenario_specs=result.scenario_specs,
        functional_test_specs=result.functional_test_specs,
    )
    [row] = accounting.rows
    assert row.disposition == "generation_failed"
    assert row.stop_reason == "scenario_generation_failure"
    assert row.ica_ids == (ica_id,)


# --- the cited value must itself be a sole failed-intent predicate ----------


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (
            "does not match authorized intent and the currency is wrong",
            "the request does not match authorized intent and the currency is wrong",
        ),
        (
            "intent unknown before the authorization status is confirmed",
            "the request is intent unknown before the authorization status is "
            "confirmed",
        ),
        (
            "does not match the customer's authorized intent or transaction context",
            "the request does not match the customer's authorized intent or "
            "transaction context",
        ),
        (
            "not aligned with authorized intent and the amount is negative",
            "the request is not aligned with authorized intent and the amount is "
            "negative",
        ),
        (
            "unauthorized transaction over the limit",
            "the request is an unauthorized transaction over the limit",
        ),
        (
            "intent matches but currency is different",
            "intent matches but currency is different",
        ),
    ],
)
def test_a_cited_value_with_mixed_grounds_or_another_failure_is_not_routed(
    value, reason
) -> None:
    variable = _var("PM-1-1", value, description=INTENT.description)

    assert _recognize(reason, _row(variable)) is None


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (
            "not aligned with authorized intent",
            "the request is not aligned with authorized intent",
        ),
        (
            "inconsistent with authorized intent",
            "the request is inconsistent with authorized intent",
        ),
        ("user intent unknown", "the request is user intent unknown"),
    ],
)
def test_a_cited_value_in_a_new_intent_only_form_is_routed(value, reason) -> None:
    variable = _var("PM-1-1", value, description=INTENT.description)

    disposition = _recognize(reason, _row(variable))

    assert disposition is not None
    assert disposition.basis == "reason_variable"


# --- common intent-only phrasings --------------------------------------------


@pytest.mark.parametrize(
    "reason",
    [
        "the request is not aligned with the customer's authorized intent",
        "the request is inconsistent with the customer's authorized intent",
        "the request is not consistent with the customer's authorized intent",
        "the request is misaligned with the customer's authorized intent",
        "the requested operation does not agree with the user's stated intent",
        "the user intent is unknown",
        "the customer intent is unknown",
        "the guest's intent is unknown",
        "the user's intent is not known",
        "the customer intent does not match the requested operation",
        "the user intent is not aligned with the requested payment",
    ],
)
def test_common_intent_only_phrasings_are_routed(reason) -> None:
    for row in (None, _row(ELIGIBLE)):
        disposition = _recognize(reason, row)
        assert disposition is not None, (reason, row)
        assert disposition.basis == "reason_wording"


@pytest.mark.parametrize(
    "reason",
    [
        "the request is not aligned with the customer's authorized intent and the "
        "amount is negative",
        "the request is inconsistent with the customer's authorized intent or "
        "transaction context",
        "the user intent is unknown before the authorization status is confirmed",
        "the user intent is known but the currency is inconsistent with the order",
        "the currency is not aligned with the user intent",
        "the user intent is classified as unknown",
        "the guest's intent is unknown and the guest is not the host",
    ],
)
def test_the_new_phrasings_reopen_no_mixed_ground(reason) -> None:
    for row in (None, _row(ELIGIBLE), _row(INTENT, ELIGIBLE)):
        assert _recognize(reason, row) is None, (reason, row)
