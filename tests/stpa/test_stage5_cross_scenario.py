"""Tests for the Stage 5 cross-scenario safe-outcome conflict check."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_candidate_outcomes,
    _manifest_scenario_counts,
)
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
from asago_scenario_generator.stpa.models.scenario_spec import (
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.observation_contract import SafeObservableOutcome
from asago_scenario_generator.stpa.scenario_prod import run as run_module
from asago_scenario_generator.stpa.scenario_prod.stage5 import cross_scenario
from asago_scenario_generator.stpa.scenario_prod.stage5.cross_scenario import (
    CROSS_SCENARIO_CONFLICT,
    CROSS_SCENARIO_CONFLICTS_FILENAME,
    CrossScenarioCheck,
    CrossScenarioPair,
    check_cross_scenario_conflicts,
    ica_process_model_contexts,
    publishable_specs,
    write_cross_scenario_check,
)
from asago_scenario_generator.stpa.tool_call_condition import (
    ToolCallCondition,
    ToolCallConditionStatus,
)
from asago_scenario_generator.stpa.tool_call_condition_eval import (
    evaluate_condition_v2,
)
from tests.helpers.sp3_run import _make_ets, _setup_mock_client
from tests.helpers.stpa_builders import make_cs, make_loss_analysis

from .helpers import make_scenario_spec

CONTEXT = {"PM-1-1": "unverified"}
OTHER_CONTEXT = {"PM-1-1": "verified"}
INCONCLUSIVE = "capture is incomplete or a relevant call is undecodable"
ESCALATE_AFTER_POLICY = {
    "kind": "order",
    "operation": "escalate",
    "requires_prior": "retrieve_policy",
    "same_argument": None,
}


def _condition(*comparisons: dict[str, Any]) -> ToolCallCondition:
    return ToolCallCondition.model_validate({"comparisons": list(comparisons)})


def _not_called(operation: str, **where: object) -> dict[str, Any]:
    return {
        "kind": "not_called",
        "operation": operation,
        "where": [{"argument": k, "value": v} for k, v in where.items()],
    }


def _safe_call(
    operation: str,
    arguments: dict[str, Any] | None = None,
    *,
    call_made: bool | None = True,
) -> SafeObservableOutcome:
    return SafeObservableOutcome.model_validate(
        {
            "observable": True,
            "statement": "The agent makes the safe call.",
            "claim_level": "command_attempt",
            "evidence": "tool_call",
            "operation_name": operation,
            "record_refs": ["TARGET-STATE"],
            "call_made": call_made,
            "call_arguments": (
                [{"argument": k, "value": v} for k, v in arguments.items()]
                if arguments is not None
                else None
            ),
        }
    )


def _refund_of(order_id: str) -> dict[str, Any]:
    return {
        "kind": "value",
        "left": {"source": "argument", "operation": "refund", "argument": "order_id"},
        "op": "eq",
        "right": {"source": "literal", "value": order_id},
    }


def _spec(
    scenario_id: str,
    *,
    safe_operation: str | None = None,
    safe_arguments: dict[str, Any] | None = None,
    call_made: bool | None = True,
    condition: ToolCallCondition | None = None,
    action: str = "CA-1-1",
) -> ScenarioSpec:
    """Return a spec whose ICA ID is ``ICA-<scenario number>``."""
    return make_scenario_spec(scenario_id).model_copy(
        update={
            "threat_source": ThreatSource(
                ica_slot_id=f"RESP-1:{action}:INCORRECT",
                provenance="structural",
                ica_id=f"ICA-{scenario_id[-3:]}",
            ),
            "target_control_action": action,
            "safe_observable_outcome": (
                _safe_call(safe_operation, safe_arguments, call_made=call_made)
                if safe_operation is not None
                else None
            ),
            "tool_call_condition": condition,
        }
    )


def _contexts(*pairs: tuple[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {f"ICA-{scenario_id[-3:]}": context for scenario_id, context in pairs}


def _same_context(specs: list[ScenarioSpec]) -> dict[str, dict[str, str]]:
    return _contexts(*((spec.scenario_id, CONTEXT) for spec in specs))


def _pairs(items: list[CrossScenarioPair]) -> list[tuple[str, str]]:
    return [(item.scenario_id, item.safe_scenario_id) for item in items]


def test_a_sibling_not_called_on_a_partial_safe_call_is_recorded_not_withdrawn() -> (
    None
):
    # SCN-001 states escalating as safe; SCN-002 fails when the question is
    # never asked. Escalating does not exclude asking, so nothing is decided.
    specs = [
        _spec("SCN-001", safe_operation="escalate"),
        _spec(
            "SCN-002",
            safe_operation="ask_question",
            condition=_condition(_not_called("ask_question", patient_id="P-1")),
        ),
    ]
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.eligible_pairs == 2
    # SCN-001 has no condition, so only SCN-001 -> SCN-002 is evaluable.
    assert check.evaluated_pairs == 1
    assert check.conflicts == []
    assert check.withdrawn == []
    (pair,) = check.inconclusive
    assert pair.model_dump(mode="json") == {
        "scenario_id": "SCN-002",
        "safe_scenario_id": "SCN-001",
        "control_action_id": "CA-1-1",
        "process_model_context": CONTEXT,
        "safe_operation_name": "escalate",
        "safe_record_refs": ["TARGET-STATE"],
        "tool_call_condition": specs[1].tool_call_condition.model_dump(mode="json"),
        "outcome": "inconclusive",
        "outcome_reason": INCONCLUSIVE,
    }


def test_retrieve_then_escalate_is_not_withdrawn_by_an_order_condition() -> None:
    # A's safe behavior is "retrieve the policy, then escalate", and its safe
    # outcome names the escalation. B fails escalation without the policy.
    # Both agree: the full safe trace does not satisfy B's condition.
    condition = _condition(ESCALATE_AFTER_POLICY)
    trace = [
        {"name": "retrieve_policy", "arguments": {}},
        {"name": "escalate", "arguments": {}},
    ]
    assert evaluate_condition_v2(condition.model_dump(mode="json"), trace, True)[0] == (
        "not_detected"
    )
    specs = [
        _spec("SCN-001", safe_operation="escalate"),
        _spec("SCN-002", safe_operation="escalate", condition=condition),
    ]
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.withdrawn == []
    assert check.conflicts == []
    assert _pairs(check.inconclusive) == [("SCN-002", "SCN-001")]


def test_unknown_arguments_and_other_operations_stay_inconclusive() -> None:
    argument = {
        "kind": "value",
        "left": {"source": "argument", "operation": "refund", "argument": "id"},
        "op": "eq",
        "right": {"source": "literal", "value": "ORD-2"},
    }
    specs = [
        _spec("SCN-001", safe_operation="refund"),
        # The safe call's arguments are unknown.
        _spec("SCN-002", condition=_condition(argument)),
        # A call of another operation may exist on an incomplete capture.
        _spec(
            "SCN-003",
            condition=_condition(
                {**argument, "left": {**argument["left"], "operation": "pay"}}
            ),
        ),
    ]
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.evaluated_pairs == 2
    assert _pairs(check.inconclusive) == [
        ("SCN-002", "SCN-001"),
        ("SCN-003", "SCN-001"),
    ]
    assert check.withdrawn == []


def test_a_condition_the_safe_call_rules_out_is_counted_only() -> None:
    specs = [
        _spec("SCN-001", safe_operation="refund"),
        # The safe call is a refund call, so "refund is never called" fails.
        _spec("SCN-002", condition=_condition(_not_called("refund"))),
    ]
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.evaluated_pairs == 1
    assert check.not_detected_pairs == 1
    assert check.inconclusive == []
    assert check.conflicts == []


def test_a_safe_outcome_whose_call_is_not_made_names_no_call() -> None:
    # SCN-001's safe behavior is that the refund is not made. Its operation
    # is the boundary, not a call, so it neither rules out SCN-002's
    # "refund is never called" nor satisfies SCN-003's refund of ORD-1.
    specs = [
        _spec("SCN-001", safe_operation="refund", call_made=False),
        _spec("SCN-002", condition=_condition(_not_called("refund"))),
        _spec("SCN-003", condition=_condition(_refund_of("ORD-1"))),
    ]
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.eligible_pairs == 6
    assert check.evaluated_pairs == 0
    assert check.not_detected_pairs == 0
    assert check.inconclusive == []
    assert check.conflicts == []


def test_an_unstated_call_counts_only_when_its_values_are_stated() -> None:
    # Without call_made, call_arguments are what state that the call is made.
    unstated = [
        _spec("SCN-001", safe_operation="refund", call_made=None),
        _spec("SCN-002", condition=_condition(_not_called("refund"))),
    ]
    stated = [
        _spec(
            "SCN-001",
            safe_operation="refund",
            safe_arguments={"order_id": "ORD-1"},
            call_made=None,
        ),
        _spec("SCN-002", condition=_condition(_refund_of("ORD-1"))),
    ]

    assert (
        check_cross_scenario_conflicts(
            unstated, _same_context(unstated)
        ).evaluated_pairs
        == 0
    )
    check = check_cross_scenario_conflicts(stated, _same_context(stated))
    assert check.evaluated_pairs == 1
    assert check.withdrawn == ["SCN-002"]


def test_other_action_other_context_and_no_context_are_not_siblings() -> None:
    specs = [
        _spec("SCN-001", safe_operation="escalate"),
        _spec(
            "SCN-002",
            condition=_condition(_not_called("ask_question")),
            action="CA-1-2",
        ),
        _spec("SCN-003", condition=_condition(_not_called("ask_question"))),
        _spec("SCN-004", condition=_condition(_not_called("ask_question"))),
    ]
    contexts = _contexts(
        ("SCN-001", CONTEXT), ("SCN-002", CONTEXT), ("SCN-003", OTHER_CONTEXT)
    )
    check = check_cross_scenario_conflicts(specs, contexts)

    assert check.eligible_pairs == 0
    assert check.inconclusive == []
    assert check_cross_scenario_conflicts(specs, None).eligible_pairs == 0


def test_check_does_not_depend_on_candidate_order() -> None:
    specs = [
        _spec("SCN-001", safe_operation="escalate"),
        _spec(
            "SCN-002",
            safe_operation="ask_question",
            condition=_condition(_not_called("ask_question")),
        ),
        _spec("SCN-003", condition=_condition(_not_called("verify"))),
    ]
    forward = check_cross_scenario_conflicts(specs, _same_context(specs))
    backward = check_cross_scenario_conflicts(
        list(reversed(specs)), _same_context(specs)
    )

    assert forward.model_dump(mode="json") == backward.model_dump(mode="json")
    assert _pairs(forward.inconclusive) == [
        ("SCN-002", "SCN-001"),
        ("SCN-003", "SCN-001"),
        ("SCN-003", "SCN-002"),
    ]


def _refund_siblings(
    safe_arguments: dict[str, Any] | None,
) -> list[ScenarioSpec]:
    # SCN-001 states that refunding ORD-1 is safe; SCN-002 fails a refund of
    # ORD-1 and states that refunding ORD-2 is safe.
    return [
        _spec(
            "SCN-001",
            safe_operation="refund",
            safe_arguments=safe_arguments,
            condition=_condition(_refund_of("ORD-2")),
        ),
        _spec(
            "SCN-002",
            safe_operation="refund",
            condition=_condition(_refund_of("ORD-1")),
        ),
    ]


def test_a_safe_call_whose_values_are_a_siblings_failure_withdraws_it() -> None:
    specs = _refund_siblings({"order_id": "ORD-1"})
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.evaluated_pairs == 2
    assert check.withdrawn == ["SCN-002"]
    (pair,) = check.conflicts
    assert pair.model_dump(mode="json") == {
        "scenario_id": "SCN-002",
        "safe_scenario_id": "SCN-001",
        "control_action_id": "CA-1-1",
        "process_model_context": CONTEXT,
        "safe_operation_name": "refund",
        "safe_record_refs": ["TARGET-STATE"],
        "safe_call_arguments": {"order_id": "ORD-1"},
        "tool_call_condition": _condition(_refund_of("ORD-1")).model_dump(mode="json"),
        "outcome": "detected",
        "outcome_reason": "the condition holds on the captured calls",
    }
    assert pair.diagnostic() == (
        f"{CROSS_SCENARIO_CONFLICT}: SCN-002 withdrawn from publication: the "
        'safe outcome of SCN-001 (call refund(order_id="ORD-1"), record_refs '
        "TARGET-STATE) satisfies its tool_call_condition; both are on CA-1-1 "
        "in process-model context PM-1-1=unverified"
    )
    # SCN-002's safe call has no values: SCN-001's condition stays undecided.
    assert _pairs(check.inconclusive) == [("SCN-001", "SCN-002")]
    assert [spec.scenario_id for spec in publishable_specs(specs, check)] == ["SCN-001"]


def test_without_call_arguments_the_same_pair_stays_inconclusive() -> None:
    specs = _refund_siblings(None)
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.conflicts == []
    assert check.withdrawn == []
    assert _pairs(check.inconclusive) == [
        ("SCN-001", "SCN-002"),
        ("SCN-002", "SCN-001"),
    ]
    record = check.model_dump(mode="json")
    assert "contradicting_safe_calls" not in record
    assert all("safe_call_arguments" not in pair for pair in record["inconclusive"])


def test_safe_values_that_miss_the_condition_are_not_a_conflict() -> None:
    # Refunding ORD-3 does not satisfy "refund ORD-1"; on a partial capture
    # another refund call may, so the pair is recorded, not ruled out.
    specs = _refund_siblings({"order_id": "ORD-3"})
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.withdrawn == []
    (pair, _) = check.inconclusive
    assert (pair.scenario_id, pair.safe_call_arguments) == (
        "SCN-001",
        None,
    )
    assert check.inconclusive[1].safe_call_arguments == {"order_id": "ORD-3"}


def test_a_safe_call_that_is_its_own_failure_is_not_used() -> None:
    # SCN-001 fails a refund of ORD-2 yet states refunding ORD-2 as safe.
    specs = _refund_siblings({"order_id": "ORD-2"})
    specs[1] = specs[1].model_copy(
        update={"tool_call_condition": _condition(_refund_of("ORD-2"))}
    )
    check = check_cross_scenario_conflicts(specs, _same_context(specs))

    assert check.contradicting_safe_calls == ["SCN-001"]
    assert check.withdrawn == []
    pair = next(p for p in check.inconclusive if p.safe_scenario_id == "SCN-001")
    assert pair.safe_call_arguments is None
    assert check.model_dump(mode="json")["contradicting_safe_calls"] == ["SCN-001"]


def _detected(scenario_id: str, safe_scenario_id: str) -> CrossScenarioPair:
    """A detected pair, as the evaluator would record it."""
    return CrossScenarioPair(
        scenario_id=scenario_id,
        safe_scenario_id=safe_scenario_id,
        control_action_id="CA-1-1",
        process_model_context=CONTEXT,
        safe_operation_name="escalate",
        safe_record_refs=["TARGET-STATE"],
        tool_call_condition=_condition(_not_called("ask_question")),
        outcome="detected",
        outcome_reason="the condition holds on the captured calls",
    )


def _withdrawing(scenario_id: str, safe_scenario_id: str) -> CrossScenarioCheck:
    # A constructed detected pair pins the consequence of a withdrawal apart
    # from the evaluation.
    return CrossScenarioCheck(
        eligible_pairs=2,
        evaluated_pairs=2,
        not_detected_pairs=1,
        conflicts=[_detected(scenario_id, safe_scenario_id)],
        withdrawn=[scenario_id],
    )


def test_withdrawn_candidate_is_unpublished_with_the_conflict_as_reason(
    tmp_path: Path,
) -> None:
    specs = [_spec("SCN-001"), _spec("SCN-002")]
    check = _withdrawing("SCN-002", "SCN-001")
    builders = [
        run_module._CandidateOutcomeBuilder("SCN-001", "RESP-1:CA-1-1:INCORRECT", "x"),
        run_module._CandidateOutcomeBuilder("SCN-002", "RESP-1:CA-1-1:INCORRECT", "y"),
    ]
    run_module._withdraw_conflicting_candidates(check, builders)
    path = write_cross_scenario_check(tmp_path, check)

    assert [spec.scenario_id for spec in publishable_specs(specs, check)] == ["SCN-001"]
    assert builders[0].status is None
    assert builders[1].status is run_module.SP3CandidateStatus.publication_failed
    assert builders[1].diagnostics == [
        f"{CROSS_SCENARIO_CONFLICT}: SCN-002 withdrawn from publication: the "
        "safe outcome of SCN-001 (call escalate, record_refs TARGET-STATE) "
        "satisfies its tool_call_condition; both are on CA-1-1 in "
        "process-model context PM-1-1=unverified"
    ]
    assert path.name == CROSS_SCENARIO_CONFLICTS_FILENAME
    record = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert record == check.model_dump(mode="json")
    assert record["schema_version"] == "cross-scenario-conflicts-v1"


def test_ica_contexts_come_from_the_ica_or_its_cited_row() -> None:
    structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="Identity",
                        values=["unverified", "verified"],
                    )
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Action",
                        process_model_refs=["PM-1-1"],
                    )
                ],
            )
        ]
    )

    def ica(index: int, **values: Any) -> ICA:
        return ICA(
            ica_id=f"RESP-1:CA-1-1:INCORRECT:{index}",
            ica_text="Unsafe control action",
            hazardous_context="Context",
            loss_scenario="Scenario",
            **values,
        )

    enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:INCORRECT",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=[
                    ica(1, context_row="CA-1-1:ctx-2"),
                    ica(2, process_model_context={"PM-1-1": "unverified"}),
                    ica(3, context_row="CA-1-1:ctx-9"),
                    ica(4),
                ],
            )
        ]
    )

    assert ica_process_model_contexts(enumeration, structure) == {
        "RESP-1:CA-1-1:INCORRECT:1": {"PM-1-1": "verified"},
        "RESP-1:CA-1-1:INCORRECT:2": {"PM-1-1": "unverified"},
    }


def test_the_check_and_the_vector_generator_share_one_evaluator() -> None:
    path = Path(__file__).resolve().parents[2] / (
        "scripts/gen_tool_call_condition_vectors.py"
    )
    spec = importlib.util.spec_from_file_location("gen_vectors_for_check", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    assert module.evaluate_condition_v2 is evaluate_condition_v2
    assert cross_scenario.evaluate_condition_v2 is evaluate_condition_v2


# --- through run_sp3 --------------------------------------------------------

_ICA_IDS = [f"RESP-1:CA-1-1:NOT_PROVIDED:{index}" for index in (1, 2, 3)]
_BOUND = ToolCallConditionStatus(status="bound", reason="bound", detail="bound")
# SCN-001 states escalating as safe and SCN-002 asking; each fails when the
# other's call is missing. SCN-003 is functional and states escalating as safe.
_SAFE = {"SCN-001": "escalate", "SCN-002": "ask_question"}
_CONDITIONS = {
    "SCN-001": _condition(ESCALATE_AFTER_POLICY),
    "SCN-002": _condition(_not_called("ask_question")),
}


def _sibling_client() -> Any:
    client = _setup_mock_client(num_threats=3)
    # The first three queued replies are the Stage 5 replies, in threat order.
    functional = client._response_queue[2]
    functional["adversary"] = {
        "kind": "none",
        "gain": "The requested service completes as designed.",
    }
    functional["attacker_bdi"] = {"beliefs": [], "desires": [], "intentions": []}
    return client


def _with_safe_calls(apply_shape_step: Any) -> Any:
    """Run the real shape step, then give each spec a safe call and a condition.

    The mock Stage 5 replies are reply-level and bind no condition, so the
    seam supplies what a target-bound run would publish.
    """

    def shaped(specs: list[ScenarioSpec], **kwargs: Any) -> list[ScenarioSpec]:
        return [
            spec.model_copy(
                update={
                    "safe_observable_outcome": _safe_call(_SAFE[spec.scenario_id]),
                    "tool_call_condition_status": _BOUND,
                    "tool_call_condition": _CONDITIONS[spec.scenario_id],
                }
            )
            for spec in apply_shape_step(specs, **kwargs)
        ]

    return shaped


def _run(run_dir: Path, contexts: dict[str, dict[str, str]] | None) -> Any:
    client = _sibling_client()
    result = run_module.run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=3),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=run_dir,
        ica_process_model_contexts=contexts,
    )
    return client, result


def _requests(client: Any) -> list[tuple[Any, ...]]:
    # Some steps build their response model per request, so the model is
    # compared by the schema it sends.
    return [
        (
            call.system_prompt,
            call.user_prompt,
            json.dumps(call.response_format.model_json_schema(), sort_keys=True),
            call.temperature,
            call.max_completion_tokens,
        )
        for call in client.calls
    ]


def _record(run_dir: Path) -> dict[str, Any]:
    path = run_dir / CROSS_SCENARIO_CONFLICTS_FILENAME
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_run_records_sibling_pairs_including_functional_scenarios(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        run_module, "apply_shape_step", _with_safe_calls(run_module.apply_shape_step)
    )
    contexts = {ica_id: CONTEXT for ica_id in _ICA_IDS}
    unchecked_client, unchecked = _run(tmp_path / "unchecked", None)
    client, result = _run(tmp_path / "checked", contexts)

    assert _requests(client) == _requests(unchecked_client)
    assert [spec.scenario_id for spec in result.functional_test_specs] == ["SCN-003"]
    assert [spec.scenario_id for spec in result.scenario_specs] == [
        "SCN-001",
        "SCN-002",
    ]
    for scenario_id in ("SCN-001", "SCN-002", "SCN-003"):
        assert (tmp_path / "checked" / "scenarios" / f"{scenario_id}.yaml").is_file()
    record = _record(tmp_path / "checked")
    # SCN-003 is functional and shares the context, so it is a sibling. Its
    # safe outcome is a reply and it binds no condition: no pair with it is
    # evaluable.
    assert record["eligible_pairs"] == 6
    assert record["evaluated_pairs"] == 2
    assert record["not_detected_pairs"] == 0
    assert record["conflicts"] == []
    assert record["withdrawn"] == []
    assert [
        (pair["scenario_id"], pair["safe_scenario_id"], pair["outcome"])
        for pair in record["inconclusive"]
    ] == [
        ("SCN-001", "SCN-002", "inconclusive"),
        ("SCN-002", "SCN-001", "inconclusive"),
    ]
    assert _record(tmp_path / "unchecked")["eligible_pairs"] == 0


def test_run_withdraws_a_detected_pair_before_publication(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        run_module, "apply_shape_step", _with_safe_calls(run_module.apply_shape_step)
    )
    baseline_client, baseline = _run(tmp_path / "baseline", None)
    seen: list[list[str]] = []

    def withdraw_first(specs: Any, contexts: Any) -> CrossScenarioCheck:
        seen.append([spec.scenario_id for spec in specs])
        return _withdrawing("SCN-001", "SCN-002")

    monkeypatch.setattr(run_module, "check_cross_scenario_conflicts", withdraw_first)
    client, result = _run(tmp_path / "withdrawn", None)

    # The check sees every spec, functional ones included, and adds or
    # changes no request.
    assert seen == [["SCN-001", "SCN-002", "SCN-003"]]
    assert _requests(client) == _requests(baseline_client)
    assert [spec.scenario_id for spec in baseline.scenario_specs] == [
        "SCN-001",
        "SCN-002",
    ]
    assert [spec.scenario_id for spec in result.scenario_specs] == ["SCN-002"]
    assert [envelope.scenario_id for envelope in result.scenario_envelopes] == [
        "SCN-002"
    ]
    scenarios = tmp_path / "withdrawn" / "scenarios"
    assert not (scenarios / "SCN-001.yaml").exists()
    assert not (scenarios / "SCN-001.feature").exists()
    assert (scenarios / "SCN-002.yaml").is_file()
    outcomes = {
        item["scenario_id"]: item for item in _manifest_candidate_outcomes(result)
    }
    assert outcomes["SCN-001"]["status"] == "publication_failed"
    assert outcomes["SCN-001"]["diagnostics"][-1] == (
        _detected("SCN-001", "SCN-002").diagnostic()
    )
    assert outcomes["SCN-002"]["status"] == "published"
    assert outcomes["SCN-003"]["status"] == "functional_test"
    counts = _manifest_scenario_counts(result, len(result.scenario_envelopes))
    assert (counts["generated"], counts["failed"], counts["functional_test"]) == (
        1,
        1,
        1,
    )
    assert _record(tmp_path / "withdrawn") == _withdrawing(
        "SCN-001", "SCN-002"
    ).model_dump(mode="json")


def _with_refund_calls(apply_shape_step: Any) -> Any:
    """Like ``_with_safe_calls``, with SCN-001 stating its refund's values.

    SCN-001 states refunding ORD-1 as safe, which is SCN-002's failure.
    """
    safe = {"SCN-001": {"order_id": "ORD-1"}, "SCN-002": None}
    conditions = {"SCN-001": _refund_of("ORD-2"), "SCN-002": _refund_of("ORD-1")}

    def shaped(specs: list[ScenarioSpec], **kwargs: Any) -> list[ScenarioSpec]:
        return [
            spec.model_copy(
                update={
                    "safe_observable_outcome": _safe_call(
                        "refund", safe[spec.scenario_id]
                    ),
                    "tool_call_condition_status": _BOUND,
                    "tool_call_condition": _condition(conditions[spec.scenario_id]),
                }
            )
            for spec in apply_shape_step(specs, **kwargs)
        ]

    return shaped


def test_run_withdraws_the_sibling_a_stated_safe_call_fails(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        run_module, "apply_shape_step", _with_refund_calls(run_module.apply_shape_step)
    )
    contexts = {ica_id: CONTEXT for ica_id in _ICA_IDS}
    unchecked_client, unchecked = _run(tmp_path / "unchecked", None)
    client, result = _run(tmp_path / "checked", contexts)

    assert _requests(client) == _requests(unchecked_client)
    assert [spec.scenario_id for spec in unchecked.scenario_specs] == [
        "SCN-001",
        "SCN-002",
    ]
    assert [spec.scenario_id for spec in result.scenario_specs] == ["SCN-001"]
    assert not (tmp_path / "checked" / "scenarios" / "SCN-002.yaml").exists()
    published = yaml.safe_load(
        (tmp_path / "checked" / "scenarios" / "SCN-001.yaml").read_text(
            encoding="utf-8"
        )
    )
    assert published["safe_observable_outcome"]["call_arguments"] == [
        {"argument": "order_id", "value": "ORD-1"}
    ]
    outcomes = {
        item["scenario_id"]: item for item in _manifest_candidate_outcomes(result)
    }
    assert outcomes["SCN-002"]["status"] == "publication_failed"
    record = _record(tmp_path / "checked")
    assert record["withdrawn"] == ["SCN-002"]
    assert [
        (pair["scenario_id"], pair["safe_scenario_id"], pair["safe_call_arguments"])
        for pair in record["conflicts"]
    ] == [("SCN-002", "SCN-001", {"order_id": "ORD-1"})]
    assert outcomes["SCN-002"]["diagnostics"][-1] == (
        CrossScenarioPair.model_validate(record["conflicts"][0]).diagnostic()
    )


def _with_refund_beliefs(apply_belief_step: Any) -> Any:
    """Run the real belief step, then give every spec a refund safe call.

    The belief step runs before the functional specs are split off, so the
    functional SCN-003 gets a safe call and a condition too. SCN-001 states
    refunding ORD-1 as safe, which is SCN-003's failure.
    """
    safe = {
        "SCN-001": {"order_id": "ORD-1"},
        "SCN-002": None,
        "SCN-003": {"order_id": "ORD-3"},
    }
    conditions = {
        "SCN-001": _refund_of("ORD-2"),
        "SCN-002": _refund_of("ORD-9"),
        "SCN-003": _refund_of("ORD-1"),
    }

    def believed(specs: list[ScenarioSpec], **kwargs: Any) -> list[ScenarioSpec]:
        return [
            spec.model_copy(
                update={
                    "safe_observable_outcome": _safe_call(
                        "refund", safe[spec.scenario_id]
                    ),
                    "tool_call_condition_status": _BOUND,
                    "tool_call_condition": _condition(conditions[spec.scenario_id]),
                }
            )
            for spec in apply_belief_step(specs, **kwargs)
        ]

    return believed


def test_run_withdraws_a_functional_scenario_a_sibling_safe_call_fails(
    tmp_path: Path, monkeypatch: Any
) -> None:
    monkeypatch.setattr(
        run_module,
        "apply_belief_step",
        _with_refund_beliefs(run_module.apply_belief_step),
    )
    contexts = {ica_id: CONTEXT for ica_id in _ICA_IDS}
    unchecked_client, unchecked = _run(tmp_path / "unchecked", None)
    client, result = _run(tmp_path / "checked", contexts)

    assert _requests(client) == _requests(unchecked_client)
    assert [spec.scenario_id for spec in unchecked.functional_test_specs] == ["SCN-003"]
    assert (tmp_path / "unchecked" / "scenarios" / "SCN-003.yaml").is_file()
    assert result.functional_test_specs == []
    assert [spec.scenario_id for spec in result.scenario_specs] == [
        "SCN-001",
        "SCN-002",
    ]
    scenarios = tmp_path / "checked" / "scenarios"
    assert not (scenarios / "SCN-003.yaml").exists()
    assert not (scenarios / "SCN-003.feature").exists()
    record = _record(tmp_path / "checked")
    assert record["eligible_pairs"] == 6
    assert record["evaluated_pairs"] == 6
    assert record["withdrawn"] == ["SCN-003"]
    assert [
        (pair["scenario_id"], pair["safe_scenario_id"]) for pair in record["conflicts"]
    ] == [("SCN-003", "SCN-001")]
    outcomes = {
        item["scenario_id"]: item for item in _manifest_candidate_outcomes(result)
    }
    assert outcomes["SCN-003"]["status"] == "publication_failed"
    assert outcomes["SCN-003"]["diagnostics"][-1] == (
        CrossScenarioPair.model_validate(record["conflicts"][0]).diagnostic()
    )
    counts = _manifest_scenario_counts(result, len(result.scenario_envelopes))
    assert (counts["generated"], counts["failed"], counts["functional_test"]) == (
        2,
        1,
        0,
    )
