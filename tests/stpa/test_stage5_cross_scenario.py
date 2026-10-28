"""Tests for the Stage 5 cross-scenario safe-outcome conflict check."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

import yaml

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
    check_cross_scenario_conflicts,
    ica_process_model_contexts,
    publishable_specs,
    write_cross_scenario_check,
)
from asago_scenario_generator.stpa.tool_call_condition import ToolCallCondition
from asago_scenario_generator.stpa.tool_call_condition_eval import (
    evaluate_condition_v2,
)

from tests.helpers.sp3_run import _make_ets, _setup_mock_client
from tests.helpers.stpa_builders import make_cs, make_loss_analysis

from .helpers import make_scenario_spec

CONTEXT = {"PM-1-1": "unverified"}
OTHER_CONTEXT = {"PM-1-1": "verified"}


def _condition(*comparisons: dict[str, Any]) -> ToolCallCondition:
    return ToolCallCondition.model_validate({"comparisons": list(comparisons)})


def _not_called(operation: str, **where: object) -> dict[str, Any]:
    return {
        "kind": "not_called",
        "operation": operation,
        "where": [{"argument": k, "value": v} for k, v in where.items()],
    }


def _spec(
    scenario_id: str,
    *,
    safe_operation: str | None = None,
    condition: ToolCallCondition | None = None,
    action: str = "CA-1-1",
) -> ScenarioSpec:
    """Return a spec whose ICA ID is ``ICA-<scenario number>``."""
    safe = None
    if safe_operation is not None:
        safe = SafeObservableOutcome(
            observable=True,
            statement="The agent makes the safe call.",
            claim_level="command_attempt",
            evidence="tool_call",
            operation_name=safe_operation,
            record_refs=("TARGET-STATE",),
        )
    return make_scenario_spec(scenario_id).model_copy(
        update={
            "threat_source": ThreatSource(
                ica_slot_id=f"RESP-1:{action}:INCORRECT",
                provenance="structural",
                ica_id=f"ICA-{scenario_id[-3:]}",
            ),
            "target_control_action": action,
            "safe_observable_outcome": safe,
            "tool_call_condition": condition,
        }
    )


def _contexts(*pairs: tuple[str, dict[str, str]]) -> dict[str, dict[str, str]]:
    return {f"ICA-{scenario_id[-3:]}": context for scenario_id, context in pairs}


def _escalate_vs_answer() -> list[ScenarioSpec]:
    # SCN-001 states escalating as safe; SCN-002 fails when the question is
    # never asked, which escalating alone satisfies.
    return [
        _spec("SCN-001", safe_operation="escalate"),
        _spec(
            "SCN-002",
            safe_operation="ask_question",
            condition=_condition(_not_called("ask_question", patient_id="P-1")),
        ),
    ]


def test_safe_call_that_satisfies_a_sibling_condition_withdraws_the_sibling() -> None:
    specs = _escalate_vs_answer()
    check = check_cross_scenario_conflicts(
        specs, _contexts(("SCN-001", CONTEXT), ("SCN-002", CONTEXT))
    )

    assert check.eligible_pairs == 2
    # SCN-001 has no condition, so only SCN-001 -> SCN-002 is evaluable.
    assert check.evaluated_pairs == 1
    assert check.withdrawn == ["SCN-002"]
    (conflict,) = check.conflicts
    assert conflict.model_dump(mode="json") == {
        "scenario_id": "SCN-002",
        "reason": CROSS_SCENARIO_CONFLICT,
        "safe_scenario_id": "SCN-001",
        "control_action_id": "CA-1-1",
        "process_model_context": CONTEXT,
        "safe_operation_name": "escalate",
        "safe_record_refs": ["TARGET-STATE"],
        "tool_call_condition": specs[1].tool_call_condition.model_dump(mode="json"),
    }


def test_conflicts_in_both_directions_withdraw_both_scenarios() -> None:
    specs = [
        _spec(
            "SCN-001",
            safe_operation="escalate",
            condition=_condition(_not_called("escalate")),
        ),
        _spec(
            "SCN-002",
            safe_operation="ask_question",
            condition=_condition(_not_called("ask_question")),
        ),
    ]
    check = check_cross_scenario_conflicts(
        specs, _contexts(("SCN-001", CONTEXT), ("SCN-002", CONTEXT))
    )

    assert check.withdrawn == ["SCN-001", "SCN-002"]
    assert [(c.scenario_id, c.safe_scenario_id) for c in check.conflicts] == [
        ("SCN-001", "SCN-002"),
        ("SCN-002", "SCN-001"),
    ]


def test_order_without_the_prior_call_is_a_conflict() -> None:
    order = {
        "kind": "order",
        "operation": "escalate",
        "requires_prior": "retrieve_policy",
        "same_argument": None,
    }
    specs = [
        _spec("SCN-001", safe_operation="escalate"),
        _spec("SCN-002", safe_operation="escalate", condition=_condition(order)),
    ]
    check = check_cross_scenario_conflicts(
        specs, _contexts(("SCN-001", CONTEXT), ("SCN-002", CONTEXT))
    )

    assert check.withdrawn == ["SCN-002"]


def test_condition_the_safe_call_does_not_satisfy_is_no_conflict() -> None:
    argument = {
        "kind": "value",
        "left": {"source": "argument", "operation": "refund", "argument": "id"},
        "op": "eq",
        "right": {"source": "literal", "value": "ORD-2"},
    }
    specs = [
        _spec("SCN-001", safe_operation="refund"),
        # Calling refund does not satisfy "refund is never called".
        _spec("SCN-002", condition=_condition(_not_called("refund"))),
        # The safe call's arguments are unknown: inconclusive, not detected.
        _spec("SCN-003", condition=_condition(argument)),
        # No call of another operation exists on a complete capture.
        _spec(
            "SCN-004",
            condition=_condition(
                {**argument, "left": {**argument["left"], "operation": "pay"}}
            ),
        ),
    ]
    contexts = _contexts(*((spec.scenario_id, CONTEXT) for spec in specs))
    check = check_cross_scenario_conflicts(specs, contexts)

    assert check.evaluated_pairs == 3
    assert check.conflicts == []
    assert check.withdrawn == []


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
    assert check.withdrawn == []
    assert check_cross_scenario_conflicts(specs, None).eligible_pairs == 0


def test_check_does_not_depend_on_candidate_order() -> None:
    specs = [
        *_escalate_vs_answer(),
        _spec("SCN-003", condition=_condition(_not_called("verify"))),
    ]
    contexts = _contexts(*((spec.scenario_id, CONTEXT) for spec in specs))
    forward = check_cross_scenario_conflicts(specs, contexts)
    backward = check_cross_scenario_conflicts(list(reversed(specs)), contexts)

    assert forward.model_dump(mode="json") == backward.model_dump(mode="json")
    assert [(c.scenario_id, c.safe_scenario_id) for c in forward.conflicts] == [
        ("SCN-002", "SCN-001"),
        ("SCN-003", "SCN-001"),
        ("SCN-003", "SCN-002"),
    ]
    assert forward.withdrawn == ["SCN-002", "SCN-003"]


def test_withdrawn_candidate_is_unpublished_with_the_conflict_as_reason(
    tmp_path: Path,
) -> None:
    specs = _escalate_vs_answer()
    check = check_cross_scenario_conflicts(
        specs, _contexts(("SCN-001", CONTEXT), ("SCN-002", CONTEXT))
    )
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
    assert record["schema_version"] == "cross-scenario-conflicts-v1"
    assert record["withdrawn"] == ["SCN-002"]
    assert record["conflicts"][0]["reason"] == CROSS_SCENARIO_CONFLICT


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


def _withdraw_first(specs, contexts):
    """Stand in for the check: withdraw SCN-001 for a sibling SCN-002."""
    conflict = cross_scenario.CrossScenarioConflict(
        scenario_id="SCN-001",
        safe_scenario_id="SCN-002",
        control_action_id="CA-1-1",
        process_model_context=CONTEXT,
        safe_operation_name="escalate",
        safe_record_refs=["TARGET-STATE"],
        tool_call_condition=_condition(_not_called("ask_question")),
    )
    return cross_scenario.CrossScenarioCheck(
        eligible_pairs=2, evaluated_pairs=2, conflicts=[conflict], withdrawn=["SCN-001"]
    )


def test_run_withdraws_before_publication_without_another_model_call(
    tmp_path: Path, monkeypatch: Any
) -> None:
    def run(run_dir: Path) -> tuple[Any, Any]:
        client = _setup_mock_client(num_threats=2)
        result = run_module.run_sp3(
            llm_client=client,
            enriched_threat_set=_make_ets(num_threats=2),
            control_structure=make_cs(),
            loss_analysis=make_loss_analysis(),
            run_dir=run_dir,
        )
        return client, result

    baseline_client, baseline = run(tmp_path / "baseline")
    monkeypatch.setattr(run_module, "check_cross_scenario_conflicts", _withdraw_first)
    client, result = run(tmp_path / "withdrawn")

    assert len(client.calls) == len(baseline_client.calls)
    assert [spec.scenario_id for spec in baseline.scenario_specs] == [
        "SCN-001",
        "SCN-002",
    ]
    assert [spec.scenario_id for spec in result.scenario_specs] == ["SCN-002"]
    assert [e.scenario_id for e in result.scenario_envelopes] == ["SCN-002"]
    scenarios = tmp_path / "withdrawn" / "scenarios"
    assert not (scenarios / "SCN-001.yaml").exists()
    assert (scenarios / "SCN-002.yaml").is_file()
    outcomes = {item.scenario_id: item for item in result.candidate_outcomes}
    assert (
        outcomes["SCN-001"].status is run_module.SP3CandidateStatus.publication_failed
    )
    assert outcomes["SCN-001"].diagnostics[-1].startswith(CROSS_SCENARIO_CONFLICT)
    assert outcomes["SCN-002"].status is run_module.SP3CandidateStatus.published
    record = yaml.safe_load(
        (tmp_path / "withdrawn" / CROSS_SCENARIO_CONFLICTS_FILENAME).read_text(
            encoding="utf-8"
        )
    )
    assert record["withdrawn"] == ["SCN-001"]
    # Without ICA contexts nothing is eligible, and the record says so.
    assert yaml.safe_load(
        (tmp_path / "baseline" / CROSS_SCENARIO_CONFLICTS_FILENAME).read_text(
            encoding="utf-8"
        )
    ) == {
        "schema_version": "cross-scenario-conflicts-v1",
        "eligible_pairs": 0,
        "evaluated_pairs": 0,
        "conflicts": [],
        "withdrawn": [],
    }
