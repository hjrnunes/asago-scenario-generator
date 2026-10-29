"""The research script counts the sibling pairs the cross-scenario check evaluates."""

from __future__ import annotations

import collections
import importlib.util
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

from asago_scenario_generator.stpa.models.scenario_spec import (
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.observation_contract import SafeObservableOutcome
from asago_scenario_generator.stpa.scenario_prod.stage5.cross_scenario import (
    check_cross_scenario_conflicts,
)
from asago_scenario_generator.stpa.tool_call_condition import ToolCallCondition

from tests.stpa.helpers import make_scenario_spec

_SCRIPT = (
    Path(__file__).resolve().parents[1] / "scripts" / "safe_outcome_conflict_ceiling.py"
)
CONTEXT = {"PM-1-1": "unverified"}


def _script() -> ModuleType:
    name = "safe_outcome_conflict_ceiling_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


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
    call_made: bool | None,
    arguments: dict[str, Any] | None = None,
    condition: dict[str, Any] | None = None,
) -> ScenarioSpec:
    outcome = SafeObservableOutcome.model_validate(
        {
            "observable": True,
            "statement": "The agent's safe behavior around the refund.",
            "claim_level": "command_attempt",
            "evidence": "tool_call",
            "operation_name": "refund",
            "record_refs": ["TARGET-STATE"],
            "call_made": call_made,
            "call_arguments": (
                [{"argument": k, "value": v} for k, v in arguments.items()]
                if arguments is not None
                else None
            ),
        }
    )
    return make_scenario_spec(scenario_id).model_copy(
        update={
            "threat_source": ThreatSource(
                ica_slot_id="RESP-1:CA-1-1:INCORRECT",
                provenance="structural",
                ica_id=f"ICA-{scenario_id[-3:]}",
            ),
            "safe_observable_outcome": outcome,
            "tool_call_condition": (
                ToolCallCondition.model_validate({"comparisons": [condition]})
                if condition is not None
                else None
            ),
        }
    )


def _published(spec: ScenarioSpec) -> dict[str, Any]:
    """The fields of a published scenario the script reads."""
    outcome = spec.safe_observable_outcome
    condition = spec.tool_call_condition
    return {
        "scenario_id": spec.scenario_id,
        "lineage": {
            "ica_id": spec.threat_source.ica_id,
            "control_action_id": spec.target_control_action,
        },
        "safe_observable_outcome": (
            outcome.model_dump(mode="json") if outcome is not None else None
        ),
        "tool_call_condition": (
            condition.model_dump(mode="json") if condition is not None else None
        ),
    }


def _siblings() -> list[ScenarioSpec]:
    return [
        # States refunding ORD-1 as safe.
        _spec(
            "SCN-001",
            call_made=True,
            arguments={"order_id": "ORD-1"},
            condition=_refund_of("ORD-2"),
        ),
        # States that the refund is not made: it names no call.
        _spec("SCN-002", call_made=False, condition=_refund_of("ORD-1")),
        # Leaves open whether the refund is made: it names no call.
        _spec("SCN-003", call_made=None, condition=_refund_of("ORD-3")),
        # States the refund is made, with no values.
        _spec("SCN-004", call_made=True),
    ]


def test_the_script_counts_exactly_the_pairs_the_check_evaluates() -> None:
    specs = _siblings()
    contexts = {spec.threat_source.ica_id: CONTEXT for spec in specs}
    check = check_cross_scenario_conflicts(specs, contexts)

    eligible, pairs, invalid = _script().sibling_pairs(
        [_published(spec) for spec in specs], contexts
    )

    assert invalid == []
    assert (eligible, len(pairs)) == (check.eligible_pairs, check.evaluated_pairs)
    # Only SCN-001 and SCN-004 state a call; SCN-004 binds no condition.
    assert sorted(
        (failing["scenario_id"], safe["scenario_id"]) for safe, failing, _ in pairs
    ) == [
        ("SCN-001", "SCN-004"),
        ("SCN-002", "SCN-001"),
        ("SCN-002", "SCN-004"),
        ("SCN-003", "SCN-001"),
        ("SCN-003", "SCN-004"),
    ]
    rows = [_script().measure_pair(*pair) for pair in pairs]
    today = collections.Counter(row["today"] for row in rows)
    assert today == {
        "detected": len(check.conflicts),
        "inconclusive": len(check.inconclusive),
    }
    assert check.not_detected_pairs == 0
    assert [
        (row["scenario_id"], row["safe_scenario_id"])
        for row in rows
        if row["today"] == "detected"
    ] == [("SCN-002", "SCN-001")]


def test_a_published_condition_that_no_longer_validates_is_reported() -> None:
    scenarios = [_published(spec) for spec in _siblings()]
    argument = {"source": "argument", "operation": "refund", "argument": "order_id"}
    scenarios[1]["tool_call_condition"] = {
        "comparisons": [
            {"kind": "value", "left": argument, "op": "ne", "right": argument}
        ]
    }
    contexts = {scenario["lineage"]["ica_id"]: CONTEXT for scenario in scenarios}

    eligible, pairs, invalid = _script().sibling_pairs(scenarios, contexts)

    assert invalid == ["SCN-002"]
    assert eligible == 12
    assert all(failing["scenario_id"] != "SCN-002" for _, failing, _ in pairs)
