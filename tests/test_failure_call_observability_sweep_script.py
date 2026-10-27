"""The offline before/after count of the failure-call observability rule."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)

_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "scripts"
    / "failure_call_observability_sweep.py"
)
OPERATIONS = ("commit_to_ehr", "get_referral")


def _script() -> ModuleType:
    name = "failure_call_observability_sweep_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def _handoff(
    scenario_id: str = "SCN-001",
    *,
    disposition: str = "analytical_only",
    failure_call: dict | None = None,
    named: tuple[str, ...] = (),
    reason: str = "The contract does not capture tool arguments.",
) -> dict:
    handoff = {
        "scenario_id": scenario_id,
        "semantic_failure_criterion": "The assistant commits an unreviewed draft.",
        "documented_operations": [
            {"name": name, "authority": "criterion_observed_operation"}
            for name in named
        ],
        "observation": {
            "criteria": [
                {
                    "criterion_id": "obs_1",
                    "outcome": "An unreviewed draft is committed.",
                    "observable": False,
                    "reason": reason,
                }
            ],
            "assessment": {
                "disposition": disposition,
                "reason": "no_observable_outcome",
            },
        },
        "tool_call_condition_status": {"status": "not_executable"},
    }
    if failure_call is not None:
        handoff["semantic_failure_call"] = failure_call
    return handoff


def _assess(handoff: dict) -> dict:
    return _script().assess_handoff(handoff, default_observation_contract(), OPERATIONS)


def test_a_handoff_failure_call_of_a_recorded_operation_becomes_executable() -> None:
    row = _assess(
        _handoff(
            failure_call={"kind": "incorrect_call", "operation_name": "commit_to_ehr"}
        )
    )

    assert (row["before"], row["after"], row["after_proxy"]) == (
        "analytical_only",
        "executable",
        "executable",
    )


def test_without_a_failure_call_only_the_proxy_moves() -> None:
    row = _assess(_handoff(named=("commit_to_ehr",)))

    assert (row["after"], row["after_proxy"]) == ("analytical_only", "executable")
    assert row["proxy_operations"] == ["commit_to_ehr"]
    assert row["population"] == "provider_unobservable"


def test_a_criterion_that_names_no_recorded_operation_stays_analytical() -> None:
    row = _assess(_handoff(named=("delete_account",)))

    assert (row["after"], row["after_proxy"]) == ("analytical_only", "analytical_only")
    assert row["proxy_operations"] == []


def test_a_demoted_criterion_is_counted_as_a_failed_condition() -> None:
    row = _assess(
        _handoff(
            named=("commit_to_ehr",),
            reason="Not observable: the discriminating condition failed validation "
            "(discriminating_condition_check_failed), so the scenario is "
            "published as analytical_only and no criterion is observed.",
        )
    )

    assert row["population"] == "condition_failed"


def test_an_executable_handoff_is_left_out_of_the_counts() -> None:
    script = _script()
    rows = [
        _assess(_handoff("SCN-001", named=("commit_to_ehr",))),
        _assess(_handoff("SCN-002", disposition="executable")),
    ]

    summary = script.summarize(Path("out"), "miniocciai", rows)
    report = script.report([summary], ["miniocciai:SCN-001", "miniocciai:SCN-002"])

    assert (
        summary["handoffs"],
        summary["analytical_before"],
        summary["analytical_after"],
        summary["analytical_after_proxy"],
    ) == (2, 1, 1, 0)
    assert summary["executable_after_proxy"] == ["SCN-001"]
    assert [item["before"] for item in report["examples"]] == [
        "analytical_only",
        "not analytical_only",
    ]
    assert report["total"]["analytical_before"] == 1


FAILED_NOTE = (
    "The discriminating condition failed validation after two corrections "
    "(discriminating_condition_check_failed); the failure call names an "
    "operation the target records, so the command_attempt claim stays "
    "observable and the scenario is published without a condition."
)


def _failed_condition_handoff(
    scenario_id: str = "SCN-001",
    *,
    failure_call: dict | None = None,
    named: tuple[str, ...] = (),
    claim_level: str = "command_attempt",
) -> dict:
    handoff = _handoff(
        scenario_id, disposition="executable", failure_call=failure_call, named=named
    )
    handoff["condition_omitted_reason"] = FAILED_NOTE
    handoff["safe_observable_outcome"] = {"claim_level": claim_level}
    return handoff


def test_a_failed_condition_of_a_recorded_missing_call_gets_the_derived_condition() -> (
    None
):
    row = _assess(
        _failed_condition_handoff(
            failure_call={"kind": "missing_call", "operation_name": "get_referral"}
        )
    )

    assert (row["condition"], row["condition_proxy"]) == ("derived_not_called", False)


def test_a_failed_condition_of_an_incorrect_call_stays_without_one() -> None:
    row = _assess(
        _failed_condition_handoff(
            failure_call={"kind": "incorrect_call", "operation_name": "commit_to_ehr"}
        )
    )

    assert row["condition"] == "incorrect_call_no_condition"


def test_no_condition_is_derived_off_the_failure_call_route() -> None:
    missing = {"kind": "missing_call", "operation_name": "get_referral"}
    outside = {"kind": "missing_call", "operation_name": "delete_account"}
    bound = _failed_condition_handoff(failure_call=missing)
    bound["tool_call_condition"] = {"comparisons": [{"kind": "not_called"}]}

    rows = [
        _assess(_failed_condition_handoff(failure_call=outside)),
        _assess(_failed_condition_handoff(failure_call=missing, claim_level="reply")),
        _assess(bound),
        _assess(_handoff(disposition="executable", failure_call=missing)),
    ]

    assert [row["condition"] for row in rows] == ["unchanged"] * 4


def test_a_failed_condition_without_a_failure_call_is_only_a_proxy() -> None:
    row = _assess(_failed_condition_handoff(named=("commit_to_ehr",)))

    assert (row["condition"], row["condition_proxy"]) == ("unchanged", True)


def test_the_condition_classes_are_counted_per_directory() -> None:
    script = _script()
    missing = {"kind": "missing_call", "operation_name": "get_referral"}
    incorrect = {"kind": "incorrect_call", "operation_name": "commit_to_ehr"}
    rows = [
        _assess(_failed_condition_handoff("SCN-001", failure_call=missing)),
        _assess(_failed_condition_handoff("SCN-002", failure_call=incorrect)),
        _assess(_failed_condition_handoff("SCN-003", named=("commit_to_ehr",))),
        _assess(_handoff("SCN-004")),
    ]

    summary = script.summarize(Path("out"), "miniocciai", rows)
    report = script.report([summary])

    assert (
        summary["derived_not_called"],
        summary["incorrect_call_no_condition"],
        summary["unchanged"],
        summary["condition_proxy"],
    ) == (["SCN-001"], ["SCN-002"], 2, ["SCN-003"])
    assert {
        key: report["total"][key]
        for key in (
            "derived_not_called",
            "incorrect_call_no_condition",
            "unchanged",
            "condition_proxy",
        )
    } == {
        "derived_not_called": 1,
        "incorrect_call_no_condition": 1,
        "unchanged": 2,
        "condition_proxy": 1,
    }
    assert "| miniocciai | out | 1 | 1 | 2 | 1 |" in script.render([summary])
