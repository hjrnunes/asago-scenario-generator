"""The offline parts of the conflict review pilot: selector, cases, validators, runner.

Every model reply here comes from a fake provider; nothing reaches a network.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest
import yaml
from pydantic import ValidationError

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
from tests.helpers.provider_call_record import (
    _client,
    _completion,
    _Provider,
    _records,
)

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "conflict_review_pilot.py"


def _script() -> ModuleType:
    name = "conflict_review_pilot_script"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


# A tiny recorded run ------------------------------------------------------


def _structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Controller",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="Identity of the actor",
                        values=["unverified", "verified"],
                    )
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Read record",
                        process_model_refs=["PM-1-1"],
                    ),
                    ControlAction(
                        ca_id="CA-1-2",
                        description="Change record",
                        process_model_refs=["PM-1-1"],
                    ),
                ],
            )
        ]
    )


def _enumeration() -> ICAEnumeration:
    def ica(action: str, index: int, context: dict[str, str] | None) -> ICA:
        return ICA(
            ica_id=f"RESP-1:{action}:INCORRECT:{index}",
            ica_text="Unsafe control action",
            hazardous_context="Context",
            loss_scenario="Scenario",
            process_model_context=context,
        )

    return ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=f"RESP-1:{action}:INCORRECT",
                responsibility="RESP-1",
                control_action=action,
                uca_type=UCAType.incorrect,
                is_na=False,
                icas=icas,
            )
            for action, icas in (
                ("CA-1-1", [ica("CA-1-1", 1, {"PM-1-1": "unverified"})]),
                ("CA-1-2", [ica("CA-1-2", 1, None)]),
            )
        ]
    )


def _scenario(
    scenario_id: str,
    action: str,
    ica_index: int,
    *,
    operation: str | None,
    constraints: list[str],
    variables: list[str],
) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "kind": "adversarial",
        "uca": {
            "control_action": f"action {action}",
            "context": f"context of {scenario_id}",
            "statement": f"unsafe action of {scenario_id}",
        },
        "causal_factors": [
            {
                "process_model_belief": "the actor owns the record",
                "flaw": "ownership is not checked",
                "process_model_variable": {"id": pm_id, "description": "Identity"},
            }
            for pm_id in variables
        ],
        "preconditions": [f"precondition of {scenario_id}"],
        "semantic_failure_call": (
            {"kind": "incorrect_call", "operation_name": operation}
            if operation
            else None
        ),
        "semantic_failure_criterion": f"failure of {scenario_id}",
        "safe_alternative": f"safe alternative of {scenario_id}",
        "lineage": {
            "control_action_id": action,
            "ica_id": f"RESP-1:{action}:INCORRECT:{ica_index}",
            "constraint_ids": constraints,
        },
    }


SCENARIOS = (
    _scenario(
        "SCN-001",
        "CA-1-1",
        1,
        operation="get_record",
        constraints=["SC-1"],
        variables=["PM-1-1"],
    ),
    _scenario(
        "SCN-002",
        "CA-1-1",
        1,
        operation="update_record",
        constraints=["SC-2"],
        variables=[],
    ),
    _scenario(
        "SCN-003",
        "CA-1-2",
        1,
        operation="get_record",
        constraints=["SC-2"],
        variables=["PM-1-1"],
    ),
    # A duplicate that shares everything with SCN-001; the selector skips it.
    _scenario(
        "SCN-004",
        "CA-1-1",
        1,
        operation="get_record",
        constraints=["SC-1"],
        variables=["PM-1-1"],
    ),
    _scenario(
        "SCN-005",
        "CA-1-2",
        1,
        operation="delete_record",
        constraints=["SC-3"],
        variables=[],
    ),
)
STATUS = {
    "SCN-001": "canonical",
    "SCN-002": "canonical",
    "SCN-003": "analytical_only",
    "SCN-004": "duplicate",
    "SCN-005": "canonical",
}
USE_CASE = (
    "# Records assistant\n\n"
    "## Purpose\n"
    "The assistant reads and changes records for their owners.\n\n"
    "Owners and auditors may read a record.\n"
)


def _dump(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(value, sort_keys=False), encoding="utf-8")


def _run_dir(tmp_path: Path, name: str = "run-a") -> Path:
    run_dir = tmp_path / name
    output = run_dir / "stages" / "generate" / "output"
    _dump(output / "control-structure.yaml", _structure().model_dump(mode="json"))
    _dump(
        output / "target-realization.yaml",
        {
            "effective_view": {
                "effective_ica_enumeration": _enumeration().model_dump(mode="json")
            }
        },
    )
    for scenario in SCENARIOS:
        _dump(output / "scenarios" / f"{scenario['scenario_id']}.yaml", scenario)
    _dump(
        output / "testability.yaml",
        {
            "scenarios": [
                {"scenario_id": sid, "status": status} for sid, status in STATUS.items()
            ]
        },
    )
    _dump(
        output / "loss-analysis.yaml",
        {
            "security_constraints": [
                {
                    "constraint_id": f"SC-{number}",
                    "rule": f"rule {number}",
                    "applies_when": ["a record is read"] if number == 1 else [],
                    "obligations": [
                        {
                            "obligation_id": "O1",
                            "kind": "required",
                            "behavior": f"behaviour {number}",
                            "rule_span": f"span {number}",
                        }
                    ],
                }
                for number in (1, 2, 3)
            ]
        },
    )
    use_case = run_dir / "inputs" / "target" / "use_case" / "use-case.txt"
    use_case.parent.mkdir(parents=True)
    use_case.write_text(USE_CASE, encoding="utf-8")
    return run_dir


def _pairs(script: ModuleType, run_dir: Path) -> dict[tuple[str, str], dict]:
    run = script.load_run(run_dir)
    return {
        (pair.first, pair.second): dict(pair.shared)
        for pair in script.candidate_pairs(run)
    }


# Selector -----------------------------------------------------------------


def test_the_selector_pairs_non_duplicates_by_each_shared_element(
    tmp_path: Path,
) -> None:
    script = _script()

    pairs = _pairs(script, _run_dir(tmp_path))

    assert pairs == {
        ("SCN-001", "SCN-002"): {
            "ca_context": ("CA-1-1 | PM-1-1=unverified",),
            "control_action": ("CA-1-1",),
        },
        ("SCN-001", "SCN-003"): {
            "operation": ("get_record",),
            "pm_variable": ("PM-1-1",),
        },
        ("SCN-002", "SCN-003"): {"constraint": ("SC-2",)},
        ("SCN-003", "SCN-005"): {"control_action": ("CA-1-2",)},
    }


def test_the_counts_keep_control_action_alone_out_of_the_union(
    tmp_path: Path,
) -> None:
    script = _script()
    run = script.load_run(_run_dir(tmp_path))

    counts = script.pair_counts(script.candidate_pairs(run))

    assert counts == {
        "ca_context": 1,
        "operation": 1,
        "constraint": 1,
        "pm_variable": 1,
        "control_action": 2,
        "union": 3,
    }


def test_hand_coverage_counts_candidates_whose_scenarios_share_an_element(
    tmp_path: Path,
) -> None:
    script = _script()
    run_dir = _run_dir(tmp_path)
    run = script.load_run(run_dir)
    pairs_by_run = {str(run_dir.resolve()): script.candidate_pairs(run)}
    hand = [
        {
            "case_id": "H1",
            "run_dir": str(run_dir),
            "scenario_ids": ["SCN-003", "SCN-001"],
        },
        {"case_id": "H2", "run_dir": str(run_dir), "scenario_ids": ["SCN-005"]},
        {
            "case_id": "H3",
            "run_dir": str(run_dir),
            "scenario_ids": ["SCN-001", "SCN-005"],
        },
    ]

    coverage = script.hand_coverage(hand, pairs_by_run)

    assert coverage["candidates"] == 3
    assert coverage["pairable"] == 2
    assert coverage["covered"]["operation"] == 1
    assert coverage["covered"]["pm_variable"] == 1
    assert coverage["covered"]["constraint"] == 0
    assert coverage["covered"]["union"] == 1
    assert [row["covered_by"] for row in coverage["rows"]] == [
        ["operation", "pm_variable"],
        [],
        [],
    ]


def test_the_sample_draws_union_pairs_no_hand_candidate_holds(
    tmp_path: Path,
) -> None:
    script = _script()
    run_dir = _run_dir(tmp_path)
    run = script.load_run(run_dir)
    pairs_by_run = {str(run_dir.resolve()): script.candidate_pairs(run)}
    hand = [
        {
            "case_id": "H1",
            "run_dir": str(run_dir),
            "scenario_ids": ["SCN-001", "SCN-003"],
        }
    ]

    sample = script.sample_unselected(pairs_by_run, hand, size=5, seed=7)

    assert sorted(tuple(item["scenario_ids"]) for item in sample) == [
        ("SCN-001", "SCN-002"),
        ("SCN-002", "SCN-003"),
    ]
    assert all(item["label"] is None for item in sample)
    assert sample == script.sample_unselected(pairs_by_run, hand, size=5, seed=7)


def test_select_writes_its_outputs_and_leaves_the_run_unchanged(
    tmp_path: Path,
) -> None:
    script = _script()
    run_dir = _run_dir(tmp_path)
    before = {path: path.read_bytes() for path in run_dir.rglob("*") if path.is_file()}
    manifest = tmp_path / "hand.yaml"
    _dump(
        manifest,
        {
            "cases": [
                {
                    "case_id": "H1",
                    "run_dir": str(run_dir),
                    "scenario_ids": ["SCN-001", "SCN-003"],
                }
            ]
        },
    )
    out = tmp_path / "out"

    script.main(
        [
            "select",
            "--run",
            str(run_dir),
            "--hand-manifest",
            str(manifest),
            "--sample-size",
            "2",
            "--out-dir",
            str(out),
        ]
    )

    counts = json.loads((out / "selector-counts.json").read_text())
    assert counts["runs"]["run-a"]["pairs"]["union"] == 3
    assert counts["runs"]["run-a"]["non_duplicate_scenarios"] == 4
    assert counts["hand_coverage"]["covered"]["union"] == 1
    rows = [
        json.loads(line)
        for line in (out / "candidate-pairs.jsonl").read_text().splitlines()
    ]
    assert len(rows) == 4
    sample = yaml.safe_load((out / "sample-manifest.yaml").read_text())["cases"]
    assert len(sample) == 2
    assert "| union |" in (out / "selector-summary.md").read_text()
    assert before == {
        path: path.read_bytes() for path in run_dir.rglob("*") if path.is_file()
    }


def test_runs_that_share_a_basename_keep_separate_reports(tmp_path: Path) -> None:
    script = _script()
    first = _run_dir(tmp_path / "one")
    second = _run_dir(tmp_path / "two")
    other = _run_dir(tmp_path / "two", "run-b")
    out = tmp_path / "out"

    script.main(
        ["select", "--run", str(first), "--run", str(second), "--run", str(other)]
        + ["--out-dir", str(out)]
    )

    labels = [str(first.resolve()), str(second.resolve()), "run-b"]
    counts = json.loads((out / "selector-counts.json").read_text())
    assert list(counts["runs"]) == labels
    assert [run["run_dir"] for run in counts["runs"].values()] == [
        str(path.resolve()) for path in (first, second, other)
    ]
    assert all(run["pairs"]["union"] == 3 for run in counts["runs"].values())
    groups = json.loads((out / "candidate-groups.json").read_text())
    assert list(groups) == labels
    rows = [
        json.loads(line)
        for line in (out / "candidate-pairs.jsonl").read_text().splitlines()
    ]
    assert Counter(row["run"] for row in rows) == {label: 4 for label in labels}
    summary = (out / "selector-summary.md").read_text()
    assert all(f"| {label} |" in summary for label in labels)


def test_a_run_given_twice_is_refused(tmp_path: Path) -> None:
    script = _script()
    run_dir = _run_dir(tmp_path)

    with pytest.raises(SystemExit, match="runs repeat"):
        script.main(
            ["select", "--run", str(run_dir), "--run", str(run_dir)]
            + ["--out-dir", str(tmp_path / "out")]
        )


# Fixtures and rendered requests -------------------------------------------


def test_the_fixtures_pair_each_safeguard_with_a_request_to_block_and_one_to_allow() -> (
    None
):
    script = _script()
    fixtures = script.load_fixtures()

    assert 12 <= len(fixtures) <= 16
    assert len({item["fixture_id"] for item in fixtures}) == len(fixtures)
    for fixture in fixtures:
        expected = [item["expected"] for item in fixture["requests"]]
        assert expected.count("allow") == 1
        assert expected.count("block") == 1
        assert set(expected) <= {"allow", "block", "escalate"}
        if "escalate" in expected:
            assert fixture["expected_class"] == "demonstrated_conflict"
        assert fixture["expected_class"] in script.FINDING_CLASSES
        assert set(fixture["acceptable_classes"]) <= set(script.FINDING_CLASSES)
        assert isinstance(fixture["expected_over_refusal"], bool)
    families = {item["family"] for item in fixtures}
    assert {
        "confidentiality_vs_notification",
        "stop_authority_vs_business_pressure",
        "retry_vs_duplicate_effect",
        "verification_vs_budget",
        "refinement_faithfulness",
    } <= families
    classes = {item["expected_class"] for item in fixtures}
    assert set(script.FINDING_CLASSES) == classes


def test_a_rendered_fixture_request_carries_the_case_text_and_no_label() -> None:
    script = _script()

    for fixture in script.load_fixtures():
        case = script.fixture_case(fixture)
        system, user = script.render_review_prompts(case)
        text = " ".join(user.split())
        for item in (*fixture["requirements"], *fixture["requests"]):
            assert f"[{item['id']}]" in user
            assert " ".join(item["text"].split()) in text
        assert " ".join(fixture["situation"].split()) in text
        for label in script.FINDING_CLASSES:
            assert label not in user
        for hidden in ("expected", fixture["family"], "over_refusal", "acceptable"):
            assert hidden not in user
        assert " ".join(fixture["note"].split()) not in text
        assert "Identifiers you may cite" in user
        assert system == script.render_review_prompts(script.fixture_case(fixture))[0]


def test_a_rendered_recorded_request_cites_scenarios_constraints_and_use_case(
    tmp_path: Path,
) -> None:
    script = _script()
    run = script.load_run(_run_dir(tmp_path))
    case = script.recorded_case(
        run,
        {
            "case_id": "H1",
            "scenario_ids": ["SCN-001", "SCN-003"],
            "label": "demonstrated_conflict",
            "acceptable": ["missing_information"],
            "note": "hand note that must stay out",
        },
    )

    _, user = script.render_review_prompts(case)

    assert case.identifiers == (
        "UC-1",
        "UC-2",
        "SC-1",
        "SC-1/O1",
        "SC-2",
        "SC-2/O1",
        "SCN-001",
        "SCN-003",
    )
    assert "[UC-1]\n# Records assistant\n## Purpose\nThe assistant reads" in user
    assert "[SC-2]\nrule 2\nApplies when: not stated" in user
    assert "[SC-1/O1] (required obligation)\nbehaviour 1\nRule span: span 1" in user
    assert "Process-model context: PM-1-1 (Identity of the actor) = unverified" in user
    assert "Safe alternative: safe alternative of SCN-003" in user
    assert "This case lists no requests" in user
    for hidden in ("demonstrated_conflict", "missing_information", "hand note"):
        assert hidden not in user


def test_use_case_paragraphs_join_a_heading_to_the_paragraph_after_it() -> None:
    script = _script()

    assert script.use_case_paragraphs(
        "# Title\n\n## Part\n\nBody one\n\n\nBody two"
    ) == [
        "# Title\n## Part\nBody one",
        "Body two",
    ]


# Schema and validators ----------------------------------------------------


def _fixture_case(script: ModuleType) -> Any:
    return script.fixture_case(
        {
            "fixture_id": "FX-T",
            "expected_class": "demonstrated_conflict",
            "acceptable_classes": [],
            "expected_over_refusal": False,
            "situation": "A situation.",
            "requirements": [
                {"id": "R1", "origin": "security constraint", "text": "First."},
                {"id": "R2", "origin": "business objective", "text": "Second."},
            ],
            "safeguard": {"id": "SA-1", "refines": "R1", "text": "Safeguard."},
            "requests": [
                {"id": "Q1", "expected": "block", "text": "Bad request."},
                {"id": "Q2", "expected": "allow", "text": "Good request."},
            ],
        }
    )


def _verdict(**changes: Any) -> dict[str, Any]:
    verdict: dict[str, Any] = {
        "finding_class": "demonstrated_conflict",
        "requirements": [
            {"ref": "R1", "property": "confidentiality", "requires": "keep it secret"},
            {"ref": "R2", "property": "business_objective", "requires": "send it"},
        ],
        "overlapping_context": {"kind": "resource", "description": "one channel"},
        "mechanisms": [{"ref": "SA-1", "mechanism": "strip the content"}],
        "causal_explanation": "Only one channel exists, so both cannot hold.",
        "missing_facts": [],
        "shared_dependency": None,
        "assertions": [],
        "expected_behaviour": "escalate",
        "over_refusal": {
            "blocks_legitimate_request": False,
            "request": None,
            "source_ref": None,
            "reason": "The good request is served.",
        },
        "request_decisions": [
            {"request_id": "Q1", "decision": "block", "safeguard_as_written": "block"},
            {"request_id": "Q2", "decision": "allow", "safeguard_as_written": "allow"},
        ],
    }
    verdict.update(changes)
    return verdict


def _failures(script: ModuleType, verdict: dict[str, Any]) -> list[str]:
    return script.verdict_failures(
        script.ConflictVerdict.model_validate(verdict), _fixture_case(script)
    )


def test_a_valid_verdict_breaks_no_rule() -> None:
    script = _script()

    assert _failures(script, _verdict()) == []


@pytest.mark.parametrize(
    "change",
    [
        {"finding_class": "conflict"},
        {"requirements": [{"ref": "R1", "property": "secrecy", "requires": "x"}]},
        {"surplus": 1},
        {"causal_explanation": ""},
    ],
)
def test_the_schema_rejects_a_malformed_verdict(change: dict[str, Any]) -> None:
    script = _script()

    with pytest.raises(ValidationError):
        script.ConflictVerdict.model_validate(_verdict(**change))


def test_a_cited_id_the_case_lacks_is_rejected() -> None:
    script = _script()
    verdict = _verdict()
    verdict["requirements"][1]["ref"] = "R9"
    verdict["mechanisms"][0]["ref"] = "SC-1"

    assert _failures(script, verdict) == [
        "requirements cites 'R9', which the case does not list",
        "mechanisms cites 'SC-1', which the case does not list",
    ]


def test_a_demonstrated_conflict_needs_no_missing_facts_and_a_stop() -> None:
    script = _script()

    failures = _failures(
        script,
        _verdict(missing_facts=["the deadline"], expected_behaviour="satisfy_all"),
    )

    assert len(failures) == 2
    assert failures[0].startswith("a demonstrated_conflict lists missing facts")
    assert failures[1].startswith("a demonstrated_conflict cannot satisfy")


def test_missing_information_needs_a_missing_fact() -> None:
    script = _script()

    assert _failures(
        script, _verdict(finding_class="missing_information", missing_facts=[" "])
    ) == ["a missing_information finding must list at least one missing fact"]
    assert (
        _failures(
            script,
            _verdict(finding_class="missing_information", missing_facts=["a fact"]),
        )
        == []
    )


def test_reinforcement_needs_a_shared_dependency_and_an_assertion_per_requirement() -> (
    None
):
    script = _script()

    failures = _failures(
        script,
        _verdict(
            finding_class="reinforcement",
            expected_behaviour="satisfy_all",
            assertions=[{"ref": "R1", "assertion": "no disclosure"}],
        ),
    )

    assert failures == [
        "a reinforcement finding must name its shared_dependency",
        "a reinforcement finding needs one assertion per cited requirement; "
        "none for R2",
    ]
    assert (
        _failures(
            script,
            _verdict(
                finding_class="reinforcement",
                expected_behaviour="satisfy_all",
                shared_dependency="the ownership check",
                assertions=[
                    {"ref": "R1", "assertion": "no disclosure"},
                    {"ref": "R2", "assertion": "no change"},
                ],
            ),
        )
        == []
    )


def test_an_over_refusal_flag_needs_a_named_request_and_source() -> None:
    script = _script()
    flagged = {
        "blocks_legitimate_request": True,
        "request": None,
        "source_ref": None,
        "reason": "It blocks the physician.",
    }

    assert _failures(script, _verdict(over_refusal=flagged)) == [
        "over_refusal is flagged but names no request",
        "over_refusal is flagged but cites no source_ref",
    ]
    named = {**flagged, "request": "the physician's send", "source_ref": "Q2"}
    assert _failures(script, _verdict(over_refusal=named)) == []


def test_every_listed_request_gets_exactly_one_decision() -> None:
    script = _script()
    decisions = [
        {"request_id": "Q1", "decision": "block", "safeguard_as_written": "block"},
        {"request_id": "Q3", "decision": "allow", "safeguard_as_written": "allow"},
    ]

    assert _failures(script, _verdict(request_decisions=decisions)) == [
        "request_decisions names 'Q3', which is not a listed request",
        "request_decisions has no decision for Q2",
    ]


# Runner -------------------------------------------------------------------


def _cases(script: ModuleType, count: int) -> list[Any]:
    cases = []
    for index in range(1, count + 1):
        case = _fixture_case(script)
        case.case_id = f"FX-T{index}"
        cases.append(case)
    return cases


def _reply(verdict: dict[str, Any]) -> Any:
    return _completion(json.dumps(verdict))


def _run(
    script: ModuleType,
    provider: _Provider,
    cases: list[Any],
    out: Path,
    budget: int,
    replay_dir: Path | None = None,
) -> dict[str, Any]:
    return script.run_command(
        cases,
        out_dir=out,
        max_live_requests=budget,
        client_factory=lambda session: _client(provider, session=session),
        profile="fake",
        replay_dir=replay_dir,
    )


def test_the_runner_starts_no_case_once_the_budget_is_spent(tmp_path: Path) -> None:
    script = _script()
    provider = _Provider(lambda **kw: _reply(_verdict()))

    summary = _run(script, provider, _cases(script, 3), tmp_path / "out", budget=2)

    assert len(provider.requests) == 2
    assert summary["cases_run"] == 2
    assert summary["cases_not_run"] == ["FX-T3"]
    assert summary["stop_reason"] == "live request budget spent"
    assert summary["spend"]["by_source"] == {"live": 2}
    assert [row["class_correct"] for row in summary["rows"]] == [True, True]
    record = json.loads((tmp_path / "out" / "verdicts" / "FX-T1.json").read_text())
    assert record["accepted"] is True
    assert record["verdict"]["finding_class"] == "demonstrated_conflict"
    assert (tmp_path / "out" / "summary.md").is_file()


def test_a_rejected_reply_earns_one_correction_with_the_failures(
    tmp_path: Path,
) -> None:
    script = _script()
    replies = iter(
        [
            _reply(_verdict(finding_class="missing_information")),
            _reply(_verdict()),
        ]
    )
    provider = _Provider(lambda **kw: next(replies))

    summary = _run(script, provider, _cases(script, 1), tmp_path / "out", budget=5)

    assert len(provider.requests) == 2
    correction = provider.requests[1]["messages"][-1]["content"]
    assert "Code rejected the prior reply." in correction
    assert "must list at least one missing fact" in correction
    assert summary["accepted"] == 1
    assert summary["rows"][0]["corrections"] == 1
    assert summary["spend"]["corrections"] == 1
    assert summary["spend"]["by_source"] == {"live": 2}


def test_a_correction_beyond_the_budget_is_refused_and_stops_the_run(
    tmp_path: Path,
) -> None:
    script = _script()
    provider = _Provider(
        lambda **kw: _reply(_verdict(finding_class="missing_information"))
    )

    summary = _run(script, provider, _cases(script, 2), tmp_path / "out", budget=1)

    assert len(provider.requests) == 1
    assert summary["cases_run"] == 1
    assert summary["accepted"] == 0
    assert summary["stop_reason"] == "a request was refused by the live request budget"
    assert summary["budget_error"] is not None
    assert summary["spend"]["by_source"] == {"live": 1, "refused": 1}


def test_a_rerun_replays_the_recording_without_a_live_request(tmp_path: Path) -> None:
    script = _script()
    first = _Provider(lambda **kw: _reply(_verdict()))
    _run(script, first, _cases(script, 2), tmp_path / "first", budget=2)
    second = _Provider(lambda **kw: pytest.fail("a replayed run went live"))

    summary = _run(
        script,
        second,
        _cases(script, 2),
        tmp_path / "second",
        budget=0,
        replay_dir=tmp_path / "first",
    )

    assert second.requests == []
    assert summary["accepted"] == 2
    assert summary["spend"]["by_source"] == {"replay": 2}
    assert [r["source"] for r in _records(tmp_path / "second")] == ["replay", "replay"]


def test_the_runner_stops_after_consecutive_cases_without_a_verdict(
    tmp_path: Path,
) -> None:
    script = _script()
    provider = _Provider(lambda **kw: _completion("not json"))
    cases = _cases(script, 5)

    summary = script.run_command(
        cases,
        out_dir=tmp_path / "out",
        max_live_requests=10,
        client_factory=lambda session: _client(provider, session=session),
        profile="fake",
        stop_after_failures=2,
    )

    assert summary["cases_run"] == 2
    assert summary["stop_reason"] == "2 consecutive cases had no accepted verdict"
    assert len(provider.requests) == 2


def test_a_fixture_score_checks_class_and_each_request(tmp_path: Path) -> None:
    script = _script()
    case = _fixture_case(script)
    verdict = copy.deepcopy(_verdict())
    verdict["request_decisions"][1]["decision"] = "escalate"
    result = script.CaseResult(case_id=case.case_id, source="fixture", verdict=verdict)

    row = script.score_case(case, result)

    assert row["class_correct"] is True
    assert row["requests_judged"]["Q1"]["correct"] is True
    assert row["requests_judged"]["Q2"]["correct"] is False


@pytest.mark.parametrize(
    ("decision", "correct"), [("escalate", True), ("block", True), ("allow", False)]
)
def test_a_request_to_escalate_is_met_by_stopping_it(
    decision: str, correct: bool
) -> None:
    script = _script()
    case = _fixture_case(script)
    case.labels["expected_requests"]["Q1"] = "escalate"
    verdict = copy.deepcopy(_verdict())
    verdict["request_decisions"][0]["decision"] = decision
    result = script.CaseResult(case_id=case.case_id, source="fixture", verdict=verdict)

    row = script.score_case(case, result)

    assert row["requests_judged"]["Q1"]["correct"] is correct


def test_fx_01_keeps_its_conflict_and_pairs_a_truly_permissible_request() -> None:
    script = _script()
    (fixture,) = [f for f in script.load_fixtures() if f["fixture_id"] == "FX-01"]
    requests = {item["expected"]: item["text"] for item in fixture["requests"]}

    assert fixture["expected_class"] == "demonstrated_conflict"
    assert "critical-result message" in requests["escalate"]
    assert "potassium" not in requests["allow"]
    assert "employer" in requests["block"]
