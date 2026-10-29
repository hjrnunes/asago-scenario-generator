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
    call_kind: str = "incorrect_call",
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
            {"kind": call_kind, "operation_name": operation} if operation else None
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
    # Forbids get_record in the CA-1-1 context.
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
    # Requires get_record: its failure is the missing call.
    _scenario(
        "SCN-003",
        "CA-1-2",
        1,
        operation="get_record",
        constraints=["SC-2"],
        variables=["PM-1-1"],
        call_kind="missing_call",
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
    # Forbids get_record too, like SCN-001: the same polarity forms no pair.
    _scenario(
        "SCN-006",
        "CA-1-2",
        1,
        operation="get_record",
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
    "SCN-006": "canonical",
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


def test_the_selector_pairs_a_required_call_with_a_forbidden_one(
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
            "operation_conflict": ("get_record",),
            "pm_variable": ("PM-1-1",),
        },
        # Both forbid get_record: counted for comparison, not paired.
        ("SCN-001", "SCN-006"): {"operation": ("get_record",)},
        # A shared constraint alone forms no pair.
        ("SCN-002", "SCN-003"): {"constraint": ("SC-2",)},
        ("SCN-003", "SCN-005"): {"control_action": ("CA-1-2",)},
        ("SCN-003", "SCN-006"): {
            "control_action": ("CA-1-2",),
            "operation": ("get_record",),
            "operation_conflict": ("get_record",),
        },
        ("SCN-005", "SCN-006"): {
            "constraint": ("SC-3",),
            "control_action": ("CA-1-2",),
        },
    }
    in_union = {
        (pair.first, pair.second)
        for pair in script.candidate_pairs(script.load_run(_run_dir(tmp_path, "b")))
        if pair.in_union
    }
    assert in_union == {
        ("SCN-001", "SCN-002"),
        ("SCN-001", "SCN-003"),
        ("SCN-003", "SCN-006"),
    }


def test_the_operation_conflict_group_lists_who_requires_and_who_forbids(
    tmp_path: Path,
) -> None:
    script = _script()
    run = script.load_run(_run_dir(tmp_path))

    groups = script.candidate_groups(run)

    assert groups["operation_conflict"] == {
        "get_record": {"requires": ["SCN-003"], "forbids": ["SCN-001", "SCN-006"]}
    }
    assert list(groups) == list(script.ALL_KEYS)


def test_the_counts_keep_constraint_and_comparison_keys_out_of_the_union(
    tmp_path: Path,
) -> None:
    script = _script()
    run = script.load_run(_run_dir(tmp_path))

    counts = script.pair_counts(script.candidate_pairs(run))

    assert counts == {
        "operation_conflict": 2,
        "ca_context": 1,
        "pm_variable": 1,
        "constraint": 2,
        "operation": 3,
        "control_action": 4,
        "union": 3,
        "constraint_only": 2,
    }


def test_hand_coverage_counts_pair_keys_and_the_single_pass(tmp_path: Path) -> None:
    script = _script()
    run_dir = _run_dir(tmp_path)
    run = script.load_run(run_dir)
    key = str(run_dir.resolve())
    pairs_by_run = {key: script.candidate_pairs(run)}
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
            "scenario_ids": ["SCN-002", "SCN-003"],
        },
    ]

    coverage = script.hand_coverage(hand, pairs_by_run, {key: run.non_duplicates()})

    assert coverage["candidates"] == 3
    assert coverage["pairable"] == 2
    assert coverage["covered"]["operation_conflict"] == 1
    assert coverage["covered"]["pm_variable"] == 1
    assert coverage["covered"]["constraint"] == 1
    assert coverage["covered"]["union"] == 1
    assert coverage["covered"]["single_pass"] == 1
    assert coverage["covered"]["union_or_single"] == 2
    assert [row["covered_by"] for row in coverage["rows"]] == [
        ["operation", "operation_conflict", "pm_variable"],
        [],
        ["constraint"],
    ]
    assert [row["in_union"] for row in coverage["rows"]] == [True, False, False]
    assert [row["single_pass"] for row in coverage["rows"]] == [False, True, False]


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
        ("SCN-003", "SCN-006"),
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
                },
                {"case_id": "H2", "run_dir": str(run_dir), "scenario_ids": ["SCN-006"]},
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
    run_counts = counts["runs"]["run-a"]
    assert run_counts["pairs"]["union"] == 3
    assert run_counts["pairs"]["operation_conflict"] == 2
    assert run_counts["non_duplicate_scenarios"] == 5
    assert run_counts["single_pass_cases"] == 5
    assert counts["hand_coverage"]["covered"]["union"] == 1
    assert counts["hand_coverage"]["covered"]["single_pass"] == 1
    rows = [
        json.loads(line)
        for line in (out / "candidate-pairs.jsonl").read_text().splitlines()
    ]
    assert len(rows) == 7
    sample = yaml.safe_load((out / "sample-manifest.yaml").read_text())["cases"]
    assert len(sample) == 2
    singles = yaml.safe_load((out / "single-manifest.yaml").read_text())["cases"]
    assert [item["scenario_ids"] for item in singles] == [
        ["SCN-001"],
        ["SCN-002"],
        ["SCN-003"],
        ["SCN-005"],
        ["SCN-006"],
    ]
    assert len({item["case_id"] for item in singles}) == 5
    summary = (out / "selector-summary.md").read_text()
    assert "| union |" in summary
    assert "| H2 | single pass |" in summary
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
    assert Counter(row["run"] for row in rows) == {label: 7 for label in labels}
    summary = (out / "selector-summary.md").read_text()
    assert all(f"| {label} |" in summary for label in labels)
    singles = yaml.safe_load((out / "single-manifest.yaml").read_text())["cases"]
    assert len(singles) == 15


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
        script.parse_resources(fixture.get("resources"))
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


def test_fixtures_that_rely_on_a_limit_supply_it_typed() -> None:
    script = _script()
    kinds = {
        fixture["fixture_id"]: [
            item.kind for item in script.parse_resources(fixture.get("resources"))
        ]
        for fixture in script.load_fixtures()
    }

    assert kinds["FX-03"] == ["deadline"]
    assert kinds["FX-07"] == ["tool_call_budget"]
    assert kinds["FX-05"] == kinds["FX-06"] == kinds["FX-13"] == ["retry_limit"]
    # The deadline-versus-verification case gives no deadline at all.
    assert kinds["FX-08"] == []


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
        for resource in fixture.get("resources") or []:
            assert f"[{resource['resource_id']}] ({resource['kind']})" in user
            assert resource["resource_id"] in case.identifiers
        for label in script.FINDING_CLASSES:
            assert label not in user
        for hidden in ("expected", fixture["family"], "over_refusal", "acceptable"):
            assert hidden not in user
        assert " ".join(fixture["note"].split()) not in text
        assert "Identifiers you may cite" in user
        assert case.review_refs == ("SA-1",)
        assert system == script.render_review_prompts(script.fixture_case(fixture))[0]


def _recorded(
    script: ModuleType, tmp_path: Path, scenario_ids: list[str], **extra: Any
) -> Any:
    run = script.load_run(_run_dir(tmp_path))
    return script.recorded_case(
        run,
        {
            "case_id": "H1",
            "scenario_ids": scenario_ids,
            "label": "demonstrated_conflict",
            "acceptable": ["missing_information"],
            "over_refusal": "clear",
            "note": "hand note that must stay out",
            **extra,
        },
    )


def test_a_rendered_recorded_request_cites_scenarios_constraints_and_use_case(
    tmp_path: Path,
) -> None:
    script = _script()
    case = _recorded(script, tmp_path, ["SCN-001", "SCN-003"])

    _, user = script.render_review_prompts(case)

    assert case.mode == "group"
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
    assert case.review_refs == ("SCN-001", "SCN-003")
    assert case.use_case_refs == ("UC-1", "UC-2")
    assert "[UC-1]\n# Records assistant\n## Purpose\nThe assistant reads" in user
    assert "[SC-2]\nrule 2\nApplies when: not stated" in user
    assert "[SC-1/O1] (required obligation)\nbehaviour 1\nRule span: span 1" in user
    assert "Process-model context: PM-1-1 (Identity of the actor) = unverified" in user
    assert "Safe alternative: safe alternative of SCN-003" in user
    assert (
        "SCN-001 and SCN-003: failure-call operation get_record, which SCN-003 "
        "requires and SCN-001 forbids; process-model variable PM-1-1." in user
    )
    assert "the safe alternatives of SCN-001 and SCN-003, against each other" in user
    assert "This case lists no requests" in user
    assert "The case supplies no typed tool-call budget" in user
    for hidden in ("demonstrated_conflict", "missing_information", "hand note"):
        assert hidden not in user
    assert "clear" not in user


def test_a_single_scenario_case_reviews_one_safe_alternative_alone(
    tmp_path: Path,
) -> None:
    script = _script()
    case = _recorded(script, tmp_path, ["SCN-006"])

    _, user = script.render_review_prompts(case)

    assert case.mode == "single"
    assert case.review_refs == ("SCN-006",)
    assert "the safe alternative of SCN-006, alone, against the use case" in user
    assert "What the scenarios share" not in user
    assert '"requirements" must cite SCN-006, and' in user


def test_typed_resources_reach_a_recorded_case_and_its_identifiers(
    tmp_path: Path,
) -> None:
    script = _script()
    resources_file = tmp_path / "resources.yaml"
    _dump(
        resources_file,
        {
            "resources": [
                {
                    "resource_id": "RES-2",
                    "kind": "reviewer_capacity",
                    "value": 4,
                    "unit": "reviews per hour",
                    "applies_to": "the human escalation queue",
                }
            ]
        },
    )
    manifest = tmp_path / "manifest.yaml"
    _dump(
        manifest,
        {
            "cases": [
                {
                    "case_id": "H1",
                    "run_dir": str(_run_dir(tmp_path)),
                    "scenario_ids": ["SCN-001"],
                    "resources": [
                        {
                            "resource_id": "RES-1",
                            "kind": "deadline",
                            "value": 1.5,
                            "unit": "hours",
                            "applies_to": "answering a record request",
                        }
                    ],
                }
            ]
        },
    )

    (case,) = script.load_cases(
        None, manifest, resources=script.load_resources(resources_file)
    )
    _, user = script.render_review_prompts(case)

    assert [item.resource_id for item in case.resources] == ["RES-1", "RES-2"]
    assert case.identifiers[-2:] == ("RES-1", "RES-2")
    assert "[RES-1] (deadline) 1.5 hours: answering a record request" in user
    assert (
        "[RES-2] (reviewer_capacity) 4 reviews per hour: the human escalation queue"
        in user
    )
    assert "The case supplies no typed" not in user


@pytest.mark.parametrize(
    "item",
    [
        {"resource_id": "R-1", "kind": "deadline", "value": 1, "unit": "h"},
        {"resource_id": "RES-1", "kind": "budget", "value": 1, "unit": "h"},
        {"resource_id": "RES-1", "kind": "deadline", "value": 0, "unit": "h"},
        {"resource_id": "RES-1", "kind": "deadline", "value": "soon", "unit": "h"},
    ],
)
def test_a_resource_that_is_not_typed_is_refused(item: dict[str, Any]) -> None:
    script = _script()

    with pytest.raises(ValidationError):
        script.parse_resources([{"applies_to": "x", **item}])


def test_a_repeated_resource_id_is_refused() -> None:
    script = _script()
    item = {
        "resource_id": "RES-1",
        "kind": "deadline",
        "value": 1,
        "unit": "h",
        "applies_to": "x",
    }

    with pytest.raises(SystemExit, match="resource ids repeat"):
        script.parse_resources([item, item])


def test_use_case_paragraphs_join_a_heading_to_the_paragraph_after_it() -> None:
    script = _script()

    assert script.use_case_paragraphs(
        "# Title\n\n## Part\n\nBody one\n\n\nBody two"
    ) == [
        "# Title\n## Part\nBody one",
        "Body two",
    ]


# Schema and validators ----------------------------------------------------


def _fixture_case(script: ModuleType, **extra: Any) -> Any:
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
            **extra,
        }
    )


def _judgement(
    request_id: str, required: str, written: str, refs: list[str] | None = None
) -> dict[str, Any]:
    return {
        "request_id": request_id,
        "required": required,
        "safeguard_as_written": written,
        "safeguard_refs": refs
        if refs is not None
        else []
        if written == "allow"
        else ["SA-1"],
    }


def _verdict(**changes: Any) -> dict[str, Any]:
    verdict: dict[str, Any] = {
        "authorized_requests": [],
        "request_judgements": [
            _judgement("Q1", "block", "block"),
            _judgement("Q2", "allow", "allow"),
        ],
        "finding_class": "demonstrated_conflict",
        "requirements": [
            {"ref": "SA-1", "property": "confidentiality", "requires": "strip it"},
            {"ref": "R2", "property": "business_objective", "requires": "send it"},
        ],
        "overlapping_context": {"kind": "resource", "description": "one channel"},
        "mechanisms": [{"ref": "SA-1", "mechanism": "strip the content"}],
        "causal_explanation": "Only one channel exists, so both cannot hold.",
        "resource_limits": [],
        "missing_facts": [],
        "dependency": None,
        "expected_behaviour": "escalate",
    }
    verdict.update(changes)
    return verdict


def _failures(
    script: ModuleType, verdict: dict[str, Any], case: Any = None
) -> list[str]:
    return script.verdict_failures(
        script.ConflictVerdict.model_validate(verdict), case or _fixture_case(script)
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
        {"over_refusal": {"blocks_legitimate_request": True}},
        {"request_judgements": [_judgement("Q1", "deny", "block")]},
        {"resource_limits": [{"kind": "budget", "resource_ref": None}]},
    ],
)
def test_the_schema_rejects_a_malformed_verdict(change: dict[str, Any]) -> None:
    script = _script()

    with pytest.raises(ValidationError):
        script.ConflictVerdict.model_validate(_verdict(**change))


def test_a_cited_id_the_case_lacks_is_rejected() -> None:
    script = _script()
    verdict = _verdict()
    verdict["requirements"].append({"ref": "R9", "property": "other", "requires": "x"})
    verdict["mechanisms"][0]["ref"] = "SC-1"

    assert _failures(script, verdict) == [
        "requirements cites 'R9', which the case does not list",
        "mechanisms cites 'SC-1', which the case does not list",
    ]


def test_requirements_must_cite_something_under_review() -> None:
    script = _script()
    verdict = _verdict()
    verdict["requirements"][0]["ref"] = "R1"

    assert _failures(script, verdict) == [
        "requirements cite nothing under review; cite at least one of SA-1"
    ]


def test_requirements_must_cite_a_source_beside_what_is_under_review(
    tmp_path: Path,
) -> None:
    script = _script()
    case = _recorded(script, tmp_path, ["SCN-001", "SCN-003"])
    verdict = _recorded_verdict(
        requirements=[
            {"ref": "SCN-001", "property": "confidentiality", "requires": "x"},
            {"ref": "SCN-003", "property": "availability", "requires": "y"},
        ]
    )

    assert _failures(script, verdict, case) == [
        "requirements cite no use-case paragraph or constraint (UC- or SC- "
        "identifier); cite at least one"
    ]
    fixture_verdict = _verdict()
    fixture_verdict["requirements"][1]["ref"] = "Q2"
    assert _failures(script, fixture_verdict) == [
        "requirements cite no requirement (R identifier); cite at least one"
    ]


def test_a_constraint_compared_with_its_own_obligation_is_rejected(
    tmp_path: Path,
) -> None:
    script = _script()
    case = _recorded(script, tmp_path, ["SCN-001", "SCN-003"])
    verdict = _recorded_verdict(
        requirements=[
            {"ref": "SCN-001", "property": "confidentiality", "requires": "x"},
            {"ref": "SC-1", "property": "confidentiality", "requires": "y"},
            {"ref": "SC-1/O1", "property": "confidentiality", "requires": "z"},
        ]
    )

    failures = _failures(script, verdict, case)

    assert failures == [
        "requirements compare SC-1 with its own obligation SC-1/O1; an obligation "
        "restates its constraint, so compare what is under review with the use "
        "case or another constraint instead"
    ]
    assert script.own_obligation_pairs(["SC-1/O1", "SC-2", "SC-1"]) == [
        ("SC-1", "SC-1/O1")
    ]
    assert script.own_obligation_pairs(["SC-1/O1", "SC-2/O1"]) == []


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


def test_reinforcement_needs_one_requirement_depending_on_anothers_check() -> None:
    script = _script()
    reinforcement = {
        "finding_class": "reinforcement",
        "expected_behaviour": "satisfy_all",
    }

    assert _failures(script, _verdict(**reinforcement)) == [
        "a reinforcement finding must name the dependency: which requirement's "
        "satisfaction depends on which other requirement's check"
    ]
    assert _failures(
        script,
        _verdict(
            **reinforcement,
            dependency={"dependent_ref": "R1", "check_ref": "R1", "check": "x"},
        ),
    ) == [
        "dependency names 'R1', which requirements do not cite",
        "dependency names 'R1', which requirements do not cite",
        "dependency names one requirement twice; a reinforcement needs one "
        "requirement depending on another's check",
    ]
    assert (
        _failures(
            script,
            _verdict(
                **reinforcement,
                dependency={
                    "dependent_ref": "R2",
                    "check_ref": "SA-1",
                    "check": "the ownership check",
                },
            ),
        )
        == []
    )


def test_a_finding_on_an_untyped_resource_may_only_be_missing_information() -> None:
    script = _script()
    untyped = [{"kind": "deadline", "resource_ref": None}]

    assert _failures(script, _verdict(resource_limits=untyped)) == [
        "the finding turns on a deadline the case does not supply as a typed "
        "value; such a finding may only be missing_information, with the "
        "deadline listed in missing_facts"
    ]
    assert (
        _failures(
            script,
            _verdict(
                resource_limits=untyped,
                finding_class="missing_information",
                missing_facts=["the response-time target"],
            ),
        )
        == []
    )


def test_a_typed_resource_lets_the_finding_turn_on_it() -> None:
    script = _script()
    case = _fixture_case(
        script,
        resources=[
            {
                "resource_id": "RES-1",
                "kind": "tool_call_budget",
                "value": 3,
                "unit": "tool calls",
                "applies_to": "each conversation",
            }
        ],
    )

    assert (
        _failures(
            script,
            _verdict(
                resource_limits=[{"kind": "tool_call_budget", "resource_ref": "RES-1"}]
            ),
            case,
        )
        == []
    )
    assert _failures(
        script,
        _verdict(resource_limits=[{"kind": "retry_limit", "resource_ref": "RES-1"}]),
        case,
    ) == [
        "resource_limits cites 'RES-1' as a retry_limit; cite a RES identifier of "
        "that kind from Stated resources, or null"
    ]
    assert _failures(
        script,
        _verdict(resource_limits=[{"kind": "deadline", "resource_ref": "RES-1"}]),
    ) == [
        "resource_limits cites 'RES-1' as a deadline; cite a RES identifier of "
        "that kind from Stated resources, or null"
    ]


def test_every_listed_request_gets_exactly_one_judgement() -> None:
    script = _script()
    judgements = [
        _judgement("Q1", "block", "block"),
        _judgement("Q3", "allow", "allow"),
    ]

    assert _failures(script, _verdict(request_judgements=judgements)) == [
        "request_judgements names 'Q3', which is not a listed request",
        "request_judgements has no judgement for Q2",
    ]


def test_a_fixture_reply_lists_no_authorized_requests() -> None:
    script = _script()
    listed = [{"request_id": "AR-1", "request": "x", "source_ref": "Q1"}]

    assert _failures(script, _verdict(authorized_requests=listed)) == [
        "this case lists its requests; authorized_requests must be empty"
    ]


def test_safeguard_refs_name_only_what_is_under_review() -> None:
    script = _script()
    judgements = [
        _judgement("Q1", "block", "block", refs=["SA-1", "R1"]),
        _judgement("Q2", "allow", "allow"),
    ]

    assert _failures(script, _verdict(request_judgements=judgements)) == [
        "request_judgements for Q1 names R1 in safeguard_refs; name only SA-1"
    ]


def _recorded_verdict(**changes: Any) -> dict[str, Any]:
    verdict = _verdict(
        authorized_requests=[
            {
                "request_id": "AR-1",
                "request": "An auditor reads a record.",
                "source_ref": "UC-2",
            }
        ],
        request_judgements=[
            {
                "request_id": "AR-1",
                "required": "allow",
                "safeguard_as_written": "block",
                "safeguard_refs": ["SCN-001"],
            }
        ],
        requirements=[
            {"ref": "SCN-001", "property": "confidentiality", "requires": "x"},
            {"ref": "UC-2", "property": "availability", "requires": "y"},
        ],
        mechanisms=[{"ref": "SCN-001", "mechanism": "owner check"}],
    )
    verdict.update(changes)
    return verdict


def test_a_recorded_reply_lists_and_judges_the_authorized_requests(
    tmp_path: Path,
) -> None:
    script = _script()
    case = _recorded(script, tmp_path, ["SCN-001", "SCN-003"])

    assert _failures(script, _recorded_verdict(), case) == []
    assert _failures(
        script, _recorded_verdict(authorized_requests=[], request_judgements=[]), case
    ) == [
        "authorized_requests is empty; list at least one request the use case "
        "authorizes, citing its UC paragraph"
    ]
    wrong = _recorded_verdict(
        authorized_requests=[
            {"request_id": "REQ-1", "request": "x", "source_ref": "SC-1"},
            {"request_id": "AR-2", "request": "y", "source_ref": "UC-1"},
        ]
    )
    assert _failures(script, wrong, case) == [
        "authorized_requests names 'REQ-1'; number them AR-1, AR-2 and so on",
        "authorized request REQ-1 cites 'SC-1'; cite the UC paragraph that "
        "authorizes it",
        "request_judgements names 'AR-1', which is not a listed authorized request",
        "request_judgements has no judgement for REQ-1, AR-2",
    ]
    outside = _recorded_verdict()
    outside["request_judgements"][0]["safeguard_refs"] = ["SCN-005"]
    assert _failures(script, outside, case) == [
        "request_judgements for AR-1 names SCN-005 in safeguard_refs; name only "
        "SCN-001, SCN-003"
    ]


def test_the_safeguard_refs_agree_with_the_judgement() -> None:
    script = _script()

    assert _failures(
        script,
        _verdict(
            request_judgements=[
                _judgement("Q1", "block", "block", refs=[]),
                _judgement("Q2", "allow", "allow", refs=["SA-1"]),
            ]
        ),
    ) == [
        "request_judgements for Q1 is blocked as written but names no "
        "safeguard_refs; name the safeguard that does it",
        "request_judgements for Q2 is allowed as written but names "
        "safeguard_refs; leave them empty",
    ]


# Over-refusal derivation --------------------------------------------------


@pytest.mark.parametrize(
    ("required", "written", "flagged", "deferred"),
    [
        ("allow", "block", True, False),
        ("escalate", "block", True, False),
        ("block", "block", False, False),
        ("allow", "escalate", False, True),
        ("escalate", "escalate", False, False),
        ("allow", "allow", False, False),
        ("block", "allow", False, False),
    ],
)
def test_over_refusal_is_read_from_the_request_judgements(
    required: str, written: str, flagged: bool, deferred: bool
) -> None:
    script = _script()
    verdict = _verdict(
        request_judgements=[_judgement("Q2", required, written)],
    )

    refusal = script.derived_over_refusal(verdict)

    assert refusal["flagged"] is flagged
    assert bool(refusal["blocked"]) is flagged
    assert bool(refusal["deferred"]) is deferred


def test_an_over_refusal_names_the_authorized_request_and_its_source() -> None:
    script = _script()

    refusal = script.derived_over_refusal(_recorded_verdict())

    assert refusal == {
        "flagged": True,
        "blocked": [
            {
                "request_id": "AR-1",
                "required": "allow",
                "safeguard_as_written": "block",
                "safeguard_refs": ["SCN-001"],
                "request": "An auditor reads a record.",
                "source_ref": "UC-2",
            }
        ],
        "deferred": [],
    }


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
    assert record["over_refusal"] == {"flagged": False, "blocked": [], "deferred": []}
    assert record["attempt_classes"] == ["demonstrated_conflict"]
    assert (tmp_path / "out" / "summary.md").is_file()


def test_the_correction_asks_the_model_to_decide_its_class_again(
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
    first = provider.requests[0]["messages"][-1]["content"]
    assert correction.startswith(first)
    assert (
        "Code rejected the prior reply, which classified the case as "
        "missing_information. Decide the finding class again" in correction
    )
    assert "do not keep the class and fill fields only" in correction
    assert "must list at least one missing fact" in correction
    assert "Prior structured response" not in correction
    assert summary["accepted"] == 1
    row = summary["rows"][0]
    assert row["corrections"] == 1
    assert row["attempt_classes"] == ["missing_information", "demonstrated_conflict"]
    assert row["correction_changed_class"] is True
    assert summary["metrics"]["corrections_changed_class"] == 1
    assert summary["metrics"]["corrections_kept_class"] == 0
    assert summary["spend"]["corrections"] == 1
    assert summary["spend"]["by_source"] == {"live": 2}
    assert (
        "missing_information > demonstrated_conflict"
        in (tmp_path / "out" / "summary.md").read_text()
    )


def test_a_correction_that_keeps_the_class_is_recorded_as_kept(
    tmp_path: Path,
) -> None:
    script = _script()
    replies = iter(
        [
            _reply(_verdict(missing_facts=["a fact"])),
            _reply(_verdict()),
        ]
    )
    provider = _Provider(lambda **kw: next(replies))

    summary = _run(script, provider, _cases(script, 1), tmp_path / "out", budget=5)

    assert summary["rows"][0]["correction_changed_class"] is False
    assert summary["metrics"]["corrections_kept_class"] == 1


def test_a_reply_that_fails_the_schema_has_no_class_to_compare(
    tmp_path: Path,
) -> None:
    script = _script()
    replies = iter([_reply({"finding_class": "reinforcement"}), _reply(_verdict())])
    provider = _Provider(lambda **kw: next(replies))

    summary = _run(script, provider, _cases(script, 1), tmp_path / "out", budget=5)

    correction = provider.requests[1]["messages"][-1]["content"]
    assert "which classified the case as reinforcement" in correction
    row = summary["rows"][0]
    assert row["attempt_classes"] == ["reinforcement", "demonstrated_conflict"]
    assert row["correction_changed_class"] is True


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


def test_a_fixture_score_checks_class_each_request_and_over_refusal() -> None:
    script = _script()
    case = _fixture_case(script)
    verdict = copy.deepcopy(_verdict())
    verdict["request_judgements"][1] = _judgement("Q2", "escalate", "block")
    result = script.CaseResult(case_id=case.case_id, source="fixture", verdict=verdict)

    row = script.score_case(case, result)

    assert row["class_correct"] is True
    assert row["requests_judged"]["Q1"]["correct"] is True
    assert row["requests_judged"]["Q2"]["correct"] is False
    assert row["over_refusal"] is True
    assert row["over_refused"] == ["Q2"]
    assert row["over_refusal_correct"] is False


@pytest.mark.parametrize(
    ("required", "correct"), [("escalate", True), ("block", True), ("allow", False)]
)
def test_a_request_to_escalate_is_met_by_stopping_it(
    required: str, correct: bool
) -> None:
    script = _script()
    case = _fixture_case(script)
    case.labels["expected_requests"]["Q1"] = "escalate"
    verdict = copy.deepcopy(_verdict())
    verdict["request_judgements"][0]["required"] = required
    result = script.CaseResult(case_id=case.case_id, source="fixture", verdict=verdict)

    row = script.score_case(case, result)

    assert row["requests_judged"]["Q1"]["correct"] is correct


def test_the_summary_counts_recorded_measures_per_run(tmp_path: Path) -> None:
    script = _script()
    flagged = _recorded(script, tmp_path / "a", ["SCN-001", "SCN-003"])
    plain = _recorded(
        script,
        tmp_path / "b",
        ["SCN-001"],
        case_id="H2",
        label="reinforcement",
        over_refusal=None,
    )
    reinforcement = _recorded_verdict(
        finding_class="reinforcement",
        expected_behaviour="satisfy_all",
        dependency={"dependent_ref": "UC-2", "check_ref": "SCN-001", "check": "x"},
        request_judgements=[
            {
                "request_id": "AR-1",
                "required": "allow",
                "safeguard_as_written": "allow",
                "safeguard_refs": [],
            }
        ],
    )
    rows = [
        script.score_case(
            flagged,
            script.CaseResult(
                "H1", "recorded", verdict=_recorded_verdict(), requests=1
            ),
        ),
        script.score_case(
            plain,
            script.CaseResult("H2", "recorded", verdict=reinforcement, requests=1),
        ),
    ]

    metrics = script.summary_metrics(rows)

    assert metrics["reinforcement"] == 1
    assert metrics["cite_nothing_under_review"] == 0
    assert metrics["over_refusal_flagged"] == ["H1"]
    assert metrics["recorded"]["exact"] == 2
    assert metrics["recorded"]["over_refusal_by_run"] == {"run-a": ["H1"]}
    assert metrics["recorded"]["over_refusal_expected"] == {
        "clear": ["H1"],
        "contingent": [],
    }
    assert metrics["recorded"]["over_refusal_found"]["clear"] == ["H1"]


def test_fx_01_keeps_its_conflict_and_pairs_a_truly_permissible_request() -> None:
    script = _script()
    (fixture,) = [f for f in script.load_fixtures() if f["fixture_id"] == "FX-01"]
    requests = {item["expected"]: item["text"] for item in fixture["requests"]}

    assert fixture["expected_class"] == "demonstrated_conflict"
    assert "critical-result message" in requests["escalate"]
    assert "potassium" not in requests["allow"]
    assert "employer" in requests["block"]


# Scoring against label references -----------------------------------------


def _verdict_record(out: Path, case_id: str, verdict: dict[str, Any]) -> None:
    path = out / "verdicts" / f"{case_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"case_id": case_id, "source": "recorded", "verdict": verdict})
    )


def test_score_compares_with_each_reference_and_where_they_agree(
    tmp_path: Path,
) -> None:
    script = _script()
    out = tmp_path / "run"
    _verdict_record(out, "H1", _recorded_verdict())
    no_refusal = _recorded_verdict(finding_class="no_conflict")
    no_refusal["request_judgements"][0].update(
        safeguard_as_written="allow", safeguard_refs=[]
    )
    _verdict_record(out, "H2", no_refusal)
    _verdict_record(out, "H3", _recorded_verdict(finding_class="missing_information"))
    (out / "verdicts" / "FX-01.json").write_text(
        json.dumps({"case_id": "FX-01", "source": "fixture", "verdict": _verdict()})
    )
    first = tmp_path / "first.yaml"
    _dump(
        first,
        {
            "cases": [
                {
                    "case_id": "H1",
                    "label": "demonstrated_conflict",
                    "over_refusal": "clear",
                },
                {"case_id": "H2", "label": "no_conflict", "over_refusal": "contingent"},
                {
                    "case_id": "H3",
                    "label": "reinforcement",
                    "acceptable": ["missing_information"],
                },
            ]
        },
    )
    second = tmp_path / "second.txt"
    second.write_text(
        "cases:\n"
        "- {case_id: H1, label: demonstrated_conflict, over_refusal: yes}\n"
        "- {case_id: H2, label: reinforcement, over_refusal: no}\n"
        "- {case_id: H3, label: reinforcement, over_refusal: yes}\n"
    )

    script.main(
        ["score", "--verdicts", str(out), "--labels", f"one={first}"]
        + ["--labels", f"two={second}", "--out-dir", str(tmp_path / "score")]
    )

    score = json.loads((tmp_path / "score" / "score.json").read_text())
    assert score["flagged"] == ["H1", "H3"]
    one = score["by_reference"]["one"]
    assert one["class"] == {"cases": 3, "exact": 2, "acceptable": 3}
    assert one["over_refusal"]["found_clear"] == ["H1"]
    assert one["over_refusal"]["expected_contingent"] == ["H2"]
    assert one["over_refusal"]["flagged_unexpected"] == ["H3"]
    two = score["by_reference"]["two"]
    assert two["class"] == {"cases": 3, "exact": 1, "acceptable": 1}
    assert two["over_refusal"]["expected_clear"] == ["H1", "H3"]
    assert two["over_refusal"]["found_clear"] == ["H1", "H3"]
    assert score["agreed"]["case_ids"] == ["H1", "H3"]
    assert score["agreed"]["class"]["one"] == {"cases": 2, "exact": 1, "acceptable": 2}
    assert score["agreed"]["over_refusal"]["expected_clear"] == ["H1"]
    assert (
        "| one | 3 of 3 | 3 | 2 | 3 |" in (tmp_path / "score" / "score.md").read_text()
    )


def test_score_refuses_a_label_argument_without_a_name(tmp_path: Path) -> None:
    script = _script()

    with pytest.raises(SystemExit, match="NAME=FILE"):
        script.main(
            ["score", "--verdicts", str(tmp_path), "--labels", "labels.yaml"]
            + ["--out-dir", str(tmp_path / "score")]
        )


def test_score_covers_only_the_cases_a_partial_reference_labels(
    tmp_path: Path,
) -> None:
    script = _script()
    out = tmp_path / "run"
    for case_id in ("H1", "H2", "H3"):
        _verdict_record(out, case_id, _recorded_verdict())
    full = tmp_path / "full.yaml"
    _dump(
        full,
        {
            "cases": [
                {"case_id": cid, "label": "demonstrated_conflict"}
                for cid in ("H1", "H2", "H3")
            ]
        },
    )
    partial = tmp_path / "partial.yaml"
    _dump(
        partial,
        {"cases": [{"case_id": "H2", "label": "no_conflict", "over_refusal": "yes"}]},
    )

    script.main(
        ["score", "--verdicts", str(out), "--labels", f"full={full}"]
        + ["--labels", f"partial={partial}", "--out-dir", str(tmp_path / "score")]
    )

    score = json.loads((tmp_path / "score" / "score.json").read_text())
    assert score["verdicts"] == 3
    assert score["by_reference"]["full"]["covers"] == 3
    assert score["by_reference"]["full"]["class"]["exact"] == 3
    partial_score = score["by_reference"]["partial"]
    assert partial_score["covers"] == 1
    assert partial_score["class"] == {"cases": 1, "exact": 0, "acceptable": 0}
    assert partial_score["over_refusal"]["found_clear"] == ["H2"]
    assert partial_score["over_refusal"]["flagged_unexpected"] == []
    assert score["agreed"]["case_ids"] == []
    assert "| partial | 1 of 3 |" in (tmp_path / "score" / "score.md").read_text()


def test_a_resource_id_repeated_across_sources_is_refused(tmp_path: Path) -> None:
    script = _script()
    manifest = tmp_path / "manifest.yaml"
    _dump(
        manifest,
        {
            "cases": [
                {
                    "case_id": "H1",
                    "run_dir": str(_run_dir(tmp_path)),
                    "scenario_ids": ["SCN-001"],
                    "resources": [
                        {
                            "resource_id": "RES-1",
                            "kind": "deadline",
                            "value": 1,
                            "unit": "hours",
                            "applies_to": "answering",
                        }
                    ],
                }
            ]
        },
    )
    shared = script.parse_resources(
        [
            {
                "resource_id": "RES-1",
                "kind": "reviewer_capacity",
                "value": 4,
                "unit": "reviews per hour",
                "applies_to": "the queue",
            }
        ]
    )

    with pytest.raises(SystemExit, match=r"H1: resource ids repeat: \['RES-1'\]"):
        script.load_cases(None, manifest, resources=shared)


def test_a_transport_retry_is_not_counted_as_a_correction(tmp_path: Path) -> None:
    from tests.helpers.transport_retry import _status_error

    script = _script()
    pending: list[BaseException] = [_status_error(502)]

    def respond(**kw: Any) -> Any:
        if pending:
            raise pending.pop(0)
        return _reply(_verdict())

    provider = _Provider(respond)

    summary = _run(script, provider, _cases(script, 1), tmp_path / "out", budget=5)

    assert len(provider.requests) == 2
    assert summary["spend"]["transport_retries"] == 1
    row = summary["rows"][0]
    assert row["requests"] == 2
    assert row["corrections"] == 0
    assert row["correction_changed_class"] is None
    assert summary["metrics"]["corrections"] == 0
    assert summary["metrics"]["cases_corrected"] == 0


def test_a_transport_retry_of_a_correction_is_still_one_correction(
    tmp_path: Path,
) -> None:
    from tests.helpers.transport_retry import _status_error

    script = _script()
    steps: list[Any] = [
        _reply(_verdict(finding_class="missing_information")),
        _status_error(502),
        _reply(_verdict()),
    ]

    def respond(**kw: Any) -> Any:
        step = steps.pop(0)
        if isinstance(step, BaseException):
            raise step
        return step

    provider = _Provider(respond)
    out = tmp_path / "out"

    summary = _run(script, provider, _cases(script, 1), out, budget=5)

    assert len(provider.requests) == 3
    assert summary["spend"]["records"] == 3
    assert summary["spend"]["by_source"] == {"live": 3}
    assert summary["spend"]["transport_retries"] == 1
    assert summary["spend"]["corrections"] == 1
    row = summary["rows"][0]
    assert (row["requests"], row["corrections"]) == (3, 1)
    assert row["correction_changed_class"] is True
    assert summary["metrics"]["corrections"] == 1
    assert "corrections: 1;" in (out / "summary.md").read_text()
