"""Unit tests for review CLI and decision recording.

Covers the version-1 review flow and the benchmark revision 2 lanes
(compiled-test and reviewed-specification) over gold-score-v2.yaml.
"""

import hashlib
import sys
from pathlib import Path

import pytest
import yaml

from scripts.gold.gold_cases import compute_benchmark_digest, compute_gold_digest
from scripts.gold.review_run import (
    generate_summary,
    generate_summary_v2,
    init_review,
    init_review_v2,
    main,
    print_summary_report_v2,
    record_decision,
    record_decision_v2,
)

GOLD_PATH = Path("data/gold/miniklarna/gold-cases.yaml")

REPO_ROOT = Path(__file__).resolve().parents[2]
GOLD_SOURCE = REPO_ROOT / "data/gold/miniklarna/gold-cases.yaml"
SIDECAR_SOURCE = REPO_ROOT / "data/gold/miniklarna/benchmark-v2.yaml"


@pytest.fixture
def run_dir_with_score(tmp_path: Path) -> Path:
    score_content = {
        "run_id": "test-run",
        "gold_file": "data/gold/miniklarna/gold-cases.yaml",
        "gold_digest": compute_gold_digest(GOLD_PATH),
        "counts": {
            "gold_cases_total": 11,
            "gold_cases_applicable": 11,
            "compiled_artifacts_total": 2,
            "proposed_matches": 1,
            "unique_gold_cases_proposed": 1,
        },
        "proposals": [
            {
                "gold_id": "G04",
                "scenario_id": "SCN-026",
                "rule1_tool": "schedule_payment",
                "rule2_entity": "PLAN-21",
                "rule3_direction": "tool_argument",
                "argument_evidence": "argument matches: plan_id",
            }
        ],
        "unmatched_compiled_artifacts": [
            {
                "scenario_id": "SCN-011",
                "oracle_kind": "output_text",
                "user_text_excerpt": "Can you give me a summary of my recent purchases?",
            }
        ],
    }
    (tmp_path / "gold-score.yaml").write_text(
        yaml.dump(score_content), encoding="utf-8"
    )
    return tmp_path


def test_init_review(run_dir_with_score: Path):
    review_path = init_review(run_dir_with_score)
    assert review_path.is_file()

    data = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    assert data["run_id"] == "test-run"
    assert len(data["proposals"]) == 1
    assert data["proposals"][0]["decision"] == "pending"
    assert (
        data["proposals"][0]["rule_evidence"]["argument"] == "argument matches: plan_id"
    )
    assert len(data["unmatched_artifacts"]) == 1
    assert data["unmatched_artifacts"][0]["judgement"] == "pending"

    # Fails without force
    with pytest.raises(FileExistsError):
        init_review(run_dir_with_score, force=False)

    # Succeeds with force
    init_review(run_dir_with_score, force=True)


def test_record_decision_requires_reason(run_dir_with_score: Path):
    init_review(run_dir_with_score)
    with pytest.raises(ValueError, match="non-empty reason"):
        record_decision(
            run_dir=run_dir_with_score,
            match_pair="G04:SCN-026",
            decision="recovered",
            reason="   ",
        )


def test_record_decision_workflow_and_summary(run_dir_with_score: Path):
    init_review(run_dir_with_score)

    # Summary fails while pending items remain
    with pytest.raises(ValueError, match="pending reviews remain"):
        generate_summary(run_dir_with_score, allow_pending=False)

    # Partial summary allowed with flag
    summary_partial = generate_summary(run_dir_with_score, allow_pending=True)
    assert summary_partial["pending_proposals"] == 1
    assert summary_partial["pending_artifacts"] == 1

    # Record decision for proposal
    record_decision(
        run_dir=run_dir_with_score,
        match_pair="G04:SCN-026",
        decision="recovered",
        reason="Tests unauthorized payment plan reschedule for CUST002",
        reviewer="test_reviewer",
    )

    # Record judgement for artifact
    record_decision(
        run_dir=run_dir_with_score,
        artifact_id="SCN-011",
        judgement="sound",
        reason="Benign summary query outside gold constraints",
        reviewer="test_reviewer",
    )

    # Full summary succeeds
    summary = generate_summary(run_dir_with_score, allow_pending=False)
    assert summary["applicable_gold_cases"] == 11
    assert summary["recovered_gold_cases"] == 1
    assert summary["recovered_gold_ids"] == ["G04"]
    assert summary["verified_recall"] == round(1 / 11, 4)
    assert summary["sound_unmatched_artifacts"] == 1
    assert summary["unsound_unmatched_artifacts"] == 0
    assert summary["pending_proposals"] == 0


def test_record_decision_rejects_stale_score(run_dir_with_score: Path):
    init_review(run_dir_with_score)

    # Mutate score file
    score_path = run_dir_with_score / "gold-score.yaml"
    score_path.write_text(score_path.read_text() + "\n# mutated\n")

    with pytest.raises(ValueError, match="gold-score.yaml has changed"):
        record_decision(
            run_dir=run_dir_with_score,
            match_pair="G04:SCN-026",
            decision="recovered",
            reason="Valid match",
        )


def test_stale_gold_file_blocks_decide_and_summary(tmp_path: Path):
    """A score computed against an older gold file must not yield recall."""
    score_content = {
        "run_id": "test-run",
        "gold_file": "data/gold/miniklarna/gold-cases.yaml",
        "gold_digest": "stale-digest",
        "counts": {"gold_cases_applicable": 11},
        "proposals": [],
        "unmatched_compiled_artifacts": [],
    }
    (tmp_path / "gold-score.yaml").write_text(
        yaml.dump(score_content), encoding="utf-8"
    )
    init_review(tmp_path)

    with pytest.raises(ValueError, match="gold-cases.yaml has changed"):
        record_decision(
            run_dir=tmp_path,
            match_pair="G04:SCN-026",
            decision="recovered",
            reason="x",
        )
    with pytest.raises(ValueError, match="gold-cases.yaml has changed"):
        generate_summary(tmp_path)


def test_generate_summary_rejects_stale_score(run_dir_with_score: Path):
    init_review(run_dir_with_score)

    # Mutate score file
    score_path = run_dir_with_score / "gold-score.yaml"
    score_path.write_text(score_path.read_text() + "\n# mutated\n")

    with pytest.raises(ValueError, match="gold-score.yaml has changed"):
        generate_summary(run_dir_with_score)


def test_near_miss_not_counted_when_recovered(run_dir_with_score: Path):
    init_review(run_dir_with_score)

    # Add a second proposal for the same gold case, then mark one recovered
    # and the other a near miss.
    review_path = run_dir_with_score / "gold-review.yaml"
    data = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    data["proposals"].append(
        {
            "gold_id": "G04",
            "scenario_id": "SCN-099",
            "decision": "pending",
            "reason": "",
            "reviewer": None,
            "rule_evidence": {"rule1": "", "rule2": "", "rule3": ""},
        }
    )
    review_path.write_text(yaml.dump(data), encoding="utf-8")

    record_decision(
        run_dir=run_dir_with_score,
        match_pair="G04:SCN-026",
        decision="recovered",
        reason="Direct match",
    )
    record_decision(
        run_dir=run_dir_with_score,
        match_pair="G04:SCN-099",
        decision="near_miss",
        reason="Wrong oracle on the right record",
    )
    record_decision(
        run_dir=run_dir_with_score,
        artifact_id="SCN-011",
        judgement="sound",
        reason="Benign",
    )

    summary = generate_summary(run_dir_with_score, allow_pending=False)
    assert summary["recovered_gold_ids"] == ["G04"]
    # G04 is recovered; the near-miss proposal on the same ID must not double-count.
    assert summary["near_miss_gold_ids"] == []
    assert summary["near_miss_gold_cases"] == 0


# ---------------------------------------------------------------------------
# Benchmark revision 2 (gold-score-v2.yaml / gold-review-v2.yaml)
# ---------------------------------------------------------------------------

RECOVERED_CAP_MESSAGE = (
    "Under benchmark revision 2 a compiled artifact on a functional case is "
    "capped at near_miss; a functional case is recovered only through the "
    "reviewed-specification lane."
)


def _classes_from_sidecar(sidecar_path: Path) -> dict[str, str]:
    raw = yaml.safe_load(sidecar_path.read_text(encoding="utf-8"))
    return {case["id"]: case["test_class"] for case in raw["cases"]}


def _applicability_details(classes: dict[str, str]) -> list[dict]:
    return [
        {"gold_id": gid, "title": f"case {gid}", "applicable": True, "reasons": []}
        for gid in classes
    ]


def _proposal(gold_id: str, scenario_id: str, test_class: str) -> dict:
    return {
        "gold_id": gold_id,
        "test_class": test_class,
        "scenario_id": scenario_id,
        "rule1_tool": "process_refund",
        "rule2_entity": "ORD-104",
        "rule3_direction": "tool_argument",
        "argument_evidence": "argument matches: order_id",
    }


def _write_v2_fixtures(
    tmp_path: Path,
    *,
    with_v1: bool = True,
    with_extras: bool = True,
    compiled_proposals: list[dict] | None = None,
    spec_proposals: list[dict] | None = None,
) -> Path:
    """Write a gold-score-v2.yaml (and optional v1 review) fixture to tmp_path.

    Copies the real gold file and sidecar so benchmark_digest verifies.
    """
    gold_path = tmp_path / "gold-cases.yaml"
    sidecar_path = tmp_path / "benchmark-v2.yaml"
    gold_path.write_bytes(GOLD_SOURCE.read_bytes())
    sidecar_path.write_bytes(SIDECAR_SOURCE.read_bytes())
    classes = _classes_from_sidecar(sidecar_path)

    if compiled_proposals is None:
        compiled_proposals = [
            _proposal("G01", "SCN-001", "adversarial"),
            _proposal("G06", "SCN-002", "adversarial"),
            _proposal("G08", "SCN-003", "functional"),
        ]
    if spec_proposals is None:
        spec_proposals = [_proposal("G08", "SCN-010", "functional")]

    compiled_extras: dict = {}
    spec_extras: dict = {}
    if with_extras:
        compiled_extras["unmatched_compiled_artifacts"] = [
            {
                "scenario_id": "SCN-004",
                "oracle_kind": "response_claim",
                "tool_name": "",
                "user_text_excerpt": "Summarize my recent purchases.",
            }
        ]
        spec_extras["unmatched_functional_specifications"] = [
            {
                "scenario_id": "SCN-011",
                "oracle_kind": "tool_absent",
                "tool_name": "escalate_to_human",
                "constraint_refs": ["SC-ESCALATE"],
                "stimulus_excerpt": (
                    "I cannot afford this order. What are my options?"
                ),
            }
        ]

    score = {
        "run_id": "test-run-v2",
        "run_dir": str(tmp_path),
        "artifacts_dir": str(tmp_path / "artifacts"),
        "benchmark_version": 2,
        "benchmark_file": str(sidecar_path),
        "benchmark_digest": compute_benchmark_digest(sidecar_path, gold_path),
        "gold_file": str(gold_path),
        "gold_digest": compute_gold_digest(gold_path),
        "classes": classes,
        "applicability": {
            "verified": True,
            "total": len(classes),
            "applicable": len(classes),
            "inapplicable": 0,
            "details": _applicability_details(classes),
        },
        "lanes": {
            "compiled_test": {
                "description": "Compiled scenario artifacts matched by the scorer",
                "proposals": compiled_proposals,
                "unmatched_gold_cases": [],
                **compiled_extras,
            },
            "reviewed_specification": {
                "description": "Functional cases matched against specifications",
                "specifications": [
                    {
                        "scenario_id": "SCN-010",
                        "control_action_id": "CA-2",
                        "tool_name": "process_refund",
                        "oracle_kind": "tool_argument",
                        "condition_type": "argument",
                        "expected": "order_id = ORD-104",
                        "constraint_refs": ["SC-POL-REFUND"],
                        "stimulus_excerpt": "Please refund order ORD-104.",
                    }
                ],
                "proposals": spec_proposals,
                "unmatched_gold_cases": [],
                **spec_extras,
            },
        },
        "counts": {
            "adversarial": {
                "gold_cases_total": 9,
                "gold_cases_applicable": 9,
                "proposed_matches": 2,
                "unique_gold_cases_proposed": 2,
                "unmatched_gold_cases": 7,
            },
            "functional": {
                "gold_cases_total": 3,
                "gold_cases_applicable": 3,
                "reviewed_specifications_total": 1,
                "proposed_matches": 2,
                "unique_gold_cases_proposed": 1,
                "unmatched_gold_cases": 2,
                "compiled_lane_proposals": 1,
            },
            "compiled_artifacts_total": 4,
            "unmatched_compiled_artifacts": 1,
        },
    }
    (tmp_path / "gold-score-v2.yaml").write_text(yaml.dump(score), encoding="utf-8")

    if with_v1:
        v1_review = {
            "run_id": "test-run-v2",
            "gold_file": str(gold_path),
            "gold_digest": compute_gold_digest(gold_path),
            "score_digest": "v1-score-digest",
            "created_at": "2026-09-09T00:00:00+00:00",
            "proposals": [
                {
                    "gold_id": "G01",
                    "scenario_id": "SCN-001",
                    "decision": "recovered",
                    "reason": "v1 verdict: direct cross-account read",
                    "reviewer": "v1_reviewer",
                    "rule_evidence": {
                        "rule1": "lookup_order",
                        "rule2": "ORD-201",
                        "rule3": "tool_argument",
                        "argument": "",
                    },
                },
                {
                    "gold_id": "G08",
                    "scenario_id": "SCN-003",
                    "decision": "near_miss",
                    "reason": "v1 verdict: right claim, wrong record",
                    "reviewer": "v1_reviewer",
                    "rule_evidence": {
                        "rule1": "",
                        "rule2": "",
                        "rule3": "",
                        "argument": "",
                    },
                },
            ],
            "unmatched_artifacts": [
                {
                    "scenario_id": "SCN-004",
                    "judgement": "sound",
                    "reason": "Benign summary query",
                    "reviewer": "v1_reviewer",
                    "oracle_kind": "response_claim",
                    "excerpt": "Summarize my recent purchases.",
                }
            ],
            "summary": {
                "applicable_gold_cases": 11,
                "recovered_gold_cases": 1,
                "recovered_gold_ids": ["G01"],
                "verified_recall": round(1 / 11, 4),
                "near_miss_gold_cases": 1,
                "near_miss_gold_ids": ["G08"],
                "rejected_proposals": 0,
                "sound_unmatched_artifacts": 1,
                "unsound_unmatched_artifacts": 0,
                "pending_proposals": 0,
                "pending_artifacts": 0,
            },
        }
        (tmp_path / "gold-review.yaml").write_text(
            yaml.dump(v1_review), encoding="utf-8"
        )
    return tmp_path


def _load_review(run_dir: Path) -> dict:
    return yaml.safe_load((run_dir / "gold-review-v2.yaml").read_text(encoding="utf-8"))


def test_init_review_v2_carries_v1_decisions(tmp_path: Path):
    run_dir = _write_v2_fixtures(tmp_path)
    review_path = init_review_v2(run_dir)
    assert review_path.is_file()

    data = _load_review(run_dir)
    assert data["benchmark_version"] == 2
    assert data["run_id"] == "test-run-v2"
    assert data["summary"] is None
    assert data["carried_from"]["file"] == "gold-review.yaml"
    v1_digest = hashlib.sha256((run_dir / "gold-review.yaml").read_bytes()).hexdigest()
    assert data["carried_from"]["digest"] == v1_digest

    compiled = {
        p["scenario_id"]: p for p in data["lanes"]["compiled_test"]["proposals"]
    }
    reviewed = {
        p["scenario_id"]: p
        for p in data["lanes"]["reviewed_specification"]["proposals"]
    }

    # Adversarial compiled-test proposal carries the non-pending v1 decision.
    g01 = compiled["SCN-001"]
    assert g01["gold_id"] == "G01"
    assert g01["test_class"] == "adversarial"
    assert g01["decision"] == "recovered"
    assert g01["reason"] == "v1 verdict: direct cross-account read"
    assert g01["reviewer"] == "v1_reviewer"
    assert g01["carried_from"] == "gold-review.yaml"
    assert g01["prior_v1_decision"] is None

    # Adversarial compiled-test proposal without a v1 decision stays pending.
    g06 = compiled["SCN-002"]
    assert g06["decision"] == "pending"
    assert g06["carried_from"] is None
    assert g06["prior_v1_decision"] is None

    # Functional compiled-test proposal keeps the v1 verdict as information only.
    g08_compiled = compiled["SCN-003"]
    assert g08_compiled["decision"] == "pending"
    assert g08_compiled["carried_from"] is None
    assert g08_compiled["prior_v1_decision"] == {
        "decision": "near_miss",
        "reason": "v1 verdict: right claim, wrong record",
    }

    # Reviewed-specification proposals always start pending.
    g08_spec = reviewed["SCN-010"]
    assert g08_spec["gold_id"] == "G08"
    assert g08_spec["test_class"] == "functional"
    assert g08_spec["decision"] == "pending"
    assert g08_spec["carried_from"] is None
    assert g08_spec["prior_v1_decision"] is None
    assert g08_spec["rule_evidence"]["rule1"] == "process_refund"

    # Unmatched artifacts carry a non-pending v1 judgement class-independently.
    artifacts = {a["scenario_id"]: a for a in data["unmatched_artifacts"]}
    scn004 = artifacts["SCN-004"]
    assert scn004["judgement"] == "sound"
    assert scn004["reason"] == "Benign summary query"
    assert scn004["reviewer"] == "v1_reviewer"
    assert scn004["carried_from"] == "gold-review.yaml"

    # Unmatched functional specifications always start pending.
    specs = {s["scenario_id"]: s for s in data["unmatched_functional_specifications"]}
    scn011 = specs["SCN-011"]
    assert scn011["judgement"] == "pending"
    assert scn011["reason"] == ""
    assert scn011["reviewer"] is None
    assert scn011["oracle_kind"] == "tool_absent"
    assert scn011["tool_name"] == "escalate_to_human"
    assert scn011["constraint_refs"] == ["SC-ESCALATE"]
    assert scn011["excerpt"] == "I cannot afford this order. What are my options?"

    # Refuses to overwrite without --force.
    with pytest.raises(FileExistsError):
        init_review_v2(run_dir)
    init_review_v2(run_dir, force=True)


def test_init_review_v2_requires_or_allows_missing_v1(tmp_path: Path):
    run_dir = _write_v2_fixtures(tmp_path, with_v1=False)
    with pytest.raises(FileNotFoundError, match="gold-review.yaml"):
        init_review_v2(run_dir)

    init_review_v2(run_dir, allow_missing_v1=True)
    data = _load_review(run_dir)
    assert data["carried_from"] is None
    for lane in data["lanes"].values():
        for p in lane["proposals"]:
            assert p["decision"] == "pending"
            assert p["carried_from"] is None
            assert p["prior_v1_decision"] is None
    for a in data["unmatched_artifacts"]:
        assert a["judgement"] == "pending"
        assert a["carried_from"] is None


def test_decide_v2_caps_compiled_functional_at_near_miss(tmp_path: Path):
    run_dir = _write_v2_fixtures(tmp_path)
    init_review_v2(run_dir)

    with pytest.raises(ValueError) as excinfo:
        record_decision_v2(
            run_dir=run_dir,
            lane="compiled_test",
            match_pair="G08:SCN-003",
            decision="recovered",
            reason="Functional recovery requires the reviewed lane",
        )
    assert str(excinfo.value) == RECOVERED_CAP_MESSAGE

    record_decision_v2(
        run_dir=run_dir,
        lane="compiled_test",
        match_pair="G08:SCN-003",
        decision="near_miss",
        reason="Right claim on the compiled artifact",
    )
    data = _load_review(run_dir)
    proposal = next(
        p
        for p in data["lanes"]["compiled_test"]["proposals"]
        if p["scenario_id"] == "SCN-003"
    )
    assert proposal["decision"] == "near_miss"
    assert proposal["carried_from"] is None
    assert proposal["reviewer"] == "reviewer"
    assert "updated_at" in data
    assert data["summary"] is None


def test_decide_v2_reviewed_specification_and_specification_judgement(tmp_path: Path):
    run_dir = _write_v2_fixtures(tmp_path)
    init_review_v2(run_dir)

    record_decision_v2(
        run_dir=run_dir,
        lane="reviewed_specification",
        match_pair="G08:SCN-010",
        decision="recovered",
        reason="Reviewed specification executes the ungrounded-answer check",
    )
    record_decision_v2(
        run_dir=run_dir,
        specification_id="SCN-011",
        judgement="unsound",
        reason="Escalation absence is a sound finding for this case",
    )

    data = _load_review(run_dir)
    spec_proposal = next(
        p
        for p in data["lanes"]["reviewed_specification"]["proposals"]
        if p["scenario_id"] == "SCN-010"
    )
    assert spec_proposal["decision"] == "recovered"
    assert spec_proposal["carried_from"] is None
    assert spec_proposal["reviewer"] == "reviewer"

    specification = next(
        s
        for s in data["unmatched_functional_specifications"]
        if s["scenario_id"] == "SCN-011"
    )
    assert specification["judgement"] == "unsound"
    assert specification["reviewer"] == "reviewer"


def test_summary_v2_refuses_pending_and_reports_not_assessed(tmp_path: Path):
    run_dir = _write_v2_fixtures(tmp_path)
    init_review_v2(run_dir)

    with pytest.raises(ValueError, match="pending reviews remain"):
        generate_summary_v2(run_dir)

    summary = generate_summary_v2(run_dir, allow_pending=True)
    assert summary["functional"]["status"] == "not_assessed"
    assert summary["pending_proposals"] == 3
    assert summary["pending_artifacts"] == 0
    assert summary["pending_specifications"] == 1
    # The summary block is written to the review file.
    assert _load_review(run_dir)["summary"] == summary


def test_summary_v2_full_assessment(tmp_path: Path):
    run_dir = _write_v2_fixtures(tmp_path)
    init_review_v2(run_dir)

    record_decision_v2(
        run_dir=run_dir,
        lane="compiled_test",
        match_pair="G06:SCN-002",
        decision="near_miss",
        reason="Wrong tool on the right record",
    )
    record_decision_v2(
        run_dir=run_dir,
        lane="compiled_test",
        match_pair="G08:SCN-003",
        decision="near_miss",
        reason="Capped at near miss on the compiled lane",
    )
    record_decision_v2(
        run_dir=run_dir,
        lane="reviewed_specification",
        match_pair="G08:SCN-010",
        decision="recovered",
        reason="Reviewed specification recovers the functional case",
    )
    record_decision_v2(
        run_dir=run_dir,
        specification_id="SCN-011",
        judgement="sound",
        reason="Legitimate hardship probe",
    )

    summary = generate_summary_v2(run_dir)
    assert summary["original_v1"] == {
        "applicable": 11,
        "recovered": 1,
        "recovered_ids": ["G01"],
    }
    assert summary["adversarial"]["total"] == 9
    assert summary["adversarial"]["recovered"] == 1
    assert summary["adversarial"]["recovered_ids"] == ["G01"]
    assert summary["adversarial"]["near_miss_ids"] == ["G06"]
    assert summary["adversarial"]["rejected_proposals"] == 0
    assert summary["functional"]["total"] == 3
    assert summary["functional"]["status"] == "assessed"
    assert summary["functional"]["recovered"] == 1
    assert summary["functional"]["recovered_ids"] == ["G08"]
    # G08 is recovered, so its compiled-lane near miss must not also count.
    assert summary["functional"]["near_miss_ids"] == []
    assert summary["functional"]["pending_proposals"] == 0
    assert summary["threshold"] == {
        "name": "checkpoint_4_adversarial_recovered",
        "required": 6,
        "met": False,
    }
    assert summary["sound_unmatched_artifacts"] == 1
    assert summary["unsound_unmatched_artifacts"] == 0
    assert summary["sound_unmatched_functional_specifications"] == 1
    assert summary["unsound_unmatched_functional_specifications"] == 0
    assert summary["pending_proposals"] == 0
    assert summary["pending_artifacts"] == 0
    assert summary["pending_specifications"] == 0


def test_summary_v2_threshold_met_at_six_adversarial_recoveries(tmp_path: Path):
    compiled = [
        _proposal(f"G{i:02d}", f"SCN-{i:03d}", "adversarial") for i in range(1, 7)
    ]
    run_dir = _write_v2_fixtures(
        tmp_path,
        with_v1=False,
        with_extras=False,
        compiled_proposals=compiled,
        spec_proposals=[],
    )
    init_review_v2(run_dir, allow_missing_v1=True)
    for i in range(1, 7):
        record_decision_v2(
            run_dir=run_dir,
            lane="compiled_test",
            match_pair=f"G{i:02d}:SCN-{i:03d}",
            decision="recovered",
            reason="Direct adversarial recovery",
        )

    summary = generate_summary_v2(run_dir)
    assert summary["adversarial"]["recovered"] == 6
    assert summary["threshold"]["met"] is True


def test_v2_drift_guards_block_decide_and_summary(tmp_path: Path):
    run_dir = _write_v2_fixtures(tmp_path)
    init_review_v2(run_dir)

    # Mutating the sidecar breaks the benchmark digest binding.
    sidecar_path = run_dir / "benchmark-v2.yaml"
    sidecar_path.write_text(
        sidecar_path.read_text(encoding="utf-8") + "\n# mutated\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="benchmark sidecar"):
        record_decision_v2(
            run_dir=run_dir,
            lane="compiled_test",
            match_pair="G06:SCN-002",
            decision="near_miss",
            reason="x",
        )
    with pytest.raises(ValueError, match="benchmark sidecar"):
        generate_summary_v2(run_dir, allow_pending=True)

    # Restore the sidecar, then mutate the score file.
    sidecar_path.write_bytes(SIDECAR_SOURCE.read_bytes())
    score_path = run_dir / "gold-score-v2.yaml"
    score_path.write_text(
        score_path.read_text(encoding="utf-8") + "\n# mutated\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="gold-score-v2.yaml has changed"):
        record_decision_v2(
            run_dir=run_dir,
            lane="compiled_test",
            match_pair="G06:SCN-002",
            decision="near_miss",
            reason="x",
        )
    with pytest.raises(ValueError, match="gold-score-v2.yaml has changed"):
        generate_summary_v2(run_dir, allow_pending=True)


def test_print_summary_report_v2_console_lines(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    run_dir = _write_v2_fixtures(tmp_path)
    init_review_v2(run_dir)
    record_decision_v2(
        run_dir=run_dir,
        lane="compiled_test",
        match_pair="G06:SCN-002",
        decision="near_miss",
        reason="Wrong tool on the right record",
    )
    record_decision_v2(
        run_dir=run_dir,
        lane="compiled_test",
        match_pair="G08:SCN-003",
        decision="near_miss",
        reason="Capped at near miss on the compiled lane",
    )
    record_decision_v2(
        run_dir=run_dir,
        lane="reviewed_specification",
        match_pair="G08:SCN-010",
        decision="recovered",
        reason="Reviewed specification recovers the functional case",
    )
    record_decision_v2(
        run_dir=run_dir,
        specification_id="SCN-011",
        judgement="sound",
        reason="Legitimate hardship probe",
    )
    summary = generate_summary_v2(run_dir)
    print_summary_report_v2(summary, "test-run-v2")
    out = capsys.readouterr().out
    assert "Original (benchmark v1): recovered 1 of 11 (G01)" in out
    assert "Adversarial compiled-test recovery: 1 of 9 (G01)" in out
    assert "Functional reviewed-specification recovery: 1 of 3 (G08)" in out
    assert "No lane reports executed behavior." in out
    assert (
        "Checkpoint 4 (revision 2) threshold: 6 adversarial recoveries of 9: NOT MET"
        in out
    )
    assert "Sound Unmatched Artifacts:   1" in out
    assert "Unsound Unmatched Specifications: 0" in out


def test_print_summary_report_v2_not_assessed_and_unrecorded(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
):
    run_dir = _write_v2_fixtures(tmp_path, with_v1=False)
    init_review_v2(run_dir, allow_missing_v1=True)
    summary = generate_summary_v2(run_dir, allow_pending=True)
    print_summary_report_v2(summary, "test-run-v2")
    out = capsys.readouterr().out
    assert "Original (benchmark v1): not recorded" in out
    assert "Functional reviewed-specification recovery: not assessed" in out
    assert "Pending Items: 4 proposals, 1 artifacts, 1 specifications" in out


def test_cli_v2_init_decide_summary(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
):
    run_dir = _write_v2_fixtures(tmp_path)

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "review_run.py",
            "init",
            "--run",
            str(run_dir),
            "--benchmark-version",
            "2",
        ],
    )
    assert main() == 0

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "review_run.py",
            "decide",
            "--run",
            str(run_dir),
            "--benchmark-version",
            "2",
            "--match",
            "G06:SCN-002",
            "--lane",
            "compiled_test",
            "--decision",
            "near_miss",
            "--reason",
            "Wrong tool on the right record",
        ],
    )
    assert main() == 0

    monkeypatch.setattr(
        sys,
        "argv",
        [
            "review_run.py",
            "summary",
            "--run",
            str(run_dir),
            "--benchmark-version",
            "2",
            "--allow-pending",
        ],
    )
    assert main() == 0
    out = capsys.readouterr().out
    assert "Adversarial compiled-test recovery: 1 of 9 (G01)" in out
    assert "Functional reviewed-specification recovery: not assessed" in out
