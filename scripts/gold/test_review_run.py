"""Unit tests for review CLI and decision recording."""

from pathlib import Path

import pytest
import yaml

from scripts.gold.gold_cases import compute_gold_digest
from scripts.gold.review_run import (
    generate_summary,
    init_review,
    record_decision,
)

GOLD_PATH = Path("data/gold/miniklarna/gold-cases.yaml")


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
