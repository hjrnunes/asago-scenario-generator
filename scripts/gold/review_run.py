"""Review CLI for recorded gold-scoring results.

Manages review decisions (recovered, near_miss, rejected) and computes verified recall.
See ai/findings/target-grounded-scenario-generation-spec-2026-09-07.md (Phase 0).
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from scripts.gold.gold_cases import (
    BenchmarkRevision,
    atomic_write_text,
    compute_benchmark_digest,
    compute_gold_digest,
)

SCORE_V2_NAME = "gold-score-v2.yaml"
REVIEW_V2_NAME = "gold-review-v2.yaml"
V1_REVIEW_NAME = "gold-review.yaml"
COMPILED_TEST_LANE = "compiled_test"
REVIEWED_SPECIFICATION_LANE = "reviewed_specification"
ADVERSARIAL_THRESHOLD = "checkpoint_4_adversarial_recovered"
BENCHMARK_V2_RECOVERED_MESSAGE = (
    "Under benchmark revision 2 a compiled artifact on a functional case is "
    "capped at near_miss; a functional case is recovered only through the "
    "reviewed-specification lane."
)


def _file_digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _gold_file_drifted(score_data: dict[str, Any]) -> bool:
    """True when gold-cases.yaml changed after the score was computed."""
    gold_path = score_data.get("gold_file")
    recorded = score_data.get("gold_digest")
    if not gold_path or not recorded:
        return False
    path = Path(gold_path)
    if not path.is_file():
        return False
    return compute_gold_digest(path) != recorded


def init_review(run_dir: Path, force: bool = False) -> Path:
    score_path = run_dir / "gold-score.yaml"
    if not score_path.is_file():
        raise FileNotFoundError(f"Missing {score_path}. Run score_run.py first.")

    review_path = run_dir / "gold-review.yaml"
    if review_path.is_file() and not force:
        raise FileExistsError(
            f"{review_path} already exists. Use --force to overwrite."
        )

    score_data = yaml.safe_load(score_path.read_text(encoding="utf-8"))
    score_digest = _file_digest(score_path)

    proposals_review: list[dict[str, Any]] = []
    for p in score_data.get("proposals", []):
        proposals_review.append(
            {
                "gold_id": p["gold_id"],
                "scenario_id": p["scenario_id"],
                "decision": "pending",
                "reason": "",
                "reviewer": None,
                "rule_evidence": {
                    "rule1": p.get("rule1_tool", ""),
                    "rule2": p.get("rule2_entity", ""),
                    "rule3": p.get("rule3_direction", ""),
                    "argument": p.get("argument_evidence", ""),
                },
            }
        )

    artifacts_review: list[dict[str, Any]] = []
    for a in score_data.get("unmatched_compiled_artifacts", []):
        artifacts_review.append(
            {
                "scenario_id": a["scenario_id"],
                "judgement": "pending",
                "reason": "",
                "reviewer": None,
                "oracle_kind": a.get("oracle_kind", ""),
                "excerpt": a.get("user_text_excerpt", ""),
            }
        )

    review_data = {
        "run_id": score_data.get("run_id"),
        "gold_file": score_data.get("gold_file"),
        "gold_digest": score_data.get("gold_digest"),
        "score_digest": score_digest,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "proposals": proposals_review,
        "unmatched_artifacts": artifacts_review,
        "summary": None,
    }

    atomic_write_text(review_path, yaml.dump(review_data, sort_keys=False))
    return review_path


def record_decision(
    run_dir: Path,
    match_pair: str | None = None,
    decision: str | None = None,
    artifact_id: str | None = None,
    judgement: str | None = None,
    reason: str = "",
    reviewer: str | None = None,
) -> None:
    if not reason.strip():
        raise ValueError("A non-empty reason is required for review decisions.")

    review_path = run_dir / "gold-review.yaml"
    score_path = run_dir / "gold-score.yaml"
    if not review_path.is_file():
        raise FileNotFoundError(f"Missing {review_path}. Run init first.")
    if not score_path.is_file():
        raise FileNotFoundError(f"Missing {score_path}.")

    review_data = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    score_data = yaml.safe_load(score_path.read_text(encoding="utf-8"))
    curr_score_digest = _file_digest(score_path)
    if review_data.get("score_digest") != curr_score_digest:
        raise ValueError(
            "gold-score.yaml has changed since gold-review.yaml was initialized. "
            "Re-initialize review with --force to sync."
        )
    if _gold_file_drifted(score_data):
        raise ValueError(
            "gold-cases.yaml has changed since gold-score.yaml was computed. "
            "Re-run score_run.py, then re-init the review with --force."
        )

    updated = False

    if match_pair:
        if ":" not in match_pair:
            raise ValueError(
                "Match pair must be formatted as GOLD_ID:SCENARIO_ID, e.g. G04:SCN-026"
            )
        gid, sid = match_pair.split(":", 1)
        if decision not in ("recovered", "near_miss", "rejected"):
            raise ValueError(
                f"Invalid decision {decision!r}. Must be recovered, near_miss, or rejected."
            )

        for p in review_data.get("proposals", []):
            if p["gold_id"] == gid and p["scenario_id"] == sid:
                p["decision"] = decision
                p["reason"] = reason.strip()
                p["reviewer"] = reviewer or "reviewer"
                updated = True
                break

        if not updated:
            raise ValueError(
                f"Proposal for match {match_pair} not found in {review_path}."
            )

    elif artifact_id:
        if judgement not in ("sound", "unsound"):
            raise ValueError(
                f"Invalid judgement {judgement!r}. Must be sound or unsound."
            )

        for a in review_data.get("unmatched_artifacts", []):
            if a["scenario_id"] == artifact_id:
                a["judgement"] = judgement
                a["reason"] = reason.strip()
                a["reviewer"] = reviewer or "reviewer"
                updated = True
                break

        if not updated:
            raise ValueError(
                f"Artifact {artifact_id} not found in unmatched_artifacts in {review_path}."
            )

    else:
        raise ValueError("Must provide either --match or --artifact.")

    review_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    # invalidate prior summary since decisions changed
    review_data["summary"] = None
    atomic_write_text(review_path, yaml.dump(review_data, sort_keys=False))


def generate_summary(run_dir: Path, allow_pending: bool = False) -> dict[str, Any]:
    review_path = run_dir / "gold-review.yaml"
    score_path = run_dir / "gold-score.yaml"
    if not review_path.is_file():
        raise FileNotFoundError(f"Missing {review_path}.")
    if not score_path.is_file():
        raise FileNotFoundError(f"Missing {score_path}.")

    review_data = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    score_data = yaml.safe_load(score_path.read_text(encoding="utf-8"))

    curr_score_digest = _file_digest(score_path)
    if review_data.get("score_digest") != curr_score_digest:
        raise ValueError(
            "gold-score.yaml has changed since gold-review.yaml was initialized. "
            "Re-initialize review with --force to sync."
        )
    if _gold_file_drifted(score_data):
        raise ValueError(
            "gold-cases.yaml has changed since gold-score.yaml was computed. "
            "Re-run score_run.py, then re-init the review with --force."
        )

    # Check for pending items
    pending_proposals = [
        f"{p['gold_id']}:{p['scenario_id']}"
        for p in review_data.get("proposals", [])
        if p.get("decision") == "pending"
    ]
    pending_artifacts = [
        a["scenario_id"]
        for a in review_data.get("unmatched_artifacts", [])
        if a.get("judgement") == "pending"
    ]

    if (pending_proposals or pending_artifacts) and not allow_pending:
        msg = "Cannot generate final summary: pending reviews remain.\n"
        if pending_proposals:
            msg += f"  Pending match decisions: {', '.join(pending_proposals)}\n"
        if pending_artifacts:
            msg += f"  Pending artifact judgements: {', '.join(pending_artifacts)}\n"
        raise ValueError(msg)

    # Compute verified metrics
    applicable_gold = score_data.get("counts", {}).get("gold_cases_applicable", 0)

    recovered_gold_ids: set[str] = set()
    near_miss_gold_ids: set[str] = set()
    rejected_count = 0

    for p in review_data.get("proposals", []):
        dec = p.get("decision")
        if dec == "recovered":
            recovered_gold_ids.add(p["gold_id"])
        elif dec == "near_miss":
            near_miss_gold_ids.add(p["gold_id"])
        elif dec == "rejected":
            rejected_count += 1

    # A gold case counted as recovered is not also counted as a near miss.
    near_miss_only = sorted(near_miss_gold_ids - recovered_gold_ids)

    sound_artifacts_count = sum(
        1
        for a in review_data.get("unmatched_artifacts", [])
        if a.get("judgement") == "sound"
    )
    unsound_artifacts_count = sum(
        1
        for a in review_data.get("unmatched_artifacts", [])
        if a.get("judgement") == "unsound"
    )

    verified_recall = (
        round(len(recovered_gold_ids) / applicable_gold, 4)
        if applicable_gold > 0
        else 0.0
    )

    summary = {
        "applicable_gold_cases": applicable_gold,
        "recovered_gold_cases": len(recovered_gold_ids),
        "recovered_gold_ids": sorted(recovered_gold_ids),
        "verified_recall": verified_recall,
        "near_miss_gold_cases": len(near_miss_only),
        "near_miss_gold_ids": near_miss_only,
        "rejected_proposals": rejected_count,
        "sound_unmatched_artifacts": sound_artifacts_count,
        "unsound_unmatched_artifacts": unsound_artifacts_count,
        "pending_proposals": len(pending_proposals),
        "pending_artifacts": len(pending_artifacts),
    }

    review_data["summary"] = summary
    atomic_write_text(review_path, yaml.dump(review_data, sort_keys=False))
    return summary


def print_summary_report(summary: dict[str, Any], run_id: str) -> None:
    print("=" * 64)
    print(f"Verified Review Summary: {run_id}")
    print("-" * 64)
    print(f"Applicable Gold Cases:       {summary['applicable_gold_cases']}")
    print(
        f"Recovered Gold Cases:        {summary['recovered_gold_cases']} ({', '.join(summary['recovered_gold_ids']) if summary['recovered_gold_ids'] else 'none'})"
    )
    print(f"Verified Recall:             {summary['verified_recall'] * 100:.1f}%")
    print(f"Near-miss Gold Cases:        {summary['near_miss_gold_cases']}")
    print(f"Rejected Proposals:          {summary['rejected_proposals']}")
    print(f"Sound Unmatched Artifacts:   {summary['sound_unmatched_artifacts']}")
    print(f"Unsound Unmatched Artifacts: {summary['unsound_unmatched_artifacts']}")
    if summary["pending_proposals"] or summary["pending_artifacts"]:
        print(
            f"Pending Items:               {summary['pending_proposals']} proposals, {summary['pending_artifacts']} artifacts"
        )
    print("=" * 64)


# ---------------------------------------------------------------------------
# Benchmark revision 2 (gold-score-v2.yaml / gold-review-v2.yaml)
# ---------------------------------------------------------------------------


def _v1_decision_index(
    v1_data: dict[str, Any] | None,
) -> dict[tuple[str, str], dict[str, Any]]:
    index: dict[tuple[str, str], dict[str, Any]] = {}
    for p in (v1_data or {}).get("proposals", []):
        index[(p["gold_id"], p["scenario_id"])] = p
    return index


def _v1_artifact_index(v1_data: dict[str, Any] | None) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for a in (v1_data or {}).get("unmatched_artifacts", []):
        index[a["scenario_id"]] = a
    return index


def _v2_rule_evidence(proposal: dict[str, Any]) -> dict[str, str]:
    return {
        "rule1": proposal.get("rule1_tool", ""),
        "rule2": proposal.get("rule2_entity", ""),
        "rule3": proposal.get("rule3_direction", ""),
        "argument": proposal.get("argument_evidence", ""),
    }


def _init_v2_proposal(
    proposal: dict[str, Any],
    lane_name: str,
    v1_proposals: dict[tuple[str, str], dict[str, Any]],
) -> dict[str, Any]:
    pair = (proposal["gold_id"], proposal["scenario_id"])
    v1 = v1_proposals.get(pair)
    test_class = proposal.get("test_class") or (
        "adversarial" if lane_name == COMPILED_TEST_LANE else "functional"
    )
    # A non-pending v1 verdict; a pending v1 decision is the absence of a verdict.
    v1_verdict = v1 if (v1 is not None and v1.get("decision") != "pending") else None
    carried = (
        lane_name == COMPILED_TEST_LANE
        and test_class == "adversarial"
        and v1_verdict is not None
    )
    if carried:
        decision = v1_verdict["decision"]
        reason = v1_verdict.get("reason", "")
        reviewer = v1_verdict.get("reviewer")
        carried_from: str | None = V1_REVIEW_NAME
        prior_v1_decision: dict[str, Any] | None = None
    else:
        decision = "pending"
        reason = ""
        reviewer = None
        carried_from = None
        prior_v1_decision = (
            {"decision": v1_verdict["decision"], "reason": v1_verdict.get("reason", "")}
            if v1_verdict is not None
            else None
        )
    return {
        "gold_id": proposal["gold_id"],
        "test_class": test_class,
        "scenario_id": proposal["scenario_id"],
        "decision": decision,
        "reason": reason,
        "reviewer": reviewer,
        "carried_from": carried_from,
        "prior_v1_decision": prior_v1_decision,
        "rule_evidence": _v2_rule_evidence(proposal),
    }


def init_review_v2(
    run_dir: Path, force: bool = False, allow_missing_v1: bool = False
) -> Path:
    """Initialize gold-review-v2.yaml from gold-score-v2.yaml.

    Carries non-pending version-1 decisions for adversarial compiled-test
    proposals and for unmatched artifacts. A missing version-1 review file
    raises unless ``allow_missing_v1`` is set.
    """
    score_path = run_dir / SCORE_V2_NAME
    if not score_path.is_file():
        raise FileNotFoundError(
            f"Missing {score_path}. Run score_run.py --benchmark-version 2 first."
        )

    review_path = run_dir / REVIEW_V2_NAME
    if review_path.is_file() and not force:
        raise FileExistsError(
            f"{review_path} already exists. Use --force to overwrite."
        )

    score_data = yaml.safe_load(score_path.read_text(encoding="utf-8"))
    if score_data.get("benchmark_version") != 2:
        raise ValueError(f"{score_path} does not declare benchmark_version: 2.")
    score_digest = _file_digest(score_path)

    v1_path = run_dir / V1_REVIEW_NAME
    v1_data: dict[str, Any] | None = None
    carried_from: dict[str, str] | None = None
    if v1_path.is_file():
        v1_data = yaml.safe_load(v1_path.read_text(encoding="utf-8")) or {}
        carried_from = {"file": V1_REVIEW_NAME, "digest": _file_digest(v1_path)}
    elif not allow_missing_v1:
        raise FileNotFoundError(
            f"Missing {v1_path}. Initialize the version-1 review first, or "
            "pass --allow-missing-v1 to start without carried decisions."
        )

    v1_proposals = _v1_decision_index(v1_data)
    v1_artifacts = _v1_artifact_index(v1_data)
    score_lanes = score_data.get("lanes", {}) or {}

    lanes_review: dict[str, Any] = {}
    for lane_name in (COMPILED_TEST_LANE, REVIEWED_SPECIFICATION_LANE):
        lane_score = score_lanes.get(lane_name, {}) or {}
        lanes_review[lane_name] = {
            "proposals": [
                _init_v2_proposal(p, lane_name, v1_proposals)
                for p in lane_score.get("proposals", [])
            ]
        }

    artifacts_review: list[dict[str, Any]] = []
    for a in (score_lanes.get(COMPILED_TEST_LANE, {}) or {}).get(
        "unmatched_compiled_artifacts", []
    ):
        v1_artifact = v1_artifacts.get(a["scenario_id"])
        carried = v1_artifact is not None and v1_artifact.get("judgement") not in (
            None,
            "pending",
        )
        artifacts_review.append(
            {
                "scenario_id": a["scenario_id"],
                "judgement": v1_artifact["judgement"] if carried else "pending",
                "reason": v1_artifact.get("reason", "") if carried else "",
                "reviewer": v1_artifact.get("reviewer") if carried else None,
                "carried_from": V1_REVIEW_NAME if carried else None,
                "oracle_kind": a.get("oracle_kind", ""),
                "excerpt": a.get("user_text_excerpt", ""),
            }
        )

    specifications_review: list[dict[str, Any]] = []
    for s in (score_lanes.get(REVIEWED_SPECIFICATION_LANE, {}) or {}).get(
        "unmatched_functional_specifications", []
    ):
        specifications_review.append(
            {
                "scenario_id": s["scenario_id"],
                "judgement": "pending",
                "reason": "",
                "reviewer": None,
                "oracle_kind": s.get("oracle_kind", ""),
                "tool_name": s.get("tool_name", ""),
                "constraint_refs": list(s.get("constraint_refs", [])),
                "excerpt": s.get("stimulus_excerpt", ""),
            }
        )

    review_data = {
        "run_id": score_data.get("run_id"),
        "benchmark_version": 2,
        "benchmark_file": score_data.get("benchmark_file"),
        "benchmark_digest": score_data.get("benchmark_digest"),
        "gold_file": score_data.get("gold_file"),
        "gold_digest": score_data.get("gold_digest"),
        "score_digest": score_digest,
        "carried_from": carried_from,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "lanes": lanes_review,
        "unmatched_artifacts": artifacts_review,
        "unmatched_functional_specifications": specifications_review,
        "summary": None,
    }

    atomic_write_text(review_path, yaml.dump(review_data, sort_keys=False))
    return review_path


def _check_v2_benchmark_drift(review_path: Path, review_data: dict[str, Any]) -> None:
    """Fail when the benchmark sidecar or the gold file changed under the review."""
    benchmark_file = review_data.get("benchmark_file")
    benchmark_digest = review_data.get("benchmark_digest")
    gold_file = review_data.get("gold_file")
    if not benchmark_file or not benchmark_digest or not gold_file:
        raise ValueError(
            f"{review_path} is missing benchmark binding fields. "
            "Re-initialize the review with --force to sync."
        )
    actual = compute_benchmark_digest(benchmark_file, gold_file)
    if actual != benchmark_digest:
        raise ValueError(
            "The benchmark sidecar or the gold file has changed since "
            f"{REVIEW_V2_NAME} was initialized. Re-run score_run.py "
            "--benchmark-version 2, then re-init the review with --force."
        )


def record_decision_v2(
    run_dir: Path,
    lane: str | None = None,
    match_pair: str | None = None,
    decision: str | None = None,
    artifact_id: str | None = None,
    specification_id: str | None = None,
    judgement: str | None = None,
    reason: str = "",
    reviewer: str | None = None,
) -> None:
    """Record a version-2 review decision.

    Match decisions require ``lane`` and search ``lanes[lane].proposals``.
    ``artifact_id`` adjudicates an unmatched artifact;
    ``specification_id`` adjudicates an unmatched functional specification.
    """
    if not reason.strip():
        raise ValueError("A non-empty reason is required for review decisions.")

    review_path = run_dir / REVIEW_V2_NAME
    score_path = run_dir / SCORE_V2_NAME
    if not review_path.is_file():
        raise FileNotFoundError(
            f"Missing {review_path}. Run init --benchmark-version 2 first."
        )
    if not score_path.is_file():
        raise FileNotFoundError(f"Missing {score_path}.")

    review_data = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    if review_data.get("score_digest") != _file_digest(score_path):
        raise ValueError(
            f"{SCORE_V2_NAME} has changed since {REVIEW_V2_NAME} was "
            "initialized. Re-initialize the review with --force to sync."
        )
    _check_v2_benchmark_drift(review_path, review_data)

    provided = [t for t in (match_pair, artifact_id, specification_id) if t]
    if len(provided) != 1:
        raise ValueError(
            "Must provide exactly one of --match, --artifact, or --specification."
        )

    if match_pair:
        if decision not in ("recovered", "near_miss", "rejected"):
            raise ValueError(
                f"Invalid decision {decision!r}. Must be recovered, near_miss, or rejected."
            )
        if lane not in (COMPILED_TEST_LANE, REVIEWED_SPECIFICATION_LANE):
            raise ValueError(
                "--lane must be compiled_test or reviewed_specification "
                "for --match under benchmark version 2."
            )
        if ":" not in match_pair:
            raise ValueError(
                "Match pair must be formatted as GOLD_ID:SCENARIO_ID, e.g. G04:SCN-026"
            )
        gid, sid = match_pair.split(":", 1)
        proposals = review_data.get("lanes", {}).get(lane, {}).get("proposals", [])
        target = next(
            (p for p in proposals if p["gold_id"] == gid and p["scenario_id"] == sid),
            None,
        )
        if target is None:
            raise ValueError(
                f"Proposal for match {match_pair} not found in lane {lane} "
                f"of {review_path}."
            )
        if (
            decision == "recovered"
            and lane == COMPILED_TEST_LANE
            and target.get("test_class") == "functional"
        ):
            raise ValueError(BENCHMARK_V2_RECOVERED_MESSAGE)
        target["decision"] = decision
        target["reason"] = reason.strip()
        target["reviewer"] = reviewer or "reviewer"
        target["carried_from"] = None

    elif artifact_id:
        if judgement not in ("sound", "unsound"):
            raise ValueError(
                f"Invalid judgement {judgement!r}. Must be sound or unsound."
            )
        target_artifact = next(
            (
                a
                for a in review_data.get("unmatched_artifacts", [])
                if a["scenario_id"] == artifact_id
            ),
            None,
        )
        if target_artifact is None:
            raise ValueError(
                f"Artifact {artifact_id} not found in unmatched_artifacts "
                f"in {review_path}."
            )
        target_artifact["judgement"] = judgement
        target_artifact["reason"] = reason.strip()
        target_artifact["reviewer"] = reviewer or "reviewer"
        target_artifact["carried_from"] = None

    else:  # specification_id
        if judgement not in ("sound", "unsound"):
            raise ValueError(
                f"Invalid judgement {judgement!r}. Must be sound or unsound."
            )
        target_specification = next(
            (
                s
                for s in review_data.get("unmatched_functional_specifications", [])
                if s["scenario_id"] == specification_id
            ),
            None,
        )
        if target_specification is None:
            raise ValueError(
                f"Specification {specification_id} not found in "
                f"unmatched_functional_specifications in {review_path}."
            )
        target_specification["judgement"] = judgement
        target_specification["reason"] = reason.strip()
        target_specification["reviewer"] = reviewer or "reviewer"

    review_data["updated_at"] = datetime.now(timezone.utc).isoformat()
    # invalidate prior summary since decisions changed
    review_data["summary"] = None
    atomic_write_text(review_path, yaml.dump(review_data, sort_keys=False))


def _adversarial_threshold(review_data: dict[str, Any]) -> int:
    benchmark_file = review_data.get("benchmark_file")
    if not benchmark_file:
        raise ValueError(
            f"{REVIEW_V2_NAME} is missing benchmark_file; "
            "re-initialize the review with --force."
        )
    raw = yaml.safe_load(Path(benchmark_file).read_text(encoding="utf-8"))
    revision = BenchmarkRevision.model_validate(raw)
    required = revision.thresholds.get(ADVERSARIAL_THRESHOLD)
    if required is None:
        raise ValueError(
            f"Benchmark sidecar {benchmark_file} does not define the threshold "
            f"{ADVERSARIAL_THRESHOLD}."
        )
    return required


def generate_summary_v2(run_dir: Path, allow_pending: bool = False) -> dict[str, Any]:
    review_path = run_dir / REVIEW_V2_NAME
    score_path = run_dir / SCORE_V2_NAME
    if not review_path.is_file():
        raise FileNotFoundError(f"Missing {review_path}.")
    if not score_path.is_file():
        raise FileNotFoundError(f"Missing {score_path}.")

    review_data = yaml.safe_load(review_path.read_text(encoding="utf-8"))
    if review_data.get("score_digest") != _file_digest(score_path):
        raise ValueError(
            f"{SCORE_V2_NAME} has changed since {REVIEW_V2_NAME} was "
            "initialized. Re-initialize the review with --force to sync."
        )
    _check_v2_benchmark_drift(review_path, review_data)

    score_data = yaml.safe_load(score_path.read_text(encoding="utf-8"))
    classes = score_data.get("classes", {}) or {}
    details = (score_data.get("applicability", {}) or {}).get("details", []) or []

    compiled = (
        review_data.get("lanes", {}).get(COMPILED_TEST_LANE, {}).get("proposals", [])
    )
    reviewed = (
        review_data.get("lanes", {})
        .get(REVIEWED_SPECIFICATION_LANE, {})
        .get("proposals", [])
    )
    artifacts = review_data.get("unmatched_artifacts", [])
    specifications = review_data.get("unmatched_functional_specifications", [])

    def gold_class(proposal: dict[str, Any]) -> str:
        return classes.get(proposal.get("gold_id")) or proposal.get("test_class", "")

    pending_proposals: list[str] = []
    for lane_name, proposals in (
        (COMPILED_TEST_LANE, compiled),
        (REVIEWED_SPECIFICATION_LANE, reviewed),
    ):
        for p in proposals:
            if p.get("decision") == "pending":
                pending_proposals.append(
                    f"{lane_name} {p['gold_id']}:{p['scenario_id']}"
                )
    pending_artifacts = [
        a["scenario_id"] for a in artifacts if a.get("judgement") == "pending"
    ]
    pending_specifications = [
        s["scenario_id"] for s in specifications if s.get("judgement") == "pending"
    ]

    if (
        pending_proposals or pending_artifacts or pending_specifications
    ) and not allow_pending:
        msg = "Cannot generate final summary: pending reviews remain.\n"
        if pending_proposals:
            msg += f"  Pending match decisions: {', '.join(pending_proposals)}\n"
        if pending_artifacts:
            msg += f"  Pending artifact judgements: {', '.join(pending_artifacts)}\n"
        if pending_specifications:
            msg += (
                f"  Pending specification judgements: "
                f"{', '.join(pending_specifications)}\n"
            )
        raise ValueError(msg)

    adversarial_total = sum(
        1
        for d in details
        if d.get("applicable") and classes.get(d.get("gold_id")) == "adversarial"
    )
    functional_total = sum(
        1
        for d in details
        if d.get("applicable") and classes.get(d.get("gold_id")) == "functional"
    )

    adversarial_recovered_ids = {
        p["gold_id"]
        for p in compiled
        if p.get("decision") == "recovered" and gold_class(p) == "adversarial"
    }
    adversarial_near_miss_ids = {
        p["gold_id"]
        for p in compiled
        if p.get("decision") == "near_miss" and gold_class(p) == "adversarial"
    } - adversarial_recovered_ids
    adversarial_rejected = sum(
        1
        for p in compiled
        if p.get("decision") == "rejected" and gold_class(p) == "adversarial"
    )

    functional_recovered_ids = {
        p["gold_id"]
        for p in reviewed
        if p.get("decision") == "recovered" and gold_class(p) == "functional"
    }
    functional_near_miss_ids = {
        p["gold_id"]
        for p in compiled + reviewed
        if p.get("decision") == "near_miss" and gold_class(p) == "functional"
    } - functional_recovered_ids
    functional_rejected = sum(
        1
        for p in compiled + reviewed
        if p.get("decision") == "rejected" and gold_class(p) == "functional"
    )
    functional_pending_proposals = sum(
        1
        for p in compiled + reviewed
        if p.get("decision") == "pending" and gold_class(p) == "functional"
    )
    functional_assessed = functional_pending_proposals == 0 and all(
        s.get("judgement") != "pending" for s in specifications
    )

    required = _adversarial_threshold(review_data)

    original_v1: dict[str, Any] | None = None
    v1_path = run_dir / V1_REVIEW_NAME
    if v1_path.is_file():
        v1_data = yaml.safe_load(v1_path.read_text(encoding="utf-8")) or {}
        v1_summary = v1_data.get("summary")
        if isinstance(v1_summary, dict):
            original_v1 = {
                "applicable": v1_summary.get("applicable_gold_cases"),
                "recovered": v1_summary.get("recovered_gold_cases"),
                "recovered_ids": list(v1_summary.get("recovered_gold_ids", []) or []),
            }

    summary = {
        "original_v1": original_v1,
        "adversarial": {
            "total": adversarial_total,
            "recovered": len(adversarial_recovered_ids),
            "recovered_ids": sorted(adversarial_recovered_ids),
            "near_miss_ids": sorted(adversarial_near_miss_ids),
            "rejected_proposals": adversarial_rejected,
        },
        "functional": {
            "total": functional_total,
            "status": "assessed" if functional_assessed else "not_assessed",
            "recovered": len(functional_recovered_ids),
            "recovered_ids": sorted(functional_recovered_ids),
            "near_miss_ids": sorted(functional_near_miss_ids),
            "rejected_proposals": functional_rejected,
            "pending_proposals": functional_pending_proposals,
        },
        "threshold": {
            "name": ADVERSARIAL_THRESHOLD,
            "required": required,
            "met": len(adversarial_recovered_ids) >= required,
        },
        "sound_unmatched_artifacts": sum(
            1 for a in artifacts if a.get("judgement") == "sound"
        ),
        "unsound_unmatched_artifacts": sum(
            1 for a in artifacts if a.get("judgement") == "unsound"
        ),
        "sound_unmatched_functional_specifications": sum(
            1 for s in specifications if s.get("judgement") == "sound"
        ),
        "unsound_unmatched_functional_specifications": sum(
            1 for s in specifications if s.get("judgement") == "unsound"
        ),
        "pending_proposals": len(pending_proposals),
        "pending_artifacts": len(pending_artifacts),
        "pending_specifications": len(pending_specifications),
    }

    review_data["summary"] = summary
    atomic_write_text(review_path, yaml.dump(review_data, sort_keys=False))
    return summary


def print_summary_report_v2(summary: dict[str, Any], run_id: str) -> None:
    print("=" * 64)
    print(f"Benchmark Revision 2 Review Summary: {run_id}")
    print("-" * 64)
    original = summary.get("original_v1")
    if original:
        original_ids = ", ".join(original.get("recovered_ids", []) or []) or "none"
        print(
            f"Original (benchmark v1): recovered {original['recovered']} "
            f"of {original['applicable']} ({original_ids})"
        )
    else:
        print("Original (benchmark v1): not recorded")
    adversarial = summary["adversarial"]
    adversarial_ids = ", ".join(adversarial["recovered_ids"]) or "none"
    print(
        f"Adversarial compiled-test recovery: {adversarial['recovered']} "
        f"of {adversarial['total']} ({adversarial_ids})"
    )
    functional = summary["functional"]
    if functional["status"] == "not_assessed":
        print("Functional reviewed-specification recovery: not assessed")
    else:
        functional_ids = ", ".join(functional["recovered_ids"]) or "none"
        print(
            f"Functional reviewed-specification recovery: "
            f"{functional['recovered']} of {functional['total']} ({functional_ids})"
        )
    print("No lane reports executed behavior.")
    threshold = summary["threshold"]
    verdict = "MET" if threshold["met"] else "NOT MET"
    print(
        f"Checkpoint 4 (revision 2) threshold: {threshold['required']} adversarial "
        f"recoveries of {adversarial['total']}: {verdict}"
    )
    print(f"Sound Unmatched Artifacts:   {summary['sound_unmatched_artifacts']}")
    print(f"Unsound Unmatched Artifacts: {summary['unsound_unmatched_artifacts']}")
    print(
        "Sound Unmatched Specifications:   "
        f"{summary['sound_unmatched_functional_specifications']}"
    )
    print(
        "Unsound Unmatched Specifications: "
        f"{summary['unsound_unmatched_functional_specifications']}"
    )
    if (
        summary["pending_proposals"]
        or summary["pending_artifacts"]
        or summary["pending_specifications"]
    ):
        print(
            f"Pending Items: {summary['pending_proposals']} proposals, "
            f"{summary['pending_artifacts']} artifacts, "
            f"{summary['pending_specifications']} specifications"
        )
    print("=" * 64)


def _add_benchmark_version(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--benchmark-version",
        type=int,
        choices=[1, 2],
        default=1,
        help=(
            "Benchmark revision: 2 reads gold-score-v2.yaml and writes "
            "gold-review-v2.yaml"
        ),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    init_parser = subparsers.add_parser(
        "init", help="Initialize gold-review.yaml from gold-score.yaml"
    )
    init_parser.add_argument("--run", required=True, help="Path to run directory")
    init_parser.add_argument(
        "--force", action="store_true", help="Overwrite existing gold-review.yaml"
    )
    _add_benchmark_version(init_parser)
    init_parser.add_argument(
        "--allow-missing-v1",
        action="store_true",
        help=(
            "With --benchmark-version 2, initialize without a version-1 "
            "gold-review.yaml to carry decisions from"
        ),
    )

    # decide
    decide_parser = subparsers.add_parser(
        "decide", help="Record a review decision for a match or artifact"
    )
    decide_parser.add_argument("--run", required=True, help="Path to run directory")
    decide_parser.add_argument("--match", help="Match pair (e.g. G04:SCN-026)")
    decide_parser.add_argument(
        "--decision",
        choices=["recovered", "near_miss", "rejected"],
        help="Proposal decision",
    )
    decide_parser.add_argument(
        "--artifact", help="Unmatched scenario ID (e.g. SCN-011)"
    )
    decide_parser.add_argument(
        "--judgement", choices=["sound", "unsound"], help="Artifact judgement"
    )
    decide_parser.add_argument(
        "--lane",
        choices=[COMPILED_TEST_LANE, REVIEWED_SPECIFICATION_LANE],
        help=(
            "With --benchmark-version 2, the lane holding the proposal named by --match"
        ),
    )
    decide_parser.add_argument(
        "--specification",
        help=(
            "With --benchmark-version 2, unmatched functional specification "
            "ID (e.g. SCN-011)"
        ),
    )
    decide_parser.add_argument(
        "--reason", required=True, help="Explanation justifying the decision"
    )
    decide_parser.add_argument("--reviewer", help="Name or handle of the reviewer")
    _add_benchmark_version(decide_parser)

    # summary
    summary_parser = subparsers.add_parser(
        "summary", help="Produce verified recall summary and report"
    )
    summary_parser.add_argument("--run", required=True, help="Path to run directory")
    summary_parser.add_argument(
        "--allow-pending",
        action="store_true",
        help="Generate summary even with pending items",
    )
    _add_benchmark_version(summary_parser)

    args = parser.parse_args()
    run_dir = Path(args.run)

    try:
        if args.command == "init":
            if args.benchmark_version == 2:
                out = init_review_v2(
                    run_dir,
                    force=args.force,
                    allow_missing_v1=args.allow_missing_v1,
                )
            else:
                if args.allow_missing_v1:
                    raise ValueError(
                        "--allow-missing-v1 applies only to --benchmark-version 2."
                    )
                out = init_review(run_dir, force=args.force)
            print(f"Initialized review file: {out}")
        elif args.command == "decide":
            if args.benchmark_version == 2:
                record_decision_v2(
                    run_dir=run_dir,
                    lane=args.lane,
                    match_pair=args.match,
                    decision=args.decision,
                    artifact_id=args.artifact,
                    specification_id=args.specification,
                    judgement=args.judgement,
                    reason=args.reason,
                    reviewer=args.reviewer,
                )
            else:
                if args.lane or args.specification:
                    raise ValueError(
                        "--lane and --specification apply only to "
                        "--benchmark-version 2."
                    )
                record_decision(
                    run_dir=run_dir,
                    match_pair=args.match,
                    decision=args.decision,
                    artifact_id=args.artifact,
                    judgement=args.judgement,
                    reason=args.reason,
                    reviewer=args.reviewer,
                )
            target = args.match or args.artifact or args.specification
            val = args.decision or args.judgement
            print(f"Recorded decision for {target}: {val}")
        elif args.command == "summary":
            if args.benchmark_version == 2:
                summary = generate_summary_v2(run_dir, allow_pending=args.allow_pending)
                print_summary_report_v2(summary, run_dir.name)
            else:
                summary = generate_summary(run_dir, allow_pending=args.allow_pending)
                print_summary_report(summary, run_dir.name)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
