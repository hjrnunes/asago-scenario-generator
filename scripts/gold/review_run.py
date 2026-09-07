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

from scripts.gold.gold_cases import atomic_write_text, compute_gold_digest


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
        "--reason", required=True, help="Explanation justifying the decision"
    )
    decide_parser.add_argument("--reviewer", help="Name or handle of the reviewer")

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

    args = parser.parse_args()
    run_dir = Path(args.run)

    try:
        if args.command == "init":
            out = init_review(run_dir, force=args.force)
            print(f"Initialized review file: {out}")
        elif args.command == "decide":
            record_decision(
                run_dir=run_dir,
                match_pair=args.match,
                decision=args.decision,
                artifact_id=args.artifact,
                judgement=args.judgement,
                reason=args.reason,
                reviewer=args.reviewer,
            )
            target = args.match or args.artifact
            val = args.decision or args.judgement
            print(f"Recorded decision for {target}: {val}")
        elif args.command == "summary":
            summary = generate_summary(run_dir, allow_pending=args.allow_pending)
            print_summary_report(summary, run_dir.name)
        return 0
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
