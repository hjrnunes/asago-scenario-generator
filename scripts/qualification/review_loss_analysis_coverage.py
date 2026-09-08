"""Run the advisory Stage 1a risk-coverage review offline against a saved graph.

This opt-in qualification tool exists for one owner decision: measure the
reviewer's discriminating power against a graph the review never saw.  It
does not change the product pipeline, does not gate anything, and writes
only the review artifact plus the call log under ``--out``.

The tool reuses the product seam unchanged: it loads the supplied
``loss-analysis.yaml`` and reviewed risk set, computes the same graph digest
the product run records, and calls :func:`run_risk_coverage_review` once with
a named model profile.  The provider wire, the per-row validation, and the
artifact schema are exactly the ones the product run uses, so a verdict read
here means the same thing it would mean inside a run.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.pipeline.llm_config import (
    DEFAULT_PROFILES_FILE,
    read_use_case,
    resolve_llm_client_from_profile,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.risk_coverage_review import (
    ARTIFACT_FILENAME,
    graph_digest,
    run_risk_coverage_review,
)


def _load_loss_analysis(path: Path) -> LossAnalysis:
    """Load a persisted ``loss-analysis.yaml`` through its closed model."""
    payload = yaml.safe_load(path.read_text(encoding="utf-8"))
    return LossAnalysis.model_validate(payload)


def main(argv: list[str] | None = None) -> int:
    """Run the review once and report its status and row counts."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--loss-analysis",
        type=Path,
        required=True,
        help="Path to the loss-analysis.yaml to review",
    )
    parser.add_argument(
        "--risk-set",
        type=Path,
        required=True,
        help="Path to the policy-mapper risk-extraction.json (reviewed risk set)",
    )
    parser.add_argument(
        "--use-case",
        type=Path,
        required=True,
        help="Path to the use-case text file (@ prefix optional)",
    )
    parser.add_argument(
        "--out",
        type=Path,
        required=True,
        help="Directory for the review artifact and calls.jsonl",
    )
    parser.add_argument(
        "--profile",
        default="gemma4-oc",
        help="Named model profile to load (default: gemma4-oc)",
    )
    parser.add_argument(
        "--profiles-file",
        default=DEFAULT_PROFILES_FILE,
        help=f"Model profiles YAML file (default: {DEFAULT_PROFILES_FILE})",
    )
    parser.add_argument(
        "--temperature",
        type=float,
        default=0.4,
        help="Sampling temperature (default: 0.4)",
    )
    args = parser.parse_args(argv)

    loss_analysis = _load_loss_analysis(args.loss_analysis)
    risk_cards = load_reviewed_risk_extraction(args.risk_set)
    use_case_text = read_use_case(str(args.use_case))
    args.out.mkdir(parents=True, exist_ok=True)

    llm_client, _ = resolve_llm_client_from_profile(args.profiles_file, args.profile)
    outcome = run_risk_coverage_review(
        llm_client=llm_client,
        loss_analysis=loss_analysis,
        risk_cards=risk_cards,
        use_case_text=use_case_text,
        run_dir=args.out,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=args.temperature,
        reviewed_loss_analysis_digest=graph_digest(loss_analysis),
    )

    summary = outcome.artifact.summary if outcome.artifact is not None else None
    print(f"status: {outcome.status}")
    print(f"call_count: {outcome.call_count}")
    if outcome.failure_reason:
        print(f"failure_reason: {outcome.failure_reason}")
    if summary is not None:
        print(
            "rows: "
            f"valid={summary.rows_valid} "
            f"invalid={summary.rows_invalid} "
            f"missing={summary.rows_missing}"
        )
        print(
            "coverage: "
            f"full={summary.full} "
            f"partial={summary.partial} "
            f"none={summary.none} "
            f"not_applicable_confirmed={summary.not_applicable_confirmed} "
            f"not_applicable_disputed={summary.not_applicable_disputed}"
        )
    print(f"artifact: {args.out / ARTIFACT_FILENAME}")
    print(f"calls: {args.out / 'calls.jsonl'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
