"""The final product manifest keeps the SP1-owned stage keys.

``scenario_prod.run._write_manifest`` writes the last ``run-manifest.yaml``
of a product run and rebuilds ``stage_summary`` from ``calls.jsonl``.  That
rebuild cannot recover the Stage 1a pinned/derived source, the advisory
coverage-review record, or the Stage 2 post-review digest, so the final
write must merge them back from the SP1 manifest it replaces.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    ExecutionRunIdentity,
)
from asago_scenario_generator.stpa.scenario_prod.run import _write_manifest

from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_sp3_run import _make_cs, _make_ets, _make_loss_analysis

PINNED_DIGEST = "6e127482ffcfd0d38b474e4518264c6e81c509a2c4d123f6de11d6f6e7069046"


def _write_prior_manifest(run_dir: Path, *, stage_1a: dict, stage_2: dict, **rest):
    """Write the SP1 manifest the final SP3 write replaces."""
    run_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "run_id": "sp1-prior",
        "run_dir": str(run_dir),
        "created_at": "2026-09-08T00:00:00+00:00",
        "input_hashes": {"loss_analysis": PINNED_DIGEST},
        "stage_summary": {"stage_1a": stage_1a, "stage_2": stage_2},
        **rest,
    }
    (run_dir / "run-manifest.yaml").write_text(
        yaml.safe_dump(manifest, sort_keys=False), encoding="utf-8"
    )


def _final_manifest(run_dir: Path) -> dict:
    _write_manifest(
        run_dir=run_dir,
        llm_client=MockLLMClient(),
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=_make_cs(),
        loss_analysis=_make_loss_analysis(),
        scenario_envelopes=[],
        validation_errors=[],
        max_workers=1,
        temperature=0.4,
        stage_errors=[],
        run_identity=ExecutionRunIdentity(run_id="synthesis-test"),
        run_started=datetime(2026, 9, 8, tzinfo=timezone.utc),
    )
    return yaml.safe_load((run_dir / "run-manifest.yaml").read_text(encoding="utf-8"))


def test_pinned_run_keeps_source_zero_calls_and_the_pinned_digest(tmp_path):
    run_dir = tmp_path / "pinned"
    _write_prior_manifest(
        run_dir,
        stage_1a={"call_count": 0, "source": "pinned"},
        stage_2={"call_count": 2, "mode": "target_derived"},
    )

    manifest = _final_manifest(run_dir)

    stage_1a = manifest["stage_summary"]["stage_1a"]
    assert stage_1a["source"] == "pinned"
    assert stage_1a["call_count"] == 0
    assert manifest["input_hashes"]["loss_analysis"] == PINNED_DIGEST


def test_derived_run_keeps_the_review_and_post_review_digest(tmp_path):
    run_dir = tmp_path / "derived"
    review = {
        "status": "completed",
        "call_count": 2,
        "failure_reason": None,
        "reviewed_loss_analysis_digest": "a" * 64,
    }
    _write_prior_manifest(
        run_dir,
        stage_1a={"call_count": 3, "source": "derived", "risk_coverage_review": review},
        stage_2={
            "call_count": 2,
            "mode": "target_derived",
            "post_review_loss_analysis_digest": "b" * 64,
        },
    )

    manifest = _final_manifest(run_dir)

    stage_1a = manifest["stage_summary"]["stage_1a"]
    assert stage_1a["source"] == "derived"
    assert stage_1a["risk_coverage_review"] == review
    assert manifest["stage_summary"]["stage_2"]["post_review_loss_analysis_digest"] == (
        "b" * 64
    )


def test_canonical_hash_wins_for_a_run_without_a_prior_manifest(tmp_path):
    """A run with no SP1 manifest keeps the canonical model hash."""
    run_dir = tmp_path / "fresh"
    run_dir.mkdir()

    manifest = _final_manifest(run_dir)

    assert manifest["input_hashes"]["loss_analysis"] != PINNED_DIGEST
