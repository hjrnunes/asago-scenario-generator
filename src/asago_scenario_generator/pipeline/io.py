"""Pipeline I/O boundary -- all filesystem writes for the pipeline runner.

This module centralises the file I/O that ``runner.run_pipeline`` performs so
that the pipeline orchestration logic can be tested without real filesystem
access.  Per-scenario incremental writes (``write_scenario_outputs``,
``write_call_log`` from ``generate.py``) remain in the generation loop for
crash-resilience but are re-exported here for a single import surface.

In cmps.1, all writes target a resolved **run directory** (an immutable
child of the user-supplied collection).  The manifest sentinel and
finalization are handled by :mod:`asago_scenario_generator.manifest`.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from pathlib import Path

import yaml

from asago_scenario_generator.models import ThreatSurface
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    inject_kc_subcodes_display,
)
from asago_scenario_generator.pipeline.candidate_models import FilterSeedQuarantine
from asago_scenario_generator.pipeline.jsonl import append_jsonl

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Per-stage writes
# ---------------------------------------------------------------------------


def write_use_case(run_dir: Path, use_case: str) -> Path:
    """Write the use-case description to ``use-case.txt`` in the run directory."""
    path = run_dir / "use-case.txt"
    path.write_text(use_case, encoding="utf-8")
    return path


def write_capability_profile(profile: CapabilityProfile, run_dir: Path) -> Path:
    """Serialise and write the capability profile to ``capability-profile.yaml``.

    Returns:
        Path to the written file.
    """
    profile_output_path = run_dir / "capability-profile.yaml"
    profile_data = profile.model_dump(mode="json", exclude_none=True)
    profile_data = inject_kc_subcodes_display(profile_data)
    profile_output_path.write_text(
        yaml.dump(
            profile_data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return profile_output_path


def write_threat_surface(threat_surface: ThreatSurface, run_dir: Path) -> Path:
    """Serialise and write the threat surface to ``threat-surface.yaml``.

    Returns:
        Path to the written file.
    """
    ts_path = run_dir / "threat-surface.yaml"
    ts_data = threat_surface.model_dump(mode="json", exclude_none=True)
    ts_path.write_text(
        yaml.dump(
            ts_data,
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return ts_path


def write_pipeline_call_log(entries: list[dict], run_dir: Path) -> None:
    """Append call-log entries to the top-level ``calls.jsonl`` in *run_dir*.

    This file records all LLM calls: pipeline-level calls (capability-profile
    inference, candidate filtering) and scenario-level generation calls
    (actor, narrative, tree, behavior).  Scenario calls are also written to
    ``scenarios/calls.jsonl`` by :func:`assembly.write_call_log`.
    """
    if not entries:
        return
    append_jsonl(entries, run_dir / "calls.jsonl")


def write_filter_quarantine_evidence(
    quarantines: Sequence[FilterSeedQuarantine], run_dir: Path
) -> Path | None:
    """Persist seed-local candidate-filter quarantine evidence."""
    if not quarantines:
        return None
    path = run_dir / "candidate-filter-quarantine.json"
    payload = {
        "schema_version": "1",
        "seeds": [
            item.model_dump(mode="json")
            for item in sorted(quarantines, key=lambda item: item.seed_id)
        ],
    }
    path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return path


def get_scenarios_dir(run_dir: Path) -> Path:
    """Return the path to the ``scenarios/`` subdirectory (does not create it).

    Creation is left to the incremental per-scenario writers in
    ``generate.write_scenario_outputs`` which call ``mkdir(parents=True)``.
    """
    return run_dir / "scenarios"


# ---------------------------------------------------------------------------
# Finalisation writes (post-loop)
# ---------------------------------------------------------------------------


def write_eval_scorecard(scorecard: dict, run_dir: Path) -> Path:
    """Write the evaluation scorecard to ``eval-scorecard.yaml``.

    Returns:
        Path to the written file.
    """
    from asago_scenario_generator.eval.scorecard import ScorecardV1

    validated = ScorecardV1.model_validate(scorecard)
    scorecard_path = run_dir / "eval-scorecard.yaml"
    scorecard_path.write_text(
        yaml.dump(
            validated.model_dump(mode="json"),
            default_flow_style=False,
            sort_keys=False,
            allow_unicode=True,
        ),
        encoding="utf-8",
    )
    return scorecard_path


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T00:32:13Z","module_hash":"819a391aa2d4c5463230f518b734324e12ca6b4a76c7234b5ca76e6d8973bad2","functions":[{"id":"func/write_use_case","name":"write_use_case","line":36,"end_line":40,"hash":"90c269eb1272c7dbe24c9f5cefcb2870b0cead572756da9dba50da47e59ecf48"},{"id":"func/write_capability_profile","name":"write_capability_profile","line":43,"end_line":61,"hash":"22fd04ec76add13479bc57f8ce7ff73a5b075b91b9f4c91be82586c6a90da38e"},{"id":"func/write_threat_surface","name":"write_threat_surface","line":64,"end_line":81,"hash":"23370e700083c92938f5d14477afdb073641320b1a51811b0b301b7ba4579e04"},{"id":"func/write_pipeline_call_log","name":"write_pipeline_call_log","line":84,"end_line":98,"hash":"e5017fbe9ee39afb3a6e8a181add74bdb1d51684f9489b6bcf682d346f710495"},{"id":"func/get_scenarios_dir","name":"get_scenarios_dir","line":101,"end_line":107,"hash":"a2a5ffca80c01ef6472551fa58ce0df9088c2ee52ef1b5af3fa733f5bcc73690"},{"id":"func/write_eval_scorecard","name":"write_eval_scorecard","line":115,"end_line":134,"hash":"6e8beca7507b4f95e2eb34bb9a7d32e4cf23a3b687049a6aca984b98ff00f885"}]}
# mutate4py-manifest-end
