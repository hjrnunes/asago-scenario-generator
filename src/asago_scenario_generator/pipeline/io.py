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
