"""M4 producer cutover: superseded paths are gone from normal execution.

Behavioral pins for the cutover: the normal ``run`` offers no mode-selection
input, and a normal publication (with or without an observed profile)
carries no mode sidecar or execution projection/bundle.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
)
from tests.helpers.unified_stage2 import _observations, _profile

from tests.helpers.scenario_handoff_publication import (
    _normal_semantics_payload,
    _profile_condition,
)
from tests.helpers.scenario_handoff_publication import _publish

#: Filesystem entries a normal (handoff-publishing) run must never create.
_EXECUTION_ARTIFACTS = (
    "execution-bundle.json",
    ".generations",
    "scenarios/canonical",
)


def test_run_cli_offers_no_mode_selection_input() -> None:
    """``generate`` exposes no generation-mode selector."""
    import typer.main

    command = typer.main.get_command(app)
    run_command = command.commands["generate"]  # type: ignore[index]
    names = {param.name for param in run_command.params}
    help_text = " ".join((param.help or "") for param in run_command.params).lower()
    for retired in names:
        assert "mode" not in retired, retired
    for retired in ("generation mode", "target-derived mode"):
        assert retired not in help_text, retired
    # The profile input is enrichment evidence, not an algorithm selector.
    assert "does not select a generation algorithm" in help_text


def test_normal_run_publishes_no_execution_artifacts_or_mode_sidecar(
    tmp_path: Path,
) -> None:
    _publish([_normal_semantics_payload()], tmp_path)

    for artifact in _EXECUTION_ARTIFACTS:
        assert not (tmp_path / artifact).exists(), artifact
    published = [path.name for path in tmp_path.rglob("*execution-projection*")]
    assert published == []
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert "mode" not in manifest["stage_summary"].get("stage_2", {})


def test_normal_run_with_observed_profile_publishes_no_execution_artifacts(
    tmp_path: Path,
) -> None:
    """The observed-profile run publishes the same artifact classes: no mode
    sidecar, no execution projection or bundle."""
    payload = _normal_semantics_payload()
    payload["unsafe_outcome"]["discriminating_condition"] = _profile_condition()
    result = _publish(
        [payload],
        tmp_path,
        execution_target_profile=_profile(),
        target_observations=_observations(),
    )

    assert [outcome.status for outcome in result.candidate_outcomes] == [
        SP3CandidateStatus.published
    ]
    for artifact in _EXECUTION_ARTIFACTS:
        assert not (tmp_path / artifact).exists(), artifact
    published = [path.name for path in tmp_path.rglob("*execution-projection*")]
    assert published == []
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert "mode" not in manifest["stage_summary"].get("stage_2", {})
    # The handoff is still the published artifact, and the profile input is
    # published only as enrichment evidence.
    handoff = yaml.safe_load((tmp_path / "scenarios" / "SCN-001.yaml").read_text())
    assert handoff["narrative"].strip()
    assert (tmp_path / "execution-target-profile.json").is_file()
    assert not (tmp_path / "target-derived-structure.yaml").exists()
