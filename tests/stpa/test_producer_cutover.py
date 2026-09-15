"""M4 producer cutover: superseded paths are gone from normal execution.

Behavioral pins for the cutover: the normal ``run`` offers no mode-selection
input, a normal publication (with or without an observed profile) carries no
mode sidecar or execution projection/bundle, and the retained historical
projection/bundle readers validate archived artifacts read-only — identical
digests before and after, zero writes, and zero provider clients.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.cli._app import app
from asago_scenario_generator.stpa.scenario_prod.execution_bundle import (
    verify_execution_bundle,
)
from asago_scenario_generator.stpa.scenario_prod.execution_projection import (
    validate_execution_projection,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
    run_sp3,
)
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_sp3_run import _make_cs, _make_ets, _make_loss_analysis
from tests.stpa.test_target_derived_structure import _observations, _profile

from .test_scenario_handoff_publication import (
    _adversarial_payload,
    _client,
    _normal_semantics_payload,
)

#: Filesystem entries a normal (handoff-publishing) run must never create.
_EXECUTION_ARTIFACTS = (
    "execution-bundle.json",
    ".generations",
    "scenarios/canonical",
)


def _tree_digest(root: Path) -> dict[str, str]:
    """Digest every file under ``root``, relative path to sha256."""
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _publish_handoff(payloads: list[dict], run_dir: Path, **kwargs: object):
    return run_sp3(
        llm_client=_client(payloads),
        enriched_threat_set=_make_ets(num_threats=len(payloads)),
        control_structure=_make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=run_dir,
        publish_execution_bundle=False,
        **kwargs,
    )


def test_run_cli_offers_no_mode_selection_input() -> None:
    """``run`` exposes no generation-mode selector."""
    import typer.main

    command = typer.main.get_command(app)
    run_command = command.commands["run"]  # type: ignore[index]
    names = {param.name for param in run_command.params}
    help_text = " ".join(
        (param.help or "") for param in run_command.params
    ).lower()
    for retired in names:
        assert "mode" not in retired, retired
    for retired in ("generation mode", "target-derived mode"):
        assert retired not in help_text, retired
    # The profile input is enrichment evidence, not an algorithm selector.
    assert "does not select a generation algorithm" in help_text


def test_normal_run_publishes_no_execution_artifacts_or_mode_sidecar(
    tmp_path: Path,
) -> None:
    _publish_handoff([_normal_semantics_payload()], tmp_path)

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
    result = _publish_handoff(
        [_normal_semantics_payload()],
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
    handoff = yaml.safe_load(
        (tmp_path / "scenarios" / "SCN-001.yaml").read_text()
    )
    assert handoff["narrative"].strip()
    assert (tmp_path / "execution-target-profile.json").is_file()
    assert not (tmp_path / "target-derived-structure.yaml").exists()


def test_historical_readers_validate_archived_artifacts_read_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retained readers validate a published bundle with zero writes and
    zero provider clients."""
    run_dir = tmp_path / "archived-run"
    run_dir.mkdir()
    run_sp3(
        llm_client=_client([_adversarial_payload()]),
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=_make_cs(),
        loss_analysis=_make_loss_analysis(),
        run_dir=run_dir,
    )
    bundle_path = run_dir / "execution-bundle.json"
    assert bundle_path.is_file(), "the historical seam must publish its bundle"

    def _no_provider(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the historical readers must not construct a provider")

    monkeypatch.setattr(
        "asago_scenario_generator.stpa.infra.llm.LLMClient.__init__", _no_provider
    )

    before = _tree_digest(run_dir)
    verification = verify_execution_bundle(run_dir)
    index = json.loads(bundle_path.read_text())
    projection_path = run_dir / index["entries"][0]["projection"]["path"]
    payload = yaml.safe_load(projection_path.read_text())
    validation = validate_execution_projection(payload)
    after = _tree_digest(run_dir)

    assert verification.valid
    assert validation.valid
    assert after == before, "validation must not write or modify any file"
