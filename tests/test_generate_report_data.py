"""The generate report reads the output directory through typed models."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from asago_scenario_generator.report.run_data import load_run
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.scenario_prod.handoff import ScenarioHandoffV4
from tests.helpers.generate_report_fixture import SCENARIOS, copy_run


def test_every_sidecar_loads_into_its_model(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))

    assert isinstance(run.loss, LossAnalysis)
    assert all(isinstance(s, ScenarioHandoffV4) for s in run.scenarios.values())
    assert sorted(run.scenarios) == SCENARIOS
    assert run.manifest.run_status == "completed"
    assert run.testability is not None and len(run.testability) == len(SCENARIOS)
    assert run.accounting is not None and run.structure is not None
    assert run.policy is not None and run.policy["schema_version"] == (
        "policy-coverage-v1"
    )


def test_calls_are_numbered_in_file_order(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))

    assert [c.n for c in run.calls] == list(range(1, len(run.calls) + 1))
    assert run.calls[0].attempt_number == 1


def test_a_feature_file_is_kept_beside_its_scenario(tmp_path: Path) -> None:
    run = load_run(copy_run(tmp_path))

    assert run.features["SCN-001"].startswith("Feature:")
    assert set(run.features) == set(SCENARIOS)


def test_an_absent_optional_sidecar_is_none_not_an_empty_value(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    for name in ("target-realization.yaml", "policy-coverage.json", "testability.yaml"):
        (output / name).unlink()

    run = load_run(output)

    assert run.realization is None
    assert run.policy is None
    assert run.testability is None


def test_a_run_without_a_manifest_cannot_be_reported(tmp_path: Path) -> None:
    output = copy_run(tmp_path)
    (output / "synthesis-manifest.yaml").unlink()

    with pytest.raises(FileNotFoundError):
        load_run(output)


def test_an_invalid_sidecar_fails_instead_of_rendering_a_guess(
    tmp_path: Path,
) -> None:
    output = copy_run(tmp_path)
    (output / "loss-analysis.yaml").write_text("risk_card_losses: not-a-list\n")

    with pytest.raises(ValidationError):
        load_run(output)
