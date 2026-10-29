"""A synthesis run writes the report-only specification diagnostics."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    run_synthesis,
)
from asago_scenario_generator.pipeline.synthesis_persist import (
    _persist_spec_diagnostics,
)
from asago_scenario_generator.stpa import spec_diagnostics
from asago_scenario_generator.stpa.spec_diagnostics import (
    ICA_CHECKS,
    SPEC_DIAGNOSTICS_FILENAME,
    read_spec_diagnostics,
)
from tests.stpa.helpers import (
    make_ica_slot,
    make_minimal_control_structure,
    make_minimal_loss_analysis,
)
from tests.test_synthesis import _FakeAdapters, _inputs


def test_a_run_publishes_the_diagnostics_of_its_final_artifacts(tmp_path: Path):
    result = run_synthesis(
        _inputs(tmp_path), SynthesisAdapters.from_object(_FakeAdapters(calls=[]))
    )

    path = result.artifact_paths[SPEC_DIAGNOSTICS_FILENAME]
    assert path == Path(result.inputs.output_dir) / SPEC_DIAGNOSTICS_FILENAME
    diagnostics = read_spec_diagnostics(path)
    assert all(summary.status == "run" for summary in diagnostics.checks)
    assert all(finding.disposition is None for finding in diagnostics.findings)
    assert not any("spec diagnostics" in w for w in result.stage_warnings)


def test_a_failing_check_never_stops_the_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    def fail(**_: object) -> None:
        raise RuntimeError("index broke")

    monkeypatch.setattr(spec_diagnostics, "diagnose_final_artifacts", fail)

    result = run_synthesis(
        _inputs(tmp_path), SynthesisAdapters.from_object(_FakeAdapters(calls=[]))
    )

    assert SPEC_DIAGNOSTICS_FILENAME not in result.artifact_paths
    assert not (Path(result.inputs.output_dir) / SPEC_DIAGNOSTICS_FILENAME).exists()
    assert "spec diagnostics: not written: index broke" in result.stage_warnings
    assert result.manifest["stage_warnings"] == result.stage_warnings


def test_a_stopped_fill_records_the_ica_checks_as_not_run(tmp_path: Path):
    stage = SimpleNamespace(
        fill_failure=object(),
        ica_enumeration=SimpleNamespace(slots=[make_ica_slot()]),
    )
    warnings: list[str] = []

    path = _persist_spec_diagnostics(
        tmp_path,
        loss_analysis=make_minimal_loss_analysis(),
        control_structure=make_minimal_control_structure(),
        ica_stage=stage,
        warnings=warnings,
    )

    assert path is not None and warnings == []
    not_run = {
        s.check: s.reason
        for s in read_spec_diagnostics(path).checks
        if s.status == "not_run"
    }
    assert not_run == dict.fromkeys(
        ICA_CHECKS, "the ICA fill stopped before it finished"
    )
