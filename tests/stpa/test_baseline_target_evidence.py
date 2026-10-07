"""The production baseline adapter passes the observed target to SP1."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.pipeline import synthesis
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.pipeline import llm_config
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.system_model import run as sp1_run

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "miniocciai-baseline-rev2"


def test_baseline_builds_evidence_from_the_observed_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}

    def fake_run_sp1(**kwargs: Any) -> str:
        captured.update(kwargs)
        return "sp1-result"

    monkeypatch.setattr(sp1_run, "run_sp1", fake_run_sp1)
    monkeypatch.setattr(
        llm_config, "resolve_llm_client", lambda *args: (object(), "test-profile")
    )
    inputs = synthesis.SynthesisInputs(
        use_case="A clinic assistant answers patient questions.",
        output_dir=tmp_path,
        execution_target_profile=ExecutionTargetProfile.model_validate(
            json.loads((FIXTURES / "execution-target-profile.json").read_text())
        ),
        target_observations=TargetObservationSnapshot.model_validate(
            yaml.safe_load((FIXTURES / "target-observations.yaml").read_text())
        ),
    )
    adapters = synthesis.SynthesisAdapters(baseline=synthesis._default_baseline)

    run = synthesis._run_baseline(inputs, None, None, None, None, adapters)

    assert run.value == "sp1-result"
    assert run.calls == ("baseline",)
    evidence = captured["target_evidence"]
    assert evidence is not None
    assert "get_referral" in evidence.operation_names
