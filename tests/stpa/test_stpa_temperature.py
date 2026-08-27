"""STPA pipeline temperature wiring tests (issue #11).

Verifies that the resolved model profile temperature (or an explicit
``--temperature`` override) reaches every stage call instead of the
per-module 0.4 default that previously made ``config/model-profiles.yaml``
"temperature" dead config on the STPA path.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from asago_scenario_generator.stpa.pipeline.runner import (
    _run_sp1_stage,
    _run_sp2_stage,
    _run_sp3_stage,
    run_stpa_pipeline,
)


def _make_client(temperature: float) -> MagicMock:
    """Build a fake LLM client exposing the resolved profile temperature."""
    client = MagicMock()
    client.temperature = temperature
    client.model = "mock-model"
    client.base_url = "http://mock:8080"
    return client


def _write_use_case(tmp: Path) -> Path:
    path = tmp / "use-case.txt"
    path.write_text("My agentic system use case", encoding="utf-8")
    return path


def _write_risk_extraction(tmp: Path) -> Path:
    path = tmp / "risk-extraction.json"
    payload = {
        "risks": [
            {
                "risk_id": "atlas-001",
                "risk_name": "Risk 1",
                "risk_description": "Description 1",
                "taxonomy": "ibm-risk-atlas",
                "confidence": 0.9,
                "grounding_confidence": "high",
            }
        ]
    }
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


class TestStageTemperatureWiring:
    """Each stage entry uses client.temperature unless overridden."""

    def _patch_sp1(self, client):
        return {
            "resolve": patch(
                "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
                return_value=(client, "mock-profile"),
            ),
            "read": patch(
                "asago_scenario_generator.stpa.pipeline.runner.read_use_case",
                return_value="my agentic system use case",
            ),
            "load": patch(
                "asago_scenario_generator.stpa.pipeline.runner.load_risk_extraction",
                return_value=[],
            ),
            "sp1": patch(
                "asago_scenario_generator.stpa.pipeline.runner.run_sp1",
                return_value=MagicMock(stage_errors=[]),
            ),
        }

    def test_sp1_uses_client_temperature(self, tmp_path):
        client = _make_client(1.0)
        patched = self._patch_sp1(client)
        with patched["resolve"], patched["read"], patched["load"], patched["sp1"] as sp1:
            _run_sp1_stage(
                skip=False,
                use_case_path="uc",
                risk_extraction_path="risk",
                output_dir=tmp_path,
                profile=None,
                sp1_profile=None,
                profiles_file="config/model-profiles.yaml",
                capability_profile_path=None,
                max_workers=1,
                stage_errors=[],
            )
        assert sp1.call_args.kwargs["temperature"] == 1.0

    def test_sp1_explicit_temperature_overrides_client(self, tmp_path):
        client = _make_client(1.0)
        patched = self._patch_sp1(client)
        with patched["resolve"], patched["read"], patched["load"], patched["sp1"] as sp1:
            _run_sp1_stage(
                skip=False,
                use_case_path="uc",
                risk_extraction_path="risk",
                output_dir=tmp_path,
                profile=None,
                sp1_profile=None,
                profiles_file="config/model-profiles.yaml",
                capability_profile_path=None,
                max_workers=1,
                stage_errors=[],
                temperature=0.7,
            )
        assert sp1.call_args.kwargs["temperature"] == 0.7

    def test_sp1_default_not_reapplied(self, tmp_path):
        """Without a profile the client's 0.4 default still reaches the stage."""
        client = _make_client(0.4)
        patched = self._patch_sp1(client)
        with patched["resolve"], patched["read"], patched["load"], patched["sp1"] as sp1:
            _run_sp1_stage(
                skip=False,
                use_case_path="uc",
                risk_extraction_path="risk",
                output_dir=tmp_path,
                profile=None,
                sp1_profile=None,
                profiles_file="config/model-profiles.yaml",
                capability_profile_path=None,
                max_workers=1,
                stage_errors=[],
            )
        assert sp1.call_args.kwargs["temperature"] == 0.4

    def test_sp2_uses_client_temperature(self, tmp_path):
        client = _make_client(1.0)
        with patch(
            "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
            return_value=(client, "mock-profile"),
        ), patch(
            "asago_scenario_generator.stpa.pipeline.runner.run_sp2",
            return_value=MagicMock(stage_errors=[]),
        ) as sp2:
            _run_sp2_stage(
                skip=False,
                output_dir=tmp_path,
                control_structure=MagicMock(),
                capability_profile=MagicMock(),
                loss_analysis=MagicMock(),
                profile=None,
                sp2_profile=None,
                profiles_file="config/model-profiles.yaml",
                max_workers=1,
                stage_errors=[],
            )
        assert sp2.call_args.kwargs["temperature"] == 1.0

    def test_sp3_uses_client_temperature(self, tmp_path):
        client = _make_client(1.0)
        with patch(
            "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
            return_value=(client, "mock-profile"),
        ), patch(
            "asago_scenario_generator.stpa.pipeline.runner.run_sp3",
            return_value=MagicMock(stage_errors=[]),
        ) as sp3:
            _run_sp3_stage(
                skip=False,
                output_dir=tmp_path,
                enriched_threat_set=MagicMock(),
                control_structure=MagicMock(),
                loss_analysis=MagicMock(),
                profile=None,
                sp3_profile=None,
                profiles_file="config/model-profiles.yaml",
                capability_profile_path=None,
                max_workers=1,
                stage_errors=[],
            )
        assert sp3.call_args.kwargs["temperature"] == 1.0


class TestPipelineTemperature:
    """run_stpa_pipeline forwards the resolved temperature end to end."""

    def _run(self, tmp_path: Path, temperature: float | None, client_temp: float):
        uc = _write_use_case(tmp_path)
        risk = _write_risk_extraction(tmp_path)
        client = _make_client(client_temp)
        kwargs = {
            "use_case_path": str(uc),
            "risk_extraction_path": str(risk),
            "output_dir": tmp_path / "output",
        }
        if temperature is not None:
            kwargs["temperature"] = temperature
        with patch(
            "asago_scenario_generator.stpa.pipeline.runner.resolve_llm_client",
            return_value=(client, "mock-profile"),
        ), patch(
            "asago_scenario_generator.stpa.pipeline.runner.run_sp1",
            return_value=MagicMock(stage_errors=[]),
        ) as sp1, patch(
            "asago_scenario_generator.stpa.pipeline.runner.run_sp2",
            return_value=MagicMock(stage_errors=[]),
        ), patch(
            "asago_scenario_generator.stpa.pipeline.runner.run_sp3",
            return_value=MagicMock(stage_errors=[]),
        ):
            run_stpa_pipeline(**kwargs)
        return sp1

    def test_profile_temperature_flows_to_sp1(self, tmp_path):
        sp1 = self._run(tmp_path, temperature=None, client_temp=1.0)
        assert sp1.call_args.kwargs["temperature"] == 1.0

    def test_explicit_temperature_flows_to_sp1(self, tmp_path):
        sp1 = self._run(tmp_path, temperature=0.7, client_temp=1.0)
        assert sp1.call_args.kwargs["temperature"] == 0.7

    def test_default_temperature_flows_to_sp1(self, tmp_path):
        sp1 = self._run(tmp_path, temperature=None, client_temp=0.4)
        assert sp1.call_args.kwargs["temperature"] == 0.4
