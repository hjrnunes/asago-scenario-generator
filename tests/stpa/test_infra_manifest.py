"""Tests for STPA infra run manifest (InfraManifest-01 through InfraManifest-05)."""

from __future__ import annotations

import importlib

import yaml

from asago_scenario_generator.stpa.infra.manifest import STPARunManifest
from asago_scenario_generator.stpa.system_model.run import SP1RunResult


class TestInfraManifest:
    """Simplified STPA run manifest."""

    def _base_manifest_data(self) -> dict:
        return {
            "run_id": "RUN-001",
            "run_dir": "output/test",
            "created_at": "2026-08-08T12:00:00Z",
            "model_config": {"model": "test-model", "temperature": 0.4},
            "input_hashes": {"use_case": "abc123"},
            "prompt_hashes": {"call0_system.j2": "def456"},
            "stage_summary": {"stage_1": {"calls": 1, "duration_ms": 5000}},
        }

    def test_manifest_01_valid_manifest_passes(self):
        """InfraManifest-01: valid run manifest passes validation."""
        manifest = STPARunManifest(**self._base_manifest_data())
        assert manifest.run_id == "RUN-001"
        assert manifest.run_dir == "output/test"

    def test_manifest_01a_defaults_are_zero(self):
        """InfraManifest-01a: optional numeric fields default to zero."""
        manifest = STPARunManifest(**self._base_manifest_data())
        assert manifest.slot_count == 0
        assert manifest.na_count == 0
        assert manifest.fill_rate == 0.0
        assert manifest.scenario_count == 0
        assert manifest.critic_findings == []
        assert manifest.revised is False
        assert manifest.post_revision_warnings == []
        assert manifest.stage_errors == []
        assert manifest.stage_warnings == []
        assert manifest.eval_scorecard_path is None

    def test_manifest_02_with_fill_rate_and_counts(self):
        """InfraManifest-02: manifest with fill_rate and counts passes."""
        data = self._base_manifest_data()
        data["slot_count"] = 10
        data["na_count"] = 2
        data["fill_rate"] = 0.8
        data["scenario_count"] = 5
        manifest = STPARunManifest(**data)
        assert manifest.slot_count == 10
        assert manifest.na_count == 2
        assert manifest.fill_rate == 0.8
        assert manifest.scenario_count == 5

    def test_manifest_03_with_critic_findings(self):
        """InfraManifest-03: manifest with critic findings passes."""
        data = self._base_manifest_data()
        data["critic_findings"] = [
            "gap in hazard coverage",
            "missing constraint for H-2",
        ]
        manifest = STPARunManifest(**data)
        assert len(manifest.critic_findings) == 2

    def test_manifest_04_with_eval_scorecard_path(self):
        """InfraManifest-04: manifest with eval scorecard path passes."""
        data = self._base_manifest_data()
        data["eval_scorecard_path"] = "output/test/eval-scorecard.yaml"
        manifest = STPARunManifest(**data)
        assert manifest.eval_scorecard_path == "output/test/eval-scorecard.yaml"

    def test_manifest_records_revision_outcome(self):
        """Revision attempts and warnings are durable operator diagnostics."""
        data = self._base_manifest_data()
        data["revised"] = True
        data["post_revision_warnings"] = [
            "Revision delta merge degraded: missing-state"
        ]
        manifest = STPARunManifest(**data)
        assert manifest.revised is True
        assert manifest.post_revision_warnings == [
            "Revision delta merge degraded: missing-state"
        ]

    def test_manifest_05_not_coupled_to_existing_manifest(self):
        """InfraManifest-05: module does not import the existing pipeline manifest."""
        # Reload the module and check its loaded modules
        mod = importlib.import_module("asago_scenario_generator.stpa.infra.manifest")
        mod_source = open(mod.__file__).read()
        assert "asago_scenario_generator.manifest" not in mod_source
        assert "from asago_scenario_generator.manifest" not in mod_source
        assert "import asago_scenario_generator.manifest" not in mod_source

    def test_combined_manifest_preserves_fatal_and_recoverable_diagnostics(
        self, tmp_path
    ):
        """Later stage manifest writes cannot erase SP1 repair diagnostics."""
        from asago_scenario_generator.stpa.pipeline.runner import (
            _persist_pipeline_diagnostics,
        )

        manifest_path = tmp_path / "run-manifest.yaml"
        manifest_path.write_text(
            yaml.safe_dump({"run_id": "later-stage", "stage_errors": []}),
            encoding="utf-8",
        )
        sp1_result = SP1RunResult(
            revised=True,
            post_revision_warnings=["revision retained original"],
            stage_warnings=["normalized CP-5"],
        )

        _persist_pipeline_diagnostics(
            tmp_path,
            sp1_result=sp1_result,
            stage_errors=["SP3 did not produce required scenarios"],
            stage_warnings=["normalized CP-5"],
        )

        persisted = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
        assert persisted["stage_errors"] == ["SP3 did not produce required scenarios"]
        assert persisted["stage_warnings"] == ["normalized CP-5"]
        assert persisted["revised"] is True
        assert persisted["post_revision_warnings"] == ["revision retained original"]
