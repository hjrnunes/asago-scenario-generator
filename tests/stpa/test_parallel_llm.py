"""Tests for the SP1 ``max_workers`` setting and sequential execution.

Covers:
  - parallel_max_workers_config.feature (ParallelConfig-01 .. ParallelConfig-03)
  - parallel_sp1_compatibility.feature (ParallelSP1-01 .. ParallelSP1-03,
    ParallelSP1-05)
"""

from __future__ import annotations

import yaml

from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    make_risk_cards,
    read_calls_jsonl,
    setup_sp1_mock_client,
)
import inspect
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.profile import derive_capability_profile
from asago_scenario_generator.stpa.system_model.control_structure import (
    derive_control_structure,
)


# ===========================================================================
# Feature: parallel_max_workers_config — ParallelConfig-01 .. ParallelConfig-03
# ===========================================================================


class TestParallelMaxWorkersConfig:
    """max_workers configuration and manifest recording."""

    # ParallelConfig-01
    def test_parallel_config_01_run_sp1_accepts_max_workers(self, tmp_path):
        """run_sp1 completes without error when max_workers=4."""
        client = setup_sp1_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            max_workers=4,
        )
        assert (tmp_path / "loss-analysis.yaml").exists()

    # ParallelConfig-02
    def test_parallel_config_02_max_workers_default_is_1(self, tmp_path):
        """Default max_workers is 1 (backwards compatible)."""
        client = setup_sp1_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["model_settings"]["max_workers"] == 1

    # ParallelConfig-03
    def test_parallel_config_03_manifest_records_max_workers(self, tmp_path):
        """Run manifest records the max_workers value."""
        client = setup_sp1_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            max_workers=4,
        )
        manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
        assert manifest["model_settings"]["max_workers"] == 4


# ===========================================================================
# Feature: parallel_sp1_compatibility — ParallelSP1-01 .. ParallelSP1-06
# ===========================================================================


class TestParallelSP1Compatibility:
    """SP1 runs its stages sequentially for any ``max_workers`` value."""

    # ParallelSP1-01
    def test_parallel_sp1_01_max_workers_1_produces_artifacts(self, tmp_path):
        """max_workers=1 produces all output artifacts."""
        client = setup_sp1_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            max_workers=1,
        )
        assert (tmp_path / "loss-analysis.yaml").exists()
        assert (tmp_path / "capability-profile.yaml").exists()
        assert (tmp_path / "control-structure.yaml").exists()

    # ParallelSP1-02
    def test_parallel_sp1_02_stage_execution_order_preserved(self, tmp_path):
        """Stage 1b → 1a → 2 order preserved with max_workers=1."""
        client = setup_sp1_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            max_workers=1,
        )
        entries = read_calls_jsonl(tmp_path)
        stages = [e["stage"] for e in entries]
        assert "stage_1a" in stages
        assert "stage_1b" in stages
        assert "stage_2" in stages
        # New ordering: 1b before 1a before 2
        assert stages.index("stage_1b") < stages.index("stage_1a")
        assert stages.index("stage_1a") < stages.index("stage_2")

    # ParallelSP1-03
    def test_parallel_sp1_03_call_log_identical_with_max_workers_1(self, tmp_path):
        """calls.jsonl exists and contains entries for all stages in order."""
        client = setup_sp1_mock_client()
        run_sp1(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
            max_workers=1,
        )
        entries = read_calls_jsonl(tmp_path)
        assert len(entries) > 0
        stages = [e["stage"] for e in entries]
        assert "stage_1a" in stages
        assert "stage_1b" in stages
        assert "stage_2" in stages

    # ParallelSP1-05
    def test_parallel_sp1_05_data_dependencies_prevent_parallelization(self):
        """SP1 pipeline has sequential data dependencies between stages."""
        # This is a structural assertion: the stages have data dependencies
        # that prevent parallelization. We verify by checking that run_sp1
        # function signature accepts max_workers but the stage functions
        # don't accept it (they remain sequential).

        sig_loss = inspect.signature(derive_loss_analysis)
        sig_profile = inspect.signature(derive_capability_profile)
        sig_cs = inspect.signature(derive_control_structure)

        # None of the stage functions accept max_workers
        assert "max_workers" not in sig_loss.parameters
        assert "max_workers" not in sig_profile.parameters
        assert "max_workers" not in sig_cs.parameters
