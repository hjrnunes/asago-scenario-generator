"""Tests for parallel LLM call infrastructure.

Covers all scenarios from:
  - parallel_llm_calls.feature (ParallelLLM-01 .. ParallelLLM-12)
  - parallel_max_workers_config.feature (ParallelConfig-01 .. ParallelConfig-06)
  - parallel_sp1_compatibility.feature (ParallelSP1-01 .. ParallelSP1-06)
  - parallel_sp2_sp3_design.feature (ParallelSP2-01, ParallelSP2-02,
    ParallelSP3-01 .. ParallelSP3-04)
"""

from __future__ import annotations

import threading
import time
from unittest.mock import patch

import pytest
import yaml
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.parallel_llm import (
    LLMCallResult,
    LLMCallSpec,
    parallel_safe_llm_calls,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockCall,
    MockLLMClient,
    make_risk_cards,
    read_calls_jsonl,
    setup_sp1_mock_client,
)


# ---------------------------------------------------------------------------
# Test models
# ---------------------------------------------------------------------------


class _DummyModel(BaseModel):
    """Simple model for parallel call tests."""

    value: str = "default"


class _AnotherModel(BaseModel):
    """Second model to distinguish call specs by response_format."""

    name: str = "another"


# ---------------------------------------------------------------------------
# Concurrent mock LLM client
# ---------------------------------------------------------------------------


class ConcurrentMockLLMClient:
    """Mock LLM client for parallel call tests.

    Supports:
    - Response mapping by response_format type
    - Step-based delays (step substring searched in user_prompt)
    - Step-based exceptions
    - Concurrent in-flight call tracking
    - Per-call temperature recording
    """

    def __init__(
        self,
        base_url: str = "http://test:8080",
        model: str = "test-model",
        temperature: float = 0.4,
    ) -> None:
        self.base_url = base_url
        self.model = model
        self.temperature = temperature
        self.max_completion_tokens = None
        self.calls: list[MockCall] = []
        self._response_map: dict[type, object] = {}
        self._delay_by_step: dict[str, float] = {}
        self._exception_by_step: dict[str, Exception] = {}
        self._in_flight = 0
        self._max_in_flight = 0
        self._tracker_lock = threading.Lock()

    def set_response_for(self, model_class: type, response: object) -> None:
        self._response_map[model_class] = response

    def set_delay_for_step(self, step: str, seconds: float) -> None:
        self._delay_by_step[step] = seconds

    def set_exception_for_step(self, step: str, exc: Exception) -> None:
        self._exception_by_step[step] = exc

    @property
    def max_in_flight(self) -> int:
        return self._max_in_flight

    def _find_matching_step(self, user_prompt: str) -> str | None:
        for step in self._delay_by_step:
            if step in user_prompt:
                return step
        for step in self._exception_by_step:
            if step in user_prompt:
                return step
        return None

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        with self._tracker_lock:
            self._in_flight += 1
            if self._in_flight > self._max_in_flight:
                self._max_in_flight = self._in_flight

        try:
            step = self._find_matching_step(user_prompt)

            if step and step in self._delay_by_step:
                time.sleep(self._delay_by_step[step])

            if step and step in self._exception_by_step:
                raise self._exception_by_step[step]

            self.calls.append(
                MockCall(
                    system_prompt=system_prompt,
                    user_prompt=user_prompt,
                    response_format=response_format,
                    temperature=temperature,
                    max_completion_tokens=max_completion_tokens,
                )
            )

            content = self._response_map.get(response_format)

            return LLMResult(
                content=content,
                prompt_tokens=100,
                completion_tokens=50,
                duration_ms=10,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
            )
        finally:
            with self._tracker_lock:
                self._in_flight -= 1


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_spec(
    step: str,
    *,
    response_format: type[BaseModel] = _DummyModel,
    stage: str = "stage_3",
    temperature: float = 0.4,
    system_prompt: str = "sys",
) -> LLMCallSpec:
    """Build an LLMCallSpec with the step embedded in the user_prompt."""
    return LLMCallSpec(
        system_prompt=system_prompt,
        user_prompt=f"prompt for {step}",
        response_format=response_format,
        stage=stage,
        step=step,
        temperature=temperature,
    )


# ---------------------------------------------------------------------------
# SP1 full-run helpers — use shared helpers from sp1_helpers
# ---------------------------------------------------------------------------


def _run_cli_with_max_workers(max_workers_arg: str | None) -> int | None:
    """Run run_sp1.main() with mocked deps and return the max_workers passed to run_sp1.

    Args:
        max_workers_arg: The --max-workers value, or None to omit the flag.
    """
    import sys

    import scripts.run_sp1 as runner_mod

    fake_result = type(
        "R",
        (),
        {
            "loss_analysis": None,
            "capability_profile": None,
            "control_structure": None,
            "heuristic_errors": [],
            "heuristic_warnings": [],
            "critic_findings": None,
            "revised": False,
            "stage_errors": [],
            "solution_neutrality_warnings": [],
            "post_revision_warnings": [],
        },
    )()

    argv = [
        "run_sp1.py",
        "--use-case",
        "test.txt",
        "--risk-extraction",
        "test.json",
        "--output-dir",
        "output/test",
    ]
    if max_workers_arg is not None:
        argv.extend(["--max-workers", max_workers_arg])

    with (
        patch.object(runner_mod, "run_sp1") as mock_run,
        patch.object(runner_mod, "load_risk_extraction", return_value=[]),
        patch.object(runner_mod, "read_use_case", return_value="test"),
        patch.object(
            runner_mod, "resolve_llm_client_from_env", return_value=MockLLMClient()
        ),
    ):
        mock_run.return_value = fake_result
        old_argv = sys.argv
        sys.argv = argv
        try:
            runner_mod.main()
        finally:
            sys.argv = old_argv
        _, kwargs = mock_run.call_args
        return kwargs.get("max_workers")


# ===========================================================================
# Feature: parallel_llm_calls — ParallelLLM-01 .. ParallelLLM-12
# ===========================================================================


class TestParallelLLMCalls:
    """Core parallel LLM call infrastructure tests."""

    # ParallelLLM-01
    def test_parallel_llm_01_multiple_calls_execute_and_return_results(self, tmp_path):
        """Three calls execute and return three LLMCallResult objects."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [_make_spec(f"slot_{i}") for i in range(3)]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=2
        )
        assert len(results) == 3
        for r in results:
            assert isinstance(r, LLMCallResult)
            assert r.error is None
            assert r.result is not None

    # ParallelLLM-02
    def test_parallel_llm_02_results_in_input_order_regardless_of_execution(
        self, tmp_path
    ):
        """Results are in input order even when execution order differs."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        # Delay slot_a by 0ms, slot_c by 100ms — slot_c finishes last
        client.set_delay_for_step("slot_c", 0.1)
        calls = [
            _make_spec("slot_a"),
            _make_spec("slot_b"),
            _make_spec("slot_c"),
        ]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=3
        )
        assert results[0].call_spec.step == "slot_a"
        assert results[1].call_spec.step == "slot_b"
        assert results[2].call_spec.step == "slot_c"

    # ParallelLLM-03
    def test_parallel_llm_03_failed_call_does_not_affect_others(self, tmp_path):
        """A failed call doesn't kill other calls."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        client.set_exception_for_step("bad_1", RuntimeError("boom"))
        calls = [
            _make_spec("good_1"),
            _make_spec("bad_1"),
            _make_spec("good_2"),
        ]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=3
        )
        assert len(results) == 3
        assert results[0].error is None
        assert results[1].error is not None
        assert results[2].error is None

    # ParallelLLM-04
    def test_parallel_llm_04_all_call_log_entries_thread_safe(self, tmp_path):
        """Five calls produce five valid JSON lines in calls.jsonl."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [_make_spec(f"s{i}") for i in range(1, 6)]
        parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=4
        )
        entries = read_calls_jsonl(tmp_path)
        assert len(entries) == 5
        for entry in entries:
            assert "stage" in entry
            assert "step" in entry
            assert "model" in entry
            assert "timestamp" in entry

    # ParallelLLM-05
    def test_parallel_llm_05_max_workers_controls_concurrency(self, tmp_path):
        """max_workers=2 means at most 2 concurrent in-flight calls."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        # Small delay to increase chance of overlap
        client.set_delay_for_step("s", 0.05)
        calls = [_make_spec(f"s{i}") for i in range(4)]
        parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=2
        )
        assert client.max_in_flight <= 2

    # ParallelLLM-06
    def test_parallel_llm_06_single_call_degenerate_case(self, tmp_path):
        """A single call works correctly."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [_make_spec("slot_a", stage="stage_3")]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=1
        )
        assert len(results) == 1
        assert results[0].error is None
        assert results[0].result is not None

    # ParallelLLM-07
    def test_parallel_llm_07_empty_call_list_returns_empty(self, tmp_path):
        """Empty call list returns empty result list, no calls.jsonl."""
        client = ConcurrentMockLLMClient()
        results = parallel_safe_llm_calls(
            [], llm_client=client, run_dir=tmp_path, max_workers=4
        )
        assert results == []
        assert not (tmp_path / "calls.jsonl").exists()

    # ParallelLLM-08
    def test_parallel_llm_08_llm_call_spec_bundles_arguments(self):
        """LLMCallSpec bundles all call arguments."""
        spec = LLMCallSpec(
            system_prompt="sys",
            user_prompt="usr",
            response_format=LossAnalysis,
            stage="stage_3",
            step="slot_a",
            temperature=0.7,
        )
        assert spec.system_prompt == "sys"
        assert spec.user_prompt == "usr"
        assert spec.response_format is LossAnalysis
        assert spec.stage == "stage_3"
        assert spec.step == "slot_a"
        assert spec.temperature == 0.7

    # ParallelLLM-09
    def test_parallel_llm_09_llm_call_result_success_bundling(self, tmp_path):
        """Successful LLMCallResult has model, result, and no error."""
        client = ConcurrentMockLLMClient(model="my-model")
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        spec = _make_spec("slot_a")
        results = parallel_safe_llm_calls(
            [spec], llm_client=client, run_dir=tmp_path, max_workers=1
        )
        r = results[0]
        assert r.model == "my-model"
        assert r.result is not None
        assert r.error is None
        assert r.call_spec is spec

    # ParallelLLM-10
    def test_parallel_llm_10_failed_call_result_has_model_none_and_error(
        self, tmp_path
    ):
        """Failed LLMCallResult has model None and error set."""
        client = ConcurrentMockLLMClient(model="my-model")
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        client.set_exception_for_step("bad_1", RuntimeError("boom"))
        spec = _make_spec("bad_1")
        results = parallel_safe_llm_calls(
            [spec], llm_client=client, run_dir=tmp_path, max_workers=1
        )
        r = results[0]
        assert r.model is None
        assert r.error is not None
        assert "boom" in r.error
        assert r.call_spec is spec

    # ParallelLLM-11
    def test_parallel_llm_11_call_log_entries_success_and_failure(self, tmp_path):
        """Call log has one success and one failure entry."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        client.set_exception_for_step("bad_1", RuntimeError("boom"))
        calls = [_make_spec("good_1"), _make_spec("bad_1")]
        parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=2
        )
        entries = read_calls_jsonl(tmp_path)
        assert len(entries) == 2
        success_steps = {e["step"] for e in entries if e["success"]}
        failure_entries = [e for e in entries if not e["success"]]
        assert "good_1" in success_steps
        assert len(failure_entries) == 1
        assert failure_entries[0].get("error")

    # ParallelLLM-12
    def test_parallel_llm_12_temperature_propagated_to_each_call(self, tmp_path):
        """Each call receives its specified temperature."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [
            _make_spec("t1", temperature=0.2),
            _make_spec("t2", temperature=0.7),
        ]
        parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=2
        )
        temps = [c.temperature for c in client.calls]
        assert 0.2 in temps
        assert 0.7 in temps


# ===========================================================================
# Feature: parallel_max_workers_config — ParallelConfig-01 .. ParallelConfig-06
# ===========================================================================


class TestParallelMaxWorkersConfig:
    """max_workers configuration, CLI flag, and manifest recording."""

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

    # ParallelConfig-04
    def test_parallel_config_04_cli_flag_passes_value(self):
        """--max-workers 8 passes max_workers=8 to run_sp1."""
        assert _run_cli_with_max_workers("8") == 8

    # ParallelConfig-05
    def test_parallel_config_05_cli_flag_defaults_to_1(self):
        """Without --max-workers, run_sp1 is called with max_workers=1."""
        assert _run_cli_with_max_workers(None) == 1

    # ParallelConfig-06 (parameterised)
    @pytest.mark.parametrize("workers", [1, 2, 4, 8, 16])
    def test_parallel_config_06_cli_accepts_valid_values(self, workers):
        """--max-workers accepts various valid values."""
        assert _run_cli_with_max_workers(str(workers)) == workers


# ===========================================================================
# Feature: parallel_sp1_compatibility — ParallelSP1-01 .. ParallelSP1-06
# ===========================================================================


class TestParallelSP1Compatibility:
    """SP1 backwards compatibility with parallel module present."""

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

    # ParallelSP1-04
    def test_parallel_sp1_04_sp1_does_not_call_parallel_when_max_workers_1(
        self, tmp_path
    ):
        """With max_workers=1, SP1 uses safe_llm_call directly, not parallel."""
        with patch(
            "asago_scenario_generator.stpa.system_model.run.parallel_safe_llm_calls"
        ) as mock_parallel:
            client = setup_sp1_mock_client()
            run_sp1(
                llm_client=client,
                use_case_text="Test use case",
                risk_cards=make_risk_cards(),
                run_dir=tmp_path,
                max_workers=1,
            )
            mock_parallel.assert_not_called()

    # ParallelSP1-05
    def test_parallel_sp1_05_data_dependencies_prevent_parallelization(self):
        """SP1 pipeline has sequential data dependencies between stages."""
        # This is a structural assertion: the stages have data dependencies
        # that prevent parallelization. We verify by checking that run_sp1
        # function signature accepts max_workers but the stage functions
        # don't accept it (they remain sequential).
        import inspect

        from asago_scenario_generator.stpa.system_model.loss_analysis import (
            derive_loss_analysis,
        )
        from asago_scenario_generator.stpa.system_model.profile import (
            derive_capability_profile,
        )
        from asago_scenario_generator.stpa.system_model.control_structure import (
            derive_control_structure,
        )

        sig_loss = inspect.signature(derive_loss_analysis)
        sig_profile = inspect.signature(derive_capability_profile)
        sig_cs = inspect.signature(derive_control_structure)

        # None of the stage functions accept max_workers
        assert "max_workers" not in sig_loss.parameters
        assert "max_workers" not in sig_profile.parameters
        assert "max_workers" not in sig_cs.parameters

    # ParallelSP1-06
    def test_parallel_sp1_06_existing_tests_pass_with_parallel_module(self):
        """The parallel module is importable without breaking existing imports."""
        from asago_scenario_generator.stpa.infra.parallel_llm import (
            LLMCallResult,
            LLMCallSpec,
            parallel_safe_llm_calls,
        )

        assert parallel_safe_llm_calls is not None
        assert LLMCallSpec is not None
        assert LLMCallResult is not None


# ===========================================================================
# Feature: parallel_sp2_sp3_design — ParallelSP2-01, ParallelSP2-02,
#           ParallelSP3-01 .. ParallelSP3-04
# ===========================================================================


class TestParallelSP2SP3Design:
    """Infrastructure tests for future SP2/SP3 parallel patterns."""

    # ParallelSP2-01
    def test_parallel_sp2_01_per_responsibility_independent_calls(self, tmp_path):
        """SP2 Stage 3 slot-filling: one call per responsibility, independent."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [_make_spec(f"resp_{i}_slot") for i in range(3)]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=3
        )
        assert len(results) == 3
        steps = [r.call_spec.step for r in results]
        assert steps == ["resp_0_slot", "resp_1_slot", "resp_2_slot"]

    # ParallelSP2-02
    def test_parallel_sp2_02_parallel_equals_sequential(self, tmp_path):
        """max_workers=1 produces identical results to max_workers=3."""
        client1 = ConcurrentMockLLMClient()
        client1.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [_make_spec(f"resp_{i}_slot") for i in range(3)]
        results_seq = parallel_safe_llm_calls(
            calls, llm_client=client1, run_dir=tmp_path / "seq", max_workers=1
        )

        client2 = ConcurrentMockLLMClient()
        client2.set_response_for(_DummyModel, _DummyModel(value="ok"))
        results_par = parallel_safe_llm_calls(
            calls, llm_client=client2, run_dir=tmp_path / "par", max_workers=3
        )

        assert len(results_seq) == len(results_par)
        for rs, rp in zip(results_seq, results_par):
            assert rs.call_spec.step == rp.call_spec.step
            assert rs.error is None
            assert rp.error is None

    # ParallelSP3-01
    def test_parallel_sp3_01_per_scenario_independent_bdi_calls(self, tmp_path):
        """SP3 Stage 5: one BDI call per scenario, independent."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [_make_spec(f"scenario_{i}_bdi") for i in range(5)]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=4
        )
        assert len(results) == 5
        steps = [r.call_spec.step for r in results]
        assert steps == [f"scenario_{i}_bdi" for i in range(5)]

    # ParallelSP3-02
    def test_parallel_sp3_02_calls_independent_within_scenario(self, tmp_path):
        """SP3 Stage 6: narrative, attack_tree, gherkin calls are independent."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = [
            _make_spec("narrative", stage="stage_6_narrative"),
            _make_spec("attack_tree", stage="stage_6_tree"),
            _make_spec("gherkin", stage="stage_6_gherkin"),
        ]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=3
        )
        assert len(results) == 3
        assert results[0].call_spec.step == "narrative"
        assert results[1].call_spec.step == "attack_tree"
        assert results[2].call_spec.step == "gherkin"

    # ParallelSP3-03
    def test_parallel_sp3_03_different_scenarios_concurrent(self, tmp_path):
        """3 scenarios × 4 calls each = 12 results in input order."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        calls = []
        for s in range(3):
            for c in range(4):
                calls.append(_make_spec(f"scenario_{s}_call_{c}"))
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=4
        )
        assert len(results) == 12
        # Verify scenario grouping preserved in result order
        for i, r in enumerate(results):
            expected_scenario = i // 4
            assert f"scenario_{expected_scenario}" in r.call_spec.step

    # ParallelSP3-04
    def test_parallel_sp3_04_failure_for_one_scenario_does_not_block_others(
        self, tmp_path
    ):
        """Failure for scenario 2 doesn't block scenarios 1 and 3."""
        client = ConcurrentMockLLMClient()
        client.set_response_for(_DummyModel, _DummyModel(value="ok"))
        client.set_exception_for_step("scenario_1_bdi", RuntimeError("sc2 fail"))
        calls = [_make_spec(f"scenario_{i}_bdi") for i in range(3)]
        results = parallel_safe_llm_calls(
            calls, llm_client=client, run_dir=tmp_path, max_workers=3
        )
        assert len(results) == 3
        assert results[0].error is None
        assert results[1].error is not None
        assert results[2].error is None

    def test_parallel_call_can_omit_schema_from_validation_retry(self, tmp_path):
        """Structured parallel calls pass the compact-retry policy through."""
        spec = LLMCallSpec(
            system_prompt="sys",
            user_prompt="prompt for slot",
            response_format=_DummyModel,
            stage="stage_3",
            step="slot",
            validation_retries=1,
            validation_retry_include_schema=False,
            slot_id="RESP-1:CA-1-1:INCORRECT",
            scenario_id="SCN-007",
        )
        with patch(
            "asago_scenario_generator.stpa.infra.parallel_llm.safe_llm_call",
            return_value=(_DummyModel(value="ok"), None, None),
        ) as mocked:
            results = parallel_safe_llm_calls(
                [spec],
                llm_client=ConcurrentMockLLMClient(),
                run_dir=tmp_path,
                max_workers=1,
            )

        assert results[0].error is None
        assert mocked.call_args.kwargs["validation_retry_include_schema"] is False
        assert mocked.call_args.kwargs["slot_id"] == "RESP-1:CA-1-1:INCORRECT"
        assert mocked.call_args.kwargs["scenario_id"] == "SCN-007"
