"""A synthesis run that loses every candidate to its prompt budget does not fail.

A recorded OcciAI run generated no scenario and exited 0: all 119 synthesis
calls failed the prompt-reference check (``PromptContractError``) before
any request was sent, every slot became unresolved, and the manifest read
``no_candidates``.  That run failed a check the prompt itself broke, so it is
now ``failed``.  A call its prompt budget stopped is a different loss: the
profile could not fit the rendered prompt, no request was sent, and a run
that requested no candidate stays a valid empty analysis.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest
import yaml

from asago_scenario_generator.cli import app
from asago_scenario_generator.pipeline import synthesis as synthesis_module
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    SynthesisRunStatus,
    run_synthesis,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _scenario_generation_status,
)
from asago_scenario_generator.stpa.infra.call_log import append_call_log
from tests.cli_helpers import PlainCliRunner
from tests.helpers.synthesis import _FakeAdapters, _inputs

# Two of the blocked rows of that run's call log, trimmed to the fields the
# manifest copies.
_CONTRACT_FAILURES = (
    {
        "stage": "synthesis_obligation_aware_routing",
        "step": "initial-batch-1",
        "success": False,
        "error": (
            "PromptContractError: prompt-view reference 'PM-3' is not in the "
            "authoritative slice (target_index.coordination_paths[7].description)"
        ),
    },
    {
        "stage": "synthesis_obligation_aware_icas",
        "step": "RESP-2",
        "success": False,
        "error": (
            "PromptContractError: prompt-view reference 'H-10' is not in the "
            "authoritative slice (target_index.hazards[1].id)"
        ),
    },
)
_OTHER_FAILURE = {
    "stage": "synthesis_obligation_aware_icas",
    "step": "RESP-3",
    "success": False,
    "error": "ValidationError: 1 validation error for SynthesisSlotResponse",
}
# Two calls the prompt budget stopped before dispatch, as the m1-baseline-a
# recording logs one at ICA verification.  The budget error is a
# ``PromptContractError`` subclass, but its recorded text names its own class.
_BUDGET_FAILURES = (
    {
        "stage": "synthesis_obligation_aware_icas",
        "step": "RESP-1",
        "success": False,
        "error": (
            "PromptBudgetExceeded: prompt_budget_exceeded: rendered prompt uses "
            "24676 input tokens, budget allows 21299 (context_window=32768, "
            "maximum_completion_tokens=8192, safety_margin=3277)"
        ),
    },
    {
        "stage": "synthesis_obligation_aware_routing",
        "step": "initial-batch-2",
        "success": False,
        "error": (
            "PromptBudgetExceeded: prompt_budget_exceeded: rendered prompt uses "
            "23018 input tokens, budget allows 21299 (context_window=32768, "
            "maximum_completion_tokens=8192, safety_margin=3277)"
        ),
    },
)
_PUBLISHED = (
    SimpleNamespace(
        scenario_id="SCN-001",
        ica_slot_id="RESP-1:CA-1-1:INCORRECT",
        ica_id="ICA-1",
        status="published",
        diagnostics=(),
    ),
)
_VOLATILE = ("run_id", "created_at", "semantic_digest")
# The no-candidate manifest of ``_run`` with ``_OTHER_FAILURE`` seeded, as the
# start commit writes it, without its run ID, timestamp, and digest, without
# the copy of the call records the manifest no longer keeps, and with the
# funnel's second denominator (``applicable_without_llm_fan_out``), and with
# the ``not_applicable`` candidate count beside the other scenario counts.
_NO_CANDIDATES_MANIFEST_DIGEST = (
    "4f9f95a0d64638ebd277ce5d6b5b4daaa725f0699f062a4c4848c25da81ace00"
)


def _seed_call_records(monkeypatch: pytest.MonkeyPatch, records: tuple) -> None:
    real = synthesis_module._run_synthesis

    def seeded(inputs: Any, adapters: Any, session: Any) -> Any:
        append_call_log(list(records), Path(inputs.output_dir), session.call_log)
        return real(inputs, adapters, session)

    monkeypatch.setattr(synthesis_module, "_run_synthesis", seeded)


def _run(tmp_path: Path, monkeypatch, records: tuple, *, published: bool = False):
    _seed_call_records(monkeypatch, records)
    fake = _FakeAdapters(
        calls=[],
        scenario_envelopes=("scenario-1",) if published else (),
        candidate_outcomes=_PUBLISHED if published else (),
    )
    return run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))


def _stable_digest(manifest_path: Path) -> str:
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    stable = {key: value for key, value in manifest.items() if key not in _VOLATILE}
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _invoke_cli(tmp_path: Path, result: Any):
    risk = tmp_path / "risk-extraction.json"
    facts = tmp_path / "qualification-facts.json"
    sssom = tmp_path / "mapping.tsv"
    risk.write_text("{}", encoding="utf-8")
    facts.write_text("{}", encoding="utf-8")
    sssom.write_text("", encoding="utf-8")
    with (
        patch(
            "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
            return_value=(),
        ),
        patch(
            "asago_scenario_generator.pipeline.synthesis.run_synthesis",
            return_value=result,
        ),
    ):
        return PlainCliRunner().invoke(
            app,
            [
                "generate",
                "--use-case",
                "a deterministic system",
                "--risk-extraction",
                str(risk),
                "--qualification-facts",
                str(facts),
                "--sssom",
                str(sssom),
                "--output-dir",
                str(result.output_dir),
            ],
        )


class TestZeroCandidatesAfterContractFailures:
    def test_the_run_fails_and_names_the_contract_failures(
        self, tmp_path, monkeypatch
    ) -> None:
        result = _run(tmp_path, monkeypatch, (*_CONTRACT_FAILURES, _OTHER_FAILURE))

        manifest = yaml.safe_load(
            (tmp_path / "synthesis-manifest.yaml").read_text(encoding="utf-8")
        )
        assert result.run_status == "failed"
        assert manifest["run_status"] == "failed"
        assert manifest["run_status_reason"].startswith("prompt_contract_failures: 2 ")
        assert manifest["prompt_contract_failures"] == 2
        assert manifest["scenario_counts"]["requested"] == 0
        report = result.report_path.read_text(encoding="utf-8")
        assert "Scenario generation ended failed: prompt_contract_failures: 2" in report

    def test_the_cli_exits_non_zero_and_says_why(self, tmp_path, monkeypatch) -> None:
        result = _run(tmp_path / "run", monkeypatch, _CONTRACT_FAILURES)

        cli = _invoke_cli(tmp_path, result)

        assert cli.exit_code == 1
        assert "Scenario generation: failed" in cli.stdout
        assert "prompt_contract_failures: 2 " in cli.stderr
        assert "after attempting candidates" not in cli.stderr


class TestZeroCandidatesAfterBudgetOverflow:
    def test_the_run_reports_no_candidates_and_names_the_budget(
        self, tmp_path, monkeypatch
    ) -> None:
        result = _run(tmp_path, monkeypatch, (*_BUDGET_FAILURES, _OTHER_FAILURE))

        manifest = yaml.safe_load(
            (tmp_path / "synthesis-manifest.yaml").read_text(encoding="utf-8")
        )
        assert result.run_status == "no_candidates"
        assert manifest["run_status"] == "no_candidates"
        assert manifest["run_status_reason"].startswith("prompt_budget_exceeded: 2 ")
        assert manifest["prompt_budget_failures"] == 2
        assert "prompt_contract_failures" not in manifest
        assert manifest["scenario_counts"]["requested"] == 0

    def test_the_cli_exits_zero_and_reports_no_candidates(
        self, tmp_path, monkeypatch
    ) -> None:
        result = _run(tmp_path / "run", monkeypatch, _BUDGET_FAILURES)

        cli = _invoke_cli(tmp_path, result)

        assert cli.exit_code == 0
        assert "Scenario generation: no_candidates" in cli.stdout
        assert cli.stderr == ""


class TestZeroCandidatesWithoutContractFailures:
    def test_the_run_keeps_no_candidates_and_the_cli_exits_zero(
        self, tmp_path, monkeypatch
    ) -> None:
        result = _run(tmp_path / "run", monkeypatch, (_OTHER_FAILURE,))

        assert result.run_status == "no_candidates"
        assert result.manifest["run_status_reason"] == "no_eligible_candidates"
        assert "prompt_contract_failures" not in result.manifest
        assert _invoke_cli(tmp_path, result).exit_code == 0

    def test_the_manifest_is_byte_identical_to_the_start_commit(
        self, tmp_path, monkeypatch
    ) -> None:
        _run(tmp_path, monkeypatch, (_OTHER_FAILURE,))

        digest = _stable_digest(tmp_path / "synthesis-manifest.yaml")
        assert digest == _NO_CANDIDATES_MANIFEST_DIGEST


class TestSomeCandidatesDespiteContractFailures:
    def test_the_status_is_unchanged_and_the_failures_are_counted(
        self, tmp_path, monkeypatch
    ) -> None:
        result = _run(tmp_path, monkeypatch, _CONTRACT_FAILURES, published=True)

        assert result.run_status == "completed"
        assert result.manifest["run_status_reason"] == (
            "all_requested_candidates_resolved"
        )
        assert result.manifest["prompt_contract_failures"] == 2


class TestSomeCandidatesDespiteBudgetOverflow:
    def test_the_status_is_unchanged_and_the_budget_failures_are_counted(
        self, tmp_path, monkeypatch
    ) -> None:
        result = _run(tmp_path, monkeypatch, _BUDGET_FAILURES, published=True)

        assert result.run_status == "completed"
        assert result.manifest["run_status_reason"] == (
            "all_requested_candidates_resolved"
        )
        assert result.manifest["prompt_budget_failures"] == 2
        assert "prompt_contract_failures" not in result.manifest


@pytest.mark.parametrize(
    ("counts", "failures", "expected"),
    [
        (
            {"requested": 0, "attempted": 0, "generated": 0},
            119,
            SynthesisRunStatus.FAILED,
        ),
        (
            {"requested": 0, "attempted": 0, "generated": 0},
            0,
            SynthesisRunStatus.NO_CANDIDATES,
        ),
        (
            {"requested": 2, "attempted": 2, "generated": 1},
            3,
            SynthesisRunStatus.DEGRADED,
        ),
        (
            {"requested": None, "attempted": None, "generated": None},
            3,
            SynthesisRunStatus.UNKNOWN,
        ),
    ],
)
def test_the_status_helper_fails_only_a_zero_candidate_run(
    counts, failures, expected
) -> None:
    status, reason = _scenario_generation_status(
        counts, prompt_contract_failures=failures
    )

    assert status == expected
    assert ("prompt_contract_failures" in reason) == (
        expected == SynthesisRunStatus.FAILED
    )


@pytest.mark.parametrize(
    ("contract_failures", "budget_failures", "expected"),
    [
        (0, 2, SynthesisRunStatus.NO_CANDIDATES),
        (0, 0, SynthesisRunStatus.NO_CANDIDATES),
        (2, 0, SynthesisRunStatus.FAILED),
        (2, 1, SynthesisRunStatus.FAILED),
        (1, 3, SynthesisRunStatus.FAILED),
    ],
)
def test_the_status_helper_does_not_fail_a_zero_request_budget_overflow(
    contract_failures, budget_failures, expected
) -> None:
    status, reason = _scenario_generation_status(
        {"requested": 0, "attempted": 0, "generated": 0},
        prompt_contract_failures=contract_failures,
        prompt_budget_failures=budget_failures,
    )

    assert status == expected
    if status == SynthesisRunStatus.FAILED:
        assert reason.startswith("prompt_contract_failures: ")
    elif budget_failures:
        assert reason.startswith("prompt_budget_exceeded: ")
    else:
        assert reason == "no_eligible_candidates"
