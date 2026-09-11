"""JSON-decode retry behavior at the model-call boundaries.

Stage 2 keeps its bounded JSON-decode retry (one extra attempt).  Stage 1a
has none (owner authorization 2026-09-11, rev2; owner correction
2026-09-12): an undecodable body is a typed terminal outcome of the single
first attempt, recorded as an unsupported response failure in the run-level
repair record, and is never answered with a second dispatch or a repair
call.
"""

from __future__ import annotations

import pytest
import yaml

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    read_calls_jsonl,
    setup_sp1_mock_client,
    valid_gap_draft_dict,
    valid_risk_draft_dict,
    valid_responsibility_set_dict,
)


def test_stage2_json_decode_retry_continues_and_logs_both_attempts(tmp_path):
    """One malformed 2a response is retried and remains observable in evidence."""
    client: MockLLMClient = setup_sp1_mock_client()
    client.set_response_for(
        ResponsibilitySet,
        ["{malformed JSON", valid_responsibility_set_dict()],
    )

    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.control_structure is not None
    assert result.stage_errors == []

    calls = read_calls_jsonl(tmp_path)
    attempts = [entry for entry in calls if entry["step"] == "call_2a_responsibilities"]
    assert [entry["success"] for entry in attempts] == [False, True]
    assert len(attempts) == 2
    for entry in attempts:
        assert entry["prompt_tokens"] == 100
        assert entry["completion_tokens"] == 50
        assert entry["duration_ms"] == 5000
    assert "JSONDecodeError" in attempts[0]["error"]

    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert manifest["stage_errors"] == []

    # The failed response is logged as metadata only; response bodies are not
    # needed to prove retry behavior and should not be asserted here.
    assert all(entry["stage"] == "stage_2" for entry in attempts)


def test_stage2_json_decode_retry_is_bounded(tmp_path):
    """Two malformed responses do not trigger an unbounded retry loop."""
    client: MockLLMClient = setup_sp1_mock_client()
    client.set_response_for(
        ResponsibilitySet,
        ["{malformed JSON", "{still malformed JSON", valid_responsibility_set_dict()],
    )

    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.control_structure is None
    assert len(result.stage_errors) == 1
    assert "JSONDecodeError" in result.stage_errors[0]
    attempts = [
        entry
        for entry in read_calls_jsonl(tmp_path)
        if entry["step"] == "call_2a_responsibilities"
    ]
    assert len(attempts) == 2
    assert [entry["success"] for entry in attempts] == [False, False]


def test_stage2_semantic_failure_gets_one_corrective_retry(tmp_path):
    """A semantically empty tolerant result gets one bounded retry."""
    client: MockLLMClient = setup_sp1_mock_client()
    client.set_response_for(
        ResponsibilitySet,
        [{"responsibilities": []}, valid_responsibility_set_dict()],
    )

    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.control_structure is not None
    attempts = [
        entry
        for entry in read_calls_jsonl(tmp_path)
        if entry["step"] == "call_2a_responsibilities"
    ]
    assert len(attempts) == 2
    assert [entry["success"] for entry in attempts] == [False, True]
    assert "ValueError" in attempts[0]["error"]
    assert (
        "Prior structured response to correct in place"
        in attempts[1]["user_prompt_text"]
    )
    assert '"responsibilities": []' in attempts[1]["user_prompt_text"]


def test_stage2_semantic_failure_retry_is_bounded(tmp_path):
    """Two semantically empty results stop without consuming a third fixture."""
    client: MockLLMClient = setup_sp1_mock_client()
    client.set_response_for(
        ResponsibilitySet,
        [
            {"responsibilities": []},
            {"responsibilities": []},
            valid_responsibility_set_dict(),
        ],
    )

    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.control_structure is None
    attempts = [
        entry
        for entry in read_calls_jsonl(tmp_path)
        if entry["step"] == "call_2a_responsibilities"
    ]
    assert len(attempts) == 2
    assert [entry["success"] for entry in attempts] == [False, False]
    assert all("ValueError" in entry["error"] for entry in attempts)


def test_stage2_client_failure_is_not_retried(tmp_path):
    """Client/authentication failures remain single-attempt StageErrors."""
    client: MockLLMClient = setup_sp1_mock_client()
    client.set_exception_for(ResponsibilitySet, RuntimeError("authentication failed"))

    result = run_sp1(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    assert result.control_structure is None
    attempts = [
        entry
        for entry in read_calls_jsonl(tmp_path)
        if entry["step"] == "call_2a_responsibilities"
    ]
    assert len(attempts) == 1
    assert attempts[0]["success"] is False
    assert "RuntimeError" in attempts[0]["error"]


def test_stage1a_malformed_json_gets_no_second_dispatch_and_is_recorded(tmp_path):
    """One malformed risk draft is a typed terminal: no retry, one attempt.

    The corrected Stage 1a contract (owner authorization 2026-09-11, rev2;
    owner correction 2026-09-12) allows exactly one call per stage plus at
    most one targeted repair, so an undecodable body is a typed terminal
    outcome of the first attempt — never an automatic second dispatch —
    and the run-level repair record carries it.
    """
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft

    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        ["{malformed JSON", valid_risk_draft_dict(), valid_gap_draft_dict()],
    )

    with pytest.raises(StageError, match="never decoded as JSON"):
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

    attempts = [
        entry
        for entry in read_calls_jsonl(tmp_path)
        if entry["stage"] == "stage_1a" and entry["step"] == "risk_derivation"
    ]
    # Exactly one attempt: the valid fixtures are never consumed.
    assert len(attempts) == 1
    assert attempts[0]["success"] is False
    assert "JSONDecodeError" in attempts[0]["error"]
    assert client.call_count == 1
    # The terminal outcome is recorded as an unsupported response failure.
    record = yaml.safe_load(
        (tmp_path / "loss-analysis-repair.yaml").read_text(encoding="utf-8")
    )
    assert [
        (
            entry["stage"],
            entry["attempt"],
            entry["kind"],
            entry["identity"],
            entry["outcome"],
            entry["raw_step"],
        )
        for entry in record["records"]
    ] == [
        (
            "risk_derivation",
            "first",
            "unsupported",
            "response",
            "unsupported",
            "risk_derivation",
        )
    ]
    assert record["records"][0]["reason"].startswith(
        "the response body never decoded as JSON"
    )


def test_stage1a_malformed_json_terminal_is_never_answered_with_a_repair(tmp_path):
    """A second malformed body changes nothing: still one attempt, one record."""
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft

    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [
            "{malformed JSON",
            "{still malformed JSON",
            valid_risk_draft_dict(),
            valid_gap_draft_dict(),
        ],
    )

    with pytest.raises(StageError, match="stage_1a/risk_derivation"):
        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=make_risk_cards(),
            run_dir=tmp_path,
        )

    attempts = [
        entry
        for entry in read_calls_jsonl(tmp_path)
        if entry["stage"] == "stage_1a" and entry["step"] == "risk_derivation"
    ]
    assert len(attempts) == 1
    assert [entry["success"] for entry in attempts] == [False]
    assert client.call_count == 1


def test_stage1a_calls_forward_exact_completion_cap(tmp_path):
    """Both Stage 1a structured calls use the bounded completion budget."""
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft

    client = MockLLMClient()
    client.set_response_for(
        LossAnalysisDraft,
        [valid_risk_draft_dict(), valid_gap_draft_dict()],
    )

    derive_loss_analysis(
        llm_client=client,
        use_case_text="Test use case",
        risk_cards=make_risk_cards(),
        run_dir=tmp_path,
    )

    stage1a_calls = [
        call
        for call in client.calls
        if call.response_format and issubclass(call.response_format, LossAnalysisDraft)
    ]
    assert len(stage1a_calls) == 2
    assert [call.max_completion_tokens for call in stage1a_calls] == [8192, 8192]
