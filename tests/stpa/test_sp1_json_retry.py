"""Regression tests for bounded JSON-decode retries at the Stage 2 boundary."""

from __future__ import annotations

import yaml

from asago_scenario_generator.stpa.system_model.control_structure import (
    ResponsibilitySet,
)
from asago_scenario_generator.stpa.system_model.run import run_sp1
from tests.stpa.sp1_helpers import (
    MockLLMClient,
    make_risk_cards,
    read_calls_jsonl,
    setup_sp1_mock_client,
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
