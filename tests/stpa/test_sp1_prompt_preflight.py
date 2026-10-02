"""Pure model-aware prompt-contract and budget tests."""

from __future__ import annotations

import json

import pytest
from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import safe_llm_call
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    PromptBudgetExceeded,
    PromptContractError,
    audit_prompt_contract,
)


def test_prompt_budget_uses_the_greater_of_ten_percent_or_1024_margin() -> None:
    small = PromptBudget(context_window=8_000, maximum_completion_tokens=2_000)
    large = PromptBudget(context_window=32_000, maximum_completion_tokens=4_000)

    assert small.safety_margin == 1_024
    assert small.usable_input_tokens == 4_976
    assert large.safety_margin == 3_200
    assert large.usable_input_tokens == 24_800


def test_prompt_audit_records_digest_and_estimated_size() -> None:
    audit = audit_prompt_contract(
        stage="stage_2",
        prompt_view={"target": "CA-1-1"},
        system_prompt='Return JSON with ca_id and description. Example: {"ca_id": "CA-1-1"}',
        user_prompt="Copy-only handle: CA-1-1",
        input_handles=("CA-1-1",),
        accounted_handles=("CA-1-1",),
        selectable_references={"CA-1-1": "Authorize request"},
        output_schema=("ca_id", "description"),
        valid_example={"ca_id": "CA-1-1", "description": "Authorize request"},
        budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
    )

    assert audit.ok
    assert len(audit.rendered_prompt_digest) == 64
    assert audit.input_tokens > 0
    assert audit.input_tokens_estimated is True
    assert audit.usable_input_tokens == 5_976


def test_prompt_audit_rejects_prohibited_metadata_and_local_paths() -> None:
    with pytest.raises(PromptContractError, match="digest|path"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"source_digest": "abc123"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Read /Users/example/run/control.yaml",
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_prompt_audit_requires_descriptions_for_selectable_ids() -> None:
    with pytest.raises(PromptContractError, match="description"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Choose CA-1-1",
            selectable_references={"CA-1-1": ""},
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_prompt_audit_fails_closed_when_input_handles_are_not_accounted_for() -> None:
    with pytest.raises(PromptContractError, match="handle"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Copy-only handle: CA-1-1",
            input_handles=("CA-1-1", "CA-1-2"),
            accounted_handles=("CA-1-1",),
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_prompt_audit_requires_an_accounting_set_for_input_handles() -> None:
    with pytest.raises(PromptContractError, match="accounted"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Copy-only handle: CA-1-1",
            input_handles=("CA-1-1",),
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
        )


def test_prompt_audit_rejects_reference_outside_authoritative_slice() -> None:
    with pytest.raises(PromptContractError, match="authoritative"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-9-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Select a control action.",
            authoritative_references={"CA-1-1": "Authorize request"},
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
        )


def test_prompt_audit_rejects_oversized_prompt_before_dispatch() -> None:
    with pytest.raises(PromptBudgetExceeded, match="prompt_budget_exceeded") as exc:
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"target": "CA-1-1"},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="x" * 10_000,
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(
                context_window=1_024,
                maximum_completion_tokens=128,
                safety_margin=128,
                token_counter=lambda value: len(value),
            ),
        )
    assert exc.value.code == "prompt_budget_exceeded"
    assert exc.value.provider_call_allowed is False


def test_prompt_audit_does_not_accept_raw_mapping_payload_as_view_text() -> None:
    raw_mapping = json.dumps({"source": "SC-1", "target": "H-1"})

    with pytest.raises(PromptContractError, match="mapping"):
        audit_prompt_contract(
            stage="stage_2",
            prompt_view={"mapping_json": raw_mapping},
            system_prompt='Return JSON with ca_id. Example: {"ca_id": "CA-1-1"}',
            user_prompt="Choose a route",
            output_schema=("ca_id",),
            valid_example={"ca_id": "CA-1-1"},
            budget=PromptBudget(context_window=8_000, maximum_completion_tokens=1_000),
        )


def test_configured_provider_is_not_called_when_rendered_prompt_exceeds_budget(
    tmp_path,
) -> None:
    class Response(BaseModel):
        value: str

    class Client:
        model = "budget-test"
        context_window = 128
        max_completion_tokens = 64
        safety_margin = 0

        def __init__(self) -> None:
            self.calls = 0

        def complete(self, **kwargs):
            del kwargs
            self.calls += 1
            return LLMResult(
                content={"value": "unexpected"},
                prompt_tokens=0,
                completion_tokens=0,
                duration_ms=0,
            )

    client = Client()
    value, result, error = safe_llm_call(
        llm_client=client,
        system_prompt="contract",
        user_prompt="x" * 1024,
        response_format=Response,
        run_dir=tmp_path,
        stage="budget-stage",
        step="oversized",
        max_completion_tokens=64,
    )

    assert value is None
    assert result is None
    assert error is not None and "prompt_budget_exceeded" in error
    assert client.calls == 0

    [record] = [
        json.loads(line)
        for line in (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()
    ]
    assert record["prompt_preflight"] == {
        "rendered_prompt_digest": record["rendered_prompt_digest"],
        "input_tokens": record["preflight_input_tokens"],
        "input_tokens_estimated": True,
        "context_window": 128,
        "maximum_completion_tokens": 64,
        "safety_margin": 0,
        "usable_input_tokens": 64,
        "provider_call_allowed": False,
        "errors": record["prompt_preflight"]["errors"],
    }
    assert record["preflight_input_tokens"] > 64
    assert "prompt_budget_exceeded" in record["prompt_preflight"]["errors"][0]


def test_configured_provider_logs_successful_preflight_budget(tmp_path) -> None:
    class Response(BaseModel):
        value: str

    class Client:
        model = "budget-test"
        context_window = 8_000
        max_completion_tokens = 1_000
        safety_margin = 1_024

        def complete(self, **kwargs):
            return LLMResult(
                content={"value": "ok"},
                prompt_tokens=23,
                completion_tokens=2,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    value, _result, error = safe_llm_call(
        llm_client=Client(),
        system_prompt="contract",
        user_prompt="small prompt",
        response_format=Response,
        run_dir=tmp_path,
        stage="budget-stage",
        step="within-budget",
        max_completion_tokens=1_000,
    )

    assert value == Response(value="ok")
    assert error is None
    record = json.loads(
        (tmp_path / "calls.jsonl").read_text(encoding="utf-8").splitlines()[0]
    )
    assert record["prompt_preflight"]["provider_call_allowed"] is True
    assert record["prompt_preflight"]["context_window"] == 8_000
    assert record["preflight_input_tokens"] > 0
