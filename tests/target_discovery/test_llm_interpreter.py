"""Focused tests for the profile-backed target interpretation adapter."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.execution_classification import (
    InterpreterVerifierAgreement,
    TargetInterpretationDisposition,
    TargetOperationEffect,
    TargetStateEffect,
)
from asago_scenario_generator.target_discovery import (
    McpTargetDiscoveryInputs,
    TargetDiscoveryLlmInterpreter,
    TargetDiscoveryLlmError,
    TargetInterpretationDraft,
    TargetInterpretationResponse,
    TargetInterpretationVerification,
    TargetToolPromptView,
    discover_mcp_target,
    write_target_discovery,
)


def _request():
    from asago_scenario_generator.target_discovery import TargetInterpretationRequest

    return TargetInterpretationRequest(
        batch_id="BATCH-1",
        tools=(
            TargetToolPromptView(
                handle="TOOL-1",
                name="read_order",
                input_schema={"type": "object"},
                evidence_refs=("inventory:tool:read_order:description",),
            ),
        ),
    )


def _response() -> TargetInterpretationResponse:
    return TargetInterpretationResponse(
        interpretations=(
            TargetInterpretationDraft(
                tool_handle="TOOL-1",
                disposition=TargetInterpretationDisposition.supported,
                likely_effect=TargetOperationEffect.read,
                likely_state_effect=TargetStateEffect.none,
                semantic_roles=("reader",),
                evidence_refs=("inventory:tool:read_order:description",),
                rationale="The quoted evidence names a read operation.",
            ),
        )
    )


def _typed_response(response_format, interpretation: TargetInterpretationResponse):
    """Answer the verifier schema with an agreeing verdict per interpretation."""
    if response_format.__name__ != "TargetInterpretationProviderVerification":
        return interpretation
    return response_format.model_validate(
        {
            "verdicts": [
                {
                    "tool_handle": item.tool_handle,
                    "reason": "The cited description supports the record.",
                    "agreement": "agree",
                }
                for item in interpretation.interpretations
            ]
        }
    )


def test_profile_backed_adapter_calls_interpreter_and_verifier_with_full_records():
    request = _request()
    response = _response()
    seen: list[dict] = []
    client = SimpleNamespace(model="fixture-model")

    def fake_safe_llm_call(**kwargs):
        seen.append(kwargs)
        value = _typed_response(kwargs["response_format"], response)
        return (
            value,
            LLMResult(
                content=value,
                prompt_tokens=11,
                completion_tokens=7,
                duration_ms=3,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            ),
            None,
        )

    with patch(
        "asago_scenario_generator.target_discovery.llm_interpreter.safe_llm_call",
        side_effect=fake_safe_llm_call,
    ):
        adapter = TargetDiscoveryLlmInterpreter(client)
        interpreted = adapter.interpret(request)
        verification = adapter.verify(request, interpreted)

    assert interpreted == response
    assert isinstance(verification, TargetInterpretationVerification)
    assert [item.agreement for item in verification.verdicts] == [
        InterpreterVerifierAgreement.agree
    ]
    assert seen[0]["response_format"].__name__ == (
        "TargetInterpretationProviderResponse"
    )
    assert seen[1]["response_format"].__name__ == (
        "TargetInterpretationProviderVerification"
    )
    records = adapter.drain_call_records()
    assert [record["kind"] for record in records] == [
        "interpretation",
        "verification",
    ]
    for record in records:
        assert record["system_prompt_text"]
        assert record["user_prompt_text"]
        assert record["prompt_hash"]
        assert record["validated_response"]
        assert "server_url" not in str(record)
        assert "Authorization" not in str(record)
    assert records[0]["validated_response"] == response.model_dump(mode="json")


def test_provider_response_rejects_empty_interpretation_list():
    from asago_scenario_generator.target_discovery.llm_interpreter import (
        _provider_response_model,
    )

    with pytest.raises(ValidationError):
        _provider_response_model(1).model_validate({"interpretations": []})


def test_interpreter_rejects_omitted_handle_before_verifier():
    request = _request()
    empty_response = TargetInterpretationResponse.model_construct(interpretations=())
    seen: list[object] = []
    client = SimpleNamespace(model="fixture-model")

    def fake_safe_llm_call(**kwargs):
        seen.append(kwargs["response_format"])
        return (
            empty_response,
            LLMResult(
                content=empty_response,
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            ),
            None,
        )

    with (
        patch(
            "asago_scenario_generator.target_discovery.llm_interpreter.safe_llm_call",
            side_effect=fake_safe_llm_call,
        ),
        pytest.raises(TargetDiscoveryLlmError),
    ):
        TargetDiscoveryLlmInterpreter(client).interpret(request)

    assert len(seen) == 1
    assert seen[0].__name__ == "TargetInterpretationProviderResponse"


def test_failed_safe_call_retains_stable_error_metadata_without_body_or_fake_duration():
    request = _request()
    client = SimpleNamespace(model="fixture-model")

    with (
        patch(
            "asago_scenario_generator.target_discovery.llm_interpreter.safe_llm_call",
            return_value=(
                None,
                None,
                "InternalServerError: Error code: 503 - "
                "<html>Application is not available at https://secret.example</html>",
            ),
        ),
        pytest.raises(TargetDiscoveryLlmError) as raised,
    ):
        adapter = TargetDiscoveryLlmInterpreter(client)
        adapter.interpret(request)

    records = adapter.drain_call_records()
    assert len(records) == 1
    record = records[0]
    assert record["error_type"] == "InternalServerError"
    assert record["http_status"] == 503
    assert record["duration_ms"] is None
    assert "secret.example" not in str(record)
    assert "Application is not available" not in str(record)
    assert (
        str(raised.value)
        == "interpretation call failed (InternalServerError, status=503)"
    )


def test_discovery_includes_adapter_calls_and_profile_provenance(tmp_path: Path):
    row = {"name": "read_order", "inputSchema": {"type": "object"}}
    request_response = _response()
    client = SimpleNamespace(model="fixture-model")

    def fake_safe_llm_call(**kwargs):
        value = _typed_response(kwargs["response_format"], request_response)
        return (
            value,
            LLMResult(
                content=value,
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            ),
            None,
        )

    class Inventory:
        def list_tools(self, cursor=None):
            del cursor
            return {"tools": [row]}

        def call_tool(self, name, arguments):
            del name, arguments
            return None

    inputs = McpTargetDiscoveryInputs(
        target_id="fixture-target",
        authorization_scope_id="fixture-scope",
        model_profile="fixture-profile",
        model_name="fixture-model",
    )
    with patch(
        "asago_scenario_generator.target_discovery.llm_interpreter.safe_llm_call",
        side_effect=fake_safe_llm_call,
    ):
        result = discover_mcp_target(
            inputs,
            Inventory(),
            TargetDiscoveryLlmInterpreter(client),
        )

    assert result.profile is not None
    assert result.profile.semantic_authority.value == "inferred"
    assert result.provenance is not None
    assert result.provenance.model_profile == "fixture-profile"
    assert result.provenance.model_name == "fixture-model"
    assert [record["kind"] for record in result.calls] == [
        "tools/list",
        "interpretation",
        "verification",
    ]
    assert result.calls[1]["validated_response"]["interpretations"]
    assert result.calls[2]["validated_response"]["verdicts"][0]["agreement"] == (
        "agree"
    )
    assert result.profile.interpretations[0].interpreter_verifier_agreement is (
        InterpreterVerifierAgreement.agree
    )
    written = write_target_discovery(tmp_path, result)
    persisted_calls = [
        json.loads(line)
        for line in written["calls.jsonl"].read_text(encoding="utf-8").splitlines()
    ]
    assert persisted_calls[1]["system_prompt_text"]
    assert persisted_calls[1]["user_prompt_text"]
    assert (
        persisted_calls[1]["validated_response"]
        == result.calls[1]["validated_response"]
    )


def test_from_profile_uses_existing_named_profile_resolver(tmp_path: Path):
    client = SimpleNamespace(model="resolved-model")
    with patch(
        "asago_scenario_generator.target_discovery.llm_interpreter.resolve_llm_client_from_profile",
        return_value=(client, "named-profile"),
    ) as resolver:
        adapter = TargetDiscoveryLlmInterpreter.from_profile(
            tmp_path / "profiles.yaml", "named-profile"
        )

    resolver.assert_called_once_with(str(tmp_path / "profiles.yaml"), "named-profile")
    assert adapter.model_name == "resolved-model"
