"""Per-tool verifier verdicts: a disputed tool loses only its own verification."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.infra.llm_helpers import CallOutcome
from tests.discovery_call_log import logged
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.models.execution_classification import (
    InterpreterVerifierAgreement,
    TargetInterpretationDisposition,
    TargetOperationEffect,
    TargetStateEffect,
)
from asago_scenario_generator.target_discovery import (
    McpTargetDiscoveryInputs,
    TargetDiscoveryLlmError,
    TargetDiscoveryLlmInterpreter,
    TargetInterpretationDraft,
    TargetInterpretationRequest,
    TargetInterpretationResponse,
    TargetInterpretationVerdict,
    TargetInterpretationVerification,
    TargetToolPromptView,
    discover_mcp_target,
)
from asago_scenario_generator.target_discovery.prompts import build_verifier_prompt


FIXTURE = (
    Path(__file__).parents[2] / "data/contracts/target-discovery/mcp-tools-list.json"
)
DISPUTED = "lookup_order"
OBSERVER = "get_klarna_state_summary"
REASON = "The description names an identifier lookup, not a free-text search."


class _Inventory:
    def __init__(self) -> None:
        self.payload = json.loads(FIXTURE.read_text(encoding="utf-8"))

    def list_tools(self, cursor=None):
        del cursor
        return self.payload

    def call_tool(self, name, arguments):
        del name, arguments
        return None


class _Interpreter:
    """Interpret every tool as a supported read; verify through ``verdicts``."""

    def __init__(self, verdicts) -> None:
        self._verdicts = verdicts

    def interpret(self, request):
        return TargetInterpretationResponse(
            interpretations=tuple(
                TargetInterpretationDraft(
                    tool_handle=tool.handle,
                    disposition=TargetInterpretationDisposition.supported,
                    likely_effect=(
                        TargetOperationEffect.observe
                        if tool.name == OBSERVER
                        else TargetOperationEffect.read
                    ),
                    likely_state_effect=TargetStateEffect.none,
                    evidence_refs=(f"inventory:tool:{tool.name}:description",),
                    rationale="The quoted description supports this bounded label.",
                )
                for tool in request.tools
            )
        )

    def verify(self, request, response):
        del response
        return self._verdicts(request)


def _inputs() -> McpTargetDiscoveryInputs:
    return McpTargetDiscoveryInputs(
        target_id="mini-klarna-safe", authorization_scope_id="test-customer"
    )


def _verdict(tool, agreement, reason="The cited description supports it."):
    return TargetInterpretationVerdict(
        tool_handle=tool.handle,
        reason=reason,
        agreement=InterpreterVerifierAgreement(agreement),
    )


def _dispute_one(request):
    return TargetInterpretationVerification(
        verdicts=tuple(
            _verdict(tool, "disagree", REASON)
            if tool.name == DISPUTED
            else _verdict(tool, "agree")
            for tool in request.tools
        )
    )


def _agreements(result) -> dict[str, InterpreterVerifierAgreement]:
    return {
        item.tool_name: item.interpreter_verifier_agreement
        for item in result.profile.interpretations
    }


def test_disputed_tool_loses_only_its_own_verification():
    result = discover_mcp_target(_inputs(), _Inventory(), _Interpreter(_dispute_one))

    agreements = _agreements(result)
    assert agreements.pop(DISPUTED) is InterpreterVerifierAgreement.disagree
    assert agreements[OBSERVER] is InterpreterVerifierAgreement.agree
    assert set(agreements.values()) == {InterpreterVerifierAgreement.agree}
    disagreements = [
        item
        for item in result.diagnostics
        if item.code.value == "verifier_disagreement"
    ]
    assert [item.tool_name for item in disagreements] == [DISPUTED]
    assert REASON in disagreements[0].detail
    assert result.valid is True


def test_batch_level_disagreement_still_marks_every_tool_in_the_batch():
    result = discover_mcp_target(
        _inputs(), _Inventory(), _Interpreter(lambda request: False)
    )

    assert set(_agreements(result).values()) == {InterpreterVerifierAgreement.disagree}
    disagreements = [
        item
        for item in result.diagnostics
        if item.code.value == "verifier_disagreement"
    ]
    assert len(disagreements) == 1
    assert disagreements[0].tool_name is None


def test_missing_verdict_leaves_only_that_tool_unverified():
    def omit_disputed(request):
        return TargetInterpretationVerification(
            verdicts=tuple(
                _verdict(tool, "agree")
                for tool in request.tools
                if tool.name != DISPUTED
            )
        )

    result = discover_mcp_target(_inputs(), _Inventory(), _Interpreter(omit_disputed))

    agreements = _agreements(result)
    assert agreements.pop(DISPUTED) is InterpreterVerifierAgreement.unverified
    assert set(agreements.values()) == {InterpreterVerifierAgreement.agree}
    missing = [
        item
        for item in result.diagnostics
        if item.code.value == "interpretation_invalid" and item.tool_name == DISPUTED
    ]
    assert len(missing) == 1
    assert "no verdict" in missing[0].detail


def test_verdict_for_a_foreign_handle_leaves_the_batch_unverified():
    def foreign(request):
        return TargetInterpretationVerification(
            verdicts=(
                *(_verdict(tool, "agree") for tool in request.tools),
                TargetInterpretationVerdict(
                    tool_handle="TOOL-99",
                    reason="Invented handle.",
                    agreement=InterpreterVerifierAgreement.agree,
                ),
            )
        )

    result = discover_mcp_target(_inputs(), _Inventory(), _Interpreter(foreign))

    assert set(_agreements(result).values()) == {
        InterpreterVerifierAgreement.unverified
    }
    assert any(
        item.code.value == "interpretation_invalid" and "TOOL-99" in item.detail
        for item in result.diagnostics
    )


def test_mapping_verdicts_are_accepted_from_plain_adapters():
    def as_mapping(request):
        return _dispute_one(request).model_dump(mode="json")

    result = discover_mcp_target(_inputs(), _Inventory(), _Interpreter(as_mapping))

    agreements = _agreements(result)
    assert agreements.pop(DISPUTED) is InterpreterVerifierAgreement.disagree
    assert set(agreements.values()) == {InterpreterVerifierAgreement.agree}


def test_verification_contract_rejects_duplicate_handles_and_unverified_verdicts():
    verdict = {"tool_handle": "TOOL-1", "reason": "Supported.", "agreement": "agree"}
    with pytest.raises(ValidationError, match="duplicate"):
        TargetInterpretationVerification.model_validate(
            {"verdicts": [verdict, verdict]}
        )
    with pytest.raises(ValidationError, match="agree or disagree"):
        TargetInterpretationVerification.model_validate(
            {"verdicts": [{**verdict, "agreement": "unverified"}]}
        )
    with pytest.raises(ValidationError):
        TargetInterpretationVerification.model_validate(
            {"verdicts": [{**verdict, "reason": ""}]}
        )


def _two_tool_request() -> TargetInterpretationRequest:
    return TargetInterpretationRequest(
        batch_id="BATCH-1",
        tools=tuple(
            TargetToolPromptView(
                handle=f"TOOL-{index}",
                name=name,
                input_schema={"type": "object"},
                evidence_refs=(f"inventory:tool:{name}:description",),
            )
            for index, name in enumerate(("read_order", "search_docs"), start=1)
        ),
    )


def _interpretations(request) -> TargetInterpretationResponse:
    return TargetInterpretationResponse(
        interpretations=tuple(
            TargetInterpretationDraft(
                tool_handle=tool.handle,
                disposition=TargetInterpretationDisposition.supported,
                likely_effect=TargetOperationEffect.read,
                likely_state_effect=TargetStateEffect.none,
                evidence_refs=tool.evidence_refs,
                rationale="The quoted evidence names a read operation.",
            )
            for tool in request.tools
        )
    )


def test_verifier_prompt_asks_one_independent_verdict_with_a_reason_per_handle():
    request = _two_tool_request()
    system, user = build_verifier_prompt(request, _interpretations(request))
    system = " ".join(system.split())

    assert "one verdict for each interpretation record" in system
    assert "reason" in system
    assert "does not change the verdict for any other record" in system
    assert "exactly 2 supplied handles: TOOL-1, TOOL-2" in user
    assert "typed agreement enum: agree or disagree" not in user


def _llm_result(value, kwargs) -> LLMResult:
    return LLMResult(
        content=value,
        prompt_tokens=1,
        completion_tokens=1,
        duration_ms=1,
        system_prompt=kwargs["system_prompt"],
        user_prompt=kwargs["user_prompt"],
    )


def test_llm_verifier_requests_and_returns_one_verdict_per_handle(tmp_path: Path):
    request = _two_tool_request()
    seen: list[type] = []

    def fake_call_with_policy(**kwargs):
        schema = kwargs["response_format"]
        seen.append(schema)
        with pytest.raises(ValidationError):
            schema.model_validate({"verdicts": []})
        value = schema.model_validate(
            {
                "verdicts": [
                    {
                        "tool_handle": "TOOL-1",
                        "reason": "Supported.",
                        "agreement": "agree",
                    },
                    {
                        "tool_handle": "TOOL-2",
                        "reason": REASON,
                        "agreement": "disagree",
                    },
                ]
            }
        )
        return CallOutcome(value, _llm_result(value, kwargs), None, 1)

    adapter = TargetDiscoveryLlmInterpreter(
        SimpleNamespace(model="fixture-model"), run_dir=tmp_path
    )
    with patch(
        "asago_scenario_generator.target_discovery.llm_interpreter.call_with_policy",
        side_effect=logged(fake_call_with_policy),
    ):
        verification = adapter.verify(request, _interpretations(request))

    assert seen[0].__name__ == "TargetInterpretationProviderVerification"
    assert isinstance(verification, TargetInterpretationVerification)
    assert [
        (item.tool_handle, item.agreement.value) for item in verification.verdicts
    ] == [
        ("TOOL-1", "agree"),
        ("TOOL-2", "disagree"),
    ]
    record = adapter.drain_call_records()[0]
    assert record["step"] == "verification"
    assert record["cleaned_response"]["verdicts"][1]["reason"] == REASON


def test_llm_verifier_rejects_verdicts_that_do_not_cover_each_handle_once(
    tmp_path: Path,
):
    request = _two_tool_request()

    def fake_call_with_policy(**kwargs):
        value = kwargs["response_format"].model_validate(
            {
                "verdicts": [
                    {
                        "tool_handle": "TOOL-1",
                        "reason": "Supported.",
                        "agreement": "agree",
                    },
                    {"tool_handle": "TOOL-1", "reason": "Again.", "agreement": "agree"},
                ]
            }
        )
        return CallOutcome(value, _llm_result(value, kwargs), None, 1)

    adapter = TargetDiscoveryLlmInterpreter(
        SimpleNamespace(model="fixture-model"), run_dir=tmp_path
    )
    with (
        patch(
            "asago_scenario_generator.target_discovery.llm_interpreter.call_with_policy",
            side_effect=logged(fake_call_with_policy),
        ),
        pytest.raises(TargetDiscoveryLlmError, match="verification"),
    ):
        adapter.verify(request, _interpretations(request))
