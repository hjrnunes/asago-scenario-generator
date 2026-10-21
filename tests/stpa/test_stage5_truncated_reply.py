"""A Stage 5 reply cut off at the completion cap earns the concise length retry.

A partial reply that fails to parse is one scenario's repetition loop, so a
failed retry fails that scenario only and never stops the remaining threats.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.scenario_prod.run import (
    SP3CandidateStatus,
    run_sp3,
)
from asago_scenario_generator.stpa.scenario_prod.stage5 import generate
from asago_scenario_generator.stpa.scenario_prod.stage5.wire import (
    _ContextScenarioSemanticsPayload,
)
from tests.helpers.provider_call_record import _client, _completion, _Provider
from tests.helpers.sp3_run import _make_ets, _setup_mock_client
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.sp1_helpers import MockCall, MockLLMClient

_PARTIAL_REPLY = '{"adversary": {"kind": "malicious_customer", "gain": "Learns'


def _is_stage5(response_format: type | None) -> bool:
    return isinstance(response_format, type) and issubclass(
        response_format, _ContextScenarioSemanticsPayload
    )


class _TruncatingClient(MockLLMClient):
    """Cut off the Stage 5 replies at the listed call indexes.

    A truncated call takes no queued payload, so the next Stage 5 call
    receives the payload the truncated one would have.
    """

    def __init__(self, base: MockLLMClient, truncated: set[int]) -> None:
        super().__init__()
        self.__dict__.update(base.__dict__)
        self._truncated = truncated
        self._stage5_index = 0

    def complete(
        self,
        system_prompt: str,
        user_prompt: str,
        response_format: type | None = None,
        max_completion_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        if not _is_stage5(response_format):
            return super().complete(
                system_prompt,
                user_prompt,
                response_format,
                max_completion_tokens,
                temperature,
            )
        index = self._stage5_index
        self._stage5_index += 1
        if index not in self._truncated:
            return super().complete(
                system_prompt,
                user_prompt,
                response_format,
                max_completion_tokens,
                temperature,
            )
        self.calls.append(
            MockCall(
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                response_format=response_format,
                temperature=temperature,
                max_completion_tokens=max_completion_tokens,
            )
        )
        return LLMResult(
            content=_PARTIAL_REPLY,
            prompt_tokens=100,
            completion_tokens=4096,
            duration_ms=5000,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            raw_response=_PARTIAL_REPLY,
            finish_reason="length",
        )


def _stage5_calls(client: MockLLMClient) -> list[Any]:
    return [call for call in client.calls if _is_stage5(call.response_format)]


def test_a_truncated_reply_is_retried_concisely_and_recovers(tmp_path: Path) -> None:
    client = _TruncatingClient(_setup_mock_client(num_threats=1), truncated={0})

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=1),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
    )

    first, retry = _stage5_calls(client)
    assert first.max_completion_tokens == generate._BDI_MAX_COMPLETION_TOKENS
    assert retry.max_completion_tokens == generate._LENGTH_RETRY_MAX_COMPLETION_TOKENS
    assert retry.user_prompt == first.user_prompt + generate._LENGTH_RETRY_PROMPT
    assert [outcome.status for outcome in result.candidate_outcomes] != [
        SP3CandidateStatus.generation_failed
    ]
    assert not any("Stage 5 BDI generation failed" in e for e in result.stage_errors)


def test_a_failed_retry_after_a_truncated_reply_does_not_stop_later_threats(
    tmp_path: Path,
) -> None:
    client = _TruncatingClient(_setup_mock_client(num_threats=2), truncated={0, 1})

    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=tmp_path,
    )

    # Two truncated calls for the first threat, then one call for the second.
    assert len(_stage5_calls(client)) == 3
    statuses = [outcome.status for outcome in result.candidate_outcomes]
    assert statuses[0] == SP3CandidateStatus.generation_failed
    assert statuses[1] != SP3CandidateStatus.generation_failed
    joined = "\n".join(result.stage_errors)
    assert generate._TRUNCATED_RETRY_FAILED_PREFIX in joined
    assert "retry exhausted" not in joined.lower()
    assert "remaining threats" not in joined


def test_the_client_reports_the_provider_finish_reason() -> None:
    provider = _Provider(lambda **_: _completion('{"answer": ', finish_reason="length"))

    result = _client(provider).complete("s", "u")

    assert result.finish_reason == "length"
    assert result.raw_response == '{"answer": '
