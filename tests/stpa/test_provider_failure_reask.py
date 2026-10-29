"""A caller-level re-ask follows an invalid reply, never a provider failure.

The client already makes the one transport retry it allows (HTTP 5xx, or a
connection error that is not a timeout) and never retries a timeout or a
4xx.  The routing, governance-routing, actionability and omitted-findings
re-asks therefore repeat only a reply that failed decoding or validation.
"""

from __future__ import annotations

import json
from pathlib import Path

import openai
import pytest
from pydantic import BaseModel, ValidationError

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    ProviderCallError,
    is_provider_failure,
)
from asago_scenario_generator.stpa.infra.provider_record import (
    ReplayedProviderError,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    route_governance_rows,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    _request_for_batch,
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    RiskActionabilityResponse,
    classify_risk_actionability,
)
from asago_scenario_generator.stpa.target_realization import (
    TargetDerivedICALlmFinder,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.risk_card import RiskCard
from tests.helpers.governance import _controls as _governance_controls
from tests.helpers.governance import _setup as _governance_setup
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.target_realization_provider import (
    _payment_draft,
    _payment_ica_request,
    _supported,
)
from tests.helpers.transport_retry import (
    _REQUEST,
    _connection_error,
    _status_error,
)
from tests.stpa.sp1_helpers import MockLLMClient

_INVALID_JSON = "THIS_IS_NOT_VALID_JSON{{{"


def _timeout() -> openai.APITimeoutError:
    return openai.APITimeoutError(request=_REQUEST)


# Provider failures as they reach a caller: the timeout and every 4xx the
# client never retries, and the 5xx and connection error its retry left.
_PROVIDER_FAILURES = {
    "timeout": _timeout,
    "400": lambda: _status_error(400),
    "429": lambda: _status_error(429),
    "500": lambda: _status_error(500),
    "connection": _connection_error,
}
_FAILURE_PARAMS = pytest.mark.parametrize(
    "make_failure",
    list(_PROVIDER_FAILURES.values()),
    ids=list(_PROVIDER_FAILURES),
)


class _Shape(BaseModel):
    value: int


def _validation_error() -> ValidationError:
    try:
        _Shape.model_validate({"value": "x"})
    except ValidationError as error:
        return error
    raise AssertionError("expected a validation error")


@_FAILURE_PARAMS
def test_a_provider_or_transport_error_is_a_provider_failure(make_failure) -> None:
    assert is_provider_failure(make_failure())


def test_a_replayed_provider_error_is_a_provider_failure() -> None:
    assert is_provider_failure(ReplayedProviderError("APIError", "replayed", 503))


@pytest.mark.parametrize(
    "error",
    [
        None,
        ValueError("routing response is bound to another request"),
        json.JSONDecodeError("Expecting value", "x", 0),
        _validation_error(),
        TypeError("unsupported response"),
    ],
    ids=["none", "value", "decode", "schema", "type"],
)
def test_an_invalid_reply_is_not_a_provider_failure(error) -> None:
    assert not is_provider_failure(error)


def test_a_provider_call_error_is_a_value_error() -> None:
    """Existing ``ValueError`` handlers still catch it as a failed call."""
    assert issubclass(ProviderCallError, ValueError)


# (a) Obligation routing.


def _brief():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return build_neutral_briefs(make_plan(), (pattern,))[0]


def _route_once(client: MockLLMClient, tmp_path: Path):
    controls = _controls().model_copy(update={"max_batch_size": 1})
    return route_obligations(
        ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=controls),
        briefs=(_brief(),),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=controls,
        max_batch_size=1,
    )


def test_the_routing_adapter_raises_a_provider_call_error(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_queue([_timeout()])
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())
    request = _request_for_batch(
        (_brief(),),
        batch_index=0,
        purpose="initial",
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
        controls=_controls(),
    )

    with pytest.raises(ProviderCallError):
        adapter.route(request)


@_FAILURE_PARAMS
def test_routing_makes_no_reask_after_a_provider_failure(
    tmp_path: Path, make_failure
) -> None:
    client = MockLLMClient()
    client.set_response_queue([make_failure(), _INVALID_JSON])

    result = _route_once(client, tmp_path)

    assert client.call_count == 1
    assert [route.disposition for route in result.routes] == ["unresolved"]
    assert result.call_evidence[0].attempt_count == 1


def test_routing_still_reasks_an_invalid_reply(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_queue([_INVALID_JSON, _INVALID_JSON])

    result = _route_once(client, tmp_path)

    assert client.call_count == 2
    assert "Validation correction:" in client.calls[1].user_prompt
    assert [route.disposition for route in result.routes] == ["unresolved"]


# (b) Governance routing.


class _GovernanceClient:
    model = "governance-provider-test"

    def __init__(self, *contents) -> None:
        self.session = None
        self.contents = list(contents)
        self.user_prompts: list[str] = []

    def complete(self, **kwargs):
        self.user_prompts.append(kwargs["user_prompt"])
        content = self.contents.pop(0)
        if isinstance(content, BaseException):
            raise content
        return LLMResult(
            content=content,
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _route_governance(client: _GovernanceClient, tmp_path: Path):
    briefs, selection, loss, structure = _governance_setup("risk-b")
    adapter = ObligationAwareLLMAdapter(
        client, run_dir=tmp_path, controls=_governance_controls()
    )
    return route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        controls=_governance_controls(),
    )


@_FAILURE_PARAMS
def test_governance_routing_makes_no_reask_after_a_provider_failure(
    tmp_path: Path, make_failure
) -> None:
    client = _GovernanceClient(make_failure(), _INVALID_JSON)

    result = _route_governance(client, tmp_path)

    assert len(client.user_prompts) == 1
    assert result.routes == ()
    assert result.call_evidence[0].attempt_count == 1
    assert result.call_evidence[0].outcome == "unresolved"


def test_governance_routing_still_reasks_an_invalid_reply(tmp_path: Path) -> None:
    client = _GovernanceClient(_INVALID_JSON, _INVALID_JSON)

    result = _route_governance(client, tmp_path)

    assert len(client.user_prompts) == 2
    assert result.call_evidence[0].attempt_count == 2


# (c) The risk-actionability retry step.


def _card(risk_id: str) -> RiskCard:
    return RiskCard(
        risk_id=risk_id,
        risk_name=f"Risk {risk_id}",
        risk_description=f"Description of {risk_id}",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )


def _classify(client: MockLLMClient, tmp_path: Path):
    return classify_risk_actionability(
        llm_client=client,
        use_case_text="A clinic assistant answers patient questions.",
        risk_cards=[_card("r-1")],
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
    )


@_FAILURE_PARAMS
def test_actionability_makes_no_retry_step_after_a_provider_failure(
    tmp_path: Path, make_failure
) -> None:
    client = MockLLMClient()
    client.set_exception_for(RiskActionabilityResponse, make_failure())

    outcome = _classify(client, tmp_path)

    assert client.call_count == 1
    assert outcome.record.call_count == 1
    assert outcome.record.entries[0].source == "fallback"


def test_actionability_still_retries_an_invalid_reply(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_invalid_response_for(RiskActionabilityResponse)

    outcome = _classify(client, tmp_path)

    # Each step sends its request and one JSON-decode repeat.
    assert client.call_count == 4
    assert outcome.record.call_count == 4


def test_a_provider_failure_in_the_json_repeat_ends_the_batch(
    tmp_path: Path,
) -> None:
    client = MockLLMClient()
    client.set_response_queue([_INVALID_JSON, _timeout(), _INVALID_JSON])

    outcome = _classify(client, tmp_path)

    assert client.call_count == 2
    assert outcome.record.call_count == 2
    assert outcome.record.entries[0].source == "fallback"


# (d) The omitted-findings verifier retry.


def _find(client: MockLLMClient, tmp_path: Path):
    finder = TargetDerivedICALlmFinder(client, tmp_path, temperature=0.4)
    return finder(_payment_ica_request())


@_FAILURE_PARAMS
def test_the_verifier_makes_no_retry_after_a_provider_failure(
    tmp_path: Path, make_failure
) -> None:
    client = MockLLMClient()
    client.set_response_queue(
        [_payment_draft("The payment action is not provided."), make_failure()]
    )

    response = _find(client, tmp_path)

    assert client.call_count == 2
    assert response.findings[0].verification.status == "unverified"


def test_the_verifier_still_retries_an_invalid_reply(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_queue(
        [
            _payment_draft("The payment action is not provided."),
            _INVALID_JSON,
            _supported(1),
        ]
    )

    response = _find(client, tmp_path)

    assert client.call_count == 3
    assert response.findings[0].verification.status == "verified"
