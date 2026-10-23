"""A null in a field the selected union branch requires is repaired as a null.

A flat reply sets the fields its branch does not use to null.  When the
model also writes null in a field its own branch requires, the repair
request names that field and says the value may not be null, rather than
reporting the field as missing.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, Field, ValidationError

from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
    compact_validation_error,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _routing_provider_payload_type,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    _routing_validation_feedback,
)
from tests.helpers.discriminating_condition import (
    _generate,
    _ownership_condition,
    _payload_with,
)
from tests.helpers.provider_call_record import _client, _completion, _Provider
from tests.stpa.sp1_helpers import MockLLMClient

_ROUTING = _routing_provider_payload_type(1)
_ERROR_BLOCK = "Exact validation error from the prior response:\n"


def _upstream_gap_route(missing_concepts: Any) -> dict[str, Any]:
    return {
        "obligation_id": "ob:v1:" + "0" * 64,
        "semantic_assessment": {
            "mechanism_assessment": "absent_from_system",
            "risk_alignment": "supported",
            "mechanism_rationale": "No payment process is modelled.",
            "risk_alignment_rationale": "It realizes the risk.",
        },
        "rationale": "The payment process is missing.",
        "evidence": ["RESP-1 handles refunds."],
        "disposition": "upstream_gap",
        "targeting": None,
        "missing_concepts": missing_concepts,
    }


def _routing_feedback(tmp_path: Path, route: dict[str, Any]) -> str:
    text = json.dumps({"routes": [route]})
    outcome = call_with_policy(
        llm_client=_client(_Provider(lambda **_: _completion(text))),
        system_prompt="s",
        user_prompt="u",
        response_format=_ROUTING,
        run_dir=tmp_path,
        stage="stage_x",
        step="route",
        policy=CorrectionPolicy(validation_retries=0),
    )
    assert outcome.value is None
    # The provider raises the call's error; the router repairs from it.
    return _routing_validation_feedback(ValueError(outcome.error))


def test_an_upstream_gap_with_null_missing_concepts_asks_for_them(
    tmp_path: Path,
) -> None:
    feedback = _routing_feedback(tmp_path, _upstream_gap_route(None))

    assert "routes.0.upstream_gap.missing_concepts" in feedback
    assert "Input should be a valid tuple" in feedback
    assert "input_value=None" in feedback
    assert "Field required" not in feedback
    assert "upstream_gap requires non-empty missing_concepts" in feedback
    assert "missing_route_rationale" not in feedback


def test_a_valid_upstream_gap_route_still_validates(tmp_path: Path) -> None:
    concept = {
        "concept_type": "controlled_process",
        "description": "No payment process is modelled.",
        "concept_id": None,
        "evidence_refs": ["RESP-1"],
        "obligation_id": None,
    }
    text = json.dumps({"routes": [_upstream_gap_route([concept])]})
    outcome = call_with_policy(
        llm_client=_client(_Provider(lambda **_: _completion(text))),
        system_prompt="s",
        user_prompt="u",
        response_format=_ROUTING,
        run_dir=tmp_path,
        stage="stage_x",
        step="route",
        policy=CorrectionPolicy(validation_retries=0),
    )
    assert outcome.error is None
    assert outcome.value is not None
    assert outcome.value.routes[0].missing_concepts[0].concept_id is None


def _stage5_correction(tmp_path: Path, first: dict[str, Any]) -> str:
    client = MockLLMClient()
    client.set_response_queue([first, _payload_with(_ownership_condition("ORD-2"))])
    result, error = _generate(client, tmp_path)
    assert error is None and result is not None
    assert client.call_count == 2
    return client.calls[1].user_prompt


def _error_block(correction: str) -> str:
    return correction[correction.index(_ERROR_BLOCK) + len(_ERROR_BLOCK) :]


def test_a_stage5_null_adversary_gain_is_reported_as_a_null(tmp_path: Path) -> None:
    first = _payload_with(_ownership_condition("ORD-2"))
    first["adversary"]["gain"] = None

    error = _error_block(_stage5_correction(tmp_path, first))

    assert error.startswith(
        "ValidationError:\n- adversary.malicious_customer.gain: "
        "Input should be a valid string, not null (string_type)\n"
    )
    assert "(missing)" not in error


def test_a_stage5_null_delay_is_reported_with_the_temporal_guidance(
    tmp_path: Path,
) -> None:
    first = _payload_with(_ownership_condition("ORD-2"))
    # The flat form: the delay branch's own field is null, and so are the
    # fields of the other temporal branches, which the restore drops.
    first["causal_factors"][0]["temporal_condition"] = {
        "type": "delay",
        "reference_handle": "target_action",
        "delay_ms": None,
        "relation": None,
        "duration_ms": None,
        "window_from_ms": None,
        "window_to_ms": None,
        "until_step_handle": None,
    }

    correction = _stage5_correction(tmp_path, first)

    # delay_ms takes a placeholder or a scalar, so it fails once per form.
    assert (
        "- causal_factors.0.structural_failure.temporal_condition.delay.delay_ms.int: "
        "Input should be a valid integer, not null (int_type)\n"
    ) in correction
    assert "missing_temporal_branch_field: " in correction
    error = _error_block(correction)
    assert "(missing)" not in error
    assert "relation" not in error


class _Plain(BaseModel):
    count: int
    label: str = Field(min_length=1)


def test_only_a_type_failure_on_a_null_is_called_null() -> None:
    with pytest.raises(ValidationError) as caught:
        _Plain.model_validate({"count": "many", "label": ""})
    lines = compact_validation_error(caught.value).splitlines()
    assert lines[1:] == [
        "- count: Input should be a valid integer, unable to parse string as an "
        "integer (int_parsing)",
        "- label: String should have at least 1 character (string_too_short)",
    ]
    with pytest.raises(ValidationError) as caught:
        _Plain.model_validate({"count": None, "label": None})
    assert compact_validation_error(caught.value).splitlines()[1:] == [
        "- count: Input should be a valid integer, not null (int_type)",
        "- label: Input should be a valid string, not null (string_type)",
    ]
