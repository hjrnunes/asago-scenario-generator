"""ICA fill stops at the first provider rejection of its request schema.

A provider answers HTTP 400 to a request whose response schema it cannot
compile, and it rejects every later slot request of the same fill the same
way.  The fill therefore sends no further slot request after the first such
rejection, names the failure ``request_schema_rejected``, and the run fails.
Any other per-slot failure leaves the fill going on to the next slot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import openai
import pytest
import yaml

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_neutral_briefs,
)
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    run_synthesis,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.provider_record import (
    ReplayedProviderError,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware import slot_filling
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    REQUEST_SCHEMA_REJECTED,
    fill_synthesis_slots,
    is_request_schema_rejection,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    requires_provider_slot_analysis,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.scripted_client import ScriptedClient
from tests.helpers.synthesis import _FakeAdapters, _inputs
from tests.test_synthesis_prompt_contract_status import _invoke_cli

_SLOT_ID = re.compile(r"^\s*id: (RESP-1:\S+)$", re.MULTILINE)
_SCHEMA_MESSAGE = (
    "The provided JSON schema contains features not supported by xgrammar."
)
_CONTEXT_MESSAGE = (
    "This model's maximum context length is 8192 tokens. However, you "
    "requested 9000 tokens."
)


def _bad_request(message: str, *, status: int = 400) -> openai.APIStatusError:
    """Build the SDK error a provider's HTTP error reply raises, offline."""
    request = httpx.Request("POST", "http://provider.invalid/v1/chat/completions")
    body = {"object": "error", "message": message, "code": status}
    response = httpx.Response(status, request=request, json=body)
    error_type = openai.BadRequestError if status == 400 else openai.InternalServerError
    return error_type(f"Error code: {status} - {body}", response=response, body=body)


class _FailingClient(ScriptedClient):
    """Raise *first* for the first request; answer every later slot N/A."""

    def __init__(self, first: BaseException, *, every: bool = False) -> None:
        super().__init__([])
        self._first = first
        self._every = every

    def complete(self, **kwargs: Any) -> LLMResult:
        self.calls.append(kwargs)
        if self._every or len(self.calls) == 1:
            raise self._first
        # The prompt names its own slot first; route rows list other slots.
        match = _SLOT_ID.search(kwargs["user_prompt"])
        assert match is not None
        content = {
            "filled_slots": [
                {
                    "slot_id": match.group(1),
                    "is_na": True,
                    "na_rationale": "No routed concern applies.",
                    "findings": [],
                    "consideration_results": {},
                }
            ]
        }
        return LLMResult(
            content=content, prompt_tokens=1, completion_tokens=1, duration_ms=1
        )


def _fill(tmp_path: Path, client: ScriptedClient):
    """Fill every slot of the small structure; the first slot sent is routed."""
    plan = make_plan()
    briefs = build_neutral_briefs(
        plan, (AttackPattern.model_validate(get_test_raw_pattern()),)
    )
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=("RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="The validation path is structurally relevant.",
        evidence=("RESP-1", "H-1", "SC-1"),
    )
    return fill_synthesis_slots(
        ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls()),
        briefs=briefs,
        routes=(route,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )


def _provider_slot_ids(filled: Any) -> set[str]:
    """Name every slot the fill asks the provider to analyze."""
    return {
        slot.slot_id
        for request in filled.result.requests
        for slot in request.slots
        if requires_provider_slot_analysis(slot)
    }


def _provider_slot_count(filled: Any) -> int:
    """Count the slot requests the fill would send to the provider."""
    return sum(map(slot_filling._has_provider_slot, filled.result.requests))


class TestFirstRequestSchemaRejected:
    def test_exactly_one_request_is_sent(self, tmp_path) -> None:
        client = _FailingClient(_bad_request(_SCHEMA_MESSAGE), every=True)

        filled = _fill(tmp_path, client)

        assert _provider_slot_count(filled) > 1
        assert len(client.calls) == 1
        rows = read_calls_jsonl(tmp_path)
        assert len(rows) == 1
        assert rows[0]["success"] is False
        assert "BadRequestError" in rows[0]["error"]

    def test_the_failure_is_named_for_every_unfilled_slot(self, tmp_path) -> None:
        client = _FailingClient(_bad_request(_SCHEMA_MESSAGE), every=True)

        filled = _fill(tmp_path, client)

        codes = {item.code for item in filled.diagnostics}
        assert codes == {REQUEST_SCHEMA_REJECTED}
        assert filled.lost_slots
        assert {item.error_class for item in filled.lost_slots} == {
            REQUEST_SCHEMA_REJECTED
        }
        assert {item.slot_id for item in filled.lost_slots} == _provider_slot_ids(
            filled
        )
        assert [item.attempt_count for item in filled.call_evidence][:2] == [1, 0]


class TestOtherPerSlotFailures:
    @pytest.mark.parametrize(
        "error",
        [
            _bad_request(_CONTEXT_MESSAGE),
            _bad_request("upstream failed to compile the schema", status=500),
            ValueError("the reply does not decode"),
        ],
        ids=["400-context-length", "500-mentions-schema", "local-error"],
    )
    def test_the_fill_goes_on_to_the_next_slot(self, tmp_path, error) -> None:
        client = _FailingClient(error)

        filled = _fill(tmp_path, client)

        assert len(client.calls) == _provider_slot_count(filled)
        assert REQUEST_SCHEMA_REJECTED not in {item.code for item in filled.diagnostics}
        assert len(filled.lost_slots) == 1


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (_bad_request(_SCHEMA_MESSAGE), True),
        (_bad_request("Invalid schema for response_format 'Payload'"), True),
        (_bad_request(_CONTEXT_MESSAGE), False),
        (_bad_request(_SCHEMA_MESSAGE, status=500), False),
        (ReplayedProviderError("BadRequestError", _SCHEMA_MESSAGE, 400), True),
        (ReplayedProviderError("BadRequestError", _CONTEXT_MESSAGE, 400), False),
        (ValueError(_SCHEMA_MESSAGE), False),
        (None, False),
    ],
)
def test_classification(error: BaseException | None, expected: bool) -> None:
    assert is_request_schema_rejection(error) is expected


def test_the_classification_reads_the_cause_of_a_slot_failure() -> None:
    try:
        try:
            raise _bad_request(_SCHEMA_MESSAGE)
        except openai.BadRequestError as cause:
            raise ValueError("slot provider returned no payload") from cause
    except ValueError as error:
        assert is_request_schema_rejection(error)


@dataclass
class _SchemaRejectedRun(_FakeAdapters):
    """Fill the run's slots for real against a provider rejecting the schema."""

    client: ScriptedClient = field(
        default_factory=lambda: _FailingClient(
            _bad_request(_SCHEMA_MESSAGE), every=True
        )
    )

    def fill_icas(
        self, *, routes, briefs, loss_analysis, control_structure, output_dir, **_
    ) -> object:
        return fill_synthesis_slots(
            ObligationAwareLLMAdapter(
                self.client, run_dir=Path(output_dir), controls=_controls()
            ),
            briefs=briefs,
            routes=routes,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            controls=_controls(),
        )


class TestTheRunFails:
    def test_the_manifest_names_the_failure(self, tmp_path) -> None:
        fake = _SchemaRejectedRun(calls=[])

        result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

        assert len(fake.client.calls) == 1
        manifest = yaml.safe_load(
            (tmp_path / "synthesis-manifest.yaml").read_text(encoding="utf-8")
        )
        assert manifest["run_status"] == "failed"
        assert manifest["run_status_reason"].startswith(
            f"{REQUEST_SCHEMA_REJECTED}: the provider rejected the ICA fill "
        )
        lost = manifest["provider_evidence"]["ica"]["lost_slots"]
        assert {item["error_class"] for item in lost} == {REQUEST_SCHEMA_REJECTED}
        assert result.run_status == "failed"

    def test_the_cli_exits_non_zero_and_names_the_failure(self, tmp_path) -> None:
        fake = _SchemaRejectedRun(calls=[])
        result = run_synthesis(
            _inputs(tmp_path / "run"), SynthesisAdapters.from_object(fake)
        )

        cli = _invoke_cli(tmp_path, result)

        assert cli.exit_code == 1
        assert "Scenario generation: failed" in cli.stdout
        assert f"ICA fill stopped ({REQUEST_SCHEMA_REJECTED}: " in cli.stderr
