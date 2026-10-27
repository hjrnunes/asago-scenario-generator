"""ICA fill stops at the first provider rejection of its request schema.

A provider answers HTTP 400 to a request whose response schema it cannot
compile, and it rejects every later slot request of the same fill the same
way.  The fill therefore sends no further slot request after the first such
rejection, names the failure ``request_schema_rejected``, and the run fails.
Any other per-slot failure leaves the fill going on to the next slot.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, replace
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
from asago_scenario_generator.pipeline import synthesis as synthesis_module
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    SynthesisRunStatus,
    run_synthesis,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _scenario_generation_status,
)
from asago_scenario_generator.pipeline.synthesis_types import StageRun
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.prompt_preflight import PromptBudget
from asago_scenario_generator.stpa.infra.provider_record import (
    ReplayedProviderError,
    _error_record,
    _rebuild_error,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    IcaDeviationDraft,
    IcaFindingDraft,
    SlotFillFailure,
    SlotIcaDraft,
    SynthesisSlotResponse,
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
    create_slots,
    requires_provider_slot_analysis,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    _routed_slot_draft,
    provider_slot_payload,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.scripted_client import ScriptedClient
from tests.helpers.slot_fill_budget_split import (
    _COMPLETION,
    _prompt_tokens,
)
from tests.helpers.synthesis import _FakeAdapters, _inputs
from tests.test_synthesis_prompt_contract_status import _invoke_cli

_SLOT_ID = re.compile(r"^\s*id: (RESP-1:\S+)$", re.MULTILINE)
_SCHEMA_MESSAGE = (
    "The provided JSON schema contains features not supported by xgrammar."
)
_COMPILATION_MESSAGE = "JSON schema compilation failed: unsupported keyword oneOf"
# A 400 that mentions the schema without rejecting it.
_SCHEMA_CONTEXT_MESSAGE = (
    "Context length exceeded: messages and schema total 9000 tokens, limit 8192"
)
# A context-length 400 whose clause after the colon reads like a rejection.
_CONTEXT_SCHEMA_MESSAGE = (
    "Context length exceeded: invalid combined size of messages and schema"
)
# A 400 about another parameter that mentions the request schema.
_TOP_K_SCHEMA_MESSAGE = "Invalid value for top_k under the request schema"
_TOP_K = {"param": "top_k"}
_GRAMMAR_MESSAGE = "Failed to convert json_schema to grammar"
_FORMAT_TYPE_MESSAGE = (
    "Invalid value: 'json_schema'. Supported values are: 'json_object' and 'text'."
)
_FORMAT_TYPE = {"param": "response_format.type"}
_CONTEXT_MESSAGE = (
    "This model's maximum context length is 8192 tokens. However, you "
    "requested 9000 tokens."
)


def _bad_request(
    message: str, *, status: int = 400, extra: dict[str, Any] | None = None
) -> openai.APIStatusError:
    """Build the SDK error a provider's HTTP error reply raises, offline."""
    request = httpx.Request("POST", "http://provider.invalid/v1/chat/completions")
    body = {"object": "error", "message": message, "code": status, **(extra or {})}
    response = httpx.Response(status, request=request, json=body)
    error_type = openai.BadRequestError if status == 400 else openai.InternalServerError
    return error_type(f"Error code: {status} - {body}", response=response, body=body)


def _replayed(error: BaseException) -> BaseException:
    """Record *error* as a provider call does, then rebuild it as a replay does.

    The rebuilt error keeps the recorded status and text, but not the body.
    """
    return _rebuild_error(_error_record(error))


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
        assert filled.fill_failure == SlotFillFailure(
            code=REQUEST_SCHEMA_REJECTED,
            call_id=filled.call_evidence[0].call_id,
            unsent_requests=_provider_slot_count(filled) - 1,
        )


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
        assert filled.fill_failure is None


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (_bad_request(_SCHEMA_MESSAGE), True),
        (_bad_request("Invalid schema for response_format 'Payload'"), True),
        (_bad_request("Invalid JSON schema: unknown keyword"), True),
        (_bad_request("Failed to compile the JSON schema into a grammar"), True),
        (
            _bad_request(
                "Unsupported value: 'json_schema'",
                extra={"param": "response_format"},
            ),
            True,
        ),
        (
            _bad_request(
                "Cannot compile the JSON schema for response_format: "
                "unsupported keyword oneOf"
            ),
            True,
        ),
        (
            _bad_request(
                "Unable to compile the response schema: unsupported keyword oneOf"
            ),
            True,
        ),
        (_bad_request(_COMPILATION_MESSAGE), True),
        (_bad_request("response_format schema is invalid"), True),
        (_bad_request("schema contains unsupported keyword oneOf"), True),
        (_bad_request("The output schema could not be parsed"), True),
        (_bad_request("Response schema is not supported by the backend"), True),
        (_bad_request("Output schema is not valid JSON Schema"), True),
        (_bad_request("Bad request", extra={"code": "invalid_json_schema"}), True),
        (_bad_request("Bad request", extra={"code": "invalid_schema"}), True),
        (_replayed(_bad_request(_COMPILATION_MESSAGE)), True),
        (_replayed(_bad_request("Bad", extra={"param": "response_format"})), True),
        (_bad_request(_CONTEXT_MESSAGE), False),
        (_bad_request(_SCHEMA_CONTEXT_MESSAGE), False),
        (_bad_request("The JSON schema is invalid for 8192 context tokens"), False),
        (_bad_request("Invalid value for 'top_k': must be positive"), False),
        (_bad_request("Unsupported parameter", extra={"param": "top_k"}), False),
        (_replayed(_bad_request("Unsupported", extra={"param": "top_k"})), False),
        (_replayed(_bad_request(_SCHEMA_CONTEXT_MESSAGE)), False),
        (_bad_request(_SCHEMA_MESSAGE, status=500), False),
        (_bad_request(_CONTEXT_SCHEMA_MESSAGE), False),
        (_replayed(_bad_request(_CONTEXT_SCHEMA_MESSAGE)), False),
        (_bad_request(_TOP_K_SCHEMA_MESSAGE, extra=_TOP_K), False),
        (_replayed(_bad_request(_TOP_K_SCHEMA_MESSAGE, extra=_TOP_K)), False),
        (_bad_request(_TOP_K_SCHEMA_MESSAGE), False),
        (_replayed(_bad_request(_TOP_K_SCHEMA_MESSAGE)), False),
        (_bad_request("Bad request", extra={"param": "response_format_x"}), False),
        (
            _bad_request(
                _SCHEMA_MESSAGE, extra={"param": "top_k", "code": "invalid_value"}
            ),
            False,
        ),
        (_bad_request(_GRAMMAR_MESSAGE), True),
        (_replayed(_bad_request(_GRAMMAR_MESSAGE)), True),
        (_bad_request(_FORMAT_TYPE_MESSAGE, extra=_FORMAT_TYPE), True),
        (_replayed(_bad_request(_FORMAT_TYPE_MESSAGE, extra=_FORMAT_TYPE)), True),
        (_bad_request(_FORMAT_TYPE_MESSAGE), True),
        (_replayed(_bad_request(_FORMAT_TYPE_MESSAGE)), True),
        (_bad_request("Bad request", extra={"param": "response_format[0]"}), True),
        (
            _bad_request(
                "Bad request", extra={"param": "response_format.json_schema.schema"}
            ),
            True,
        ),
        (ReplayedProviderError("BadRequestError", _SCHEMA_MESSAGE, 400), True),
        (ReplayedProviderError("BadRequestError", _CONTEXT_MESSAGE, 400), False),
        (ValueError(_SCHEMA_MESSAGE), False),
        (None, False),
    ],
)
def test_classification(error: BaseException | None, expected: bool) -> None:
    assert is_request_schema_rejection(error) is expected


def _caused(error: BaseException, cause: BaseException) -> BaseException:
    """Return *error* raised from *cause*."""
    try:
        try:
            raise cause
        except BaseException as caught:
            raise error from caught
    except BaseException as raised:
        return raised


def test_the_classification_reads_the_cause_of_a_slot_failure() -> None:
    error = _caused(
        ValueError("slot provider returned no payload"), _bad_request(_SCHEMA_MESSAGE)
    )
    assert is_request_schema_rejection(error)


def test_a_generic_400_wrapping_a_schema_rejection_is_one() -> None:
    error = _caused(
        ReplayedProviderError("BadRequestError", "Bad request", 400),
        _bad_request(_SCHEMA_MESSAGE),
    )
    assert is_request_schema_rejection(error)


def test_a_generic_400_wrapping_another_400_is_not_one() -> None:
    error = _caused(
        ReplayedProviderError("BadRequestError", "Bad request", 400),
        _bad_request(_SCHEMA_CONTEXT_MESSAGE),
    )
    assert not is_request_schema_rejection(error)


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


class _SplitRejectingAdapter:
    """Accept each slot's first request part; reject a later part's schema."""

    def __init__(self, usable_input_tokens: int) -> None:
        self.prompt_budget = PromptBudget(
            context_window=_COMPLETION + usable_input_tokens,
            maximum_completion_tokens=_COMPLETION,
            safety_margin=0,
        )
        self.parts: list[str] = []

    def fill(self, request):
        slot_id = request.slots[0].slot_id
        if slot_id in self.parts:
            self.parts.append(slot_id)
            # The provider adapter raises its call failure as the cause.
            raise _caused(
                ValueError("slot provider returned no payload"),
                _bad_request(_SCHEMA_MESSAGE),
            )
        self.parts.append(slot_id)
        return SynthesisSlotResponse(
            adapter_kind="fake",
            request_digest=request.semantic_digest,
            filled_slots=tuple(
                _routed_slot_draft(
                    slot,
                    [r for r in request.routed_routes if slot.slot_id in r.slot_ids],
                )
                for slot in request.slots
            ),
        )


def test_a_rejected_later_part_of_the_last_slot_fails_the_run() -> None:
    briefs = build_neutral_briefs(
        make_plan(risk_ids=("risk-a", "risk-b", "risk-c")),
        (AttackPattern.model_validate(get_test_raw_pattern()),),
    )
    last = [
        slot
        for slot in create_slots(_control_structure())
        if requires_provider_slot_analysis(slot)
    ][-1]
    routes = tuple(
        ObligationRoute(
            obligation_id=brief.obligation_id,
            disposition="targeted",
            slot_ids=(last.slot_id,),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=(f"route-{index}",),
        )
        for index, brief in enumerate(briefs)
    )
    adapter = _SplitRejectingAdapter(_prompt_tokens(briefs, routes[:2], last))

    filled = fill_synthesis_slots(
        adapter,
        briefs=briefs,
        routes=routes,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )

    # The rejected part was the fill's last request, and its slot kept the
    # first part's fill, so no lost slot carries the failure name.
    assert adapter.parts[-2:] == [last.slot_id, last.slot_id]
    assert REQUEST_SCHEMA_REJECTED in {item.code for item in filled.diagnostics}
    assert REQUEST_SCHEMA_REJECTED not in {
        item.error_class for item in filled.lost_slots
    }
    assert filled.fill_failure == SlotFillFailure(
        code=REQUEST_SCHEMA_REJECTED,
        call_id=filled.call_evidence[-1].call_id,
        unsent_requests=0,
    )
    counts = {"requested": 0, "attempted": 0, "generated": 0}
    status, reason = _scenario_generation_status(
        counts, fill_failure=filled.fill_failure
    )
    assert status is SynthesisRunStatus.FAILED
    assert reason.startswith(f"{REQUEST_SCHEMA_REJECTED}: ")
    assert _scenario_generation_status(counts)[0] is SynthesisRunStatus.NO_CANDIDATES


class _FindingThenRejectingClient(ScriptedClient):
    """Answer the first slot request with a finding; reject every later schema."""

    def complete(self, **kwargs: Any) -> LLMResult:
        self.calls.append(kwargs)
        if len(self.calls) > 1:
            raise _bad_request(_SCHEMA_MESSAGE)
        match = _SLOT_ID.search(kwargs["user_prompt"])
        assert match is not None and match.group(1) == "RESP-1:CA-1-1:INCORRECT"
        draft = SlotIcaDraft(
            slot_id=match.group(1),
            is_na=False,
            findings=(
                IcaFindingDraft(
                    deviation=IcaDeviationDraft(
                        incorrect_value_or_effect=(
                            "the request is checked against outdated rules"
                        )
                    ),
                    hazardous_context="the unreviewed request reaches the process",
                    loss_consequence="the protected operation is harmed",
                    related_hazard_ids=("H-1",),
                    related_constraint_ids=("SC-1",),
                ),
            ),
        )
        return LLMResult(
            content={"filled_slots": [provider_slot_payload(draft)]},
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
        )


class _CountingVerifier:
    """Stand for the model-backed ICA hazard verifier; count each request."""

    def __init__(self) -> None:
        self.requests: list[Any] = []

    def verify_ica_hazards(self, requests: Any, **_: Any) -> Any:
        self.requests.append(requests)
        raise AssertionError("the ICA verifier sent a request after the stop")


def test_no_later_model_backed_stage_sends_a_request(tmp_path, monkeypatch) -> None:
    fake = _SchemaRejectedRun(calls=[], client=_FindingThenRejectingClient([]))
    verifier = _CountingVerifier()
    target_realizations: list[Any] = []
    monkeypatch.setattr(
        synthesis_module,
        "_run_target_realization",
        lambda **kwargs: target_realizations.append(kwargs) or StageRun(None),
    )
    adapters = replace(SynthesisAdapters.from_object(fake), obligation_adapter=verifier)

    result = run_synthesis(_inputs(tmp_path), adapters)

    assert len(fake.client.calls) == 2
    assert verifier.requests == []
    assert target_realizations == []
    assert "scenarios" not in [name for name, _ in fake.calls]
    assert result.run_status == "failed"
    assert result.ica_enumeration.slots[0].icas
    assert result.manifest["provider_evidence"]["ica"]["fill_failure"] == {
        "code": REQUEST_SCHEMA_REJECTED,
        "call_id": "stpa-slot:RESP-1:part-2",
        "unsent_requests": 1,
    }
    assert (tmp_path / "obligation-accounting.yaml").exists()
    assert result.report_path is not None and result.report_path.exists()


@pytest.mark.parametrize(
    "error",
    [
        _bad_request(_COMPILATION_MESSAGE),
        _replayed(_bad_request(_COMPILATION_MESSAGE)),
    ],
    ids=["sdk-error", "replayed-error"],
)
def test_a_compilation_rejection_stops_the_fill_and_fails_the_run(
    tmp_path, error
) -> None:
    fake = _SchemaRejectedRun(calls=[], client=_FailingClient(error, every=True))

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert len(fake.client.calls) == 1
    slot_rows = [row for row in read_calls_jsonl(tmp_path) if "icas" in row["stage"]]
    assert len(slot_rows) == 1
    assert slot_rows[0]["success"] is False
    assert _COMPILATION_MESSAGE in slot_rows[0]["error"]
    failure = result.manifest["provider_evidence"]["ica"]["fill_failure"]
    assert failure["code"] == REQUEST_SCHEMA_REJECTED
    assert failure["unsent_requests"] > 0
    assert result.run_status == "failed"
    assert result.manifest["run_status_reason"].startswith(
        f"{REQUEST_SCHEMA_REJECTED}: "
    )


_SHAPES = {"sdk": lambda error: error, "replayed": _replayed}


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize(
    ("message", "extra"),
    [(_CONTEXT_SCHEMA_MESSAGE, None), (_TOP_K_SCHEMA_MESSAGE, _TOP_K)],
    ids=["context-length-with-colon", "top-k-param"],
)
def test_a_400_that_is_not_a_schema_rejection_keeps_the_run_filling(
    tmp_path, message, extra, shape
) -> None:
    error = _SHAPES[shape](_bad_request(message, extra=extra))
    fake = _SchemaRejectedRun(calls=[], client=_FailingClient(error))

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert len(fake.client.calls) > 1
    assert "fill_failure" not in result.manifest["provider_evidence"]["ica"]
    assert result.run_status != "failed"


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize(
    ("message", "extra"),
    [(_GRAMMAR_MESSAGE, None), (_FORMAT_TYPE_MESSAGE, _FORMAT_TYPE)],
    ids=["json-schema-to-grammar", "response-format-type-param"],
)
def test_a_schema_rejection_stops_the_run_after_one_request(
    tmp_path, message, extra, shape
) -> None:
    error = _SHAPES[shape](_bad_request(message, extra=extra))
    fake = _SchemaRejectedRun(calls=[], client=_FailingClient(error, every=True))

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert len(fake.client.calls) == 1
    failure = result.manifest["provider_evidence"]["ica"]["fill_failure"]
    assert failure["code"] == REQUEST_SCHEMA_REJECTED
    assert result.run_status == "failed"
