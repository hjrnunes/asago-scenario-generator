"""ICA fill stops when two consecutive slot requests get the same HTTP 400.

The schema-rejection classifier reads a 400's fields and wording, so it can
miss a provider's rejection of the request itself.  Such a provider then
rejects every slot request alike, so two consecutive slot requests whose
HTTP 400 replies have the same recorded text stop the fill after the second,
named ``request_rejection_repeated``, and the run fails as for a classified
schema rejection.  The second request is sent, recorded, and counted.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

import pytest
import yaml

from asago_scenario_generator.models.obligation_consideration import (
    REQUEST_REJECTION_REPEATED,
    REQUEST_SCHEMA_REJECTED,
)
from asago_scenario_generator.pipeline import synthesis as synthesis_module
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    run_synthesis,
)
from asago_scenario_generator.pipeline.synthesis_types import StageRun
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.provider_record import (
    ReplayFill,
    provider_call_session,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SlotFillFailure,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    fill_synthesis_slots,
    repeatable_rejection,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_aware import _controls
from tests.helpers.provider_call_record import _Provider, _client, _records
from tests.helpers.scripted_client import ScriptedClient
from tests.helpers.synthesis import _FakeAdapters, _inputs
from tests.test_ica_fill_schema_rejection import (
    _CONTEXT_MESSAGE,
    _SCHEMA_MESSAGE,
    _SLOT_ID,
    _TOP_K,
    _CountingVerifier,
    _bad_request,
    _caused,
    _fill,
    _provider_slot_count,
    _replayed,
)
from tests.test_synthesis_prompt_contract_status import _invoke_cli

# A 400 the classifier does not flag: it names another parameter.
_TOP_K_MESSAGE = "Unsupported parameter: top_k"
_ICA_STAGE = "synthesis_obligation_aware_icas"


def _unflagged(message: str = _TOP_K_MESSAGE) -> Any:
    return _bad_request(message, extra=_TOP_K)


def _na_reply(kwargs: Any) -> LLMResult:
    """Answer the request's own slot N/A."""
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


class _SequenceClient(ScriptedClient):
    """Give the n-th request ``outcome(n)``: an error to raise, or ``None``.

    ``None`` answers the request's slot N/A.
    """

    def __init__(self, outcome: Callable[[int], BaseException | None]) -> None:
        super().__init__([])
        self._outcome = outcome

    def complete(self, **kwargs: Any) -> LLMResult:
        self.calls.append(kwargs)
        error = self._outcome(len(self.calls))
        if error is not None:
            raise error
        return _na_reply(kwargs)


def _always(error: BaseException) -> _SequenceClient:
    return _SequenceClient(lambda _n: error)


def _script(*outcomes: BaseException | None) -> _SequenceClient:
    """Give each request its outcome in turn; answer every later one N/A."""
    return _SequenceClient(lambda n: outcomes[n - 1] if n <= len(outcomes) else None)


class TestTwoIdenticalUnflaggedRejections:
    def test_exactly_two_requests_are_sent_and_recorded(self, tmp_path) -> None:
        client = _always(_unflagged())

        filled = _fill(tmp_path, client)

        assert _provider_slot_count(filled) > 2
        assert len(client.calls) == 2
        rows = read_calls_jsonl(tmp_path)
        assert len(rows) == 2
        assert [row["success"] for row in rows] == [False, False]
        assert all(_TOP_K_MESSAGE in row["error"] for row in rows)
        assert [item.attempt_count for item in filled.call_evidence][:3] == [1, 1, 0]

    def test_the_fill_failure_names_the_second_request(self, tmp_path) -> None:
        filled = _fill(tmp_path, _always(_unflagged()))

        assert filled.fill_failure == SlotFillFailure(
            code=REQUEST_REJECTION_REPEATED,
            call_id=filled.call_evidence[1].call_id,
            unsent_requests=_provider_slot_count(filled) - 2,
        )

    def test_the_first_rejection_keeps_its_per_slot_name(self, tmp_path) -> None:
        filled = _fill(tmp_path, _always(_unflagged()))

        codes = sorted(item.code for item in filled.diagnostics)
        assert codes == [REQUEST_REJECTION_REPEATED] * (len(codes) - 1) + [
            "slot_response_unresolved"
        ]
        first = filled.call_evidence[0].call_id
        by_call = {item.call_id: item.error_class for item in filled.lost_slots}
        assert by_call.pop(first) != REQUEST_REJECTION_REPEATED
        assert set(by_call.values()) == {REQUEST_REJECTION_REPEATED}
        assert REQUEST_SCHEMA_REJECTED not in codes


class TestPrecedence:
    def test_a_classified_rejection_stops_on_the_first_request(self, tmp_path) -> None:
        client = _always(_bad_request(_SCHEMA_MESSAGE))

        filled = _fill(tmp_path, client)

        assert len(client.calls) == 1
        assert filled.fill_failure is not None
        assert filled.fill_failure.code == REQUEST_SCHEMA_REJECTED

    def test_a_classified_rejection_after_an_unflagged_one_is_named_so(
        self, tmp_path
    ) -> None:
        client = _script(_unflagged(), _bad_request(_SCHEMA_MESSAGE))

        filled = _fill(tmp_path, client)

        assert len(client.calls) == 2
        assert filled.fill_failure is not None
        assert filled.fill_failure.code == REQUEST_SCHEMA_REJECTED
        assert filled.fill_failure.call_id == filled.call_evidence[1].call_id


def _numbered(n: int) -> BaseException:
    return _unflagged(f"{_TOP_K_MESSAGE} (request {n})")


class TestTheFillGoesOn:
    @pytest.mark.parametrize(
        "client",
        [
            pytest.param(lambda: _always(_bad_request(_CONTEXT_MESSAGE)), id="context"),
            pytest.param(
                lambda: _always(_replayed(_bad_request(_CONTEXT_MESSAGE))),
                id="replayed-context",
            ),
            pytest.param(lambda: _SequenceClient(_numbered), id="bodies-differ"),
            pytest.param(
                lambda: _script(_unflagged(), None, _unflagged()), id="success"
            ),
            pytest.param(
                lambda: _script(
                    _unflagged(),
                    _bad_request("upstream failed", status=500),
                    _unflagged(),
                ),
                id="5xx",
            ),
            pytest.param(
                lambda: _script(
                    _unflagged(), ValueError("the reply does not decode"), _unflagged()
                ),
                id="local-error",
            ),
        ],
    )
    def test_without_two_consecutive_identical_400s(self, tmp_path, client) -> None:
        scripted = client()

        filled = _fill(tmp_path, scripted)

        assert len(scripted.calls) == _provider_slot_count(filled) >= 3
        assert filled.fill_failure is None
        assert REQUEST_REJECTION_REPEATED not in {
            item.code for item in filled.diagnostics
        }


class TestRepeatableRejection:
    def test_a_live_reply_and_its_replay_compare_alike(self) -> None:
        live = _unflagged()

        assert repeatable_rejection(live) is not None
        assert repeatable_rejection(live) == repeatable_rejection(_replayed(live))

    def test_the_text_holds_the_reply_body(self) -> None:
        text = repeatable_rejection(_unflagged())

        assert text is not None
        assert "'param': 'top_k'" in text and _TOP_K_MESSAGE in text

    def test_the_cause_chain_is_read(self) -> None:
        error = _caused(ValueError("slot provider returned no payload"), _unflagged())

        assert repeatable_rejection(error) == repeatable_rejection(_unflagged())

    @pytest.mark.parametrize(
        "error",
        [
            _bad_request(_SCHEMA_MESSAGE),
            _bad_request(_CONTEXT_MESSAGE),
            _bad_request(_TOP_K_MESSAGE, status=500),
            ValueError(_TOP_K_MESSAGE),
            None,
        ],
        ids=["schema-rejection", "context-length", "5xx", "local", "none"],
    )
    def test_other_failures_have_no_repeatable_text(self, error) -> None:
        assert repeatable_rejection(error) is None


@dataclass
class _RejectedRun(_FakeAdapters):
    """Fill the run's slots for real through *client*."""

    client: Any = field(default_factory=lambda: _always(_unflagged()))

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


_REASON = (
    f"{REQUEST_REJECTION_REPEATED}: the provider gave two consecutive ICA fill "
    "requests the same HTTP 400 reply, the second at "
)


class TestTheRunFails:
    def test_the_manifest_names_the_failure(self, tmp_path) -> None:
        fake = _RejectedRun(calls=[])

        result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

        assert len(fake.client.calls) == 2
        manifest = yaml.safe_load(
            (tmp_path / "synthesis-manifest.yaml").read_text(encoding="utf-8")
        )
        assert manifest["run_status"] == "failed"
        assert manifest["run_status_reason"].startswith(_REASON)
        failure = manifest["provider_evidence"]["ica"]["fill_failure"]
        assert failure["code"] == REQUEST_REJECTION_REPEATED
        assert failure["unsent_requests"] > 0
        lost = manifest["provider_evidence"]["ica"]["lost_slots"]
        assert REQUEST_REJECTION_REPEATED in {item["error_class"] for item in lost}
        assert result.run_status == "failed"

    def test_no_later_model_backed_stage_sends_a_request(
        self, tmp_path, monkeypatch
    ) -> None:
        fake = _RejectedRun(calls=[])
        verifier = _CountingVerifier()
        target_realizations: list[Any] = []
        monkeypatch.setattr(
            synthesis_module,
            "_run_target_realization",
            lambda **kwargs: target_realizations.append(kwargs) or StageRun(None),
        )
        adapters = replace(
            SynthesisAdapters.from_object(fake), obligation_adapter=verifier
        )

        result = run_synthesis(_inputs(tmp_path), adapters)

        assert len(fake.client.calls) == 2
        assert verifier.requests == []
        assert target_realizations == []
        assert "scenarios" not in [name for name, _ in fake.calls]
        assert result.run_status == "failed"
        assert (tmp_path / "obligation-accounting.yaml").exists()
        assert result.report_path is not None and result.report_path.exists()

    def test_the_cli_exits_non_zero_and_names_the_failure(self, tmp_path) -> None:
        fake = _RejectedRun(calls=[])
        result = run_synthesis(
            _inputs(tmp_path / "run"), SynthesisAdapters.from_object(fake)
        )

        cli = _invoke_cli(tmp_path, result)

        assert cli.exit_code == 1
        assert "Scenario generation: failed" in cli.stdout
        assert f"ICA fill stopped ({REQUEST_REJECTION_REPEATED}: " in cli.stderr


def _rejecting_provider() -> _Provider:
    """An SDK stand-in answering every request with the same unflagged 400."""

    def respond(**_kwargs: Any) -> Any:
        raise _unflagged()

    return _Provider(respond)


def _recorded_run(directory: Path, **session: Any) -> tuple[Any, _Provider]:
    """Run synthesis through a provider call session; return result and SDK."""
    provider = _rejecting_provider()
    with provider_call_session(record_dir=directory / "record", **session) as calls:
        fake = _RejectedRun(calls=[], client=_client(provider, session=calls))
        result = run_synthesis(
            _inputs(directory / "run"), SynthesisAdapters.from_object(fake)
        )
    return result, provider


class TestRecordedAndReplayed:
    def test_a_replayed_run_stops_identically(self, tmp_path) -> None:
        live, live_provider = _recorded_run(tmp_path / "live")

        replayed, replay_provider = _recorded_run(
            tmp_path / "replayed", replay_dir=tmp_path / "live" / "record"
        )

        assert len(live_provider.requests) == 2
        assert replay_provider.requests == []
        assert len(_records(tmp_path / "live" / "record")) == 2
        assert len(_records(tmp_path / "replayed" / "record")) == 2
        for result in (live, replayed):
            assert result.run_status == "failed"
            assert result.manifest["run_status_reason"].startswith(_REASON)
        assert (
            replayed.manifest["provider_evidence"]["ica"]["fill_failure"]
            == live.manifest["provider_evidence"]["ica"]["fill_failure"]
        )
        assert (
            replayed.manifest["run_status_reason"]
            == (live.manifest["run_status_reason"])
        )

    def test_the_second_rejection_counts_as_a_live_request(self, tmp_path) -> None:
        _recorded_run(tmp_path / "live")
        fill = ReplayFill(max_live_requests=2, live_stages=frozenset({_ICA_STAGE}))

        with provider_call_session(
            record_dir=tmp_path / "filled" / "record",
            replay_dir=tmp_path / "live" / "record",
            fill=fill,
        ) as calls:
            provider = _rejecting_provider()
            fake = _RejectedRun(calls=[], client=_client(provider, session=calls))
            result = run_synthesis(
                _inputs(tmp_path / "filled" / "run"),
                SynthesisAdapters.from_object(fake),
            )
            summary = calls.fill_summary()

        assert len(provider.requests) == 2
        assert summary is not None
        assert summary["live_requests_by_stage"] == {_ICA_STAGE: 2}
        records = _records(tmp_path / "filled" / "record")
        assert [record["source"] for record in records] == ["live", "live"]
        assert result.manifest["run_status_reason"].startswith(_REASON)
