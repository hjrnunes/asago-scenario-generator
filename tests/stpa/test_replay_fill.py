"""Replay with live fill at the single provider seam.

A fill session serves every request the recording holds and sends the rest
through the normal client.  Every test here uses a fake provider; nothing
reaches a network.
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any

import openai
import pytest

from asago_scenario_generator.stpa.infra import transport_retry
from asago_scenario_generator.stpa.infra.provider_record import (
    RECORD_FILENAME,
    CallIdentity,
    LiveRequestBudgetError,
    ReplayFill,
    ReplayIncompleteError,
    call_identity,
    provider_call_session,
)
from tests.helpers.provider_call_record import (
    _Answer,
    _client,
    _completion,
    _Provider,
    _records,
)
from tests.helpers.transport_retry import _status_error


def _tagged(tag: str) -> _Provider:
    """A provider that answers ``<tag>:<user prompt>``."""
    return _Provider(
        lambda **kw: _completion(
            json.dumps({"answer": f"{tag}:{kw['messages'][-1]['content']}"})
        )
    )


def _ask(client: Any, stage: str, prompt: str) -> str:
    with call_identity(CallIdentity(stage=stage, step="step")):
        return client.complete("sys", prompt, response_format=_Answer).content.answer


def _record(directory: Path, asks: list[tuple[str, str]]) -> None:
    with provider_call_session(record_dir=directory) as session:
        client = _client(_tagged("recorded"), session=session)
        for stage, prompt in asks:
            _ask(client, stage, prompt)


def _fill(budget: int, *stages: str) -> ReplayFill:
    return ReplayFill(max_live_requests=budget, live_stages=frozenset(stages))


@pytest.fixture
def no_pause(monkeypatch: pytest.MonkeyPatch) -> list[float]:
    slept: list[float] = []
    monkeypatch.setattr(transport_retry, "_sleep", slept.append)
    return slept


def test_a_recorded_request_is_served_and_marked_replay(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])
    live = _tagged("live")

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(5)
    ) as session:
        answer = _ask(_client(live, session=session), "stage_a", "q1")

    assert answer == "recorded:q1"
    assert live.requests == []
    (record,) = _records(tmp_path / "out")
    assert record["source"] == "replay"


def test_a_request_with_no_recording_is_sent_live_and_marked_live(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])
    live = _tagged("live")

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(5)
    ) as session:
        client = _client(live, session=session)
        answers = [_ask(client, "stage_a", "q1"), _ask(client, "stage_a", "new")]

    assert answers == ["recorded:q1", "live:new"]
    assert len(live.requests) == 1
    assert [r["source"] for r in _records(tmp_path / "out")] == ["replay", "live"]


def test_a_forced_stage_goes_live_although_recorded(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q"), ("stage_b", "q")])
    live = _tagged("live")

    with provider_call_session(
        record_dir=tmp_path / "out",
        replay_dir=recorded,
        fill=_fill(5, "stage_b"),
    ) as session:
        client = _client(live, session=session)
        answers = [_ask(client, "stage_a", "q"), _ask(client, "stage_b", "q")]
        summary = session.fill_summary()

    assert answers == ["recorded:q", "live:q"]
    assert summary is not None
    assert summary["unused_recorded_responses"] == 1
    assert summary["live_requests_by_stage"] == {"stage_b": 1}


def test_the_summary_counts_served_and_live_requests(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1"), ("stage_a", "q2"), ("stage_b", "q3")])

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(7, "stage_b")
    ) as session:
        client = _client(_tagged("live"), session=session)
        _ask(client, "stage_a", "q1")
        _ask(client, "stage_a", "fresh")
        _ask(client, "stage_b", "q3")
        _ask(client, "stage_c", "other")
        summary = session.fill_summary()

    assert summary == {
        "mode": "fill",
        "replay_source": str(recorded),
        "live_stages": ["stage_b"],
        "max_live_requests": 7,
        "served_requests": 1,
        "live_requests": 3,
        "live_requests_by_stage": {"stage_a": 1, "stage_b": 1, "stage_c": 1},
        "unused_recorded_responses": 2,
        "refused_requests": 0,
    }


def test_a_request_without_identity_counts_as_unattributed(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(2)
    ) as session:
        _client(_tagged("live"), session=session).complete(
            "sys", "bare", response_format=_Answer
        )
        summary = session.fill_summary()

    assert summary is not None
    assert summary["live_requests_by_stage"] == {"unattributed": 1}


def test_a_live_transport_error_is_retried_once_with_retry_of(
    tmp_path: Path, no_pause: list[float]
) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])
    pending = [_status_error(502)]

    def flaky(**kwargs: Any) -> Any:
        if pending:
            raise pending.pop(0)
        return _completion('{"answer": "live-ok"}')

    live = _Provider(flaky)
    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(5)
    ) as session:
        answer = _ask(_client(live, session=session), "stage_a", "new")
        summary = session.fill_summary()

    assert answer == "live-ok"
    assert len(live.requests) == 2
    assert no_pause == [transport_retry.RETRY_DELAY_SECONDS]
    failed, retried = _records(tmp_path / "out")
    assert (failed["source"], retried["source"]) == ("live", "live")
    assert "retry_of" not in failed
    assert retried["retry_of"] == {"type": "InternalServerError", "status_code": 502}
    assert summary is not None and summary["live_requests"] == 2


def test_a_recorded_transport_error_and_its_retry_are_served_without_pause(
    tmp_path: Path, no_pause: list[float]
) -> None:
    pending = [_status_error(502)]

    def flaky(**kwargs: Any) -> Any:
        if pending:
            raise pending.pop(0)
        return _completion('{"answer": "recorded-ok"}')

    recorded = tmp_path / "recorded"
    with provider_call_session(record_dir=recorded) as session:
        _ask(_client(_Provider(flaky), session=session), "stage_a", "q")

    no_pause.clear()
    live = _tagged("live")
    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(5)
    ) as session:
        answer = _ask(_client(live, session=session), "stage_a", "q")

    assert answer == "recorded-ok"
    assert live.requests == [] and no_pause == []
    assert [r["source"] for r in _records(tmp_path / "out")] == ["replay", "replay"]


def test_a_recorded_failure_without_a_recorded_retry_is_not_retried_live(
    tmp_path: Path, no_pause: list[float]
) -> None:
    recorded = tmp_path / "recorded"
    failure = _status_error(502)

    def always_fail(**kwargs: Any) -> Any:
        raise failure

    with provider_call_session(record_dir=tmp_path / "both") as session:
        with pytest.raises(openai.InternalServerError):
            _ask(_client(_Provider(always_fail), session=session), "stage_a", "q")
    first = _records(tmp_path / "both")[0]
    recorded.mkdir()
    (recorded / RECORD_FILENAME).write_text(json.dumps(first) + "\n")

    no_pause.clear()
    live = _tagged("live")
    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(5)
    ) as session:
        with pytest.raises(openai.InternalServerError):
            _ask(_client(live, session=session), "stage_a", "q")

    assert live.requests == [] and no_pause == []


def test_the_budget_stops_the_run_at_exactly_n_live_requests(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])
    live = _tagged("live")

    with pytest.raises(LiveRequestBudgetError, match="2"):
        with provider_call_session(
            record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(2)
        ) as session:
            client = _client(live, session=session)
            _ask(client, "stage_a", "n1")
            _ask(client, "stage_a", "n2")
            with pytest.raises(LiveRequestBudgetError):
                _ask(client, "stage_a", "n3")
            with pytest.raises(LiveRequestBudgetError):
                _ask(client, "stage_a", "n4")
            assert _ask(client, "stage_a", "q1") == "recorded:q1"
            summary = session.fill_summary()

    assert len(live.requests) == 2
    assert summary is not None
    assert summary["live_requests"] == 2 and summary["refused_requests"] == 2
    records = _records(tmp_path / "out")
    assert [r["source"] for r in records] == [
        "live",
        "live",
        "refused",
        "refused",
        "replay",
    ]
    assert records[2]["error"]["type"] == "LiveRequestBudgetError"


def test_exactly_n_live_requests_do_not_trip_the_budget(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(2)
    ) as session:
        client = _client(_tagged("live"), session=session)
        _ask(client, "stage_a", "n1")
        _ask(client, "stage_a", "n2")


def test_the_transport_retry_counts_against_the_budget(
    tmp_path: Path, no_pause: list[float]
) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])
    live = _Provider(lambda **_: (_ for _ in ()).throw(_status_error(502)))

    with pytest.raises(LiveRequestBudgetError):
        with provider_call_session(
            record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(1)
        ) as session:
            with pytest.raises(LiveRequestBudgetError):
                _ask(_client(live, session=session), "stage_a", "new")

    assert len(live.requests) == 1


def test_a_zero_budget_serves_recordings_and_sends_nothing(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])
    live = _tagged("live")

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(0)
    ) as session:
        assert _ask(_client(live, session=session), "stage_a", "q1") == "recorded:q1"

    assert live.requests == []


def test_strict_replay_still_ends_in_replay_incomplete_and_marks_nothing(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])

    with pytest.raises(ReplayIncompleteError):
        with provider_call_session(
            record_dir=tmp_path / "out", replay_dir=recorded
        ) as session:
            client = _client(None, base_url=None, session=session)
            _ask(client, "stage_a", "q1")
            with pytest.raises(Exception):
                _ask(client, "stage_a", "missing")
            assert session.fill_summary() is None

    assert all("source" not in r for r in _records(tmp_path / "out"))


def test_a_fill_run_leaves_no_replay_incomplete_error(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(1)
    ) as session:
        _ask(_client(_tagged("live"), session=session), "stage_a", "new")


def test_the_output_of_a_fill_run_replays_natively_with_no_miss(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1"), ("stage_b", "q2")])
    filled = tmp_path / "filled"
    with provider_call_session(
        record_dir=filled, replay_dir=recorded, fill=_fill(3, "stage_b")
    ) as session:
        client = _client(_tagged("live"), session=session)
        first = [
            _ask(client, "stage_a", "q1"),
            _ask(client, "stage_b", "q2"),
            _ask(client, "stage_c", "fresh"),
        ]

    with provider_call_session(
        record_dir=tmp_path / "again", replay_dir=filled
    ) as session:
        client = _client(None, base_url=None, session=session)
        again = [
            _ask(client, "stage_a", "q1"),
            _ask(client, "stage_b", "q2"),
            _ask(client, "stage_c", "fresh"),
        ]
        assert session.replayer is not None
        assert session.replayer.unmatched == []
        assert session.replayer.unused() == []

    assert again == first == ["recorded:q1", "live:q2", "live:fresh"]


def test_concurrent_workers_keep_one_sequence_and_exact_counts(
    tmp_path: Path,
) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", f"q{i}") for i in range(8)])
    live = _tagged("live")
    workers = 16
    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(8)
    ) as session:
        client = _client(live, session=session)
        # Half the requests are recorded, half are not.
        prompts = [f"q{i}" for i in range(8)] + [f"new{i}" for i in range(8)]
        barrier = threading.Barrier(workers)

        def work(prompt: str) -> None:
            barrier.wait(timeout=5)
            _ask(client, "stage_a", prompt)

        threads = [threading.Thread(target=work, args=(p,)) for p in prompts]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        summary = session.fill_summary()

    records = _records(tmp_path / "out")
    assert sorted(r["sequence"] for r in records) == list(range(1, workers + 1))
    assert summary is not None
    assert (summary["served_requests"], summary["live_requests"]) == (8, 8)
    assert len(live.requests) == 8


def test_concurrent_workers_never_exceed_the_budget(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q0")])
    live = _tagged("live")
    refused: list[str] = []
    with pytest.raises(LiveRequestBudgetError):
        with provider_call_session(
            record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(3)
        ) as session:
            client = _client(live, session=session)
            barrier = threading.Barrier(12)

            def work(prompt: str) -> None:
                barrier.wait(timeout=5)
                try:
                    _ask(client, "stage_a", prompt)
                except LiveRequestBudgetError:
                    refused.append(prompt)

            threads = [
                threading.Thread(target=work, args=(f"n{i}",)) for i in range(12)
            ]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join()

    assert len(live.requests) == 3
    assert len(refused) == 9


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"replay_dir": None, "fill": _fill(1)}, "needs a replay directory"),
        ({"fill": ReplayFill(max_live_requests=-1)}, "non-negative"),
        ({"fill": _fill(1, "no_such_stage")}, "no_such_stage"),
    ],
    ids=["no-replay-directory", "negative-budget", "stage-absent-from-recording"],
)
def test_a_fill_session_rejects_a_configuration_that_cannot_work(
    tmp_path: Path, kwargs: dict[str, Any], message: str
) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])
    arguments: dict[str, Any] = {"replay_dir": recorded}
    arguments.update(kwargs)

    with pytest.raises(ValueError, match=message):
        with provider_call_session(record_dir=tmp_path / "out", **arguments):
            pass


def test_a_fill_client_still_needs_an_endpoint(tmp_path: Path) -> None:
    recorded = tmp_path / "recorded"
    _record(recorded, [("stage_a", "q1")])

    with provider_call_session(
        record_dir=tmp_path / "out", replay_dir=recorded, fill=_fill(1)
    ) as session:
        with pytest.raises(ValueError, match="No LLM endpoint"):
            _client(None, base_url=None, session=session)
