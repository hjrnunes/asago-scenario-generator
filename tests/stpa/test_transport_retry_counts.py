"""Call counters and call evidence include the retry after a transport error."""

from __future__ import annotations

import json
from pathlib import Path

from asago_scenario_generator.stpa.infra.llm_helpers import (
    count_requests,
)
from tests.helpers.provider_call_record import _answer, _client, _Provider
from tests.helpers.transport_retry import (
    _call,
    _connection_error,
    _failing_then,
    _status_error,
)


def test_a_retried_call_counts_both_requests(tmp_path: Path) -> None:
    provider = _failing_then(_status_error(502))
    with count_requests() as tally:
        outcome = _call(_client(provider), tmp_path)

    assert outcome.error is None
    assert outcome.calls == 2
    assert tally.requests == 2


def test_a_call_whose_retry_also_failed_counts_both_requests(
    tmp_path: Path,
) -> None:
    failure = _connection_error()
    with count_requests() as tally:
        outcome = _call(_client(_failing_then(failure, failure)), tmp_path)

    assert outcome.error is not None
    assert outcome.calls == 2
    assert tally.requests == 2


def test_a_call_without_a_retry_counts_one_request(tmp_path: Path) -> None:
    with count_requests() as tally:
        outcome = _call(_client(_Provider(_answer)), tmp_path)

    assert (outcome.calls, tally.requests) == (1, 1)


def test_the_logged_request_controls_name_the_retry(tmp_path: Path) -> None:
    outcome = _call(_client(_failing_then(_connection_error())), tmp_path)

    assert outcome.result is not None
    log = (tmp_path / "calls.jsonl").read_text(encoding="utf-8")
    entry = json.loads(log.splitlines()[-1])
    assert entry["request_controls"]["transport_retries"] == 1


def test_a_failed_call_logs_the_retry_it_made(tmp_path: Path) -> None:
    failure = _status_error(500)
    outcome = _call(_client(_failing_then(failure, failure)), tmp_path)

    assert outcome.error is not None
    log = (tmp_path / "calls.jsonl").read_text(encoding="utf-8")
    entry = json.loads(log.splitlines()[-1])
    assert entry["request_controls"]["transport_retries"] == 1


def test_a_call_without_a_retry_logs_no_retry_control(tmp_path: Path) -> None:
    _call(_client(_Provider(_answer)), tmp_path)

    log = (tmp_path / "calls.jsonl").read_text(encoding="utf-8")
    entry = json.loads(log.splitlines()[-1])
    assert "transport_retries" not in entry["request_controls"]
