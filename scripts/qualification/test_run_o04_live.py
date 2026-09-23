from __future__ import annotations

import json

import pytest

from run_o04_live import (
    _parse_child_protocol,
    _persist_child_output,
    _require_expected_package_digest,
    _validate_read_only_tool_calls,
)


def test_generation_tool_calls_must_be_declared_read_only_and_within_limit() -> None:
    allowed = ["ask_clinical_question", "get_education", "get_referral"]
    calls = [{"name": name} for name in allowed] + [{"name": allowed[0]}]

    assert _validate_read_only_tool_calls(calls, allowed) == calls

    with pytest.raises(RuntimeError, match="postgeneration safety stop"):
        _validate_read_only_tool_calls(calls + [{"name": allowed[1]}], allowed)
    with pytest.raises(RuntimeError, match="allowlist"):
        _validate_read_only_tool_calls([{"name": "escalate_to_clinician"}], allowed)
    with pytest.raises(RuntimeError, match="allowlist"):
        _validate_read_only_tool_calls([None], allowed)


def test_expected_package_digest_is_a_preflight_pin() -> None:
    digest = "a" * 64
    _require_expected_package_digest(digest, digest)
    with pytest.raises(ValueError, match="does not match"):
        _require_expected_package_digest(digest, "b" * 64)


def test_child_protocol_is_parsed_after_both_streams_and_status_are_saved(
    tmp_path,
) -> None:
    capture_dir = tmp_path / "generation_capture"
    stdout = b'{"gateway_responses_request_count":1,"response_status":"completed"}\n'
    stderr = b"Garak progress: 1 generation\n"

    capture = _persist_child_output(
        capture_dir,
        stdout=stdout,
        stderr=stderr,
        returncode=0,
        status="completed",
    )
    parsed = _parse_child_protocol(capture_dir, capture)

    assert parsed == {
        "gateway_responses_request_count": 1,
        "response_status": "completed",
    }
    assert (capture_dir / "garak-stdout.bin").read_bytes() == stdout
    assert (capture_dir / "garak-stderr.bin").read_bytes() == stderr
    status = json.loads((capture_dir / "child-status.json").read_text())
    assert status["returncode"] == 0
    assert status["stdout"]["bytes"] == len(stdout)
    assert status["stderr"]["bytes"] == len(stderr)


@pytest.mark.parametrize(
    ("stdout", "stderr", "returncode", "status", "error"),
    [
        (b'{"partial":true}', b"provider error", 1, "failed", "subprocess failed"),
        (b"progress {not-json}", b"trace", 0, "completed", "not one JSON"),
    ],
)
def test_failed_or_invalid_child_protocol_keeps_original_streams(
    tmp_path, stdout, stderr, returncode, status, error
) -> None:
    capture_dir = tmp_path / "generation_capture"
    capture = _persist_child_output(
        capture_dir,
        stdout=stdout,
        stderr=stderr,
        returncode=returncode,
        status=status,
    )

    with pytest.raises(RuntimeError, match=error):
        _parse_child_protocol(capture_dir, capture)

    assert (capture_dir / "garak-stdout.bin").read_bytes() == stdout
    assert (capture_dir / "garak-stderr.bin").read_bytes() == stderr
    recorded = json.loads((capture_dir / "child-status.json").read_text())
    assert recorded["returncode"] == returncode


def test_timeout_partial_child_output_is_saved_without_parse(tmp_path) -> None:
    capture_dir = tmp_path / "generation_capture"
    capture = _persist_child_output(
        capture_dir,
        stdout=b'{"partial":',
        stderr=b"progress before timeout",
        returncode=None,
        status="timed_out",
        failure_type="TimeoutExpired",
    )

    with pytest.raises(RuntimeError, match="timed out"):
        _parse_child_protocol(capture_dir, capture)

    assert (capture_dir / "garak-stdout.bin").read_bytes() == b'{"partial":'
    assert (capture_dir / "garak-stderr.bin").read_bytes() == b"progress before timeout"
    recorded = json.loads((capture_dir / "child-status.json").read_text())
    assert recorded["status"] == "timed_out"
    assert recorded["failure_type"] == "TimeoutExpired"
