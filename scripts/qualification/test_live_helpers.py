from __future__ import annotations

import json
import os
import sys

import pytest

from live_helpers import (
    main,
    parse_child_protocol,
    persist_child_output,
    run_protocol_child,
    validate_allowed_tool_calls,
)


def _run_fake_child(tmp_path, code: str, *, timeout: float = 5.0):
    capture_dir = tmp_path / "capture"
    return run_protocol_child(
        [sys.executable, "-c", code],
        {},
        cwd=tmp_path,
        env={"PATH": os.environ.get("PATH", "")},
        timeout=timeout,
        capture_dir=capture_dir,
        prefix="fake",
    )


def test_fake_child_keeps_progress_on_stderr_and_one_json_protocol_on_stdout(
    tmp_path,
) -> None:
    protocol, status = _run_fake_child(
        tmp_path,
        "import json,sys; "
        "print('Garak progress: generation 1', file=sys.stderr, flush=True); "
        "print(json.dumps({'native_exchange':[{'status':'completed'}]}))",
    )

    assert protocol == {"native_exchange": [{"status": "completed"}]}
    assert (tmp_path / "capture" / "fake-stdout.bin").read_bytes() == (
        b'{"native_exchange": [{"status": "completed"}]}\n'
    )
    assert (tmp_path / "capture" / "fake-stderr.bin").read_bytes() == (
        b"Garak progress: generation 1\n"
    )
    recorded = json.loads((tmp_path / "capture" / "child-status.json").read_text())
    assert recorded["returncode"] == 0
    assert status["status"] == "completed"


@pytest.mark.parametrize(
    ("code", "error", "returncode"),
    [
        (
            "import sys; print('partial protocol'); "
            "print('provider failed', file=sys.stderr); sys.exit(7)",
            "subprocess failed",
            7,
        ),
        (
            "import sys; print('progress {not-json}'); print('trace', file=sys.stderr)",
            "not one JSON",
            0,
        ),
    ],
)
def test_failed_or_invalid_fake_child_keeps_streams_before_raising(
    tmp_path, code: str, error: str, returncode: int
) -> None:
    with pytest.raises(RuntimeError, match=error):
        _run_fake_child(tmp_path, code)

    capture_dir = tmp_path / "capture"
    assert (capture_dir / "fake-stdout.bin").is_file()
    assert (capture_dir / "fake-stderr.bin").is_file()
    recorded = json.loads((capture_dir / "child-status.json").read_text())
    assert recorded["returncode"] == returncode


def test_timed_out_fake_child_keeps_available_partial_output(tmp_path) -> None:
    code = (
        "import sys,time; print('{\\\"partial\\\":', flush=True); "
        "print('progress before timeout', file=sys.stderr, flush=True); time.sleep(2)"
    )
    with pytest.raises(RuntimeError, match="timed out"):
        _run_fake_child(tmp_path, code, timeout=0.1)

    capture_dir = tmp_path / "capture"
    assert (capture_dir / "fake-stdout.bin").read_bytes() == b'{"partial":\n'
    assert (
        capture_dir / "fake-stderr.bin"
    ).read_bytes() == b"progress before timeout\n"
    recorded = json.loads((capture_dir / "child-status.json").read_text())
    assert recorded["status"] == "timed_out"
    assert recorded["failure_type"] == "TimeoutExpired"
    assert recorded["returncode"] is None


def test_child_protocol_is_parsed_after_both_streams_and_status_are_saved(
    tmp_path,
) -> None:
    capture_dir = tmp_path / "generation_capture"
    stdout = b'{"gateway_responses_request_count":1,"response_status":"completed"}\n'
    stderr = b"Garak progress: 1 generation\n"

    capture = persist_child_output(
        capture_dir,
        stdout=stdout,
        stderr=stderr,
        returncode=0,
        status="completed",
    )
    parsed = parse_child_protocol(capture_dir, capture)

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


def test_timeout_partial_child_output_is_saved_without_parse(tmp_path) -> None:
    capture_dir = tmp_path / "generation_capture"
    capture = persist_child_output(
        capture_dir,
        stdout=b'{"partial":',
        stderr=b"progress before timeout",
        returncode=None,
        status="timed_out",
        failure_type="TimeoutExpired",
    )

    with pytest.raises(RuntimeError, match="timed out"):
        parse_child_protocol(capture_dir, capture)

    assert (capture_dir / "garak-stdout.bin").read_bytes() == b'{"partial":'
    recorded = json.loads((capture_dir / "child-status.json").read_text())
    assert recorded["status"] == "timed_out"
    assert recorded["failure_type"] == "TimeoutExpired"


def test_tool_calls_must_stay_within_the_exposed_allowlist() -> None:
    calls = [{"name": "lookup_order"}, {"name": "process_refund"}]

    assert validate_allowed_tool_calls(calls, ["lookup_order", "process_refund"]) == (
        calls
    )
    with pytest.raises(RuntimeError, match="outside the exposed allowlist"):
        validate_allowed_tool_calls(calls, ["lookup_order"])
    with pytest.raises(RuntimeError, match="not a list"):
        validate_allowed_tool_calls({"name": "lookup_order"}, ["lookup_order"])


def test_helper_entrypoint_rejects_unknown_modes(capsys) -> None:
    assert main(["--unknown"]) == 2
    assert "usage" in capsys.readouterr().err


def test_helper_module_imports_only_the_standard_library() -> None:
    import subprocess
    from pathlib import Path

    helper = Path(__file__).resolve().parent / "live_helpers.py"
    code = (
        "import runpy, sys; "
        f"runpy.run_path({str(helper)!r}, run_name='live_helpers'); "
        "print(','.join(sorted(m for m in ('mcp', 'garak', 'openai', 'yaml') "
        "if m in sys.modules)))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-c", code],
        capture_output=True,
        text=True,
        check=True,
    )

    assert result.stdout.strip() == ""
