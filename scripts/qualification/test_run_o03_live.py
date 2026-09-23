from __future__ import annotations

import json
import os
import sys

import pytest

from run_o03_live import _run_protocol_child, _validate_runtime_tools


def _run_fake_child(tmp_path, code: str, *, timeout: float = 5.0):
    capture_dir = tmp_path / "capture"
    return _run_protocol_child(
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


def test_o03_validation_compares_two_declared_operations_and_live_state_tool() -> None:
    def operation(properties: dict, required: list[str], description: str) -> dict:
        return {
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
            },
        }

    operations = {
        "summarize_for_ehr": operation(
            {"patient_id": {"type": "string"}, "text": {"type": "string"}},
            ["patient_id", "text"],
            "Create a draft.",
        ),
        "commit_to_ehr": operation(
            {"draft_id": {"type": "string"}, "patient_id": {"type": "string"}},
            ["draft_id", "patient_id"],
            "Commit a reviewed draft.",
        ),
    }
    observed = [
        {
            "name": name,
            "description": declared["description"],
            "inputSchema": declared["parameters"],
        }
        for name, declared in operations.items()
    ]
    observed.append(
        {
            "name": "get_occiai_state_summary",
            "description": "Read the current state.",
            "inputSchema": {"type": "object", "properties": {}, "required": []},
        }
    )

    comparisons = _validate_runtime_tools(operations, observed)

    assert [item["operation"] for item in comparisons] == [
        "commit_to_ehr",
        "summarize_for_ehr",
    ]
