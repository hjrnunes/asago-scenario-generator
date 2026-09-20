"""Offline tests for the injectable stack cleanup seam (VAL-QUAL-011).

Every probe is injected: no test pkills a process, probes a real port, or
waits on the network. The seam's production defaults are never exercised
here.
"""

from __future__ import annotations

import json
import getpass
from datetime import datetime
from pathlib import Path

from stack_cleanup import (
    CLEANUP_SCHEMA,
    DEFAULT_MISSION_PATH,
    SAFE_PROCESS_PATTERN,
    SAFE_PROCESS_PATTERNS,
    SAFE_STACK_PORTS,
    UNSAFE_STACK_PORTS,
    CleanupProbes,
    load_cleanup_record,
    record_kept_running,
    run_stack_cleanup,
)


def test_safe_cleanup_port_set_excludes_forbidden_listeners() -> None:
    assert SAFE_STACK_PORTS == (8321, 8888, 8890, 8892)
    assert set(SAFE_STACK_PORTS).isdisjoint(UNSAFE_STACK_PORTS)
    assert "mini_agents" in SAFE_PROCESS_PATTERNS
    assert "ogx" in SAFE_PROCESS_PATTERNS


def test_forbidden_listener_fails_closed_even_when_safe_ports_are_clear(
    tmp_path: Path,
) -> None:
    record = run_stack_cleanup(
        record_path=tmp_path / "cleanup" / "stack-cleanup.json",
        probes=offline_probes(
            open_ports={8889},
            wait_error=TimeoutError("forbidden listener remains"),
        ),
    )

    assert record["status"] == "error"
    assert record["ports_open_before"] == []
    assert record["forbidden_ports_open_before"] == [8889]
    assert record["forbidden_ports_open_after"] == [8889]
    assert record["ports_clear"] is True
    assert any("ports did not close" in error for error in record["errors"])


def offline_probes(
    *,
    processes: list[list[object]] | None = None,
    open_ports: set[int] | None = None,
    stop_calls: list[str] | None = None,
    stop_error: Exception | None = None,
    wait_error: Exception | None = None,
    process_error: Exception | None = None,
) -> CleanupProbes:
    """Build injected probes with fully observed, controlled state."""
    observations = list(processes or [])
    ports = set(open_ports or set())
    stop_calls_ref = stop_calls if stop_calls is not None else []

    def process_evidence(pattern: str) -> list[object]:
        if observations:
            return observations.pop(0)
        if process_error is not None:
            raise process_error
        return []

    def stop(pattern: str) -> str:
        stop_calls_ref.append(pattern)
        if stop_error is not None:
            raise stop_error
        return "exit 0"

    def port_is_listening(port: int) -> bool:
        return port in ports

    def wait_ports_closed(ports_to_wait, timeout: float) -> None:
        if wait_error is not None:
            raise wait_error

    return CleanupProbes(
        process_evidence=process_evidence,
        stop=stop,
        stop_command="test-stop",
        port_is_listening=port_is_listening,
        wait_ports_closed=wait_ports_closed,
        wait_processes_exit=lambda _processes, _timeout: {
            "result": "confirmed",
            "survivors": [],
        },
    )


def process_identity(pid: int = 111) -> dict[str, object]:
    return {
        "pid": pid,
        "ppid": 1,
        "owner": getpass.getuser(),
        "command": "python -m mini_agents --domain klarna --port 8888",
        "exists": True,
        "ancestry": [
            {
                "pid": pid,
                "ppid": 1,
                "owner": getpass.getuser(),
                "command": "python -m mini_agents --domain klarna --port 8888",
            }
        ],
        "cwd": DEFAULT_MISSION_PATH,
        "mission_path": DEFAULT_MISSION_PATH,
        "mission_path_in_command": False,
    }


def test_completed_cleanup_records_the_full_evidence_set(tmp_path: Path) -> None:
    """A clean stop records run_id/target, ports, process evidence, stop
    result, the final no-orphan check, and the completed status."""
    record_path = tmp_path / "cleanup" / "stack-cleanup.json"

    record = run_stack_cleanup(
        run_id="synthesis-1",
        target="klarna",
        record_path=record_path,
        probes=offline_probes(processes=[[process_identity(4321)]]),
    )

    assert record["schema_version"] == CLEANUP_SCHEMA
    assert record["run_id"] == "synthesis-1"
    assert record["target"] == "klarna"
    assert record["checked_ports"] == list(SAFE_STACK_PORTS)
    assert record["process_evidence"] == [process_identity(4321)]
    assert record["stop_command"] == "test-stop"
    assert record["stop_result"] == "exit 0"
    assert record["ports_open_after"] == []
    assert record["ports_clear"] is True
    assert record["orphan_processes"] == []
    assert record["no_orphan_check"] == "passed"
    assert record["status"] == "completed"
    assert record["errors"] == []
    # The timestamp is a parseable UTC instant.
    datetime.strptime(record["recorded_at"], "%Y-%m-%dT%H:%M:%SZ")
    # The record is on disk, valid JSON, and carries no temp leftovers.
    on_disk = json.loads(record_path.read_text(encoding="utf-8"))
    assert on_disk["status"] == "completed"
    assert list(record_path.parent.glob(".*")) == []


def test_failed_cleanup_preserves_observed_orphans_and_ports(tmp_path: Path) -> None:
    """A failed stop preserves the observed survivors exactly: no fabricated
    empty orphan list and no cleared-port claim."""
    record_path = tmp_path / "cleanup" / "stack-cleanup.json"
    stop_calls: list[str] = []

    record = run_stack_cleanup(
        run_id="synthesis-2",
        target="occiai",
        record_path=record_path,
        probes=offline_probes(
            processes=[
                [process_identity()],
                [process_identity(), process_identity(222)],
            ],
            open_ports={8888, 8321},
            stop_calls=stop_calls,
            wait_error=TimeoutError("ports still listening after 20s: [8888, 8321]"),
        ),
    )

    assert record["status"] == "failed"
    assert stop_calls == [SAFE_PROCESS_PATTERN]
    assert record["orphan_processes"] == [
        process_identity(),
        process_identity(222),
    ]
    assert record["no_orphan_check"] == "failed"
    assert record["ports_open_after"] == [8321, 8888]
    assert record["ports_clear"] is False
    assert record["process_evidence"] == [process_identity()]
    assert any("ports did not close" in error for error in record["errors"])


def test_probe_failure_records_null_state_never_an_empty_list(tmp_path: Path) -> None:
    """A failed final process probe is unknown state: ``null``, plus the error,
    with the status never claiming completion."""
    record_path = tmp_path / "cleanup" / "stack-cleanup.json"
    probes = offline_probes(
        processes=[[process_identity()]],
        process_error=RuntimeError("pgrep exited 2: boom"),
    )

    record = run_stack_cleanup(
        run_id="synthesis-3",
        target="airbnb",
        record_path=record_path,
        probes=probes,
    )

    assert record["status"] == "error"
    assert record["orphan_processes"] is None
    assert record["no_orphan_check"] == "unavailable"
    assert record["ports_open_after"] == []
    assert record["ports_clear"] is True
    assert any("pgrep exited 2" in error for error in record["errors"])
    # The observed pre-stop evidence is still preserved.
    assert record["process_evidence"] == [process_identity()]


def test_stop_action_failure_is_recorded_not_raised(tmp_path: Path) -> None:
    """A raising stop action becomes recorded evidence; the function returns
    and the record carries the failure plus the observed final state."""
    record_path = tmp_path / "cleanup" / "stack-cleanup.json"

    record = run_stack_cleanup(
        record_path=record_path,
        probes=offline_probes(
            processes=[[process_identity()]],
            stop_error=RuntimeError("pkill exploded"),
        ),
    )

    assert record["status"] == "error"
    assert record["stop_result"].startswith("error:")
    assert any("pkill exploded" in error for error in record["errors"])
    assert record["orphan_processes"] == []
    assert record["ports_open_after"] == []


def test_kept_running_records_resume_reason_scope_and_observed_state(
    tmp_path: Path,
) -> None:
    """A pause records the intentional kept_running status, the resume reason
    and scope, and the observed live state; no stop action runs."""
    record_path = tmp_path / "cleanup" / "stack-cleanup.json"
    stop_calls: list[str] = []

    record = record_kept_running(
        run_id="synthesis-4",
        target="klarna",
        record_path=record_path,
        resume_reason="paused before dispatch; operator writes the record",
        resume_scope="execution stage dispatch after the pre-dispatch record",
        probes=offline_probes(
            processes=[[process_identity()]],
            open_ports={8888},
            stop_calls=stop_calls,
        ),
    )

    assert record["status"] == "kept_running"
    assert (
        record["resume_reason"] == "paused before dispatch; operator writes the record"
    )
    assert (
        record["resume_scope"]
        == "execution stage dispatch after the pre-dispatch record"
    )
    assert record["process_evidence"] == [process_identity()]
    assert record["ports_open_before"] == [8888]
    assert record["stop_command"] is None
    assert record["stop_result"] is None
    # The pause never signals the stack.
    assert stop_calls == []


def test_terminal_cleanup_replaces_the_pause_record_atomically(tmp_path: Path) -> None:
    """The resume path writes to the same record path: the kept_running record
    is replaced in full, with no temp leftovers or duplicate records."""
    record_path = tmp_path / "cleanup" / "stack-cleanup.json"
    record_kept_running(
        run_id="synthesis-5",
        target="klarna",
        record_path=record_path,
        resume_reason="pause",
        resume_scope="execution",
        probes=offline_probes(processes=[[process_identity()]]),
    )

    record = run_stack_cleanup(
        run_id="synthesis-5",
        target="klarna",
        record_path=record_path,
        probes=offline_probes(),
    )

    assert load_cleanup_record(record_path) == record
    assert record["status"] == "completed"
    assert record.get("resume_reason") is None
    files = sorted(path.name for path in record_path.parent.iterdir())
    assert files == ["stack-cleanup.json"] or (
        len(files) == 2
        and "stack-cleanup.json" in files
        and any(
            name.startswith("stack-cleanup-current-verification-") for name in files
        )
    )


def test_cleanup_records_never_carry_secrets(tmp_path: Path) -> None:
    """The record holds process/port evidence only: no endpoint, key, or env
    values are copied into the record by the seam."""
    record = run_stack_cleanup(
        run_id="synthesis-6",
        target="klarna",
        record_path=tmp_path / "cleanup" / "stack-cleanup.json",
        probes=offline_probes(),
    )

    serialized = json.dumps(record)
    for marker in ("base_url", "api_key", "OPENAI", "sk-"):
        assert marker not in serialized


def test_record_write_surviving_a_dirty_directory(tmp_path: Path) -> None:
    """Writing into a directory that already holds unrelated files preserves
    them; only the record file and its payload change."""
    unrelated = tmp_path / "cleanup"
    unrelated.mkdir()
    (unrelated / "other-evidence.json").write_text("keep me\n", encoding="utf-8")

    run_stack_cleanup(
        run_id="synthesis-7",
        target="klarna",
        record_path=unrelated / "stack-cleanup.json",
        probes=offline_probes(),
    )

    assert (unrelated / "other-evidence.json").read_text() == "keep me\n"


def test_cleanup_waits_for_confirmed_process_exit_after_listener_closure(
    tmp_path: Path,
) -> None:
    events: list[str] = []
    identity = process_identity(700)
    observations = iter(([identity], []))

    def process_evidence(_pattern: str) -> list[object]:
        events.append("process_probe")
        return next(observations)

    def stop(_pattern: str, processes: list[dict[str, object]]) -> dict[str, object]:
        events.append("signal_match")
        assert processes == [identity]
        return {"result": "signal_match", "signal_match_pids": [700]}

    def wait_ports(_ports, _timeout) -> None:
        events.append("listener_closed")

    def wait_processes(processes, _timeout) -> dict[str, object]:
        events.append("process_exit_confirmed")
        assert processes == [identity]
        return {"result": "confirmed", "survivors": []}

    record = run_stack_cleanup(
        record_path=tmp_path / "cleanup" / "stack-cleanup.json",
        probes=CleanupProbes(
            process_evidence=process_evidence,
            stop=stop,
            stop_command="test-stop",
            port_is_listening=lambda _port: False,
            wait_ports_closed=wait_ports,
            wait_processes_exit=wait_processes,
        ),
    )

    assert events == [
        "process_probe",
        "signal_match",
        "listener_closed",
        "process_exit_confirmed",
        "process_probe",
    ]
    assert record["listener_closure"]["status"] == "confirmed"
    assert record["process_exit_wait"]["status"] == "confirmed"
    assert record["signal_match"] is True
    assert record["status"] == "completed"


def test_process_exit_timeout_is_failed_with_exact_survivor_evidence(
    tmp_path: Path,
) -> None:
    identity = process_identity(701)
    observations = iter(([identity], [identity]))

    def wait_processes(processes, timeout) -> None:
        assert processes == [identity]
        assert timeout == 0.01
        raise TimeoutError("pid 701 still exists")

    record = run_stack_cleanup(
        record_path=tmp_path / "cleanup" / "stack-cleanup.json",
        process_exit_timeout=0.01,
        probes=CleanupProbes(
            process_evidence=lambda _pattern: next(observations),
            stop=lambda _pattern, _processes: {
                "result": "signal_match",
                "signal_match_pids": [701],
            },
            stop_command="test-stop",
            port_is_listening=lambda _port: False,
            wait_ports_closed=lambda _ports, _timeout: None,
            wait_processes_exit=wait_processes,
        ),
    )

    assert record["status"] == "failed"
    assert record["signal_match"] is True
    assert record["process_exit_wait"]["status"] == "timeout"
    assert record["process_exit_wait"]["survivors"] == [identity]
    assert record["orphan_processes"] == [identity]
    assert record["no_orphan_check"] == "failed"
    assert any("processes did not exit" in error for error in record["errors"])


def test_stale_or_incomplete_identity_never_authorizes_signal(tmp_path: Path) -> None:
    stale = {"pid": 702, "command": "uv run mini-agents-stack"}
    stop_calls: list[object] = []

    record = run_stack_cleanup(
        record_path=tmp_path / "cleanup" / "stack-cleanup.json",
        probes=CleanupProbes(
            process_evidence=lambda _pattern: [stale],
            stop=lambda *_args: stop_calls.append(_args),
            stop_command="test-stop",
            port_is_listening=lambda _port: False,
            wait_ports_closed=lambda _ports, _timeout: None,
            wait_processes_exit=lambda _processes, _timeout: None,
        ),
    )

    assert stop_calls == []
    assert record["authorized_processes"] == []
    assert record["unauthorized_processes"] == [stale]
    assert record["stop_result"]["result"] == "not_authorized"
    assert record["status"] == "failed"
    assert record["orphan_processes"] == [stale]


def test_current_verification_is_timestamped_and_distinguishes_history(
    tmp_path: Path,
) -> None:
    record_path = tmp_path / "cleanup" / "stack-cleanup.json"
    record = run_stack_cleanup(
        run_id="current-run",
        target="klarna",
        record_path=record_path,
        probes=offline_probes(),
    )

    current_path = Path(record["current_verification_record"])
    assert current_path.is_file()
    current = json.loads(current_path.read_text(encoding="utf-8"))
    assert current["schema_version"] == "stack-cleanup-current-verification-v1"
    assert current["ports"]["checked"] == list(SAFE_STACK_PORTS)
    assert current["action"]["stop_command"] == "test-stop"
    assert current["result"] == "completed"
    assert "2026-09-17T18:54:29Z" in current["historical_distinction"]
    assert "stack-cleanup.json" not in current_path.name
