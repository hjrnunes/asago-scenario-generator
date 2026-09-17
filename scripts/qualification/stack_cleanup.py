"""Maintained cleanup-evidence seam for the local mini-agent stack (VAL-QUAL-011).

Every qualification orchestration that touches the local mini-agent stack ends
with a recorded cleanup. The record captures what was observed (processes and
ports, before and after), what stop action ran, the final no-orphan check, the
resulting status, a timestamp, and any errors. Records are written atomically
(temp file plus ``os.replace``), so a crash never leaves a half-written
cleanup claim.

Observed state is recorded exactly as the probes report it: a failed probe
records ``null`` plus an error entry, never an empty orphan list or a cleared
port that was not observed. ``completed`` requires a final observation of no
orphan processes and every documented port closed.

The seam is injectable: the stop action, the process-evidence probe, and the
port probes are callables supplied by the caller. Tests inject offline fakes;
the production defaults match only the documented stack supervisor pattern, so
an unrelated process is never signalled.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

CLEANUP_SCHEMA = "stack-cleanup-record-v1"
CLEANUP_RECORD_FILENAME = "stack-cleanup.json"
STACK_PROCESS_PATTERN = "mini-agents-stack"

# Mirror of run_recipe.STACK_PORTS (the six documented MCP ports plus the OGX
# Responses API port), kept self-contained so this seam imports without the
# recipe module.
SAFE_STACK_PORTS: tuple[int, ...] = (8888, 8889, 8890, 8891, 8892, 8893, 8321)

STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_ERROR = "error"
STATUS_KEPT_RUNNING = "kept_running"

ProcessProbe = Callable[[str], list[str]]
StopAction = Callable[[str], Any]
PortProbe = Callable[[int], bool]
PortsClosedWait = Callable[[Sequence[int], float], None]


def default_process_evidence(pattern: str = STACK_PROCESS_PATTERN) -> list[str]:
    """Return ``pgrep -fl`` lines for the documented stack pattern."""
    result = subprocess.run(
        ["pgrep", "-fl", pattern],
        capture_output=True,
        text=True,
        check=False,
    )
    # pgrep exits 1 when nothing matches; that is evidence, not an error.
    if result.returncode not in (0, 1):
        raise RuntimeError(f"pgrep exited {result.returncode}: {result.stderr.strip()}")
    return [line for line in result.stdout.splitlines() if line.strip()]


def default_stop(pattern: str = STACK_PROCESS_PATTERN) -> str:
    """Signal the documented stack supervisor pattern and report the exit."""
    result = subprocess.run(["pkill", "-f", pattern], check=False)
    return f"exit {result.returncode}"


def default_port_is_listening(
    port: int, host: str = "127.0.0.1", timeout: float = 0.25
) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(timeout)
        return sock.connect_ex((host, port)) == 0


def default_wait_ports_closed(
    ports: Sequence[int],
    timeout: float,
    probe: PortProbe = default_port_is_listening,
    sleep: float = 0.25,
) -> None:
    """Block until no port accepts a connection, then raise or return."""
    open_ports = list(ports)
    deadline = time.monotonic() + timeout
    while open_ports and time.monotonic() < deadline:
        open_ports = [port for port in open_ports if probe(port)]
        if open_ports:
            time.sleep(sleep)
    if open_ports:
        raise TimeoutError(
            f"ports still listening after {timeout:.0f}s: {sorted(open_ports)}"
        )


@dataclass(frozen=True)
class CleanupProbes:
    """Injected probes for the cleanup seam; defaults are the production ones."""

    process_evidence: ProcessProbe = default_process_evidence
    stop: StopAction = default_stop
    stop_command: str = f"pkill -f {STACK_PROCESS_PATTERN}"
    port_is_listening: PortProbe = default_port_is_listening
    wait_ports_closed: PortsClosedWait = default_wait_ports_closed


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_cleanup_record(record: dict[str, Any], path: Path) -> Path:
    """Atomically write one cleanup record: temp file, then ``os.replace``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        tmp.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()
    return path


def load_cleanup_record(path: Path) -> dict[str, Any] | None:
    """Read one cleanup record without turning malformed evidence into success."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _observe_processes(
    probes: CleanupProbes, pattern: str, errors: list[str]
) -> list[str] | None:
    try:
        return list(probes.process_evidence(pattern))
    except Exception as error:  # noqa: BLE001 - recorded, never fabricated
        errors.append(f"process probe failed: {error}")
        return None


def _observe_ports(
    probes: CleanupProbes, ports: Sequence[int], errors: list[str]
) -> list[int] | None:
    observed: list[int] = []
    for port in ports:
        try:
            if probes.port_is_listening(port):
                observed.append(port)
        except Exception as error:  # noqa: BLE001 - recorded, never fabricated
            errors.append(f"port {port} probe failed: {error}")
            return None
    return observed


def run_stack_cleanup(
    *,
    run_id: str | None = None,
    target: str | None = None,
    record_path: Path,
    probes: CleanupProbes | None = None,
    ports: Sequence[int] = SAFE_STACK_PORTS,
    pattern: str = STACK_PROCESS_PATTERN,
    stop_timeout: float = 20.0,
) -> dict[str, Any]:
    """Stop the stack and atomically record the complete cleanup evidence.

    Process and port state is observed before the stop and again as the final
    no-orphan/no-listener check. ``completed`` requires a final observation of
    no orphan processes and every documented port closed; a failed probe keeps
    the record honest with ``null`` state and an error entry instead of an
    empty list or a cleared-port claim.
    """
    probes = probes or CleanupProbes()
    errors: list[str] = []
    checked_ports = list(ports)

    process_evidence = _observe_processes(probes, pattern, errors)
    ports_open_before = _observe_ports(probes, checked_ports, errors)

    try:
        stop_result = str(probes.stop(pattern))
    except Exception as error:  # noqa: BLE001 - recorded, never raised
        errors.append(f"stop action failed: {error}")
        stop_result = f"error: {error}"

    try:
        probes.wait_ports_closed(checked_ports, stop_timeout)
    except Exception as error:  # noqa: BLE001 - recorded, never raised
        errors.append(f"ports did not close: {error}")

    ports_open_after = _observe_ports(probes, checked_ports, errors)
    orphan_processes = _observe_processes(probes, pattern, errors)

    if orphan_processes is None:
        no_orphan_check = "unavailable"
    elif orphan_processes:
        no_orphan_check = "failed"
    else:
        no_orphan_check = "passed"
    ports_clear = None if ports_open_after is None else not ports_open_after

    stop_raised = stop_result.startswith("error:")
    if stop_raised or ports_open_after is None or orphan_processes is None:
        # The final state is unknown; never claim completion.
        status = STATUS_ERROR
    elif not ports_open_after and not orphan_processes:
        status = STATUS_COMPLETED
    else:
        status = STATUS_FAILED

    record: dict[str, Any] = {
        "schema_version": CLEANUP_SCHEMA,
        "run_id": run_id,
        "target": target,
        "recorded_at": _utc_now(),
        "checked_ports": checked_ports,
        "process_evidence": process_evidence,
        "ports_open_before": ports_open_before,
        "stop_command": probes.stop_command,
        "stop_result": stop_result,
        "ports_open_after": ports_open_after,
        "ports_clear": ports_clear,
        "orphan_processes": orphan_processes,
        "no_orphan_check": no_orphan_check,
        "status": status,
        "errors": errors,
        "record_path": str(record_path),
    }
    write_cleanup_record(record, record_path)
    return record


def record_kept_running(
    *,
    run_id: str | None = None,
    target: str | None = None,
    record_path: Path,
    resume_reason: str,
    resume_scope: str,
    probes: CleanupProbes | None = None,
    ports: Sequence[int] = SAFE_STACK_PORTS,
    pattern: str = STACK_PROCESS_PATTERN,
) -> dict[str, Any]:
    """Record an intentional pause: the stack stays up for the resume path.

    No stop action runs. The observed process and port state is recorded as-is
    beside the resume reason and scope, so the pause is auditable evidence, not
    a missing cleanup.
    """
    probes = probes or CleanupProbes()
    errors: list[str] = []
    checked_ports = list(ports)
    process_evidence = _observe_processes(probes, pattern, errors)
    ports_open = _observe_ports(probes, checked_ports, errors)
    record: dict[str, Any] = {
        "schema_version": CLEANUP_SCHEMA,
        "run_id": run_id,
        "target": target,
        "recorded_at": _utc_now(),
        "checked_ports": checked_ports,
        "process_evidence": process_evidence,
        "ports_open_before": ports_open,
        "stop_command": None,
        "stop_result": None,
        "status": STATUS_KEPT_RUNNING,
        "resume_reason": resume_reason,
        "resume_scope": resume_scope,
        "errors": errors,
        "record_path": str(record_path),
    }
    write_cleanup_record(record, record_path)
    return record
