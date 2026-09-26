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
import getpass
import importlib.util
import inspect
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from safe_lifecycle import SAFE_PORTS, UNSAFE_PORTS
except ModuleNotFoundError as error:
    if error.name != "safe_lifecycle":
        raise
    try:
        from _qualification_safe_lifecycle import SAFE_PORTS, UNSAFE_PORTS
    except ModuleNotFoundError:
        module_path = Path(__file__).with_name("safe_lifecycle.py")
        spec = importlib.util.spec_from_file_location(
            "_qualification_safe_lifecycle", module_path
        )
        if spec is None or spec.loader is None:
            raise ImportError(
                f"cannot load safe lifecycle from {module_path}"
            ) from error
        safe_lifecycle = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = safe_lifecycle
        spec.loader.exec_module(safe_lifecycle)
        SAFE_PORTS = safe_lifecycle.SAFE_PORTS
        UNSAFE_PORTS = safe_lifecycle.UNSAFE_PORTS

CLEANUP_SCHEMA = "stack-cleanup-record-v1"
CLEANUP_RECORD_FILENAME = "stack-cleanup.json"
# ``STACK_PROCESS_PATTERN`` remains the historical supervisor label used by
# the legacy recipe tests and records. Safe cleanup uses the process patterns
# below and never launches that supervisor.
STACK_PROCESS_PATTERN = "mini-agents-stack"
SAFE_PROCESS_PATTERNS: tuple[str, ...] = ("mini_agents", "ogx")
SAFE_PROCESS_PATTERN = "|".join(SAFE_PROCESS_PATTERNS)
CURRENT_VERIFICATION_SCHEMA = "stack-cleanup-current-verification-v1"
HISTORICAL_FAILURE_TIMESTAMP = "2026-09-17T18:54:29Z"
HISTORICAL_FAILURE_PATH = (
    "build/adaptive-e2e/fresh-miniklarna-qualification-final-20260917/"
    "cleanup/stack-cleanup.json"
)
DEFAULT_MISSION_PATH = "/Users/hjrnunes/workspace/hjrnunes/mini-agents"

# The safe-only topology is one gateway plus three safe target endpoints.
# Keep this self-contained so the cleanup seam imports without the recipe
# module. The unsafe counterparts are intentionally absent.
SAFE_STACK_PORTS: tuple[int, ...] = tuple(sorted(SAFE_PORTS))
UNSAFE_STACK_PORTS: tuple[int, ...] = tuple(sorted(UNSAFE_PORTS))

STATUS_COMPLETED = "completed"
STATUS_FAILED = "failed"
STATUS_ERROR = "error"
STATUS_KEPT_RUNNING = "kept_running"

ProcessEvidence = str | dict[str, Any]
ProcessProbe = Callable[[str], list[ProcessEvidence]]
StopAction = Callable[..., Any]
PortProbe = Callable[[int], bool]
PortsClosedWait = Callable[[Sequence[int], float], None]
ProcessesExitWait = Callable[[Sequence[dict[str, Any]], float], Any]


def _ps_record(pid: int) -> dict[str, Any] | None:
    """Read one current process identity from the operating system."""
    result = subprocess.run(
        ["ps", "-o", "pid=,ppid=,user=,command=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    fields = result.stdout.strip().split(None, 3)
    if len(fields) < 4:
        return None
    current_pid, parent_pid, owner, command = fields
    return {
        "pid": int(current_pid),
        "ppid": int(parent_pid),
        "owner": owner,
        "command": command,
        "exists": True,
    }


def _process_ancestry(pid: int) -> list[dict[str, Any]]:
    """Return current parent records, stopping at the first unavailable one."""
    ancestry: list[dict[str, Any]] = []
    seen: set[int] = set()
    current = pid
    while current > 1 and current not in seen:
        seen.add(current)
        record = _ps_record(current)
        if record is None:
            break
        ancestry.append(record)
        parent = record.get("ppid")
        if not isinstance(parent, int) or parent == current:
            break
        current = parent
    return ancestry


def _process_cwd(pid: int) -> str | None:
    """Read a process's current working directory without trusting its PID."""
    result = subprocess.run(
        ["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"],
        capture_output=True,
        text=True,
        check=False,
    )
    for line in result.stdout.splitlines():
        if line.startswith("n"):
            return line[1:]
    return None


def default_process_evidence(
    pattern: str = STACK_PROCESS_PATTERN,
) -> list[dict[str, Any]]:
    """Return current process identity records for the documented pattern.

    ``pgrep -fl`` is only a candidate query. Each candidate is re-read through
    ``ps`` and receives command, ancestry, owner, and mission-path evidence
    before the cleanup seam can authorize a signal.
    """
    result = subprocess.run(
        ["pgrep", "-fl", pattern],
        capture_output=True,
        text=True,
        check=False,
    )
    # pgrep exits 1 when nothing matches; that is evidence, not an error.
    if result.returncode not in (0, 1):
        raise RuntimeError(f"pgrep exited {result.returncode}: {result.stderr.strip()}")
    evidence: list[dict[str, Any]] = []
    mission_path = os.environ.get("MINI_AGENTS_ROOT", DEFAULT_MISSION_PATH)
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        try:
            pid = int(line.split(None, 1)[0])
        except (IndexError, ValueError):
            continue
        record = _ps_record(pid)
        if record is None:
            continue
        ancestry = _process_ancestry(pid)
        cwd = _process_cwd(pid)
        record["ancestry"] = ancestry
        record["cwd"] = cwd
        record["mission_path"] = mission_path
        record["mission_path_in_command"] = any(
            mission_path in str(item.get("command", "")) for item in ancestry
        )
        evidence.append(record)
    return evidence


def default_stop(
    pattern: str = STACK_PROCESS_PATTERN,
    identities: Sequence[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Signal only the already-authorized current process identities.

    The old pattern-wide ``pkill`` action is intentionally gone. A PID is
    useful only after the caller has attached current command, ancestry, owner,
    and mission-path evidence.
    """
    del pattern
    signal_matches: list[int] = []
    errors: list[str] = []
    for identity in identities or ():
        pid = identity.get("pid")
        if not isinstance(pid, int):
            errors.append(f"invalid pid: {pid!r}")
            continue
        current = _ps_record(pid)
        current_cwd = _process_cwd(pid)
        mission_path = identity.get("mission_path")
        current_ancestry = _process_ancestry(pid)
        if (
            current is None
            or current.get("command") != identity.get("command")
            or current.get("owner") != identity.get("owner")
            or not current_ancestry
            or not isinstance(mission_path, str)
            or current_cwd != mission_path
        ):
            errors.append(f"pid {pid} identity changed before signal")
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except ProcessLookupError:
            errors.append(f"pid {pid} disappeared before signal")
        except OSError as error:
            errors.append(f"pid {pid} signal failed: {error}")
        else:
            signal_matches.append(pid)
    return {
        "result": "signal_match" if signal_matches else "error",
        "signal_match_pids": signal_matches,
        "errors": errors,
    }


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


def default_wait_processes_exit(
    processes: Sequence[dict[str, Any]],
    timeout: float,
    sleep: float = 0.25,
) -> dict[str, Any]:
    """Wait until every authorized PID no longer exists.

    A successful signal does not satisfy this wait. The PID must disappear
    from a fresh current-state lookup; otherwise the timeout is retained as a
    failed cleanup result.
    """
    pending = [process for process in processes if isinstance(process, dict)]
    deadline = time.monotonic() + timeout
    while pending and time.monotonic() < deadline:
        pending = [
            process
            for process in pending
            if isinstance(process.get("pid"), int)
            and _ps_record(process["pid"]) is not None
        ]
        if pending:
            time.sleep(sleep)
    if pending:
        raise TimeoutError(
            f"mission-owned processes still exist after {timeout:.0f}s: {pending!r}"
        )
    return {"result": "confirmed", "survivors": []}


@dataclass(frozen=True)
class CleanupProbes:
    """Injected probes for the cleanup seam; defaults are the production ones."""

    process_evidence: ProcessProbe = default_process_evidence
    stop: StopAction = default_stop
    stop_command: str = "SIGTERM only confirmed mission-owned identities"
    port_is_listening: PortProbe = default_port_is_listening
    wait_ports_closed: PortsClosedWait = default_wait_ports_closed
    wait_processes_exit: ProcessesExitWait = default_wait_processes_exit


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
) -> list[ProcessEvidence] | None:
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


def _identity_is_authorized(
    evidence: ProcessEvidence,
    *,
    pattern: str,
    mission_path: str,
    owner: str,
) -> bool:
    """Require current identity evidence before authorizing a signal."""
    if not isinstance(evidence, dict):
        return False
    if evidence.get("exists") is not True:
        return False
    if not isinstance(evidence.get("pid"), int):
        return False
    if evidence.get("owner") != owner:
        return False
    command = evidence.get("command")
    if not isinstance(command, str) or not _pattern_matches(pattern, command):
        return False
    ancestry = evidence.get("ancestry")
    if not isinstance(ancestry, list) or not ancestry:
        return False
    if not all(isinstance(parent, dict) for parent in ancestry):
        return False
    command_slice = [command, *[parent.get("command") for parent in ancestry]]
    if not all(isinstance(value, str) for value in command_slice):
        return False
    if not any(_pattern_matches(pattern, value) for value in command_slice):
        return False
    path_evidence = evidence.get("mission_path")
    if path_evidence != mission_path:
        return False
    cwd = evidence.get("cwd")
    path_in_commands = any(mission_path in value for value in command_slice)
    return (
        cwd == mission_path
        or path_in_commands
        or (evidence.get("mission_path_in_command") is True)
    )


def _pattern_matches(pattern: str, value: str) -> bool:
    """Match a safe alternation while retaining literal-pattern compatibility."""
    try:
        import re

        return re.search(pattern, value) is not None
    except re.error:
        return pattern in value


def _authorized_processes(
    evidence: Sequence[ProcessEvidence] | None,
    *,
    pattern: str,
    mission_path: str,
    owner: str,
) -> list[dict[str, Any]]:
    if evidence is None:
        return []
    return [
        item
        for item in evidence
        if _identity_is_authorized(
            item,
            pattern=pattern,
            mission_path=mission_path,
            owner=owner,
        )
    ]


def _process_survivor_labels(evidence: Sequence[ProcessEvidence] | None) -> list[Any]:
    """Keep exact probe values readable in JSON and backwards compatible."""
    return list(evidence or [])


def _stop_result_details(stop_result: Any) -> dict[str, Any]:
    if isinstance(stop_result, dict):
        return dict(stop_result)
    return_code = getattr(stop_result, "returncode", None)
    if return_code == 0:
        return {"result": "signal_match", "returncode": 0}
    if isinstance(stop_result, int) and stop_result == 0:
        return {"result": "signal_match", "returncode": 0}
    if isinstance(stop_result, str) and stop_result.startswith("exit 0"):
        return {"result": "signal_match", "detail": stop_result}
    return {"result": str(stop_result)}


def _invoke_stop(
    probes: CleanupProbes,
    pattern: str,
    authorized_processes: Sequence[dict[str, Any]],
) -> Any:
    """Invoke injected stops without weakening the production authority gate.

    Older offline fakes accepted only ``pattern``. They remain usable, while
    the maintained default and new fakes receive the exact authorized process
    identities instead of a stale or broad PID source.
    """
    try:
        parameters = inspect.signature(probes.stop).parameters.values()
        positional = [
            parameter
            for parameter in parameters
            if parameter.kind
            in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ]
        accepts_varargs = any(
            parameter.kind == inspect.Parameter.VAR_POSITIONAL
            for parameter in parameters
        )
    except (TypeError, ValueError):
        positional = []
        accepts_varargs = True
    if accepts_varargs or len(positional) >= 2:
        return probes.stop(pattern, authorized_processes)
    return probes.stop(pattern)


def run_stack_cleanup(
    *,
    run_id: str | None = None,
    target: str | None = None,
    record_path: Path,
    probes: CleanupProbes | None = None,
    ports: Sequence[int] = SAFE_STACK_PORTS,
    pattern: str = SAFE_PROCESS_PATTERN,
    stop_pattern: str | None = None,
    stop_timeout: float = 20.0,
    process_exit_timeout: float | None = None,
    mission_path: str = DEFAULT_MISSION_PATH,
    owner: str | None = None,
) -> dict[str, Any]:
    """Stop the stack and atomically record the complete cleanup evidence.

    Process and port state is observed before the stop and again as the final
    no-orphan/no-listener check. Listener closure is a separate milestone:
    after ports close, every process with complete current identity evidence
    receives a bounded exit wait. ``completed`` requires confirmed process exit
    and every documented port closed; a signal match or a timeout never proves
    process exit.
    """
    probes = probes or CleanupProbes()
    errors: list[str] = []
    checked_ports = list(ports)
    if any(port in UNSAFE_STACK_PORTS for port in checked_ports):
        errors.append(
            "cleanup port set contains forbidden ports: "
            f"{sorted(set(checked_ports).intersection(UNSAFE_STACK_PORTS))}"
        )
    process_exit_timeout = (
        stop_timeout if process_exit_timeout is None else process_exit_timeout
    )
    expected_owner = owner or getpass.getuser()

    process_evidence = _observe_processes(probes, pattern, errors)
    ports_open_before = _observe_ports(probes, checked_ports, errors)
    forbidden_ports_open_before = _observe_ports(probes, UNSAFE_STACK_PORTS, errors)
    authorized_processes = _authorized_processes(
        process_evidence,
        pattern=pattern,
        mission_path=mission_path,
        owner=expected_owner,
    )
    unauthorized_processes = [
        evidence
        for evidence in (process_evidence or [])
        if evidence not in authorized_processes
    ]

    if not authorized_processes:
        stop_result = {"result": "not_authorized", "signal_match_pids": []}
        stop_evidence = stop_result
    else:
        try:
            stop_result_raw = _invoke_stop(
                probes,
                stop_pattern or pattern,
                authorized_processes,
            )
            stop_result = stop_result_raw
            stop_evidence = _stop_result_details(stop_result_raw)
        except Exception as error:  # noqa: BLE001 - recorded, never raised
            errors.append(f"stop action failed: {error}")
            stop_result = f"error: {error}"
            stop_evidence = {
                "result": "error",
                "detail": str(error),
                "signal_match_pids": [],
            }

    listener_closure = "unavailable"
    try:
        probes.wait_ports_closed(checked_ports, stop_timeout)
        listener_closure = "confirmed"
    except Exception as error:  # noqa: BLE001 - recorded, never raised
        errors.append(f"ports did not close: {error}")
        listener_closure = "failed"

    ports_open_after = _observe_ports(probes, checked_ports, errors)
    forbidden_ports_open_after = _observe_ports(probes, UNSAFE_STACK_PORTS, errors)
    process_exit_wait: dict[str, Any] = {
        "status": "not_started",
        "timeout_seconds": process_exit_timeout,
        "confirmed_processes": authorized_processes,
        "survivors": [],
    }
    if listener_closure == "confirmed" and authorized_processes:
        try:
            wait_result = probes.wait_processes_exit(
                authorized_processes, process_exit_timeout
            )
            process_exit_wait = {
                "status": "confirmed",
                "timeout_seconds": process_exit_timeout,
                "confirmed_processes": authorized_processes,
                "survivors": [],
                "probe_result": wait_result,
            }
        except Exception as error:  # noqa: BLE001 - recorded, never raised
            errors.append(f"processes did not exit: {error}")
            process_exit_wait = {
                "status": "timeout",
                "timeout_seconds": process_exit_timeout,
                "confirmed_processes": authorized_processes,
                "survivors": authorized_processes,
                "error": str(error),
            }
    elif listener_closure == "confirmed":
        process_exit_wait["status"] = "confirmed"

    orphan_processes = _observe_processes(probes, pattern, errors)

    if orphan_processes is None:
        no_orphan_check = "unavailable"
    elif orphan_processes:
        no_orphan_check = "failed"
    else:
        no_orphan_check = "passed"
    ports_clear = None if ports_open_after is None else not ports_open_after

    stop_result_kind = stop_evidence.get("result")
    stop_raised = stop_result_kind == "error" or (
        isinstance(stop_result, str) and stop_result.startswith("error:")
    )
    stop_failed = bool(authorized_processes) and stop_result_kind != "signal_match"
    signal_match = stop_evidence.get("result") == "signal_match" or (
        isinstance(stop_result, str) and stop_result.startswith("exit 0")
    )
    timeout = process_exit_wait["status"] == "timeout"
    if (
        stop_raised
        or stop_failed
        or process_evidence is None
        or ports_open_before is None
        or ports_open_after is None
        or forbidden_ports_open_before is None
        or forbidden_ports_open_after is None
        or orphan_processes is None
        or bool(forbidden_ports_open_before)
        or bool(forbidden_ports_open_after)
    ):
        # The final state is unknown; never claim completion.
        status = STATUS_ERROR
    elif timeout or listener_closure != "confirmed":
        status = STATUS_FAILED
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
        "authorized_processes": authorized_processes,
        "unauthorized_processes": unauthorized_processes,
        "ports_open_before": ports_open_before,
        "forbidden_ports": list(UNSAFE_STACK_PORTS),
        "forbidden_ports_open_before": forbidden_ports_open_before,
        "stop_command": probes.stop_command,
        "stop_result": stop_result,
        "stop_evidence": stop_evidence,
        "signal_match": signal_match,
        "listener_closure": {
            "status": listener_closure,
            "ports": checked_ports,
            "ports_open_after": ports_open_after,
        },
        "process_exit_wait": process_exit_wait,
        "ports_open_after": ports_open_after,
        "forbidden_ports_open_after": forbidden_ports_open_after,
        "ports_clear": ports_clear,
        "orphan_processes": orphan_processes,
        "no_orphan_check": no_orphan_check,
        "status": status,
        "errors": errors,
        "record_path": str(record_path),
        "current_verification": {
            "schema_version": CURRENT_VERIFICATION_SCHEMA,
            "recorded_at": _utc_now(),
            "processes": {
                "before": _process_survivor_labels(process_evidence),
                "authorized": authorized_processes,
                "after": _process_survivor_labels(orphan_processes),
                "remaining_mission_owned": _authorized_processes(
                    orphan_processes,
                    pattern=pattern,
                    mission_path=mission_path,
                    owner=expected_owner,
                ),
            },
            "ports": {
                "checked": checked_ports,
                "open_before": ports_open_before,
                "open_after": ports_open_after,
                "forbidden": list(UNSAFE_STACK_PORTS),
                "forbidden_open_before": forbidden_ports_open_before,
                "forbidden_open_after": forbidden_ports_open_after,
            },
            "action": {
                "stop_command": probes.stop_command,
                "stop_result": stop_result,
                "stop_evidence": stop_evidence,
                "signal_authorized_from_current_identity": bool(authorized_processes),
            },
            "result": status,
            "historical_distinction": (
                f"current verification; not a rewrite of the preserved "
                f"{HISTORICAL_FAILURE_TIMESTAMP} failure at {HISTORICAL_FAILURE_PATH}"
            ),
        },
    }
    current_verification_path = record_path.with_name(
        f"{record_path.stem}-current-verification-{record['recorded_at'].replace(':', '')}.json"
    )
    record["current_verification_record"] = str(current_verification_path)
    write_cleanup_record(record["current_verification"], current_verification_path)
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
    if any(port in UNSAFE_STACK_PORTS for port in checked_ports):
        errors.append(
            "pause port set contains forbidden ports: "
            f"{sorted(set(checked_ports).intersection(UNSAFE_STACK_PORTS))}"
        )
    process_evidence = _observe_processes(probes, pattern, errors)
    ports_open = _observe_ports(probes, checked_ports, errors)
    forbidden_ports_open = _observe_ports(probes, UNSAFE_STACK_PORTS, errors)
    recorded_at = _utc_now()
    pause_status = (
        STATUS_ERROR
        if errors or forbidden_ports_open is None or forbidden_ports_open
        else STATUS_KEPT_RUNNING
    )
    record: dict[str, Any] = {
        "schema_version": CLEANUP_SCHEMA,
        "run_id": run_id,
        "target": target,
        "recorded_at": recorded_at,
        "checked_ports": checked_ports,
        "forbidden_ports": list(UNSAFE_STACK_PORTS),
        "process_evidence": process_evidence,
        "ports_open_before": ports_open,
        "forbidden_ports_open_before": forbidden_ports_open,
        "stop_command": None,
        "stop_result": None,
        "stop_evidence": None,
        "listener_closure": {"status": "not_attempted", "ports": checked_ports},
        "process_exit_wait": {
            "status": "not_attempted",
            "confirmed_processes": [],
            "survivors": [],
        },
        "signal_match": False,
        "status": pause_status,
        "resume_reason": resume_reason,
        "resume_scope": resume_scope,
        "errors": errors,
        "record_path": str(record_path),
        "current_verification": {
            "schema_version": CURRENT_VERIFICATION_SCHEMA,
            "recorded_at": recorded_at,
            "processes": {"current": _process_survivor_labels(process_evidence)},
            "ports": {"checked": checked_ports, "open": ports_open},
            "action": {
                "type": "intentional_pause",
                "reason": resume_reason,
                "scope": resume_scope,
                "signal_authorized_from_current_identity": False,
            },
            "result": pause_status,
            "historical_distinction": (
                f"current verification; not a rewrite of the preserved "
                f"{HISTORICAL_FAILURE_TIMESTAMP} failure at {HISTORICAL_FAILURE_PATH}"
            ),
        },
    }
    current_verification_path = record_path.with_name(
        f"{record_path.stem}-current-verification-{recorded_at.replace(':', '')}.json"
    )
    record["current_verification_record"] = str(current_verification_path)
    write_cleanup_record(record["current_verification"], current_verification_path)
    write_cleanup_record(record, record_path)
    return record
