"""Safe-only per-service lifecycle and identity-checked cleanup."""

from __future__ import annotations

import os
import signal
import subprocess
from dataclasses import dataclass
from typing import Any, Callable, Sequence

SAFE_PORTS = frozenset({8321, 8888, 8890, 8892})
UNSAFE_PORTS = frozenset({8889, 8891, 8893})
FORBIDDEN_WRAPPERS = ("stack", "six-service", "unsafe")


@dataclass(frozen=True)
class SafeService:
    name: str
    port: int
    start: tuple[str, ...]
    stop: tuple[str, ...]
    healthcheck: tuple[str, ...] = ()


def assert_safe_service(service: SafeService) -> None:
    if service.port not in SAFE_PORTS or service.port in UNSAFE_PORTS:
        raise ValueError(f"service port is outside the safe allowlist: {service.port}")
    command = " ".join(service.start).lower()
    if any(wrapper in command for wrapper in FORBIDDEN_WRAPPERS):
        raise ValueError("combined or unsafe service wrappers are forbidden")
    if any(str(port) in command for port in UNSAFE_PORTS):
        raise ValueError("unsafe port appears in safe service command")


def probe_ports(
    probe: Callable[[int], bool],
    *,
    ports: Sequence[int] = tuple(sorted(SAFE_PORTS | UNSAFE_PORTS)),
) -> dict[int, bool]:
    """Record every allowed port and fail closed if an unsafe port listens."""

    observed = {port: bool(probe(port)) for port in ports}
    open_unsafe = [port for port in UNSAFE_PORTS if observed.get(port)]
    if open_unsafe:
        raise RuntimeError(f"unsafe ports are listening: {sorted(open_unsafe)}")
    return observed


def start_safe_service(
    service: SafeService,
    *,
    popen: Callable[..., Any] = subprocess.Popen,
    identity: Callable[[int], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Start one allowlisted service and capture its process identity."""

    assert_safe_service(service)
    process = popen(list(service.start), start_new_session=True)
    pid = int(process.pid)
    captured = (
        identity(pid) if identity else {"pid": pid, "command": list(service.start)}
    )
    return {
        "service": service.name,
        "port": service.port,
        "pid": pid,
        "identity": captured,
    }


def cleanup_captured_identities(
    identities: Sequence[dict[str, Any]],
    *,
    current_identity: Callable[[int], dict[str, Any] | None],
    stop: Callable[[int], Any] | None = None,
) -> dict[str, Any]:
    """Signal only identities that still match their captured process record."""

    stopped: list[int] = []
    refused: list[int] = []
    errors: list[str] = []
    stop = stop or (lambda pid: os.kill(pid, signal.SIGTERM))
    for captured in identities:
        pid = captured.get("pid")
        current = current_identity(pid) if isinstance(pid, int) else None
        if current is None or not _identity_matches(captured, current):
            refused.append(pid)
            continue
        try:
            stop(pid)
        except (OSError, ProcessLookupError) as exc:
            errors.append(f"pid {pid}: {exc}")
        else:
            stopped.append(pid)
    return {
        "stopped": stopped,
        "refused": refused,
        "errors": errors,
        "complete": not errors and not refused,
    }


def _identity_matches(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    keys = ("pid", "command", "owner", "cwd", "identity")
    compared = [key for key in keys if key in expected]
    return bool(compared) and all(
        expected.get(key) == current.get(key) for key in compared
    )


__all__ = [
    "FORBIDDEN_WRAPPERS",
    "SAFE_PORTS",
    "UNSAFE_PORTS",
    "SafeService",
    "assert_safe_service",
    "cleanup_captured_identities",
    "probe_ports",
    "start_safe_service",
]
