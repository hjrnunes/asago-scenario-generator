"""Safe-only per-service lifecycle and identity-checked cleanup.

The normal mini-agents stack starts six MCP servers and therefore opens the
three ports reserved for unsafe counterparts.  This module keeps the bounded
alternative deliberately small: one gateway and one safe target process per
service.  Process identities are persisted separately from the command
environment so cleanup can refuse a stale or reused PID.
"""

from __future__ import annotations

import copy
import json
import os
import re
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Sequence
from urllib.parse import urlparse

SAFE_GATEWAY_PORT = 8321
SAFE_TARGET_PORTS: dict[str, int] = {
    "klarna": 8888,
    "airbnb": 8890,
    "occiai": 8892,
}
SAFE_PORTS = frozenset({SAFE_GATEWAY_PORT, *SAFE_TARGET_PORTS.values()})
UNSAFE_PORTS = frozenset({8889, 8891, 8893})
SAFE_CONNECTORS: dict[str, str] = {
    f"{domain}-safe": f"http://localhost:{port}/sse"
    for domain, port in SAFE_TARGET_PORTS.items()
}

# These values describe the complete boundary checked by this module.  The
# legacy stack wrapper remains available for historical offline tests, but no
# safe service may invoke it.
FORBIDDEN_WRAPPERS = ("stack", "six-service", "unsafe", "compose")
IDENTITY_SCHEMA = "safe-service-process-identity-v1"
IDENTITY_FILENAME = "process-identity.json"
STOP_RESULT_FILENAME = "stop-result.json"


@dataclass(frozen=True)
class SafeService:
    """One independently startable service in the safe-only topology."""

    name: str
    port: int
    start: tuple[str, ...]
    stop: tuple[str, ...]
    healthcheck: tuple[str, ...] = ()
    cwd: str | None = None


def _command_text(command: Sequence[str]) -> str:
    return " ".join(str(part) for part in command).lower()


def assert_safe_service(service: SafeService) -> None:
    """Reject a service definition that can cross the mission boundary."""

    if service.port not in SAFE_PORTS or service.port in UNSAFE_PORTS:
        raise ValueError(f"service port is outside the safe allowlist: {service.port}")
    command = _command_text(service.start)
    if any(wrapper in command for wrapper in FORBIDDEN_WRAPPERS):
        raise ValueError("combined or unsafe service wrappers are forbidden")
    if "--unsafe" in command:
        raise ValueError("unsafe mode is forbidden for safe services")
    if any(str(port) in command for port in UNSAFE_PORTS):
        raise ValueError("unsafe port appears in safe service command")


def _target_python(target_root: Path) -> str:
    target_root = Path(target_root)
    candidate = target_root / ".venv" / "bin" / "python"
    return str(candidate) if candidate.is_file() else sys.executable


def safe_target_service(
    domain: str,
    *,
    port: int | None = None,
    target_root: Path = Path("/Users/hjrnunes/workspace/hjrnunes/mini-agents"),
) -> SafeService:
    """Build the direct safe MCP entry point for one target domain."""

    target_root = Path(target_root)
    if domain not in SAFE_TARGET_PORTS:
        raise ValueError(f"unknown safe target domain: {domain!r}")
    expected_port = SAFE_TARGET_PORTS[domain]
    selected_port = expected_port if port is None else port
    if selected_port != expected_port:
        raise ValueError(
            f"safe target {domain!r} must use port {expected_port}, not {selected_port}"
        )
    command = (
        _target_python(target_root),
        "-m",
        "mini_agents",
        "--domain",
        domain,
        "--host",
        "127.0.0.1",
        "--port",
        str(selected_port),
    )
    return SafeService(
        name=domain,
        port=selected_port,
        start=command,
        stop=("pid", str(selected_port)),
        healthcheck=("port", str(selected_port)),
        cwd=str(target_root),
    )


def safe_gateway_service(
    *,
    gateway_config: Path,
    port: int = SAFE_GATEWAY_PORT,
    target_root: Path = Path("/Users/hjrnunes/workspace/hjrnunes/mini-agents"),
) -> SafeService:
    """Build the direct OGX entry point for the safe connector config."""

    target_root = Path(target_root)
    gateway_config = Path(gateway_config)
    if port != SAFE_GATEWAY_PORT:
        raise ValueError(f"safe gateway must use port {SAFE_GATEWAY_PORT}, not {port}")
    executable = target_root / ".venv" / "bin" / "ogx"
    ogx = str(executable) if executable.is_file() else "ogx"
    return SafeService(
        name="gateway",
        port=port,
        start=(ogx, "run", str(gateway_config), "--insecure"),
        stop=("pid", str(port)),
        healthcheck=("port", str(port)),
        cwd=str(target_root),
    )


def safe_service_definitions(
    *,
    target_root: Path = Path("/Users/hjrnunes/workspace/hjrnunes/mini-agents"),
    gateway_config: Path = Path("ogx-config-safe.yaml"),
) -> dict[str, SafeService]:
    """Return the only four services allowed by the safe-only recipe."""

    target_root = Path(target_root)
    gateway_config = Path(gateway_config)
    services = {
        "gateway": safe_gateway_service(
            gateway_config=gateway_config,
            target_root=target_root,
        ),
    }
    services.update(
        {
            domain: safe_target_service(domain, target_root=target_root)
            for domain in SAFE_TARGET_PORTS
        }
    )
    for service in services.values():
        assert_safe_service(service)
    return services


def _sanitize_config(value: Any, key: str | None = None) -> Any:
    """Keep environment placeholders while removing inline credential data."""

    sensitive = {
        "api_key",
        "api_token",
        "access_token",
        "client_secret",
        "password",
        "secret",
        "token",
    }
    if key and key.lower() in sensitive:
        if isinstance(value, str) and value.startswith("${env."):
            return value
        return "${env.OPENAI_API_KEY:=unused}"
    if isinstance(value, dict):
        return {
            item_key: _sanitize_config(item_value, str(item_key))
            for item_key, item_value in value.items()
        }
    if isinstance(value, list):
        return [_sanitize_config(item) for item in value]
    return value


def _write_json_atomic(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def render_safe_gateway_config(source: Path) -> str:
    """Render a validated safe-only OGX config without writing a file."""

    import yaml

    loaded = yaml.safe_load(source.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError(f"{source} is not a gateway configuration mapping")
    config = _sanitize_config(copy.deepcopy(loaded))
    config["server"] = dict(config.get("server") or {})
    config["server"]["port"] = SAFE_GATEWAY_PORT

    connectors = config.get("connectors")
    if not isinstance(connectors, list):
        raise ValueError(f"{source} has no connector list")
    safe_connectors: list[dict[str, Any]] = []
    safe_ports = set(SAFE_TARGET_PORTS.values())
    for connector in connectors:
        if not isinstance(connector, dict):
            continue
        connector_id = connector.get("connector_id")
        url = connector.get("url")
        parsed = urlparse(url) if isinstance(url, str) else None
        try:
            connector_port = parsed.port if parsed is not None else None
        except ValueError:
            connector_port = None
        if (
            isinstance(connector_id, str)
            and connector_id in SAFE_CONNECTORS
            and connector_port in safe_ports
            and parsed is not None
            and parsed.hostname in {"localhost", "127.0.0.1"}
        ):
            safe_entry = dict(connector)
            safe_entry["url"] = SAFE_CONNECTORS[connector_id]
            safe_connectors.append(safe_entry)
    config["connectors"] = safe_connectors

    if {entry.get("connector_id") for entry in safe_connectors} != set(SAFE_CONNECTORS):
        raise ValueError("gateway config does not contain every safe connector")

    rendered = yaml.safe_dump(config, sort_keys=False)
    if any(str(port) in rendered for port in UNSAFE_PORTS):
        raise ValueError("scratch gateway config contains a forbidden port")
    return rendered


def build_safe_gateway_config(
    source: Path,
    destination: Path,
    *,
    profile_values: Mapping[str, str] | None = None,
) -> Path:
    """Write a scratch OGX config containing safe connectors only.

    ``profile_values`` is accepted by the caller-facing seam to make the
    environment boundary explicit, but values are intentionally never copied
    into this file.  The gateway receives them through ``Popen(env=...)``.
    """

    del profile_values
    rendered = render_safe_gateway_config(source)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(f".{destination.name}.tmp-{os.getpid()}")
    try:
        temporary.write_text(rendered, encoding="utf-8")
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def _process_cwd(pid: int) -> str | None:
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


def capture_process_identity(pid: int) -> dict[str, Any]:
    """Capture stable process fields used to guard a later signal."""

    result = subprocess.run(
        ["ps", "-o", "pid=,ppid=,user=,command=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0 or not result.stdout.strip():
        raise RuntimeError(f"process {pid} disappeared before identity capture")
    fields = result.stdout.strip().split(None, 3)
    if len(fields) < 4:
        raise RuntimeError(f"process {pid} identity output is incomplete")
    current_pid, parent_pid, owner, command = fields
    start_time = subprocess.run(
        ["ps", "-o", "lstart=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    ).stdout.strip()
    return {
        "pid": int(current_pid),
        "ppid": int(parent_pid),
        "owner": owner,
        "command": command,
        "cwd": _process_cwd(pid),
        "start_time": start_time,
        "exists": True,
    }


def _redact_identity(value: Any, secrets: Sequence[str]) -> Any:
    if isinstance(value, dict):
        return {key: _redact_identity(item, secrets) for key, item in value.items()}
    if isinstance(value, list):
        return [_redact_identity(item, secrets) for item in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret and secret in value:
                return "[redacted]"
    return value


def _identity_path(state_dir: Path, service: SafeService) -> Path:
    return Path(state_dir) / service.name / IDENTITY_FILENAME


def _legacy_identity_path(state_dir: Path) -> Path:
    return Path(state_dir) / IDENTITY_FILENAME


def _stored_identity_path(state_dir: Path, service: SafeService) -> Path:
    canonical = _identity_path(state_dir, service)
    if canonical.is_file():
        return canonical
    legacy = _legacy_identity_path(state_dir)
    return legacy if legacy.is_file() else canonical


def _stop_result_path(state_dir: Path, service: SafeService) -> Path:
    return Path(state_dir) / service.name / STOP_RESULT_FILENAME


def load_persisted_identity(
    state_dir: Path,
    service: SafeService | None = None,
) -> dict[str, Any] | None:
    """Load one persisted identity without treating malformed state as safe."""

    path = (
        _stored_identity_path(state_dir, service)
        if service is not None
        else _legacy_identity_path(state_dir)
    )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(value, dict):
        return None
    if service is not None and (
        value.get("service") != service.name or value.get("port") != service.port
    ):
        return None
    identity = value.get("identity")
    return identity if isinstance(identity, dict) else None


def start_safe_service(
    service: SafeService,
    *,
    popen: Callable[..., Any] = subprocess.Popen,
    identity: Callable[[int], dict[str, Any]] | None = None,
    state_dir: Path,
    environment: Mapping[str, str] | None = None,
    cwd: str | Path | None = None,
) -> dict[str, Any]:
    """Start one allowlisted service and persist its captured identity."""

    assert_safe_service(service)
    child_environment = {**os.environ, **(dict(environment) if environment else {})}
    process = popen(
        list(service.start),
        start_new_session=True,
        cwd=str(cwd or service.cwd) if (cwd or service.cwd) else None,
        env=child_environment,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    pid = int(process.pid)
    capture = identity or capture_process_identity
    try:
        captured = capture(pid)
    except Exception:
        try:
            process.terminate()
        except (AttributeError, OSError):
            pass
        raise
    if not isinstance(captured, dict) or captured.get("pid") != pid:
        raise ValueError(f"captured identity for {service.name} does not match pid")

    result: dict[str, Any] = {
        "schema_version": IDENTITY_SCHEMA,
        "service": service.name,
        "port": service.port,
        "pid": pid,
        "identity": _redact_identity(
            captured,
            [
                str(value)
                for value in (environment or {}).values()
                if isinstance(value, str)
            ],
        ),
    }
    path = _identity_path(state_dir, service)
    _write_json_atomic(path, result)
    result["identity_path"] = str(path)
    return result


def _identity_matches(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    """Compare the captured process record with fresh current evidence."""

    nested = expected.get("identity")
    if isinstance(nested, dict):
        expected = {**nested, "pid": expected.get("pid", nested.get("pid"))}
    keys = ("pid", "command", "owner", "cwd", "start_time")
    compared = [key for key in keys if key in expected and key in current]
    return bool(compared) and all(
        expected.get(key) == current.get(key) for key in compared
    )


def identity_matches(expected: dict[str, Any], current: dict[str, Any]) -> bool:
    """Public identity comparison used by recipe verification and cleanup."""

    return _identity_matches(expected, current)


def verify_persisted_identity(
    service: SafeService,
    *,
    state_dir: Path,
    current_identity: Callable[[int], dict[str, Any] | None] = capture_process_identity,
) -> dict[str, Any]:
    """Return truthful evidence for a persisted service identity."""

    path = _stored_identity_path(state_dir, service)
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return {
            "service": service.name,
            "port": service.port,
            "identity_path": str(path),
            "status": "identity_unavailable",
            "identity": None,
            "current_identity": None,
        }
    if (
        not isinstance(stored, dict)
        or not isinstance(stored.get("pid"), int)
        or stored.get("service") != service.name
        or stored.get("port") != service.port
    ):
        return {
            "service": service.name,
            "port": service.port,
            "identity_path": str(path),
            "status": "identity_invalid",
            "identity": None,
            "current_identity": None,
        }
    current = current_identity(stored["pid"])
    expected = stored.get("identity")
    matches = (
        isinstance(expected, dict)
        and current is not None
        and _identity_matches({"pid": stored["pid"], **expected}, current)
    )
    return {
        "service": service.name,
        "port": service.port,
        "identity_path": str(path),
        "status": "verified" if matches else "identity_mismatch",
        "identity": expected,
        "current_identity": current,
    }


def stop_safe_service(
    service: SafeService,
    *,
    state_dir: Path,
    current_identity: Callable[[int], dict[str, Any] | None] = capture_process_identity,
    stop: Callable[[int], Any] | None = None,
    wait: Callable[[int], Any] | None = None,
) -> dict[str, Any]:
    """Stop only the PID whose current identity still matches the persisted one."""

    assert_safe_service(service)
    path = _stored_identity_path(state_dir, service)

    def record_result(result: dict[str, Any]) -> dict[str, Any]:
        _write_json_atomic(
            _stop_result_path(state_dir, service),
            {
                "schema_version": "safe-service-stop-result-v1",
                "recorded_at": datetime.now(timezone.utc).strftime(
                    "%Y-%m-%dT%H:%M:%SZ"
                ),
                **result,
            },
        )
        return result

    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return record_result(
            {
                "service": service.name,
                "identity_path": str(path),
                "stopped": [],
                "refused": ["missing_or_malformed_identity"],
                "errors": [],
                "complete": False,
            }
        )
    if (
        not isinstance(stored, dict)
        or not isinstance(stored.get("pid"), int)
        or stored.get("service") != service.name
        or stored.get("port") != service.port
    ):
        return record_result(
            {
                "service": service.name,
                "identity_path": str(path),
                "stopped": [],
                "refused": ["missing_or_malformed_identity"],
                "errors": [],
                "complete": False,
            }
        )
    pid = stored["pid"]
    try:
        current = current_identity(pid)
    except (OSError, RuntimeError, ValueError):
        current = None
    expected = stored.get("identity")
    if (
        not isinstance(expected, dict)
        or current is None
        or not _identity_matches({**expected, "pid": pid}, current)
    ):
        return record_result(
            {
                "service": service.name,
                "identity_path": str(path),
                "stopped": [],
                "refused": [pid],
                "errors": [],
                "complete": False,
            }
        )
    signal_process = stop or (lambda current_pid: os.kill(current_pid, signal.SIGTERM))
    try:
        signal_process(pid)
        if wait is not None:
            wait(pid)
    except (OSError, ProcessLookupError, TimeoutError) as error:
        result = {
            "service": service.name,
            "identity_path": str(path),
            "stopped": [],
            "refused": [],
            "errors": [str(error)],
            "complete": False,
        }
    else:
        result = {
            "service": service.name,
            "identity_path": str(path),
            "stopped": [pid],
            "refused": [],
            "errors": [],
            "complete": True,
        }
    return record_result(result)


def cleanup_captured_identities(
    identities: Sequence[dict[str, Any]],
    *,
    current_identity: Callable[[int], dict[str, Any] | None],
    stop: Callable[[int], Any] | None = None,
) -> dict[str, Any]:
    """Signal only identities that still match their captured process record."""

    stopped: list[int] = []
    refused: list[Any] = []
    errors: list[str] = []
    signal_process = stop or (lambda pid: os.kill(pid, signal.SIGTERM))
    for captured in identities:
        pid = captured.get("pid")
        current = current_identity(pid) if isinstance(pid, int) else None
        if current is None or not _identity_matches(captured, current):
            refused.append(pid)
            continue
        try:
            signal_process(pid)
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


def _pattern_matches(command: str, pattern: str) -> bool:
    try:
        return re.search(pattern, command) is not None
    except re.error:
        return pattern in command


def probe_ports(
    probe: Callable[[int], bool],
    *,
    ports: Sequence[int] = tuple(sorted(SAFE_PORTS | UNSAFE_PORTS)),
) -> dict[int, bool]:
    """Record every boundary port and fail closed if an unsafe port listens."""

    observed = {port: bool(probe(port)) for port in ports}
    open_unsafe = [port for port in UNSAFE_PORTS if observed.get(port)]
    if open_unsafe:
        raise RuntimeError(f"unsafe ports are listening: {sorted(open_unsafe)}")
    return observed


__all__ = [
    "FORBIDDEN_WRAPPERS",
    "IDENTITY_FILENAME",
    "IDENTITY_SCHEMA",
    "SAFE_CONNECTORS",
    "SAFE_GATEWAY_PORT",
    "SAFE_PORTS",
    "SAFE_TARGET_PORTS",
    "STOP_RESULT_FILENAME",
    "UNSAFE_PORTS",
    "SafeService",
    "assert_safe_service",
    "build_safe_gateway_config",
    "capture_process_identity",
    "cleanup_captured_identities",
    "identity_matches",
    "load_persisted_identity",
    "probe_ports",
    "safe_gateway_service",
    "safe_service_definitions",
    "safe_target_service",
    "start_safe_service",
    "stop_safe_service",
    "verify_persisted_identity",
]
