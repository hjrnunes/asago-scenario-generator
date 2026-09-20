from __future__ import annotations

import json
from pathlib import Path

import yaml

from safe_lifecycle import (
    SAFE_GATEWAY_PORT,
    SAFE_PORTS,
    SAFE_TARGET_PORTS,
    UNSAFE_PORTS,
    SafeService,
    assert_safe_service,
    build_safe_gateway_config,
    cleanup_captured_identities,
    probe_ports,
    safe_service_definitions,
    start_safe_service,
    stop_safe_service,
)


def test_safe_service_commands_are_individual_and_ports_are_allowlisted() -> None:
    service = SafeService(
        name="klarna_safe",
        port=8888,
        start=("python", "-m", "mini_agents", "--domain", "klarna", "--port", "8888"),
        stop=("kill", "123"),
    )

    assert service.port in SAFE_PORTS
    assert "--port" in service.start
    assert "8889" not in service.start
    assert_safe_service(service)
    assert all(port not in SAFE_PORTS for port in UNSAFE_PORTS)


def test_cleanup_signals_only_current_matching_identities() -> None:
    signaled: list[int] = []
    result = cleanup_captured_identities(
        [
            {"pid": 10, "command": "safe", "identity": "a"},
            {"pid": 11, "command": "changed", "identity": "b"},
        ],
        current_identity=lambda pid: (
            {"pid": pid, "command": "safe", "identity": "a"}
            if pid == 10
            else {"pid": pid, "command": "different", "identity": "other"}
        ),
        stop=lambda pid: signaled.append(pid),
    )

    assert signaled == [10]
    assert result["stopped"] == [10]
    assert result["refused"] == [11]


def test_port_probe_rejects_any_unsafe_listener() -> None:
    observed = probe_ports(lambda port: port == 8888)
    assert observed[8888] is True
    assert all(observed[port] is False for port in UNSAFE_PORTS)


def test_safe_service_definitions_cover_only_gateway_and_safe_targets() -> None:
    services = safe_service_definitions(
        target_root=Path("/tmp/mini-agents"),
        gateway_config=Path("/tmp/gateway-safe.yaml"),
    )

    assert set(services) == {"gateway", "klarna", "airbnb", "occiai"}
    assert services["gateway"].port == SAFE_GATEWAY_PORT
    assert {domain: services[domain].port for domain in SAFE_TARGET_PORTS} == dict(
        SAFE_TARGET_PORTS
    )
    for service in services.values():
        assert_safe_service(service)
        command = " ".join(service.start)
        assert all(str(port) not in command for port in UNSAFE_PORTS)


def test_safe_gateway_config_filters_unsafe_connectors_and_profile_values(
    tmp_path: Path,
) -> None:
    source = tmp_path / "ogx-config.yaml"
    destination = tmp_path / "runtime" / "gateway-safe.yaml"
    source.write_text(
        """
version: 2
server:
  port: 8321
providers:
  inference:
    - config:
        api_token: ${env.OPENAI_API_KEY:=fake}
        base_url: ${env.OPENAI_BASE_URL:=http://host.docker.internal:11434/v1}
connectors:
  - connector_id: klarna-safe
    url: http://localhost:8888/sse
  - connector_id: klarna-unsafe
    url: http://localhost:8889/sse
  - connector_id: airbnb-safe
    url: http://localhost:8890/sse
  - connector_id: airbnb-unsafe
    url: http://localhost:8891/sse
  - connector_id: occiai-safe
    url: http://localhost:8892/sse
  - connector_id: occiai-unsafe
    url: http://localhost:8893/sse
""".strip()
        + "\n",
        encoding="utf-8",
    )

    written = build_safe_gateway_config(
        source,
        destination,
        profile_values={
            "base_url": "https://secret.example.invalid/v1",
            "api_key": "test-value-not-persisted",
        },
    )

    assert written == destination
    text = destination.read_text(encoding="utf-8")
    assert "klarna-safe" in text
    assert "airbnb-safe" in text
    assert "occiai-safe" in text
    assert all(str(port) not in text for port in UNSAFE_PORTS)
    assert "secret.example.invalid" not in text
    assert "test-value-not-persisted" not in text
    assert yaml.safe_load(text)["server"]["port"] == 8321


def test_start_safe_service_persists_captured_identity_without_environment(
    tmp_path: Path,
) -> None:
    class FakeProcess:
        pid = 4321

    calls: list[dict[str, object]] = []

    def fake_popen(command, **kwargs):
        calls.append({"command": command, **kwargs})
        return FakeProcess()

    result = start_safe_service(
        SafeService(
            name="klarna",
            port=8888,
            start=("python", "-m", "mini_agents", "--port", "8888"),
            stop=("identity",),
        ),
        popen=fake_popen,
        identity=lambda pid: {
            "pid": pid,
            "command": "python -m mini_agents --port 8888",
            "owner": "tester",
        },
        state_dir=tmp_path,
        environment={"OPENAI_API_KEY": "test-value-not-persisted"},
    )

    identity_path = Path(result["identity_path"])
    assert identity_path.is_file()
    persisted = json.loads(identity_path.read_text(encoding="utf-8"))
    assert persisted["pid"] == 4321
    assert persisted["identity"]["owner"] == "tester"
    assert "test-value-not-persisted" not in json.dumps(persisted)
    assert calls[0]["env"]["OPENAI_API_KEY"] == "test-value-not-persisted"


def test_start_safe_service_uses_one_identity_file_per_service(
    tmp_path: Path,
) -> None:
    class FakeProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

    next_pid = iter((4321, 4322))

    def fake_popen(_command, **_kwargs):
        return FakeProcess(next(next_pid))

    def fake_identity(pid: int) -> dict[str, object]:
        return {"pid": pid, "command": "safe", "owner": "tester"}

    for service in (
        SafeService(name="klarna", port=8888, start=("klarna",), stop=("pid",)),
        SafeService(name="airbnb", port=8890, start=("airbnb",), stop=("pid",)),
    ):
        start_safe_service(
            service,
            popen=fake_popen,
            identity=fake_identity,
            state_dir=tmp_path,
        )

    assert (tmp_path / "klarna" / "process-identity.json").is_file()
    assert (tmp_path / "airbnb" / "process-identity.json").is_file()


def test_stop_safe_service_refuses_a_reused_pid(tmp_path: Path) -> None:
    identity_path = tmp_path / "process-identity.json"
    identity_path.write_text(
        json.dumps(
            {
                "schema_version": "safe-service-process-identity-v1",
                "service": "klarna",
                "port": 8888,
                "pid": 4321,
                "identity": {
                    "pid": 4321,
                    "command": "python -m mini_agents --port 8888",
                    "owner": "tester",
                },
            }
        ),
        encoding="utf-8",
    )
    signaled: list[int] = []

    result = stop_safe_service(
        SafeService(
            name="klarna",
            port=8888,
            start=("python", "-m", "mini_agents", "--port", "8888"),
            stop=("identity",),
        ),
        state_dir=tmp_path,
        current_identity=lambda _pid: {
            "pid": 4321,
            "command": "different-process",
            "owner": "tester",
        },
        stop=signaled.append,
    )

    assert result["complete"] is False
    assert result["refused"] == [4321]
    assert signaled == []
