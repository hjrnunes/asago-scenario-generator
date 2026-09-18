from __future__ import annotations

from safe_lifecycle import (
    SAFE_PORTS,
    UNSAFE_PORTS,
    SafeService,
    assert_safe_service,
    cleanup_captured_identities,
    probe_ports,
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
