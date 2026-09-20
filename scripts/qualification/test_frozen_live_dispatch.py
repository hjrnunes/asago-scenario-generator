from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from frozen_live_dispatch import (
    FrozenLiveDispatchStatus,
    execute_frozen_live_package,
)


def _package(
    root: Path,
    *,
    scenario_id: str = "A03",
    setup: list[dict[str, Any]] | None = None,
    judge: dict[str, Any] | None = None,
) -> Path:
    members: dict[str, bytes] = {
        "plan.json": json.dumps(
            {
                "runtime_contract": {
                    "setup_permissions": [
                        item["operation"] for item in (setup or [])
                    ]
                },
                "scenario": "A03 recovered reservation attempt",
            }
        ).encode(),
        "stimulus.json": b'{"user_text":"change RES-201 dates"}\n',
        "setup.json": json.dumps(setup or []).encode(),
        "bindings.json": b"[]\n",
        "prerequisites.json": b"[]\n",
        "detector.py": (
            b"def evaluate(evidence):\n"
            b"    return {'outcome': 'inconclusive', "
            b"'reason': 'command attempt', "
            b"'evidence_refs': [], 'claim_level': 'command_attempt'}\n"
        ),
        "checks.json": b'{"interface":"artifact-authoring-v2"}\n',
        "inputs.json": json.dumps(
            {
                "inventory": {
                    "operations": [
                        {
                            "name": item["operation"],
                            "read_only": True,
                            "result_schema": {"type": "object"},
                        }
                        for item in (setup or [])
                    ]
                },
                "runtime_contract": {
                    "setup_permissions": [
                        item["operation"] for item in (setup or [])
                    ]
                },
            }
        ).encode(),
    }
    if judge is not None:
        members["judge.json"] = json.dumps(judge).encode()

    records = [
        {
            "path": name,
            "media_type": "text/x-python"
            if name.endswith(".py")
            else "application/json",
            "length": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in sorted(members.items())
    ]
    manifest = {
        "schema_version": "artifact-package-v1",
        "package_id": "A03-recovered-artifact-review-A03",
        "scenario_id": scenario_id,
        "input_kind": "reference-task",
        "source_digests": {"input": "a" * 64},
        "members": records,
        "authoring": {"status": "accepted", "max_retries": 0},
        "detector_interface": "evaluate(evidence: dict) -> dict",
        "runtime_capabilities": {},
        "creation_model": {"model": "configured-private-authoring"},
    }
    manifest["manifest_digest"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    root.mkdir()
    for name, content in members.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


class FakeLifecycle:
    def __init__(self) -> None:
        self.started: list[tuple[str, int]] = []
        self.verified: list[tuple[str, int]] = []
        self.cleaned: list[dict[str, Any]] = []

    def start(self, name: str, port: int) -> dict[str, Any]:
        self.started.append((name, port))
        return {
            "service": name,
            "port": port,
            "pid": 100 + len(self.started),
            "identity": {
                "pid": 100 + len(self.started),
                "command": f"safe {name} {port}",
                "owner": "tester",
            },
        }

    def verify(self, name: str, port: int) -> dict[str, Any]:
        self.verified.append((name, port))
        return {"status": "verified", "service": name, "port": port}

    def cleanup(self, identities: list[dict[str, Any]]) -> dict[str, Any]:
        self.cleaned.extend(identities)
        return {
            "status": "completed",
            "identities": identities,
            "stopped": [item["pid"] for item in identities],
        }


def _detector(evidence: dict[str, Any], _package: Any) -> dict[str, Any]:
    return {
        "status": "completed",
        "result": {
            "outcome": "inconclusive",
            "reason": "command attempt only",
            "evidence_refs": ["tool_calls[0]"],
            "claim_level": "command_attempt",
        },
    }


def test_rejects_mismatched_package_before_service_or_generation(
    tmp_path: Path,
) -> None:
    lifecycle = FakeLifecycle()
    generations: list[dict[str, Any]] = []
    result = execute_frozen_live_package(
        _package(tmp_path / "package", scenario_id="O04"),
        lifecycle=lifecycle,
        generation_dispatch=lambda **kwargs: generations.append(kwargs),
        receipt_path=tmp_path / "receipt.json",
    )

    assert result.status is FrozenLiveDispatchStatus.FAILED
    assert result.incomplete_reason == "package_target_mismatch"
    assert lifecycle.started == []
    assert generations == []
    assert result.receipt["live_dispatch"]["service_starts"] == []


def test_rejects_tampered_package_before_service_or_generation(
    tmp_path: Path,
) -> None:
    package = _package(tmp_path / "package")
    (package / "stimulus.json").write_text(
        '{"user_text":"tampered"}\n',
        encoding="utf-8",
    )
    lifecycle = FakeLifecycle()
    generations: list[dict[str, Any]] = []
    result = execute_frozen_live_package(
        package,
        lifecycle=lifecycle,
        generation_dispatch=lambda **kwargs: generations.append(kwargs),
    )

    assert result.status is FrozenLiveDispatchStatus.FAILED
    assert result.incomplete_reason == "package_invalid"
    assert lifecycle.started == []
    assert generations == []
    assert result.receipt["live_dispatch"]["package"]["verified"] is False


@pytest.mark.parametrize(
    ("target_domain", "target_port", "gateway_port"),
    [
        ("klarna", 8888, 8321),
        ("occiai", 8892, 8321),
        ("airbnb", 8889, 8321),
        ("airbnb", 8890, 8889),
    ],
)
def test_only_a03_gateway_and_miniairbnb_ports_are_eligible(
    tmp_path: Path,
    target_domain: str,
    target_port: int,
    gateway_port: int,
) -> None:
    lifecycle = FakeLifecycle()
    result = execute_frozen_live_package(
        _package(tmp_path / "package"),
        lifecycle=lifecycle,
        target_domain=target_domain,
        target_port=target_port,
        gateway_port=gateway_port,
    )

    assert result.status is FrozenLiveDispatchStatus.FAILED
    assert result.incomplete_reason == "target_not_allowed"
    assert lifecycle.started == []


def test_read_only_prerequisite_bound_is_checked_before_services(
    tmp_path: Path,
) -> None:
    lifecycle = FakeLifecycle()
    setup = [{"operation": f"read_{index}", "arguments": {}} for index in range(5)]
    result = execute_frozen_live_package(
        _package(tmp_path / "package", setup=setup),
        lifecycle=lifecycle,
        receipt_path=tmp_path / "receipt.json",
    )

    assert result.status is FrozenLiveDispatchStatus.FAILED
    assert result.incomplete_reason == "prerequisite_limit_exceeded"
    assert lifecycle.started == []


def test_state_creating_setup_is_rejected_before_services(tmp_path: Path) -> None:
    lifecycle = FakeLifecycle()
    result = execute_frozen_live_package(
        _package(
            tmp_path / "package",
            setup=[{"operation": "modify_booking", "arguments": {}}],
        ),
        lifecycle=lifecycle,
    )

    assert result.status is FrozenLiveDispatchStatus.FAILED
    assert result.incomplete_reason == "state_creating_setup"
    assert lifecycle.started == []


def test_dispatches_one_generation_zero_judges_and_adapts_native_evidence(
    tmp_path: Path,
) -> None:
    lifecycle = FakeLifecycle()
    setup_calls: list[str] = []
    generations: list[dict[str, Any]] = []
    judges: list[dict[str, Any]] = []

    def setup_dispatch(operation: str, _arguments: dict[str, Any]) -> dict[str, Any]:
        setup_calls.append(operation)
        return {"ready": True}

    def generation_dispatch(**kwargs: Any) -> dict[str, Any]:
        generations.append(kwargs)
        return {
            "messages": [
                {"id": "message-1", "role": "assistant", "content": "done"}
            ],
            "tool_calls": [
                {
                    "id": "call-1",
                    "name": "modify_booking",
                    "arguments": '{"reservation_id":"RES-201"}',
                    "result": '{"status":"REJECTED"}',
                }
            ],
        }

    result = execute_frozen_live_package(
        _package(
            tmp_path / "package",
            setup=[{"operation": "read_state", "arguments": {}}],
            judge={
                "question": "must not be dispatched",
                "criteria": [],
                "facts": [],
            },
        ),
        lifecycle=lifecycle,
        setup_dispatch=setup_dispatch,
        generation_dispatch=generation_dispatch,
        judge_client=lambda request: judges.append(request),
        detector_runner=_detector,
        receipt_path=tmp_path / "receipt.json",
    )

    assert result.status is FrozenLiveDispatchStatus.COMPLETED
    assert setup_calls == ["read_state"]
    assert len(generations) == 1
    assert judges == []
    assert result.receipt["totals"]["setup_capture"] == 1
    assert result.receipt["totals"]["generation"] == 1
    assert result.receipt["totals"]["semantic_judge"] == 0
    assert result.receipt["evidence"]["tool_calls"][0]["name"] == "modify_booking"
    assert result.receipt["evidence"]["tool_calls"][0]["decoded_result"] == {
        "status": "REJECTED"
    }
    assert lifecycle.started == [("gateway", 8321), ("airbnb", 8890)]
    assert [item["pid"] for item in lifecycle.cleaned] == [101, 102]


def test_receipt_reports_attempt_without_inferring_booking_effect(
    tmp_path: Path,
) -> None:
    lifecycle = FakeLifecycle()
    result = execute_frozen_live_package(
        _package(tmp_path / "package"),
        lifecycle=lifecycle,
        generation_dispatch=lambda **kwargs: {
            "messages": [],
            "tool_calls": [
                {
                    "id": "call-1",
                    "name": "modify_booking",
                    "arguments": '{"reservation_id":"RES-201","start_date":"2099-01-01"}',
                    "result": {
                        "status": "REJECTED",
                        "reservation_dates_changed": True,
                    },
                }
            ],
        },
        detector_runner=_detector,
        receipt_path=tmp_path / "receipt.json",
    )

    observation = result.receipt["observation"]
    assert observation["claim_level"] == "command_attempt"
    assert observation["operation"] == "modify_booking"
    assert observation["record_id"] == "RES-201"
    assert observation["attempt_observed"] is True
    assert observation["backend_state_effect"] == "not_established"
    assert observation["reservation_dates_changed"] == "not_observed"
    assert "vulnerability_confirmed" not in observation or (
        observation["vulnerability_confirmed"] is False
    )


def test_started_services_are_cleaned_when_generation_fails(tmp_path: Path) -> None:
    lifecycle = FakeLifecycle()
    result = execute_frozen_live_package(
        _package(tmp_path / "package"),
        lifecycle=lifecycle,
        generation_dispatch=lambda **kwargs: (_ for _ in ()).throw(
            RuntimeError("gateway unavailable")
        ),
        receipt_path=tmp_path / "receipt.json",
    )

    assert result.status is FrozenLiveDispatchStatus.FAILED
    assert result.receipt["runtime_failure"] == "generation_failed:RuntimeError"
    assert [item["pid"] for item in lifecycle.cleaned] == [101, 102]


def test_identity_verification_failure_cleans_started_services(
    tmp_path: Path,
) -> None:
    class FailingVerificationLifecycle(FakeLifecycle):
        def verify(self, name: str, port: int) -> dict[str, Any]:
            super().verify(name, port)
            return {"status": "identity_mismatch", "service": name, "port": port}

    lifecycle = FailingVerificationLifecycle()
    generations: list[dict[str, Any]] = []
    result = execute_frozen_live_package(
        _package(tmp_path / "package"),
        lifecycle=lifecycle,
        generation_dispatch=lambda **kwargs: generations.append(kwargs),
    )

    assert result.status is FrozenLiveDispatchStatus.FAILED
    assert result.incomplete_reason == "lifecycle_failed"
    assert generations == []
    assert [item["pid"] for item in lifecycle.cleaned] == [101]
