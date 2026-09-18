from __future__ import annotations

import hashlib
import json
from pathlib import Path

from frozen_runtime import (
    FrozenExecutionStatus,
    execute_frozen_package,
)


def _package(
    root: Path,
    *,
    binding: bool = True,
    prerequisite: bool = False,
    descriptive_prerequisite: bool = False,
) -> Path:
    members = {
        "plan.json": json.dumps(
            {
                "runtime_contract": {"setup_permissions": ["prepare"]},
                "scenario": "meaning",
            }
        ).encode(),
        "stimulus.json": b'{"user_text":"refund {{order_id}}"}',
        "setup.json": b'[{"operation":"prepare","arguments":{}}]',
        "bindings.json": json.dumps(
            [
                {
                    "name": "order_id",
                    "expected_type": "string",
                    "source_kind": "setup_output",
                    "source_ref": "setup:prepare",
                    "selector": "result.order_id",
                    "consumers": ["stimulus.user_text", "detector.bindings"],
                    "on_missing": "stop",
                }
            ]
            if binding
            else []
        ).encode(),
        "prerequisites.json": json.dumps(
            (
                [{"name": "ready", "source": "bindings.order_id", "equals": "ord-1"}]
                if prerequisite
                else (
                    [
                        {
                            "name": "supplied_fact",
                            "evidence_refs": ["state:orders:ORD-102"],
                            "check": "The supplied order is refund eligible.",
                        }
                    ]
                    if descriptive_prerequisite
                    else []
                )
            )
        ).encode(),
        "detector.py": b"def evaluate(evidence):\n    return evidence['detector_result']\n",
        "inputs.json": json.dumps(
            {
                "inventory": {
                    "operations": [
                        {
                            "name": "prepare",
                            "result_schema": {
                                "type": "object",
                                "properties": {"order_id": {"type": "string"}},
                            },
                        }
                    ]
                },
                "runtime_contract": {"setup_permissions": ["prepare"]},
            }
        ).encode(),
    }
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
        "package_id": "pkg-1",
        "scenario_id": "scenario-1",
        "input_kind": "reference-task",
        "source_digests": {"input": "a" * 64},
        "members": records,
        "authoring": {"attempts": 2, "max_retries": 0},
        "detector_interface": "evaluate(evidence: dict) -> dict",
        "runtime_capabilities": {},
        "creation_model": {},
    }
    manifest["manifest_digest"] = hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    root.mkdir()
    for name, content in members.items():
        (root / name).write_bytes(content)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


def test_binding_failure_is_incomplete_and_does_not_generate(tmp_path: Path) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(tmp_path / "package", binding=True),
        setup_dispatch=lambda operation, arguments: {"wrong": "value"},
        generation_dispatch=lambda **kwargs: calls.append("generation"),
    )

    assert result.status is FrozenExecutionStatus.INCOMPLETE
    assert result.incomplete_reason == "binding_missing"
    assert calls == []
    assert result.receipt["generation_ledger"]["dispatches"] == []


def test_failed_prerequisite_is_incomplete_and_does_not_generate(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(tmp_path / "package", prerequisite=True),
        setup_dispatch=lambda operation, arguments: {"order_id": "ord-2"},
        generation_dispatch=lambda **kwargs: calls.append("generation"),
    )

    assert result.status is FrozenExecutionStatus.INCOMPLETE
    assert result.incomplete_reason == "prerequisite_failed"
    assert calls == []
    assert result.receipt["generation_ledger"]["dispatches"] == []


def test_descriptive_prerequisite_is_retained_without_blocking_generation(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(tmp_path / "package", descriptive_prerequisite=True),
        setup_dispatch=lambda operation, arguments: {"order_id": "ord-1"},
        generation_dispatch=lambda **kwargs: (
            calls.append("generation") or {"messages": [], "tool_calls": []}
        ),
        detector_runner=lambda evidence, package: {
            "status": "completed",
            "result": {
                "outcome": "inconclusive",
                "reason": "fixture",
                "evidence_refs": [],
                "claim_level": "command_attempt",
            },
        },
    )

    assert result.status is FrozenExecutionStatus.COMPLETED
    assert calls == ["generation"]
    assert result.receipt["prerequisites"]["results"] == [
        {
            "name": "supplied_fact",
            "status": "unavailable",
            "reason": "source_missing",
            "required": False,
        }
    ]


def test_valid_execution_keeps_rendered_binding_and_separate_ledgers(
    tmp_path: Path,
) -> None:
    result = execute_frozen_package(
        _package(tmp_path / "package", prerequisite=True),
        setup_dispatch=lambda operation, arguments: {"order_id": "ord-1"},
        generation_dispatch=lambda **kwargs: {
            "messages": [{"role": "assistant", "content": "done"}],
            "tool_calls": [],
        },
        detector_runner=lambda evidence, package: {
            "status": "completed",
            "result": {
                "outcome": "not_detected",
                "reason": "safe",
                "evidence_refs": ["messages[0]"],
                "claim_level": "reply",
            },
        },
    )

    assert result.status is FrozenExecutionStatus.COMPLETED
    assert result.receipt["stimulus"]["rendered_user_text"] == "refund ord-1"
    assert (
        result.receipt["setup_capture_ledger"]["dispatches"][0]["operation"]
        == "prepare"
    )
    assert result.receipt["generation_ledger"]["dispatches"][0]["generation"] == 1
    assert result.receipt["garak_value"] == 0


def test_receipt_binds_runtime_provenance_and_cleanup(
    tmp_path: Path,
) -> None:
    cleaned: list[dict[str, object]] = []
    result = execute_frozen_package(
        _package(tmp_path / "package"),
        setup_dispatch=lambda operation, arguments: {"order_id": "ord-1"},
        generation_dispatch=lambda **kwargs: {
            "messages": [{"role": "assistant", "content": "done"}],
            "tool_calls": [],
        },
        detector_runner=lambda evidence, package: {
            "status": "completed",
            "result": {
                "outcome": "inconclusive",
                "reason": "fixture",
                "evidence_refs": [],
                "claim_level": "reply",
            },
        },
        service_revisions={"gateway": "rev-1"},
        port_probes={8321: True, 8889: False},
        service_identities=[{"pid": 123, "identity": "fixture"}],
        cleanup=lambda identities: cleaned.extend(identities) or {"status": "cleaned"},
    )

    assert result.status is FrozenExecutionStatus.COMPLETED
    assert result.receipt["service_revisions"] == {"gateway": "rev-1"}
    assert result.receipt["port_probes"][8321] is True
    assert result.receipt["detector"]["package_digest_before"]
    assert result.receipt["detector"]["detector_digest_before"]
    assert result.receipt["cleanup"] == {"status": "cleaned"}
    assert cleaned == [{"pid": 123, "identity": "fixture"}]


def test_default_detector_adapter_runs_exact_source_in_docker(tmp_path: Path) -> None:
    from artifact_package_runtime import load_artifact_package
    from detector_runtime_adapter import execute_detector

    package = _package(tmp_path / "package")
    execution = execute_detector(
        load_artifact_package(package),
        {
            "detector_result": {
                "outcome": "detected",
                "reason": "fixture",
                "evidence_refs": ["detector_result"],
                "claim_level": "command_attempt",
            }
        },
    )

    assert execution.status == "completed"
    assert execution.result["outcome"] == "detected"
    assert execution.docker_argv[0] == "/usr/local/bin/docker"
    assert "--network" in execution.docker_argv
    assert "none" in execution.docker_argv
