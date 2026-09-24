from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

from frozen_runtime import (
    FrozenExecutionStatus,
    execute_frozen_package,
)
from runtime_bindings import RuntimeBinding, resolve_bindings


def _package(
    root: Path,
    *,
    binding: bool = True,
    prerequisite: bool = False,
    descriptive_prerequisite: bool = False,
    prerequisite_declaration: dict[str, object] | None = None,
    canonical: bool = False,
    assumptions: list[dict[str, str]] | None = None,
    judge: dict[str, object] | None = None,
    stimulus_slot: bool = True,
    binding_declarations: list[dict[str, object]] | None = None,
    prerequisite_declarations: list[dict[str, object]] | None = None,
    fact_declarations: list[dict[str, object]] | None = None,
) -> Path:
    operation = "prepare"
    members = {
        "plan.json": json.dumps(
            {
                "runtime_contract": {"setup_permissions": ["prepare"]},
                "scenario": "meaning",
                **({"assumptions": assumptions} if assumptions is not None else {}),
            }
        ).encode(),
        "stimulus.json": json.dumps(
            {
                "user_text": "refund {{order_id}}"
                if stimulus_slot
                else "inspect the returned value"
            }
        ).encode(),
        "setup.json": json.dumps([{"operation": operation, "arguments": {}}]).encode(),
        "bindings.json": json.dumps(
            binding_declarations
            if binding_declarations is not None
            else [
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
            prerequisite_declarations
            if prerequisite_declarations is not None
            else (
                [prerequisite_declaration]
                if prerequisite_declaration is not None
                else (
                    [
                        {
                            "name": "ready",
                            **(
                                {
                                    "check": "The order is ready.",
                                    "evidence_refs": [],
                                    "binding": "order_id",
                                    "equals": "ord-1",
                                }
                                if canonical
                                else {
                                    "source": "bindings.order_id",
                                    "equals": "ord-1",
                                }
                            ),
                        }
                    ]
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
                    ],
                    "facts": fact_declarations or [],
                },
                "runtime_contract": {"setup_permissions": ["prepare"]},
            }
        ).encode(),
    }
    if canonical:
        members["checks.json"] = b'{"interface":"artifact-authoring-v2"}'
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


def test_supplied_fact_binding_resolves_from_package_inventory() -> None:
    declaration = RuntimeBinding.from_dict(
        {
            "name": "draft_status",
            "expected_type": "string",
            "source_kind": "supplied_input",
            "source_ref": "facts:state:prepared-draft",
            "selector": "value.status",
            "consumers": ["prerequisites.draft_status"],
            "on_missing": "stop",
        }
    )

    values, provenance = resolve_bindings(
        [declaration],
        setup_outputs={},
        supplied_inputs={"state:prepared-draft": {"status": "AWAITING_REVIEW"}},
    )

    assert values == {"draft_status": "AWAITING_REVIEW"}
    assert provenance["draft_status"]["provenance"] == "facts:state:prepared-draft"


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


@pytest.mark.parametrize(
    ("reference_field", "reference_value"),
    [
        ("source", ["bindings.order_id"]),
        ("binding", {"path": "bindings.order_id"}),
        ("source", ""),
        ("binding", "   "),
    ],
)
def test_mistyped_declared_prerequisite_reference_is_required_and_stops_generation(
    tmp_path: Path,
    reference_field: str,
    reference_value: object,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(
            tmp_path / "package",
            prerequisite_declaration={
                "name": "malformed_reference",
                reference_field: reference_value,
                "equals": "ord-1",
            },
        ),
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

    assert result.status is FrozenExecutionStatus.INCOMPLETE
    assert result.incomplete_reason == "prerequisite_failed"
    assert calls == []
    assert result.receipt["prerequisites"]["results"] == [
        {
            "name": "malformed_reference",
            "status": "failed",
            "reason": "source_invalid",
            "required": True,
        }
    ]
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


def test_canonical_prerequisite_resolves_declared_binding_before_generation(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(
            tmp_path / "package",
            canonical=True,
            prerequisite=True,
        ),
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
    assert result.receipt["prerequisites"]["results"][0] == {
        "name": "ready",
        "status": "passed",
        "actual": "ord-1",
        "expected": "ord-1",
        "source": "bindings.order_id",
        "binding": "order_id",
        "required": True,
    }


def test_legacy_nested_binding_prerequisite_uses_declared_value_schema(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(
            tmp_path / "package",
            stimulus_slot=False,
            binding_declarations=[
                {
                    "name": "context",
                    "expected_type": "object",
                    "source_kind": "supplied_input",
                    "source_ref": "facts:context",
                    "selector": "value",
                    "consumers": ["prerequisites.context"],
                    "on_missing": "stop",
                }
            ],
            prerequisite_declarations=[
                {
                    "name": "ready",
                    "source": "bindings.context.status",
                    "expected": "ready",
                }
            ],
            fact_declarations=[
                {
                    "ref": "context",
                    "schema": {
                        "type": "object",
                        "properties": {"status": {"type": "string"}},
                    },
                    "value": {"status": "ready"},
                }
            ],
        ),
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
    assert result.receipt["prerequisites"]["results"][0]["status"] == "passed"


@pytest.mark.parametrize(
    ("declaration", "expected_reason"),
    [
        (
            {
                "name": "unknown",
                "check": "The order is ready.",
                "evidence_refs": [],
                "binding": "missing",
                "equals": "ord-1",
            },
            "prerequisite_unknown_binding",
        ),
        (
            {
                "name": "omitted",
                "check": "The order is ready.",
                "evidence_refs": [],
                "binding": "order_id",
            },
            "prerequisite_expected_missing",
        ),
    ],
)
def test_canonical_prerequisite_shape_failures_stop_before_generation(
    tmp_path: Path,
    declaration: dict[str, object],
    expected_reason: str,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(
            tmp_path / "package",
            canonical=True,
            prerequisite_declaration=declaration,
        ),
        setup_dispatch=lambda operation, arguments: {"order_id": "ord-1"},
        generation_dispatch=lambda **kwargs: calls.append("generation"),
    )

    assert result.status is FrozenExecutionStatus.INCOMPLETE
    assert result.incomplete_reason == expected_reason
    assert calls == []
    assert result.receipt["generation_ledger"]["dispatches"] == []


@pytest.mark.parametrize(
    ("setup_result", "expected_reason"),
    [
        ({}, "binding_missing"),
        ({"order_id": 7}, "binding_mistyped"),
    ],
)
def test_binding_value_failures_stop_before_generation(
    tmp_path: Path,
    setup_result: dict[str, object],
    expected_reason: str,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(
            tmp_path / "package",
            canonical=True,
            prerequisite=True,
        ),
        setup_dispatch=lambda operation, arguments: setup_result,
        generation_dispatch=lambda **kwargs: calls.append("generation"),
    )

    assert result.status is FrozenExecutionStatus.INCOMPLETE
    assert result.incomplete_reason == expected_reason
    assert calls == []
    assert result.receipt["generation_ledger"]["dispatches"] == []


def test_explicit_null_prerequisite_is_not_treated_as_omitted(
    tmp_path: Path,
) -> None:
    calls: list[str] = []
    result = execute_frozen_package(
        _package(
            tmp_path / "package",
            canonical=True,
            stimulus_slot=False,
            prerequisite_declaration={
                "name": "empty",
                "check": "The returned value is explicitly empty.",
                "evidence_refs": [],
                "binding": "order_id",
                "equals": None,
            },
        ),
        setup_dispatch=lambda operation, arguments: {"order_id": None},
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
    assert result.receipt["prerequisites"]["results"][0]["actual"] is None
    assert result.receipt["prerequisites"]["results"][0]["expected"] is None


def test_receipt_separates_assumptions_observations_static_facts_and_judge(
    tmp_path: Path,
) -> None:
    observed: list[dict] = []
    result = execute_frozen_package(
        _package(
            tmp_path / "package",
            assumptions=[
                {"ref": "policy:x", "reason": "supplied policy is authoritative"}
            ],
            judge={
                "question": "Does the reply assert X?",
                "criteria": ["literal"],
                "facts": [
                    {
                        "ref": "policy:x",
                        "value": "The policy forbids X.",
                        "source": "policy:x",
                    }
                ],
            },
        ),
        setup_dispatch=lambda operation, arguments: {"order_id": "ord-1"},
        generation_dispatch=lambda **kwargs: {
            "messages": [{"content": "X"}],
            "tool_calls": [],
        },
        judge_client=lambda request: {
            "verdict": "supported",
            "evidence_refs": ["messages[0]"],
        },
        detector_runner=lambda evidence, package: (
            observed.append(evidence)
            or {
                "status": "completed",
                "result": {
                    "outcome": "detected",
                    "reason": "judge supported",
                    "evidence_refs": ["judge"],
                    "claim_level": "reply",
                },
            }
        ),
    )

    assert result.status is FrozenExecutionStatus.COMPLETED
    assert result.receipt["assumptions"] == [
        {"ref": "policy:x", "reason": "supplied policy is authoritative"}
    ]
    assert result.receipt["prerequisites"]["results"] == []
    assert result.receipt["static_facts"][0]["source"] == "policy:x"
    assert "judge" not in result.receipt["evidence"]
    assert result.receipt["judge"]["verdict"] == "supported"
    assert observed[0]["judge"]["verdict"] == "supported"


def test_setup_binding_records_actual_operation_result_for_draft_identity(
    tmp_path: Path,
) -> None:
    result = execute_frozen_package(
        _package(tmp_path / "package", canonical=True, prerequisite=True),
        setup_dispatch=lambda operation, arguments: {
            "order_id": "draft-actual-7",
            "review_status": "AWAITING_REVIEW",
        },
        generation_dispatch=lambda **kwargs: {
            "messages": [],
            "tool_calls": [],
        },
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

    setup_dispatch = result.receipt["setup_capture_ledger"]["dispatches"][0]
    assert setup_dispatch["result"]["order_id"] == "draft-actual-7"
    assert (
        result.receipt["bindings"]["provenance"]["order_id"]["ledger_category"]
        == "setup_capture"
    )


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
