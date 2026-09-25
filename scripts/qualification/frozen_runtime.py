"""Generic authoring-free execution of an immutable artifact package."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Callable

from artifact_package_runtime import (
    ArtifactPackage,
    ArtifactPackageError,
    load_artifact_package,
)
from evidence_adapter import adapt_generation_evidence
from frozen_judge import evaluate_frozen_judge
from request_ledger import RequestLedger, mapped_garak_value
from runtime_bindings import (
    BindingError,
    RuntimeBinding,
    resolve_bindings,
    select_value,
    substitute_slots,
    validate_binding_declarations,
    validate_slot_references,
)


class FrozenExecutionStatus(StrEnum):
    COMPLETED = "completed"
    INCOMPLETE = "incomplete"
    FAILED = "failed"


@dataclass(frozen=True)
class FrozenExecution:
    status: FrozenExecutionStatus
    receipt: dict[str, Any]
    incomplete_reason: str | None = None


def execute_frozen_package(
    package: str | Path | ArtifactPackage,
    *,
    setup_dispatch: Callable[[str, dict[str, Any]], dict[str, Any]] | None = None,
    generation_dispatch: Callable[..., dict[str, Any]] | None = None,
    detector_runner: Callable[[dict[str, Any], ArtifactPackage], Any] | None = None,
    judge_client: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    discovery_records: list[dict[str, Any]] | None = None,
    receipt_path: str | Path | None = None,
    service_identities: list[dict[str, Any]] | None = None,
    cleanup: Callable[[list[dict[str, Any]]], dict[str, Any]] | None = None,
    service_revisions: dict[str, Any] | None = None,
    port_probes: dict[int, bool] | None = None,
) -> FrozenExecution:
    """Run setup, bindings, prerequisites, one generation, evidence and detector.

    Every dispatch ledger is updated before its injected transport is called.
    A setup, binding or prerequisite failure returns an incomplete receipt and
    never invokes ``generation_dispatch``.
    """

    try:
        loaded = (
            package
            if isinstance(package, ArtifactPackage)
            else load_artifact_package(package)
        )
    except (ArtifactPackageError, OSError, ValueError) as exc:
        receipt = _base_receipt(None, discovery_records)
        receipt["status"] = FrozenExecutionStatus.FAILED.value
        receipt["incomplete_reason"] = "package_invalid"
        receipt["runtime_failure"] = str(exc)
        _write_receipt(receipt_path, receipt)
        return FrozenExecution(FrozenExecutionStatus.FAILED, receipt, "package_invalid")

    plan = loaded.json_member("plan.json", default={})
    stimulus = loaded.json_member("stimulus.json", default={})
    setup = loaded.json_member("setup.json", default=[])
    declarations_raw = loaded.json_member("bindings.json", default=[])
    prerequisites = loaded.json_member("prerequisites.json", default=[])
    checks = loaded.json_member("checks.json", default={})
    new_wire = (
        isinstance(checks, dict) and checks.get("interface") == "artifact-authoring-v2"
    )
    canonical_prerequisites = new_wire or _has_canonical_prerequisites(prerequisites)
    inputs = loaded.json_member("inputs.json", default={})
    runtime_contract = _runtime_contract(
        plan, inputs, loaded.manifest.runtime_capabilities
    )
    inventory = inputs.get("inventory", {}) if isinstance(inputs, dict) else {}
    setup_ledger = RequestLedger("setup_capture")
    generation_ledger = RequestLedger("generation")
    command_ledger = RequestLedger("server_command")
    judge_ledger = RequestLedger("semantic_judge")
    receipt = _base_receipt(loaded, discovery_records)
    receipt["service_revisions"] = dict(service_revisions or {})
    receipt["port_probes"] = dict(port_probes or {})
    receipt["authored_meaning"] = plan
    receipt["assumptions"] = (
        plan.get("assumptions", []) if isinstance(plan, dict) else []
    )
    receipt["static_facts"] = []
    receipt["judge"] = None
    receipt["fact_classes"] = {
        "static_facts": "supplied_static_fact",
        "bindings.resolved": "runtime_binding",
        "evidence": "runtime_observation",
        "judge": "judge_conclusion",
        "assumptions": "static_assumption",
    }
    receipt["stimulus"] = {"authored": stimulus}
    receipt["setup_outputs"] = {}
    receipt["bindings"] = {"declared": declarations_raw}
    receipt["prerequisites"] = {"declared": prerequisites}
    receipt["ledgers"] = {
        "setup_capture": setup_ledger.as_dict(),
        "generation": generation_ledger.as_dict(),
        "server_command": command_ledger.as_dict(),
        "semantic_judge": judge_ledger.as_dict(),
    }

    try:
        _validate_setup(setup, inventory, runtime_contract)
        setup_outputs = _run_setup(setup, setup_dispatch, setup_ledger)
        receipt["setup_outputs"] = setup_outputs
        declarations = validate_binding_declarations(
            declarations_raw, inventory=inventory, runtime_contract=runtime_contract
        )
        values, provenance = resolve_bindings(
            declarations,
            setup_outputs=setup_outputs,
            supplied_inputs=_supplied_fact_values(inputs),
            allow_null_bindings=_null_prerequisite_bindings(
                prerequisites if canonical_prerequisites else []
            ),
        )
        _annotate_binding_provenance(provenance, declarations, setup_ledger)
        receipt["bindings"] = {
            "declared": declarations_raw,
            "resolved": values,
            "provenance": provenance,
        }
        prerequisite_result = check_prerequisites(
            prerequisites,
            values=values,
            setup_outputs=setup_outputs,
            strict=canonical_prerequisites,
        )
        receipt["prerequisites"] = {
            "declared": prerequisites,
            "results": prerequisite_result,
        }
        failed = next(
            (
                item
                for item in prerequisite_result
                if item["status"] != "passed" and item.get("required", True)
            ),
            None,
        )
        if failed is not None:
            return _finish_incomplete(
                receipt,
                (
                    failed.get("reason")
                    if str(failed.get("reason", "")).startswith("prerequisite_")
                    else (
                        "prerequisite_failed"
                        if failed["status"] == "failed"
                        else "prerequisite_unavailable"
                    )
                ),
                loaded,
                setup_ledger,
                generation_ledger,
                command_ledger,
                judge_ledger,
                receipt_path,
            )
        rendered = _render_stimulus(stimulus, values, declarations)
    except BindingError as exc:
        reason = _binding_reason(str(exc))
        return _finish_incomplete(
            receipt,
            reason,
            loaded,
            setup_ledger,
            generation_ledger,
            command_ledger,
            judge_ledger,
            receipt_path,
        )
    except SetupError as exc:
        return _finish_incomplete(
            receipt,
            "setup_failed",
            loaded,
            setup_ledger,
            generation_ledger,
            command_ledger,
            judge_ledger,
            receipt_path,
            error=str(exc),
        )

    receipt["stimulus"]["rendered_user_text"] = rendered["user_text"]
    receipt["stimulus"]["rendered_history"] = rendered.get("history", [])
    if generation_dispatch is None:
        return _finish_incomplete(
            receipt,
            "generation_unavailable",
            loaded,
            setup_ledger,
            generation_ledger,
            command_ledger,
            judge_ledger,
            receipt_path,
        )
    generation_record = generation_ledger.before_dispatch(
        generation=1,
        stimulus_digest=_digest(rendered),
        retries=0,
    )
    try:
        raw_generation = generation_dispatch(
            stimulus=rendered,
            bindings=values,
            prerequisites=receipt["prerequisites"],
            ledger_record=generation_record,
        )
    except Exception as exc:  # pragma: no cover - injected transport boundary
        generation_ledger.complete(generation_record, status="failed", error=str(exc))
        receipt["runtime_failure"] = f"generation_failed:{type(exc).__name__}"
        return _finish_failed(
            receipt,
            loaded,
            setup_ledger,
            generation_ledger,
            command_ledger,
            judge_ledger,
            receipt_path,
        )
    generation_ledger.complete(generation_record, status="completed")
    packet = evidence_packet_from_generation(
        raw_generation,
        bindings=values,
        binding_provenance=receipt["bindings"].get("provenance"),
        setup_outputs=setup_outputs,
    )
    for call in packet["tool_calls"]:
        command = command_ledger.before_dispatch(
            generation=1,
            native_id=call.get("native_id"),
            call_id=call.get("call_id"),
            name=call.get("name"),
            status=call.get("status"),
        )
        command_ledger.complete(command, observed=True)
    receipt["evidence"] = packet

    judge_spec = loaded.json_member("judge.json")
    if isinstance(judge_spec, dict):
        receipt["static_facts"] = list(judge_spec.get("facts", []))
    judge_record = None
    if judge_spec is not None and judge_client is not None:
        judge_record = judge_ledger.before_dispatch(
            evaluation=1,
            frozen_spec_digest=_digest(judge_spec),
            reused=False,
            retries=0,
        )
    judged = evaluate_frozen_judge(judge_spec, packet, client=judge_client)
    if judge_record is not None:
        judge_ledger.complete(
            judge_record,
            status="completed" if judged.dispatched else "unresolved",
            dispatched=judged.dispatched,
            reused=judged.reused,
            request=judged.request,
            output=judged.output,
            verdict=judged.verdict,
            evidence_refs=list(judged.evidence_refs),
            reason=judged.reason,
        )
    judge_value = judged.as_dict()
    detector_packet = dict(packet)
    detector_packet["judge"] = judge_value
    receipt["judge"] = judge_value

    try:
        detector = (
            detector_runner(detector_packet, loaded)
            if detector_runner is not None
            else _execute_detector(detector_packet, loaded)
        )
    except Exception as exc:  # pragma: no cover - runtime boundary
        detector = {"status": "failed", "failure": f"{type(exc).__name__}: {exc}"}
    detector_status, rich_result, runtime_failure = _detector_result(detector)
    detector_metadata = detector if isinstance(detector, dict) else {}
    receipt["evidence"] = packet
    receipt["detector"] = {
        "status": detector_status,
        "runtime_failure": runtime_failure,
        "result": rich_result,
        "source_digest": loaded.detector_digest,
        "package_digest_before": loaded.digest,
        "package_digest_after": detector_metadata.get("package_digest_after"),
        "detector_digest_before": loaded.detector_digest,
        "detector_digest_after": detector_metadata.get("detector_sha256_after"),
        "docker_argv": detector_metadata.get("docker_argv", []),
    }
    receipt["runtime_status"] = detector_status
    receipt["rich_result"] = rich_result
    receipt["garak_value"] = mapped_garak_value(
        rich_result, runtime_status=detector_status
    )
    receipt["status"] = (
        FrozenExecutionStatus.COMPLETED.value
        if detector_status == "completed"
        else FrozenExecutionStatus.FAILED.value
    )
    _finish_receipt(
        receipt,
        loaded,
        setup_ledger,
        generation_ledger,
        command_ledger,
        judge_ledger,
        service_identities,
        cleanup,
        receipt_path,
    )
    return FrozenExecution(FrozenExecutionStatus(receipt["status"]), receipt)


def evidence_packet_from_generation(
    raw_generation: Any,
    *,
    bindings: dict[str, Any],
    binding_provenance: dict[str, Any] | None,
    setup_outputs: dict[str, Any],
) -> dict[str, Any]:
    """Build the detector evidence packet from one raw generation record."""

    return adapt_generation_evidence(
        raw_generation,
        bindings=bindings,
        binding_provenance=binding_provenance,
        setup_outputs=setup_outputs,
        snapshots=raw_generation.get("snapshots")
        if isinstance(raw_generation, dict)
        else None,
    )


def check_prerequisites(
    declarations: Any,
    *,
    values: dict[str, Any],
    setup_outputs: dict[str, Any],
    strict: bool | None = None,
) -> list[dict[str, Any]]:
    """Evaluate exact declared equality checks without interpreting prose."""

    if declarations is None:
        return []
    if not isinstance(declarations, list):
        raise BindingError("prerequisites must be a list")
    if strict is None:
        strict = any(
            isinstance(item, dict)
            and "binding" in item
            and "check" in item
            and "evidence_refs" in item
            and not ({"source", "expected"} & set(item))
            for item in declarations
        )
    context = {"bindings": values, "setup": setup_outputs}
    results = []
    for index, declaration in enumerate(declarations):
        if not isinstance(declaration, dict):
            raise BindingError(f"prerequisite[{index}] must be an object")
        if strict:
            results.append(
                _check_canonical_prerequisite(
                    index, declaration, values=values, setup_outputs=setup_outputs
                )
            )
            continue
        name = declaration.get("name", f"prerequisite-{index + 1}")
        expected = declaration.get("equals", declaration.get("expected"))
        reference_fields = [
            field for field in ("source", "binding") if field in declaration
        ]
        if not reference_fields:
            results.append(
                {
                    "name": name,
                    "status": "unavailable",
                    "reason": "source_missing",
                    "required": False,
                }
            )
            continue
        if any(
            not isinstance(declaration[field], str) or not declaration[field].strip()
            for field in reference_fields
        ):
            results.append(
                {
                    "name": name,
                    "status": "failed",
                    "reason": "source_invalid",
                    "required": True,
                }
            )
            continue
        source = declaration[reference_fields[0]]
        try:
            actual = select_value(context, source)
        except BindingError:
            results.append(
                {
                    "name": name,
                    "status": "unavailable",
                    "reason": "source_unavailable",
                    "required": True,
                }
            )
            continue
        results.append(
            {
                "name": name,
                "status": "passed" if actual == expected else "failed",
                "actual": actual,
                "expected": expected,
                "source": source,
                "required": True,
            }
        )
    return results


_MISSING = object()


def _check_canonical_prerequisite(
    index: int,
    declaration: dict[str, Any],
    *,
    values: dict[str, Any],
    setup_outputs: dict[str, Any],
) -> dict[str, Any]:
    del index
    name = declaration.get("name", "prerequisite")
    allowed = {"name", "check", "evidence_refs", "binding", "equals"}
    if set(declaration) - allowed:
        return {
            "name": name,
            "status": "failed",
            "reason": "prerequisite_noncanonical",
            "required": True,
        }
    if "equals" not in declaration:
        return {
            "name": name,
            "status": "failed",
            "reason": "prerequisite_expected_missing",
            "binding": declaration.get("binding"),
            "required": True,
        }
    if allowed - set(declaration):
        return {
            "name": name,
            "status": "failed",
            "reason": "prerequisite_noncanonical",
            "required": True,
        }
    binding = declaration["binding"]
    if not isinstance(binding, str) or not binding.strip():
        return {
            "name": name,
            "status": "failed",
            "reason": "prerequisite_binding_invalid",
            "required": True,
        }
    if binding not in values:
        return {
            "name": name,
            "status": "failed",
            "reason": "prerequisite_unknown_binding",
            "binding": binding,
            "required": True,
        }
    expected = declaration["equals"]
    actual = values[binding]
    result = {
        "name": name,
        "status": "passed" if actual == expected else "failed",
        "actual": actual,
        "expected": expected,
        "source": f"bindings.{binding}",
        "binding": binding,
        "required": True,
    }
    if actual != expected:
        result["reason"] = "prerequisite_value_mismatch"
    return result


def _null_prerequisite_bindings(declarations: Any) -> frozenset[str]:
    if not isinstance(declarations, list):
        return frozenset()
    return frozenset(
        item["binding"]
        for item in declarations
        if isinstance(item, dict)
        and item.get("equals", _MISSING) is None
        and isinstance(item.get("binding"), str)
    )


def _annotate_binding_provenance(
    provenance: dict[str, Any],
    declarations: tuple[RuntimeBinding, ...],
    ledger: RequestLedger,
) -> None:
    """Join setup bindings to the exact setup ledger dispatch."""

    dispatches = ledger.dispatches
    for binding in declarations:
        if binding.source_kind != "setup_output":
            provenance[binding.name]["ledger_category"] = "supplied_input"
            continue
        operation = binding.source_ref.partition(":")[2]
        record = next(
            (item for item in dispatches if item.get("operation") == operation),
            None,
        )
        if record is not None:
            provenance[binding.name]["ledger_category"] = record["category"]
            provenance[binding.name]["ledger_sequence"] = record["sequence"]


class SetupError(ValueError):
    """Raised when a package setup declaration cannot be dispatched safely."""


def _validate_setup(
    setup: Any,
    inventory: dict[str, Any],
    runtime_contract: dict[str, Any],
) -> None:
    if not isinstance(setup, list):
        raise SetupError("setup must be a list")
    allowed = runtime_contract.get("setup_permissions", [])
    operations = {
        item.get("name"): item
        for item in inventory.get("operations", [])
        if isinstance(item, dict)
    }
    for index, step in enumerate(setup):
        if not isinstance(step, dict) or not isinstance(step.get("operation"), str):
            raise SetupError(f"setup[{index}] must name an operation")
        operation = step["operation"]
        if operation not in operations:
            raise SetupError(f"setup operation undocumented: {operation}")
        if operation not in allowed:
            raise SetupError(f"setup operation not permitted: {operation}")
        if not isinstance(step.get("arguments", {}), dict):
            raise SetupError(f"setup[{index}].arguments must be an object")


def _run_setup(
    setup: list[dict[str, Any]],
    dispatch: Callable[[str, dict[str, Any]], dict[str, Any]] | None,
    ledger: RequestLedger,
) -> dict[str, Any]:
    outputs: dict[str, Any] = {}
    for step in setup:
        operation = step["operation"]
        arguments = step.get("arguments", {})
        record = ledger.before_dispatch(
            operation=operation, arguments=arguments, retries=0
        )
        if dispatch is None:
            ledger.complete(record, status="failed", error="setup dispatch unavailable")
            raise SetupError("setup dispatch unavailable")
        try:
            output = dispatch(operation, arguments)
        except Exception as exc:  # pragma: no cover - injected transport boundary
            ledger.complete(record, status="failed", error=str(exc))
            raise SetupError(f"setup dispatch failed: {operation}") from exc
        if not isinstance(output, dict):
            ledger.complete(
                record, status="failed", error="setup result is not an object"
            )
            raise SetupError(f"setup result is not an object: {operation}")
        ledger.complete(record, status="completed", result=output)
        outputs[operation] = output
    return outputs


def _render_stimulus(
    stimulus: Any,
    values: dict[str, Any],
    declarations: tuple[RuntimeBinding, ...],
) -> dict[str, Any]:
    if not isinstance(stimulus, dict) or not isinstance(stimulus.get("user_text"), str):
        raise BindingError("stimulus user_text is unavailable")
    rendered = dict(stimulus)
    rendered["user_text"] = substitute_slots(
        stimulus["user_text"], values, declarations
    )
    history = _stimulus_history(stimulus)
    rendered["history"] = [
        {
            **turn,
            "content": substitute_slots(turn["content"], values, declarations),
        }
        for turn in history
        if isinstance(turn, dict) and isinstance(turn.get("content"), str)
    ]
    return rendered


def _stimulus_history(stimulus: dict[str, Any]) -> list[Any]:
    history = stimulus.get("history", [])
    if not isinstance(history, list):
        raise BindingError("stimulus history must be a list")
    return history


def validate_stimulus_declarations(
    stimulus: Any,
    declarations: tuple[RuntimeBinding, ...] | list[RuntimeBinding],
) -> None:
    """Check static stimulus shape and declared slots without resolving values."""

    if not isinstance(stimulus, dict) or not isinstance(stimulus.get("user_text"), str):
        raise BindingError("stimulus user_text is unavailable")
    validate_slot_references(stimulus["user_text"], declarations)
    history = _stimulus_history(stimulus)
    for turn in history:
        if isinstance(turn, dict) and isinstance(turn.get("content"), str):
            validate_slot_references(turn["content"], declarations)


def _runtime_contract(
    plan: Any, inputs: Any, manifest_capabilities: dict[str, Any]
) -> dict[str, Any]:
    for candidate in (
        inputs.get("runtime_contract") if isinstance(inputs, dict) else None,
        plan.get("runtime_contract") if isinstance(plan, dict) else None,
        manifest_capabilities,
    ):
        if isinstance(candidate, dict):
            return candidate
    return {}


def _supplied_fact_values(inputs: Any) -> dict[str, Any]:
    """Extract only code-supplied fact values from the package inventory."""

    if not isinstance(inputs, dict):
        return {}
    direct = inputs.get("facts")
    if isinstance(direct, dict):
        return dict(direct)
    inventory = inputs.get("inventory")
    facts = inventory.get("facts") if isinstance(inventory, dict) else None
    if not isinstance(facts, list):
        return {}
    return {
        item["ref"]: item["value"]
        for item in facts
        if isinstance(item, dict)
        and isinstance(item.get("ref"), str)
        and "value" in item
    }


def _has_canonical_prerequisites(declarations: Any) -> bool:
    return isinstance(declarations, list) and any(
        isinstance(item, dict)
        and {"check", "evidence_refs", "binding"}.issubset(item)
        and not ({"source", "expected"} & set(item))
        for item in declarations
    )


def _base_receipt(
    package: ArtifactPackage | None, discovery_records: list[dict[str, Any]] | None
) -> dict[str, Any]:
    return {
        "schema": "frozen-execution-receipt-v1",
        "package_digest": package.digest if package else None,
        "detector_digest": package.detector_digest if package else None,
        "discovery_ledger": {
            "category": "discovery",
            "dispatches": list(discovery_records or []),
            "total": len(discovery_records or []),
        },
        "runtime_status": "not_started",
        "rich_result": None,
        "garak_value": None,
        "cleanup": {"status": "not_started"},
        "service_revisions": {},
        "port_probes": {},
        "totals": {},
    }


def _finish_incomplete(
    receipt: dict[str, Any],
    reason: str,
    package: ArtifactPackage,
    setup: RequestLedger,
    generation: RequestLedger,
    commands: RequestLedger,
    judge: RequestLedger,
    receipt_path: str | Path | None,
    *,
    error: str | None = None,
) -> FrozenExecution:
    receipt["status"] = FrozenExecutionStatus.INCOMPLETE.value
    receipt["incomplete_reason"] = reason
    if error:
        receipt["runtime_failure"] = error
    receipt["runtime_status"] = "not_started"
    receipt["rich_result"] = None
    receipt["garak_value"] = None
    _finish_receipt(
        receipt, package, setup, generation, commands, judge, None, None, receipt_path
    )
    return FrozenExecution(FrozenExecutionStatus.INCOMPLETE, receipt, reason)


def _finish_failed(
    receipt: dict[str, Any],
    package: ArtifactPackage,
    setup: RequestLedger,
    generation: RequestLedger,
    commands: RequestLedger,
    judge: RequestLedger,
    receipt_path: str | Path | None,
) -> FrozenExecution:
    receipt["status"] = FrozenExecutionStatus.FAILED.value
    _finish_receipt(
        receipt, package, setup, generation, commands, judge, None, None, receipt_path
    )
    return FrozenExecution(FrozenExecutionStatus.FAILED, receipt)


def _finish_receipt(
    receipt: dict[str, Any],
    package: ArtifactPackage,
    setup: RequestLedger,
    generation: RequestLedger,
    commands: RequestLedger,
    judge: RequestLedger,
    identities: list[dict[str, Any]] | None,
    cleanup: Callable[[list[dict[str, Any]]], dict[str, Any]] | None,
    receipt_path: str | Path | None,
) -> None:
    ledgers = {
        "setup_capture": setup.as_dict(),
        "generation": generation.as_dict(),
        "server_command": commands.as_dict(),
        "semantic_judge": judge.as_dict(),
        "discovery": receipt["discovery_ledger"],
    }
    receipt["ledgers"] = ledgers
    receipt["setup_capture_ledger"] = ledgers["setup_capture"]
    receipt["generation_ledger"] = ledgers["generation"]
    receipt["server_command_ledger"] = ledgers["server_command"]
    receipt["judge_ledger"] = ledgers["semantic_judge"]
    receipt["authoring_totals"] = package.manifest.authoring
    receipt["totals"] = {
        "setup_capture": setup.as_dict()["total"],
        "generation": generation.as_dict()["total"],
        "server_commands": commands.as_dict()["total"],
        "semantic_judge": judge.as_dict()["total"],
        "discovery": receipt["discovery_ledger"]["total"],
    }
    if identities is not None:
        receipt["cleanup"] = (
            cleanup(identities)
            if cleanup
            else {
                "status": "captured",
                "identities": identities,
            }
        )
    elif receipt["cleanup"].get("status") == "not_started":
        receipt["cleanup"] = {"status": "not_requested", "identities": []}
    _write_receipt(receipt_path, receipt)


def _detector_result(value: Any) -> tuple[str, dict[str, Any] | None, str | None]:
    if not isinstance(value, dict):
        return "failed", None, "detector runtime returned a non-object"
    status = value.get("status")
    result = value.get("result")
    if status != "completed":
        return (
            str(status or "failed"),
            None,
            value.get("failure", "detector runtime failed"),
        )
    if not isinstance(result, dict):
        return "failed", None, "detector runtime returned no rich result"
    return "completed", result, None


def _execute_detector(
    evidence: dict[str, Any], package: ArtifactPackage
) -> dict[str, Any]:
    from detector_runtime_adapter import execute_detector

    execution = execute_detector(package, evidence)
    return {
        "status": execution.status,
        "result": execution.result,
        "failure": execution.failure,
        "docker_argv": list(execution.docker_argv),
        "package_digest_after": execution.package_digest_after,
        "detector_sha256_after": execution.detector_sha256_after,
    }


def _binding_reason(message: str) -> str:
    if "mistyped" in message:
        return "binding_mistyped"
    if "missing" in message or "not found" in message or "selector" in message:
        return "binding_missing"
    return "binding_invalid"


def _write_receipt(path: str | Path | None, receipt: dict[str, Any]) -> None:
    if path is None:
        return
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(receipt, stream, sort_keys=True, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, destination)
    except Exception:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _digest(value: Any) -> str:
    return (
        __import__("hashlib")
        .sha256(
            json.dumps(
                value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        )
        .hexdigest()
    )


run_frozen_package = execute_frozen_package

__all__ = [
    "FrozenExecution",
    "FrozenExecutionStatus",
    "SetupError",
    "check_prerequisites",
    "evidence_packet_from_generation",
    "execute_frozen_package",
    "run_frozen_package",
    "validate_stimulus_declarations",
]
