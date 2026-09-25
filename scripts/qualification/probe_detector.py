"""Run a package's own detector on neutral, synthetic evidence probes.

The command answers one question offline: does the packaged oracle fire on a
supplied tool-call or message pattern and stay quiet on another? It never
contacts a model, target, or gateway. Each probe becomes an evidence packet
through the same adapter, binding resolution, and judge seam that live
execution uses, and the unchanged ``detector.py`` bytes run in the same
constrained Docker sandbox.

Usage::

    python scripts/qualification/probe_detector.py --package <dir> \
        --probes <probes.json> --output <results.json> \
        [--docker-path /usr/local/bin/docker]

Exit codes: 0 when results are written (per-probe failures are
``outcome: error``), 1 when the request or package cannot be loaded or the
detector digest is invalid, 2 on an unexpected crash.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from artifact_package_runtime import (
    ArtifactPackage,
    ArtifactPackageError,
    load_artifact_package,
)
from detector_runtime_adapter import DOCKER, execute_detector
from frozen_judge import evaluate_frozen_judge
from frozen_runtime import (
    _annotate_binding_provenance,
    _has_canonical_prerequisites,
    _null_prerequisite_bindings,
    _render_stimulus,
    _runtime_contract,
    _supplied_fact_values,
    evidence_packet_from_generation,
)
from request_ledger import RequestLedger
from runtime_bindings import (
    BindingError,
    RuntimeBinding,
    resolve_bindings,
    validate_binding_declarations,
)

REQUEST_SCHEMA = "detector-probe-request-v1"
RESULT_SCHEMA = "detector-probe-result-v1"
PROBE_OUTCOMES = frozenset({"detected", "not_detected", "inconclusive", "error"})
BINDING_STATES = frozenset({"resolved", "unavailable"})
PROBE_FIELDS = frozenset({"id", "tool_calls", "assistant_messages", "user_text"})
TOOL_CALL_FIELDS = frozenset({"name", "arguments", "result", "status"})
SERVER_LABEL = "qualification_target"

DetectorRunner = Callable[[ArtifactPackage, dict[str, Any]], dict[str, Any]]


class ProbeRequestError(ValueError):
    """Raised when a probe request does not match the closed request schema."""


@dataclass(frozen=True)
class BindingContext:
    values: dict[str, Any]
    provenance: dict[str, Any]
    declarations: tuple[RuntimeBinding, ...]
    state: str
    error: str | None = None


def validate_probe_request(value: Any) -> list[dict[str, Any]]:
    """Return the probe list after checking the closed request schema."""

    if not isinstance(value, dict) or set(value) != {"schema", "probes"}:
        raise ProbeRequestError("probe request must contain only schema and probes")
    if value["schema"] != REQUEST_SCHEMA:
        raise ProbeRequestError(f"probe request schema must be {REQUEST_SCHEMA}")
    probes = value["probes"]
    if not isinstance(probes, list):
        raise ProbeRequestError("probes must be a list")
    seen: set[str] = set()
    for index, probe in enumerate(probes):
        where = f"probes[{index}]"
        if not isinstance(probe, dict) or set(probe) != PROBE_FIELDS:
            raise ProbeRequestError(f"{where} fields must be {sorted(PROBE_FIELDS)}")
        probe_id = probe["id"]
        if not isinstance(probe_id, str) or not probe_id.strip():
            raise ProbeRequestError(f"{where}.id must be a nonblank string")
        if probe_id in seen:
            raise ProbeRequestError(f"duplicate probe id: {probe_id}")
        seen.add(probe_id)
        if probe["user_text"] is not None and not isinstance(probe["user_text"], str):
            raise ProbeRequestError(f"{where}.user_text must be a string or null")
        calls = probe["tool_calls"]
        if not isinstance(calls, list):
            raise ProbeRequestError(f"{where}.tool_calls must be a list")
        for call_index, call in enumerate(calls):
            call_where = f"{where}.tool_calls[{call_index}]"
            if not isinstance(call, dict) or set(call) != TOOL_CALL_FIELDS:
                raise ProbeRequestError(
                    f"{call_where} fields must be {sorted(TOOL_CALL_FIELDS)}"
                )
            if not isinstance(call["name"], str) or not call["name"].strip():
                raise ProbeRequestError(f"{call_where}.name must be nonblank")
            if not isinstance(call["arguments"], dict):
                raise ProbeRequestError(f"{call_where}.arguments must be an object")
            if call["status"] is not None and not isinstance(call["status"], str):
                raise ProbeRequestError(f"{call_where}.status must be a string or null")
        messages = probe["assistant_messages"]
        if not isinstance(messages, list) or not all(
            isinstance(item, str)
            or (
                isinstance(item, dict)
                and set(item) == {"content"}
                and isinstance(item["content"], str)
            )
            for item in messages
        ):
            raise ProbeRequestError(
                f"{where}.assistant_messages must be strings or {{content}} objects"
            )
    return probes


def validate_probe_result(value: Any) -> None:
    """Check a result document against the closed result schema."""

    required = {"schema", "package_digest", "detector_digest", "error", "results"}
    if not isinstance(value, dict) or set(value) != required:
        raise ValueError("probe result fields are not closed")
    if value["schema"] != RESULT_SCHEMA:
        raise ValueError("probe result schema is invalid")
    for name in ("package_digest", "detector_digest", "error"):
        if value[name] is not None and not isinstance(value[name], str):
            raise ValueError(f"probe result {name} must be a string or null")
    results = value["results"]
    if not isinstance(results, list):
        raise ValueError("probe results must be a list")
    if value["error"] is not None and results:
        raise ValueError("a top-level error requires empty results")
    for item in results:
        if not isinstance(item, dict) or set(item) != {
            "id",
            "outcome",
            "reason",
            "bindings",
        }:
            raise ValueError("probe result entry fields are not closed")
        if item["outcome"] not in PROBE_OUTCOMES:
            raise ValueError("probe result outcome is invalid")
        if item["bindings"] not in BINDING_STATES:
            raise ValueError("probe result bindings state is invalid")
        if not isinstance(item["id"], str) or not isinstance(item["reason"], str):
            raise ValueError("probe result id and reason must be strings")


def resolve_offline_bindings(package: ArtifactPackage) -> BindingContext:
    """Resolve supplied-input bindings exactly as the live runtime does.

    Setup-output bindings need a live setup capture, so they stay unresolved
    and mark the whole context unavailable.
    """

    declarations_raw = package.json_member("bindings.json", default=[])
    prerequisites = package.json_member("prerequisites.json", default=[])
    checks = package.json_member("checks.json", default={})
    inputs = package.json_member("inputs.json", default={})
    plan = package.json_member("plan.json", default={})
    runtime_contract = _runtime_contract(
        plan, inputs, package.manifest.runtime_capabilities
    )
    inventory = inputs.get("inventory", {}) if isinstance(inputs, dict) else {}
    canonical = (
        isinstance(checks, dict) and checks.get("interface") == "artifact-authoring-v2"
    ) or _has_canonical_prerequisites(prerequisites)
    try:
        declarations = validate_binding_declarations(
            declarations_raw, inventory=inventory, runtime_contract=runtime_contract
        )
    except BindingError as exc:
        return BindingContext({}, {}, (), "unavailable", f"binding_invalid: {exc}")
    supplied = _supplied_fact_values(inputs)
    allow_null = _null_prerequisite_bindings(prerequisites if canonical else [])
    values: dict[str, Any] = {}
    provenance: dict[str, Any] = {}
    resolved: list[RuntimeBinding] = []
    state = "resolved"
    for binding in declarations:
        if binding.source_kind != "supplied_input":
            state = "unavailable"
            continue
        try:
            value, record = resolve_bindings(
                [binding],
                setup_outputs={},
                supplied_inputs=supplied,
                allow_null_bindings=allow_null,
            )
        except BindingError:
            state = "unavailable"
            continue
        values.update(value)
        provenance.update(record)
        resolved.append(binding)
    _annotate_binding_provenance(
        provenance, tuple(resolved), RequestLedger("setup_capture")
    )
    return BindingContext(values, provenance, declarations, state)


def probe_generation(
    probe: dict[str, Any],
    probe_index: int,
    stimulus: dict[str, Any],
) -> dict[str, Any]:
    """Build a raw generation record in the live launcher's native shape."""

    tool_calls = []
    for call_index, call in enumerate(probe["tool_calls"]):
        native: dict[str, Any] = {
            "arguments": json.dumps(call["arguments"], ensure_ascii=False),
            "id": f"fc_probe_{probe_index:03d}_{call_index:03d}",
            "name": call["name"],
            "output": None
            if call["result"] is None
            else json.dumps(call["result"], ensure_ascii=False),
            "server_label": SERVER_LABEL,
            "type": "mcp_call",
        }
        if call["status"] is not None:
            native["status"] = call["status"]
        tool_calls.append(native)
    messages = [
        {
            "role": "assistant",
            "content": item if isinstance(item, str) else item["content"],
        }
        for item in probe["assistant_messages"]
    ]
    user_text = probe["user_text"]
    return {
        "messages": messages,
        "tool_calls": tool_calls,
        "tool_calls_capture": {"available": True, "complete": True},
        "transport": {
            "client": "detector-probe",
            "synthetic": True,
            "gateway_responses_request_count": 0,
        },
        "user_text": stimulus["user_text"] if user_text is None else user_text,
        "history": stimulus.get("history", []),
    }


def build_probe_packet(
    package: ArtifactPackage,
    probe: dict[str, Any],
    probe_index: int,
    bindings: BindingContext,
) -> dict[str, Any]:
    """Return the detector packet a live run would build for this probe."""

    authored = package.json_member("stimulus.json", default={})
    try:
        stimulus = _render_stimulus(authored, bindings.values, bindings.declarations)
    except BindingError:
        if not isinstance(authored, dict) or not isinstance(
            authored.get("user_text"), str
        ):
            raise
        stimulus = {
            "user_text": authored["user_text"],
            "history": list(authored.get("history") or []),
        }
    raw = probe_generation(probe, probe_index, stimulus)
    packet = evidence_packet_from_generation(
        raw,
        bindings=bindings.values,
        binding_provenance=bindings.provenance,
        setup_outputs={},
    )
    judge_spec = package.json_member("judge.json")
    detector_packet = dict(packet)
    detector_packet["judge"] = evaluate_frozen_judge(
        judge_spec, packet, client=None
    ).as_dict()
    return detector_packet


def docker_detector_runner(docker_path: str = DOCKER) -> DetectorRunner:
    def run(package: ArtifactPackage, evidence: dict[str, Any]) -> dict[str, Any]:
        execution = execute_detector(package, evidence, docker_path=docker_path)
        return {
            "status": execution.status,
            "result": execution.result,
            "failure": execution.failure,
            "detector_sha256": execution.detector_sha256,
        }

    return run


def run_probes(
    package_path: str | Path,
    request: Any,
    *,
    detector_runner: DetectorRunner,
) -> tuple[int, dict[str, Any]]:
    """Return the exit code and result document for one probe request."""

    document: dict[str, Any] = {
        "schema": RESULT_SCHEMA,
        "package_digest": None,
        "detector_digest": None,
        "error": None,
        "results": [],
    }
    try:
        probes = validate_probe_request(request)
    except ProbeRequestError as exc:
        document["error"] = f"probe_request_invalid: {exc}"
        return 1, document
    try:
        package = load_artifact_package(package_path)
        document["package_digest"] = package.digest
        document["detector_digest"] = package.detector_digest
        source = package.members["detector.py"].decode("utf-8")
    except (ArtifactPackageError, OSError, UnicodeDecodeError, KeyError) as exc:
        document["error"] = f"package_invalid: {exc}"
        return 1, document
    if "def evaluate(" not in source:
        document["error"] = "detector_invalid: detector.py must define evaluate"
        return 1, document

    bindings = resolve_offline_bindings(package)
    for index, probe in enumerate(probes):
        document["results"].append(
            _run_one(package, probe, index, bindings, detector_runner)
        )
    return 0, document


def _run_one(
    package: ArtifactPackage,
    probe: dict[str, Any],
    index: int,
    bindings: BindingContext,
    detector_runner: DetectorRunner,
) -> dict[str, Any]:
    entry = {
        "id": probe["id"],
        "outcome": "error",
        "reason": "",
        "bindings": bindings.state,
    }
    if bindings.error is not None:
        entry["reason"] = bindings.error
        return entry
    try:
        packet = build_probe_packet(package, probe, index, bindings)
    except BindingError as exc:
        entry["reason"] = f"stimulus_invalid: {exc}"
        return entry
    try:
        execution = detector_runner(package, packet)
    except Exception as exc:  # detector runtime boundary
        entry["reason"] = f"detector_runtime_failed: {type(exc).__name__}: {exc}"
        return entry
    digest = execution.get("detector_sha256")
    if digest is not None and digest != package.detector_digest:
        entry["reason"] = "detector_digest_mismatch"
        return entry
    result = execution.get("result")
    if execution.get("status") != "completed" or not isinstance(result, dict):
        entry["reason"] = str(execution.get("failure") or "detector runtime failed")
        return entry
    entry["outcome"] = result["outcome"]
    entry["reason"] = result["reason"]
    return entry


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, ensure_ascii=False)
            stream.write("\n")
        os.replace(temporary, path)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def main(
    argv: list[str] | None = None,
    *,
    detector_runner: DetectorRunner | None = None,
) -> int:
    parser = argparse.ArgumentParser(
        description="Run a package detector on synthetic evidence probes."
    )
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--probes", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--docker-path", default=DOCKER)
    args = parser.parse_args(argv)
    try:
        try:
            request = json.loads(args.probes.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            code, document = (
                1,
                {
                    "schema": RESULT_SCHEMA,
                    "package_digest": None,
                    "detector_digest": None,
                    "error": f"probe_request_unreadable: {exc}",
                    "results": [],
                },
            )
        else:
            code, document = run_probes(
                args.package,
                request,
                detector_runner=detector_runner
                or docker_detector_runner(args.docker_path),
            )
        validate_probe_result(document)
        _write_json(args.output, document)
    except Exception:
        traceback.print_exc(file=sys.stderr)
        return 2
    if document["error"] is not None:
        print(document["error"], file=sys.stderr)
    return code


__all__ = [
    "BindingContext",
    "ProbeRequestError",
    "REQUEST_SCHEMA",
    "RESULT_SCHEMA",
    "build_probe_packet",
    "docker_detector_runner",
    "main",
    "probe_generation",
    "resolve_offline_bindings",
    "run_probes",
    "validate_probe_request",
    "validate_probe_result",
]


if __name__ == "__main__":
    raise SystemExit(main())
