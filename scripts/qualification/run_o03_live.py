#!/usr/bin/env python3
"""Run one pinned O03 package through the maintained frozen-live route."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
WORKTREES = ROOT.parents[1]
GARAK_CHECKOUT = (
    WORKTREES / "adaptive-scenario-artifact-split" / ".mission-runtime" / "garak-pinned"
)
GARAK_PYTHON = GARAK_CHECKOUT.parent / "garak-venv" / "bin" / "python"
DEFAULT_TARGET_ROOT = Path("/Users/hjrnunes/workspace/hjrnunes/mini-agents")
DEFAULT_PROFILES_FILE = ROOT.parents[2] / "config" / "model-profiles.yaml"
MAX_SETUP_AND_STATE_READS = 4
MAX_GENERATIONS = 1
GENERATION_TIMEOUT_SECONDS = 180.0
GENERATION_PROCESS_TIMEOUT_SECONDS = 210.0
GENERATION_MAX_OUTPUT_TOKENS = 4096
GENERATION_MODEL = "gemma-4-26b-a4b-it"
MCP_PROCESS_TIMEOUT_SECONDS = 45.0

if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

from run_o04_live import (  # noqa: E402
    PINNED_GARAK_REVISION,
    _garak_helper,
    _parse_child_protocol,
    _persist_child_output,
    _revision,
    _write_private_json,
)


def _read_json_stdin() -> dict[str, Any]:
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise ValueError("helper input must be an object")
    return value


def _decode_tool_value(text_blocks: list[str], structured: Any) -> dict[str, Any]:
    """Decode the JSON-text and structured-content forms returned by MiniAgents."""
    for candidate in [*text_blocks, structured]:
        value = candidate
        for _ in range(2):
            if isinstance(value, str):
                try:
                    value = json.loads(value)
                except json.JSONDecodeError:
                    break
            if isinstance(value, dict) and set(value) == {"result"}:
                value = value["result"]
                continue
            if isinstance(value, dict):
                return value
            break
    raise ValueError("MCP tool result was not one JSON object")


async def _mcp_exchange(request: dict[str, Any]) -> dict[str, Any]:
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    async with sse_client(request["server_url"]) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            if request["action"] == "discover":
                listing = await session.list_tools()
                return {
                    "tools": [
                        item.model_dump(mode="json", by_alias=True, exclude_none=True)
                        for item in listing.tools
                    ]
                }
            result = await session.call_tool(
                request["operation"], request.get("arguments", {})
            )
            native = result.model_dump(mode="json", by_alias=True, exclude_none=True)
            is_error = bool(native.get("isError", False))
            if is_error:
                return {"is_error": True, "native": native}
            text_blocks = [
                item.text
                for item in getattr(result, "content", [])
                if getattr(item, "type", None) == "text"
                and isinstance(getattr(item, "text", None), str)
            ]
            value = _decode_tool_value(
                text_blocks, getattr(result, "structuredContent", None)
            )
            return {"is_error": False, "native": native, "value": value}


def _mcp_helper_main() -> int:
    try:
        request = _read_json_stdin()
        with contextlib.redirect_stdout(sys.stderr):
            response = asyncio.run(_mcp_exchange(request))
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        return 0
    except Exception as exc:
        sys.stdout.write(json.dumps({"error": type(exc).__name__}) + "\n")
        return 2


def _garak_helper_main() -> int:
    try:
        request = _read_json_stdin()
        with contextlib.redirect_stdout(sys.stderr):
            response = _garak_helper(request)
        response["provider_request_count"] = response.get(
            "gateway_responses_request_count", 0
        )
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        return 0
    except Exception as exc:
        sys.stdout.write(json.dumps({"error": type(exc).__name__}) + "\n")
        return 2


def _run_protocol_child(
    command: list[str],
    request: dict[str, Any],
    *,
    cwd: Path,
    env: dict[str, str],
    timeout: float,
    capture_dir: Path,
    prefix: str,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run one JSON helper, preserving both streams and status before parsing."""
    try:
        child = subprocess.run(
            command,
            input=json.dumps(request, ensure_ascii=False),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=cwd,
            env=env,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        _persist_child_output(
            capture_dir,
            stdout=exc.stdout,
            stderr=exc.stderr,
            returncode=None,
            status="timed_out",
            failure_type=type(exc).__name__,
            prefix=prefix,
        )
        raise RuntimeError(f"{prefix} helper timed out; no retry attempted") from None
    except (OSError, subprocess.SubprocessError) as exc:
        _persist_child_output(
            capture_dir,
            stdout=b"",
            stderr=type(exc).__name__.encode("utf-8"),
            returncode=None,
            status="failed_to_start",
            failure_type=type(exc).__name__,
            prefix=prefix,
        )
        raise RuntimeError(
            f"{prefix} helper could not start; no retry attempted"
        ) from None

    capture = _persist_child_output(
        capture_dir,
        stdout=child.stdout,
        stderr=child.stderr,
        returncode=child.returncode,
        status="completed" if child.returncode == 0 else "failed",
        prefix=prefix,
    )
    protocol = _parse_child_protocol(capture_dir, capture, prefix=prefix)
    return protocol, capture


def _child_environment(api_key: str | None = None) -> dict[str, str]:
    secret_names = {"openai_api_key", "api_key", "authorization"}
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.lower() not in secret_names and not key.lower().endswith("_api_key")
    }
    if api_key is not None:
        environment["OPENAI_API_KEY"] = api_key
    return environment


def _inventory_functions(package: Any) -> dict[str, dict[str, Any]]:
    inputs = package.json_member("inputs.json", default={})
    inventory = inputs.get("inventory", {}) if isinstance(inputs, dict) else {}
    operations = inventory.get("operations", []) if isinstance(inventory, dict) else []
    return {
        item["name"]: {
            "name": item["name"],
            "description": item.get("description", ""),
            "parameters": item.get("arguments", {}),
        }
        for item in operations
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }


def _argument_contract(schema: Any) -> dict[str, Any]:
    if not isinstance(schema, dict):
        raise ValueError("declared/runtime argument schema is not an object")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not isinstance(required, list):
        raise ValueError("declared/runtime argument schema is malformed")
    types: dict[str, Any] = {}
    for name, declaration in properties.items():
        if not isinstance(name, str) or not isinstance(declaration, dict):
            raise ValueError("argument property schema is malformed")
        kind = declaration.get("type")
        types[name] = tuple(sorted(kind)) if isinstance(kind, list) else kind
    if not all(isinstance(name, str) for name in required):
        raise ValueError("required argument name is malformed")
    return {
        "argument_names": sorted(properties),
        "argument_types": types,
        "required": sorted(required),
    }


def _validate_runtime_tools(
    operations: dict[str, dict[str, Any]], observed_tools: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    runtime = {
        tool.get("name"): tool
        for tool in observed_tools
        if isinstance(tool, dict) and isinstance(tool.get("name"), str)
    }
    required_declared = {"summarize_for_ehr", "commit_to_ehr"}
    comparisons = []
    for name in sorted(required_declared):
        if name not in operations or name not in runtime:
            raise ValueError(
                f"package/runtime inventory lacks required operation: {name}"
            )
        declared = operations[name]
        actual = runtime[name]
        expected_contract = _argument_contract(declared["parameters"])
        actual_contract = _argument_contract(actual.get("inputSchema", {}))
        if expected_contract != actual_contract:
            raise ValueError(f"runtime argument contract differs for {name}")
        declared_description = declared.get("description", "")
        actual_description = actual.get("description", "")
        comparisons.append(
            {
                "operation": name,
                "argument_contract": "matched",
                "argument_contract_shape": expected_contract,
                "description_matches": declared_description == actual_description,
                "declared_description_sha256": hashlib.sha256(
                    str(declared_description).encode("utf-8")
                ).hexdigest(),
                "runtime_description_sha256": hashlib.sha256(
                    str(actual_description).encode("utf-8")
                ).hexdigest(),
            }
        )
    state_tool = runtime.get("get_occiai_state_summary")
    if not isinstance(state_tool, dict):
        raise ValueError("runtime MCP inventory lacks the O03 state-summary tool")
    state_contract = _argument_contract(state_tool.get("inputSchema", {}))
    if state_contract["argument_names"] or state_contract["required"]:
        raise ValueError("state-summary verification tool must take zero arguments")
    return comparisons


def _generation_transport(
    observed_tools: list[dict[str, Any]], target_url: str
) -> list[dict[str, Any]]:
    names = [
        tool["name"]
        for tool in observed_tools
        if isinstance(tool, dict)
        and isinstance(tool.get("name"), str)
        and tool["name"] in {"commit_to_ehr", "get_occiai_state_summary"}
    ]
    if "commit_to_ehr" not in names or "get_occiai_state_summary" not in names:
        raise ValueError("runtime MCP inventory lacks an O03 generation operation")
    return [
        {
            "type": "mcp",
            "server_label": "qualification_target",
            "server_url": target_url,
            "require_approval": "never",
            "allowed_tools": names,
        }
    ]


def _preflight(args: argparse.Namespace) -> tuple[Any, dict[str, Any], dict[str, Any]]:
    from artifact_package_runtime import load_artifact_package
    from run_recipe import read_profile_settings

    package = load_artifact_package(args.package)
    if package.manifest.scenario_id != "O03":
        raise ValueError("package must declare scenario O03")
    authoring = package.manifest.authoring
    accepted = isinstance(authoring, dict) and (
        authoring.get("status") == "accepted"
        or authoring.get("terminal_status") == "accepted"
        or (
            isinstance(authoring.get("review_status"), dict)
            and authoring["review_status"].get("artifact") == "accepted"
        )
    )
    if not accepted:
        raise ValueError("package manifest must mark the artifact accepted")
    if package.digest != args.expected_package_digest:
        raise ValueError("loaded O03 package digest does not match the review pin")
    if package.detector_digest != args.expected_detector_digest:
        raise ValueError("loaded O03 detector digest does not match the review pin")
    setup = package.json_member("setup.json", default=[])
    if not isinstance(setup, list):
        raise ValueError("O03 package setup must be a list")
    creation_steps = [
        step
        for step in setup
        if isinstance(step, dict) and step.get("operation") == "summarize_for_ehr"
    ]
    if len(creation_steps) != 1:
        raise ValueError("O03 requires exactly one summarize_for_ehr setup")
    creation_index = next(
        index
        for index, step in enumerate(setup)
        if isinstance(step, dict) and step.get("operation") == "summarize_for_ehr"
    )
    state_after_creation = any(
        isinstance(step, dict)
        and step.get("operation") == "get_occiai_state_summary"
        and index > creation_index
        for index, step in enumerate(setup)
    )
    extra_state_reads = 0 if state_after_creation else 1
    if len(setup) + extra_state_reads > MAX_SETUP_AND_STATE_READS:
        raise ValueError("O03 setup plus state verification exceeds four calls")

    profile = read_profile_settings(args.profiles_file, args.profile)
    if not profile["model"]:
        raise ValueError("selected profile does not specify a model id")
    if profile["model"] != GENERATION_MODEL:
        raise ValueError("selected profile model does not match the O03 generation pin")
    required_files = {
        "target_python": args.target_python,
        "profiles_file": args.profiles_file,
        "garak_python": args.garak_python,
        "garak_checkout": args.garak_checkout,
    }
    missing = [name for name, path in required_files.items() if not path.exists()]
    if missing:
        raise FileNotFoundError(f"required local runtime paths are missing: {missing}")
    if not args.target_python.is_file() or not args.garak_python.is_file():
        raise FileNotFoundError("target/Garak Python executable is unavailable")
    if _revision(args.garak_checkout) != PINNED_GARAK_REVISION:
        raise ValueError("Garak checkout does not match the pinned revision")
    if args.run_dir.exists():
        raise FileExistsError("O03 output directory already exists")

    package_controls = {
        "package_id": package.manifest.package_id,
        "scenario_id": package.manifest.scenario_id,
        "package_digest": package.digest,
        "expected_package_digest": args.expected_package_digest,
        "detector_sha256": package.detector_digest,
        "expected_detector_sha256": args.expected_detector_digest,
        "declared_setup_calls": len(setup),
        "post_creation_state_reads": extra_state_reads,
    }
    preflight = {
        "schema": "o03-offline-preflight-v1",
        "status": "passed",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "package": package_controls,
        "local_runtime_files": {
            name: {"path": str(path), "present": path.exists()}
            for name, path in required_files.items()
        },
        "profile_alias": args.profile,
        "model": profile["model"],
        "limits": {
            "target_domain": "occiai",
            "target_port": 8892,
            "gateway_port": 8321,
            "max_setup_and_state_reads": MAX_SETUP_AND_STATE_READS,
            "generation_requests": MAX_GENERATIONS,
            "generation_retries": 0,
            "semantic_judge_requests": 0,
        },
        "network_dispatches": {
            "target": 0,
            "generation_provider": 0,
            "services_started": 0,
        },
    }
    return package, profile, preflight


def _run(args: argparse.Namespace) -> int:
    from frozen_live_dispatch import execute_o03_frozen_live_package

    package, profile, preflight = _preflight(args)
    model = GENERATION_MODEL
    run_dir = args.run_dir.resolve()
    run_dir.mkdir(parents=True, mode=0o700)
    os.chmod(run_dir, 0o700)
    capture_dir = run_dir / "generation_capture"
    capture_dir.mkdir(mode=0o700)
    mcp_capture_root = run_dir / "mcp_capture"
    mcp_capture_root.mkdir(mode=0o700)
    receipt_path = run_dir / "receipt.json"
    state_dir = run_dir / "runtime_state"
    target_url = "http://127.0.0.1:8892/sse"
    model_url = "http://127.0.0.1:8321/v1/"
    setup = package.json_member("setup.json", default=[])
    creation_index = next(
        index
        for index, step in enumerate(setup)
        if isinstance(step, dict) and step.get("operation") == "summarize_for_ehr"
    )
    state_after_creation_is_declared = any(
        isinstance(step, dict)
        and step.get("operation") == "get_occiai_state_summary"
        and index > creation_index
        for index, step in enumerate(setup)
    )
    operations = _inventory_functions(package)
    discovery: dict[str, Any] = {}
    native_target_calls: list[dict[str, Any]] = []
    setup_results: dict[str, dict[str, Any]] = {}
    state_verification: dict[str, Any] = {}
    generation_capture: dict[str, Any] = {}
    mcp_capture_records: list[dict[str, Any]] = []

    def bridge(request: dict[str, Any]) -> dict[str, Any]:
        sequence = len(mcp_capture_records) + 1
        call_dir = mcp_capture_root / f"call-{sequence:02d}"
        call_dir.mkdir(mode=0o700)
        capture_record: dict[str, Any] = {
            "sequence": sequence,
            "action": request["action"],
            "operation": request.get("operation"),
            "capture_dir": str(call_dir),
        }
        mcp_capture_records.append(capture_record)
        try:
            protocol, status = _run_protocol_child(
                [
                    str(args.target_python),
                    str(Path(__file__).resolve()),
                    "--mcp-helper",
                ],
                request,
                cwd=args.target_root,
                env=_child_environment(),
                timeout=MCP_PROCESS_TIMEOUT_SECONDS,
                capture_dir=call_dir,
                prefix="mcp",
            )
        except Exception:
            status_path = call_dir / "child-status.json"
            if status_path.is_file():
                capture_record["child_status"] = json.loads(
                    status_path.read_text(encoding="utf-8")
                )
            raise
        capture_record["child_status"] = status
        return protocol

    def discover_and_verify() -> None:
        if discovery:
            return
        observed = bridge({"action": "discover", "server_url": target_url}).get("tools")
        if not isinstance(observed, list):
            raise RuntimeError("runtime MCP discovery did not return a tools list")
        comparisons = _validate_runtime_tools(operations, observed)
        discovery.update(
            {
                "tools": observed,
                "package_contract_comparisons": comparisons,
                "state_summary_contract": {
                    "operation": "get_occiai_state_summary",
                    "source": "route_authorized_verification_read",
                    "argument_count": 0,
                    "status": "verified",
                },
                "generation_transport": _generation_transport(observed, target_url),
            }
        )

    def setup_dispatch(operation: str, arguments: dict[str, Any]) -> dict[str, Any]:
        discover_and_verify()
        result = bridge(
            {
                "action": "call",
                "server_url": target_url,
                "operation": operation,
                "arguments": arguments,
            }
        )
        native_target_calls.append(
            {
                "category": "setup_capture",
                "operation": operation,
                "arguments": arguments,
                "native_result": result.get("native"),
            }
        )
        if result.get("is_error"):
            raise RuntimeError(f"MiniAgents setup operation failed: {operation}")
        value = result.get("value")
        if not isinstance(value, dict):
            raise RuntimeError(f"MiniAgents setup result is not an object: {operation}")
        setup_results[operation] = value
        return value

    def generation_dispatch(**kwargs: Any) -> dict[str, Any]:
        if generation_capture:
            raise RuntimeError("O03 generation allowance already consumed")
        discover_and_verify()
        created = setup_results.get("summarize_for_ehr")
        if not isinstance(created, dict):
            raise RuntimeError("draft-creation setup result is unavailable")
        draft_id = created.get("draft_id")
        patient_id = created.get("patient_id")
        if (
            created.get("status") != "AWAITING_REVIEW"
            or not isinstance(draft_id, str)
            or not isinstance(patient_id, str)
        ):
            raise RuntimeError("draft-creation result is not an awaiting-review draft")

        snapshot = (
            setup_results.get("get_occiai_state_summary")
            if state_after_creation_is_declared
            else None
        )
        if snapshot is None:
            observed = bridge(
                {
                    "action": "call",
                    "server_url": target_url,
                    "operation": "get_occiai_state_summary",
                    "arguments": {},
                }
            )
            native_target_calls.append(
                {
                    "category": "post_setup_state_verification",
                    "operation": "get_occiai_state_summary",
                    "arguments": {},
                    "native_result": observed.get("native"),
                }
            )
            if observed.get("is_error"):
                raise RuntimeError("MiniAgents state-summary read failed")
            snapshot = observed.get("value")
        if not isinstance(snapshot, dict):
            raise RuntimeError("MiniAgents state summary is not an object")
        drafts = snapshot.get("ehr_drafts", [])
        matching = (
            next(
                (
                    item
                    for item in drafts
                    if isinstance(item, dict) and item.get("draft_id") == draft_id
                ),
                None,
            )
            if isinstance(drafts, list)
            else None
        )
        state_verification.update(
            {
                "operation": "get_occiai_state_summary",
                "source": (
                    "declared_setup"
                    if state_after_creation_is_declared
                    else "post_setup_read"
                ),
                "session_id": snapshot.get("session_id"),
                "authenticated_patient_id": snapshot.get("authenticated_patient_id"),
                "setup_draft_id": draft_id,
                "setup_patient_id": patient_id,
                "matching_draft": matching,
                "status": "verified"
                if (
                    isinstance(snapshot.get("session_id"), str)
                    and snapshot.get("authenticated_patient_id") == patient_id
                    and isinstance(matching, dict)
                    and matching.get("patient_id") == patient_id
                    and matching.get("status") == "AWAITING_REVIEW"
                )
                else "mismatch",
            }
        )
        if state_verification["status"] != "verified":
            raise RuntimeError("same-session draft persistence check failed")

        tools = discovery["generation_transport"]
        child_request = {
            "garak_checkout": str(args.garak_checkout),
            "model": model,
            "model_url": kwargs["model_url"],
            "target_url": target_url,
            "tools": tools,
            "stimulus": kwargs["stimulus"],
            "max_output_tokens": GENERATION_MAX_OUTPUT_TOKENS,
            "timeout_seconds": GENERATION_TIMEOUT_SECONDS,
        }
        protocol, status = _run_protocol_child(
            [str(args.garak_python), str(Path(__file__).resolve()), "--garak-helper"],
            child_request,
            cwd=ROOT,
            env=_child_environment(profile["api_key"]),
            timeout=GENERATION_PROCESS_TIMEOUT_SECONDS,
            capture_dir=capture_dir,
            prefix="garak",
        )
        generation_capture.update(protocol)
        generation_capture["child_status"] = status
        if protocol.get("provider_request_count") != 1:
            raise RuntimeError("Garak did not capture exactly one Responses request")
        if (
            protocol.get("generation_error_type")
            or protocol.get("response_status") != "completed"
        ):
            raise RuntimeError("Garak generation response did not complete")
        messages = protocol.get("messages")
        if not isinstance(messages, list):
            raise RuntimeError("Garak message capture was not a list")
        calls = protocol.get("tool_calls", [])
        if not isinstance(calls, list):
            raise RuntimeError("Garak tool-call capture was not a list")
        return {
            "messages": messages,
            "tool_calls": calls,
            "tool_calls_capture": protocol.get("tool_calls_capture"),
            "transport": {
                "client": "pinned-garak-openai-responses",
                "garak_revision": PINNED_GARAK_REVISION,
                "gateway_responses_request_count": 1,
                "provider_request_count": 1,
                "sdk_retries": 0,
                "garak_retries": 0,
                "max_output_tokens": GENERATION_MAX_OUTPUT_TOKENS,
                "timeout_seconds": GENERATION_TIMEOUT_SECONDS,
            },
            "snapshots": {"post_setup_target_state": snapshot},
            "user_text": kwargs["stimulus"]["user_text"],
            "history": kwargs["stimulus"].get("history", []),
        }

    env = {
        "OPENAI_BASE_URL": profile["base_url"],
        "OPENAI_API_KEY": profile["api_key"],
        "MODEL_ID": model,
    }
    _write_private_json(run_dir / "preflight.json", preflight)
    _write_private_json(
        run_dir / "launcher-controls.json",
        {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "package_digest": package.digest,
            "detector_sha256": package.detector_digest,
            "profile_alias": args.profile,
            "model": model,
            "garak_revision": PINNED_GARAK_REVISION,
            "generation": {
                "max_dispatches": MAX_GENERATIONS,
                "retries": 0,
                "timeout_seconds": GENERATION_TIMEOUT_SECONDS,
                "process_timeout_seconds": GENERATION_PROCESS_TIMEOUT_SECONDS,
                "max_output_tokens": GENERATION_MAX_OUTPUT_TOKENS,
                "allowed_tools": ["commit_to_ehr", "get_occiai_state_summary"],
            },
            "setup": {
                "declared_steps": len(setup),
                "post_creation_state_read": not state_after_creation_is_declared,
                "maximum_combined_setup_and_state_reads": MAX_SETUP_AND_STATE_READS,
            },
            "semantic_judge_dispatches": 0,
            "ports": {"gateway": 8321, "target": 8892},
            "secret_values_persisted": False,
        },
    )
    result = execute_o03_frozen_live_package(
        package,
        setup_dispatch=setup_dispatch,
        generation_dispatch=generation_dispatch,
        receipt_path=receipt_path,
        state_dir=state_dir,
        target_root=args.target_root,
        gateway_config_source=args.target_root / "ogx-config.yaml",
        environment=env,
        target_url=target_url,
        model_url=model_url,
        model=model,
        discovery_records=[],
        service_revisions={
            "producer": _revision(ROOT),
            "mini_agents": _revision(args.target_root),
            "garak": PINNED_GARAK_REVISION,
        },
    )
    receipt = result.receipt
    if discovery:
        receipt["discovery_ledger"]["dispatches"].append(
            {
                "category": "discovery",
                "sequence": 1,
                "operation": "tools/list",
                "status": "completed",
                "observed_tools": discovery["tools"],
                "package_contract_comparisons": discovery[
                    "package_contract_comparisons"
                ],
                "state_summary_contract": discovery["state_summary_contract"],
                "generation_allowed_tools": discovery["generation_transport"][0][
                    "allowed_tools"
                ],
            }
        )
        receipt["discovery_ledger"]["total"] = 1
        receipt["totals"]["discovery"] = 1
    if state_verification:
        receipt["post_setup_state_verification"] = state_verification
        if not state_after_creation_is_declared:
            ledger = receipt["setup_capture_ledger"]
            ledger["dispatches"].append(
                {
                    "category": "setup_capture",
                    "sequence": len(ledger["dispatches"]) + 1,
                    "operation": "get_occiai_state_summary",
                    "status": "completed",
                    "retries": 0,
                    "result": state_verification,
                    "verification_only": True,
                }
            )
            ledger["total"] = len(ledger["dispatches"])
            receipt["ledgers"]["setup_capture"] = ledger
            receipt["totals"]["setup_capture"] = ledger["total"]
            receipt["live_dispatch"]["limits"]["setup_capture"] = ledger["total"]
    receipt["native_target_calls"] = native_target_calls
    generated_calls = generation_capture.get("tool_calls", [])
    if not isinstance(generated_calls, list):
        generated_calls = []
    generated_state_reads = [
        call
        for call in generated_calls
        if isinstance(call, dict) and call.get("name") == "get_occiai_state_summary"
    ]
    generated_commits = [
        call
        for call in generated_calls
        if isinstance(call, dict) and call.get("name") == "commit_to_ehr"
    ]
    setup_call_count = receipt.get("setup_capture_ledger", {}).get("total", 0)
    receipt["target_operation_totals"] = {
        "setup_and_verification_calls": setup_call_count,
        "generation_state_reads": len(generated_state_reads),
        "generation_commit_attempts": len(generated_commits),
        "generation_target_tool_calls": len(generated_calls),
        "total_target_tool_calls": setup_call_count + len(generated_calls),
    }
    receipt["generation_native_exchange"] = generation_capture.get(
        "native_exchange", []
    )
    receipt["post_setup_state_verification"] = state_verification or receipt.get(
        "post_setup_state_verification"
    )
    capture_files: dict[str, str] = {}
    for name in (
        "garak-stdout.bin",
        "garak-stderr.bin",
        "child-status.json",
        "garak-protocol.json",
    ):
        path = capture_dir / name
        if path.is_file():
            capture_files[f"generation_{name.replace('-', '_')}"] = str(path)
    for record in mcp_capture_records:
        call_dir = Path(record["capture_dir"])
        for name in (
            "mcp-stdout.bin",
            "mcp-stderr.bin",
            "child-status.json",
            "mcp-protocol.json",
        ):
            path = call_dir / name
            if path.is_file():
                capture_files[f"mcp_{record['sequence']}_{name.replace('-', '_')}"] = (
                    str(path)
                )
    receipt["launcher_capture_files"] = capture_files
    receipt["mcp_helper_calls"] = mcp_capture_records
    receipt["launcher_controls"] = {
        "scenario": "O03",
        "package_digest": package.digest,
        "detector_sha256": package.detector_digest,
        "setup_calls_limit": MAX_SETUP_AND_STATE_READS,
        "generation_calls_limit": MAX_GENERATIONS,
        "semantic_judge_calls_limit": 0,
        "setup_plus_post_setup_reads": len(setup)
        + (0 if state_after_creation_is_declared else 1),
        "generation_read_tool": "get_occiai_state_summary",
        "generation_write_tool": "commit_to_ehr",
        "no_reset_between_setup_and_generation": True,
        "rendered_stimulus_source": "frozen_runtime receipt.stimulus",
        "profile_name": args.profile,
        "model": model,
        "garak_revision": PINNED_GARAK_REVISION,
        "generation_retries": 0,
    }
    _write_private_json(receipt_path, receipt)
    print(
        json.dumps(
            {
                "status": result.status.value,
                "receipt": str(receipt_path),
                "run_dir": str(run_dir),
            },
            sort_keys=True,
        )
    )
    return 0 if result.status.value == "completed" else 1


def _arguments() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--expected-package-digest", required=True)
    parser.add_argument("--expected-detector-digest", required=True)
    parser.add_argument("--profile", default="gemma4-oc")
    parser.add_argument("--profiles-file", type=Path, default=DEFAULT_PROFILES_FILE)
    parser.add_argument("--target-root", type=Path, default=DEFAULT_TARGET_ROOT)
    parser.add_argument(
        "--target-python",
        type=Path,
        default=DEFAULT_TARGET_ROOT / ".venv" / "bin" / "python",
    )
    parser.add_argument("--garak-checkout", type=Path, default=GARAK_CHECKOUT)
    parser.add_argument("--garak-python", type=Path, default=GARAK_PYTHON)
    parser.add_argument("--run-dir", type=Path, required=True)
    return parser


def main() -> int:
    if "--mcp-helper" in sys.argv:
        return _mcp_helper_main()
    if "--garak-helper" in sys.argv:
        return _garak_helper_main()
    old_umask = os.umask(0o077)
    try:
        return _run(_arguments().parse_args())
    except Exception as exc:
        print(f"O03 execution failed: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    finally:
        os.umask(old_umask)


if __name__ == "__main__":
    raise SystemExit(main())
