#!/usr/bin/env python3
"""Child-process edges shared by the fresh-package live launcher.

The launcher runs this file twice as a standalone script: once under the
target's Python (``--mcp-helper``) for MCP setup calls, and once under the
pinned Garak Python (``--garak-helper``) for the single generation. Top-level
imports therefore stay in the standard library; ``mcp``, ``garak``, and
``openai`` load only inside the helper that needs them.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

PINNED_GARAK_REVISION = "06aba1a2c9b142d561eeeff08dfaffcbe77487c3"
GENERATION_MODEL = "gemma-4-26b-a4b-it"
GENERATION_MAX_OUTPUT_TOKENS = 4096
GENERATION_TIMEOUT_SECONDS = 180.0
GENERATION_PROCESS_TIMEOUT_SECONDS = 210.0
JUDGE_MAX_COMPLETION_TOKENS = 512
JUDGE_TIMEOUT_SECONDS = 180.0
MCP_PROCESS_TIMEOUT_SECONDS = 45.0


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n"
    ).encode("utf-8")


def write_private_bytes(path: Path, content: bytes) -> None:
    """Atomically write owner-only bytes inside an owner-only directory."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
        os.chmod(path, 0o600)
    finally:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass


def write_private_json(path: Path, value: Any) -> None:
    """Atomically write one owner-only JSON document."""

    write_private_bytes(path, _json_bytes(value))


def _as_bytes(value: str | bytes | None) -> bytes:
    if value is None:
        return b""
    return value if isinstance(value, bytes) else value.encode("utf-8")


def persist_child_output(
    capture_dir: Path,
    *,
    stdout: str | bytes | None,
    stderr: str | bytes | None,
    returncode: int | None,
    status: str,
    failure_type: str | None = None,
    prefix: str = "garak",
) -> dict[str, Any]:
    """Persist both protocol streams and exit status before any parse or raise."""

    stdout_bytes = _as_bytes(stdout)
    stderr_bytes = _as_bytes(stderr)
    stdout_path = capture_dir / f"{prefix}-stdout.bin"
    stderr_path = capture_dir / f"{prefix}-stderr.bin"
    write_private_bytes(stdout_path, stdout_bytes)
    write_private_bytes(stderr_path, stderr_bytes)
    record = {
        "status": status,
        "returncode": returncode,
        "failure_type": failure_type,
        "stdout": {
            "path": str(stdout_path),
            "sha256": hashlib.sha256(stdout_bytes).hexdigest(),
            "bytes": len(stdout_bytes),
        },
        "stderr": {
            "path": str(stderr_path),
            "sha256": hashlib.sha256(stderr_bytes).hexdigest(),
            "bytes": len(stderr_bytes),
        },
    }
    write_private_json(capture_dir / "child-status.json", record)
    return record


def parse_child_protocol(
    capture_dir: Path, capture: dict[str, Any], *, prefix: str = "garak"
) -> dict[str, Any]:
    """Parse only after stdout, stderr, and exit status are safely recorded."""

    if capture["status"] == "timed_out":
        raise RuntimeError(f"{prefix} subprocess timed out; no retry attempted")
    if capture["returncode"] != 0:
        raise RuntimeError(f"{prefix} subprocess failed; no retry attempted")
    stdout_path = Path(capture["stdout"]["path"])
    try:
        value = json.loads(stdout_path.read_text(encoding="utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"{prefix} stdout was not one JSON protocol object") from exc
    if not isinstance(value, dict):
        raise RuntimeError(f"{prefix} protocol response was not an object")
    write_private_json(capture_dir / f"{prefix}-protocol.json", value)
    return value


def run_protocol_child(
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
        persist_child_output(
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
        persist_child_output(
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

    capture = persist_child_output(
        capture_dir,
        stdout=child.stdout,
        stderr=child.stderr,
        returncode=child.returncode,
        status="completed" if child.returncode == 0 else "failed",
        prefix=prefix,
    )
    protocol = parse_child_protocol(capture_dir, capture, prefix=prefix)
    return protocol, capture


def child_environment(api_key: str | None = None) -> dict[str, str]:
    """Return the parent environment without inherited API credentials."""

    secret_names = {"openai_api_key", "api_key", "authorization"}
    environment = {
        key: value
        for key, value in os.environ.items()
        if key.lower() not in secret_names and not key.lower().endswith("_api_key")
    }
    if api_key is not None:
        environment["OPENAI_API_KEY"] = api_key
    return environment


def git_revision(repository: Path) -> str | None:
    """Return the checked-out commit of one repository, or None."""

    try:
        result = subprocess.run(
            ["git", "-C", str(repository), "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return result.stdout.strip() if result.returncode == 0 else None


def validate_allowed_tool_calls(
    calls: Any, allowed_tools: list[str]
) -> list[dict[str, Any]]:
    """Reject a capture that names a tool outside the exposed allowlist."""

    if not isinstance(calls, list):
        raise RuntimeError("Garak tool-call capture was not a list")
    if any(
        not isinstance(call, dict)
        or not isinstance(call.get("name"), str)
        or call["name"] not in allowed_tools
        for call in calls
    ):
        raise RuntimeError("Garak captured a tool outside the exposed allowlist")
    return calls


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
            if bool(native.get("isError", False)):
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


def garak_helper(request: dict[str, Any]) -> dict[str, Any]:
    """Run one pinned-Garak Responses generation and capture its native exchange."""

    checkout = Path(request["garak_checkout"])
    if git_revision(checkout) != PINNED_GARAK_REVISION:
        raise ValueError("pinned Garak revision mismatch")
    if str(checkout) not in sys.path:
        sys.path.insert(0, str(checkout))
    from garak import _config
    from garak.attempt import Conversation
    from garak.generators.openai import OpenAIResponsesGenerator
    import openai

    _config.load_config()
    _config.system.parallel_attempts = 1
    _config.run.generations = 1
    generator = OpenAIResponsesGenerator(
        name=request["model"],
        config_root={
            "generators": {
                "openai": {
                    "OpenAIResponsesGenerator": {
                        "uri": request["model_url"],
                        "tools": request["tools"],
                        "max_tokens": request["max_output_tokens"],
                        "extra_params": {"tool_choice": "auto"},
                    }
                }
            }
        },
    )
    generator.client = openai.OpenAI(
        api_key=os.environ.get("OPENAI_API_KEY", "unused"),
        base_url=request["model_url"],
        max_retries=0,
        timeout=request["timeout_seconds"],
    )
    generator.generator = generator.client.responses
    native_exchange: list[dict[str, Any]] = []
    original_create = generator.client.responses.create

    def capture_create(**kwargs: Any) -> Any:
        item: dict[str, Any] = {"request": kwargs, "response": None}
        native_exchange.append(item)
        try:
            response = original_create(**kwargs)
        except Exception as exc:
            item.update({"status": "failed", "error_type": type(exc).__name__})
            raise
        item.update(
            {
                "status": "completed",
                "response": response.model_dump(mode="json", by_alias=True),
            }
        )
        return response

    generator.client.responses.create = capture_create
    turns = list(request["stimulus"].get("history", []))
    turns.append({"role": "user", "content": request["stimulus"]["user_text"]})
    conversation = Conversation.from_openai(turns)
    call_error = None
    try:
        messages = list(
            OpenAIResponsesGenerator._call_model.__wrapped__(generator, conversation, 1)
        )
    except Exception as exc:
        messages = []
        call_error = type(exc).__name__
    message = messages[0] if messages else None
    notes = dict(getattr(message, "notes", {}) or {}) if message is not None else {}
    tool_calls = list(notes.get("tool_calls", []))
    if len(native_exchange) != 1:
        call_error = call_error or "ResponsesRequestCountMismatch"
    elif native_exchange[0].get("status") != "completed":
        call_error = call_error or native_exchange[0].get(
            "error_type", "ResponsesRequestFailed"
        )
    response_status = (
        native_exchange[0].get("response", {}).get("status")
        if native_exchange and isinstance(native_exchange[0].get("response"), dict)
        else None
    )
    if response_status != "completed":
        call_error = call_error or "ResponsesNotCompleted"
    return {
        "messages": [
            {
                "role": "assistant",
                "content": getattr(message, "text", None),
                "notes": notes,
                "raw_response": native_exchange[0]["response"]
                if native_exchange
                else None,
            }
        ]
        if message is not None
        else [],
        "tool_calls": tool_calls,
        "tool_calls_capture": {
            "available": bool(native_exchange),
            "complete": (
                call_error is None
                and len(native_exchange) == 1
                and response_status == "completed"
            ),
        },
        "native_exchange": native_exchange,
        "garak_revision": PINNED_GARAK_REVISION,
        "gateway_responses_request_count": len(native_exchange),
        "generation_error_type": call_error,
        "response_status": response_status,
        "controls": {
            "max_output_tokens": request["max_output_tokens"],
            "tool_choice": "auto",
            "provider_timeout_seconds": request["timeout_seconds"],
            "sdk_retries": 0,
            "garak_retries": 0,
            "generations": 1,
        },
    }


def _read_json_stdin() -> dict[str, Any]:
    value = json.load(sys.stdin)
    if not isinstance(value, dict):
        raise ValueError("helper input must be an object")
    return value


def _helper_main(handler: Any) -> int:
    try:
        request = _read_json_stdin()
        # Keep stdout for the single JSON protocol response.
        with contextlib.redirect_stdout(sys.stderr):
            response = handler(request)
        sys.stdout.write(json.dumps(response, ensure_ascii=False) + "\n")
        return 0
    except Exception as exc:
        sys.stdout.write(json.dumps({"error": type(exc).__name__}) + "\n")
        return 2


def main(argv: list[str] | None = None) -> int:
    arguments = sys.argv[1:] if argv is None else argv
    if arguments == ["--mcp-helper"]:
        return _helper_main(lambda request: asyncio.run(_mcp_exchange(request)))
    if arguments == ["--garak-helper"]:
        return _helper_main(garak_helper)
    sys.stderr.write("usage: live_helpers.py --mcp-helper | --garak-helper\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
