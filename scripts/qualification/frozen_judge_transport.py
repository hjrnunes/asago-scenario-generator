"""Raw-preserving transport for one strict semantic-judge request.

This module owns provider transport evidence only. JSON parsing and frozen
judge validation remain separate so malformed provider output cannot become a
semantic ``unresolved`` verdict.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any, Callable


CompletionCreate = Callable[..., Any]
PersistRecord = Callable[[dict[str, Any]], None]


@dataclass(frozen=True)
class JudgeTransportResult:
    """The provider result after raw capture and optional JSON parsing."""

    record: dict[str, Any]
    raw_response: bytes
    parsed: Any
    status: str
    failure: str | None = None

    @property
    def response_received(self) -> bool:
        """Return whether the provider returned a response object."""

        return self.status in {"response_received", "parse_failed"}

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-safe transport record with raw bytes preserved."""

        value = {
            **self.record,
            "status": self.status,
            "failure": self.failure,
            "raw_response_base64": base64.b64encode(self.raw_response).decode(
                "ascii"
            ),
            "raw_response_sha256": hashlib.sha256(self.raw_response).hexdigest(),
            "raw_response_byte_length": len(self.raw_response),
            "parsed": self.parsed,
        }
        try:
            value["raw_response"] = self.raw_response.decode("utf-8")
        except UnicodeDecodeError:
            value["raw_response"] = None
        return value


def request_judge(
    system_prompt: str,
    user_prompt: str,
    *,
    model: str,
    completion_create: CompletionCreate,
    persist: PersistRecord | None = None,
    temperature: float = 0.0,
    enable_thinking: bool = False,
    max_completion_tokens: int = 512,
    timeout: float = 180.0,
    max_retries: int = 0,
) -> JudgeTransportResult:
    """Call one completion, persist raw evidence, then parse its JSON content.

    ``persist`` runs after a response or transport exception is normalized into
    a non-secret record and before this function attempts JSON parsing.
    """

    controls = {
        "temperature": temperature,
        "thinking_enabled": enable_thinking,
        "max_completion_tokens": max_completion_tokens,
        "timeout_seconds": timeout,
        "max_retries": max_retries,
    }
    started = time.perf_counter_ns()
    response: Any = None
    transport_failure: str | None = None
    try:
        response = completion_create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_completion_tokens=max_completion_tokens,
            timeout=timeout,
            max_retries=max_retries,
            extra_body={
                "chat_template_kwargs": {"enable_thinking": enable_thinking}
            },
            response_format={"type": "json_object"},
        )
    except Exception as exc:  # pragma: no cover - exercised through fake transport
        transport_failure = f"{type(exc).__name__}: {exc}"

    elapsed_ms = (time.perf_counter_ns() - started) // 1_000_000
    raw_response = _response_content_bytes(response)
    record: dict[str, Any] = {
        "system_prompt": system_prompt,
        "user_prompt": user_prompt,
        "controls": controls,
        "elapsed_ms": elapsed_ms,
    }
    for key, value in (
        ("response_id", _response_id(response)),
        ("finish_reason", _finish_reason(response)),
        ("usage", _usage(response)),
    ):
        if value is not None:
            record[key] = value
    transport_result = JudgeTransportResult(
        record=record,
        raw_response=raw_response,
        parsed=None,
        status="transport_failed" if transport_failure else "response_received",
        failure=transport_failure,
    )
    if persist is not None:
        persist(transport_result.as_dict())
    if transport_failure is not None:
        return transport_result

    try:
        parsed = json.loads(raw_response.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return JudgeTransportResult(
            record=record,
            raw_response=raw_response,
            parsed=None,
            status="parse_failed",
            failure=f"{type(exc).__name__}: {exc}",
        )
    return JudgeTransportResult(
        record=record,
        raw_response=raw_response,
        parsed=parsed,
        status="parsed",
    )


def _response_choice(response: Any) -> Any | None:
    choices = getattr(response, "choices", None)
    if not choices:
        return None
    try:
        return choices[0]
    except (IndexError, KeyError, TypeError):
        return None


def _response_content_bytes(response: Any) -> bytes:
    choice = _response_choice(response)
    message = getattr(choice, "message", None) if choice is not None else None
    content = getattr(message, "content", None)
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    if content is None:
        return b""
    return json.dumps(content, ensure_ascii=False, separators=(",", ":")).encode(
        "utf-8"
    )


def _response_id(response: Any) -> str | None:
    value = getattr(response, "id", None)
    return value if isinstance(value, str) and value else None


def _finish_reason(response: Any) -> str | None:
    choice = _response_choice(response)
    value = getattr(choice, "finish_reason", None) if choice is not None else None
    return value if isinstance(value, str) and value else None


def _usage(response: Any) -> dict[str, Any] | None:
    usage = getattr(response, "usage", None)
    if usage is None:
        return None
    if isinstance(usage, dict):
        return dict(usage)
    if hasattr(usage, "model_dump"):
        value = usage.model_dump()
        return value if isinstance(value, dict) else None
    fields = {}
    for name in ("prompt_tokens", "completion_tokens", "total_tokens"):
        value = getattr(usage, name, None)
        if value is not None:
            fields[name] = value
    return fields or None


__all__ = ["JudgeTransportResult", "request_judge"]
