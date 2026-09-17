"""JSONL call logging for the STPA pipeline — clean copy.

The STPA pipeline owns this append-only call-log boundary.
Appends JSONL entries with stage/step/slot_id/scenario_id metadata.
No manifest coupling.

Call log entry format (Section 6 of the STPA-Sec foundation spec):

    {
      "stage": "stage_2",
      "step": "call_2a_responsibilities",
      "slot_id": null,
      "scenario_id": null,
      "system_prompt_hash": "sha256...",
      "user_prompt_hash": "sha256...",
      "model": "claude-sonnet-4-...",
      "prompt_tokens": 4500,
      "completion_tokens": 1200,
      "duration_ms": 8500,
      "timestamp": "2026-08-08T12:34:56Z",
      "success": true
    }
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping

_call_log_lock = threading.Lock()
_SENSITIVE_ERROR = re.compile(
    r"(?i)\b(?:api[-_ ]?key|token|password|authorization)\s*[:=]\s*[^\s,;]+"
)
_SENSITIVE_CONTROL_KEY = re.compile(
    r"(?i)(?:api[-_ ]?key|token|password|authorization|secret|credential|url|endpoint)"
)
_URL_VALUE = re.compile(r"https?://[^\s\"')]+", re.IGNORECASE)


def _sha256(text: str) -> str:
    """Return SHA-256 hex digest of *text*."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _jsonable(value: Any) -> Any:
    """Return a stable JSON-compatible value for evidence pins."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


def _content_pin(value: Any, frame: str) -> str:
    """Pin one evidence value without retaining a second serialized copy."""
    payload = json.dumps(
        _jsonable(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return _sha256(f"{frame}\n{payload}")


def _safe_error(error: str) -> str:
    """Keep lifecycle context while excluding connection material."""
    detail = re.sub(r"https?://[^\s\"')]+", "[redacted-url]", str(error))
    detail = _SENSITIVE_ERROR.sub("[redacted-secret]", detail)
    detail = re.sub(r"(?i)\bbearer\s+\S+", "Bearer [redacted]", detail)
    detail = re.sub(r"(?i)\bsk-[A-Za-z0-9_-]+\b", "[redacted-key]", detail)
    return detail[:800]


def _safe_controls(value: Mapping[str, Any]) -> dict[str, Any]:
    """Retain provider controls while removing sensitive control values."""

    def safe_value(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {
                str(key): "[redacted]"
                if _SENSITIVE_CONTROL_KEY.search(str(key))
                else safe_value(nested)
                for key, nested in item.items()
            }
        if isinstance(item, (list, tuple)):
            return [safe_value(nested) for nested in item]
        if isinstance(item, str):
            return _URL_VALUE.sub("[redacted-url]", item)
        return _jsonable(item)

    return {
        str(key): "[redacted]"
        if _SENSITIVE_CONTROL_KEY.search(str(key))
        else safe_value(item)
        for key, item in value.items()
    }


def _usage_record(
    prompt_tokens: int | None,
    completion_tokens: int | None,
) -> dict[str, Any]:
    """Build truthful usage evidence for one provider request."""
    available = prompt_tokens is not None and completion_tokens is not None
    return {
        "status": "reported" if available else "unavailable",
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
    }


def _lifecycle_fields(
    *,
    success: bool,
    provider_response_received: bool | None,
    draft_parsed: bool | None,
    semantic_validation_passed: bool | None,
    compiled: bool | None,
) -> dict[str, Any]:
    """Build lifecycle outcomes without treating failure as missing evidence."""
    return {
        "provider_response_received": (
            success
            if provider_response_received is None
            else provider_response_received
        ),
        "draft_parsed": success if draft_parsed is None else draft_parsed,
        "semantic_validation_passed": (
            success
            if semantic_validation_passed is None
            else semantic_validation_passed
        ),
        "compiled": success if compiled is None else compiled,
    }


def _attempt_fields(
    *,
    stage: str,
    step: str,
    slot_id: str | None,
    scenario_id: str | None,
    attempt_id: str | None,
    attempt_number: int | None,
    request_variant_digest: str | None,
    request_controls: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """Build explicit attempt identity and nonsecret request controls."""
    number = attempt_number or 1
    variant_digest = request_variant_digest or _sha256(
        json.dumps(
            {
                "stage": stage,
                "step": step,
                "slot_id": slot_id,
                "scenario_id": scenario_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return {
        "attempt_id": attempt_id
        or f"{stage}:{step}:{slot_id or '-'}:{scenario_id or '-'}:"
        f"{variant_digest[:16]}:{number}",
        "attempt_number": number,
        "request_controls": _safe_controls(request_controls or {}),
    }


def _response_fields(
    *,
    raw_response: Any | None,
    cleaned_response: Any | None,
    cleanup_transformations: tuple[Mapping[str, Any], ...],
) -> dict[str, Any]:
    """Build raw/cleaned response evidence and ordered cleanup records."""
    fields: dict[str, Any] = {
        "cleanup_transformations": [
            dict(transformation) for transformation in cleanup_transformations
        ]
    }
    for name, value, frame in (
        ("raw_response", raw_response, "stpa-provider-raw-response-v1"),
        ("cleaned_response", cleaned_response, "stpa-provider-cleaned-response-v1"),
    ):
        fields[name] = _jsonable(value) if value is not None else None
        fields[f"{name}_pin"] = (
            _content_pin(value, frame) if value is not None else None
        )
    return fields


def _optional_fields(
    *,
    failure_class: str | None,
    response_content: str | None,
    error: str | None,
) -> dict[str, Any]:
    """Build optional lifecycle details without dropping explicit failures."""
    fields: dict[str, Any] = {}
    if failure_class is not None:
        fields["failure_class"] = failure_class
    if response_content is not None:
        fields["response_content"] = response_content
    if error is not None:
        fields["error"] = _safe_error(error)
    return fields


def make_call_log_entry(
    *,
    stage: str,
    step: str,
    model: str,
    system_prompt: str = "",
    user_prompt: str = "",
    prompt_tokens: int | None = None,
    completion_tokens: int | None = None,
    duration_ms: int = 0,
    success: bool = True,
    error: str | None = None,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    timestamp: str | None = None,
    response_content: str | None = None,
    raw_response: Any | None = None,
    cleaned_response: Any | None = None,
    cleanup_transformations: tuple[Mapping[str, Any], ...] = (),
    attempt_id: str | None = None,
    attempt_number: int | None = None,
    failure_class: str | None = None,
    request_controls: Mapping[str, Any] | None = None,
    provider_response_received: bool | None = None,
    draft_parsed: bool | None = None,
    semantic_validation_passed: bool | None = None,
    compiled: bool | None = None,
    published: bool = False,
    terminal_error_codes: tuple[str, ...] = (),
    prompt_template_hashes: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Build a call-log entry dict following the STPA format (Section 6).

    Args:
        stage: Pipeline stage (e.g. ``stage_2``, ``stage_6_narrative``).
        step: Sub-step within the stage (e.g. ``call_1_requirements``).
        model: LLM model name.
        system_prompt: System prompt text (hashed and stored full in the entry).
        user_prompt: User prompt text (hashed and stored full in the entry).
        prompt_tokens: Prompt tokens consumed, or ``None`` when unavailable.
        completion_tokens: Completion tokens generated, or ``None`` when
            unavailable.
        duration_ms: Wall-clock duration in milliseconds.
        success: Whether the call succeeded.
        error: Optional error message for failed calls.
        slot_id: Stage 3 slot ID (e.g. ``RESP-1:CA-1-1:TYPE-1``), or None.
        scenario_id: Stage 5/6 scenario ID (e.g. ``SCN-001``), or None.
        timestamp: ISO 8601 timestamp; defaults to current UTC time.
        response_content: Optional full response content (string representation).

    Returns:
        A dict suitable for JSONL serialization.
    """
    _timestamp = timestamp or datetime.now(timezone.utc).isoformat()
    entry: dict[str, Any] = {
        "stage": stage,
        "step": step,
        "slot_id": slot_id,
        "scenario_id": scenario_id,
        "system_prompt_hash": _sha256(system_prompt) if system_prompt else "",
        "user_prompt_hash": _sha256(user_prompt) if user_prompt else "",
        "system_prompt_text": system_prompt,
        "user_prompt_text": user_prompt,
        "model": model,
        "call_category": "producer_provider",
        "provider_request": True,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "usage": _usage_record(prompt_tokens, completion_tokens),
        "duration_ms": duration_ms,
        "timestamp": _timestamp,
        "success": success,
        "published": published,
        "terminal_error_codes": list(terminal_error_codes),
        "prompt_template_hashes": dict(sorted((prompt_template_hashes or {}).items())),
    }
    entry.update(
        _lifecycle_fields(
            success=success,
            provider_response_received=provider_response_received,
            draft_parsed=draft_parsed,
            semantic_validation_passed=semantic_validation_passed,
            compiled=compiled,
        )
    )
    entry.update(
        _attempt_fields(
            stage=stage,
            step=step,
            slot_id=slot_id,
            scenario_id=scenario_id,
            attempt_id=attempt_id,
            attempt_number=attempt_number,
            request_variant_digest=_sha256(
                json.dumps(
                    {
                        "stage": stage,
                        "step": step,
                        "slot_id": slot_id,
                        "scenario_id": scenario_id,
                        "system_prompt_hash": entry["system_prompt_hash"],
                        "user_prompt_hash": entry["user_prompt_hash"],
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                )
            ),
            request_controls=request_controls,
        )
    )
    entry.update(
        _response_fields(
            raw_response=raw_response,
            cleaned_response=cleaned_response,
            cleanup_transformations=cleanup_transformations,
        )
    )
    entry.update(
        _optional_fields(
            failure_class=failure_class,
            response_content=response_content,
            error=error,
        )
    )
    return entry


def append_call_log(entries: list[dict], run_dir: Path) -> None:
    """Append call-log entries to ``calls.jsonl`` in *run_dir*.

    If *entries* is empty, no file is created. The directory is created
    if it does not exist.
    """
    if not entries:
        return
    with _call_log_lock:
        run_dir.mkdir(parents=True, exist_ok=True)
        calls_path = run_dir / "calls.jsonl"
        payload = "".join(
            f"{json.dumps(entry, ensure_ascii=False)}\n" for entry in entries
        )
        with calls_path.open("a", encoding="utf-8") as fh:
            fh.write(payload)


def mark_call_published(run_dir: Path, stage: str, step: str) -> None:
    """Mark the latest matching validated call as compiled and published."""
    calls_path = Path(run_dir) / "calls.jsonl"
    with _call_log_lock:
        entries = _load_call_entries(calls_path)
        match = _latest_validated_call(entries, stage=stage, step=step)
        match["compiled"] = True
        match["published"] = True
        _replace_call_entries(calls_path, entries)


def _load_call_entries(calls_path: Path) -> list[dict[str, Any]]:
    """Load an existing call log for a lifecycle transition."""
    if not calls_path.exists():
        raise ValueError("cannot publish lifecycle for a missing call log")
    return [
        json.loads(line)
        for line in calls_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _latest_validated_call(
    entries: list[dict[str, Any]], *, stage: str, step: str
) -> dict[str, Any]:
    """Resolve the latest exact call and require semantic validation."""
    matches = (
        entry
        for entry in reversed(entries)
        if entry.get("stage") == stage and entry.get("step") == step
    )
    match = next(matches, None)
    if match is None or not match.get("semantic_validation_passed", False):
        raise ValueError("cannot publish a call without semantic validation")
    return match


def _replace_call_entries(calls_path: Path, entries: list[dict[str, Any]]) -> None:
    """Atomically replace a call log after a lifecycle transition."""
    temporary = calls_path.with_suffix(".jsonl.tmp")
    temporary.write_text(
        "".join(f"{json.dumps(entry, ensure_ascii=False)}\n" for entry in entries),
        encoding="utf-8",
    )
    temporary.replace(calls_path)
