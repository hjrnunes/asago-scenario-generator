"""JSONL call logging for the STPA pipeline — clean copy.

Simplified from ``asago_scenario_generator.pipeline.io.write_pipeline_call_log``.
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
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

_call_log_lock = threading.Lock()


def _sha256(text: str) -> str:
    """Return SHA-256 hex digest of *text*."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def make_call_log_entry(
    *,
    stage: str,
    step: str,
    model: str,
    system_prompt: str = "",
    user_prompt: str = "",
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    duration_ms: int = 0,
    success: bool = True,
    error: str | None = None,
    slot_id: str | None = None,
    scenario_id: str | None = None,
    timestamp: str | None = None,
    response_content: str | None = None,
) -> dict[str, Any]:
    """Build a call-log entry dict following the STPA format (Section 6).

    Args:
        stage: Pipeline stage (e.g. ``stage_2``, ``stage_6_narrative``).
        step: Sub-step within the stage (e.g. ``call_1_requirements``).
        model: LLM model name.
        system_prompt: System prompt text (hashed and stored full in the entry).
        user_prompt: User prompt text (hashed and stored full in the entry).
        prompt_tokens: Prompt tokens consumed.
        completion_tokens: Completion tokens generated.
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
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "duration_ms": duration_ms,
        "timestamp": _timestamp,
        "success": success,
    }
    if response_content is not None:
        entry["response_content"] = response_content
    if error is not None:
        entry["error"] = error
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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-09T17:32:48Z","module_hash":"bdd4259849dc001e9ce50ac9e05f4af149ab09e2c47936e3cc4e6651abb12935","functions":[{"id":"func/_sha256","name":"_sha256","line":37,"end_line":39,"hash":"67d51b4b362a429bf5d02c7d0ff6e4f6338360ab956b700e80bf057a0e9a9443"},{"id":"func/make_call_log_entry","name":"make_call_log_entry","line":42,"end_line":101,"hash":"853111b20a56322817d78971f08c532b5013bf36f41b60205fb169e0d396c09d"},{"id":"func/append_call_log","name":"append_call_log","line":104,"end_line":117,"hash":"5c770898b5ddec662466b41f29ab930af8034546067a37e0d08aa4c36b37bad2"}]}
# mutate4py-manifest-end
