"""Pipeline (non-scenario) LLM call log section builder."""

from __future__ import annotations

import json
from typing import Any

from asago_scenario_generator.html_utils import escape_html as _esc
from asago_scenario_generator.report.scenario_common import (
    _usage_call_label,
    _usage_failure_suffix,
    _usage_metrics,
    _usage_summary,
    _usage_totals,
    _usage_warning_html,
)


def _semantic_stage_label(evidence: dict[str, Any], entry: dict[str, Any]) -> str:
    """Human-readable stage label for the semantic draft message."""
    stage = str(evidence.get("stage") or entry.get("call") or "semantic")
    return {
        "actor": "Actor",
        "narrative": "Narrative",
        "tree": "Attack tree",
        "behavior": "Behavior",
    }.get(stage, stage.replace("_", " ").title())


def _semantic_last_result(evidence: dict[str, Any]) -> Any:
    """Return the last attempt result, or None when unavailable."""
    attempts = evidence.get("attempts")
    if isinstance(attempts, list) and attempts and isinstance(attempts[-1], dict):
        return attempts[-1].get("result")
    return None


def _semantic_status_text(
    evidence: dict[str, Any],
    entry: dict[str, Any],
    last_result: Any,
) -> str:
    """Describe the semantic acceptance status of a provider draft."""
    if bool(evidence.get("accepted_draft_digest")) and last_result == "accepted":
        return "Accepted provider semantics"
    failure = str(last_result or entry.get("code") or "failed")
    return f"Rejected: {failure.replace('_', ' ')}"


def _semantic_warning_items(evidence: dict[str, Any]) -> str:
    """Render semantic-evidence warning lines, or '' when absent."""
    warning_items = []
    warnings = evidence.get("warnings")
    if isinstance(warnings, list):
        prefix = "presentation_fallback:"
        for warning in warnings:
            detail = str(warning)
            if detail.startswith(prefix):
                detail = detail[len(prefix) :].strip()
                warning_items.append(
                    f"<div><strong>Presentation fallback used:</strong> {_esc(detail)}</div>"
                )
            else:
                warning_items.append(
                    f"<div><strong>Warning:</strong> {_esc(detail)}</div>"
                )
    return "".join(warning_items)


def _semantic_stage_status_html(entry: dict[str, Any]) -> str:
    """Render accepted provider semantics independently from presentation status."""
    evidence = entry.get("semantic_evidence")
    if not isinstance(evidence, dict):
        return ""

    stage_label = _semantic_stage_label(evidence, entry)
    last_result = _semantic_last_result(evidence)
    status = _semantic_status_text(evidence, entry, last_result)
    warning_items = _semantic_warning_items(evidence)

    return (
        '<div class="warning-banner" role="status">'
        f"<div><strong>{_esc(stage_label)} semantic draft:</strong> {_esc(status)}</div>"
        f"{warning_items}"
        "</div>"
    )


def _build_pipeline_call_item(
    entry: dict[str, Any],
    index: int,
    display_names: dict[str, str],
) -> tuple[dict[str, int | float | None], str]:
    """Build one pipeline call item and return its normalized usage metrics."""
    call_name = entry.get("call", "")
    display_name = display_names.get(call_name, call_name)
    call_label = _usage_call_label(entry, index)
    usage = _usage_metrics(entry, call_label=call_label)
    sys_prompt = _esc(entry.get("system_prompt", ""))
    usr_prompt = _esc(entry.get("user_prompt", ""))
    response_raw = entry.get("response", "")
    if isinstance(response_raw, (dict, list)):
        response_text = _esc(json.dumps(response_raw, indent=2, ensure_ascii=False))
    else:
        response_text = _esc(str(response_raw))

    seed_label = ""
    seed_id = entry.get("seed_id")
    if seed_id:
        seed_label = f" (seed: {_esc(seed_id)})"

    failure_suffix = _usage_failure_suffix(entry)
    warning_html = _usage_warning_html(call_label, usage)
    semantic_status_html = _semantic_stage_status_html(entry)
    item_html = f"""
        {warning_html}
        {semantic_status_html}
        <details class="expandable">
          <summary>Call {index}: {_esc(display_name)}{seed_label} ({_esc(_usage_summary(usage))}){failure_suffix}</summary>
          <div style="padding:8px 0;">
            <h4 style="margin:8px 0 4px;font-size:12px;color:var(--text-muted);">System Prompt</h4>
            <pre class="call-log-pre">{sys_prompt}</pre>
            <h4 style="margin:12px 0 4px;font-size:12px;color:var(--text-muted);">User Prompt</h4>
            <pre class="call-log-pre">{usr_prompt}</pre>
            <h4 style="margin:12px 0 4px;font-size:12px;color:var(--text-muted);">Response</h4>
            <pre class="call-log-pre">{response_text}</pre>
          </div>
        </details>"""
    return usage, item_html


def build_pipeline_calls_section(call_logs: list[dict[str, Any]]) -> str:
    """Build an expandable section showing non-scenario LLM calls.

    These are pipeline-level calls such as capability profile inference and
    candidate filtering, logged to the top-level ``calls.jsonl``.  The UI
    mirrors the collapsible prompt/response pattern used for per-scenario
    call logs.
    """
    if not call_logs:
        return ""

    _CALL_DISPLAY_NAMES: dict[str, str] = {
        "capability_profile": "Capability Profile Inference",
        "candidate_filter": "Candidate Filter",
    }

    call_items: list[str] = []
    normalized_usage: list[dict[str, int | float | None]] = []
    for idx, entry in enumerate(call_logs):
        usage, item_html = _build_pipeline_call_item(
            entry,
            idx,
            _CALL_DISPLAY_NAMES,
        )
        normalized_usage.append(usage)
        call_items.append(item_html)

    # Compute aggregate stats.
    total_prompt, total_completion, total_duration = _usage_totals(normalized_usage)
    call_items_html = "".join(call_items)

    return f"""
    <section id="sec-pipeline-calls" class="section">
      <h2>Pipeline LLM Calls</h2>
      <p style="color:var(--text-secondary);font-size:13px;margin-bottom:12px;">
        Non-scenario LLM calls made during pipeline execution.
        {len(call_logs)} call(s) &middot;
        {total_prompt:,} prompt tokens &middot;
        {total_completion:,} completion tokens &middot;
        {total_duration:,}ms total
      </p>
      {call_items_html}
    </section>
    """
