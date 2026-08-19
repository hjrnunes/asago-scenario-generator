"""Acceptance handlers for nullable usage metrics in taxonomy reports."""

from __future__ import annotations

import json
import re
import tempfile
from pathlib import Path
from typing import Any

from asago_scenario_generator.report.data import ReportData
from asago_scenario_generator.report.generator import generate_report
from runtime_world import World

FEATURE_ID = "nullable_usage"


def _call(
    name: str,
    *,
    prompt_tokens: int | None,
    completion_tokens: int | None,
    duration_ms: int | None,
    success: bool = True,
) -> dict[str, Any]:
    return {
        "call": name,
        "success": success,
        "error": "synthetic failure" if not success else "",
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "duration_ms": duration_ms,
        "system_prompt": "",
        "user_prompt": "",
        "response": "",
    }


def _scenario(scenario_id: str) -> dict[str, Any]:
    return {
        "scenario_id": scenario_id,
        "priority": {"composite": 0.5},
        "narrative": {"title": scenario_id},
        "faceting": {"taxonomy_chain": {"agentic_threat_ids": []}},
        "validation": {
            "semantic": {
                "corpus_claim_applicability": [
                    {
                        "category": "entry_points",
                        "status": "not_applicable",
                        "reason": "Acceptance fixture",
                    },
                    {
                        "category": "tool_inventory",
                        "status": "not_applicable",
                        "reason": "Acceptance fixture",
                    },
                ]
            }
        },
    }


def _h_background(world: World, text: str, examples: dict) -> tuple[bool, str]:
    world.report_tmpdir = Path(tempfile.mkdtemp(prefix="nullable-usage-"))
    world.report_html_path = None
    world.report_html_content = None
    world.nullable_pipeline_calls = []
    world.nullable_scenario_calls = {}
    world.nullable_scenarios = []
    world.nullable_report_error = None
    return True, ""


def _h_failed_pipeline_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.nullable_pipeline_calls = [
        _call(
            "failed_pipeline_call",
            prompt_tokens=None,
            completion_tokens=None,
            duration_ms=None,
            success=False,
        )
    ]
    return True, ""


def _h_nullable_pipeline_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    match = re.search(r"except (\w+) is null", text)
    field = examples.get("unavailable_field") or (match.group(1) if match else "")
    if field not in {"prompt_tokens", "completion_tokens", "duration_ms"}:
        return False, f"Could not identify nullable metric field in: {text}"
    first = _call(
        "nullable_pipeline_call",
        prompt_tokens=5,
        completion_tokens=7,
        duration_ms=90,
    )
    first[field] = None
    world.nullable_pipeline_calls = [first]
    return True, ""


def _h_second_pipeline_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.nullable_pipeline_calls.append(
        _call(
            "numeric_pipeline_call",
            prompt_tokens=11,
            completion_tokens=13,
            duration_ms=170,
        )
    )
    return True, ""


def _h_synthetic_scenario_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    scenario_id = "synthetic-scenario"
    world.nullable_scenarios.append(_scenario(scenario_id))
    world.nullable_scenario_calls[scenario_id] = [
        _call(
            "synthetic_scenario_call",
            prompt_tokens=None,
            completion_tokens=None,
            duration_ms=None,
        )
    ]
    return True, ""


def _h_numeric_scenario_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    scenario_id = "numeric-scenario"
    world.nullable_scenarios.append(_scenario(scenario_id))
    world.nullable_scenario_calls[scenario_id] = [
        _call(
            "numeric_scenario_call",
            prompt_tokens=19,
            completion_tokens=23,
            duration_ms=290,
        )
    ]
    return True, ""


def _parse_invalid_value(raw: str) -> Any:
    value = raw.strip()
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return value.strip('"')


def _invalid_metric_details(text: str, examples: dict) -> tuple[str, str]:
    """Extract the invalid metric field and value from a Gherkin step."""
    match = re.search(r"whose (\w+) value is (.+)$", text)
    field = examples.get("metric_field") or (match.group(1) if match else "")
    raw_value = examples.get("invalid_value") or (match.group(2) if match else "")
    return str(field), str(raw_value)


def _h_invalid_pipeline_metric(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    field, raw_value = _invalid_metric_details(text, examples)
    if field not in {"prompt_tokens", "completion_tokens", "duration_ms"}:
        return False, f"Could not identify invalid metric field in: {text}"
    value = _parse_invalid_value(raw_value)
    world.nullable_pipeline_calls = [
        _call(
            "invalid_pipeline_call",
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
        )
    ]
    world.nullable_pipeline_calls[0][field] = value
    return True, ""


def _h_complete_pipeline_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    world.nullable_pipeline_calls = [
        _call(
            "complete_pipeline_call",
            prompt_tokens=31,
            completion_tokens=17,
            duration_ms=410,
        )
    ]
    return True, ""


def _h_generate_report(world: World, text: str, examples: dict) -> tuple[bool, str]:
    if world.report_tmpdir is None:
        return False, "Report input was not initialized"
    data = ReportData(
        scenarios=world.nullable_scenarios,
        call_logs=world.nullable_scenario_calls,
        pipeline_call_logs=world.nullable_pipeline_calls,
    )
    try:
        world.report_html_path = generate_report(data, world.report_tmpdir)
        world.report_html_content = world.report_html_path.read_text(encoding="utf-8")
        world.nullable_report_error = None
    except Exception as exc:  # Expected for the invalid-metric scenarios.
        world.report_html_path = None
        world.report_html_content = None
        world.nullable_report_error = str(exc)
    return True, ""


def _h_report_succeeds(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.nullable_report_error is None
        and world.report_html_path is not None
        and world.report_html_path.exists(),
        f"report generation failed: {world.nullable_report_error}",
    )


def _html(world: World) -> str:
    return world.report_html_content or ""


def _h_report_retains_failed_call(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return "failed_pipeline_call" in _html(world) and "FAILED" in _html(world), ""


def _h_unavailable_metrics(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        all(
            f"{field}=unavailable" in _html(world)
            for field in (
                "prompt_tokens",
                "completion_tokens",
                "duration_ms",
            )
        ),
        "not all nullable usage metrics were displayed as unavailable",
    )


def _h_pipeline_totals(world: World, text: str, examples: dict) -> tuple[bool, str]:
    match = re.search(
        r"show (\d+) prompt tokens, (\d+) completion tokens, and (\d+) milliseconds",
        text,
    )
    if not match:
        return False, f"Could not parse expected totals from: {text}"
    prompt, completion, duration = match.groups()
    html = _html(world)
    return (
        f"{prompt} prompt tokens" in html
        and f"{completion} completion tokens" in html
        and f"{duration}ms total" in html,
        f"expected totals not found in report: {prompt}/{completion}/{duration}",
    )


def _h_report_contains_both_pipeline_calls(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    html = _html(world)
    return (
        "nullable_pipeline_call" in html and "numeric_pipeline_call" in html,
        "both pipeline calls are not present",
    )


def _h_report_warns_unavailable(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return "unavailable usage metrics" in _html(world), "warning is missing"


def _h_report_contains_both_scenarios(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    html = _html(world)
    return (
        "synthetic-scenario" in html and "numeric-scenario" in html,
        "both scenarios are not present",
    )


def _h_numeric_scenario_metrics(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    return (
        "19 prompt / 23 completion tokens, 290ms" in _html(world),
        "numeric scenario usage metrics are missing",
    )


def _h_invalid_diagnostic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    error = world.nullable_report_error or ""
    field, raw_value = _invalid_metric_details(text, examples)
    expected_value = _parse_invalid_value(raw_value)
    value_fragments = {str(expected_value), repr(expected_value)}
    identifies_value = any(fragment in error for fragment in value_fragments)
    return (
        field in error and identifies_value and "invalid_pipeline_call" in error,
        f"diagnostic did not identify field, value, and call: {error}",
    )


def _h_report_fails(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        world.nullable_report_error is not None and world.report_html_path is None,
        "invalid report unexpectedly succeeded",
    )


def _h_no_arithmetic_exception(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    error = world.nullable_report_error or ""
    forbidden = ("unsupported operand type", "TypeError", "Traceback")
    return not any(fragment in error for fragment in forbidden), error


def _h_report_no_warning(world: World, text: str, examples: dict) -> tuple[bool, str]:
    return (
        "unavailable usage metrics" not in _html(world),
        "unexpected unavailable-metrics warning",
    )


def register(api: Any) -> None:
    """Register nullable usage reporting step handlers."""
    api.register(
        r"an offline taxonomy-and-risk report input",
        _h_background,
        source_order=5000,
    )
    api.register(
        r"the pipeline call log contains one failed call with null prompt_tokens, completion_tokens, and duration_ms",
        _h_failed_pipeline_call,
        source_order=5001,
    )
    api.register(
        r"the pipeline call log contains one call with prompt_tokens 5, completion_tokens 7, and duration_ms 90 except .* is null",
        _h_nullable_pipeline_call,
        source_order=5002,
    )
    api.register(
        r"it contains another call with prompt_tokens 11, completion_tokens 13, and duration_ms 170",
        _h_second_pipeline_call,
        source_order=5003,
    )
    api.register(
        r"a reportable scenario has a synthetic call with null prompt_tokens, completion_tokens, and duration_ms",
        _h_synthetic_scenario_call,
        source_order=5004,
    )
    api.register(
        r"another reportable scenario has a call with prompt_tokens 19, completion_tokens 23, and duration_ms 290",
        _h_numeric_scenario_call,
        source_order=5005,
    )
    api.register(
        r"the pipeline call log contains a call whose .* value is .*",
        _h_invalid_pipeline_metric,
        source_order=5006,
    )
    api.register(
        r"the pipeline call log contains one call with prompt_tokens 31, completion_tokens 17, and duration_ms 410",
        _h_complete_pipeline_call,
        source_order=5007,
    )
    api.register(
        r"the HTML report is generated",
        _h_generate_report,
        source_order=5008,
    )
    api.register(
        r"report generation succeeds",
        _h_report_succeeds,
        source_order=5009,
    )
    api.register(
        r"the report retains the failed call",
        _h_report_retains_failed_call,
        source_order=5010,
    )
    api.register(
        r"the unavailable call displays prompt_tokens, completion_tokens, and duration_ms as unavailable",
        _h_unavailable_metrics,
        source_order=5011,
    )
    api.register(
        r"the pipeline totals show .* prompt tokens, .* completion tokens, and .* milliseconds",
        _h_pipeline_totals,
        source_order=5012,
    )
    api.register(
        r"the report contains both pipeline calls",
        _h_report_contains_both_pipeline_calls,
        source_order=5013,
    )
    api.register(
        r"the report warns that .*(?:is unavailable|has unavailable usage metrics)",
        _h_report_warns_unavailable,
        source_order=5014,
    )
    api.register(
        r"the report contains both scenarios",
        _h_report_contains_both_scenarios,
        source_order=5015,
    )
    api.register(
        r"the numeric scenario call displays 19 prompt tokens, 23 completion tokens, and 290 milliseconds",
        _h_numeric_scenario_metrics,
        source_order=5016,
    )
    api.register(
        r"report generation fails with an invalid usage metric diagnostic",
        _h_report_fails,
        source_order=5017,
    )
    api.register(
        r"the diagnostic identifies .* and the call",
        _h_invalid_diagnostic,
        source_order=5018,
    )
    api.register(
        r"the diagnostic does not expose an arithmetic exception",
        _h_no_arithmetic_exception,
        source_order=5019,
    )
    api.register(
        r"the report does not warn that usage metrics are unavailable",
        _h_report_no_warning,
        source_order=5020,
    )


__all__ = ["FEATURE_ID", "register"]
