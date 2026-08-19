"""Regression tests for nullable LLM usage metrics in taxonomy reports."""

from __future__ import annotations

import pytest

from asago_scenario_generator.report.template import (
    build_pipeline_calls_section,
    build_scenarios_section,
)


def _pipeline_call(**metrics: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "call": "capability_profile",
        "success": True,
        "system_prompt": "",
        "user_prompt": "",
        "response": "",
        "prompt_tokens": 5,
        "completion_tokens": 7,
        "duration_ms": 90,
    }
    entry.update(metrics)
    return entry


def _scenario() -> dict[str, object]:
    return {
        "scenario_id": "scenario-synthetic",
        "priority": {"composite": 0.5},
        "narrative": {"title": "Synthetic scenario"},
        "faceting": {"taxonomy_chain": {"agentic_threat_ids": []}},
    }


def test_failed_pipeline_call_with_unavailable_metrics_is_reported() -> None:
    html = build_pipeline_calls_section(
        [
            _pipeline_call(
                call="failed_profile",
                success=False,
                error="endpoint unavailable",
                prompt_tokens=None,
                completion_tokens=None,
                duration_ms=None,
            )
        ]
    )

    assert "FAILED" in html
    assert html.count("unavailable") >= 3
    assert "failed_profile" in html
    assert "0 prompt tokens" in html
    assert "0 completion tokens" in html
    assert "0ms total" in html
    assert "unavailable usage metrics" in html


@pytest.mark.parametrize(
    ("field", "prompt_total", "completion_total", "duration_total"),
    [
        ("prompt_tokens", "11", "20", "260"),
        ("completion_tokens", "16", "13", "260"),
        ("duration_ms", "16", "20", "170"),
    ],
)
def test_nullable_pipeline_metric_preserves_other_totals(
    field: str,
    prompt_total: str,
    completion_total: str,
    duration_total: str,
) -> None:
    first = _pipeline_call(**{field: None})
    second = _pipeline_call(
        call="candidate_filter",
        prompt_tokens=11,
        completion_tokens=13,
        duration_ms=170,
    )

    html = build_pipeline_calls_section([first, second])

    assert "unavailable" in html
    assert f"{prompt_total} prompt tokens" in html
    assert f"{completion_total} completion tokens" in html
    assert f"{duration_total}ms total" in html
    assert field in html


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("prompt_tokens", "many"),
        ("completion_tokens", {"count": 4}),
        ("duration_ms", [300]),
        ("prompt_tokens", True),
        ("duration_ms", float("nan")),
    ],
)
def test_invalid_pipeline_metric_has_a_call_specific_diagnostic(
    field: str,
    value: object,
) -> None:
    with pytest.raises(ValueError) as exc_info:
        build_pipeline_calls_section(
            [_pipeline_call(call="failed_profile", **{field: value})]
        )

    message = str(exc_info.value)
    assert field in message
    assert repr(value) in message
    assert "failed_profile" in message
    assert "unsupported operand type" not in message


def test_fractional_pipeline_metrics_are_preserved() -> None:
    html = build_pipeline_calls_section(
        [
            _pipeline_call(
                prompt_tokens=31.5,
                completion_tokens=17.25,
                duration_ms=410.5,
            )
        ]
    )

    assert "31.5 prompt tokens" in html
    assert "17.25 completion tokens" in html
    assert "410.5ms total" in html


def test_synthetic_scenario_call_remains_visible_with_unavailable_metrics() -> None:
    html = build_scenarios_section(
        [_scenario()],
        {},
        {
            "scenario-synthetic": [
                {
                    "call": "synthetic",
                    "success": True,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "duration_ms": None,
                    "system_prompt": "",
                    "user_prompt": "",
                    "response": "",
                },
                {
                    "call": "numeric",
                    "success": True,
                    "prompt_tokens": 19,
                    "completion_tokens": 23,
                    "duration_ms": 290,
                    "system_prompt": "",
                    "user_prompt": "",
                    "response": "",
                },
            ],
        },
    )

    assert "synthetic" in html
    assert html.count("unavailable") >= 3
    assert "19 prompt / 23 completion tokens, 290ms" in html
    assert "synthetic" in html
    assert "unavailable usage metrics" in html


def test_complete_pipeline_metrics_do_not_emit_unavailable_warning() -> None:
    html = build_pipeline_calls_section(
        [
            _pipeline_call(
                prompt_tokens=31,
                completion_tokens=17,
                duration_ms=410,
            )
        ]
    )

    assert "31 prompt tokens" in html
    assert "17 completion tokens" in html
    assert "410ms total" in html
    assert "unavailable" not in html


def test_missing_pipeline_metrics_use_zero_totals() -> None:
    entry = _pipeline_call()
    for field in ("prompt_tokens", "completion_tokens", "duration_ms"):
        entry.pop(field)

    html = build_pipeline_calls_section([entry])

    assert "0 prompt tokens" in html
    assert "0 completion tokens" in html
    assert "0ms total" in html


def test_successful_pipeline_call_has_no_failure_marker() -> None:
    entry = _pipeline_call()
    entry.pop("success")

    html = build_pipeline_calls_section([entry])

    assert "FAILED" not in html
