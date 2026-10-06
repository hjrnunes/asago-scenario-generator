"""Secret redaction of observed MCP tool metadata."""

from __future__ import annotations

from asago_scenario_generator.target_discovery import redaction


def test_sanitizer_covers_closed_input_shapes():
    assert redaction.sanitize_json(
        {"password": "secret", "properties": {"password": "keep-name"}}
    ) == {"password": "[REDACTED]", "properties": {"password": "keep-name"}}
    assert redaction.sanitize_json(("token=secret", 1)) == (
        "token=[REDACTED]",
        1,
    )
    assert redaction.sanitize_json(None) is None
