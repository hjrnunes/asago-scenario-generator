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


def test_authorization_value_is_redacted_whole():
    assert redaction.sanitize_json(
        "Header Authorization: Bearer EXAMPLE_ONLY_TOKEN"
    ) == ("Header Authorization: [REDACTED]")
    assert redaction.sanitize_json(
        "authorization = Basic RVhBTVBMRQ==, then retry"
    ) == ("authorization = [REDACTED], then retry")
    assert redaction.sanitize_json("Authorization: Digest EXAMPLE_ONLY_TOKEN") == (
        "Authorization: [REDACTED]"
    )
    assert redaction.sanitize_json('Authorization: "Bearer EXAMPLE_ONLY_TOKEN"') == (
        "Authorization: [REDACTED]"
    )


def test_authorization_value_without_a_scheme_is_one_token():
    assert redaction.sanitize_json("Authorization: EXAMPLE_ONLY_TOKEN") == (
        "Authorization: [REDACTED]"
    )
    assert redaction.sanitize_json("Authorization: EXAMPLE_ONLY_TOKEN; retry") == (
        "Authorization: [REDACTED]; retry"
    )


def test_authorization_redaction_stops_at_the_line_end():
    assert redaction.sanitize_json("Authorization: Bearer\nnext line") == (
        "Authorization: [REDACTED]\nnext line"
    )


def test_other_text_keys_still_redact_one_token():
    assert redaction.sanitize_json("token: abc def password=xyz uvw") == (
        "token: [REDACTED] def password=[REDACTED] uvw"
    )
