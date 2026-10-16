"""Secret redaction of observed MCP tool metadata."""

from __future__ import annotations

import pytest

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


IDEMPOTENCE_SAMPLES = (
    "token=secret",
    "token: abc def password=xyz uvw",
    "token=[REDACTED]",
    "token: [REDACTED] and more",
    "api_key=[REDACTED]]",
    "token=[REDACTED]trailing",
    "Header Authorization: Bearer EXAMPLE_ONLY_TOKEN",
    "authorization = Basic RVhBTVBMRQ==, then retry",
    "Authorization: [REDACTED]",
    "Authorization: Bearer [REDACTED]",
    "Authorization: Bearer\nnext line",
    'Authorization: "Bearer EXAMPLE_ONLY_TOKEN"',
    "Authorization: EXAMPLE_ONLY_TOKEN; retry",
    "no credential here",
)


@pytest.mark.parametrize("text", IDEMPOTENCE_SAMPLES)
def test_text_redaction_is_idempotent(text):
    once = redaction.sanitize_json(text)
    assert redaction.sanitize_json(once) == once


def test_an_existing_redaction_marker_stays_as_it_is():
    assert redaction.sanitize_json("token=[REDACTED]") == "token=[REDACTED]"
    assert redaction.sanitize_json("password: [REDACTED], next") == (
        "password: [REDACTED], next"
    )
    assert redaction.sanitize_json("token=[REDACTED]trailing") == "token=[REDACTED]"


def test_other_text_keys_still_redact_one_token():
    assert redaction.sanitize_json("token: abc def password=xyz uvw") == (
        "token: [REDACTED] def password=[REDACTED] uvw"
    )
