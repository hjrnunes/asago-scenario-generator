"""Secret redaction of observed MCP tool metadata."""

from __future__ import annotations

import time

import pytest
from hypothesis import given, settings, strategies as st

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


@pytest.mark.parametrize(
    "scheme",
    [
        "Basic",
        "Bearer",
        "Digest",
        "Negotiate",
        "NTLM",
        "Token",
        "HOBA",
        "Mutual",
        "AWS4-HMAC-SHA256",
        "bearer",
        "BEARER",
        "aws4-hmac-sha256",
    ],
)
def test_known_authentication_scheme_joins_the_credential(scheme):
    assert redaction.sanitize_json(f"Authorization: {scheme} EXAMPLE_ONLY, next") == (
        "Authorization: [REDACTED], next"
    )


def test_prose_after_authorization_loses_only_its_first_word():
    assert redaction.sanitize_json("Authorization: required for admin tools") == (
        "Authorization: [REDACTED] for admin tools"
    )
    assert redaction.sanitize_json("authorization = Bearerish value") == (
        "authorization = [REDACTED] value"
    )


def test_authorization_redaction_stops_at_the_line_end():
    assert redaction.sanitize_json("Authorization: Bearer\nnext line") == (
        "Authorization: [REDACTED]\nnext line"
    )


def test_quoted_key_with_quoted_value_keeps_key_and_quotes():
    assert redaction.sanitize_json('{"token": "x"}') == '{"token": "[REDACTED]"}'
    assert redaction.sanitize_json('{"Authorization": "Bearer x"}') == (
        '{"Authorization": "[REDACTED]"}'
    )
    assert redaction.sanitize_json("{'password': 'two words', 'id': 'keep'}") == (
        "{'password': '[REDACTED]', 'id': 'keep'}"
    )
    assert redaction.sanitize_json('{"api_key":"k","name":"keep"}') == (
        '{"api_key":"[REDACTED]","name":"keep"}'
    )
    assert redaction.sanitize_json("{'token': \"x'y\"}") == "{'token': \"[REDACTED]\"}"


def test_quoted_value_ends_at_its_closing_quote_not_an_escaped_one():
    assert redaction.sanitize_json(r'{"token": "a\"b c", "id": "keep"}') == (
        '{"token": "[REDACTED]", "id": "keep"}'
    )


def test_quoted_key_with_unquoted_value_redacts_the_value():
    assert redaction.sanitize_json('{"token": 12345, "id": 1}') == (
        '{"token": [REDACTED], "id": 1}'
    )
    assert redaction.sanitize_json('{"secret": null}') == '{"secret": [REDACTED]}'


def test_unterminated_quoted_value_still_redacts_its_first_token():
    assert redaction.sanitize_json('{"token": "abc') == '{"token": [REDACTED]'


def test_unquoted_key_with_quoted_value_redacts_the_whole_value():
    assert redaction.sanitize_json('token: "abc def" next') == "token: [REDACTED] next"
    assert redaction.sanitize_json("password='p q'") == "password=[REDACTED]"


def test_text_glued_to_a_closing_quote_belongs_to_the_value():
    assert redaction.sanitize_json('token:""token') == "token:[REDACTED]"
    assert redaction.sanitize_json('token: "abc def"next, id') == (
        "token: [REDACTED], id"
    )
    assert redaction.sanitize_json('{"token": "x"y, "id": 1}') == (
        '{"token": "[REDACTED]", "id": 1}'
    )


def test_quoted_text_without_a_sensitive_key_is_unchanged():
    text = '{"name": "token holder", "note": "no secrets here"}'
    assert redaction.sanitize_json(text) == text


IDEMPOTENCE_SAMPLES = (
    '{"token": "x"}',
    '{"Authorization": "Bearer x"}',
    "{'password': 'two words', 'id': 'keep'}",
    '{"token": 12345, "id": 1}',
    '{"token": "[REDACTED]"}',
    '{"token": "abc',
    'token: "abc def" next',
    'token:""token',
    'token: "abc def"next, id',
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
    "Authorization: required for admin tools",
    "Authorization: AWS4-HMAC-SHA256 Credential=EXAMPLE, Signature=EXAMPLE",
    "Authorization: Token for access",
    "Authorization: Bearer\nnext line",
    'Authorization: "Bearer EXAMPLE_ONLY_TOKEN"',
    "Authorization: EXAMPLE_ONLY_TOKEN; retry",
    "no credential here",
)


@pytest.mark.parametrize("text", IDEMPOTENCE_SAMPLES)
def test_text_redaction_is_idempotent(text):
    once = redaction.sanitize_json(text)
    assert redaction.sanitize_json(once) == once


_FRAGMENTS = st.sampled_from(
    [
        "token",
        "Token",
        "Authorization",
        "authorization",
        "password",
        "api_key",
        "Bearer",
        "Basic",
        "AWS4-HMAC-SHA256",
        "[REDACTED]",
        "abc",
        "two words",
        "required",
        ":",
        "=",
        " ",
        "\n",
        ",",
        ";",
        "]",
        "}",
        '"',
        "'",
        "\\",
    ]
)


@given(st.lists(_FRAGMENTS, max_size=12).map("".join))
@settings(max_examples=500, deadline=None)
def test_text_redaction_is_idempotent_over_joined_fragments(text):
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


@pytest.mark.parametrize("key", ["token", "Authorization"])
def test_an_unclosed_quote_before_a_backslash_run_redacts_in_linear_time(key):
    text = f'{key}: "' + "\\" * 36 + " tail"

    started = time.perf_counter()
    redacted = redaction.sanitize_json(text)

    assert time.perf_counter() - started < 0.5
    assert redacted.startswith(f"{key}: [REDACTED]")


def test_an_escaped_quote_stays_inside_the_quoted_value():
    assert redaction.sanitize_json('{"token": "a\\"b c", "next": 1}') == (
        '{"token": "[REDACTED]", "next": 1}'
    )
