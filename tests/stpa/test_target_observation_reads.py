"""Read-result decoding and capture validation in the runtime-context parser."""

from __future__ import annotations

import json
from typing import Any

import pytest

from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    MAX_CONTENT_CHARS,
    MAX_OBSERVATIONS,
    TargetObservationSnapshot,
)

_DIGEST = "a" * 64


def _read(result: Any = None, **overrides: Any) -> dict[str, Any]:
    raw: dict[str, Any] = {
        "profile_digest": _DIGEST,
        "status": {"transport": "verified", "content": "untrusted"},
        "result": result,
    }
    raw.update(overrides)
    return raw


def _context(*reads: Any, **overrides: Any) -> dict[str, Any]:
    context: dict[str, Any] = {
        "target_profile_digest": _DIGEST,
        "state": {"authorization": "approved"},
        "read_observations": list(reads),
    }
    context.update(overrides)
    return context


def _parse(context: Any) -> TargetObservationSnapshot:
    return TargetObservationSnapshot.from_runtime_context(context)


def _only_read(result: Any) -> tuple[str, str]:
    read = _parse(_context(_read(result))).observations[1]
    return read.content_format, read.content


def _text_blocks(*texts: str) -> dict[str, Any]:
    return {"content": [{"type": "text", "text": text} for text in texts]}


# Returned content decoding


def test_structured_json_string_is_decoded_and_canonicalized() -> None:
    assert _only_read({"structuredContent": '{"b": 1, "a": [true]}'}) == (
        "json",
        '{"a":[true],"b":1}',
    )


def test_structured_plain_string_stays_text() -> None:
    assert _only_read({"structuredContent": {"result": "approved"}}) == (
        "text",
        "approved",
    )


def test_structured_empty_string_is_rejected() -> None:
    with pytest.raises(ValueError, match="read result exceeds"):
        _parse(_context(_read({"structuredContent": ""})))


def test_text_blocks_are_joined_and_decoded_as_json() -> None:
    result = {
        "content": [
            {"type": "text", "text": '{"items":'},
            {"type": "image", "data": "ignored"},
            "not a block",
            {"type": "text", "text": 7},
            {"type": "text", "text": "[1, 2]}"},
        ]
    }
    assert _only_read(result) == ("json", '{"items":[1,2]}')


def test_non_json_text_blocks_stay_verbatim_text() -> None:
    assert _only_read(_text_blocks("status: approved", "limit: 5")) == (
        "text",
        "status: approved\nlimit: 5",
    )


def test_text_block_result_envelope_is_unwrapped_once() -> None:
    envelope = json.dumps({"result": json.dumps("still text")})
    assert _only_read(_text_blocks(envelope)) == ("text", "still text")


@pytest.mark.parametrize(
    ("result", "message"),
    (
        (None, "requires a result object"),
        ({"isError": True, "content": []}, "contains an unsuccessful result"),
        ({}, "requires content or structuredContent"),
        ({"content": "text"}, "requires content or structuredContent"),
        ({"content": [{"type": "image"}]}, "has no textual returned content"),
    ),
)
def test_unusable_read_results_are_rejected(result: Any, message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _parse(_context(_read(result)))


def test_oversized_text_blocks_are_rejected() -> None:
    result = _text_blocks("x" * (MAX_CONTENT_CHARS + 1))
    with pytest.raises(
        ValueError, match=f"read observation exceeds {MAX_CONTENT_CHARS} characters"
    ):
        _parse(_context(_read(result)))


# Capture envelope validation


@pytest.mark.parametrize(
    ("context", "error", "message"),
    (
        ([], TypeError, "must be a mapping"),
        (_context(extra=1), ValueError, "unsupported fields: extra"),
        (
            _context(target_profile_digest="A" * 64),
            ValueError,
            "requires target_profile_digest",
        ),
        (_context(state=[]), ValueError, "state must be an object"),
        (_context(read_observations="x"), ValueError, "must be a list"),
        (
            _context(*[_read(_text_blocks("x"))] * MAX_OBSERVATIONS),
            ValueError,
            f"more than {MAX_OBSERVATIONS - 1} read observations",
        ),
        (_context("x"), ValueError, "must be an object"),
        (
            _context(_read(_text_blocks("x"), profile_digest="b" * 64)),
            ValueError,
            "profile_digest does not match",
        ),
        (
            _context(_read(_text_blocks("x"), status={"transport": "verified"})),
            ValueError,
            "content must be marked untrusted",
        ),
        (
            _context(_read(_text_blocks("x"), tool_name=3)),
            ValueError,
            "tool_name must be text",
        ),
        (
            _context(_read(_text_blocks("x"), tool_description=3)),
            ValueError,
            "tool_description must be text",
        ),
        (
            _context(_read(_text_blocks("x"), arguments=["q"])),
            ValueError,
            "arguments must be a string mapping",
        ),
    ),
)
def test_malformed_capture_is_rejected(
    context: Any, error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        _parse(context)


def test_reads_keep_order_and_source_metadata() -> None:
    snapshot = _parse(
        _context(
            _read(_text_blocks("first"), tool_name="a", arguments={"q": "1"}),
            _read(_text_blocks("second"), tool_description="b"),
        )
    )

    assert snapshot.read_status == "observed"
    assert [item.observation_ref for item in snapshot.observations] == [
        "TARGET-STATE",
        "TARGET-READ-001",
        "TARGET-READ-002",
    ]
    first, second = snapshot.observations[1:]
    assert (first.source_name, first.source_arguments, first.content) == (
        "a",
        {"q": "1"},
        "first",
    )
    assert (second.source_description, second.source_arguments) == ("b", None)


@pytest.mark.parametrize(
    ("overrides", "status"),
    (
        ({}, "not_requested"),
        ({"read_observations": None}, "not_requested"),
        ({"read_observation_input": {}}, "unavailable"),
        ({"read_observation_diagnostics": [{"code": "x"}]}, "unavailable"),
        ({"read_observation_diagnostics": []}, "not_requested"),
    ),
)
def test_read_status_without_reads(overrides: dict[str, Any], status: str) -> None:
    assert _parse(_context(**overrides)).read_status == status
