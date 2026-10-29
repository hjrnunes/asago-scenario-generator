"""The client redacts its API key from a provider error without replacing it.

Retry decisions read the type of the error the provider raised, so redaction
must leave that error propagating whatever its type allows to be rewritten.
"""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.stpa.infra.llm import _drop_api_key
from tests.helpers.provider_call_record import _Provider, _client

KEY = "bluebird"
ECHOED = f"Incorrect API key provided: {KEY}"
REDACTED = "Incorrect API key provided: [redacted-key]"


class _ReadOnlyArgs(Exception):
    """An error whose ``args`` cannot be assigned."""

    @property
    def args(self) -> tuple[Any, ...]:  # type: ignore[override]
        return (ECHOED,)


class _ReadOnlyMessage(Exception):
    """An error whose ``message`` is a property with no setter."""

    @property
    def message(self) -> str:
        return ECHOED


class _Frozen(Exception):
    """An error that refuses every attribute assignment."""

    def __setattr__(self, name: str, value: Any) -> None:
        raise TypeError(f"{name} is frozen")


@pytest.mark.parametrize(
    "error",
    [_ReadOnlyArgs, _ReadOnlyMessage, lambda: _Frozen(ECHOED)],
    ids=["read-only-args", "read-only-message", "frozen"],
)
def test_an_error_that_cannot_be_rewritten_is_left_as_it_is(error) -> None:
    failure = error()

    assert _drop_api_key(failure, KEY) is None


@pytest.mark.parametrize(
    "error",
    [_ReadOnlyArgs, _ReadOnlyMessage, lambda: _Frozen(ECHOED)],
    ids=["read-only-args", "read-only-message", "frozen"],
)
def test_the_client_reraises_the_provider_error_it_could_not_rewrite(error) -> None:
    failure = error()

    def fail(**kwargs: Any) -> Any:
        raise failure

    client = _client(_Provider(fail), api_key=KEY)
    with pytest.raises(type(failure)) as raised:
        client._send("chat.completions.create", model="m", messages=[])

    assert raised.value is failure


def test_a_rewritable_part_is_redacted_beside_a_read_only_one() -> None:
    failure = _ReadOnlyMessage(ECHOED)

    _drop_api_key(failure, KEY)

    assert failure.args == (REDACTED,)


def test_the_cause_and_the_context_are_redacted() -> None:
    cause = RuntimeError(ECHOED)
    context = ValueError(ECHOED)
    failure = RuntimeError("request failed")
    failure.__cause__ = cause
    failure.__context__ = context

    _drop_api_key(failure, KEY)

    assert cause.args == (REDACTED,)
    assert context.args == (REDACTED,)


def test_a_chain_two_levels_deep_is_redacted() -> None:
    root = OSError(ECHOED)
    middle = RuntimeError("transport")
    middle.__cause__ = root
    failure = RuntimeError("request failed")
    failure.__context__ = middle

    _drop_api_key(failure, KEY)

    assert root.args == (REDACTED,)


def test_a_cyclic_chain_is_redacted_once_and_ends() -> None:
    first = RuntimeError(ECHOED)
    second = ValueError(ECHOED)
    first.__context__ = second
    second.__context__ = first
    first.__cause__ = first

    _drop_api_key(first, KEY)

    assert first.args == (REDACTED,)
    assert second.args == (REDACTED,)


def test_an_empty_key_changes_nothing() -> None:
    failure = RuntimeError("an error with no key")

    _drop_api_key(failure, "")

    assert failure.args == ("an error with no key",)


@pytest.mark.parametrize("key", ["x", "EMPTY", "none", "abc1234"])
def test_a_key_shorter_than_eight_characters_is_not_redacted_by_value(key) -> None:
    text = f"model none is unavailable: EMPTY response x abc12345 {key}"
    failure = RuntimeError(text)

    _drop_api_key(failure, key)

    assert failure.args == (text,)


def test_an_eight_character_key_is_redacted() -> None:
    failure = RuntimeError(ECHOED)

    _drop_api_key(failure, KEY)

    assert len(KEY) == 8
    assert failure.args == (REDACTED,)
