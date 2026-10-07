"""The one retry the model client makes after a transport error.

A request retries once, after a short fixed delay, when the provider failed
before it answered: an HTTP 5xx status, or a connection error that is not a
timeout.  A timeout, every 4xx status (429 included), and every failure to
parse or validate an answer are never retried.  The SDK client keeps
``max_retries=0``, so each attempt reaches this code.

Both attempts reach ``provider-calls.jsonl`` (see ``provider_record``), and
every active :func:`count_transport_retries` scope counts the retry, so call
tallies include it.
"""

from __future__ import annotations

import time
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass
from typing import Any, Callable, Iterator, TypeVar

DEFAULT_RETRY_DELAY_SECONDS = 1.0
RETRY_DELAY_SECONDS = DEFAULT_RETRY_DELAY_SECONDS
_sleep = time.sleep

_T = TypeVar("_T")


def retryable_failure(error: BaseException) -> dict[str, Any] | None:
    """Describe *error* as ``{"type", "status_code"}`` when it earns the retry."""
    import openai

    if isinstance(error, openai.APITimeoutError):
        return None
    if isinstance(error, openai.APIConnectionError):
        return {"type": type(error).__name__, "status_code": None}
    if isinstance(error, openai.APIStatusError) and 500 <= error.status_code <= 599:
        return {"type": type(error).__name__, "status_code": error.status_code}
    return None


def pause_before_retry() -> None:
    """Wait the fixed delay between a failed attempt and its retry."""
    _sleep(RETRY_DELAY_SECONDS)


def retry_once(send: Callable[[], _T]) -> _T:
    """Call *send*; after a retryable transport error call it once more."""
    try:
        return send()
    except Exception as error:
        if retryable_failure(error) is None:
            raise
    note_transport_retry()
    pause_before_retry()
    return send()


@dataclass
class TransportRetryCount:
    """The transport retries made inside one :func:`count_transport_retries` scope."""

    count: int = 0


_COUNTS: ContextVar[tuple[TransportRetryCount, ...]] = ContextVar(
    "transport_retry_counts", default=()
)


@contextmanager
def count_transport_retries() -> Iterator[TransportRetryCount]:
    """Count the retries made inside the block; scopes nest and each counts."""
    scope = TransportRetryCount()
    token = _COUNTS.set((*_COUNTS.get(), scope))
    try:
        yield scope
    finally:
        _COUNTS.reset(token)


def note_transport_retry() -> None:
    """Add one retry to every active counting scope."""
    for scope in _COUNTS.get():
        scope.count += 1
