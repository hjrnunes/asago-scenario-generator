"""Per-request provider record and replay for the STPA pipeline.

``calls.jsonl`` is the call-site log: it holds parsed, sanitized evidence and
is rewritten when a call publishes.  This module records one level lower, at
the single transport seam in ``LLMClient``, so a run keeps every request
exactly as sent and every provider response exactly as returned.  The same
seam can serve those responses back, which makes a recorded run replayable
without a model endpoint.

Record format (one JSON object per line of ``provider-calls.jsonl``)::

    {
      "kind": "provider-call-record-v1",
      "sequence": 7,
      "identity": {"stage": ..., "step": ..., "slot_id": ...,
                   "scenario_id": ..., "attempt_number": 1},
      "request": {"api": ..., "model": ..., "messages": [...],
                  "parameters": {...}},
      "request_sha256": "...",
      "outcome": "response" | "error",
      "response": {"id", "model", "finish_reason", "usage", "body"} | null,
      "error": {"type", "message", "status_code"} | null,
      "local_rejection": {"type", "message"} | null,
      "timestamp": "...", "duration_ms": 123
    }

The request holds only per-call arguments.  The endpoint, credential, and
connection headers belong to the SDK client, never to a request, and the
recorder drops any parameter that names one.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from collections import defaultdict, deque
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from pydantic import BaseModel

from asago_scenario_generator.stpa.infra.call_log import _safe_error

RECORD_FILENAME = "provider-calls.jsonl"
RECORD_KIND = "provider-call-record-v1"

_CONNECTION_PARAMETERS = frozenset(
    {
        "base_url",
        "api_key",
        "extra_headers",
        "headers",
        "default_headers",
        "authorization",
    }
)


class ReplayMissError(RuntimeError):
    """A request has no recorded response."""


class ReplayedProviderError(RuntimeError):
    """A recorded provider failure, raised again during replay."""

    def __init__(self, error_type: str, message: str, status_code: Any = None) -> None:
        super().__init__(message)
        self.recorded_type = error_type
        self.status_code = status_code


class ReplayIncompleteError(RuntimeError):
    """A replayed run sent requests that the record does not contain."""


@dataclass(frozen=True)
class CallIdentity:
    """Pipeline-level identity of the call that issues a provider request."""

    stage: str
    step: str
    slot_id: str | None = None
    scenario_id: str | None = None
    attempt_number: int = 1

    def as_record(self) -> dict[str, Any]:
        return asdict(self)


_IDENTITY: ContextVar[CallIdentity | None] = ContextVar(
    "provider_call_identity", default=None
)


@contextmanager
def call_identity(identity: CallIdentity) -> Iterator[None]:
    """Attribute provider requests sent inside the block to *identity*."""
    token = _IDENTITY.set(identity)
    try:
        yield
    finally:
        _IDENTITY.reset(token)


def _request_value(value: Any) -> Any:
    """Convert one request argument to canonical JSON-compatible data."""
    if isinstance(value, type) and issubclass(value, BaseModel):
        return {
            "pydantic_model": value.__name__,
            "json_schema": value.model_json_schema(),
        }
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json")
    if isinstance(value, Mapping):
        return {str(key): _request_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_request_value(item) for item in value]
    return _scalar_request_value(value)


def _scalar_request_value(value: Any) -> Any:
    """Keep JSON scalars and stringify anything else."""
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def canonical_request(api: str, request: Mapping[str, Any]) -> dict[str, Any]:
    """Build the replayable request: model, messages, and every other control."""
    parameters = {
        key: _request_value(value)
        for key, value in request.items()
        if key not in {"model", "messages"} and key not in _CONNECTION_PARAMETERS
    }
    return {
        "api": api,
        "model": request.get("model"),
        "messages": _request_value(request.get("messages", [])),
        "parameters": parameters,
    }


def request_digest(request: Mapping[str, Any]) -> str:
    """Return the SHA-256 of the canonical JSON form of *request*."""
    payload = json.dumps(
        request, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _plain(value: Any) -> Any:
    """Return a JSON-compatible copy, stringifying anything unserializable."""
    return json.loads(json.dumps(value, default=str))


def _response_body(response: Any) -> Any:
    """Serialize a provider response without dropping provider-specific fields."""
    dump = getattr(response, "model_dump", None)
    if isinstance(response, BaseModel) and callable(dump):
        return _plain(dump(mode="json"))
    choices = getattr(response, "choices", None) or []
    first = choices[0] if choices else None
    message = getattr(first, "message", None)
    return _plain(
        {
            "id": getattr(response, "id", None),
            "model": getattr(response, "model", None),
            "choices": [
                {
                    "finish_reason": getattr(first, "finish_reason", None),
                    "message": {"content": getattr(message, "content", None)},
                }
            ]
            if first is not None
            else [],
            "usage": getattr(response, "usage", None),
        }
    )


def _response_record(response: Any) -> dict[str, Any]:
    body = _response_body(response)
    choices = body.get("choices") if isinstance(body, dict) else None
    first = choices[0] if isinstance(choices, list) and choices else {}
    return {
        "id": body.get("id") if isinstance(body, dict) else None,
        "model": body.get("model") if isinstance(body, dict) else None,
        "finish_reason": first.get("finish_reason")
        if isinstance(first, dict)
        else None,
        "usage": body.get("usage") if isinstance(body, dict) else None,
        "body": body,
    }


def _error_record(error: BaseException) -> dict[str, Any]:
    return {
        "type": getattr(error, "recorded_type", type(error).__name__),
        "message": _safe_error(str(error)),
        "status_code": getattr(error, "status_code", None),
    }


@dataclass
class _Attempt:
    """One provider request awaiting its final outcome."""

    sequence: int
    identity: CallIdentity | None
    request: dict[str, Any]
    digest: str
    timestamp: str
    started_ns: int
    duration_ms: int = 0
    response: dict[str, Any] | None = None
    error: dict[str, Any] | None = None
    local_rejection: dict[str, Any] | None = None

    def as_record(self) -> dict[str, Any]:
        return {
            "kind": RECORD_KIND,
            "sequence": self.sequence,
            "identity": self.identity.as_record() if self.identity else None,
            "request": self.request,
            "request_sha256": self.digest,
            "outcome": "error" if self.error is not None else "response",
            "response": self.response,
            "error": self.error,
            "local_rejection": self.local_rejection,
            "timestamp": self.timestamp,
            "duration_ms": self.duration_ms,
        }


def _replay_key(identity: Mapping[str, Any] | None, digest: str) -> str:
    return json.dumps([identity, digest], sort_keys=True)


_BUILTIN_TRANSPORT_ERRORS: dict[str, type[Exception]] = {
    cls.__name__: cls
    for cls in (
        TimeoutError,
        ConnectionError,
        ConnectionRefusedError,
        ConnectionResetError,
        ConnectionAbortedError,
        OSError,
        RuntimeError,
        ValueError,
    )
}


def _rebuild_error(error: Mapping[str, Any]) -> BaseException:
    """Recreate a recorded provider failure as the class the live call raised.

    Call sites branch on the exception class (the service-tier fallback only
    retries ``openai.RateLimitError`` with HTTP 429) and log its class name, so
    a replay must raise the same class with the same message and status.  A
    class this module cannot rebuild replays as :class:`ReplayedProviderError`.
    """
    import httpx
    import openai

    name, message = str(error["type"]), str(error["message"])
    status_code = error.get("status_code")
    request = httpx.Request("POST", "https://replay.invalid/v1/chat/completions")
    candidate = getattr(openai, name, None)
    try:
        rebuilt = _rebuild_openai_error(candidate, message, status_code, request)
        if rebuilt is None:
            rebuilt = _rebuild_builtin_error(name, message, status_code)
    except Exception:  # noqa: BLE001 - fall back to the generic replayed error
        rebuilt = None
    if rebuilt is None:
        return ReplayedProviderError(name, message, status_code)
    return rebuilt


def _rebuild_openai_error(
    candidate: Any, message: str, status_code: Any, request: Any
) -> BaseException | None:
    """Rebuild an ``openai`` error class, or ``None`` when its shape does not fit."""
    import httpx
    import openai

    if not (isinstance(candidate, type) and issubclass(candidate, openai.APIError)):
        return None
    if issubclass(candidate, openai.APITimeoutError):
        return candidate(request=request)
    if issubclass(candidate, openai.APIConnectionError):
        return candidate(message=message, request=request)
    if issubclass(candidate, openai.APIStatusError) and status_code is not None:
        return candidate(
            message,
            response=httpx.Response(int(status_code), request=request),
            body=None,
        )
    return None


def _rebuild_builtin_error(
    name: str, message: str, status_code: Any
) -> BaseException | None:
    """Rebuild a built-in transport error that round-trips its message exactly."""
    candidate = _BUILTIN_TRANSPORT_ERRORS.get(name)
    if candidate is None or status_code is not None:
        return None
    rebuilt = candidate(message)
    return rebuilt if str(rebuilt) == message else None


class ProviderCallReplayer:
    """Serve recorded responses by call identity and request digest.

    Byte-identical requests are common (parallel workers asking the same
    question for different scenarios), and their recorded responses differ.
    Keying on identity as well as digest gives each caller its own response
    whatever order threads arrive in; requests that share both are served in
    recorded sequence order.
    """

    def __init__(self, directory: Path) -> None:
        path = Path(directory) / RECORD_FILENAME
        records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        records.sort(key=lambda record: record["sequence"])
        self._pending: dict[str, deque[dict[str, Any]]] = defaultdict(deque)
        for record in records:
            key = _replay_key(record.get("identity"), record["request_sha256"])
            self._pending[key].append(record)
        self._lock = threading.Lock()
        self.unmatched: list[dict[str, Any]] = []

    def serve(self, digest: str, identity: CallIdentity | None) -> Any:
        """Return the recorded response for *digest* or raise the recorded error."""
        identity_record = identity.as_record() if identity else None
        with self._lock:
            queue = self._pending.get(_replay_key(identity_record, digest))
            record = queue.popleft() if queue else None
            if record is None:
                self.unmatched.append(
                    {"request_sha256": digest, "identity": identity_record}
                )
        if record is None:
            raise ReplayMissError(
                f"no recorded response for request {digest} issued by {identity_record}"
            )
        if record["outcome"] == "error":
            raise _rebuild_error(record["error"])
        from openai.types.chat import ChatCompletion

        return ChatCompletion.model_validate(record["response"]["body"])

    def unused(self) -> list[dict[str, Any]]:
        """Return recorded requests the replay never sent."""
        with self._lock:
            return [
                {
                    "sequence": record["sequence"],
                    "request_sha256": record["request_sha256"],
                    "identity": record["identity"],
                }
                for queue in self._pending.values()
                for record in queue
            ]


class ProviderCallSession:
    """Records every provider exchange and optionally serves them from a record."""

    def __init__(
        self,
        *,
        record_dir: Path | None,
        replayer: ProviderCallReplayer | None = None,
    ) -> None:
        self.record_dir = Path(record_dir) if record_dir is not None else None
        self.replayer = replayer
        self._lock = threading.Lock()
        self._local = threading.local()
        self._sequence = self._existing_records()

    @property
    def replaying(self) -> bool:
        return self.replayer is not None

    def _existing_records(self) -> int:
        if self.record_dir is None:
            return 0
        path = self.record_dir / RECORD_FILENAME
        if not path.exists():
            return 0
        with path.open(encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())

    def _next_sequence(self) -> int:
        with self._lock:
            self._sequence += 1
            return self._sequence

    def _write(self, attempt: _Attempt) -> None:
        if self.record_dir is None:
            return
        line = json.dumps(attempt.as_record(), ensure_ascii=False) + "\n"
        with self._lock:
            self.record_dir.mkdir(parents=True, exist_ok=True)
            with (self.record_dir / RECORD_FILENAME).open(
                "a", encoding="utf-8"
            ) as handle:
                handle.write(line)

    @contextmanager
    def scope(self) -> Iterator[None]:
        """Hold requests until the caller finishes locally validating the response.

        A response that the client later rejects (length stop, schema failure)
        is recorded with the rejection, because the request still happened.
        """
        pending: list[_Attempt] = []
        self._local.pending = pending
        try:
            yield
        except Exception as error:
            if pending and pending[-1].error is None:
                pending[-1].local_rejection = _error_record(error)
            raise
        finally:
            self._local.pending = None
            for attempt in pending:
                self._write(attempt)

    def exchange(
        self,
        *,
        api: str,
        request: Mapping[str, Any],
        send: Callable[[], Any],
    ) -> Any:
        """Perform one provider request through record and, if set, replay."""
        canonical = canonical_request(api, request)
        attempt = _Attempt(
            sequence=self._next_sequence(),
            identity=_IDENTITY.get(),
            request=canonical,
            digest=request_digest(canonical),
            timestamp=datetime.now(timezone.utc).isoformat(),
            started_ns=time.perf_counter_ns(),
        )
        pending = getattr(self._local, "pending", None)
        if pending is not None:
            pending.append(attempt)
        try:
            if self.replayer is not None:
                response = self.replayer.serve(attempt.digest, attempt.identity)
            else:
                response = send()
        except Exception as error:
            attempt.error = _error_record(error)
            raise
        else:
            attempt.response = _response_record(response)
            return response
        finally:
            attempt.duration_ms = (time.perf_counter_ns() - attempt.started_ns) // (
                1_000_000
            )
            if pending is None:
                self._write(attempt)


_ACTIVE: ProviderCallSession | None = None


def active_provider_session() -> ProviderCallSession | None:
    """Return the session that ``LLMClient`` should record through, if any."""
    return _ACTIVE


@contextmanager
def provider_call_session(
    *, record_dir: Path | None, replay_dir: Path | None = None
) -> Iterator[ProviderCallSession]:
    """Record provider requests into *record_dir*; serve them from *replay_dir*.

    The session is process-wide so concurrent worker threads share one sequence.
    A replay that sent a request the record lacks raises
    :class:`ReplayIncompleteError` on clean exit, because call sites catch and
    log provider errors and would otherwise hide the miss.
    """
    global _ACTIVE
    if (
        replay_dir is not None
        and record_dir is not None
        and Path(replay_dir).resolve() == Path(record_dir).resolve()
    ):
        raise ValueError("replay directory must differ from the record directory")
    replayer = (
        ProviderCallReplayer(Path(replay_dir)) if replay_dir is not None else None
    )
    session = ProviderCallSession(record_dir=record_dir, replayer=replayer)
    previous, _ACTIVE = _ACTIVE, session
    try:
        yield session
    finally:
        _ACTIVE = previous
    if replayer is not None and replayer.unmatched:
        raise ReplayIncompleteError(
            f"{len(replayer.unmatched)} request(s) had no recorded response: "
            f"{replayer.unmatched[:3]}"
        )
