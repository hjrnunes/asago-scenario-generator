"""Closed, target-only observations supplied to Stage 5.

The systemic STPA context remains target-blind.  This module accepts the
normalized capture boundary produced by the qualification tooling and keeps
only bounded state/read content plus the exact target-profile pairing.
Captured invocation metadata (the source name, description, and arguments
behind each read) may label its observation in a Stage 5 prompt as
invocation context (spec 4.1(4)); query hashes and capture diagnostics
remain deterministic bookkeeping and never enter a prompt.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any, ClassVar, Literal

from pydantic import Field, StrictStr, model_validator

from asago_scenario_generator.models.canonical import (
    ClosedCanonicalModel,
    canonical_json_bytes,
    compute_framed_digest,
)


SHA256_PATTERN = r"^[0-9a-f]{64}$"
TARGET_OBSERVATIONS_FILENAME = "target-observations.yaml"
TARGET_OBSERVATION_DIGEST_FRAME = (
    "asago-scenario-generator:target-observation-content:v1"
)
MAX_OBSERVATIONS = 16
MAX_CONTENT_CHARS = 16_384
MAX_JSON_DEPTH = 8
MAX_JSON_NODES = 256


class TargetObservation(ClosedCanonicalModel):
    """One bounded, quoted observation retained for Stage 5 reasoning."""

    observation_ref: StrictStr = Field(pattern=r"^TARGET-(?:STATE|READ-[0-9]{3})$")
    kind: Literal["state", "read"]
    source_name: StrictStr | None = Field(default=None, max_length=256)
    source_description: StrictStr | None = Field(default=None, max_length=4096)
    # Exact captured read-operation arguments (the query that produced this
    # observation).  Spec 4.1(4) labels every policy observation with the
    # query that produced it; the capture boundary supplies the mapping.
    source_arguments: dict[str, StrictStr] | None = None
    content_format: Literal["json", "text"]
    content: StrictStr = Field(min_length=1, max_length=MAX_CONTENT_CHARS)


class TargetObservationSnapshot(ClosedCanonicalModel):
    """Exact target pairing and bounded observation content for one run."""

    _digest_frame: ClassVar[str] = TARGET_OBSERVATION_DIGEST_FRAME

    target_profile_digest: StrictStr = Field(pattern=SHA256_PATTERN)
    observations: tuple[TargetObservation, ...] = Field(
        min_length=1, max_length=MAX_OBSERVATIONS
    )
    read_status: Literal["not_requested", "observed", "unavailable"] = "not_requested"
    content_digest: StrictStr = Field(pattern=SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_snapshot(self) -> "TargetObservationSnapshot":
        """Require one state record and an exact content digest."""
        refs = tuple(item.observation_ref for item in self.observations)
        if len(refs) != len(set(refs)):
            raise ValueError("target observation references must be unique")
        state_refs = tuple(item for item in self.observations if item.kind == "state")
        if len(state_refs) != 1 or state_refs[0].observation_ref != "TARGET-STATE":
            raise ValueError("target observations require exactly one TARGET-STATE")
        expected_refs = tuple(
            ["TARGET-STATE"]
            + [f"TARGET-READ-{index:03d}" for index in range(1, len(refs))]
        )
        if refs != expected_refs:
            raise ValueError(
                "target observation references must be in deterministic state/read order"
            )
        has_read = any(item.kind == "read" for item in self.observations)
        if self.read_status == "observed" and not has_read:
            raise ValueError("observed read_status requires a read observation")
        if has_read and self.read_status != "observed":
            raise ValueError("read observations require read_status=observed")
        if self.content_digest != self.compute_content_digest():
            raise ValueError("target observation content_digest does not match content")
        return self

    @classmethod
    def create(
        cls,
        *,
        target_profile_digest: str,
        observations: Sequence[TargetObservation],
        read_status: Literal["not_requested", "observed", "unavailable"] | None = None,
    ) -> "TargetObservationSnapshot":
        """Create a snapshot and derive its content digest deterministically."""
        if read_status is None:
            read_status = (
                "observed"
                if any(item.kind == "read" for item in observations)
                else "not_requested"
            )
        payload = {
            "target_profile_digest": target_profile_digest,
            "observations": [item.model_dump(mode="json") for item in observations],
            "read_status": read_status,
        }
        return cls.model_validate(
            {
                **payload,
                "read_status": read_status,
                "content_digest": compute_framed_digest(cls._digest_frame, payload),
            }
        )

    @classmethod
    def from_runtime_context(
        cls, payload: Mapping[str, Any]
    ) -> "TargetObservationSnapshot":
        """Parse normalized capture JSON without importing capture tooling.

        Only ``state``, ``read_observations``, and the exact top-level profile
        digest are semantic input.  Known capture bookkeeping is accepted so
        the parser can consume the qualification artifact, but it is excluded
        structurally rather than by business-field allowlists in prompts.
        """
        profile_digest = _runtime_profile_digest(payload)
        observations = [_state_observation(payload)]
        for index, raw in enumerate(_runtime_read_values(payload), start=1):
            observations.append(_read_observation(raw, index, profile_digest))
        return cls.create(
            target_profile_digest=profile_digest,
            observations=observations,
            read_status=_runtime_read_status(payload, has_reads=len(observations) > 1),
        )

    def compute_content_digest(self) -> str:
        """Return the digest over the exact pairing and retained content."""
        return compute_framed_digest(self._digest_frame, self._content_payload())

    def assert_integrity(self) -> None:
        """Raise if content has been changed after construction."""
        if self.content_digest != self.compute_content_digest():
            raise ValueError("target observation content_digest does not match content")

    def prompt_records(self) -> tuple[dict[str, str], ...]:
        """Return only quoted observation records for the provider prompt."""
        records: list[dict[str, str]] = []
        for item in self.observations:
            record = {
                "observation_ref": item.observation_ref,
                "kind": item.kind,
                "content_format": item.content_format,
                "content": item.content,
            }
            if item.source_name is not None:
                record["source_name"] = item.source_name
            if item.source_description is not None:
                record["source_description"] = item.source_description
            if item.source_arguments:
                record["query_label"] = ", ".join(
                    f"{key}: {value}"
                    for key, value in sorted(item.source_arguments.items())
                )
            records.append(record)
        return tuple(records)

    def source_texts(self) -> dict[str, str]:
        """Return exact observation text for comparison-evidence grounding."""
        return {item.observation_ref: item.content for item in self.observations}

    def _content_payload(self) -> dict[str, Any]:
        return {
            "target_profile_digest": self.target_profile_digest,
            "observations": [
                item.model_dump(mode="json") for item in self.observations
            ],
            "read_status": self.read_status,
        }


_RUNTIME_CONTEXT_FIELDS = frozenset(
    {
        "state",
        "read_observations",
        "target_profile_digest",
        "read_observation_input",
        "read_observation_diagnostics",
    }
)


def _runtime_profile_digest(payload: Mapping[str, Any]) -> str:
    """Validate the runtime-context envelope and return its profile digest."""
    if not isinstance(payload, Mapping):
        raise TypeError("target runtime context must be a mapping")
    unknown = sorted(set(payload) - _RUNTIME_CONTEXT_FIELDS)
    if unknown:
        raise ValueError(
            "target runtime context contains unsupported fields: " + ", ".join(unknown)
        )
    profile_digest = payload.get("target_profile_digest")
    if not isinstance(profile_digest, str) or not _is_sha256(profile_digest):
        raise ValueError("target runtime context requires target_profile_digest")
    return profile_digest


def _state_observation(payload: Mapping[str, Any]) -> TargetObservation:
    """Build the TARGET-STATE observation from the captured state object."""
    state = payload.get("state")
    if not isinstance(state, Mapping):
        raise ValueError("target runtime context state must be an object")

    # ``audit_log`` is capture telemetry, not target state that can ground
    # a Stage 5 comparison.  Remove that top-level telemetry record while
    # retaining every other state field verbatim and canonically.
    semantic_state = {key: value for key, value in state.items() if key != "audit_log"}
    return TargetObservation(
        observation_ref="TARGET-STATE",
        kind="state",
        content_format="json",
        content=_canonical_content(semantic_state, "state"),
    )


def _runtime_read_values(payload: Mapping[str, Any]) -> Sequence[Any]:
    """Return the bounded list of raw read observations."""
    read_values = payload.get("read_observations", ())
    if read_values is None:
        read_values = ()
    if not isinstance(read_values, Sequence) or isinstance(
        read_values, (str, bytes, bytearray)
    ):
        raise ValueError("target runtime context read_observations must be a list")
    if len(read_values) > MAX_OBSERVATIONS - 1:
        raise ValueError(
            f"target runtime context has more than {MAX_OBSERVATIONS - 1} read observations"
        )
    return read_values


def _read_observation(raw: Any, index: int, profile_digest: str) -> TargetObservation:
    """Validate one captured read and build its TARGET-READ observation."""
    if not isinstance(raw, Mapping):
        raise ValueError("each target read observation must be an object")
    nested_digest = raw.get("profile_digest")
    if nested_digest != profile_digest:
        raise ValueError(
            "target read observation profile_digest does not match "
            "target_profile_digest"
        )
    status = raw.get("status")
    if not isinstance(status, Mapping) or status.get("transport") != "verified":
        raise ValueError("target read observation transport must be verified")
    if status.get("content") != "untrusted":
        raise ValueError("target read observation content must be marked untrusted")
    content_format, content = _read_content(raw)
    source_name, source_description = _read_source_texts(raw)
    return TargetObservation(
        observation_ref=f"TARGET-READ-{index:03d}",
        kind="read",
        source_name=source_name,
        source_description=source_description,
        source_arguments=_read_source_arguments(raw),
        content_format=content_format,
        content=content,
    )


def _read_source_texts(raw: Mapping[str, Any]) -> tuple[str | None, str | None]:
    """Return the captured tool name and description, if present."""
    source_name = raw.get("tool_name")
    if source_name is not None and not isinstance(source_name, str):
        raise ValueError("target read observation tool_name must be text")
    source_description = raw.get("tool_description")
    if source_description is not None and not isinstance(source_description, str):
        raise ValueError("target read observation tool_description must be text")
    return source_name, source_description


def _read_source_arguments(raw: Mapping[str, Any]) -> dict[str, str] | None:
    """Return the captured invocation arguments as a string mapping."""
    source_arguments = raw.get("arguments")
    if source_arguments is None:
        return None
    if not isinstance(source_arguments, Mapping) or not all(
        isinstance(key, str) and isinstance(value, str)
        for key, value in source_arguments.items()
    ):
        raise ValueError("target read observation arguments must be a string mapping")
    return dict(source_arguments)


def _runtime_read_status(
    payload: Mapping[str, Any], *, has_reads: bool
) -> Literal["not_requested", "observed", "unavailable"]:
    """Distinguish observed reads, a failed read attempt, and no request."""
    if has_reads:
        return "observed"
    if (
        payload.get("read_observation_diagnostics")
        or payload.get("read_observation_input") is not None
    ):
        return "unavailable"
    return "not_requested"


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(char in "0123456789abcdef" for char in value)


def _canonical_content(value: object, label: str) -> str:
    """Canonicalize bounded JSON without interpreting its business meaning."""
    _validate_json_tree(value, label=label, depth=0, counter=[0])
    content = canonical_json_bytes(value).decode("utf-8")
    if len(content) > MAX_CONTENT_CHARS:
        raise ValueError(
            f"target observation {label} exceeds {MAX_CONTENT_CHARS} characters"
        )
    return content


def _validate_json_tree(
    value: object,
    *,
    label: str,
    depth: int,
    counter: list[int],
) -> None:
    if depth > MAX_JSON_DEPTH:
        raise ValueError(f"target observation {label} exceeds JSON depth limit")
    counter[0] += 1
    if counter[0] > MAX_JSON_NODES:
        raise ValueError(f"target observation {label} exceeds JSON node limit")
    if value is None or isinstance(value, (str, bool, int, float)):
        return
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ValueError(f"target observation {label} has a non-string JSON key")
        for key, item in value.items():
            _validate_json_tree(
                item, label=f"{label}.{key}", depth=depth + 1, counter=counter
            )
        return
    if isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            _validate_json_tree(
                item,
                label=f"{label}[{index}]",
                depth=depth + 1,
                counter=counter,
            )
        return
    raise ValueError(f"target observation {label} contains a non-JSON value")


def _read_content(raw: Mapping[str, Any]) -> tuple[Literal["json", "text"], str]:
    """Extract returned observation content, excluding capture bookkeeping."""
    result = raw.get("result")
    if not isinstance(result, Mapping):
        raise ValueError("target read observation requires a result object")
    if result.get("isError") is True:
        raise ValueError("target read observation contains an unsuccessful result")
    structured = result.get("structuredContent")
    if structured is not None:
        value = _unwrap_result_envelope(structured)
        if isinstance(value, str):
            return "text", _bounded_text(value, "read result")
        return "json", _canonical_content(value, "read result")
    blocks = result.get("content")
    if not isinstance(blocks, Sequence) or isinstance(blocks, (str, bytes, bytearray)):
        raise ValueError(
            "target read observation result requires content or structuredContent"
        )
    texts = [
        item.get("text")
        for item in blocks
        if isinstance(item, Mapping)
        and item.get("type") == "text"
        and isinstance(item.get("text"), str)
    ]
    if not texts:
        raise ValueError("target read observation has no textual returned content")
    text = "\n".join(texts)
    if len(text) > MAX_CONTENT_CHARS:
        raise ValueError(
            f"target read observation exceeds {MAX_CONTENT_CHARS} characters"
        )
    try:
        decoded = json.loads(text)
    except json.JSONDecodeError:
        return "text", text
    decoded = _unwrap_result_envelope(decoded)
    if isinstance(decoded, str):
        return "text", _bounded_text(decoded, "read result")
    return "json", _canonical_content(decoded, "read result")


def _unwrap_result_envelope(value: object) -> object:
    """Unwrap one MCP ``result`` envelope and decode one JSON string.

    MCP adapters commonly return ``{"result": "{...}"}`` inside
    ``structuredContent``.  That wrapper is transport shape, not a target
    fact; retaining it would make the model quote an escaped JSON string.
    One unwrap/decode pass is enough and avoids interpreting arbitrary text as
    a second document.
    """
    if isinstance(value, Mapping) and set(value) == {"result"}:
        value = value["result"]
    if isinstance(value, str):
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return value
    return value


def _bounded_text(value: str, label: str) -> str:
    if not value or len(value) > MAX_CONTENT_CHARS:
        raise ValueError(
            f"target observation {label} exceeds {MAX_CONTENT_CHARS} characters"
        )
    return value


__all__ = [
    "MAX_CONTENT_CHARS",
    "MAX_OBSERVATIONS",
    "TARGET_OBSERVATIONS_FILENAME",
    "TargetObservation",
    "TargetObservationSnapshot",
]
