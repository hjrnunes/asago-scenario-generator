"""Safe projected step-ID echo normalization for projection-aware responses.

Projection-aware model responses may echo canonical step IDs in a small set
of transport shapes before strict validation.  This module normalizes those
echoes to the exact canonical IDs while preserving order:

- exact canonical string (``attacker.prepare`` -> ``attacker.prepare``)
- ``step_id`` record string (``step_id: attacker.prepare``)
- ``step.`` dotted prefix (``step.attacker.prepare`` -> ``attacker.prepare``)
- ``step_id`` object (``{"step_id": "attacker.prepare"}``)

Unknown identity, ambiguous nested prefixes, non-string values, nested
sequences, and duplicate canonical identities raise stable ``ValueError``
diagnostics (never ``TypeError``), so no defective artifact can be
finalized.
"""

from __future__ import annotations

from collections.abc import Collection, Sequence
from typing import Any

_ECHO_RECORD_PREFIX = "step_id: "
_STEP_PREFIX = "step."


def _raise_unknown_canonical_id(step_id: str, *, echoed: str | None = None) -> None:
    """Raise the stable unknown-identity ValueError, naming the original echo."""
    if echoed is None or echoed == step_id:
        raise ValueError(f"unknown canonical ID '{step_id}'")
    raise ValueError(f"unknown canonical ID '{step_id}' (echoed as '{echoed}')")


def _strip_record_prefix(value: str) -> tuple[str, bool]:
    """Split a ``step_id: `` record prefix into (inner, is_record)."""
    if value.startswith(_ECHO_RECORD_PREFIX):
        return value[len(_ECHO_RECORD_PREFIX) :].strip(), True
    return value, False


def _resolve_suffix_echo(value: str, canonical_ids: set[str], *, echoed: str) -> str:
    """Resolve one canonical or ``step.``-prefixed echo to a canonical ID.

    ``echoed`` carries the raw transport value so unknown-identity
    diagnostics name both the resolved suffix and the raw echo.
    """
    if value in canonical_ids:
        return value
    if value.startswith(_STEP_PREFIX):
        suffix = value[len(_STEP_PREFIX) :]
        if suffix in canonical_ids:
            return suffix
        _raise_unknown_canonical_id(suffix, echoed=echoed or value)
    _raise_unknown_canonical_id(value, echoed=echoed or None)


def _resolve_string_echo(
    value: str, canonical_ids: set[str], *, echoed: str = ""
) -> str:
    """Resolve one string echo to a canonical step ID or raise ValueError.

    ``echoed`` carries the original transport value so unknown-identity
    diagnostics name both the resolved suffix and the raw echo.
    """
    inner, is_record = _strip_record_prefix(value)
    if is_record:
        if inner.startswith(_STEP_PREFIX):
            raise ValueError(
                f"ambiguous prefix shape: '{value}' nests a 'step.' prefix "
                "inside a 'step_id: ' record"
            )
        return _resolve_string_echo(inner, canonical_ids, echoed=value)
    return _resolve_suffix_echo(value, canonical_ids, echoed=echoed)


def _resolve_echo_item(item: Any, canonical_ids: set[str]) -> str:
    """Resolve one raw transport item to a canonical step ID or raise ValueError."""
    if isinstance(item, dict):
        if "step_id" not in item:
            raise ValueError(
                f"unknown object shape: projected_step_ids item {item!r} is "
                "an object without a 'step_id' key"
            )
        value = item["step_id"]
        if not isinstance(value, str):
            raise ValueError(
                f"non-string step_id: projected_step_ids object has a "
                f"non-string 'step_id' value {value!r}"
            )
        return _resolve_string_echo(value, canonical_ids)
    if isinstance(item, str):
        return _resolve_string_echo(item, canonical_ids)
    if isinstance(item, (list, tuple)):
        raise ValueError(
            f"nested sequence shape: projected_step_ids item {item!r} is a "
            "sequence; nested lists are not accepted"
        )
    raise ValueError(
        f"non-string item: projected_step_ids item {item!r} is not a string "
        "or a step_id object"
    )


def normalize_projected_step_ids(
    items: Sequence[Any],
    canonical_ids: Collection[str],
) -> tuple[str, ...]:
    """Normalize transport echo items to canonical projected step IDs.

    Keeps the original order.  Raises a stable ``ValueError`` for unknown or
    ambiguous shapes, malformed items, or duplicate canonical identities —
    never ``TypeError``.
    """
    canonical = set(canonical_ids)
    resolved = tuple(_resolve_echo_item(item, canonical) for item in items)
    seen: set[str] = set()
    for step_id in resolved:
        if step_id in seen:
            raise ValueError(f"duplicate canonical step ID '{step_id}'")
        seen.add(step_id)
    return resolved
