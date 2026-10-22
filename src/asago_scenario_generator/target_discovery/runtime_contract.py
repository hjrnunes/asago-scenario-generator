"""Build a declared target's runtime contract from a shared base contract.

A declared target states its seed slots, and optionally its user-message
deliveries and limit overrides, instead of exposing a live endpoint. The
contract a consumer authors against is the shared base with those statements
applied.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

PLANTED_ITEM = "planted_item"


def declared_runtime_contract(
    base: Mapping[str, Any],
    *,
    seed_slots: Sequence[Mapping[str, Any]],
    delivery: Sequence[str] | None = None,
    limits: Mapping[str, int] | None = None,
) -> dict[str, Any]:
    """Return a declared target's runtime contract, built on a copy of ``base``.

    ``delivery`` replaces the base's deliveries when given. ``planted_item`` is
    never taken from either source: it is offered, last, exactly when at least
    one seed slot is declared. ``limits`` overrides single keys of the base's
    limits and keeps the rest. Each seed slot is already in the contract's form
    and is copied into a plain dict. Every other base key is carried over, and
    ``base`` is left unchanged.
    """

    contract = {key: value for key, value in base.items()}
    chosen = list(delivery) if delivery is not None else base.get("delivery", [])
    offered = [item for item in chosen if item != PLANTED_ITEM]
    if seed_slots:
        offered.append(PLANTED_ITEM)
    contract["delivery"] = offered
    contract["limits"] = {**base.get("limits", {}), **(limits or {})}
    contract["seed_slots"] = [dict(slot) for slot in seed_slots]
    return contract
