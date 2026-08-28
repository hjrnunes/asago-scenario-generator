"""Canonical serialization and semantic digest implementations."""

from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

if TYPE_CHECKING:
    from .attack_pattern_chain import CanonicalAttackChain
    from .attack_pattern_projection import ProjectionSnapshot


_UNORDERED_FIELDS = {
    "allowed_entry_point_controllability",
    "allowed_entry_point_directions",
    "allowed_entry_point_ingress_zones",
    "allowed_entry_point_types",
    "allowed_integration_types",
    "allowed_resource_ids",
    "allowed_trust_boundary_from_zones",
    "allowed_trust_boundary_to_zones",
    "consumed",
    "produced",
    "preconditions",
    "observable_postconditions",
    "references",
    "mappings",
    "ids",
    "resource_slots",
    "values",
    "evidence",
    "condition_results",
    "distinct_from_slot_ids",
    "omissions",
    "bindings",
    "requirements",
    "contributing_step_ids",
    "operands",
    "min_zones",
    "resource_links",
    "observable_outcome_links",
}


def _normalize_collection(value: tuple | list, field_name: str | None) -> list:
    """Normalize each item; unordered fields are sorted by canonical form."""
    items = [_normalize(item) for item in value]
    if field_name in _UNORDERED_FIELDS:
        items.sort(key=lambda item: _canonical_json(item).encode())
    return items


def _normalize_model(value: BaseModel) -> dict:
    """Python-mode dump of a model for canonicalization."""
    return value.model_dump(mode="python")


def _normalize(value: Any, field_name: str | None = None) -> Any:
    if isinstance(value, BaseModel):
        value = _normalize_model(value)
    if isinstance(value, dict):
        return {
            unicodedata.normalize("NFC", str(k)): _normalize(v, str(k))
            for k, v in value.items()
        }
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (tuple, list)):
        return _normalize_collection(value, field_name)
    return value


def _canonical_json(value: Any) -> str:
    return json.dumps(
        _normalize(value),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _semantic_digest(value: Any, digest_field: str, domain: str) -> str:
    payload = (
        value.model_dump(mode="python") if isinstance(value, BaseModel) else dict(value)
    )
    payload.pop(digest_field, None)
    encoded = domain.encode() + b"\0" + _canonical_json(payload).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _frame_laaf_axis(payload: dict[str, Any]) -> dict[str, Any]:
    """Frame the optional LAAF axis: omitted laaf equals explicit null."""
    context = payload.get("taxonomy_context")
    if isinstance(context, dict) and "laaf" not in context:
        payload["taxonomy_context"] = {**context, "laaf": None}
    return payload


_SLOT_CONSTRAINT_FIELDS = frozenset(
    {
        "allowed_integration_types",
        "allowed_entry_point_types",
        "allowed_entry_point_directions",
        "allowed_entry_point_controllability",
        "allowed_entry_point_ingress_zones",
        "allowed_trust_boundary_from_zones",
        "allowed_trust_boundary_to_zones",
        "allowed_resource_ids",
        "distinct_from_slot_ids",
    }
)


def _keep_slot_constraint(key: str, value: Any) -> bool:
    """Keep non-constraint keys and every non-empty constraint value."""
    return key not in _SLOT_CONSTRAINT_FIELDS or bool(value)


def _strip_slot_dict(slot: dict) -> dict:
    """One slot dict with empty constraint fields removed."""
    return {
        key: value for key, value in slot.items() if _keep_slot_constraint(key, value)
    }


def _strip_slot_constraints(slots: Any) -> Any:
    """Drop empty constraint fields from slot dicts (never mutates input)."""
    if not isinstance(slots, (list, tuple)):
        return slots
    return [
        _strip_slot_dict(slot) if isinstance(slot, dict) else slot for slot in slots
    ]


def _frame_chain_slots(payload: dict[str, Any]) -> None:
    """Strip empty resource constraints when the payload carries slots."""
    slots = payload.get("resource_slots")
    if isinstance(slots, (list, tuple)):
        payload["resource_slots"] = _strip_slot_constraints(slots)


def _framed_link_entry(link: dict) -> dict:
    """One resource link with optional fields framed as model defaults."""
    return {
        **{
            key: value
            for key, value in link.items()
            if key != "source_identity_kind" or value is not None
        },
        "trust_boundary_slot_id": link.get("trust_boundary_slot_id"),
        "target_ingress_slot_id": link.get("target_ingress_slot_id"),
        **(
            {"source_identity_kind": link["source_identity_kind"]}
            if link.get("source_identity_kind") is not None
            else {}
        ),
    }


def _frame_chain_link_entries(links: list | tuple) -> list:
    """Frame optional None fields on one step's resource links."""
    entries = []
    for link in links:
        if not isinstance(link, dict):
            entries.append(link)
            continue
        entries.append(_framed_link_entry(link))
    return entries


def _frame_chain_step_list(steps: list | tuple) -> list:
    """Frame optional link arrays on each chain step dict."""
    normalized_steps = []
    for step in steps:
        if not isinstance(step, dict):
            normalized_steps.append(step)
            continue
        step = {
            **step,
            "resource_links": step.get("resource_links", []),
            "observable_outcome_links": step.get("observable_outcome_links", []),
        }
        links = step["resource_links"]
        if isinstance(links, (list, tuple)):
            step = {**step, "resource_links": _frame_chain_link_entries(links)}
        normalized_steps.append(step)
    return normalized_steps


def _frame_chain_steps(payload: dict[str, Any]) -> None:
    """Frame step link arrays when the payload carries steps."""
    steps = payload.get("steps")
    if isinstance(steps, (list, tuple)):
        payload["steps"] = _frame_chain_step_list(steps)


def compute_chain_semantic_digest(chain: CanonicalAttackChain | dict[str, Any]) -> str:
    payload = (
        chain.model_dump(mode="python") if isinstance(chain, BaseModel) else dict(chain)
    )
    # Canonicalize the optional LAAF axis: an omitted ``laaf`` key in
    # ``taxonomy_context`` frames exactly like the explicit ``None`` that
    # model validation materializes, so a caller may sign a raw dict that
    # omits the key and still pass validation.  Never mutates ``chain``.
    _frame_laaf_axis(payload)
    # Empty resource constraints are unconstrained and were absent from
    # chains signed before these generic constraints existed. Keep omitted
    # and explicitly empty constraints byte-equivalent while signing every
    # non-empty constraint.
    _frame_chain_slots(payload)
    # Canonicalize optional linkage fields: a raw dict may omit
    # ``trust_boundary_slot_id`` / ``target_ingress_slot_id`` on a
    # resource link where model validation materializes ``None``, and may
    # omit ``resource_links`` / ``observable_outcome_links`` arrays where
    # model validation materializes empty tuples.  Frame omitted and
    # explicit-None/[] identically so callers can sign raw dicts that omit
    # the defaults.  Never mutates ``chain``.
    _frame_chain_steps(payload)
    return _semantic_digest(
        payload, "semantic_digest", "asago-scenario-generator:canonical-chain:v1"
    )


def _stripped_link_entry(link: dict) -> dict:
    """One resource link with null source_identity_kind removed."""
    return {
        key: value
        for key, value in link.items()
        if key != "source_identity_kind" or value is not None
    }


def _frame_projection_link_entries(links: Any) -> list:
    """Strip source_identity_kind entries from one step's resource links."""
    entries = []
    for link in links:
        if not isinstance(link, dict):
            entries.append(link)
            continue
        entries.append(_stripped_link_entry(link))
    return entries


def _frame_projection_slots(source_chain: dict) -> dict:
    """The source chain with empty resource constraints stripped."""
    resource_slots = source_chain.get("resource_slots")
    if isinstance(resource_slots, (list, tuple)):
        return {
            **source_chain,
            "resource_slots": _strip_slot_constraints(resource_slots),
        }
    return source_chain


def _frame_projection_steps(source_chain: dict) -> dict:
    """The source chain with step link fields framed."""
    steps = source_chain.get("steps")
    if isinstance(steps, (list, tuple)):
        return {
            **source_chain,
            "steps": [
                {
                    **step,
                    "resource_links": _frame_projection_link_entries(
                        step.get("resource_links", ())
                    ),
                }
                if isinstance(step, dict)
                else step
                for step in steps
            ],
        }
    return source_chain


def _frame_projection_source(payload: dict[str, Any]) -> None:
    """Frame the embedded source chain: constraints and link fields."""
    source_chain = payload.get("source_chain")
    if not isinstance(source_chain, dict):
        return
    payload["source_chain"] = _frame_projection_steps(
        _frame_projection_slots(source_chain)
    )


def _drop_empty_relation_paths(payload: dict[str, Any]) -> None:
    """Frame empty relation paths as absent (backwards-compatible default)."""
    if payload.get("source_influence_paths") == ():
        payload.pop("source_influence_paths", None)
    elif payload.get("source_influence_paths") == []:
        payload.pop("source_influence_paths", None)


def compute_projection_digest(snapshot: ProjectionSnapshot | dict[str, Any]) -> str:
    payload = (
        snapshot.model_dump(mode="python")
        if isinstance(snapshot, BaseModel)
        else dict(snapshot)
    )
    # Empty resource constraints and optional link fields frame like the
    # model materialization.  Never mutates ``snapshot``.
    _frame_projection_source(payload)
    # Empty relation paths are the backwards-compatible direct-ingress
    # default.  Keep their digest equivalent to pre-relation snapshots while
    # binding a non-empty authoritative path into the new digest.
    _drop_empty_relation_paths(payload)
    return _semantic_digest(
        payload, "projection_digest", "asago-scenario-generator:projection:v1"
    )
