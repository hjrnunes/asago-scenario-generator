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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T21:54:09Z","module_hash":"310a71499effd2301c126cab2cabeee93c2fd34f386f60808f3a7db05b2bd1cc","source_sha256":"2ecabf7bcced1cdef98b481fe481b7f7acee8dea2d717e9b05898866f34708d0","functions":[{"id":"func/_normalize_collection","name":"_normalize_collection","line":49,"end_line":54,"hash":"7802ff5b45575cf87b15589a8f2079e09a8c1122435ecbde9a94bb81d24be115"},{"id":"func/_normalize_model","name":"_normalize_model","line":57,"end_line":59,"hash":"c2caeed1a8f31caea782706bba3dc7e805871f02c8dd67ac0de217801035cdd1"},{"id":"func/_normalize","name":"_normalize","line":62,"end_line":74,"hash":"3bbaf6c8cdfc0018f8220a32fc96ee5c127e36e265a06b67c0d819d193a9324b"},{"id":"func/_canonical_json","name":"_canonical_json","line":77,"end_line":84,"hash":"64694bcd2220c1863e11a12b4364f96fe81b5ebe00172615bc437293e5be4be9"},{"id":"func/_semantic_digest","name":"_semantic_digest","line":87,"end_line":93,"hash":"a943f75a767d1d97a2a58ba0f592e16f43851f260620a693a5a59899bb6c5438"},{"id":"func/_frame_laaf_axis","name":"_frame_laaf_axis","line":96,"end_line":101,"hash":"0ea630946ccf2270e699a85134bc99cc3a6552b1aec34bdfa2133b63353aa4c6"},{"id":"func/_keep_slot_constraint","name":"_keep_slot_constraint","line":119,"end_line":121,"hash":"e3715cb2c2f9acffa89b0df9e95ae1ea3a6b12df6bcd0b7aa3cb7238a1b6c6a9"},{"id":"func/_strip_slot_dict","name":"_strip_slot_dict","line":124,"end_line":128,"hash":"1cad378a395788e39d64847bb8b6feea03cf6e5174ab202c9c2d9dce1dd5b5f6"},{"id":"func/_strip_slot_constraints","name":"_strip_slot_constraints","line":131,"end_line":137,"hash":"33d0be20b43138e9a4c69fa0a06d2dcca76dbf56acc36b9df1074ab63efed296"},{"id":"func/_frame_chain_slots","name":"_frame_chain_slots","line":140,"end_line":144,"hash":"eb856f22ee9f6752ecfdbce18660463c4b4e76480fda2d510dd729ae9c604842"},{"id":"func/_framed_link_entry","name":"_framed_link_entry","line":147,"end_line":162,"hash":"2694f3ed255523597b2a722263e3d4f3199299ad9f6fc5c23081be058f4d303f"},{"id":"func/_frame_chain_link_entries","name":"_frame_chain_link_entries","line":165,"end_line":173,"hash":"b5c60ecdb4ea0c10b2b78e12c2ab65e13b3f7001fd80f8e1f6954cff6d3d6eb6"},{"id":"func/_frame_chain_step_list","name":"_frame_chain_step_list","line":176,"end_line":192,"hash":"ef295a9bd0a01fba9926a571689b20bf40b1082f75b775d5419402769572ceb5"},{"id":"func/_frame_chain_steps","name":"_frame_chain_steps","line":195,"end_line":199,"hash":"91f67c7af57cd8c0221da0931f79ce7bb8c632e13840595068399cac85c4fdcb"},{"id":"func/compute_chain_semantic_digest","name":"compute_chain_semantic_digest","line":202,"end_line":226,"hash":"8468bfe01c04b765a65977a41f69fd7e6105ff4b22768ebb08fd19432992a484"},{"id":"func/_stripped_link_entry","name":"_stripped_link_entry","line":229,"end_line":235,"hash":"33b221190996deeab6648c415b4a95ffe488effb8f802c1b4d22a5dd1a4a41fa"},{"id":"func/_frame_projection_link_entries","name":"_frame_projection_link_entries","line":238,"end_line":246,"hash":"4a459cbafb69d58c73b0cc4eceb0c57c5829300eb5c82f928d93b6979682bdd8"},{"id":"func/_frame_projection_slots","name":"_frame_projection_slots","line":249,"end_line":257,"hash":"ea066d8cc157b01bde08fcd36c5c7be5ff061b9775e6af47150536abbedf6de5"},{"id":"func/_frame_projection_steps","name":"_frame_projection_steps","line":260,"end_line":278,"hash":"6dc7ee5a620eb3a74131d82a5c543cec12d414baa092ed6324c57968e718d02e"},{"id":"func/_frame_projection_source","name":"_frame_projection_source","line":281,"end_line":288,"hash":"510a377f309f033f1b3903bcd507ba1584db90057b6413d076a73252b3068371"},{"id":"func/_drop_empty_relation_paths","name":"_drop_empty_relation_paths","line":291,"end_line":296,"hash":"05dbdbc680f359a057f196c7bc32de302be9a9822b9cbc10dd2e5dc2845c9639"},{"id":"func/compute_projection_digest","name":"compute_projection_digest","line":299,"end_line":314,"hash":"ce3bf7513667c6a283517e87b0b7842c4900e3b1ecf1296261c7180c737c0647"}]}
# mutate4py-manifest-end
