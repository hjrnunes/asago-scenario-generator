"""Offline fixture translations shared by acceptance and unit tests.

These adapters never participate in product provider decoding.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any


def legacy_stage1a_provider_payload(
    payload: Any,
    *,
    risk: bool,
    preserve_gap_extras: bool = False,
) -> Any:
    """Translate a legacy domain fixture into the current provider wire.

    This is intentionally a test-boundary adapter.  Production provider
    parsing remains closed to canonical IDs and accepts only request-local
    ``handle`` fields.  Older SP1 fixtures are useful for exercising gate and
    repair behavior, so this helper translates their identity fields without
    validating or filling the payload. The historical risk-disposition
    collection is omitted for gap fixtures, whose current wire has no such
    field. Tests of out-of-contract gap fields supply current-wire fixtures
    directly. Other missing keys, wrong collection types, malformed rows,
    unknown references, and extra fields remain present.
    """
    if not isinstance(payload, dict):
        return payload

    # Current-wire fixtures can be registered directly while the migration is
    # in progress.  A handle anywhere in a graph is enough to leave the
    # response untouched; mixed or malformed current payloads must reach the
    # real closed validator unchanged.
    collections = (
        "risk_card_losses",
        "use_case_losses",
        "hazards",
        "security_constraints",
    )
    has_current_handle = False
    for collection in collections:
        rows = payload.get(collection)
        if isinstance(rows, list) and any(
            isinstance(row, dict) and "handle" in row for row in rows
        ):
            has_current_handle = True
            break
    if has_current_handle:
        return deepcopy(payload)

    translated = deepcopy(payload)

    def index_handles(
        collection: str,
        id_key: str,
        prefix: str,
        *,
        index_offset: int = 0,
    ) -> dict[str, str]:
        rows = payload.get(collection)
        if not isinstance(rows, list):
            return {}
        result: dict[str, str] = {}
        for index, row in enumerate(rows, index_offset + 1):
            if not isinstance(row, dict):
                continue
            old_id = row.get(id_key)
            if old_id is None and id_key != "loss_id":
                old_id = row.get("id")
            if isinstance(old_id, str):
                # Preserve duplicate identities as duplicate local handles so
                # the provider's duplicate-handle validator still catches the
                # malformed fixture instead of silently splitting it.
                result.setdefault(old_id, f"{prefix}_{index}")
        return result

    loss_handles: dict[str, str] = {}
    risk_loss_rows = payload.get("risk_card_losses")
    loss_handles.update(index_handles("risk_card_losses", "loss_id", "loss"))
    for old_id, handle in index_handles(
        "use_case_losses",
        "loss_id",
        "loss",
        index_offset=len(risk_loss_rows) if isinstance(risk_loss_rows, list) else 0,
    ).items():
        loss_handles.setdefault(old_id, handle)
    hazard_handles = index_handles("hazards", "hazard_id", "hazard")
    constraint_handles = index_handles(
        "security_constraints", "constraint_id", "constraint"
    )

    def translate_records(
        collection: str,
        id_key: str,
        handle_map: dict[str, str],
    ) -> None:
        rows = payload.get(collection)
        if not isinstance(rows, list):
            return
        output: list[Any] = []
        for row in rows:
            if not isinstance(row, dict):
                output.append(deepcopy(row))
                continue
            current = deepcopy(row)
            old_id = current.get(id_key)
            if old_id is None and id_key != "loss_id":
                old_id = current.get("id")
            if isinstance(old_id, str) and old_id in handle_map:
                current["handle"] = handle_map[old_id]
                current.pop(id_key, None)
                if id_key != "loss_id":
                    current.pop("id", None)
            output.append(current)
        translated[collection] = output

    for collection in ("risk_card_losses", "use_case_losses"):
        translate_records(collection, "loss_id", loss_handles)
    translate_records("hazards", "hazard_id", hazard_handles)
    translate_records("security_constraints", "constraint_id", constraint_handles)

    def translate_refs(collection: str, field: str, handles: dict[str, str]) -> None:
        rows = translated.get(collection)
        if not isinstance(rows, list):
            return
        for row in rows:
            if not isinstance(row, dict) or not isinstance(row.get(field), list):
                continue
            row[field] = [
                handles.get(reference, reference)
                if isinstance(reference, str)
                else reference
                for reference in row[field]
            ]

    translate_refs("hazards", "related_losses", loss_handles)
    translate_refs("security_constraints", "related_hazards", hazard_handles)

    if risk:
        dispositions = translated.get("risk_dispositions")
        if isinstance(dispositions, list):
            for row in dispositions:
                if not isinstance(row, dict) or not isinstance(
                    row.get("loss_ids"), list
                ):
                    continue
                row["loss_ids"] = [
                    loss_handles.get(reference, reference)
                    if isinstance(reference, str)
                    else reference
                    for reference in row["loss_ids"]
                ]
    elif preserve_gap_extras and translated.get("risk_dispositions") == []:
        translated.pop("risk_dispositions", None)
    elif preserve_gap_extras:
        # Explicit unit-test seam for malformed/out-of-contract gap rows.
        # Acceptance registrations use the default closed current wire.
        pass
    else:
        # Historical full-graph fixtures carried both stage collections.
        # Current gap responses have no risk-disposition field. Deliberately
        # malformed current responses return unchanged near the entry point.
        translated.pop("risk_dispositions", None)
    return translated
