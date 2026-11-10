"""The scenario-handoff saved-artifact migration: v5 -> v6.

Version 6 renamed ``attack_shape.indirect.party_relation.controller`` to
``controlling_party``. The migration renames the field, advances the document to
the v6 schema version, and recomputes ``content_digest`` under the v6 domain. It
leaves every other value as the v5 document states it, including the source text
of the ``producer handoff contract`` fact, which a v6 writer states as v6. A
handoff without the digest gains one, as the producer's writer always adds it.

The producer imports ``asago_handoff``, so importing this module registers the
hop with the shared core. Only the handoff owner defines the migration; the core
applies it.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from asago_contracts_core import (
    CONTRACT,
    HANDOFF_SCHEMA_VERSION_V6,
    KIT_V5,
    KIT_V6,
    PRODUCER_ENCODING,
    framed_digest,
    register_upgrade,
)


def _v5_to_v6(document: Mapping[str, Any]) -> dict[str, Any]:
    body = dict(document)
    body["schema_version"] = HANDOFF_SCHEMA_VERSION_V6
    attack_shape = body.get("attack_shape")
    if isinstance(attack_shape, Mapping):
        indirect = attack_shape.get("indirect")
        if isinstance(indirect, Mapping):
            relation = indirect.get("party_relation")
            if isinstance(relation, Mapping) and "controller" in relation:
                renamed = dict(relation)
                renamed["controlling_party"] = renamed.pop("controller")
                indirect = {**indirect, "party_relation": renamed}
                body["attack_shape"] = {**attack_shape, "indirect": indirect}
    payload = {key: value for key, value in body.items() if key != "content_digest"}
    body["content_digest"] = framed_digest(
        HANDOFF_SCHEMA_VERSION_V6, payload, encoding=PRODUCER_ENCODING
    )
    return body


HANDOFF_UPGRADE = register_upgrade(CONTRACT, KIT_V5, KIT_V6, _v5_to_v6)
