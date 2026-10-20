"""The NIST and OWASP tags of each policy risk, shared across its name-merged group.

Several taxonomies can list one risk under the same name; policy coverage
merges them into one entry, which carries the tags of every entry it merged.
:func:`merged_risk_tags` is that rule. Policy coverage and the scenario
handoff's OWASP references both read it, so they cannot disagree.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from typing import Protocol

from asago_scenario_generator.data.risk_schemes import (
    SCHEMES,
    is_edition_scheme,
    is_no_match,
    scheme_label,
)
from asago_scenario_generator.data.sssom import SSSOMMapping

TAG_SCHEMES = SCHEMES

_CITATION = re.compile(r"\s*\([^()]*\d{4}[^()]*\)\s*$")


class NamedRisk(Protocol):
    """A risk card or risk reference: an id and a name."""

    @property
    def risk_id(self) -> str: ...

    @property
    def risk_name(self) -> str: ...


def display_name(name: str) -> str:
    """Drop a trailing literature citation such as ``(Slattery et al., 2024)``."""
    return _CITATION.sub("", name).strip()


def normalized_name(name: str) -> str:
    """The name risks merge under: no citation, lower case, single spaces."""
    return " ".join(display_name(name).lower().split())


def mapped_tags(sssom: Sequence[SSSOMMapping]) -> dict[str, list[dict[str, str]]]:
    """Each subject's own tags, sorted by scheme and id.

    ``noMatch`` rows and rows of other schemes give no tag. An OWASP row of
    another edition, in any spelling, raises ``ValueError``, as does an object
    id outside the scheme's vocabulary.
    """
    found: dict[str, list[dict[str, str]]] = {}
    for mapping in sssom:
        if mapping.object_source not in TAG_SCHEMES:
            if is_edition_scheme(mapping.object_source):
                raise ValueError(
                    f"mapping source {mapping.object_source!r} is not a current "
                    f"scheme; expected one of {sorted(TAG_SCHEMES)}"
                )
            continue
        if is_no_match(mapping.predicate_id):
            continue
        tag = {
            "scheme": mapping.object_source,
            "id": mapping.object_id,
            "label": scheme_label(mapping.object_source, mapping.object_id),
        }
        known = found.setdefault(mapping.subject_id, [])
        if tag not in known:
            known.append(tag)
    return {
        rid: sorted(tags, key=lambda t: (t["scheme"], t["id"]))
        for rid, tags in found.items()
    }


def merged_risk_tags(
    cards: Sequence[NamedRisk], sssom: Sequence[SSSOMMapping]
) -> dict[str, tuple[dict[str, str], ...]]:
    """Map every risk id to the tags of its name-merged group.

    Risks merge when their :func:`normalized_name` is equal. The group's tags
    are its members' tags in card order, each once; a risk without tags maps
    to an empty tuple.
    """
    own = mapped_tags(sssom)
    groups: dict[str, list[str]] = {}
    for card in cards:
        groups.setdefault(normalized_name(card.risk_name), []).append(card.risk_id)
    merged: dict[str, tuple[dict[str, str], ...]] = {}
    for risk_ids in groups.values():
        union: list[dict[str, str]] = []
        for risk_id in risk_ids:
            union.extend(tag for tag in own.get(risk_id, ()) if tag not in union)
        for risk_id in risk_ids:
            merged[risk_id] = tuple(union)
    return merged
