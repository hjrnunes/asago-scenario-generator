"""What a Stage 2 revision says it did with each critic gap, checked by code.

The revision reply gives one disposition per critic gap, keyed by the gap ID
code assigns in finding order (``G-1`` to ``G-n``).  An ``addressed``
disposition must name an element the published structure adds or changes;
``dismissed`` and ``recommendation`` leave the gap unchanged.  The check only
records what it finds: a gap without a disposition, a disposition for an
unknown gap, or an ``addressed`` claim that names no changed element is
unresolved.  It sends no request and never rejects the revision.
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.stpa.models.control_structure import ControlStructure

DISPOSITION_KINDS = ("addressed", "dismissed", "recommendation")
DispositionKind = Literal["addressed", "dismissed", "recommendation"]


class GapDisposition(BaseModel):
    """What the revision did with one critic gap."""

    model_config = ConfigDict(extra="forbid")

    gap_id: str
    disposition: DispositionKind
    element_ids: list[str] = Field(default_factory=list)
    justification: str


def critic_gap_ids(gap_count: int) -> list[str]:
    """Return the IDs of *gap_count* critic gaps, in finding order."""
    return [f"G-{number}" for number in range(1, gap_count + 1)]


@dataclass(frozen=True)
class UnresolvedGap:
    """A critic gap the revision neither changed nor genuinely set aside."""

    gap_id: str
    reason: str

    @property
    def warning(self) -> str:
        return f"Revision left critic gap {self.gap_id} unresolved: {self.reason}."


@dataclass(frozen=True)
class GapReview:
    """The disposition counts of a revision reply and its unresolved gaps."""

    counts: Mapping[str, int]
    unresolved: tuple[UnresolvedGap, ...]

    def record(self) -> dict[str, Any]:
        """Return the fields this review adds to the ``critic_revision`` record."""
        return {
            "gap_dispositions": {kind: self.counts[kind] for kind in DISPOSITION_KINDS},
            "unresolved_gaps": [
                {"gap_id": gap.gap_id, "reason": gap.reason} for gap in self.unresolved
            ],
        }


def review_gap_dispositions(
    dispositions: Sequence[GapDisposition],
    *,
    gap_count: int,
    changed_ids: frozenset[str],
    aliases: Mapping[str, frozenset[str]] | None = None,
) -> GapReview:
    """Check each disposition against the elements the revision changed.

    *changed_ids* are the published IDs of the elements the revision adds or
    changes.  *aliases* maps an ID the reply wrote to the published IDs it
    became, so a claim may name an element either way.
    """
    aliases = aliases or {}
    gap_ids = critic_gap_ids(gap_count)
    counts = {kind: 0 for kind in DISPOSITION_KINDS}
    by_gap: dict[str, list[GapDisposition]] = {}
    unknown: list[str] = []
    for item in dispositions:
        counts[item.disposition] += 1
        if item.gap_id in gap_ids:
            by_gap.setdefault(item.gap_id, []).append(item)
        elif item.gap_id not in unknown:
            unknown.append(item.gap_id)

    def changed(element_id: str) -> bool:
        return element_id in changed_ids or bool(
            aliases.get(element_id, frozenset()) & changed_ids
        )

    unresolved: list[UnresolvedGap] = []
    for gap_id in gap_ids:
        given = by_gap.get(gap_id)
        if not given:
            unresolved.append(UnresolvedGap(gap_id, "no disposition"))
            continue
        for item in given:
            if item.disposition != "addressed":
                continue
            if not item.element_ids:
                reason = "claimed addressed but named no element"
            elif not any(changed(element_id) for element_id in item.element_ids):
                reason = "claimed addressed but did not change " + ", ".join(
                    item.element_ids
                )
            else:
                continue
            unresolved.append(UnresolvedGap(gap_id, reason))
            break
    unresolved.extend(UnresolvedGap(gap_id, "unknown gap id") for gap_id in unknown)
    return GapReview(counts=counts, unresolved=tuple(unresolved))


def set_aside_warnings(dispositions: Iterable[GapDisposition]) -> list[str]:
    """Return the readable warning of each dismissal and recommendation."""
    warnings: list[str] = []
    for item in dispositions:
        if item.disposition == "dismissed":
            warnings.append(
                f"Revision dismissed finding {item.gap_id}: {item.justification}"
            )
        elif item.disposition == "recommendation":
            warnings.append(
                f"Revision dismissed finding {item.gap_id} as a design "
                f"recommendation: {item.justification}"
            )
    return warnings


def _children(responsibility: Any) -> Iterator[tuple[str, str, Any]]:
    """Yield ``(kind, id, element)`` for each child element of *responsibility*."""
    for kind, items, key in (
        ("RC", responsibility.responsibility_constraints, "rc_id"),
        ("PM", responsibility.process_model_parts, "pm_id"),
        ("CA", responsibility.control_actions, "ca_id"),
        ("FB", responsibility.feedback_channels, "fb_id"),
    ):
        for item in items:
            yield kind, getattr(item, key), item


def _elements(structure: ControlStructure) -> Iterator[tuple[tuple, str, Any]]:
    """Yield ``(position, id, element)`` for every identified element.

    The position names the element by its place in the structure, so two
    structures with the same list layout can be walked side by side.
    """
    for r_index, responsibility in enumerate(structure.responsibilities):
        yield ("RESP", r_index), responsibility.resp_id, responsibility
        counters: dict[str, int] = {}
        for kind, element_id, item in _children(responsibility):
            index = counters.get(kind, 0)
            counters[kind] = index + 1
            yield (kind, r_index, index), element_id, item
    for index, process in enumerate(structure.controlled_processes):
        yield ("CP", index), process.cp_id, process
    for index, link in enumerate(structure.coordination_links):
        yield ("CL", index), link.link_id, link
        mechanism = link.coordination_mechanism
        yield ("CM", index), mechanism.cm_id, mechanism


def _payloads(structure: ControlStructure) -> dict[str, list[Any]]:
    payloads: dict[str, list[Any]] = {}
    for _, element_id, element in _elements(structure):
        payloads.setdefault(element_id, []).append(element.model_dump(mode="json"))
    return payloads


def changed_element_ids(
    before: ControlStructure, after: ControlStructure
) -> frozenset[str]:
    """Return the IDs of the elements *after* adds or changes relative to *before*.

    A responsibility whose child changes is changed itself, and so is a link
    whose mechanism changes.
    """
    old = _payloads(before)
    return frozenset(
        element_id
        for element_id, payload in _payloads(after).items()
        if old.get(element_id) != payload
    )


def source_id_aliases(
    stitched: ControlStructure, merged: ControlStructure
) -> dict[str, frozenset[str]]:
    """Map each ID the reply wrote to the published IDs it became.

    *stitched* is the delta stitched onto the reviewed structure before
    normalization, and *merged* its normalized form; normalization keeps the
    list layout and assigns IDs from position.
    """
    published = {position: element_id for position, element_id, _ in _elements(merged)}
    aliases: dict[str, set[str]] = {}
    for position, element_id, _ in _elements(stitched):
        if position in published and isinstance(element_id, str):
            aliases.setdefault(element_id, set()).add(published[position])
    return {source: frozenset(ids) for source, ids in aliases.items()}


def unread_added_process_model_warnings(
    reviewed: ControlStructure, published: ControlStructure
) -> list[str]:
    """Warn about each process-model variable the revision added that no action reads.

    A variable is added when the reviewed structure has neither its ID nor a
    variable with the same description in the same responsibility.
    """
    reviewed_ids = {
        pm.pm_id
        for resp in reviewed.responsibilities
        for pm in resp.process_model_parts
    }
    reviewed_descriptions = {
        (resp.resp_id, " ".join(pm.description.split()).casefold())
        for resp in reviewed.responsibilities
        for pm in resp.process_model_parts
    }
    warnings: list[str] = []
    for resp in published.responsibilities:
        read = {ref for ca in resp.control_actions for ref in ca.process_model_refs}
        for pm in resp.process_model_parts:
            description = (resp.resp_id, " ".join(pm.description.split()).casefold())
            if (
                pm.pm_id in reviewed_ids
                or description in reviewed_descriptions
                or pm.pm_id in read
            ):
                continue
            warnings.append(
                f"Revision added process-model variable {pm.pm_id} "
                f"({pm.description}) that no control action reads."
            )
    return warnings
