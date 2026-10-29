"""What a Stage 2 revision says it did with each critic gap, checked by code.

The revision reply gives one disposition per critic gap, keyed by the gap ID
code assigns in finding order (``G-1`` to ``G-n``).  An ``addressed``
disposition must name an element the published structure adds or changes;
``dismissed`` and ``recommendation`` leave the gap unchanged.  The check only
records what it finds: a gap without a disposition or with more than one, a
disposition for an unknown gap, or an ``addressed`` claim that names no
element changed for it is unresolved.  It sends no request and never rejects the revision.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlledProcess,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    Responsibility,
    ResponsibilityConstraint,
)

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


@dataclass(frozen=True)
class ElementChanges:
    """The elements a revision adds or changes, by published ID.

    ``members`` maps each responsibility and link to the published IDs of the
    elements it holds (a responsibility's children, a link's mechanism), in
    structure order.  ``member_changes`` maps each element that changed only
    through those members to the changed ones; an element whose own fields
    changed, that is new, or that lost a member is not in it.
    """

    ids: frozenset[str]
    members: Mapping[str, tuple[str, ...]] = MappingProxyType({})
    member_changes: Mapping[str, tuple[str, ...]] = MappingProxyType({})


def review_gap_dispositions(
    dispositions: Sequence[GapDisposition],
    *,
    gap_count: int,
    changes: ElementChanges,
    written: Mapping[str, frozenset[str]] | None = None,
) -> GapReview:
    """Check each disposition against the elements the revision changed.

    *changes* holds the published IDs of the elements the revision adds or
    changes, and of the elements each responsibility or link holds.
    *written* maps each ID the reply wrote to the published IDs of the
    elements it wrote under that ID (see :class:`RevisionIdentity`).  A
    claimed ID the reply wrote names those elements; any other claimed ID is
    read as a published ID.

    A claim that names a responsibility or link together with elements it
    holds is judged by those elements.  Named alone, it supports the claim
    when it changed on its own, or through a changed member no other gap's
    ``addressed`` claim names: a member another gap names is that gap's
    change.  A gap given more than one disposition is unresolved, and none of
    its dispositions is counted.
    """
    written = written or {}
    gap_ids = critic_gap_ids(gap_count)
    by_gap: dict[str, list[GapDisposition]] = {}
    unknown: list[str] = []
    for item in dispositions:
        if item.gap_id in gap_ids:
            by_gap.setdefault(item.gap_id, []).append(item)
        elif item.gap_id not in unknown:
            unknown.append(item.gap_id)
    counts = {kind: 0 for kind in DISPOSITION_KINDS}
    for item in dispositions:
        if len(by_gap.get(item.gap_id, ())) <= 1:
            counts[item.disposition] += 1

    def published(element_id: str) -> frozenset[str]:
        return written.get(element_id, frozenset({element_id}))

    # The gaps whose ``addressed`` claim names each published ID.
    naming: dict[str, list[str]] = {}
    for item in dispositions:
        if item.disposition == "addressed":
            for element_id in item.element_ids:
                for target in published(element_id):
                    gaps = naming.setdefault(target, [])
                    if item.gap_id not in gaps:
                        gaps.append(item.gap_id)

    unresolved: list[UnresolvedGap] = []
    for gap_id in gap_ids:
        given = by_gap.get(gap_id)
        if not given:
            unresolved.append(UnresolvedGap(gap_id, "no disposition"))
            continue
        if len(given) > 1:
            unresolved.append(
                UnresolvedGap(
                    gap_id,
                    f"gave {len(given)} dispositions: "
                    + ", ".join(_described(item) for item in given),
                )
            )
            continue
        [item] = given
        if item.disposition != "addressed":
            continue
        if not item.element_ids:
            unresolved.append(
                UnresolvedGap(gap_id, "claimed addressed but named no element")
            )
            continue
        reason = _unsupported_claim(item, published, changes, naming)
        if reason is not None:
            unresolved.append(UnresolvedGap(gap_id, reason))
    unresolved.extend(UnresolvedGap(gap_id, "unknown gap id") for gap_id in unknown)
    return GapReview(counts=counts, unresolved=tuple(unresolved))


def _described(item: GapDisposition) -> str:
    if not item.element_ids:
        return item.disposition
    return f"{item.disposition} ({', '.join(item.element_ids)})"


def _unsupported_claim(
    item: GapDisposition,
    published: Callable[[str], frozenset[str]],
    changes: ElementChanges,
    naming: Mapping[str, Sequence[str]],
) -> str | None:
    """Say why an ``addressed`` claim changed nothing it names, or ``None``."""
    named = {
        target for element_id in item.element_ids for target in published(element_id)
    }
    unchanged: list[str] = []
    elsewhere: list[str] = []
    for element_id in item.element_ids:
        targets = sorted(published(element_id) & changes.ids)
        if not targets:
            unchanged.append(element_id)
            continue
        for target in targets:
            held = [m for m in changes.members.get(target, ()) if m in named]
            if held:
                elsewhere.append(f"{element_id} changed only outside {', '.join(held)}")
                continue
            if target not in changes.member_changes:
                return None
            members = changes.member_changes[target]
            if any(set(naming.get(m, ())) <= {item.gap_id} for m in members):
                return None
            gaps = list(dict.fromkeys(gap for m in members for gap in naming[m]))
            elsewhere.append(
                f"{element_id} changed only in {', '.join(members)}, which "
                f"{', '.join(gaps)} {'names' if len(gaps) == 1 else 'name'}"
            )
    parts = []
    if unchanged:
        parts.append("did not change " + ", ".join(unchanged))
    parts.extend(elsewhere)
    return "claimed addressed but " + "; ".join(parts)


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


_CHILD_LISTS = (
    ("RC", "responsibility_constraints", "rc_id"),
    ("PM", "process_model_parts", "pm_id"),
    ("CA", "control_actions", "ca_id"),
    ("FB", "feedback_channels", "fb_id"),
)

# An element's identity: ``("reviewed", id)`` for an element of the reviewed
# structure, under its reviewed ID; ``("new", ...)`` for an element the
# revision added, keyed by its place in the merged structure.
Identity = tuple[Any, ...]


def _reviewed(element_id: str) -> Identity:
    return ("reviewed", element_id)


@dataclass(frozen=True)
class RevisionIdentity:
    """Which element each published ID is, across the merge's renumbering.

    Normalization numbers elements by position, so an inserted element can
    take the published ID an existing one had, and the existing one moves to
    another.  ``identities`` maps each published ID of the merged structure to
    its element's identity.  ``written`` maps each ID the reply wrote for an
    element it restated or added to the published IDs of those elements.
    """

    identities: Mapping[str, Identity]
    written: Mapping[str, frozenset[str]]

    @classmethod
    def unchanged(cls, structure: ControlStructure) -> RevisionIdentity:
        """The identity of a structure no reply changed: each ID is its own."""
        identities: dict[str, Identity] = {}
        for responsibility in structure.responsibilities:
            identities[responsibility.resp_id] = _reviewed(responsibility.resp_id)
            for _, items, key in _CHILD_LISTS:
                for item in getattr(responsibility, items):
                    identities[getattr(item, key)] = _reviewed(getattr(item, key))
        for process in structure.controlled_processes:
            identities[process.cp_id] = _reviewed(process.cp_id)
        for link in structure.coordination_links:
            identities[link.link_id] = _reviewed(link.link_id)
            cm_id = link.coordination_mechanism.cm_id
            identities[cm_id] = _reviewed(cm_id)
        return cls(identities=identities, written={})


def revision_identity(
    reviewed: ControlStructure,
    stitched: ControlStructure,
    merged: ControlStructure,
    *,
    restated_ids: frozenset[str],
    written_mechanism_ids: Mapping[str, str],
) -> RevisionIdentity:
    """Follow each element from the reply to the merged structure.

    *stitched* is the reply stitched onto *reviewed*: the reviewed
    responsibilities in order, those in *restated_ids* replaced by the
    reply's restatement, then the new responsibilities; the reviewed
    processes and links, then the new ones.  *merged* is its normalized form,
    which keeps that layout.  A restated responsibility's child is the
    reviewed child of that responsibility with the ID the reply wrote, if
    there is one, and new otherwise.  *written_mechanism_ids* maps each new
    link's ID to the mechanism ID the reply wrote, which the stitch may have
    renumbered to avoid a collision.
    """
    identities: dict[str, Identity] = {}
    written: dict[str, set[str]] = {}

    def record(published: str, identity: Identity, written_id: Any) -> None:
        identities[published] = identity
        if isinstance(written_id, str):
            written.setdefault(written_id, set()).add(published)

    reviewed_children = {
        responsibility.resp_id: {
            kind: {getattr(item, key) for item in getattr(responsibility, items)}
            for kind, items, key in _CHILD_LISTS
        }
        for responsibility in reviewed.responsibilities
    }
    kept = len(reviewed.responsibilities)
    for r_index, (source, target) in enumerate(
        zip(stitched.responsibilities, merged.responsibilities)
    ):
        is_new = r_index >= kept
        restated = not is_new and source.resp_id in restated_ids
        record(
            target.resp_id,
            ("new", "RESP", r_index) if is_new else _reviewed(source.resp_id),
            source.resp_id if is_new or restated else None,
        )
        known = {} if is_new else reviewed_children.get(source.resp_id, {})
        for kind, items, key in _CHILD_LISTS:
            claimed: set[str] = set()
            for index, (child, published) in enumerate(
                zip(getattr(source, items), getattr(target, items))
            ):
                child_id = getattr(child, key)
                identity: Identity = ("new", kind, r_index, index)
                if child_id in known.get(kind, ()) and child_id not in claimed:
                    claimed.add(child_id)
                    identity = _reviewed(child_id)
                record(
                    getattr(published, key),
                    identity,
                    child_id if is_new or restated else None,
                )
    kept = len(reviewed.controlled_processes)
    for index, (source, target) in enumerate(
        zip(stitched.controlled_processes, merged.controlled_processes)
    ):
        is_new = index >= kept
        record(
            target.cp_id,
            ("new", "CP", index) if is_new else _reviewed(source.cp_id),
            source.cp_id if is_new else None,
        )
    kept = len(reviewed.coordination_links)
    for index, (source, target) in enumerate(
        zip(stitched.coordination_links, merged.coordination_links)
    ):
        is_new = index >= kept
        mechanism = source.coordination_mechanism.cm_id
        record(
            target.link_id,
            ("new", "CL", index) if is_new else _reviewed(source.link_id),
            source.link_id if is_new else None,
        )
        record(
            target.coordination_mechanism.cm_id,
            ("new", "CM", index) if is_new else _reviewed(mechanism),
            written_mechanism_ids.get(source.link_id, mechanism) if is_new else None,
        )
    return RevisionIdentity(
        identities=identities,
        written={key: frozenset(ids) for key, ids in written.items()},
    )


# Each identified element type and the field that holds its own ID.
_ID_FIELDS: dict[type[BaseModel], str] = {
    Responsibility: "resp_id",
    ResponsibilityConstraint: "rc_id",
    ProcessModelPart: "pm_id",
    ControlAction: "ca_id",
    FeedbackChannel: "fb_id",
    ControlledProcess: "cp_id",
    CoordinationLink: "link_id",
    CoordinationMechanism: "cm_id",
}
# The fields that hold another element's ID as plain text.  The model types
# them as ``str``, so they cannot be read from it; they are the text
# references ``id_normalization`` rewrites.
_TEXT_REFERENCE_FIELDS: dict[type[BaseModel], tuple[str, ...]] = {
    ControlAction: ("process_model_refs",),
    FeedbackChannel: ("updates",),
    CoordinationLink: ("source", "target", "shared_pm"),
}


def _annotation_types(annotation: Any) -> Iterator[Any]:
    yield annotation
    for argument in get_args(annotation):
        yield from _annotation_types(argument)


def element_ref_fields(model: type[BaseModel]) -> tuple[str, ...]:
    """Return the fields of *model* the model types as an ``ElementRef``."""
    return tuple(
        name
        for name, field in model.model_fields.items()
        if ElementRef in tuple(_annotation_types(field.annotation))
    )


def reference_fields(model: type[BaseModel]) -> tuple[str, ...]:
    """Return the fields of *model* that hold an element ID.

    They are its own ID field, its text references, and its ``ElementRef``
    fields, whose ``id`` is the reference.
    """
    return (
        _ID_FIELDS[model],
        *_TEXT_REFERENCE_FIELDS.get(model, ()),
        *element_ref_fields(model),
    )


def _in_reviewed_terms(
    element: BaseModel, payload: dict[str, Any], tokens: Mapping[str, str]
) -> dict[str, Any]:
    """Rewrite the IDs *element*'s payload holds to reviewed IDs or new tokens.

    Only the reference fields are rewritten; every other field, such as a
    variable's values or a description, is data and stays as written, even
    when its text looks like an ID.
    """
    model = type(element)
    refs = set(element_ref_fields(model))

    def token(value: Any) -> Any:
        return tokens.get(value, value) if isinstance(value, str) else value

    for name in reference_fields(model):
        if name not in payload:
            continue
        value = payload[name]
        if name in refs:
            if isinstance(value, dict):
                payload[name] = {**value, "id": token(value.get("id"))}
        elif isinstance(value, list):
            payload[name] = [token(item) for item in value]
        else:
            payload[name] = token(value)
    return payload


def _token(identity: Identity) -> str:
    if identity[0] == "reviewed":
        return identity[1]
    return "new:" + ":".join(map(str, identity[1:]))


def _flat_elements(
    structure: ControlStructure,
) -> Iterator[tuple[str, Any, tuple[str, ...]]]:
    """Yield ``(id, element, nested fields)`` for every identified element.

    The nested fields hold other identified elements; they are compared on
    their own, not as part of the element that holds them.
    """
    children = tuple(items for _, items, _ in _CHILD_LISTS)
    for responsibility in structure.responsibilities:
        yield responsibility.resp_id, responsibility, children
        for _, items, key in _CHILD_LISTS:
            for item in getattr(responsibility, items):
                yield getattr(item, key), item, ()
    for process in structure.controlled_processes:
        yield process.cp_id, process, ()
    for link in structure.coordination_links:
        yield link.link_id, link, ("coordination_mechanism",)
        mechanism = link.coordination_mechanism
        yield mechanism.cm_id, mechanism, ()


def _members(element: Any, nested: tuple[str, ...]) -> list[str]:
    """Return the IDs of the identified elements *element* holds."""
    ids: list[str] = []
    for field in nested:
        value = getattr(element, field)
        for item in value if isinstance(value, list) else [value]:
            ids.extend(
                getattr(item, key)
                for key in ("rc_id", "pm_id", "ca_id", "fb_id", "cm_id")
                if hasattr(item, key)
            )
    return ids


def element_changes(
    before: ControlStructure,
    after: ControlStructure,
    identity: RevisionIdentity | None = None,
) -> ElementChanges:
    """Return the elements *after* adds or changes, and how each parent changed.

    *before* holds reviewed IDs; *identity* says which element each ID of
    *after* is (by default, the element with the same ID).  Elements are
    compared by identity, with every reference rewritten to the identity it
    names, so an ID that changed only by renumbering is not a change.  A
    responsibility is changed when its own fields change, when it gains or
    loses a child, or when a child changes; a link, when its own fields or its
    mechanism change.  The order of the children does not count.  A gained
    child is itself a changed member.
    """
    identity = identity or RevisionIdentity.unchanged(after)
    tokens = {
        published: _token(element) for published, element in identity.identities.items()
    }
    old: dict[str, tuple[Any, frozenset[str]]] = {}
    for element_id, element, nested in _flat_elements(before):
        old[element_id] = (
            element.model_dump(mode="json", exclude=set(nested)),
            frozenset(_members(element, nested)),
        )
    changed: set[str] = set()
    own: set[str] = set()
    for element_id, element, nested in _flat_elements(after):
        token = tokens.get(element_id)
        payload = _in_reviewed_terms(
            element, element.model_dump(mode="json", exclude=set(nested)), tokens
        )
        members = frozenset(
            tokens.get(member, member) for member in _members(element, nested)
        )
        earlier = old.get(token) if token is not None else None
        if earlier is None or earlier[0] != payload or earlier[1] - members:
            own.add(element_id)
            changed.add(element_id)
        elif earlier[1] != members:
            changed.add(element_id)
    holdings: dict[str, tuple[str, ...]] = {}
    member_changes: dict[str, tuple[str, ...]] = {}
    for element_id, element, nested in _flat_elements(after):
        if not nested:
            continue
        holdings[element_id] = tuple(_members(element, nested))
        changed_members = tuple(m for m in holdings[element_id] if m in changed)
        if not changed_members:
            continue
        changed.add(element_id)
        if element_id not in own:
            member_changes[element_id] = changed_members
    return ElementChanges(
        ids=frozenset(changed), members=holdings, member_changes=member_changes
    )


def changed_element_ids(
    before: ControlStructure,
    after: ControlStructure,
    identity: RevisionIdentity | None = None,
) -> frozenset[str]:
    """Return the published IDs of the elements *after* adds or changes.

    See :func:`element_changes`.
    """
    return element_changes(before, after, identity).ids


def unread_added_process_model_warnings(
    published: ControlStructure, identity: RevisionIdentity
) -> list[str]:
    """Warn about each process-model variable the revision added that no action reads.

    A variable is added when its identity is new, whatever published ID it
    took; it is read when a control action of its responsibility lists that ID.
    """
    warnings: list[str] = []
    for resp in published.responsibilities:
        read = {ref for ca in resp.control_actions for ref in ca.process_model_refs}
        for pm in resp.process_model_parts:
            element = identity.identities.get(pm.pm_id, ("new",))
            if element[0] == "reviewed" or pm.pm_id in read:
                continue
            warnings.append(
                f"Revision added process-model variable {pm.pm_id} "
                f"({pm.description}) that no control action reads."
            )
    return warnings
