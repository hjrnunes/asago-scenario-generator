"""Record kinds and one-hop links derived from the supplied TARGET-STATE.

The condition check uses this index to tell whether two compared strings can
be the same kind of value and whether a cited record is related to the
record the unsafe call acts on. Everything is derived from the observed
state snapshot; nothing names a target, collection, field, or identifier
prefix.

- A collection is a top-level TARGET-STATE mapping whose values are all
  mappings (the ``RecordIndex`` rule); its keys are record keys.
- A field ``(C, f)`` links to collection ``D`` when every non-null string
  value of ``f`` across the records of ``C`` is a key of ``D`` (at least one
  such value is required).
- An ID-shaped string is an ASCII letter prefix, an optional ``-`` or ``_``
  separator, and a digit run, with nothing else: ``W-2``, ``ab_17``,
  ``USR001``. UUIDs, bare digits, and free text are not ID-shaped.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field

from asago_scenario_generator.stpa.models.target_subject_model import RecordIndex

STATE_REF = "TARGET-STATE"
_ID_SHAPE = re.compile(r"^(?P<prefix>[A-Za-z]+)[-_]?[0-9]+$")
_JSON_TYPES = (dict, list, str, int, float, bool, type(None))


def id_prefix(value: object) -> str | None:
    """Return the lower-cased letter prefix of an ID-shaped string."""

    if not isinstance(value, str):
        return None
    match = _ID_SHAPE.match(value)
    return match.group("prefix").lower() if match else None


@dataclass(frozen=True)
class StateIndex:
    """Collections, observed field values, and links of one state snapshot."""

    # collection -> record key -> record
    records: Mapping[str, Mapping[str, Mapping[str, object]]] = field(
        default_factory=dict
    )
    # field label -> observed string values
    field_values: Mapping[str, frozenset[str]] = field(default_factory=dict)
    # (collection, field) -> collections its values are keys of
    links: Mapping[tuple[str, str], frozenset[str]] = field(default_factory=dict)

    @classmethod
    def from_fact_values(cls, fact_values: Mapping[str, object]) -> "StateIndex":
        """Rebuild the top-level state from its fact paths and index it."""

        prefix = STATE_REF + "."
        state: dict[str, object] = {}
        for path, value in fact_values.items():
            if not path.startswith(prefix) or not isinstance(value, _JSON_TYPES):
                continue
            key = path[len(prefix) :]
            if "." not in key:
                state[key] = value
        record_index = RecordIndex(state)
        records: dict[str, dict[str, Mapping[str, object]]] = {}
        for name in record_index.collections:
            container = state[name]
            assert isinstance(container, Mapping)
            records[name] = {str(key): record for key, record in container.items()}

        field_values: dict[str, set[str]] = {}
        per_field: dict[tuple[str, str], set[str]] = {}
        for name, value in state.items():
            if name in records:
                for record in records[name].values():
                    for field_name, field_value in record.items():
                        if isinstance(field_value, str):
                            field_values.setdefault(
                                record_field_label(name, field_name), set()
                            ).add(field_value)
                            per_field.setdefault((name, field_name), set()).add(
                                field_value
                            )
            elif isinstance(value, str):
                field_values.setdefault(f"{STATE_REF}.{name}", set()).add(value)
            elif isinstance(value, Mapping):
                for field_name, field_value in value.items():
                    if isinstance(field_value, str):
                        field_values.setdefault(
                            f"{STATE_REF}.{name}.{field_name}", set()
                        ).add(field_value)

        links: dict[tuple[str, str], frozenset[str]] = {}
        for key, values in per_field.items():
            targets = frozenset(
                target
                for target, keyed in records.items()
                if values and values <= keyed.keys()
            )
            if targets:
                links[key] = targets
        return cls(
            records=records,
            field_values={label: frozenset(v) for label, v in field_values.items()},
            links=links,
        )

    def key_collections(self, value: str) -> frozenset[str]:
        """Return the collections that have ``value`` as a record key."""

        return frozenset(name for name, keyed in self.records.items() if value in keyed)

    def field_labels(self, value: str) -> frozenset[str]:
        """Return the field labels under which ``value`` was observed."""

        return frozenset(
            label for label, values in self.field_values.items() if value in values
        )

    def describe_domain(self, value: str) -> str:
        """Describe where ``value`` occurs in the state, for feedback text."""

        parts = [
            f"a key of {collection_path(name)}"
            for name in sorted(self.key_collections(value))
        ]
        labels = sorted(self.field_labels(value))
        if labels:
            parts.append("a value of " + ", ".join(labels))
        return " and ".join(parts) if parts else "not found in TARGET-STATE"

    def linking_fields(self, collection: str) -> tuple[str, ...]:
        """Return the field labels whose values are keys of ``collection``."""

        return tuple(
            sorted(
                record_field_label(name, field_name)
                for (name, field_name), targets in self.links.items()
                if collection in targets
            )
        )

    def record_of(self, path: str) -> tuple[str, str] | None:
        """Return ``(collection, key)`` when ``path`` lies in a collection record.

        A collection path itself, a top-level scalar, and paths outside
        TARGET-STATE are not in a record.
        """

        prefix = STATE_REF + "."
        if not path.startswith(prefix):
            return None
        rest = path[len(prefix) :]
        for name, keyed in self.records.items():
            if not rest.startswith(name + "."):
                continue
            tail = rest[len(name) + 1 :]
            for key in keyed:
                if tail == key or tail.startswith(key + "."):
                    return name, key
        return None

    def one_hop(self, collection: str, key: str) -> dict[str, str]:
        """Return the records one link away from one record, with the link.

        Forward: a field of the record whose value is a key of a collection
        that field links to. Reverse: a record whose linking field holds
        this record's key.
        """

        reachable: dict[str, str] = {}
        record = self.records.get(collection, {}).get(key)
        if record is None:
            return reachable
        own = record_path(collection, key)
        for field_name, value in record.items():
            if not isinstance(value, str):
                continue
            for target in sorted(self.links.get((collection, field_name), ())):
                if value in self.records[target]:
                    reachable.setdefault(
                        record_path(target, value), f"via {own}.{field_name}"
                    )
        for (name, field_name), targets in sorted(self.links.items()):
            if collection not in targets:
                continue
            for other_key, other in self.records[name].items():
                if other.get(field_name) == key:
                    path = record_path(name, other_key)
                    if path != own:
                        reachable.setdefault(path, f"its {field_name} is {key!r}")
        return reachable


def collection_path(collection: str) -> str:
    """Return the absolute fact path of one collection."""

    return f"{STATE_REF}.{collection}"


def record_path(collection: str, key: str) -> str:
    """Return the absolute fact path of one record."""

    return f"{STATE_REF}.{collection}.{key}"


def record_field_label(collection: str, field_name: str) -> str:
    """Return the label naming one field across a collection's records."""

    return f"{STATE_REF}.{collection}.<record_key>.{field_name}"


__all__ = [
    "STATE_REF",
    "StateIndex",
    "collection_path",
    "id_prefix",
    "record_field_label",
    "record_path",
]
