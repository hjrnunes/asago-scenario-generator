"""The schema-diff check for contract versions.

A published contract version never changes meaning, so a breaking schema change
needs a new major version. This check compares each installed version's
``schema.json`` with the next one and refuses a breaking change without a major
bump. It assists review; it cannot see changed units, defaults or meaning, so a
reviewer still reads the diff.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_json
from .semver import InvalidVersionNameError, SemVer, parse_version_name

ANNOTATION_KEYWORDS = frozenset(
    {
        "$anchor",
        "$comment",
        "$dynamicAnchor",
        "$id",
        "$schema",
        "default",
        "deprecated",
        "description",
        "examples",
        "readOnly",
        "title",
        "writeOnly",
    }
)

_HANDLED_KEYWORDS = frozenset(
    {
        "$defs",
        "$ref",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "contains",
        "definitions",
        "dependentRequired",
        "dependentSchemas",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "items",
        "maxContains",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minContains",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "not",
        "oneOf",
        "pattern",
        "patternProperties",
        "prefixItems",
        "properties",
        "propertyNames",
        "required",
        "type",
        "unevaluatedProperties",
        "uniqueItems",
    }
)

_LOWER_BOUNDS = {
    "minimum": "minimum",
    "exclusiveMinimum": "minimum",
    "minLength": "min-length",
    "minItems": "min-items",
    "minProperties": "min-properties",
}
_UPPER_BOUNDS = {
    "maximum": "maximum",
    "exclusiveMaximum": "maximum",
    "maxLength": "max-length",
    "maxItems": "max-items",
    "maxProperties": "max-properties",
}


class SchemaDiffError(ValueError):
    """A schema-diff input is not a readable contracts root."""


@dataclass(frozen=True)
class SchemaChange:
    """One difference between two schema versions."""

    location: str
    kind: str
    breaking: bool


def diff_schemas(old: Any, new: Any) -> tuple[SchemaChange, ...]:
    """Return the differences that take ``old`` to ``new``."""

    changes: list[SchemaChange] = []
    _diff(old, new, "$", changes)
    return tuple(changes)


def check_roots(roots: Iterable[str | Path]) -> tuple[str, ...]:
    """Return one problem for each breaking change without a major bump."""

    problems: list[str] = []
    for root in roots:
        problems.extend(_check_root(Path(root)))
    return tuple(problems)


def main(argv: list[str] | None = None) -> int:
    """Run the check over contract roots and return the process exit code."""

    parser = argparse.ArgumentParser(
        prog="asago-contracts-core.schema-diff",
        description=(
            "Refuse a breaking schema change between installed contract versions "
            "that does not carry a new major version."
        ),
    )
    parser.add_argument("roots", nargs="+", metavar="ROOT")
    arguments = parser.parse_args(argv)
    try:
        problems = check_roots(arguments.roots)
    except SchemaDiffError as error:
        print(f"schema-diff: {error}", file=sys.stderr)
        return 2
    if problems:
        for problem in problems:
            print(f"schema-diff: {problem}", file=sys.stderr)
        return 1
    print(
        f"schema-diff: {len(arguments.roots)} root(s) checked, "
        "no breaking changes without a major bump"
    )
    return 0


def _check_root(root: Path) -> list[str]:
    if not root.is_dir():
        raise SchemaDiffError(f"{root}: not a directory")
    contracts: dict[str, dict[str, tuple[SemVer, Any]]] = {}
    for contract_dir in sorted(path for path in root.iterdir() if path.is_dir()):
        for version_dir in sorted(
            path for path in contract_dir.iterdir() if path.is_dir()
        ):
            schema_file = version_dir / "schema.json"
            if not schema_file.is_file():
                continue
            try:
                name = parse_version_name(version_dir.name)
            except InvalidVersionNameError:
                continue
            contracts.setdefault(name.contract, {})[version_dir.name] = (
                name.version,
                _load_schema(schema_file),
            )
    problems: list[str] = []
    for contract in sorted(contracts):
        versions = sorted(contracts[contract].items(), key=lambda item: item[1][0])
        for (old_name, (old_version, old_schema)), (
            new_name,
            (new_version, new_schema),
        ) in zip(versions, versions[1:]):
            breaking = tuple(
                change
                for change in diff_schemas(old_schema, new_schema)
                if change.breaking
            )
            if not breaking or new_version.major > old_version.major:
                continue
            kinds = ", ".join(sorted({change.kind for change in breaking}))
            problems.append(
                f"{contract}: {new_name} changes its schema without a major bump "
                f"from {old_name} ({kinds}); bump the major version"
            )
    return problems


def _load_schema(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SchemaDiffError(f"{path}: cannot read the schema: {error}") from error


def _diff(old: Any, new: Any, location: str, changes: list[SchemaChange]) -> None:
    if old == new:
        return
    if isinstance(old, bool) or isinstance(new, bool):
        _diff_boolean(old, new, location, changes)
        return
    if not isinstance(old, Mapping) or not isinstance(new, Mapping):
        _add(changes, location, "schema-changed", True)
        return

    _diff_type(old, new, location, changes)
    _diff_enum(old, new, location, changes)
    _diff_const(old, new, location, changes)
    _diff_required(old, new, location, changes)
    _diff_properties(old, new, location, changes)
    _diff_additional(old, new, location, changes)
    _diff_bounds(old, new, location, changes)
    _diff_scalar(old, new, location, changes, "pattern", "pattern")
    _diff_scalar(old, new, location, changes, "format", "format")
    _diff_items(old, new, location, changes)
    _diff_alternatives(old, new, location, changes, "anyOf")
    _diff_alternatives(old, new, location, changes, "oneOf")
    _diff_composition(old, new, location, changes)
    _diff_reference(old, new, location, changes)
    _diff_definitions(old, new, location, changes)
    _diff_misc(old, new, location, changes)
    _diff_leftover(old, new, location, changes)


def _diff_boolean(
    old: Any, new: Any, location: str, changes: list[SchemaChange]
) -> None:
    if old is True and new is False:
        _add(changes, location, "schema-closed", True)
    elif old is False and new is True:
        _add(changes, location, "schema-opened", False)
    elif old is True:
        _add(changes, location, "schema-narrowed", True)
    elif new is True:
        _add(changes, location, "schema-widened", False)
    elif old is False:
        _add(changes, location, "schema-opened", False)
    else:
        _add(changes, location, "schema-closed", True)


def _diff_type(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_types = _types(old.get("type"))
    new_types = _types(new.get("type"))
    if old_types == new_types:
        return
    if old_types is None or new_types is None:
        _add(changes, f"{location}.type", "type-changed", True)
    elif new_types < old_types:
        _add(changes, f"{location}.type", "type-narrowed", True)
    elif old_types < new_types:
        _add(changes, f"{location}.type", "type-widened", False)
    else:
        _add(changes, f"{location}.type", "type-changed", True)


def _types(value: Any) -> frozenset[str] | None:
    if isinstance(value, str):
        return frozenset({value})
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return frozenset(value)
    return None


def _diff_enum(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_values, new_values = old.get("enum"), new.get("enum")
    if old_values == new_values:
        return
    if old_values is None:
        _add(changes, f"{location}.enum", "enum-restricted", True)
        return
    if new_values is None:
        _add(changes, f"{location}.enum", "enum-relaxed", False)
        return
    old_keys = {canonical_json(value) for value in old_values}
    new_keys = {canonical_json(value) for value in new_values}
    if old_keys - new_keys:
        _add(changes, f"{location}.enum", "enum-removed", True)
    if new_keys - old_keys:
        _add(changes, f"{location}.enum", "enum-added", False)


def _diff_const(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_const, new_const = old.get("const", _MISSING), new.get("const", _MISSING)
    if old_const == new_const:
        return
    if old_const is _MISSING:
        _add(changes, f"{location}.const", "const-restricted", True)
    elif new_const is _MISSING:
        _add(changes, f"{location}.const", "const-relaxed", False)
    else:
        _add(changes, f"{location}.const", "const-changed", True)


def _diff_required(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_value, new_value = old.get("required"), new.get("required")
    if old_value == new_value:
        return
    old_required = _names(old_value) if old_value is not None else set()
    new_required = _names(new_value) if new_value is not None else set()
    if old_required is None or new_required is None:
        _add(changes, f"{location}.required", "keyword-changed", True)
        return
    if new_required - old_required:
        _add(changes, f"{location}.required", "required-added", True)
    if old_required - new_required:
        _add(changes, f"{location}.required", "required-removed", False)


def _names(value: Any) -> set[str] | None:
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return None


def _diff_properties(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_properties, new_properties = old.get("properties"), new.get("properties")
    if old_properties == new_properties:
        return
    if not isinstance(old_properties, Mapping) or not isinstance(
        new_properties, Mapping
    ):
        _add(changes, f"{location}.properties", "keyword-changed", True)
        return
    closed = new.get("additionalProperties", _MISSING) is False
    for name in sorted(set(old_properties) - set(new_properties)):
        _add(
            changes,
            f"{location}.properties.{name}",
            "property-removed",
            closed,
        )
    for name in sorted(set(new_properties) - set(old_properties)):
        _add(changes, f"{location}.properties.{name}", "property-added", False)
    for name in sorted(set(old_properties) & set(new_properties)):
        _diff(
            old_properties[name],
            new_properties[name],
            f"{location}.properties.{name}",
            changes,
        )


def _diff_additional(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_value = old.get("additionalProperties", True)
    new_value = new.get("additionalProperties", True)
    if old_value == new_value:
        return
    old_closed, new_closed = old_value is False, new_value is False
    if new_closed and not old_closed:
        _add(
            changes,
            f"{location}.additionalProperties",
            "additional-properties-closed",
            True,
        )
    elif old_closed and not new_closed:
        _add(
            changes,
            f"{location}.additionalProperties",
            "additional-properties-opened",
            False,
        )
    elif isinstance(old_value, Mapping) and isinstance(new_value, Mapping):
        _diff(old_value, new_value, f"{location}.additionalProperties", changes)
    elif isinstance(new_value, Mapping):
        _add(
            changes,
            f"{location}.additionalProperties",
            "additional-properties-constrained",
            True,
        )
    else:
        _add(
            changes,
            f"{location}.additionalProperties",
            "additional-properties-relaxed",
            False,
        )


def _diff_bounds(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    for keyword, label in _LOWER_BOUNDS.items():
        _diff_bound(
            old.get(keyword), new.get(keyword), location, keyword, label, True, changes
        )
    for keyword, label in _UPPER_BOUNDS.items():
        _diff_bound(
            old.get(keyword), new.get(keyword), location, keyword, label, False, changes
        )
    old_multiple, new_multiple = old.get("multipleOf"), new.get("multipleOf")
    if old_multiple != new_multiple:
        kind = (
            "multiple-of-changed" if new_multiple is not None else "multiple-of-relaxed"
        )
        _add(changes, f"{location}.multipleOf", kind, new_multiple is not None)


def _diff_bound(
    old_value: Any,
    new_value: Any,
    location: str,
    keyword: str,
    label: str,
    lower: bool,
    changes: list[SchemaChange],
) -> None:
    if old_value == new_value:
        return
    if old_value is None:
        kind = f"{label}-raised" if lower else f"{label}-lowered"
        _add(changes, f"{location}.{keyword}", kind, True)
        return
    if new_value is None:
        kind = f"{label}-lowered" if lower else f"{label}-raised"
        _add(changes, f"{location}.{keyword}", kind, False)
        return
    if not isinstance(old_value, (int, float)) or not isinstance(
        new_value, (int, float)
    ):
        _add(changes, f"{location}.{keyword}", "keyword-changed", True)
        return
    tighter = new_value > old_value if lower else new_value < old_value
    kind = f"{label}-raised" if lower else f"{label}-lowered"
    if not tighter:
        kind = f"{label}-lowered" if lower else f"{label}-raised"
    _add(changes, f"{location}.{keyword}", kind, tighter)


def _diff_scalar(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
    keyword: str,
    label: str,
) -> None:
    old_value, new_value = old.get(keyword), new.get(keyword)
    if old_value == new_value:
        return
    if old_value is None:
        _add(changes, f"{location}.{keyword}", f"{label}-added", True)
    elif new_value is None:
        _add(changes, f"{location}.{keyword}", f"{label}-removed", False)
    else:
        _add(changes, f"{location}.{keyword}", f"{label}-changed", True)


def _diff_items(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_items, new_items = old.get("items"), new.get("items")
    if old_items == new_items:
        pass
    elif old_items is None:
        _add(changes, f"{location}.items", "items-added", True)
    elif new_items is None:
        _add(changes, f"{location}.items", "items-removed", False)
    elif isinstance(old_items, Mapping) and isinstance(new_items, Mapping):
        _diff(old_items, new_items, f"{location}.items", changes)
    else:
        _add(changes, f"{location}.items", "items-changed", True)
    old_prefix, new_prefix = old.get("prefixItems"), new.get("prefixItems")
    if old_prefix != new_prefix:
        breaking = not isinstance(old_prefix, list) or not isinstance(new_prefix, list)
        breaking = breaking or len(new_prefix) > len(old_prefix)
        _add(changes, f"{location}.prefixItems", "prefix-items-changed", breaking)


def _diff_alternatives(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
    keyword: str,
) -> None:
    old_values, new_values = old.get(keyword), new.get(keyword)
    if old_values == new_values:
        return
    if not isinstance(old_values, list) or not isinstance(new_values, list):
        _add(changes, f"{location}.{keyword}", "keyword-changed", True)
        return
    old_map = {canonical_json(value): value for value in old_values}
    new_map = {canonical_json(value): value for value in new_values}
    if old_map.keys() - new_map.keys():
        _add(changes, f"{location}.{keyword}", "alternatives-removed", True)
    if new_map.keys() - old_map.keys():
        _add(changes, f"{location}.{keyword}", "alternatives-added", False)
    for key in sorted(old_map.keys() & new_map.keys()):
        _diff(old_map[key], new_map[key], f"{location}.{keyword}", changes)


def _diff_composition(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    old_all, new_all = old.get("allOf"), new.get("allOf")
    if old_all != new_all:
        if not isinstance(old_all, list) or not isinstance(new_all, list):
            _add(changes, f"{location}.allOf", "keyword-changed", True)
        else:
            old_keys = {canonical_json(value) for value in old_all}
            new_keys = {canonical_json(value) for value in new_all}
            if new_keys - old_keys:
                _add(changes, f"{location}.allOf", "all-of-restricted", True)
            if old_keys - new_keys:
                _add(changes, f"{location}.allOf", "all-of-relaxed", False)
    old_not, new_not = old.get("not"), new.get("not")
    if old_not != new_not:
        if old_not is None:
            _add(changes, f"{location}.not", "not-added", True)
        elif new_not is None:
            _add(changes, f"{location}.not", "not-removed", False)
        else:
            _add(changes, f"{location}.not", "not-changed", True)


def _diff_reference(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    if old.get("$ref") != new.get("$ref"):
        _add(changes, f"{location}.$ref", "reference-changed", True)


def _diff_definitions(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    for keyword in ("$defs", "definitions"):
        old_defs, new_defs = old.get(keyword), new.get(keyword)
        if old_defs == new_defs:
            continue
        if not isinstance(old_defs, Mapping) or not isinstance(new_defs, Mapping):
            _add(changes, f"{location}.{keyword}", "keyword-changed", True)
            continue
        for name in sorted(set(old_defs) - set(new_defs)):
            _add(changes, f"{location}.{keyword}.{name}", "definition-removed", True)
        for name in sorted(set(new_defs) - set(old_defs)):
            _add(changes, f"{location}.{keyword}.{name}", "definition-added", False)
        for name in sorted(set(old_defs) & set(new_defs)):
            _diff(
                old_defs[name], new_defs[name], f"{location}.{keyword}.{name}", changes
            )


def _diff_misc(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    for keyword in (
        "propertyNames",
        "patternProperties",
        "dependentSchemas",
        "contains",
    ):
        old_value, new_value = old.get(keyword), new.get(keyword)
        if old_value == new_value:
            continue
        if isinstance(old_value, Mapping) and isinstance(new_value, Mapping):
            _diff(old_value, new_value, f"{location}.{keyword}", changes)
        else:
            _add(changes, f"{location}.{keyword}", "keyword-changed", True)
    old_dependent, new_dependent = (
        old.get("dependentRequired"),
        new.get("dependentRequired"),
    )
    if old_dependent != new_dependent:
        if not isinstance(old_dependent, Mapping) or not isinstance(
            new_dependent, Mapping
        ):
            _add(changes, f"{location}.dependentRequired", "keyword-changed", True)
        else:
            if set(new_dependent) - set(old_dependent):
                _add(
                    changes,
                    f"{location}.dependentRequired",
                    "dependent-required-added",
                    True,
                )
            if set(old_dependent) - set(new_dependent):
                _add(
                    changes,
                    f"{location}.dependentRequired",
                    "dependent-required-removed",
                    False,
                )
    old_unique, new_unique = (
        old.get("uniqueItems", False),
        new.get("uniqueItems", False),
    )
    if old_unique != new_unique:
        _add(
            changes,
            f"{location}.uniqueItems",
            "unique-items-added" if new_unique else "unique-items-removed",
            bool(new_unique),
        )


def _diff_leftover(
    old: Mapping[str, Any],
    new: Mapping[str, Any],
    location: str,
    changes: list[SchemaChange],
) -> None:
    keyword = "unevaluatedProperties"
    old_value, new_value = old.get(keyword, True), new.get(keyword, True)
    if old_value != new_value:
        if new_value is False and old_value is not False:
            _add(
                changes, f"{location}.{keyword}", "unevaluated-properties-closed", True
            )
        elif old_value is False and new_value is not False:
            _add(
                changes, f"{location}.{keyword}", "unevaluated-properties-opened", False
            )
        else:
            _add(changes, f"{location}.{keyword}", "keyword-changed", True)
    for keyword in sorted(
        (set(old) | set(new)) - _HANDLED_KEYWORDS - ANNOTATION_KEYWORDS
    ):
        if keyword.startswith("x-"):
            continue
        if old.get(keyword) != new.get(keyword):
            _add(changes, f"{location}.{keyword}", "keyword-changed", True)


def _add(changes: list[SchemaChange], location: str, kind: str, breaking: bool) -> None:
    changes.append(SchemaChange(location=location, kind=kind, breaking=breaking))


_MISSING = object()


if __name__ == "__main__":
    raise SystemExit(main())
