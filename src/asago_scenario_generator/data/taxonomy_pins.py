"""Production taxonomy pins and the pinned ATLAS-backed resolver.

Authority rules:

- ATLAS is the sole initially qualified taxonomy.  Resolver membership comes
  only from identifiers actually present in the pinned bundled source
  (:data:`_DEFAULT_ATLAS_PATH`) — tactics and techniques, where
  sub-techniques are flat technique keys.  Mitigations and case studies are
  never taxonomy mapping targets.
- Every SSSOM ``skos:relatedMatch`` row is unqualified migration provenance.
  Rows are digested as mapping-set content only; they never populate
  resolver membership and never confer ``ExactMapping`` authority.  The
  mapping-set pin itself is fail-closed: see
  :func:`compute_mapping_set_digest` for the strict v1 canonical profile.
- LAAF is optional and non-authoritative for v1.  Nothing LAAF is bundled
  or vendored here; a future authoritative LAAF release must be supplied
  explicitly as pin plus identifier membership, with strict coherence.

The resolver performs all I/O at construction time via this module's
loaders; the constructed object is a pure in-memory implementation of the
merged :class:`~asago_scenario_generator.models.attack_pattern.TaxonomyResolver`
protocol.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any, Literal

import yaml

from asago_scenario_generator.data.canonical import _canonical_json, _nfc
from asago_scenario_generator.data.paths import DATA_ROOT

from asago_scenario_generator.models.attack_pattern_contracts import (
    TaxonomyContext,
    TaxonomyPin,
)

_DEFAULT_ATLAS_PATH = DATA_ROOT / "taxonomies" / "atlas" / "ATLAS-2026.05.yaml"
_DEFAULT_MAPPING_SET_DIR = DATA_ROOT / "taxonomies" / "attack-patterns"
_MAPPING_SET_GLOB = "attack-patterns*.sssom.tsv"
_EXPECTED_MAPPING_SET_FILES = frozenset(
    {
        "attack-patterns.sssom.tsv",
        "attack-patterns-agentic-only.sssom.tsv",
        "attack-patterns-atlas-derived.sssom.tsv",
        "attack-patterns-comms-human-supply.sssom.tsv",
        "attack-patterns-halluc-intent.sssom.tsv",
        "attack-patterns-memory-tool.sssom.tsv",
    }
)
_MAPPING_SET_DOMAIN = "asago-scenario-generator:mapping-set:v1"

# Strict v1 pin profile: exactly these six explicit-source columns.
_MAPPING_ROW_FIELDS = (
    "subject_id",
    "subject_source",
    "predicate_id",
    "object_id",
    "object_source",
    "mapping_justification",
)
# Semantic comment metadata the profile knows how to pin.  Scalar keys carry
# ``# key: value``; ``curie_map`` carries an indented block of
# ``#   prefix: uri`` entries.  Any other comment shaped like metadata (a
# lowercase-identifier ``key: value``) is rejected rather than silently
# dropped; free explanatory comments are excluded from the pin.
_METADATA_SCALAR_KEYS = frozenset({"mapping_set_id", "mapping_set_version"})
_METADATA_BLOCK_KEYS = frozenset({"curie_map"})
_METADATA_KEY_RE = re.compile(r"^([a-z][a-z0-9_]*):[ \t]*(.*)$")
_CURIE_ENTRY_RE = re.compile(r"^([^:\s]+):[ \t]*(\S.*)$")


def load_atlas_pin(path: str | Path | None = None) -> TaxonomyPin:
    """Deterministic SHA-256 pin of the bundled ATLAS release file.

    The digest covers the exact pinned file bytes; the release is read from
    the file's ``collection.version`` so pin and source move together.
    """
    atlas_path = Path(path) if path is not None else _DEFAULT_ATLAS_PATH
    raw = atlas_path.read_bytes()
    try:
        release = yaml.safe_load(raw)["collection"]["version"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise ValueError(
            f"ATLAS source {atlas_path} lacks a collection version"
        ) from exc
    return TaxonomyPin(release=str(release), digest=hashlib.sha256(raw).hexdigest())


def _validated_identifier_keys(
    entries: dict[Any, Any], atlas_path: Path, section: str
) -> list[str]:
    """Validate one pinned ATLAS section's entries and return its keys."""
    keys: list[str] = []
    for key, entry in entries.items():
        if not isinstance(entry, dict) or entry.get("id") != key:
            raise ValueError(
                f"ATLAS source {atlas_path} has an incoherent {section} entry: {key}"
            )
        keys.append(key)
    return keys


def load_atlas_identifiers(path: str | Path | None = None) -> frozenset[str]:
    """Authoritative ATLAS identifiers addressable by taxonomy mappings.

    Membership is drawn only from the pinned source's tactics and techniques
    sections (sub-techniques are flat technique keys).  Mitigation and
    case-study identifiers are deliberately excluded.
    """
    atlas_path = Path(path) if path is not None else _DEFAULT_ATLAS_PATH
    with open(atlas_path) as f:
        data = yaml.safe_load(f)
    identifiers: set[str] = set()
    for section in ("tactics", "techniques"):
        identifiers.update(
            _validated_identifier_keys(data.get(section) or {}, atlas_path, section)
        )
    if not identifiers:
        raise ValueError(
            f"ATLAS source {atlas_path} contains no tactic/technique identifiers"
        )
    return frozenset(identifiers)


def load_atlas_technique_identifiers(
    path: str | Path | None = None,
) -> frozenset[str]:
    """Technique identifiers from the authoritative pinned ATLAS source.

    Unlike :func:`load_atlas_identifiers`, this view deliberately excludes
    tactics because attack-tree ``technique_id`` fields may only name entries
    from the source's ``techniques`` section.
    """
    atlas_path = Path(path) if path is not None else _DEFAULT_ATLAS_PATH
    with open(atlas_path) as f:
        data = yaml.safe_load(f)
    identifiers = set(
        _validated_identifier_keys(
            data.get("techniques") or {}, atlas_path, "techniques"
        )
    )
    if not identifiers:
        raise ValueError(f"ATLAS source {atlas_path} contains no technique identifiers")
    return frozenset(identifiers)


def _mapping_set_paths(paths: Iterable[str | Path] | None) -> list[Path]:
    if paths is not None:
        files = [Path(p) for p in paths]
        if not files:
            raise ValueError("mapping-set pin requires at least one SSSOM file")
        return files
    files = sorted(_DEFAULT_MAPPING_SET_DIR.glob(_MAPPING_SET_GLOB))
    names = {f.name for f in files}
    if names != _EXPECTED_MAPPING_SET_FILES:
        missing = sorted(_EXPECTED_MAPPING_SET_FILES - names)
        unexpected = sorted(names - _EXPECTED_MAPPING_SET_FILES)
        raise ValueError(
            "bundled mapping set must contain exactly the pinned SSSOM files; "
            f"missing={missing} unexpected={unexpected}"
        )
    return files


def _strict_sssom_header(path: Path, lineno: int, line: str) -> list[str]:
    cells = line.split("\t")
    if len(cells) != len(set(cells)):
        raise ValueError(f"{path}:{lineno}: duplicate header columns")
    unknown = sorted(set(cells) - set(_MAPPING_ROW_FIELDS))
    missing = sorted(set(_MAPPING_ROW_FIELDS) - set(cells))
    if unknown or missing:
        raise ValueError(
            f"{path}:{lineno}: header does not match the v1 pin profile; "
            f"unknown columns={unknown} missing columns={missing}"
        )
    return cells


def _strict_sssom_row(
    path: Path, lineno: int, line: str, header: list[str]
) -> tuple[str, ...]:
    cells = line.split("\t")
    if len(cells) != len(header):
        raise ValueError(
            f"{path}:{lineno}: row has {len(cells)} cells, expected {len(header)}"
        )
    row = tuple(cells[header.index(field)] for field in _MAPPING_ROW_FIELDS)
    if any(not cell for cell in row):
        raise ValueError(f"{path}:{lineno}: row has an empty cell")
    return row


def _scalar_metadata_entry(
    path: Path,
    lineno: int,
    key: str,
    value: str,
    scalars: list[tuple[int, str, str]],
    seen_scalar_keys: set[str],
) -> None:
    if not value:
        raise ValueError(f"{path}:{lineno}: empty {key} value")
    if key in seen_scalar_keys:
        raise ValueError(f"{path}:{lineno}: duplicate {key} metadata")
    seen_scalar_keys.add(key)
    scalars.append((lineno, key, value))


def _curie_map_entry(
    path: Path,
    lineno: int,
    body: str,
    curies: list[tuple[int, str, str]],
    seen_curie_prefixes: set[str],
) -> None:
    match = _CURIE_ENTRY_RE.match(body)
    if not match:
        raise ValueError(f"{path}:{lineno}: malformed curie_map entry: {body!r}")
    prefix, uri = match.group(1), match.group(2).strip()
    if prefix in seen_curie_prefixes:
        raise ValueError(f"{path}:{lineno}: duplicate curie_map prefix {prefix!r}")
    seen_curie_prefixes.add(prefix)
    curies.append((lineno, prefix, uri))


def _curie_block_line(indented: bool, in_metadata_block: bool) -> bool:
    """Whether an indented comment line continues a curie_map block."""
    return indented and in_metadata_block


def _metadata_comment(path: Path, lineno: int, body: str) -> tuple[str, str] | None:
    """Parse one metadata comment line into (key, value); None for prose."""
    match = _METADATA_KEY_RE.match(body)
    if match is None:
        return None
    key, value = match.group(1), match.group(2).strip()
    if key not in _METADATA_SCALAR_KEYS and key not in _METADATA_BLOCK_KEYS:
        raise ValueError(
            f"{path}:{lineno}: unsupported mapping-set metadata {key!r}; "
            "the v1 pin profile must be extended to pin it"
        )
    return key, value


def _metadata_scalar_or_block(
    path: Path,
    lineno: int,
    key: str,
    value: str,
    scalars: list[tuple[int, str, str]],
    seen_scalar_keys: set[str],
) -> bool:
    """Consume a scalar entry (False) or open a block (True)."""
    if key in _METADATA_SCALAR_KEYS:
        _scalar_metadata_entry(path, lineno, key, value, scalars, seen_scalar_keys)
        return False
    if value:
        raise ValueError(f"{path}:{lineno}: {key} must introduce an indented block")
    return True


def _comment_metadata(
    path: Path,
    lineno: int,
    line: str,
    in_metadata_block: bool,
    scalars: list[tuple[int, str, str]],
    curies: list[tuple[int, str, str]],
    seen_scalar_keys: set[str],
    seen_curie_prefixes: set[str],
) -> bool:
    """Consume one comment line; returns whether an indented block stays open."""
    content = line[1:]
    indented = len(content) - len(content.lstrip(" \t")) >= 2
    body = content.strip()
    if _curie_block_line(indented, in_metadata_block):
        _curie_map_entry(path, lineno, body, curies, seen_curie_prefixes)
        return True
    if not body:
        return False  # blank comment: excluded from the pin
    metadata = _metadata_comment(path, lineno, body)
    if metadata is None:
        return False  # free explanatory comment: excluded from the pin
    key, value = metadata
    return _metadata_scalar_or_block(
        path, lineno, key, value, scalars, seen_scalar_keys
    )


def _read_strict_sssom(
    path: Path,
) -> tuple[
    list[tuple[int, str, str]],
    list[tuple[int, str, str]],
    list[tuple[int, tuple[str, ...]]],
]:
    """Parse one SSSOM TSV file under the strict v1 pin profile.

    Returns ``(scalar_metadata, curie_map_entries, rows)`` as
    ``(line_number, ...)`` triples, with row fields in
    :data:`_MAPPING_ROW_FIELDS` order.  Fails closed: unsupported metadata
    keys, unknown or missing columns, malformed rows, and ambiguous
    duplicate metadata all raise.
    """
    scalars: list[tuple[int, str, str]] = []
    curies: list[tuple[int, str, str]] = []
    rows: list[tuple[int, tuple[str, ...]]] = []
    header: list[str] | None = None
    in_metadata_block = False
    seen_scalar_keys: set[str] = set()
    seen_curie_prefixes: set[str] = set()
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.startswith("#"):
            in_metadata_block = _comment_metadata(
                path,
                lineno,
                line,
                in_metadata_block,
                scalars,
                curies,
                seen_scalar_keys,
                seen_curie_prefixes,
            )
            continue
        in_metadata_block = False
        if not line.strip():
            continue
        if header is None:
            header = _strict_sssom_header(path, lineno, line)
            continue
        rows.append((lineno, _strict_sssom_row(path, lineno, line, header)))
    if header is None:
        raise ValueError(f"{path}: lacks the required SSSOM header row")
    return scalars, curies, rows


def _merge_scalar_metadata(
    scalar_metadata: dict[str, tuple[str, str]],
    scalars: list[tuple[int, str, str]],
    path: Path,
) -> None:
    for lineno, key, value in scalars:
        normalized = _nfc(value)
        origin = f"{path}:{lineno}"
        existing = scalar_metadata.setdefault(key, (normalized, origin))
        if existing[0] != normalized:
            raise ValueError(
                f"conflicting mapping-set metadata {key!r}: {existing[0]!r} "
                f"declared at {existing[1]} but {normalized!r} declared at "
                f"{origin}"
            )


def _merge_curie_entries(
    curie_map: dict[str, tuple[str, str]],
    curies: list[tuple[int, str, str]],
    path: Path,
) -> None:
    for lineno, prefix, uri in curies:
        normalized_uri = _nfc(uri)
        origin = f"{path}:{lineno}"
        existing = curie_map.setdefault(_nfc(prefix), (normalized_uri, origin))
        if existing[0] != normalized_uri:
            raise ValueError(
                f"conflicting curie_map prefix {prefix!r}: {existing[0]!r} "
                f"declared at {existing[1]} but {normalized_uri!r} declared at "
                f"{origin}"
            )


def _merge_mapping_rows(
    rows: set[str],
    row_origins: dict[str, str],
    file_rows: list[tuple[int, tuple[str, ...]]],
    path: Path,
) -> int:
    total = 0
    for lineno, row in file_rows:
        total += 1
        canonical = _canonical_json(
            {
                field: _nfc(value)
                for field, value in zip(_MAPPING_ROW_FIELDS, row, strict=True)
            }
        )
        if canonical in rows:
            raise ValueError(
                "duplicate mapping row across the mapping set: "
                f"{canonical} first seen at {row_origins[canonical]}, "
                f"again at {path}:{lineno}"
            )
        rows.add(canonical)
        row_origins[canonical] = f"{path}:{lineno}"
    return total


def _mapping_set_payload(
    scalar_metadata: Mapping[str, tuple[str, str]],
    curie_map: Mapping[str, tuple[str, str]],
    rows: set[str],
) -> str:
    metadata = {
        _canonical_json([key, value]) for key, (value, _) in scalar_metadata.items()
    }
    metadata.update(
        _canonical_json(["curie_map", prefix, uri])
        for prefix, (uri, _) in curie_map.items()
    )
    payload = (
        _MAPPING_SET_DOMAIN.encode()
        + b"\0"
        + _canonical_json({"metadata": sorted(metadata), "rows": sorted(rows)}).encode(
            "utf-8"
        )
    )
    return hashlib.sha256(payload).hexdigest()


def compute_mapping_set_digest(paths: Iterable[str | Path] | None = None) -> str:
    """Normalized content digest over the attack-pattern SSSOM mapping set.

    Strict v1 canonical profile:

    - Default discovery requires exactly the six pinned bundled files
      (:data:`_EXPECTED_MAPPING_SET_FILES`); a missing or unexpected file
      fails rather than pinning a subset.  Explicit ``paths`` pin a custom
      set but must name at least one file.
    - Rows must use exactly the six explicit-source columns in
      :data:`_MAPPING_ROW_FIELDS`; unknown/missing columns, malformed rows,
      and empty cells are rejected.
    - Supported semantic comment metadata (``mapping_set_id``,
      ``mapping_set_version``, and ``curie_map`` blocks) is NFC-normalized
      and merged globally, keyed by scalar key and CURIE prefix with first
      origins retained.  Identical repeated declarations across partitions
      are accepted; conflicting values for the same key or prefix are
      rejected with both origins, so a metadata edit either changes the
      digest or fails.  Any other comment shaped like metadata is rejected;
      free explanatory comments are excluded.
    - Rows and metadata are NFC-normalized and framed as sorted
      canonical-JSON sets under a versioned domain, so the digest is
      independent of paths, file partitioning, file order, and row order
      but sensitive to any content addition, removal, or edit.
    - Duplicate canonical rows are rejected (including duplicates across
      file partitions): a set framing must never silently erase malformed
      duplicate provenance.  A mapping set with no rows is rejected.
    """
    scalar_metadata: dict[str, tuple[str, str]] = {}
    curie_map: dict[str, tuple[str, str]] = {}
    rows: set[str] = set()
    row_origins: dict[str, str] = {}
    total_rows = 0
    for path in _mapping_set_paths(paths):
        scalars, curies, file_rows = _read_strict_sssom(path)
        _merge_scalar_metadata(scalar_metadata, scalars, path)
        _merge_curie_entries(curie_map, curies, path)
        total_rows += _merge_mapping_rows(rows, row_origins, file_rows, path)
    if total_rows == 0:
        raise ValueError("mapping set contains no rows")
    return _mapping_set_payload(scalar_metadata, curie_map, rows)


def _checked_identifiers(identifiers: Iterable[str], *, label: str) -> frozenset[str]:
    values = frozenset(identifiers)
    if not values:
        raise ValueError(f"{label} identifier membership must not be empty")
    if any(not isinstance(value, str) or not value for value in values):
        raise ValueError(f"{label} identifiers must be non-empty strings")
    return values


class PinnedTaxonomyResolver:
    """No-I/O taxonomy resolver over pinned membership snapshots.

    ATLAS membership and pins come from the bundled pinned source.  An
    ATLAS-only resolver carries no LAAF pin, so ``taxonomy_context``
    equality fails closed against any chain that pins LAAF.  Explicit LAAF
    support requires the caller to supply both the authoritative pin and
    its identifier membership; exact LAAF ids outside that membership fail
    qualification.
    """

    def __init__(
        self,
        *,
        atlas_pin: TaxonomyPin,
        atlas_identifiers: Iterable[str],
        mapping_set_digest: str,
        laaf_pin: TaxonomyPin | None = None,
        laaf_identifiers: Iterable[str] | None = None,
    ) -> None:
        if (laaf_pin is None) != (laaf_identifiers is None):
            raise ValueError(
                "an explicit LAAF pin and its identifier membership must be "
                "supplied together"
            )
        self._atlas_identifiers = _checked_identifiers(atlas_identifiers, label="ATLAS")
        self._laaf_identifiers = (
            _checked_identifiers(laaf_identifiers, label="LAAF")
            if laaf_identifiers is not None
            else frozenset()
        )
        self._taxonomy_context = TaxonomyContext(
            atlas=atlas_pin,
            laaf=laaf_pin,
            mapping_set_digest=mapping_set_digest,
        )

    @property
    def taxonomy_context(self) -> TaxonomyContext:
        return self._taxonomy_context

    def contains(self, taxonomy: Literal["ATLAS", "LAAF"], identifier: str) -> bool:
        if taxonomy == "ATLAS":
            return identifier in self._atlas_identifiers
        return identifier in self._laaf_identifiers


def load_taxonomy_resolver(
    *,
    atlas_path: str | Path | None = None,
    mapping_set_paths: Iterable[str | Path] | None = None,
    laaf_pin: TaxonomyPin | None = None,
    laaf_identifiers: Iterable[str] | None = None,
) -> PinnedTaxonomyResolver:
    """Construct the production resolver from the pinned bundled sources.

    Performs all I/O up front; the returned resolver is purely in-memory.
    The default is ATLAS-only.  LAAF authority is never bundled: callers
    with a future authoritative LAAF release must explicitly supply both
    its pin and its identifier membership.
    """
    return PinnedTaxonomyResolver(
        atlas_pin=load_atlas_pin(atlas_path),
        atlas_identifiers=load_atlas_identifiers(atlas_path),
        mapping_set_digest=compute_mapping_set_digest(mapping_set_paths),
        laaf_pin=laaf_pin,
        laaf_identifiers=laaf_identifiers,
    )
