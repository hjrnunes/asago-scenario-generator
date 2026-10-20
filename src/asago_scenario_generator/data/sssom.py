"""SSSOM TSV parser for asago-scenario-generator.

Parses Simple Standard for Sharing Ontological Mappings (SSSOM) TSV files.
Object IDs are resolved against the pinned vocabularies in
:mod:`asago_scenario_generator.data.risk_schemes`.
"""

from __future__ import annotations

import csv
from collections.abc import Iterable, Iterator
from pathlib import Path

from pydantic import BaseModel

from asago_scenario_generator.data.risk_schemes import (
    SCHEMES,
    is_edition_scheme,
    is_no_match,
    parse_object_id,
)


class SSSOMMapping(BaseModel):
    """A single row from an SSSOM TSV mapping file."""

    subject_id: str
    subject_source: str
    predicate_id: str
    object_id: str
    object_source: str
    mapping_justification: str


def _split_curie(curie: str) -> tuple[str, str]:
    """Split a CURIE into (prefix, local_id).

    If no colon is present, returns ("", curie).
    """
    if ":" in curie:
        prefix, local = curie.split(":", 1)
        return prefix, local
    return "", curie


def _sssom_row_values(
    row: dict[str, str], has_source_cols: bool
) -> tuple[str, str, str, str]:
    """Resolve (subject_id, subject_source, object_id, object_source)."""
    if has_source_cols:
        return (
            row["subject_id"],
            row["subject_source"],
            row["object_id"],
            row["object_source"],
        )
    subject_source, subject_id = _split_curie(row["subject_id"])
    object_source, object_id = _split_curie(row["object_id"])
    return subject_id, subject_source, object_id, object_source


def load_sssom(path: str | Path) -> list[SSSOMMapping]:
    """Parse an SSSOM TSV file, skipping comment lines.

    Supports two column layouts:
      - Explicit source columns (subject_source, object_source)
      - CURIE-only format where source is derived from the ID prefix
        (e.g. ``ibm-risk-atlas:atlas-hallucination`` → source
        ``ibm-risk-atlas``, id ``atlas-hallucination``)

    Args:
        path: Path to the .sssom.tsv file.

    Returns:
        List of SSSOMMapping instances.
    """
    return [mapping for _, mapping in _numbered_mappings(path)]


def load_checked_sssom(path: str | Path) -> tuple[SSSOMMapping, ...]:
    """Parse an SSSOM file and check every NIST and OWASP row, for every subject.

    The first bad row raises ``ValueError`` naming ``<path>:<line>``, the
    subject risk and the object ID; see :func:`check_sssom` for the rules.
    """
    return _checked(
        (f"{path}:{line}", mapping) for line, mapping in _numbered_mappings(path)
    )


def check_sssom(mappings: Iterable[SSSOMMapping]) -> tuple[SSSOMMapping, ...]:
    """Return ``mappings`` once every NIST and OWASP row is checked.

    A row of an edition-bearing OWASP scheme other than the current one, in
    any spelling, raises ``ValueError``, as does a NIST, OWASP LLM or OWASP
    Agentic object ID outside its pinned vocabulary. ``noMatch`` rows assert
    no object, so their object ID is not read. The error names the row's
    position, subject risk and object ID.
    """
    return _checked(
        (f"row {index}", mapping) for index, mapping in enumerate(mappings, 1)
    )


def _checked(
    located: Iterable[tuple[str, SSSOMMapping]],
) -> tuple[SSSOMMapping, ...]:
    rows = []
    for where, mapping in located:
        source = mapping.object_source
        try:
            if source not in SCHEMES and is_edition_scheme(source):
                raise ValueError(
                    f"{source!r} is not a current scheme; "
                    f"expected one of {sorted(SCHEMES)}"
                )
            if source in SCHEMES and not is_no_match(mapping.predicate_id):
                parse_object_id(source, mapping.object_id)
        except ValueError as exc:
            raise ValueError(
                f"SSSOM {where}: risk {mapping.subject_id!r} maps to "
                f"{mapping.object_id!r} ({source}): {exc}"
            ) from None
        rows.append(mapping)
    return tuple(rows)


def _numbered_mappings(path: str | Path) -> Iterator[tuple[int, SSSOMMapping]]:
    """Each row's mapping with its 1-based line number in the file."""
    with open(path, newline="") as f:
        numbered = [
            (number, line)
            for number, line in enumerate(f, 1)
            if not line.startswith("#") and line.strip()
        ]

    reader = csv.DictReader([line for _, line in numbered], delimiter="\t")
    has_source_cols = (
        reader.fieldnames is not None and "subject_source" in reader.fieldnames
    )

    for row in reader:
        # ``line_num`` counts the lines read so far, the header included.
        yield numbered[reader.line_num - 1][0], _mapping_from_row(row, has_source_cols)


def _mapping_from_row(row: dict[str, str], has_source_cols: bool) -> SSSOMMapping:
    """One SSSOM row as a mapping, resolving the id/source split."""
    subject_id, subject_source, object_id, object_source = _sssom_row_values(
        row, has_source_cols
    )
    return SSSOMMapping(
        subject_id=subject_id,
        subject_source=subject_source,
        predicate_id=row["predicate_id"],
        object_id=object_id,
        object_source=object_source,
        mapping_justification=row["mapping_justification"],
    )
