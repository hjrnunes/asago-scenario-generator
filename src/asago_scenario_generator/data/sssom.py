"""SSSOM TSV parser and ID normalization for asago-scenario-generator.

Parses Simple Standard for Sharing Ontological Mappings (SSSOM) TSV files
and provides utilities for normalizing OWASP LLM Top 10 IDs from the
SSSOM format to our internal format.
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path

from pydantic import BaseModel

logger = logging.getLogger(__name__)


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
    mappings: list[SSSOMMapping] = []

    with open(path, newline="") as f:
        lines = [line for line in f if not line.startswith("#") and line.strip()]

    reader = csv.DictReader(lines, delimiter="\t")
    has_source_cols = (
        reader.fieldnames is not None and "subject_source" in reader.fieldnames
    )

    for row in reader:
        mappings.append(_mapping_from_row(row, has_source_cols))

    return mappings


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


# Pattern: "llm" followed by 1-2 digits, then optionally a year suffix
# and a slug. E.g. "llm062025-excessive-agency" -> "06",
# "llm01-prompt-injection" -> "01"
_LLM_ID_RE = re.compile(r"^llm(\d{2})")


def normalize_llm_id(raw_id: str) -> str:
    """Convert an SSSOM-format LLM ID to our internal format.

    Examples:
        "llm062025-excessive-agency"  -> "LLM06"
        "llm01-prompt-injection"      -> "LLM01"
        "llm102025-unbounded-consumption" -> "LLM10"

    Args:
        raw_id: The raw SSSOM object_id (e.g. "llm062025-excessive-agency").

    Returns:
        Normalized ID string (e.g. "LLM06").

    Raises:
        ValueError: If the raw_id doesn't match the expected pattern.
    """
    match = _LLM_ID_RE.match(raw_id)
    if not match:
        raise ValueError(f"Cannot normalize LLM ID from: {raw_id!r}")
    num = int(match.group(1))
    if not (1 <= num <= 10):
        raise ValueError(
            f"LLM ID numeric part out of range (1-10): {num} from {raw_id!r}"
        )
    return f"LLM{match.group(1)}"


def build_risk_to_llm_index(
    mappings: list[SSSOMMapping],
) -> dict[str, list[str]]:
    """Build a lookup from risk IDs to normalized OWASP LLM Top 10 IDs.

    Filters to rows where object_source contains "owasp-llm", then
    groups by subject_id and normalizes the object_id values.

    Args:
        mappings: List of SSSOMMapping instances (from load_sssom).

    Returns:
        Dict mapping risk_id (subject_id) to a list of normalized LLM IDs
        (e.g. {"atlas-prompt-injection": ["LLM01", "LLM06"]}).
    """
    index: dict[str, list[str]] = {}

    for m in mappings:
        if "owasp-llm" not in m.object_source:
            continue
        if "nomatch" in m.predicate_id.lower():
            logger.debug(
                "Skipping noMatch predicate: %s -> %s (%s)",
                m.subject_id,
                m.object_id,
                m.predicate_id,
            )
            continue
        normalized = normalize_llm_id(m.object_id)
        index.setdefault(m.subject_id, []).append(normalized)

    return index
