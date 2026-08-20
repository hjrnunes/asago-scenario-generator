"""Validator-derived projection alignment tables for STPA Stage 6 prompts.

Stream B Slice 4.  Every narrative, tree, and Gherkin Stage 6 prompt
renders the same compact projection alignment table.  Each row is derived
from the validated projection document and the causal-factor validator
mappings (``predicate_for`` / ``step_kind_for``) — there is no hand-authored
row that can drift from what strict traceability validation accepts.

Projection IDs are semantic structural IDs (PM-*, FB-*, CA-*), never
positional labels; the candidate identifier and UCA reference anchor the
table.
"""

from __future__ import annotations

from typing import Any

from asago_scenario_generator.stpa.models.execution_envelope import (
    CausalFactorKind,
    predicate_for,
    step_kind_for,
)

PROJECTION_ALIGNMENT_COLUMNS = (
    "projection ID",
    "source kind",
    "source ID",
    "assertion ID",
    "assertion predicate",
    "step ID",
    "step kind",
    "order",
    "required reference",
)

_ROW_CELL_KEYS = (
    "projection_id",
    "source_kind",
    "source_id",
    "assertion_id",
    "assertion_predicate",
    "step_id",
    "step_kind",
    "order",
    "required_reference",
)

__all__ = [
    "PROJECTION_ALIGNMENT_COLUMNS",
    "derive_projection_alignment_rows",
    "render_projection_alignment_table",
]


def derive_projection_alignment_rows(
    doc: dict[str, Any],
) -> list[dict[str, Any]]:
    """Derive one alignment row per temporal assertion and the final UCA step.

    Factor rows recompute assertion predicates and step kinds from the
    causal-factor validator mappings rather than trusting the document,
    so the table mirrors what traceability validation accepts.  The UCA
    row is emitted only when the document ends with the unsafe control
    action step.

    Args:
        doc: The canonical projection document.

    Returns:
        Rows in causal-factor order with the UCA row last.
    """
    rows: list[dict[str, Any]] = []
    required_reference = doc["uca_ref"]
    for index, factor in enumerate(doc.get("causal_factors") or []):
        kind = CausalFactorKind(factor["source_kind"])
        source_id = factor["source_id"]
        rows.append(
            {
                "projection_id": source_id,
                "source_kind": factor["source_kind"],
                "source_id": source_id,
                "assertion_id": f"TA-{index + 1}",
                "assertion_predicate": predicate_for(kind).value,
                "step_id": f"S-{index + 1}",
                "step_kind": step_kind_for(kind).value,
                "order": index + 1,
                "required_reference": required_reference,
            }
        )
    steps = doc.get("steps") or []
    if steps and steps[-1].get("step_kind") == "UNSAFE_CONTROL_ACTION":
        last_step = steps[-1]
        rows.append(
            {
                "projection_id": last_step["source_id"],
                "source_kind": "UNSAFE_CONTROL_ACTION",
                "source_id": last_step["source_id"],
                "assertion_id": "-",
                "assertion_predicate": "-",
                "step_id": last_step["step_id"],
                "step_kind": "UNSAFE_CONTROL_ACTION",
                "order": len(rows) + 1,
                "required_reference": required_reference,
            }
        )
    return rows


def render_projection_alignment_table(doc: dict[str, Any]) -> str:
    """Render the compact projection alignment table for one candidate.

    Includes the candidate identifier, the UCA reference, and the
    semantic-structural-ID note so prompts never reduce projection IDs to
    positional labels.  Empty projections produce an empty string (no
    table is rendered).
    """
    rows = derive_projection_alignment_rows(doc)
    if not rows:
        return ""
    lines = [
        f"Projection ID: {doc['candidate_id']}",
        f"UCA reference: {doc['uca_ref']}",
        "Projection IDs are semantic structural IDs "
        "(PM-*, FB-*, CA-*), not positional labels.",
        "",
        "| " + " | ".join(PROJECTION_ALIGNMENT_COLUMNS) + " |",
        "| " + " | ".join("---" for _ in PROJECTION_ALIGNMENT_COLUMNS) + " |",
    ]
    for row in rows:
        cells = [str(row[key]) for key in _ROW_CELL_KEYS]
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)
