"""Accounting cites each Phase 1 evidence reference once.

A Phase 1 plan row may hold repeated evidence records: the planner records one
projection issue for each slot it could not fill, and the record does not name
the slot, so two slots of one kind give two equal records.  A qualification
reason and the record of the facts behind it also share their kind and detail.
Accounting refers to a record by ``phase1:<kind>:<detail>``, so such records
are one reference, and a row that copies Phase 1 evidence names it once.
"""

from __future__ import annotations

from typing import Any

import pytest

from asago_scenario_generator.models.obligation_plan import (
    EvidenceRecord,
    TaxonomyObligation,
    TaxonomyObligationPlan,
    derive_obligation_summary,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_obligation_accounting,
)

from tests.helpers.governance import _accounting_pins, _plan_with_non_stpa_rows

_MISSING_SLOT = EvidenceRecord(
    kind="projection",
    source="missing_compatible_resource",
    detail="no compatible canonical trust_boundary resource for slot",
)
_ABSENT_FACT = "authoritative qualification fact is absent"
_ABSENT_REASON = EvidenceRecord(
    kind="qualification", source="authoritative-projection", detail=_ABSENT_FACT
)
_ABSENT_FACTS = EvidenceRecord(
    kind="qualification", source="qualification-facts", detail=_ABSENT_FACT
)
# Equal records, as two unfilled slots of one kind leave them, and two
# distinct records that share their kind and detail.
_REPEATS = {
    "equal_records": (
        (_MISSING_SLOT, _MISSING_SLOT),
        "phase1:projection:" + _MISSING_SLOT.detail,
    ),
    "shared_detail": (
        (_ABSENT_REASON, _ABSENT_FACTS),
        "phase1:qualification:" + _ABSENT_FACT,
    ),
}


def _with_repeats(
    plan: TaxonomyObligationPlan, disposition: str, repeats: tuple[EvidenceRecord, ...]
) -> TaxonomyObligationPlan:
    """Return *plan* with the first *disposition* row also holding *repeats*."""
    rows = tuple(
        TaxonomyObligation.model_validate(
            {**row.model_dump(), "evidence": (*row.evidence, *repeats)}
        )
        if row.scope_disposition == disposition
        else row
        for row in plan.obligations
    )
    unchecked = plan.model_validate(
        {
            **plan.model_dump(),
            "semantic_digest": "0" * 64,
            "obligations": rows,
            "summary": derive_obligation_summary(rows),
        }
    )
    return plan.model_validate(
        {
            **unchecked.model_dump(),
            "semantic_digest": unchecked.compute_semantic_digest(),
        }
    )


def _row(plan: TaxonomyObligationPlan, disposition: str, scope: str | None) -> Any:
    """Account *plan* with nothing routed; return the *disposition* row."""
    [obligation] = [
        item for item in plan.obligations if item.scope_disposition == disposition
    ]
    consideration = build_consideration_artifact(
        plan=plan, briefs=(), initial_routes=(), final_routes=()
    )
    scopes = {obligation.risk_ref.risk_id: scope} if scope else {}
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        source_pins=_accounting_pins(plan),
        risk_scopes=scopes,
    )
    [row] = [
        item
        for item in accounting.rows
        if item.obligation_id == obligation.obligation_id
    ]
    return row


@pytest.mark.parametrize("repeat", sorted(_REPEATS))
@pytest.mark.parametrize(
    ("disposition", "scope"),
    [
        ("applicable", "outside_boundary"),
        ("applicable", "not_applicable"),
        ("capability_excluded", None),
        ("governance_only", None),
    ],
)
def test_a_row_names_a_repeated_phase1_reference_once(
    disposition: str, scope: str | None, repeat: str
) -> None:
    repeats, reference = _REPEATS[repeat]
    plan = _with_repeats(_plan_with_non_stpa_rows(), disposition, repeats)

    row = _row(plan, disposition, scope)

    assert row.evidence.count(reference) == 1
    [obligation] = [
        item for item in plan.obligations if item.scope_disposition == disposition
    ]
    assert set(row.evidence) == {
        f"phase1:{item.kind}:{item.detail}" for item in obligation.evidence
    }


def test_a_withheld_row_keeps_every_distinct_phase1_reference() -> None:
    plan = _with_repeats(
        _plan_with_non_stpa_rows(), "applicable", (_MISSING_SLOT, _MISSING_SLOT)
    )

    row = _row(plan, "applicable", "outside_boundary")

    [obligation] = [
        item for item in plan.obligations if item.scope_disposition == "applicable"
    ]
    assert len(row.evidence) == len(obligation.evidence) - 1
    assert row.stop_reason == "risk_out_of_scope"
