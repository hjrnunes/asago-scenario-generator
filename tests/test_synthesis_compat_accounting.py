"""Compatibility accounting at the accounting stage."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    _run_accounting,
)


def _account(*, ica_enumeration: object, routes=(), plan=None, account=None):
    return _run_accounting(
        plan=SimpleNamespace() if plan is None else plan,
        consideration=SimpleNamespace(),
        routes=routes,
        ica_enumeration=ica_enumeration,
        scenario_result=SimpleNamespace(),
        loss_analysis=SimpleNamespace(),
        control_structure=SimpleNamespace(),
        inputs=SimpleNamespace(output_dir=Path(".")),
        snapshot=SimpleNamespace(),
        adapters=SynthesisAdapters(account=account or (lambda **_: None)),
        calls=[],
    )


def test_fallback_accounting_joins_routed_slots_to_their_ica_ids() -> None:
    """Without an accounting artifact, rows list the ICAs of each routed slot."""
    plan = SimpleNamespace(
        obligations=(
            SimpleNamespace(obligation_id="ob-1", scope_disposition="applicable"),
            SimpleNamespace(obligation_id="ob-2", scope_disposition="governance_only"),
        )
    )
    routes = (
        SimpleNamespace(
            obligation_id="ob-1",
            disposition="targeted",
            slot_ids=("S-1", "S-2", "S-3"),
        ),
    )
    enumeration = SimpleNamespace(
        slots=(
            SimpleNamespace(
                slot_id="S-1",
                icas=(
                    SimpleNamespace(ica_id="ICA-1"),
                    SimpleNamespace(ica_id="ICA-2"),
                    SimpleNamespace(ica_id=None),
                ),
            ),
            {"slot_id": "S-2", "icas": [{"ica_id": "ICA-9"}]},
            SimpleNamespace(slot_id=None, icas=(SimpleNamespace(ica_id="ICA-X"),)),
            SimpleNamespace(slot_id="S-3", icas=None),
        )
    )

    result = _account(ica_enumeration=enumeration, routes=routes, plan=plan)
    payload = result.model_dump()

    assert [
        (row["obligation_id"], row["disposition"], row["slot_ids"], row["ica_ids"])
        for row in payload["rows"]
    ] == [
        ("ob-1", "addressed", ["S-1", "S-2", "S-3"], ["ICA-1", "ICA-2", "ICA-9"]),
        ("ob-2", "governance_only", [], []),
    ]
    assert [row["route_refs"] for row in payload["rows"]] == [["ob-1"], []]
    assert payload["summary"]["addressed"] == 1
    assert payload["summary"]["governance_only"] == 1
    assert payload["summary"]["total"] == 2
