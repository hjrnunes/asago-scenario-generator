"""Compatibility accounting and legacy ICA filtering at the accounting stage."""

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
                    SimpleNamespace(ica_id=None, id="ICA-2"),
                    SimpleNamespace(ica_id=None),
                ),
            ),
            {"id": "S-2", "findings": [{"id": "ICA-9"}]},
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


def _record(ica_id: str, disposition: str) -> SimpleNamespace:
    return SimpleNamespace(ica_id=ica_id, disposition=disposition)


def _pairs_passed_to_account(verification: object, pairs: tuple) -> tuple:
    received: dict[str, object] = {}

    def account(**kwargs: object) -> object:
        received.update(kwargs)
        return object()

    # ``slots=None`` makes the typed filter raise TypeError for any exclusion,
    # which selects the duck-typed legacy filter.
    wrapped = SimpleNamespace(
        ica_enumeration=SimpleNamespace(slots=None),
        considerations=pairs,
        ica_hazard_verification=verification,
    )
    _account(ica_enumeration=wrapped, account=account)
    return received["ica_considerations"]  # type: ignore[return-value]


def test_legacy_filter_drops_pairs_that_cite_any_excluded_ica() -> None:
    """Unsupported and incomplete ICAs remove every pair that cites them."""
    kept_supported = SimpleNamespace(ica_ids=("ICA-1",))
    dropped_refuted = SimpleNamespace(ica_ids=("ICA-1", "ICA-2"))
    dropped_incomplete = SimpleNamespace(ica_ids=("ICA-3",))
    kept_empty = SimpleNamespace(ica_ids=())
    kept_untyped = SimpleNamespace()
    verification = SimpleNamespace(
        records=(_record("ICA-1", "supported"), _record("ICA-2", "not_applicable")),
        incomplete_ica_ids=("ICA-3",),
        diagnostics=(),
    )

    result = _pairs_passed_to_account(
        verification,
        (kept_supported, dropped_refuted, dropped_incomplete, kept_empty, kept_untyped),
    )

    assert result == (kept_supported, kept_empty, kept_untyped)


def test_legacy_filter_keeps_every_pair_without_exclusions() -> None:
    """A batch whose typed filtering fails but excludes nothing keeps all pairs."""
    pairs = (SimpleNamespace(ica_ids=("ICA-1",)), SimpleNamespace(ica_ids=()))
    # ``incomplete_ica_ids=None`` fails the typed filter; the legacy one
    # treats it as empty.
    verification = SimpleNamespace(
        records=(_record("ICA-1", "supported"),),
        incomplete_ica_ids=None,
    )

    assert _pairs_passed_to_account(verification, pairs) == pairs
