"""An obligation none of whose findings became a scenario is not addressed.

Accounting credited an obligation ``addressed`` as soon as STPA emitted an
exact structural finding for it.  When scenario writing then failed for every
one of its findings, the accounting still reported it addressed: a saved run
counted ten addressed obligations while its scenario realization recorded
each of their findings as ``scenario_generation_failure`` and realized none.

The fixture is one such row from that run.  Once the run's scenarios are
known, an addressed row that no scenario carries (adversarial or functional
test) becomes ``generation_failed`` with stop reason
``scenario_generation_failure``; it keeps its structural identities, and the
summary counts it once, under ``generation_failed``.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from asago_scenario_generator.models.obligation_accounting import (
    ObligationAccounting,
    ObligationAccountingRow,
    derive_obligation_accounting_summary,
)
from asago_scenario_generator.pipeline.scenario_realization import (
    account_generation_failures,
    build_scenario_realization_assessment,
)
from asago_scenario_generator.pipeline.synthesis_defaults import _default_account
from asago_scenario_generator.stpa.models.scenario_spec import (
    Adversary,
    AdversaryKind,
)
from tests.helpers.governance import (
    _accounting,
    _enumeration,
    _pair,
    _scenario,
)
from tests.test_obligation_stop_reasons import _account, _pattern_row

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures" / "obligation_accounting"

_DISPOSITIONS = (
    "addressed",
    "generation_failed",
    "proposed_not_applicable",
    "unresolved",
    "upstream_gap",
    "capability_excluded",
    "governance_only",
)


def _recorded_row() -> ObligationAccountingRow:
    data = yaml.safe_load(
        (FIXTURES_DIR / "addressed_row_without_scenario.yaml").read_text(
            encoding="utf-8"
        )
    )
    return ObligationAccountingRow.model_validate(data)


def _with_rows(*rows: ObligationAccountingRow) -> ObligationAccounting:
    return ObligationAccounting(
        source_pins=_accounting().source_pins,
        rows=rows,
        summary=derive_obligation_accounting_summary(rows),
    )


def _functional():
    """A scenario Stage 5 compiled as a functional test (no adversary gains)."""
    return _scenario(scenario_id="SCN-002").model_copy(
        update={
            "adversary": Adversary(
                kind=AdversaryKind.none, gain="Nobody gains.", reaches_target_via=None
            )
        }
    )


def _assert_counted_once(accounting: ObligationAccounting) -> None:
    summary = accounting.summary.model_dump()
    assert summary["total"] == len(accounting.rows)
    assert sum(summary.get(name, 0) for name in _DISPOSITIONS) == summary["total"]


def test_the_recorded_row_is_addressed_without_a_scenario() -> None:
    row = _recorded_row()

    assert row.disposition == "addressed"
    assert row.ica_ids == ("RESP-9:CA-9-1:INCORRECT:2",)
    assert row.scope == "outside_boundary"


def test_an_obligation_no_scenario_carries_is_generation_failed() -> None:
    recorded = _recorded_row()
    # Another obligation's scenario exists; none carries the recorded finding.
    accounting = account_generation_failures(
        _with_rows(recorded), scenario_specs=(_scenario(),)
    )

    [row] = accounting.rows
    assert row.disposition == "generation_failed"
    assert row.stop_reason == "scenario_generation_failure"
    assert row.ica_ids == recorded.ica_ids
    assert row.exec_candidate_ids == recorded.exec_candidate_ids
    assert row.scope == recorded.scope
    assert accounting.summary.addressed == 0
    assert accounting.summary.generation_failed == 1
    _assert_counted_once(accounting)
    accounting.assert_integrity()


def test_an_obligation_a_scenario_carries_stays_addressed() -> None:
    accounting = account_generation_failures(
        _accounting(), scenario_specs=(_scenario(),)
    )

    assert accounting == _accounting()
    assert accounting.summary.addressed == 1


def test_a_functional_test_is_not_a_generation_failure() -> None:
    accounting = account_generation_failures(
        _accounting(), scenario_specs=(), functional_test_specs=(_functional(),)
    )

    assert [row.disposition for row in accounting.rows] == ["addressed"]


def test_without_scenarios_every_addressed_row_failed() -> None:
    accounting = account_generation_failures(
        _with_rows(*_accounting().rows, _recorded_row()), scenario_specs=()
    )

    assert accounting.summary.addressed == 0
    assert accounting.summary.generation_failed == 2
    _assert_counted_once(accounting)


def test_an_accounting_without_failures_serializes_as_before() -> None:
    dumped = _accounting().model_dump(mode="json")

    assert "generation_failed" not in dumped["summary"]


def test_realization_records_the_failure_against_the_final_accounting() -> None:
    accounting = account_generation_failures(_accounting(), scenario_specs=())

    realization = build_scenario_realization_assessment(
        accounting=accounting,
        ica_considerations=(_pair(),),
        ica_enumeration=_enumeration(),
        scenario_specs=(),
    )

    [record] = realization.records
    assert record.status == "unresolved"
    assert record.stop_reason == "scenario_generation_failure"
    pin = next(
        item
        for item in realization.source_pins
        if item.artifact_id == "obligation-accounting"
    )
    assert pin.semantic_digest == accounting.semantic_digest


def test_realization_refuses_a_failed_row_that_a_scenario_carries() -> None:
    accounting = account_generation_failures(_accounting(), scenario_specs=())

    with pytest.raises(ValueError, match="generation_failed"):
        build_scenario_realization_assessment(
            accounting=accounting,
            ica_considerations=(_pair(),),
            ica_enumeration=_enumeration(),
            scenario_specs=(_scenario(),),
        )


def test_accounting_built_with_no_scenario_records_the_failure() -> None:
    row = _pattern_row(
        _account("targeted", "plausible_in_system", "supported", scenario_specs=())
    )

    assert row.disposition == "generation_failed"
    assert row.stop_reason == "scenario_generation_failure"


def test_accounting_built_before_scenarios_stays_provisional() -> None:
    row = _pattern_row(_account("targeted", "plausible_in_system", "supported"))

    assert row.disposition == "addressed"


def test_the_default_accounting_adapter_reads_the_scenario_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    def fake_build(**kwargs: object) -> str:
        seen.update(kwargs)
        return "accounting"

    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.obligation_consideration."
        "build_obligation_accounting",
        fake_build,
    )
    adversarial, functional = (_scenario(),), (_functional(),)

    _default_account(
        plan=None,
        consideration=None,
        ica_considerations=(),
        source_pins=(),
        ica_verification=None,
        ica_enumeration=None,
        scenario_result=SimpleNamespace(
            scenario_specs=adversarial, functional_test_specs=functional
        ),
    )

    assert seen["scenario_specs"] == adversarial
    assert seen["functional_test_specs"] == functional
