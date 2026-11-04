"""The old ``asago_handoff`` name re-exports the shared contracts core."""

from __future__ import annotations

from pathlib import Path

import pytest

import asago_contracts_core
import asago_handoff
from asago_contracts_core import (
    boundary as core_boundary,
    companion as core_companion,
    condition_eval as core_condition_eval,
    conformance as core_conformance,
    contract as core_contract,
    shape as core_shape,
    violation as core_violation,
    violations as core_violations,
)
from asago_handoff import boundary, companion, condition_eval, conformance, contract
from asago_handoff import shape, violation, violations

CONTRACT_DIR = (
    Path(__file__).resolve().parents[3] / "data" / "contracts" / "scenario-handoff"
)


@pytest.mark.parametrize(
    ("facade", "core"),
    [
        (boundary, core_boundary),
        (companion, core_companion),
        (condition_eval, core_condition_eval),
        (conformance, core_conformance),
        (contract, core_contract),
        (shape, core_shape),
        (violation, core_violation),
        (violations, core_violations),
    ],
)
def test_every_module_re_exports_the_core_objects(facade: object, core: object) -> None:
    assert facade.__all__ == core.__all__
    for name in core.__all__:
        assert getattr(facade, name) is getattr(core, name)


def test_the_package_exports_the_same_rules() -> None:
    assert set(asago_handoff.__all__) <= set(asago_contracts_core.__all__)
    assert asago_handoff.validate_handoff is asago_contracts_core.validate_handoff
    assert asago_handoff.ConformanceResult is asago_contracts_core.ConformanceResult


def test_the_packaged_contract_is_the_cores_copy() -> None:
    assert asago_handoff.packaged_contract() is asago_contracts_core.packaged_contract()
    assert contract.DATA_DIR == core_contract.DATA_DIR


def test_the_old_name_runs_the_authority_kits_conformance_cases() -> None:
    results = asago_handoff.run_conformance(CONTRACT_DIR)

    assert len(results) == 35
    assert [result.case.path for result in results if not result.passed] == []
