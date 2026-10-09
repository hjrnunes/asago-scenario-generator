"""Target realization reuses the pre-ICA operation matching instead of repeating it."""

from __future__ import annotations

import pytest

from asago_scenario_generator.stpa.models.execution_classification import (
    mcp_resource_id,
)
from asago_scenario_generator.models.target_realization import (
    TargetRealizationDisposition,
)
from asago_scenario_generator.pipeline.target_realization import (
    observed_operations,
    realize_baseline_rows,
    realize_target_operations,
)
from asago_scenario_generator.stpa.models.control_structure import ControlAction
from tests.helpers.target_realization import (
    _baseline,
    _baseline_with_actions,
    _ExtensionInterpreter,
    _Interpreter,
    _profile,
)


class _ForbiddenInterpreter:
    """Fails the test when realization asks it to map an action."""

    def __init__(self) -> None:
        self.map_calls = 0

    def __call__(self, *, action, operations):
        self.map_calls += 1
        raise AssertionError("realization repeated the operation matching")


def _enrichment_rows(baseline, interpreter):
    rows, _diagnostics = realize_baseline_rows(
        baseline, observed_operations(_profile()), interpreter
    )
    return tuple(rows)


def test_realization_given_baseline_rows_makes_no_map_calls_and_keeps_the_rows():
    baseline = _baseline()
    rows = _enrichment_rows(baseline, _Interpreter())
    interpreter = _ForbiddenInterpreter()

    result = realize_target_operations(
        baseline,
        _profile(),
        lambda: interpreter,
        baseline_rows=rows,
    )

    assert interpreter.map_calls == 0
    assert result.rows == rows
    assert result.rows[0].disposition is TargetRealizationDisposition.supported
    assert result.summary.supported == 1


def test_realization_given_baseline_rows_still_runs_the_extension_once():
    baseline = _baseline()
    rows = _enrichment_rows(baseline, _Interpreter())
    extension = _ExtensionInterpreter()

    result = realize_target_operations(
        baseline,
        _profile(),
        extension,
        baseline_rows=rows,
    )

    assert len(extension.requests) == 1
    assert tuple(item.operation_id for item in extension.requests[0].operations) == (
        "get_payment",
    )
    assert result.rows == rows
    assert len(result.diagnostics) == 1
    assert result.diagnostics[0].startswith("target extension rejected operation ")


class _EveryOperationInterpreter(_Interpreter):
    """Maps CA-1-1 to schedule_payment and CA-1-2 to get_payment."""

    def __call__(self, *, action, operations):
        response = super().__call__(action=action, operations=operations)
        if action["control_action_id"] == "CA-1-2":
            operation = {
                "resource_id": mcp_resource_id("target:mini", "get_payment"),
                "operation_id": "get_payment",
            }
            response["candidate_operations"] = (operation,)
            response["selected_operation"] = operation
            response["evidence_refs"] = ("inventory:mcp:payments/get_payment",)
        return response


def test_extension_is_not_asked_when_every_operation_is_supported():
    baseline = _baseline_with_actions(
        [
            ControlAction(ca_id="CA-1-1", description="Controller schedules a payment"),
            ControlAction(ca_id="CA-1-2", description="Controller reads a payment"),
        ],
        baseline_id="baseline:two",
    )
    rows = _enrichment_rows(baseline, _EveryOperationInterpreter())
    extension = _ExtensionInterpreter()

    result = realize_target_operations(
        baseline, _profile(), extension, baseline_rows=rows
    )

    assert extension.requests == []
    assert result.uncovered_operations == ()


def test_realization_accepts_no_extension_and_diagnoses_each_uncovered_operation():
    baseline = _baseline()
    rows = _enrichment_rows(baseline, _Interpreter())

    result = realize_target_operations(baseline, _profile(), None, baseline_rows=rows)

    assert result.target_derived_control_actions == ()
    assert result.diagnostics == (
        "no extension outcome for observed operation "
        f"{mcp_resource_id('target:mini', 'get_payment')}/get_payment",
    )


def test_realization_requires_baseline_rows():
    interpreter = _ForbiddenInterpreter()

    with pytest.raises(TypeError, match="baseline_rows"):
        realize_target_operations(_baseline(), _profile(), lambda: interpreter)

    assert interpreter.map_calls == 0


@pytest.mark.parametrize(
    "mutate",
    (
        pytest.param(lambda rows: (), id="missing-action"),
        pytest.param(lambda rows: (*rows, *rows), id="duplicate-action"),
        pytest.param(
            lambda rows: tuple(
                row.model_copy(update={"controller_id": "RESP-9"}) for row in rows
            ),
            id="other-controller",
        ),
        pytest.param(
            lambda rows: tuple(
                row.model_copy(update={"control_action_id": "CA-9-9"}) for row in rows
            ),
            id="unknown-action",
        ),
    ),
)
def test_realization_rejects_baseline_rows_for_another_action_set(mutate):
    from asago_scenario_generator.pipeline.target_realization import (
        BaselineRowsMismatchError,
    )

    baseline = _baseline()
    rows = mutate(_enrichment_rows(baseline, _Interpreter()))
    interpreter = _ForbiddenInterpreter()

    with pytest.raises(BaselineRowsMismatchError, match="baseline rows"):
        realize_target_operations(
            baseline,
            _profile(),
            lambda: interpreter,
            baseline_rows=rows,
        )

    assert interpreter.map_calls == 0


class _CountingLlmInterpreter:
    """Stands in for the model-backed interpreter and records every map call."""

    def __init__(self, call_variant: str, log: list[tuple[str, str]]) -> None:
        self.call_variant = call_variant
        self.log = log

    def __call__(self, *, action, operations):
        self.log.append((self.call_variant, action["control_action_id"]))
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "unmapped",
            "candidate_operations": (),
            "selected_operation": None,
            "evidence_refs": (),
            "rationale": "No observed operation completes this action's effect.",
        }


def _run_default_synthesis(tmp_path, monkeypatch, *, enrich):
    from dataclasses import replace

    from asago_scenario_generator.pipeline.synthesis import (
        SynthesisAdapters,
        run_synthesis,
    )
    from asago_scenario_generator.pipeline.synthesis_defaults import (
        _default_enrich_control_actions,
        _default_target_realize,
    )
    from tests.helpers.synthesis import (
        _miniklarna_target_package,
        _runtime,
        _TargetAwareFakeAdapters,
    )

    log: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.target_realization."
        "TargetRealizationLlmInterpreter",
        lambda client, run_dir, *, temperature, call_variant: _CountingLlmInterpreter(
            call_variant, log
        ),
    )
    package = _miniklarna_target_package(tmp_path)
    adapters = replace(
        SynthesisAdapters.from_object(_TargetAwareFakeAdapters(calls=[])),
        target_realize=_default_target_realize,
        model_runtime=_runtime(object()),
        **({"enrich_actions": _default_enrich_control_actions} if enrich else {}),
    )
    result = run_synthesis(package.inputs, adapters)
    return result, log


def test_synthesis_makes_one_map_call_per_control_action_in_total(
    tmp_path, monkeypatch
):
    result, log = _run_default_synthesis(tmp_path, monkeypatch, enrich=True)

    assert log == [("control_action_enrichment", "CA-1-1")]
    assert [row.control_action_id for row in result.target_realization.rows] == [
        "CA-1-1"
    ]


def test_default_adapter_requires_the_enrichment_rows(tmp_path, monkeypatch):
    from asago_scenario_generator.pipeline.synthesis_defaults import (
        _default_target_realize,
    )
    from tests.helpers.synthesis_fixture import (
        baseline_control_structure,
        baseline_loss_analysis,
        final_ica_result,
        synthesis_capability_profile,
    )
    from tests.helpers.synthesis import _miniklarna_target_package, _runtime

    log: list[tuple[str, str]] = []
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.target_realization."
        "TargetRealizationLlmInterpreter",
        lambda client, run_dir, *, temperature, call_variant: _CountingLlmInterpreter(
            call_variant, log
        ),
    )
    package = _miniklarna_target_package(tmp_path)

    with pytest.raises(ValueError, match="operation enrichment"):
        _default_target_realize(
            loss_analysis=baseline_loss_analysis(),
            control_structure=baseline_control_structure(),
            ica_enumeration=final_ica_result().ica_enumeration,
            capability_profile=synthesis_capability_profile(),
            execution_target_profile=package.profile,
            operation_enrichment=None,
            inputs=package.inputs,
            output_dir=tmp_path,
            model_runtime=_runtime(object()),
        )

    assert log == []


def test_default_adapter_hands_the_enrichment_rows_to_realization(
    tmp_path, monkeypatch
):
    from types import SimpleNamespace

    from asago_scenario_generator.pipeline.synthesis_defaults import (
        _default_target_realize,
    )
    from tests.helpers.synthesis_fixture import (
        baseline_control_structure,
        baseline_loss_analysis,
        final_ica_result,
        synthesis_capability_profile,
    )
    from tests.helpers.synthesis import _miniklarna_target_package, _runtime

    seen: dict[str, object] = {}

    def realize_operations(baseline, profile, factory, *, baseline_rows):
        seen["rows"] = baseline_rows
        return "mapped"

    stpa = "asago_scenario_generator.stpa.target_realization"
    monkeypatch.setattr(f"{stpa}.TargetRealizationLlmInterpreter", lambda *a, **k: "i")
    monkeypatch.setattr(f"{stpa}.TargetDerivedICALlmFinder", lambda *a, **k: "f")
    pipeline = "asago_scenario_generator.pipeline.target_realization"
    monkeypatch.setattr(f"{pipeline}.realize_target_operations", realize_operations)
    monkeypatch.setattr(
        f"{pipeline}.realize_target_derived_icas", lambda baseline, mapped, f: mapped
    )
    package = _miniklarna_target_package(tmp_path)
    rows = ("row-1",)

    _default_target_realize(
        loss_analysis=baseline_loss_analysis(),
        control_structure=baseline_control_structure(),
        ica_enumeration=final_ica_result().ica_enumeration,
        capability_profile=synthesis_capability_profile(),
        execution_target_profile=package.profile,
        operation_enrichment=SimpleNamespace(rows=rows),
        inputs=package.inputs,
        output_dir=tmp_path,
        model_runtime=_runtime(object()),
    )

    assert seen["rows"] is rows
