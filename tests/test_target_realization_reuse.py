"""Target realization reuses the pre-ICA operation matching instead of repeating it."""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import (
    TargetRealizationDisposition,
)
from asago_scenario_generator.pipeline.target_realization import (
    observed_operations,
    realize_baseline_rows,
    realize_target_operations,
)
from tests.test_target_realization import (
    _baseline,
    _ExtensionFactory,
    _Interpreter,
    _profile,
    _UnmappedInterpreter,
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
    extension_factory = _ExtensionFactory()

    result = realize_target_operations(
        baseline,
        _profile(),
        _ForbiddenInterpreter,
        extension_factory=extension_factory,
        baseline_rows=rows,
    )

    assert extension_factory.calls == 1
    assert len(extension_factory.interpreter.requests) == 1
    assert tuple(
        item.operation_id
        for item in extension_factory.interpreter.requests[0].operations
    ) == ("get_payment",)
    assert result.rows == rows


def test_realization_without_baseline_rows_maps_each_action_itself():
    interpreter = _UnmappedInterpreter()
    calls: list[str] = []

    def counting(*, action, operations):
        calls.append(action["control_action_id"])
        return interpreter(action=action, operations=operations)

    result = realize_target_operations(_baseline(), _profile(), lambda: counting)

    assert calls == ["CA-1-1"]
    assert result.rows[0].disposition is TargetRealizationDisposition.unmapped
