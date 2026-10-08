"""A structural revision that raises keeps the baseline and a typed diagnostic."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    run_synthesis,
)
from asago_scenario_generator.stpa.obligation_aware.routing import RoutingRunResult
from asago_scenario_generator.stpa.scenario_prod.run import SP3RunResult
from asago_scenario_generator.stpa.system_model.run import SP1RunResult
from tests.helpers.synthesis_fixture import (
    baseline_control_structure,
    baseline_loss_analysis,
    final_ica_result,
    obligation_routes,
    synthesis_capability_profile,
    synthesis_inputs,
    synthesis_taxonomy_inputs,
)


def _empty_record(schema_version: str, **fields: Any) -> SimpleNamespace:
    return SimpleNamespace(
        **fields,
        model_dump=lambda **_: {"schema_version": schema_version, **fields},
    )


class _RaisingRevision:
    """Route every obligation to an upstream gap; the revision call raises."""

    def __init__(self) -> None:
        self.calls: list[str] = []
        self.fill_structures: list[tuple[Any, Any]] = []
        self.loss_analysis = baseline_loss_analysis()
        self.control_structure = baseline_control_structure()

    def prepare_capability(self, **_: Any) -> Any:
        return synthesis_capability_profile()

    def build_taxonomy_inputs(self, **_: Any) -> Any:
        return synthesis_taxonomy_inputs()

    def plan_obligations(self, *, taxonomy_inputs: Any, **_: Any) -> Any:
        return plan_taxonomy_obligations(taxonomy_inputs)

    def baseline(self, **_: Any) -> Any:
        return SP1RunResult(
            loss_analysis=self.loss_analysis,
            control_structure=self.control_structure,
        )

    def consider(self, *, briefs: Any, **_: Any) -> Any:
        briefs = tuple(briefs)
        return RoutingRunResult(
            briefs=briefs,
            routes=obligation_routes(briefs, "upstream_gap"),
            requests=(),
            call_evidence=(),
        )

    def revise(self, **_: Any) -> Any:
        self.calls.append("revise")
        raise ValueError("invalid deterministic revision response")

    def recheck(self, **_: Any) -> Any:
        self.calls.append("recheck")
        raise AssertionError("a failed revision must not be rechecked")

    def fill_icas(self, *, loss_analysis: Any, control_structure: Any, **_: Any) -> Any:
        self.fill_structures.append((loss_analysis, control_structure))
        return final_ica_result()

    def scenarios(self, **_: Any) -> Any:
        return SP3RunResult(scenario_envelopes=("scenario-1",))

    def account(self, **_: Any) -> Any:
        return _empty_record(
            "stpa-obligation-accounting-v1",
            rows=(),
            summary=SimpleNamespace(addressed=0),
        )

    def realize(self, **_: Any) -> Any:
        return _empty_record(
            "stpa-scenario-realization-v1",
            records=(),
            summary=SimpleNamespace(total=0, realized=0, unresolved=0, not_requested=0),
        )


def test_raising_revision_keeps_the_baseline_without_a_recheck(
    tmp_path: Path,
) -> None:
    fake = _RaisingRevision()

    result = run_synthesis(
        synthesis_inputs(tmp_path, use_case="A deterministic acceptance system"),
        SynthesisAdapters.from_object(fake),
    )

    assert fake.calls == ["revise"]
    assert len(fake.fill_structures) == 1
    loss_analysis, control_structure = fake.fill_structures[0]
    assert loss_analysis is fake.loss_analysis
    assert control_structure is fake.control_structure
    assert result.consideration.revision.status == "technical_failure"
    assert any(
        "structural revision failed: invalid deterministic revision response" in error
        for error in result.stage_errors
    )
