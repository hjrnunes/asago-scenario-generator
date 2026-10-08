"""Shared test builders moved out of test modules."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import SimpleNamespace
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.synthesis import SynthesisInputs
from asago_scenario_generator.models.target_realization import (
    TargetRealizationResult,
    TargetRealizationSummary,
    canonical_target_realization,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.obligation_aware.revision import RevisionRunResult
from asago_scenario_generator.stpa.obligation_aware.routing import RoutingRunResult
from asago_scenario_generator.stpa.scenario_prod.run import SP3RunResult
from asago_scenario_generator.stpa.system_model.run import SP1RunResult
from tests.helpers.synthesis_fixture import (
    RevisionOutcome,
    baseline_control_structure,
    baseline_loss_analysis,
    final_ica_result,
    obligation_routes,
    structural_revision,
    synthesis_capability_profile,
    synthesis_inputs,
    synthesis_taxonomy_inputs,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservationSnapshot,
)


@dataclass
class _FakeAdapters:
    calls: list[tuple[str, object]]
    gap: bool = False
    with_evidence: bool = False
    revision_outcome: RevisionOutcome = "applied"
    routing_diagnostics: tuple[str, ...] = ()
    recheck_diagnostics: tuple[str, ...] = ()
    scenario_errors: tuple[str, ...] = ()
    candidate_outcomes: tuple[object, ...] | None = None
    scenario_envelopes: tuple[object, ...] | None = None
    loss_analysis: LossAnalysis = field(default_factory=baseline_loss_analysis)
    control_structure: ControlStructure = field(
        default_factory=baseline_control_structure
    )
    revision: RevisionRunResult | None = None

    def prepare_capability(self, **_) -> object:
        return synthesis_capability_profile()

    def build_taxonomy_inputs(self, **_) -> object:
        return synthesis_taxonomy_inputs()

    def plan_obligations(self, *, taxonomy_inputs, **_) -> object:
        self.calls.append(("plan", taxonomy_inputs))
        return plan_taxonomy_obligations(taxonomy_inputs)

    def baseline(self, *, inputs, capability_snapshot, **_) -> object:
        self.calls.append(("baseline", (inputs, capability_snapshot)))
        return SP1RunResult(
            loss_analysis=self.loss_analysis,
            control_structure=self.control_structure,
        )

    def consider(self, *, briefs, loss_analysis, control_structure, **_) -> object:
        briefs = tuple(briefs)
        self.calls.append(("consider", (briefs, loss_analysis, control_structure)))
        evidence = (
            (
                ConsiderationCallEvidence(
                    call_id="stpa-route:batch-0",
                    request_digest="a" * 64,
                    response_digest="b" * 64,
                    attempt_count=2,
                    outcome="accepted",
                ),
            )
            if self.with_evidence
            else ()
        )
        return RoutingRunResult(
            briefs=briefs,
            routes=obligation_routes(
                briefs, "upstream_gap" if self.gap else "targeted"
            ),
            requests=(),
            call_evidence=evidence,
            diagnostics=self.routing_diagnostics,
        )

    def revise(self, *, gaps, loss_analysis, control_structure, **_) -> object:
        self.calls.append(("revise", (tuple(gaps), loss_analysis, control_structure)))
        self.revision = structural_revision(
            gaps,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            outcome=self.revision_outcome,
        )
        return self.revision

    def recheck(self, *, briefs, loss_analysis, control_structure, **_) -> object:
        briefs = tuple(briefs)
        self.calls.append(("recheck", (briefs, loss_analysis, control_structure)))
        return RoutingRunResult(
            briefs=briefs,
            routes=obligation_routes(briefs, "targeted"),
            requests=(),
            call_evidence=(),
            diagnostics=self.recheck_diagnostics,
        )

    def fill_icas(self, *, routes, loss_analysis, control_structure, **_) -> object:
        self.calls.append(
            ("fill_icas", (tuple(routes), loss_analysis, control_structure))
        )
        if self.with_evidence:
            return final_ica_result(
                call_evidence=(
                    ConsiderationCallEvidence(
                        call_id="stpa-slot:RESP-1",
                        request_digest="c" * 64,
                        response_digest="d" * 64,
                        attempt_count=1,
                        outcome="accepted",
                    ),
                ),
            )
        return final_ica_result()

    def scenarios(
        self, *, ica_enumeration, loss_analysis, control_structure, **_
    ) -> object:
        self.calls.append(
            ("scenarios", (ica_enumeration, loss_analysis, control_structure))
        )
        return SP3RunResult(
            scenario_envelopes=(
                ("scenario-1",)
                if self.scenario_envelopes is None
                else self.scenario_envelopes
            ),
            stage_errors=self.scenario_errors,
            candidate_outcomes=self.candidate_outcomes,
        )

    def account(self, *, plan, consideration, ica_enumeration, **_) -> object:
        self.calls.append(("account", (plan, consideration, ica_enumeration)))
        return SimpleNamespace(
            rows=(),
            summary=SimpleNamespace(addressed=1),
            model_dump=lambda **_: {
                "schema_version": "stpa-obligation-accounting-v1",
                "rows": [],
            },
        )

    def realize(self, *, accounting, scenario_result, **_) -> object:
        self.calls.append(("realize", (accounting, scenario_result)))
        return SimpleNamespace(
            records=(),
            summary=SimpleNamespace(total=0, realized=0, unresolved=0, not_requested=0),
            model_dump=lambda **_: {
                "schema_version": "stpa-scenario-realization-v1",
                "records": [],
                "summary": {
                    "total": 0,
                    "realized": 0,
                    "unresolved": 0,
                    "not_requested": 0,
                },
            },
        )


@dataclass
class _TargetAwareFakeAdapters(_FakeAdapters):
    """Record the target boundary while returning an empty typed lens."""

    def target_realize(
        self,
        *,
        inputs,
        execution_target_profile,
        **_,
    ) -> TargetRealizationResult:
        self.calls.append(("target_realization", (inputs, execution_target_profile)))
        return canonical_target_realization(
            TargetRealizationResult(
                baseline_id="baseline:fixture",
                baseline_digest="baseline-digest",
                profile_id=execution_target_profile.target_id,
                profile_digest=execution_target_profile.semantic_digest,
                summary=TargetRealizationSummary(
                    baseline_control_actions=0,
                    observed_operations=0,
                    supported=0,
                    ambiguous=0,
                    unmapped=0,
                    contradictory=0,
                ),
            )
        )

    def enrich_actions(self, **_):
        """The offline fakes keep the deterministic composition provider-free."""
        return None


def _inputs(tmp_path: Path) -> SynthesisInputs:
    return synthesis_inputs(tmp_path)


def _miniklarna_target_package(tmp_path: Path) -> SimpleNamespace:
    """Load the byte-pinned MiniKlarna target package through production validators."""
    fixtures = Path(__file__).parent.parent / "fixtures/miniklarna-baseline-accepted"
    profile_path = fixtures / "execution-target-profile.json"
    context_path = fixtures / "target-runtime-context.json"
    expected_hashes = {
        profile_path: "1c94ba4febb1ff023fc931b81b9a94359acc7e7cc999adbfadf4171191f390cb",
        context_path: "ccd88db7dca1e91969125bbfa7b496a1af84f9b0ae566108884941b81b919c3d",
    }
    assert {
        path: hashlib.sha256(path.read_bytes()).hexdigest() for path in expected_hashes
    } == expected_hashes

    profile = ExecutionTargetProfile.model_validate(
        json.loads(profile_path.read_text(encoding="utf-8"))
    )
    observations = TargetObservationSnapshot.from_runtime_context(
        json.loads(context_path.read_text(encoding="utf-8"))
    )
    inputs = replace(
        _inputs(tmp_path),
        execution_target_profile=profile,
        target_observations=observations,
    )
    return SimpleNamespace(inputs=inputs, profile=profile, observations=observations)


def _runtime(client: object) -> SimpleNamespace:
    return SimpleNamespace(
        client=client,
        temperature=lambda: 0.25,
        obligation_adapter=lambda output_dir: ("runtime-adapter", output_dir),
    )
