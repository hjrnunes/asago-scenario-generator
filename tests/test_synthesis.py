"""Public seam tests for the obligation-aware synthesis composition root."""

from __future__ import annotations

import hashlib
import json
from typing import Any
from dataclasses import dataclass, field, replace
from html import escape
from pathlib import Path
from types import SimpleNamespace

import yaml
import pytest

from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
    ObligationIcaConsideration,
)
from asago_scenario_generator.pipeline import synthesis as synthesis_module
from asago_scenario_generator.pipeline.model_runtime import ModelRuntime
from asago_scenario_generator.pipeline.obligation_contracts import (
    RiskCardInput,
    QualificationFactsInput,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.slot_hazard_offer import SlotHazardOfferReport
from asago_scenario_generator.pipeline.control_action_enrichment import (
    ControlActionEnrichment,
    ControlActionOperationEnrichmentRecord,
)
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    SynthesisInputs,
    SynthesisRunStatus,
    run_synthesis,
)
from asago_scenario_generator.pipeline.synthesis_manifest import (
    _manifest_prompt_call_evidence,
    _manifest_provider_evidence,
    _scenario_generation_status,
    _total_prompt_tokens,
)
from asago_scenario_generator.pipeline.synthesis_types import _systemic_inputs
from asago_scenario_generator.stpa.infra.call_log import append_call_log
from asago_scenario_generator.pipeline.synthesis_baseline import (
    _assert_taxonomy_input_identity,
    _prepare_capability_profile,
)
from asago_scenario_generator.pipeline.synthesis_consideration import (
    _close_consideration_artifact,
)
from asago_scenario_generator.pipeline.synthesis_defaults import (
    _default_baseline,
    _default_prepare_capability,
    _default_revision,
    _default_scenarios,
    _default_target_realize,
    _production_defaults,
    _resolve_adapters,
    _resolve_obligation_provider,
)
from asago_scenario_generator.pipeline.synthesis_scenarios import (
    _accounting_source_pins,
    _build_synthesis_scenario_contexts,
    _run_accounting,
    _run_ica_verification,
    _run_scenarios,
)
from asago_scenario_generator.pipeline.synthesis_values import (
    _declared_capability_labels,
    _dump,
    _ica_considerations,
    _ica_verification,
    _ordinary_icas,
    _semantic_digest,
)
from asago_scenario_generator.report.synthesis import (
    _candidate_outcomes_html,
    render_synthesis_report,
)
from asago_scenario_generator.models.target_realization import (
    TargetRealizationResult,
    TargetRealizationSummary,
    canonical_target_realization,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ControlAction,
    ControlledProcess,
    ElementRef,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    Hazard,
    Loss,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.obligation_aware.revision import RevisionRunResult
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    SynthesisSlotFillResult,
)
from asago_scenario_generator.stpa.obligation_aware.routing import RoutingRunResult
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SlotFillRunResult,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaHazardVerificationBatch,
)
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
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from unittest.mock import MagicMock
from asago_scenario_generator.stpa.scenario_prod import context as context_module


def _baseline() -> SP1RunResult:
    return SP1RunResult(
        loss_analysis=baseline_loss_analysis(),
        control_structure=baseline_control_structure(),
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


class _TracingTargetAwareFakeAdapters(_TargetAwareFakeAdapters):
    """Trace target-blind and target-aware inputs through the public root."""

    provider_adapter: object | None = None

    def baseline(
        self,
        *,
        inputs,
        capability_snapshot,
        execution_target_profile,
        target_observations,
        **_,
    ) -> object:
        self.calls.append(
            (
                "baseline",
                {
                    "inputs": inputs,
                    "capability_snapshot": capability_snapshot,
                    "execution_target_profile": execution_target_profile,
                    "target_observations": target_observations,
                },
            )
        )
        return _baseline()

    def consider(
        self,
        *,
        inputs,
        obligation_adapter,
        briefs,
        loss_analysis,
        control_structure,
        **_,
    ) -> object:
        self.calls.append(("consider_boundary", (inputs, obligation_adapter)))
        return super().consider(
            briefs=briefs,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
        )


def _inputs(tmp_path: Path) -> SynthesisInputs:
    return synthesis_inputs(tmp_path)


def test_synthesis_plans_before_baseline_and_keeps_shared_snapshot(
    tmp_path: Path,
) -> None:
    """The composition root plans first and passes one capability identity onward."""
    fake = _FakeAdapters(calls=[])

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    names = [name for name, _ in fake.calls]
    assert names == [
        "plan",
        "baseline",
        "consider",
        "fill_icas",
        "scenarios",
        "account",
        "realize",
    ]
    baseline_inputs, snapshot = fake.calls[1][1]
    assert baseline_inputs is result.inputs
    assert snapshot.profile == synthesis_capability_profile()
    assert (result.output_dir / "capability-profile.yaml").is_file()


def test_synthesis_rejects_a_capability_profile_that_is_not_typed(
    tmp_path: Path,
) -> None:
    """Phase 1 and STPA share one typed profile; a stand-in stops the run."""
    fake = _FakeAdapters(calls=[])
    adapters = replace(
        SynthesisAdapters.from_object(fake),
        prepare_capability=lambda **_: SimpleNamespace(name="stand-in"),
    )

    with pytest.raises(TypeError, match="CapabilityProfile"):
        run_synthesis(_inputs(tmp_path), adapters)

    assert fake.calls == []
    assert not (tmp_path / "capability-profile.yaml").exists()


@pytest.mark.parametrize(
    "taxonomy_inputs",
    (
        lambda: synthesis_taxonomy_inputs().model_dump(mode="json"),
        lambda: SimpleNamespace(),
    ),
    ids=("mapping", "stand-in"),
)
def test_synthesis_rejects_taxonomy_inputs_that_are_not_typed(
    tmp_path: Path, taxonomy_inputs
) -> None:
    """The planner receives only a closed TaxonomyObligationInputs graph."""
    fake = _FakeAdapters(calls=[])
    adapters = replace(
        SynthesisAdapters.from_object(fake),
        build_taxonomy_inputs=lambda **_: taxonomy_inputs(),
    )

    with pytest.raises(TypeError, match="TaxonomyObligationInputs"):
        run_synthesis(_inputs(tmp_path), adapters)

    assert fake.calls == []


def test_taxonomy_input_identity_rejects_facts_the_run_does_not_supply(
    tmp_path: Path,
) -> None:
    """The facts check runs even when the synthesis inputs carry no facts."""
    taxonomy_inputs = synthesis_taxonomy_inputs()
    inputs = replace(_inputs(tmp_path), qualification_facts=None)

    with pytest.raises(ValueError, match="qualification facts do not match"):
        _assert_taxonomy_input_identity(
            taxonomy_inputs,
            inputs,
            synthesis_capability_profile(),
            taxonomy_inputs.capability_snapshot,
        )


def test_failed_baseline_retains_stage_diagnostic_before_obligation_calls(
    tmp_path: Path,
) -> None:
    fake = _FakeAdapters(calls=[])
    error = "stage_2/call_3_coordination: provider rejected unsupported response schema"
    adapters = replace(
        SynthesisAdapters.from_object(fake),
        baseline=lambda **_: SP1RunResult(
            loss_analysis=baseline_loss_analysis(),
            control_structure=None,
            stage_errors=[error],
        ),
    )

    with pytest.raises(
        ValueError, match="provider rejected unsupported response schema"
    ):
        run_synthesis(_inputs(tmp_path), adapters)

    assert [name for name, _ in fake.calls] == ["plan"]


def test_structural_revision_runs_for_every_baseline(tmp_path: Path) -> None:
    """One adaptive analysis: no baseline suppresses the structural revision.

    The observed target is enrichment evidence, so obligation-gap revision
    still runs and no "revision skipped" warning is recorded.
    """
    fake = _FakeAdapters(calls=[], gap=True)

    def baseline(*, inputs, capability_snapshot, **_) -> object:
        return _baseline()

    adapters = replace(SynthesisAdapters.from_object(fake), baseline=baseline)

    result = run_synthesis(_inputs(tmp_path), adapters)

    assert any(name == "revise" for name, _ in fake.calls)
    assert all("revision skipped" not in warning for warning in result.stage_warnings)


def test_synthesis_retains_baseline_diagnostics_without_changing_yield(tmp_path):
    """Later stage manifests must not erase the baseline's unresolved findings."""
    diagnostics = {
        "stage_warnings": ["An <input> repair was required."],
        "heuristic_errors": ["A feedback connection remains missing."],
        "heuristic_warnings": ["A responsibility has no feedback."],
        "solution_neutrality_warnings": [
            "An implementation assumption needs evidence."
        ],
        "post_revision_warnings": [
            "Revision made no structural changes; the explicit gaps remain unresolved."
        ],
    }
    fake = _FakeAdapters(calls=[])
    adapters = replace(
        SynthesisAdapters.from_object(fake),
        baseline=lambda **_: SP1RunResult(
            loss_analysis=baseline_loss_analysis(),
            control_structure=baseline_control_structure(),
            **diagnostics,
        ),
    )

    result = run_synthesis(_inputs(tmp_path), adapters)

    expected = [
        f"Baseline {category}: {warning}"
        for category, warnings in diagnostics.items()
        for warning in warnings
    ]
    saved = yaml.safe_load((tmp_path / "synthesis-manifest.yaml").read_text())
    assert result.stage_warnings == expected
    assert result.manifest["stage_warnings"] == expected
    assert saved["stage_warnings"] == expected
    assert result.scenario_envelopes == ("scenario-1",)
    assert result.stage_errors == []
    assert diagnostics["stage_warnings"] == ["An <input> repair was required."]
    assert result.report_path is not None
    report = result.report_path.read_text()
    assert "Analysis diagnostics" in report
    assert all(escape(warning) in report for warning in expected)
    assert "An <input> repair" not in report


def test_target_profile_is_absent_from_systemic_baseline_inputs(
    tmp_path: Path,
) -> None:
    """The primitive target input first appears at the target lens boundary."""
    fixture = Path("data/contracts/target-profile/target-profile-v1/valid/minimal.json")
    profile = ExecutionTargetProfile.model_validate(
        json.loads(fixture.read_text(encoding="utf-8"))
    )
    profile.assert_integrity()
    fake = _TargetAwareFakeAdapters(calls=[])
    inputs = replace(
        _inputs(tmp_path),
        execution_target_profile=profile,
    )

    result = run_synthesis(inputs, SynthesisAdapters.from_object(fake))

    names = [name for name, _ in fake.calls]
    assert names.index("baseline") < names.index("target_realization")
    baseline_inputs, _snapshot = fake.calls[names.index("baseline")][1]
    realization_inputs, seen_profile = fake.calls[names.index("target_realization")][1]
    assert baseline_inputs.execution_target_profile is None
    assert realization_inputs is inputs
    assert seen_profile is profile
    assert result.target_realization is not None
    assert (
        result.manifest["source_artifacts"]["execution_target_profile"][
            "semantic_digest"
        ]
        == profile.semantic_digest
    )


def test_systemic_inputs_exclude_the_target_inputs(tmp_path: Path) -> None:
    """A systemic input view contains no target profile, observation, or basis."""
    package = _miniklarna_target_package(tmp_path)
    inputs = package.inputs

    systemic = _systemic_inputs(inputs)

    assert systemic.execution_target_profile is None
    assert systemic.target_observations is None
    assert inputs.execution_target_profile is package.profile
    assert inputs.target_observations is package.observations


def _miniklarna_target_package(tmp_path: Path) -> SimpleNamespace:
    """Load the byte-pinned MiniKlarna target package through production validators."""
    fixtures = Path(__file__).parent / "fixtures/miniklarna-baseline-accepted"
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


def test_run_synthesis_routes_the_miniklarna_target_package_without_a_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public root keeps exact target authorities out of systemic inputs."""
    package = _miniklarna_target_package(tmp_path)
    inputs = package.inputs
    profile = package.profile
    observations = package.observations

    def provider_adapter(*args, **kwargs):
        raise AssertionError(
            f"deterministic provider adapter was called: {args!r} {kwargs!r}"
        )

    fake = _TracingTargetAwareFakeAdapters(calls=[])
    fake.obligation_adapter = provider_adapter
    provider_factory_calls: list[object] = []
    client_factory_calls: list[object] = []

    def forbid_provider_factory(*args, **kwargs):
        provider_factory_calls.append((args, kwargs))
        raise AssertionError("deterministic composition constructed a provider")

    def forbid_client_factory(*args, **kwargs):
        client_factory_calls.append((args, kwargs))
        raise AssertionError("deterministic composition constructed a client")

    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.synthesis_defaults._resolve_obligation_provider",
        forbid_provider_factory,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.pipeline.llm_config.resolve_llm_client",
        forbid_client_factory,
    )

    result = run_synthesis(inputs, SynthesisAdapters.from_object(fake))

    baseline = next(value for name, value in fake.calls if name == "baseline")
    systemic, seen_provider = next(
        value for name, value in fake.calls if name == "consider_boundary"
    )
    realization_inputs, seen_profile = next(
        value for name, value in fake.calls if name == "target_realization"
    )
    assert baseline["inputs"].execution_target_profile is None
    assert baseline["inputs"].target_observations is None
    assert baseline["execution_target_profile"] is profile
    assert baseline["target_observations"] is observations
    assert systemic.execution_target_profile is None
    assert systemic.target_observations is None
    assert seen_provider is provider_adapter
    assert realization_inputs is inputs
    assert seen_profile is profile
    assert result.inputs is inputs
    assert provider_factory_calls == []
    assert client_factory_calls == []


def test_run_synthesis_default_baseline_keeps_the_target_package_downstream(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SP1 runs the unified analysis; the target package stays downstream."""
    package = _miniklarna_target_package(tmp_path)
    fake = _TracingTargetAwareFakeAdapters(calls=[])

    def provider_adapter(*args, **kwargs):
        raise AssertionError(
            f"deterministic provider adapter was called: {args!r} {kwargs!r}"
        )

    fake.obligation_adapter = provider_adapter
    client = object()
    client_resolutions: list[tuple[object, ...]] = []
    baseline_calls: list[dict[str, object]] = []

    def resolve_client(*args):
        client_resolutions.append(args)
        return client, "deterministic"

    def run_sp1(**kwargs):
        baseline_calls.append(kwargs)
        assert kwargs["llm_client"] is client
        return _baseline()

    monkeypatch.setattr(
        "asago_scenario_generator.stpa.pipeline.llm_config.resolve_llm_client",
        resolve_client,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.system_model.run.run_sp1",
        run_sp1,
    )
    adapters = replace(SynthesisAdapters.from_object(fake), baseline=None)

    result = run_synthesis(package.inputs, adapters)

    assert len(client_resolutions) == 1
    assert len(baseline_calls) == 1
    call = baseline_calls[0]
    # One unified analysis: the observed target package never enters SP1;
    # enrichment sees it downstream instead.
    assert "execution_target_profile" not in call
    assert "target_observations" not in call
    systemic, seen_provider = next(
        value for name, value in fake.calls if name == "consider_boundary"
    )
    assert systemic.execution_target_profile is None
    assert systemic.target_observations is None
    assert seen_provider is provider_adapter
    assert result.inputs is package.inputs


def test_default_baseline_preserves_explicit_paths_and_risk_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Explicit prepared authorities override their input-path fallbacks."""
    inputs = replace(
        _inputs(tmp_path),
        risk_cards=(),
        risk_extraction_path=tmp_path / "reviewed-risks.yaml",
        loss_analysis_path=tmp_path / "unpinned-loss-analysis.yaml",
    )
    reviewed_risks = [SimpleNamespace(risk_id="reviewed-risk")]
    client = object()
    baseline_result = SimpleNamespace()
    baseline_calls: list[dict[str, object]] = []

    monkeypatch.setattr(
        "asago_scenario_generator.data.loaders.load_reviewed_risk_extraction",
        lambda path: reviewed_risks,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.pipeline.llm_config.resolve_llm_client",
        lambda *args: (client, "deterministic"),
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.system_model.run.run_sp1",
        lambda **kwargs: baseline_calls.append(kwargs) or baseline_result,
    )
    pinned_loss_analysis_path = tmp_path / "pinned-loss-analysis.yaml"

    result = _default_baseline(
        inputs=inputs,
        capability_profile="profile",
        loss_analysis_path=pinned_loss_analysis_path,
        output_dir=tmp_path,
        model_runtime=ModelRuntime.for_inputs(inputs),
    )

    assert result is baseline_result
    assert len(baseline_calls) == 1
    call = baseline_calls[0]
    assert call["risk_cards"] is reviewed_risks
    assert call["capability_profile"] == "profile"
    assert "profile_path" not in call
    assert call["loss_analysis_path"] is pinned_loss_analysis_path


def test_synthesis_runs_no_phase2_verification(tmp_path: Path) -> None:
    """Realization is the last stage; no correspondence verification follows it."""
    fake = _FakeAdapters(calls=[])

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert "verify_phase2" not in SynthesisAdapters.__dataclass_fields__
    assert not hasattr(result, "phase2_verification")
    assert "phase2_verification" not in result.manifest
    assert "verify_phase2" not in result.manifest["stage_call_counts"]
    assert result.stage_errors == []
    written = {path.name for path in tmp_path.iterdir()}
    assert written.isdisjoint(
        {
            "system-resource-map.yaml",
            "correspondence-proposals.yaml",
            "correspondence-reconciliation.yaml",
            "hybrid-coverage-assessment.yaml",
        }
    )
    assert result.report_path is not None
    assert "Phase 2" not in result.report_path.read_text(encoding="utf-8")


def test_synthesis_rechecks_every_applicable_obligation_once_after_revision(
    tmp_path: Path,
) -> None:
    """One revision causes one final structural recheck and never a loop."""
    fake = _FakeAdapters(calls=[], gap=True)

    run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    names = [name for name, _ in fake.calls]
    assert names.count("revise") == 1
    assert names.count("recheck") == 1
    assert names.index("revise") < names.index("recheck")
    recheck_briefs, loss_analysis, control_structure = fake.calls[
        names.index("recheck")
    ][1]
    assert len(recheck_briefs) == 2
    assert fake.revision is not None and fake.revision.status == "applied"
    assert loss_analysis is fake.revision.final_loss_analysis
    assert control_structure is fake.revision.final_control_structure
    assert len(loss_analysis.hazards) == len(fake.loss_analysis.hazards) + 1


@pytest.mark.parametrize(
    ("gap", "revision_outcome"),
    ((False, "applied"), (True, "rejected"), (True, "compile_failure")),
    ids=("no-gap", "rejected-revision", "failed-revision"),
)
def test_consideration_records_no_recheck_diagnostics_without_a_recheck(
    tmp_path: Path, gap: bool, revision_outcome: RevisionOutcome
) -> None:
    """Routing diagnostics appear once; a recheck that never ran adds none."""
    fake = _FakeAdapters(
        calls=[],
        gap=gap,
        revision_outcome=revision_outcome,
        routing_diagnostics=("batch-0 retained valid sibling routes",),
    )

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert "recheck" not in [name for name, _ in fake.calls]
    assert [(item.code, item.detail) for item in result.consideration.diagnostics] == [
        ("routing_diagnostic", "batch-0 retained valid sibling routes")
    ]


def test_consideration_records_recheck_diagnostics_from_the_recheck_pass(
    tmp_path: Path,
) -> None:
    """Each pass that ran contributes its own diagnostics exactly once."""
    fake = _FakeAdapters(
        calls=[],
        gap=True,
        routing_diagnostics=("initial pass note",),
        recheck_diagnostics=("recheck pass note",),
    )

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert sorted(
        (item.code, item.detail) for item in result.consideration.diagnostics
    ) == [
        ("recheck_diagnostic", "recheck pass note"),
        ("routing_diagnostic", "initial pass note"),
    ]


def _seed_call_records(monkeypatch: pytest.MonkeyPatch, *records: dict) -> None:
    """Record *records* in the run's session before the stages run."""
    real = synthesis_module._run_synthesis

    def seeded(inputs: Any, adapters: Any, session: Any) -> Any:
        append_call_log(list(records), Path(inputs.output_dir), session.call_log)
        return real(inputs, adapters, session)

    monkeypatch.setattr(synthesis_module, "_run_synthesis", seeded)


def test_synthesis_manifest_retains_taxonomy_pins_and_stage_call_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The manifest names Phase 1 pins and preserves typed provider evidence."""
    taxonomy_inputs = synthesis_taxonomy_inputs()
    inputs = _inputs(tmp_path)
    record = {
        "stage": "stage_2",
        "step": "control_action",
        "model": "test-model",
        "system_prompt_hash": "system-hash",
        "user_prompt_hash": "user-hash",
        "prompt_tokens": 23,
        "completion_tokens": 5,
        "duration_ms": 7,
        "success": True,
        "response_content": '{"control_actions": []}',
        "prompt_preflight": {
            "rendered_prompt_digest": "a" * 64,
            "input_tokens": 29,
            "input_tokens_estimated": True,
            "context_window": 8_000,
            "maximum_completion_tokens": 1_000,
            "safety_margin": 1_024,
            "usable_input_tokens": 5_976,
            "provider_call_allowed": True,
            "errors": [],
        },
    }
    _seed_call_records(monkeypatch, record)

    run_synthesis(
        inputs,
        SynthesisAdapters.from_object(_FakeAdapters(calls=[], with_evidence=True)),
    )

    manifest = yaml.safe_load(
        (tmp_path / "synthesis-manifest.yaml").read_text(encoding="utf-8")
    )
    atlas = taxonomy_inputs.catalog_pins["atlas"]
    assert manifest["catalog_pins"]["atlas"]["release"] == atlas.release
    assert manifest["catalog_pins"]["atlas"]["digest"] == atlas.digest
    assert set(manifest["mapping_pins"]) == {"sssom", "obligation_edges"}
    assert manifest["provider_evidence"]["consideration_initial"]["call_count"] == 2
    assert manifest["provider_evidence"]["ica"]["call_count"] == 1
    assert manifest["prompt_call_evidence"] == [
        {
            "stage": "stage_2",
            "step": "control_action",
            "model": "test-model",
            "system_prompt_hash": "system-hash",
            "user_prompt_hash": "user-hash",
            "prompt_tokens": 23,
            "completion_tokens": 5,
            "duration_ms": 7,
            "success": True,
            "response_digest": manifest["prompt_call_evidence"][0]["response_digest"],
            "prompt_preflight": {
                "rendered_prompt_digest": "a" * 64,
                "input_tokens": 29,
                "input_tokens_estimated": True,
                "context_window": 8_000,
                "maximum_completion_tokens": 1_000,
                "safety_margin": 1_024,
                "usable_input_tokens": 5_976,
                "provider_call_allowed": True,
                "errors": [],
            },
        }
    ]
    assert len(manifest["prompt_call_evidence"][0]["response_digest"]) == 64
    assert manifest["report"]["normative"] is False
    assert manifest["report"]["digest"] is None


def test_manifest_call_count_sums_requests_sent_including_zero() -> None:
    """A call that sent nothing adds 0, not 1, to the stage's call count."""
    evidence = tuple(
        ConsiderationCallEvidence(
            call_id=f"stpa-route:batch-{index}",
            attempt_count=sent,
            outcome="unresolved" if sent == 0 else "accepted",
        )
        for index, sent in enumerate((0, 3, 0))
    )

    result = _manifest_provider_evidence(
        {"consideration_initial": SimpleNamespace(call_evidence=evidence)},
        SimpleNamespace(profile="synthesis"),
    )

    assert result["consideration_initial"]["call_count"] == 3
    assert [
        item["attempt_count"] for item in result["consideration_initial"]["records"]
    ] == [
        0,
        3,
        0,
    ]


def test_call_evidence_attempt_count_is_a_non_negative_request_count() -> None:
    sent_none = ConsiderationCallEvidence(
        call_id="stpa-route:batch-0", attempt_count=0, outcome="unresolved"
    )

    assert sent_none.attempt_count == 0
    with pytest.raises(ValueError):
        ConsiderationCallEvidence(
            call_id="stpa-route:batch-0", attempt_count=-1, outcome="unresolved"
        )
    with pytest.raises(ValueError):
        ConsiderationCallEvidence(call_id="stpa-route:batch-0", outcome="accepted")


def test_synthesis_manifest_retains_plain_scenario_failures(tmp_path: Path) -> None:
    """A failed scenario stays visible beside the successful scenario count."""
    result = run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(
            _FakeAdapters(
                calls=[],
                scenario_errors=(
                    "Stage 6 context failed for SCN-001: ambiguous constraint",
                ),
            )
        ),
    )

    assert result.manifest["scenario_counts"] == {
        "generated": 1,
        "failed": None,
        "requested": None,
        "attempted": None,
        "skipped": None,
        "functional_test": None,
        "diagnostic_count": 1,
    }
    assert result.manifest["scenario_errors"] == [
        "Stage 6 context failed for SCN-001: ambiguous constraint"
    ]
    assert result.manifest["stage_errors"] == []


def test_synthesis_counts_candidates_separately_from_diagnostics(
    tmp_path: Path,
) -> None:
    """Two failed candidates remain two failures despite four error messages."""
    outcomes = tuple(
        SimpleNamespace(
            scenario_id=f"SCN-{index:03d}",
            ica_slot_id=f"RESP-{index}:CA-{index}-1:INCORRECT",
            ica_id=f"ICA-{index}",
            status=status,
            diagnostics=(),
        )
        for index, status in enumerate(
            ("published", "generation_failed", "rendering_failed", "skipped"), 1
        )
    )
    result = run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(
            _FakeAdapters(
                calls=[],
                candidate_outcomes=outcomes,
                scenario_errors=("first", "second", "third", "fourth"),
            )
        ),
    )

    assert result.manifest["scenario_counts"] == {
        "generated": 1,
        "failed": 2,
        "requested": 4,
        "attempted": 3,
        "skipped": 1,
        "functional_test": 0,
        "diagnostic_count": 4,
    }
    assert [item["status"] for item in result.manifest["candidate_outcomes"]] == [
        "published",
        "generation_failed",
        "rendering_failed",
        "skipped",
    ]
    report = result.report_path.read_text(encoding="utf-8")
    assert "Failed candidates</th><td>2" in report
    assert "Diagnostic messages</th><td>4" in report


def test_synthesis_no_eligible_candidates_has_distinct_valid_status(
    tmp_path: Path,
) -> None:
    """An empty candidate set is a valid analysis outcome, not a failure."""
    result = run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(
            _FakeAdapters(
                calls=[],
                scenario_envelopes=(),
                candidate_outcomes=(),
            )
        ),
    )

    assert result.manifest["run_status"] == "no_candidates"
    assert "status" not in result.manifest
    assert result.manifest["scenario_counts"] == {
        "generated": 0,
        "failed": 0,
        "requested": 0,
        "attempted": 0,
        "skipped": 0,
        "functional_test": 0,
        "diagnostic_count": 0,
    }
    assert result.run_status == "no_candidates"
    assert (tmp_path / "synthesis-manifest.yaml").exists()
    report = result.report_path.read_text(encoding="utf-8")
    assert "Scenario generation status</th><td>no_candidates" in report
    assert "No eligible scenario candidates were available." in report


def test_synthesis_attempted_zero_yield_is_failed_after_artifacts_publish(
    tmp_path: Path,
) -> None:
    """Attempted candidates with no published scenarios are a failed outcome."""
    outcomes = tuple(
        SimpleNamespace(
            scenario_id=f"SCN-{index:03d}",
            ica_slot_id=f"RESP-{index}:CA-{index}-1:INCORRECT",
            ica_id=f"ICA-{index}",
            status="generation_failed",
            diagnostics=("provider contract failure",),
        )
        for index in (1, 2)
    )
    result = run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(
            _FakeAdapters(
                calls=[],
                scenario_envelopes=(),
                candidate_outcomes=outcomes,
            )
        ),
    )

    assert result.manifest["run_status"] == "failed"
    assert result.manifest["scenario_counts"] == {
        "generated": 0,
        "failed": 2,
        "requested": 2,
        "attempted": 2,
        "skipped": 0,
        "functional_test": 0,
        "diagnostic_count": 0,
    }
    assert result.run_status == "failed"
    assert {
        "taxonomy-obligation-plan.yaml",
        "obligation-consideration.yaml",
        "obligation-accounting.yaml",
        "scenario-realization.yaml",
        "synthesis-manifest.yaml",
        "synthesis-report.html",
    }.issubset({path.name for path in tmp_path.iterdir()})
    report = result.report_path.read_text(encoding="utf-8")
    assert "Scenario generation status</th><td>failed" in report
    assert "No scenarios were published after attempting candidates." in report


def test_synthesis_partial_yield_is_degraded_with_separate_candidate_counts(
    tmp_path: Path,
) -> None:
    """A mixed candidate result is degraded while every candidate stays visible."""
    outcomes = (
        SimpleNamespace(
            scenario_id="SCN-001",
            ica_slot_id="RESP-1:CA-1-1:INCORRECT",
            ica_id="ICA-1",
            status="published",
            diagnostics=(),
        ),
        SimpleNamespace(
            scenario_id="SCN-002",
            ica_slot_id="RESP-2:CA-2-1:INCORRECT",
            ica_id="ICA-2",
            status="rendering_failed",
            diagnostics=("rendering failed",),
        ),
        SimpleNamespace(
            scenario_id="SCN-003",
            ica_slot_id="RESP-3:CA-3-1:INCORRECT",
            ica_id="ICA-3",
            status="skipped",
            diagnostics=("not attempted",),
        ),
    )
    result = run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(
            _FakeAdapters(
                calls=[],
                scenario_envelopes=("scenario-1",),
                candidate_outcomes=outcomes,
            )
        ),
    )

    assert result.manifest["run_status"] == "degraded"
    assert result.manifest["scenario_counts"] == {
        "generated": 1,
        "failed": 1,
        "requested": 3,
        "attempted": 2,
        "skipped": 1,
        "functional_test": 0,
        "diagnostic_count": 0,
    }
    assert [item["status"] for item in result.manifest["candidate_outcomes"]] == [
        "published",
        "rendering_failed",
        "skipped",
    ]
    report = result.report_path.read_text(encoding="utf-8")
    assert "Scenario generation status</th><td>degraded" in report
    assert "Published candidates</th><td>1" in report
    assert "Failed candidates</th><td>1" in report
    assert "Skipped candidates</th><td>1" in report


def test_synthesis_status_helper_covers_each_terminal_count_shape() -> None:
    """Each public terminal status remains a deterministic count mapping."""
    cases = (
        (
            {"requested": None, "attempted": None, "generated": None},
            (SynthesisRunStatus.UNKNOWN, "candidate_outcomes_unavailable"),
        ),
        (
            {"requested": 0, "attempted": 0, "generated": 0},
            (SynthesisRunStatus.NO_CANDIDATES, "no_eligible_candidates"),
        ),
        (
            {"requested": 2, "attempted": 2, "generated": 0},
            (SynthesisRunStatus.FAILED, "zero_yield_after_attempts"),
        ),
        (
            {"requested": 2, "attempted": 2, "generated": 2},
            (SynthesisRunStatus.COMPLETED, "all_requested_candidates_resolved"),
        ),
        (
            {"requested": 2, "attempted": 2, "generated": 0, "functional_test": 2},
            (SynthesisRunStatus.COMPLETED, "all_requested_candidates_resolved"),
        ),
        (
            {"requested": 2, "attempted": 2, "generated": 0, "functional_test": 1},
            (SynthesisRunStatus.DEGRADED, "requested_candidates_not_attempted"),
        ),
        (
            {"requested": 3, "attempted": 2, "generated": 1},
            (SynthesisRunStatus.DEGRADED, "partial_candidate_yield"),
        ),
        (
            {"requested": 2, "attempted": 0, "generated": 0},
            (SynthesisRunStatus.DEGRADED, "requested_candidates_not_attempted"),
        ),
    )
    for counts, expected in cases:
        assert _scenario_generation_status(counts) == expected


def test_candidate_outcomes_report_has_distinct_empty_and_record_views() -> None:
    """The report distinguishes unavailable, empty, and populated outcomes."""
    assert "not reported" in _candidate_outcomes_html(None)
    assert "No scenario candidates were requested." in _candidate_outcomes_html(())
    report = _candidate_outcomes_html(
        (
            SimpleNamespace(
                scenario_id="SCN-<1>",
                ica_slot_id="SLOT-1",
                ica_id=None,
                status=None,
                diagnostics=("bad <diagnostic>",),
            ),
        )
    )
    assert "SCN-&lt;1&gt;" in report
    assert "bad &lt;diagnostic&gt;" in report
    assert "<td><code>—</code></td>" in report


def test_report_stop_reasons_come_from_the_manifest_counts(tmp_path: Path) -> None:
    """The report renders the manifest's terminal counts, not its own tally."""
    path = render_synthesis_report(
        tmp_path,
        manifest={
            "obligation_stop_reason_counts": {
                "scenario_realized": 2,
                "addressed": 1,
            }
        },
        plan=None,
        consideration=None,
        accounting=SimpleNamespace(
            rows=(SimpleNamespace(obligation_id="ob-1", stop_reason="other"),)
        ),
        realization=None,
        scenario_result=None,
    )
    html = path.read_text(encoding="utf-8")
    assert (
        "<tr><th>addressed</th><td>1</td></tr>"
        "\n<tr><th>scenario_realized</th><td>2</td></tr>"
    ) in html
    assert "<th>other</th>" not in html


def test_synthesis_manifest_keeps_revision_as_compact_evidence_mapping(
    tmp_path: Path,
) -> None:
    """Revision manifests retain decisions and evidence, not provider objects."""
    fake = _FakeAdapters(calls=[], gap=True, revision_outcome="compile_failure")

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    revision = fake.revision
    assert revision is not None and revision.status == "technical_failure"
    assert revision.request is not None and revision.response is not None
    revision_record = result.manifest["revision"]
    assert isinstance(revision_record, dict)
    assert revision_record["status"] == "technical_failure"
    assert revision_record["trigger_obligation_ids"] == sorted(
        revision.trigger_obligation_ids
    )
    assert len(revision_record["trigger_obligation_ids"]) == 2
    assert revision_record["trigger_gap_ids"] == sorted(revision.trigger_gap_ids)
    assert revision_record["diagnostics"] == list(revision.diagnostics)
    assert revision_record["diagnostics"][0].startswith("compile failure: ")
    assert revision_record["request"] == {
        "schema_version": revision.request.schema_version,
        "semantic_digest": revision.request.semantic_digest,
    }
    assert revision_record["response"] == {
        "status": "completed",
        "request_digest": revision.request.semantic_digest,
        "response_ref": revision.response.response_ref,
    }
    assert revision_record["call_evidence"] == [
        {
            "call_id": "stpa-revision:one-round",
            "outcome": "technical_failure",
            "request_digest": revision.request.semantic_digest,
            "response_digest": revision.call_evidence.response_digest,
            "attempt_count": 0,
        }
    ]
    rendered = yaml.safe_dump(revision_record, sort_keys=False)
    assert "RevisionRunResult(" not in rendered
    assert "LossAnalysis(" not in rendered
    assert set(revision_record) == {
        "status",
        "trigger_obligation_ids",
        "trigger_gap_ids",
        "diagnostics",
        "request",
        "response",
        "call_evidence",
    }


def test_synthesis_manifest_records_that_no_run_resumes(tmp_path: Path) -> None:
    """The manifest keeps its resume keys at fixed values."""
    fake = _FakeAdapters(calls=[])

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert result.manifest["resume"] == {
        "requested": False,
        "state": "not_requested",
        "reused_stages": [],
        "checkpoint": None,
    }


def test_synthesis_manifest_records_only_the_supplied_model_controls(
    tmp_path: Path,
) -> None:
    """One profile and the worker count are the only model controls."""
    inputs = replace(_inputs(tmp_path), profile="fixture-profile", max_workers=3)

    result = run_synthesis(
        inputs, SynthesisAdapters.from_object(_FakeAdapters(calls=[]))
    )

    assert result.manifest["model_controls"] == {
        "profile": "fixture-profile",
        "max_workers": 3,
    }


def test_reviewed_risk_loader_matches_phase1_projection_without_taxonomy_filter(
    tmp_path: Path,
) -> None:
    """Synthesis preserves every reviewed risk and exact Phase 1 evidence."""
    snapshot_path = Path(
        "output/runs/20260829-phase12-live/klarna-obligation-snapshot-corrected.yaml"
    )
    if snapshot_path.exists():
        snapshot_risks = yaml.safe_load(snapshot_path.read_text(encoding="utf-8"))[
            "risk_cards"
        ]
    else:
        snapshot_risks = [
            {
                "risk_id": "risk-ibm",
                "risk_name": "IBM risk",
                "risk_description": "Reviewed IBM risk.",
                "taxonomy": "ibm-risk-atlas",
                "confidence": 0.9,
                "grounding_confidence": "high",
                "evidence": [
                    {"text": "evidence", "source": "review.pdf", "relevance": None}
                ],
                "mitigations": [],
            },
            {
                "risk_id": "risk-other",
                "risk_name": "Other risk",
                "risk_description": "Reviewed non-IBM risk.",
                "taxonomy": "credo-ucf",
                "confidence": 0.8,
                "grounding_confidence": "medium",
                "evidence": [],
                "mitigations": [],
            },
        ]

    raw_records = []
    for item in snapshot_risks:
        record = dict(item)
        record["evidence"] = [
            {
                "text": evidence["text"],
                "document": evidence.get("source"),
                "relevance": evidence.get("relevance"),
                # This ranking field must not become Phase 1 relevance.
                "cross_encoder_score": 0.123,
            }
            for evidence in item.get("evidence", [])
        ]
        record["mitigations"] = [
            {
                "action_id": mitigation.get("mitigation_id"),
                "action_name": mitigation.get("description"),
                "source": mitigation.get("source"),
            }
            for mitigation in item.get("mitigations", [])
        ]
        raw_records.append(record)
    raw_path = tmp_path / "risk-extraction.json"
    raw_path.write_text(json.dumps({"risks": raw_records}), encoding="utf-8")

    loaded = tuple(
        RiskCardInput.model_validate(item.model_dump(mode="json"))
        for item in load_reviewed_risk_extraction(raw_path)
    )
    expected = tuple(
        sorted(
            (RiskCardInput.model_validate(item) for item in snapshot_risks),
            key=lambda item: item.risk_id,
        )
    )
    assert tuple(sorted(loaded, key=lambda item: item.risk_id)) == expected
    assert {item.taxonomy for item in loaded} == {item.taxonomy for item in expected}


def test_default_stpa_workers_close_typed_consideration_and_accounting(
    tmp_path: Path,
) -> None:
    """The production defaults accept a fake provider without duck-typed accounting."""
    from asago_scenario_generator.models.obligation_consideration import (
        MissingStructuralConcept,
        ObligationRoute,
    )
    from asago_scenario_generator.stpa.obligation_aware.contracts import (
        AnalysisControls,
        IcaDeviationDraft,
        IcaFindingDraft,
        ObligationIcaDraft,
        RevisionDraft,
        SlotIcaDraft,
        StructuralRevisionResponse,
        StructuralRoutingResponse,
        SynthesisSlotResponse,
    )
    from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
        IcaHazardVerificationCorrection,
    )
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlAction,
        ControlStructure,
        ControlledProcess,
        ElementRef,
        FeedbackChannel,
        ProcessModelPart,
        ReferenceType,
        Responsibility,
        ResponsibilityConstraint,
    )
    from asago_scenario_generator.stpa.models.loss_analysis import (
        Hazard,
        Loss,
        LossAnalysis,
        LossProvenance,
        SecurityConstraint,
    )
    from tests.helpers.obligation_factory import make_inputs

    pattern_inputs = make_inputs()
    plan_inputs = pattern_inputs
    plan = __import__(
        "asago_scenario_generator.pipeline.obligation_planner",
        fromlist=["plan_taxonomy_obligations"],
    ).plan_taxonomy_obligations(plan_inputs)
    row = plan.obligations[0]
    slot_id = "RESP-1:CA-1-1:NOT_PROVIDED"
    provider_controls = AnalysisControls(
        model_profile="fake-synthesis",
        model_name="fake-provider",
        deadline_seconds=30.0,
        temperature=0.0,
    )

    loss_analysis = LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="A protected operation is harmed.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=(row.risk_ref.risk_id,),
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="An unsafe request is accepted.",
                related_losses=("L-1",),
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Requests must satisfy policy.",
                related_hazards=("H-1",),
            ),
        ),
    )
    responsibility = Responsibility(
        resp_id="RESP-1",
        description="Validate incoming requests.",
        responsibility_constraints=(
            ResponsibilityConstraint(
                rc_id="RC-1-1", description="Requests must be validated."
            ),
        ),
        process_model_parts=(
            ProcessModelPart(
                pm_id="PM-1-1",
                description="Request state.",
                values=["valid", "invalid"],
            ),
        ),
        control_actions=(
            ControlAction(
                ca_id="CA-1-1",
                description="Validate request.",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                process_model_refs=["PM-1-1"],
            ),
        ),
        feedback_channels=(
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Request feedback.",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ),
    )
    control_structure = ControlStructure(
        responsibilities=(responsibility,),
        controlled_processes=(
            ControlledProcess(cp_id="CP-1", description="Request process."),
        ),
        coordination_links=(),
    )

    class FakeProvider:
        controls = provider_controls
        purposes: list[str] = []
        fill_targets: list[str] = []
        stage_provider_ids: list[int] = []
        verification_calls: list[tuple[tuple[str, ...], object]] = []

        def route(self, request, *, correction_feedback=None):
            self.stage_provider_ids.append(id(self))
            self.purposes.append(request.purpose)
            if request.purpose == "initial":
                routes = tuple(
                    ObligationRoute(
                        obligation_id=brief.obligation_id,
                        disposition="upstream_gap",
                        rationale="A structural hazard needs one revision pass.",
                        missing_concepts=(
                            MissingStructuralConcept(
                                concept_type="hazard",
                                description="The baseline hazard is not explicit.",
                                evidence_refs=("fake-provider",),
                                obligation_id=brief.obligation_id,
                            ),
                        ),
                        evidence=("fake-provider",),
                    )
                    for brief in request.briefs
                )
            else:
                routes = tuple(
                    ObligationRoute(
                        obligation_id=brief.obligation_id,
                        disposition="targeted",
                        slot_ids=(slot_id,),
                        hazard_ids=("H-1",),
                        constraint_ids=("SC-1",),
                        evidence=("H-1", "SC-1"),
                    )
                    for brief in request.briefs
                )
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=routes,
            )

        def revise(self, request):
            self.stage_provider_ids.append(id(self))
            return StructuralRevisionResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                draft=RevisionDraft(
                    trigger_gap_ids=tuple(gap.gap_id for gap in request.gaps),
                    trigger_obligation_ids=tuple(
                        gap.obligation_id
                        for gap in request.gaps
                        if gap.obligation_id is not None
                    ),
                ),
            )

        def fill(self, request):
            self.stage_provider_ids.append(id(self))
            self.fill_targets.append(request.target_id)
            filled = []
            for slot in request.slots:
                if slot.slot_id == slot_id and request.routed_routes:
                    filled.append(
                        SlotIcaDraft(
                            slot_id=slot.slot_id,
                            is_na=False,
                            findings=(
                                IcaFindingDraft(
                                    deviation=IcaDeviationDraft(
                                        not_provided_context=(
                                            "the request is not reviewed"
                                        )
                                    ),
                                    hazardous_context="Unsafe request state.",
                                    loss_consequence=(
                                        "The protected operation is harmed."
                                    ),
                                    related_hazard_ids=("H-1",),
                                    related_constraint_ids=("SC-1",),
                                ),
                            ),
                            consideration_results=tuple(
                                ObligationIcaDraft(
                                    obligation_handle=route.obligation_id,
                                    disposition="finding",
                                    finding_indexes=(0,),
                                    rationale="The routed concern is addressed.",
                                )
                                for route in request.routed_routes
                            ),
                        )
                    )
                else:
                    filled.append(
                        SlotIcaDraft(
                            slot_id=slot.slot_id,
                            is_na=True,
                            na_rationale="No routed concern applies.",
                        )
                    )
            return SynthesisSlotResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                filled_slots=tuple(filled),
            )

        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            self.stage_provider_ids.append(id(self))
            requests = tuple(requests)
            self.verification_calls.append(
                (tuple(request.ica_id for request in requests), correction_feedback)
            )
            return tuple(
                {
                    "ica_id": request.ica_id,
                    "verdict": (
                        "supported" if correction_feedback else "insufficient_evidence"
                    ),
                    "rationale": "The typed STPA path is coherent after one correction.",
                    **(
                        {
                            "absence_loss_ids": (request.losses[0].loss_id,),
                            "absence_consequence": "The unsafe request is accepted.",
                        }
                        if correction_feedback
                        else {}
                    ),
                }
                for request in requests
            )

        def correct_ica_hazard(self, request, verdict):
            return IcaHazardVerificationCorrection(
                ica_id=request.ica_id,
                deviation=request.deviation + " after checking the timing fact",
                rationale="Add the missing typed timing fact.",
            )

    provider = FakeProvider()
    inputs = SynthesisInputs(
        use_case="A system that handles requests",
        risk_cards=pattern_inputs.risk_cards,
        qualification_facts=pattern_inputs.qualification_facts,
        output_dir=tmp_path,
    )
    adapters = SynthesisAdapters(
        prepare_capability=lambda **_: pattern_inputs.capability_snapshot.profile,
        build_taxonomy_inputs=lambda **_: pattern_inputs,
        obligation_adapter=provider,
        baseline=lambda **_: SP1RunResult(
            loss_analysis=loss_analysis,
            control_structure=control_structure,
        ),
        scenarios=lambda **_: SP3RunResult(
            scenario_envelopes=(), candidate_outcomes=None
        ),
    )

    result = run_synthesis(inputs, adapters)

    assert provider.purposes == ["initial", "recheck"]
    assert provider.stage_provider_ids
    assert set(provider.stage_provider_ids) == {id(provider)}
    assert result.consideration.schema_version == "stpa-obligation-consideration-v1"
    assert result.accounting.schema_version == "stpa-obligation-accounting-v1"
    assert result.accounting.rows[0].disposition == "addressed"
    assert result.accounting.rows[0].stop_reason == "addressed"
    assert len(provider.verification_calls) == 2
    assert provider.verification_calls[0][0] == provider.verification_calls[1][0]
    assert provider.verification_calls[0][1] is None
    assert provider.verification_calls[1][1]
    assert result.manifest["obligation_resolution_funnel"] == {
        "all_plan_rows": 1,
        "governance_only": 0,
        "capability_excluded": 0,
        "applicable_and_considered": 1,
        "terminal_reasons": {"scenario_generation_failure": 1},
        "terminal_reason_total": 1,
        "reconciles": True,
        "realized_obligation_denominator": 0,
        "admitted_scenario_denominator": 0,
    }
    assert result.manifest["context_tables"] == {
        "row_budget": 12,
        "actions": [
            {
                "control_action": "CA-1-1",
                "combinations": 2,
                "rows_shown": 2,
                "hidden_values": [],
            }
        ],
    }
    assert result.ica_considerations
    assert result.ica_enumeration is not None
    assert (tmp_path / "obligation-consideration.yaml").exists()
    assert (tmp_path / "obligation-accounting.yaml").exists()
    offers = SlotHazardOfferReport.from_yaml(
        (tmp_path / "slot-hazard-offers.yaml").read_text(encoding="utf-8")
    )
    assert offers.summary.routed_slots == 1
    assert result.accounting.slot_hazard_offers == offers.summary
    assert result.artifact_paths["slot-hazard-offers.yaml"] == (
        tmp_path / "slot-hazard-offers.yaml"
    )


def test_scenario_failure_is_recorded_without_erasing_accounting(
    tmp_path: Path,
) -> None:
    """SP3 failure is non-fatal once final ICA evidence exists."""
    fake = _FakeAdapters(calls=[])

    def fail_scenarios(**_: object) -> object:
        raise RuntimeError("SP3 failed")

    fake.scenarios = fail_scenarios  # type: ignore[method-assign]
    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert any("scenario generation failed" in error for error in result.stage_errors)
    names = [name for name, _ in fake.calls]
    assert names[-1] == "realize"
    assert result.accounting is not None


def test_accounting_without_a_numeric_summary_is_an_error(tmp_path: Path) -> None:
    """The manifest counts come from the accounting artifact, never a guess."""
    fake = _FakeAdapters(calls=[])

    def account_without_summary(**_: object) -> object:
        return SimpleNamespace(
            rows=(),
            summary=None,
            model_dump=lambda **_: {
                "schema_version": "stpa-obligation-accounting-v1",
                "rows": [],
            },
        )

    fake.account = account_without_summary  # type: ignore[method-assign]

    with pytest.raises(ValueError, match="must carry a numeric summary"):
        run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))


def test_accounting_receives_the_verified_ordinary_ica_enumeration() -> None:
    """Verifier metadata must not masquerade as the ICA enumeration."""
    wrapped = final_ica_result(
        ica_hazard_verification=IcaHazardVerificationBatch(batch_id="verification")
    )
    ordinary = wrapped.ica_enumeration
    verification = wrapped.ica_hazard_verification
    received: dict[str, object] = {}
    expected = object()

    def account(**kwargs: object) -> object:
        received.update(kwargs)
        return expected

    run = _run_accounting(
        plan=SimpleNamespace(),
        consideration=SimpleNamespace(),
        routes=(),
        ica_enumeration=wrapped,
        scenario_result=SimpleNamespace(),
        loss_analysis=SimpleNamespace(),
        control_structure=SimpleNamespace(),
        inputs=SimpleNamespace(output_dir=Path(".")),
        snapshot=SimpleNamespace(),
        adapters=SynthesisAdapters(account=account),
        slot_evidence=wrapped,
    )

    assert run.value is expected
    assert run.calls == ("account",)
    assert received["ica_enumeration"] is ordinary
    assert received["ica_verification"] is verification


def test_target_projected_final_icas_carry_no_slot_evidence() -> None:
    """A target-projected enumeration has no obligation pairs or verification."""
    projected = ICAEnumeration(slots=[])
    fill = final_ica_result(
        ica_hazard_verification=IcaHazardVerificationBatch(batch_id="verification")
    )

    assert _ordinary_icas(projected) is projected
    assert _ica_considerations(projected) == ()
    assert _ica_verification(projected) is None
    assert _ordinary_icas(fill) is fill.ica_enumeration
    assert _ica_considerations(fill) == ()
    assert _ica_verification(fill) is fill.ica_hazard_verification


def _slot_fill(
    pair: ObligationIcaConsideration, verification: IcaHazardVerificationBatch
) -> SlotFillRunResult:
    return SlotFillRunResult(
        result=SynthesisSlotFillResult(
            ica_enumeration=ICAEnumeration(slots=[]),
            considerations=(pair,),
            ica_hazard_verification=verification,
        )
    )


def _slot_pair() -> ObligationIcaConsideration:
    return ObligationIcaConsideration(
        route_id="route-1",
        obligation_id=f"ob:v1:{'1' * 64}",
        slot_id="RESP-1:CA-1-1:INCORRECT",
        disposition="finding",
        ica_ids=("RESP-1:CA-1-1:INCORRECT:1",),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("The selected ICA responds to the obligation concern.",),
    )


def test_accounting_receives_the_unprojected_pairs_beside_the_projected_icas() -> None:
    """The projection drops the slot evidence; accounting reads it from the fill."""
    verification = IcaHazardVerificationBatch(batch_id="verification")
    pair = _slot_pair()
    fill = _slot_fill(pair, verification)
    projected = ICAEnumeration(slots=[])
    received: dict[str, object] = {}

    def account(**kwargs: object) -> object:
        received.update(kwargs)
        return object()

    _run_accounting(
        plan=SimpleNamespace(),
        consideration=SimpleNamespace(),
        routes=(),
        ica_enumeration=projected,
        scenario_result=SimpleNamespace(),
        loss_analysis=SimpleNamespace(),
        control_structure=SimpleNamespace(),
        inputs=SimpleNamespace(output_dir=Path(".")),
        snapshot=SimpleNamespace(),
        adapters=SynthesisAdapters(account=account),
        slot_evidence=fill,
    )

    assert received["ica_enumeration"] is projected
    assert received["ica_considerations"] == (pair,)
    assert received["ica_verification"] == verification


def test_run_synthesis_hands_accounting_the_fill_evidence_on_the_projected_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Only the accounting call changes: scenarios still get the projected ICAs."""
    verification = IcaHazardVerificationBatch(batch_id="verification")
    pair = _slot_pair()
    projected = ICAEnumeration(slots=[])
    received: dict[str, object] = {}

    class Adapters(_FakeAdapters):
        def fill_icas(self, **_: object) -> object:
            return _slot_fill(pair, verification)

        def account(self, **kwargs: object) -> object:
            received.update(kwargs)
            return super().account(**kwargs)

    monkeypatch.setattr(
        synthesis_module,
        "_target_realized_stpa_inputs",
        lambda **kwargs: (kwargs["control_structure"], projected),
    )
    fake = Adapters(calls=[])

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    scenario_icas = next(value[0] for name, value in fake.calls if name == "scenarios")
    assert scenario_icas is projected
    assert received["ica_enumeration"] is projected
    assert received["ica_considerations"] == (pair,)
    # The fill's own verification is replaced: the stage verifies the final ICAs.
    assert received["ica_verification"].batch_id == "synthesis-ica-hazard-verification"
    assert result.ica_considerations == (pair,)


def test_ica_verification_runs_without_an_obligation_adapter() -> None:
    """A run with no verifier records a verification batch instead of skipping."""
    fill = _slot_fill(_slot_pair(), IcaHazardVerificationBatch(batch_id="from-fill"))

    verified = _run_ica_verification(
        fill,
        adapters=SynthesisAdapters(obligation_adapter=None),
        loss_analysis=None,
        control_structure=None,
        inputs=None,
    )

    batch = _ica_verification(verified)
    assert batch is not None
    assert batch.batch_id == "synthesis-ica-hazard-verification"


def test_scenarios_receive_the_unprojected_pairs_beside_the_projected_icas() -> None:
    """The projection drops the slot evidence; scenarios read it from the fill."""
    pair = _slot_pair()
    fill = _slot_fill(pair, IcaHazardVerificationBatch(batch_id="verification"))
    projected = ICAEnumeration(slots=[])
    received: dict[str, object] = {}

    def scenarios(**kwargs: object) -> object:
        received.update(kwargs)
        return object()

    _run_scenarios(
        projected,
        (),
        (),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(),
        SimpleNamespace(
            output_dir=Path("."),
            execution_target_profile=None,
            target_observations=None,
            max_workers=1,
        ),
        SimpleNamespace(),
        SynthesisAdapters(scenarios=scenarios),
        slot_evidence=fill,
    )

    assert received["ica_enumeration"] is projected
    assert received["ica_considerations"] == (pair,)


def test_run_synthesis_hands_scenarios_the_fill_pairs_on_the_projected_path(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    pair = _slot_pair()
    projected = ICAEnumeration(slots=[])
    received: dict[str, object] = {}

    class Adapters(_FakeAdapters):
        def fill_icas(self, **_: object) -> object:
            return _slot_fill(pair, IcaHazardVerificationBatch(batch_id="v"))

        def scenarios(self, **kwargs: object) -> object:
            received.update(kwargs)
            return super().scenarios(**kwargs)

    monkeypatch.setattr(
        synthesis_module,
        "_target_realized_stpa_inputs",
        lambda **kwargs: (kwargs["control_structure"], projected),
    )

    run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(Adapters(calls=[])))

    assert received["ica_enumeration"] is projected
    assert received["ica_considerations"] == (pair,)


def test_synthesis_context_preparation_supports_typed_agent_messages() -> None:
    """A responsibility-target action becomes a typed agent-message path."""

    control_structure = ControlStructure(
        responsibilities=(
            Responsibility(
                resp_id="RESP-1",
                description="Validate requests.",
                control_actions=(
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Validate one request.",
                        target=ElementRef(
                            type=ReferenceType.controlled_process,
                            id="CP-1",
                        ),
                    ),
                ),
            ),
            Responsibility(
                resp_id="RESP-2",
                description="Route a request to another controller.",
                control_actions=(
                    ControlAction(
                        ca_id="CA-2-1",
                        description="Request review.",
                        target=ElementRef(
                            type=ReferenceType.responsibility,
                            id="RESP-1",
                        ),
                    ),
                ),
            ),
        ),
        controlled_processes=(
            ControlledProcess(cp_id="CP-1", description="Request processing."),
        ),
    )
    loss_analysis = LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="An unsafe request is accepted.",
                provenance=LossProvenance.risk_card,
                source_risk_cards=("risk-1",),
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="Request validation is bypassed.",
                related_losses=("L-1",),
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Every request must be validated.",
                related_hazards=("H-1",),
            ),
        ),
    )

    def threat(controller: str, action: str) -> StructuralThreat:
        slot_id = f"{controller}:{action}:NOT_PROVIDED"
        return StructuralThreat(
            ica_slot_id=slot_id,
            ica_id=f"{slot_id}:1",
            ica_text="The required control action is not provided.",
            hazardous_context="An untrusted request is being processed.",
            loss_scenario="The unsafe request is accepted.",
            related_hazards=("H-1",),
            related_constraints=("SC-1",),
        )

    agent_message = threat("RESP-2", "CA-2-1")
    supported = threat("RESP-1", "CA-1-1")

    contexts = _build_synthesis_scenario_contexts(
        (agent_message, supported),
        control_structure,
        loss_analysis,
        briefs=(),
        ica_considerations=(),
    )

    assert tuple(contexts) == ("SCN-001", "SCN-002")
    message_path = contexts["SCN-001"].target_control_path.control_action
    assert message_path.target_kind.value == "responsibility"
    assert message_path.effect_kind.value == "agent_message"
    assert contexts["SCN-001"].scenario_identity.ica_id == agent_message.ica_id
    assert contexts["SCN-002"].scenario_identity.ica_id == supported.ica_id
    assert contexts["SCN-002"].scenario_identity.scenario_id == "SCN-002"


def test_synthesis_inputs_coerce_dumped_cards_and_facts(tmp_path: Path) -> None:
    """A list of dumped risk cards and a facts mapping become typed inputs."""
    typed = _inputs(tmp_path)
    assert typed.risk_cards
    assert typed.qualification_facts is not None

    coerced = replace(
        typed,
        risk_cards=[card.model_dump(mode="json") for card in typed.risk_cards],
        qualification_facts=typed.qualification_facts.model_dump(mode="json"),
    )

    assert coerced.risk_cards == typed.risk_cards
    assert all(isinstance(card, RiskCardInput) for card in coerced.risk_cards)
    assert isinstance(coerced.qualification_facts, QualificationFactsInput)
    assert coerced.qualification_facts == typed.qualification_facts


@pytest.mark.parametrize(
    ("changes", "error", "message"),
    [
        ({"execution_target_profile": {}}, TypeError, "must be an ExecutionTarget"),
        ({"target_observations": {}}, TypeError, "must be a TargetObservation"),
        ({"observation_contract": {}}, TypeError, "must be an ObservationContract"),
        ({"use_case": "  "}, ValueError, "use_case must be a non-empty string"),
        ({"max_workers": 0}, ValueError, "max_workers must be positive"),
    ],
)
def test_synthesis_inputs_reject_untyped_values(
    tmp_path: Path, changes: dict, error: type[Exception], message: str
) -> None:
    """Each typed request field rejects a plain value with its own message."""
    with pytest.raises(error, match=message):
        replace(_inputs(tmp_path), **changes)


def test_synthesis_inputs_require_observations_pinned_to_the_profile(
    tmp_path: Path,
) -> None:
    """Target observations need their profile, and must carry its digest."""
    fixture = Path("data/contracts/target-profile/target-profile-v1/valid/minimal.json")
    profile = ExecutionTargetProfile.model_validate(
        json.loads(fixture.read_text(encoding="utf-8"))
    )
    observations = MagicMock(spec=TargetObservationSnapshot)
    observations.target_profile_digest = "0" * 64

    with pytest.raises(ValueError, match="requires execution_target_profile"):
        replace(_inputs(tmp_path), target_observations=observations)
    with pytest.raises(ValueError, match="profile pin does not match target profile"):
        replace(
            _inputs(tmp_path),
            execution_target_profile=profile,
            target_observations=observations,
        )
    assert observations.assert_integrity.call_count == 2


def test_synthesis_contexts_carry_each_finding_to_every_named_ica(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Findings project per ICA; skipped and failing threats keep siblings."""

    received: dict[str, tuple] = {}

    def fake_context(threat, control, loss, *, scenario_id, obligation_considerations):
        if threat.ica_id == "ICA-BAD":
            raise ValueError("unbuildable context")
        received[scenario_id] = obligation_considerations
        return (threat.ica_id, scenario_id)

    monkeypatch.setattr(
        context_module, "build_scenario_generation_context", fake_context
    )
    briefs = tuple(
        SimpleNamespace(
            obligation_id=obligation_id,
            attack_pattern_id=f"AP-{obligation_id}",
            attack_pattern_name=f"Pattern {obligation_id}",
            attack_pattern_description=f"Concern {obligation_id}",
        )
        for obligation_id in ("OBL-2", "OBL-1")
    ) + (SimpleNamespace(obligation_id=None),)
    pairs = (
        SimpleNamespace(
            disposition="finding",
            obligation_id="OBL-2",
            rationale="",
            ica_ids=("ICA-A", "ICA-B"),
        ),
        SimpleNamespace(
            disposition="proposed_not_applicable",
            obligation_id="OBL-UNKNOWN",
            rationale="ignored",
            ica_ids=("ICA-A",),
        ),
        SimpleNamespace(
            disposition="finding",
            obligation_id="OBL-1",
            rationale="Seen at the ICA.",
            ica_ids=("ICA-A",),
        ),
    )
    threats = (
        SimpleNamespace(ica_id="ICA-A"),
        SimpleNamespace(ica_id="ICA-BAD"),
        SimpleNamespace(ica_id="ICA-B"),
        SimpleNamespace(ica_id="ICA-C"),
    )

    contexts = _build_synthesis_scenario_contexts(
        threats, object(), object(), briefs=briefs, ica_considerations=pairs
    )

    assert contexts == {
        "SCN-001": ("ICA-A", "SCN-001"),
        "SCN-003": ("ICA-B", "SCN-003"),
        "SCN-004": ("ICA-C", "SCN-004"),
    }
    assert [
        (item.obligation_id, item.finding_ica_id, item.rationale)
        for item in received["SCN-001"]
    ] == [
        ("OBL-1", "ICA-A", "Seen at the ICA."),
        (
            "OBL-2",
            "ICA-A",
            "STPA identified this concern in the selected ICA after "
            "analyzing the routed control path.",
        ),
    ]
    assert [item.finding_ica_id for item in received["SCN-003"]] == ["ICA-B"]
    assert received["SCN-003"][0].concise_concern == "Concern OBL-2"
    assert received["SCN-004"] == ()


def test_synthesis_contexts_reject_unknown_findings_and_unbound_threats() -> None:
    """A finding needs a brief, and every threat needs an exact ICA identity."""
    unknown = SimpleNamespace(
        disposition="finding", obligation_id="OBL-9", rationale="x", ica_ids=()
    )
    with pytest.raises(ValueError, match="unknown obligation 'OBL-9'"):
        _build_synthesis_scenario_contexts(
            (), object(), object(), briefs=(), ica_considerations=(unknown,)
        )
    with pytest.raises(ValueError, match="no exact ICA identity"):
        _build_synthesis_scenario_contexts(
            (SimpleNamespace(ica_id=None),),
            object(),
            object(),
            briefs=(),
            ica_considerations=(),
        )


@pytest.mark.parametrize(
    ("briefs", "initial_routes", "final_routes", "message"),
    [
        ((object(),), (), (), "typed neutral obligation briefs"),
        ((), (object(),), (), "typed initial obligation routes"),
        ((), (), (object(),), "typed final obligation routes"),
    ],
    ids=["brief", "initial-route", "final-route"],
)
def test_consideration_closure_requires_typed_briefs_and_routes(
    briefs: tuple, initial_routes: tuple, final_routes: tuple, message: str
) -> None:
    """The durable consideration accepts only typed briefs and routes."""
    with pytest.raises(TypeError, match=message):
        _close_consideration_artifact(
            plan=object(),
            briefs=briefs,
            initial=SimpleNamespace(routes=initial_routes),
            recheck=None,
            final_routes=final_routes,
            revision=object(),
            baseline_loss=object(),
            baseline_control=object(),
            final_loss=object(),
            final_control=object(),
        )


class _DiagnosingEnrichmentAdapters(_FakeAdapters):
    def enrich_actions(self, *, control_structure, **_):
        return ControlActionEnrichment(
            control_structure=control_structure,
            record=ControlActionOperationEnrichmentRecord(
                profile_digest="profile",
                control_structure_digest="structure",
                observed_operations=0,
                diagnostics=("operation lookup was ambiguous",),
            ),
            rows=(),
        )


def test_enrichment_diagnostics_become_stage_warnings(tmp_path: Path) -> None:
    adapters = SynthesisAdapters.from_object(_DiagnosingEnrichmentAdapters(calls=[]))
    result = run_synthesis(_inputs(tmp_path), adapters)
    assert (
        "control action enrichment: operation lookup was ambiguous"
        in result.stage_warnings
    )


def test_declared_capability_labels_are_exact_sorted_names() -> None:
    profile = SimpleNamespace(
        tool_inventory=[SimpleNamespace(name="send"), SimpleNamespace(name=None)],
        external_integrations=[
            SimpleNamespace(name="crm"),
            SimpleNamespace(name="send"),
        ],
    )
    assert _declared_capability_labels(profile) == ("crm", "send")
    assert _declared_capability_labels(None) == ()


def test_manifest_call_evidence_comes_from_the_records_not_the_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "calls.jsonl").write_text(
        json.dumps({"stage": "file", "step": "file", "prompt_tokens": 900}) + "\n",
        encoding="utf-8",
    )
    _seed_call_records(
        monkeypatch,
        {"stage": "s", "step": "a", "prompt_tokens": 4, "ignored": 1},
        {"stage": "s", "step": "b", "prompt_tokens": None},
    )

    run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(_FakeAdapters(calls=[], with_evidence=True)),
    )

    manifest = yaml.safe_load(
        (tmp_path / "synthesis-manifest.yaml").read_text(encoding="utf-8")
    )
    assert manifest["prompt_call_evidence"] == [
        {"stage": "s", "step": "a", "prompt_tokens": 4},
        {"stage": "s", "step": "b"},
    ]
    assert manifest["total_prompt_tokens"] == 4


def test_manifest_without_call_records_has_no_call_evidence() -> None:
    assert _manifest_prompt_call_evidence(None) == []
    assert _total_prompt_tokens(None) is None
    assert _total_prompt_tokens([]) == 0


def test_accounting_source_pins_reuse_matching_pins_and_reject_others() -> None:
    authorities = {
        "plan": SimpleNamespace(semantic_digest="a" * 64),
        "final_loss": {"losses": []},
        "final_control": {"controllers": []},
        "ica_enumeration": final_ica_result(),
    }

    def pins(*supplied: ArtifactPin) -> tuple[ArtifactPin, ...]:
        return _accounting_source_pins(
            consideration=SimpleNamespace(source_pins=supplied), **authorities
        )

    built = pins()
    assert [pin.artifact_id for pin in built] == [
        "taxonomy-obligation-plan",
        "stpa-loss-analysis",
        "stpa-control-structure",
        "ica-enumeration",
    ]
    assert built[0].semantic_digest == "a" * 64
    assert pins(built[1]) == built
    with pytest.raises(
        ValueError, match="source pin for stpa-loss-analysis does not match"
    ):
        pins(built[1].model_copy(update={"schema_version": "stpa-loss-analysis-v0"}))
    with pytest.raises(ValueError, match="unknown accounting authorities"):
        pins(built[1], built[1].model_copy(update={"artifact_id": "other"}))


def test_dump_falls_back_for_positional_model_dump_and_opaque_values() -> None:
    class PositionalDump:
        def model_dump(self):
            return {"a": (1, 2)}

    hidden = SimpleNamespace(b=1, _private=2, method=len)
    assert _dump([PositionalDump(), hidden, object.__new__(_Opaque)]) == [
        {"a": [1, 2]},
        {"b": 1},
        "opaque",
    ]


class _Opaque:
    __slots__ = ()

    def __str__(self) -> str:
        return "opaque"


@pytest.mark.parametrize(
    ("field_name", "value", "error", "match"),
    (
        ("prepare_capability", lambda **_: None, ValueError, "returned no profile"),
        (
            "build_taxonomy_inputs",
            None,
            ValueError,
            "requires a taxonomy-input preparation adapter",
        ),
        ("build_taxonomy_inputs", lambda **_: None, ValueError, "returned no value"),
        ("plan_obligations", lambda **_: None, ValueError, "no obligation plan"),
        (
            "plan_obligations",
            lambda **_: SimpleNamespace(),
            TypeError,
            "must return a TaxonomyObligationPlan",
        ),
        ("build_briefs", lambda **_: None, ValueError, "returned no briefs"),
        (
            "enrich_actions",
            lambda **_: "stand-in",
            TypeError,
            "must return a ControlActionEnrichment",
        ),
        ("account", lambda **_: None, ValueError, "accounting adapter returned no"),
        ("realize", lambda **_: None, ValueError, "realization adapter returned no"),
    ),
)
def test_synthesis_rejects_a_missing_or_empty_stage_result(
    tmp_path: Path, field_name, value, error, match
) -> None:
    adapters = replace(
        SynthesisAdapters.from_object(_FakeAdapters(calls=[])), **{field_name: value}
    )

    with pytest.raises(error, match=match):
        run_synthesis(_inputs(tmp_path), adapters)


def test_resolution_fills_every_stage_port_from_the_defaults() -> None:
    """The stage runners call these ports unchecked: resolution never leaves one unset.

    Only the taxonomy-input port and the persistence writer have no default.
    """
    defaults = _production_defaults()

    resolved = _resolve_adapters(SynthesisAdapters())

    assert {
        name
        for name in SynthesisAdapters.__dataclass_fields__
        if getattr(defaults, name) is not None
    } == {
        "prepare_capability",
        "plan_obligations",
        "build_briefs",
        "baseline",
        "consider",
        "revise",
        "recheck",
        "fill_icas",
        "target_realize",
        "enrich_actions",
        "scenarios",
        "account",
        "realize",
        "govern",
    }
    for name in SynthesisAdapters.__dataclass_fields__:
        assert getattr(resolved, name) is getattr(defaults, name)


def _other_profile_realization(**_) -> TargetRealizationResult:
    return canonical_target_realization(
        TargetRealizationResult(
            baseline_id="baseline:fixture",
            baseline_digest="baseline-digest",
            profile_id="target:other",
            profile_digest="other-profile-digest",
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


@pytest.mark.parametrize(
    ("target_realize", "error", "match"),
    (
        (lambda **_: "stand-in", TypeError, "must return TargetRealizationResult"),
        (
            _other_profile_realization,
            ValueError,
            "does not match execution target profile",
        ),
    ),
    ids=("untyped", "other-profile"),
)
def test_synthesis_rejects_a_target_realization_for_another_target(
    tmp_path: Path, target_realize, error, match
) -> None:
    package = _miniklarna_target_package(tmp_path)
    adapters = replace(
        SynthesisAdapters.from_object(_TargetAwareFakeAdapters(calls=[])),
        target_realize=target_realize,
    )

    with pytest.raises(error, match=match):
        run_synthesis(package.inputs, adapters)


def test_synthesis_publishes_the_target_realization_through_its_writer(
    tmp_path: Path,
) -> None:
    package = _miniklarna_target_package(tmp_path)
    written: list[object] = []

    def writer(*, output_dir, artifact):
        written.append(artifact)
        path = Path(output_dir) / "custom-target-realization.yaml"
        path.write_text(artifact.to_yaml(), encoding="utf-8")
        return path

    adapters = replace(
        SynthesisAdapters.from_object(_TargetAwareFakeAdapters(calls=[])),
        persist_target_realization=writer,
    )

    result = run_synthesis(package.inputs, adapters)

    assert written == [result.target_realization]
    assert (
        result.output_dir / "custom-target-realization.yaml"
        in result.artifact_paths.values()
    )


def test_semantic_digest_prefers_a_declared_digest() -> None:
    assert _semantic_digest(None) is None
    assert _semantic_digest(SimpleNamespace(semantic_digest="declared")) == "declared"
    assert _semantic_digest(SimpleNamespace(semantic_digest="")) != ""


def _runtime(client: object) -> SimpleNamespace:
    return SimpleNamespace(
        client=client,
        temperature=lambda: 0.25,
        obligation_adapter=lambda output_dir: ("runtime-adapter", output_dir),
    )


def test_default_capability_preparation_uses_the_run_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.system_model.profile.derive_capability_profile",
        lambda **kwargs: calls.append(kwargs) or "profile",
    )
    client = object()
    inputs = _inputs(tmp_path)

    target = object()

    profile = _default_prepare_capability(
        inputs=inputs, model_runtime=_runtime(client), execution_target_profile=target
    )

    assert profile == "profile"
    assert [
        (
            call["llm_client"],
            call["use_case_text"],
            call["run_dir"],
            call["temperature"],
            call["samples"],
            call["target_profile"],
        )
        for call in calls
    ] == [(client, inputs.use_case, inputs.output_dir, 0.25, 18, target)]


def test_capability_preparation_receives_the_target_beside_the_systemic_view(
    tmp_path: Path,
) -> None:
    """The observed target arrives as its own argument; the inputs stay systemic."""
    package = _miniklarna_target_package(tmp_path)
    seen: list[dict] = []

    def prepare(**kwargs):
        seen.append(kwargs)
        return synthesis_capability_profile()

    _prepare_capability_profile(
        package.inputs, SynthesisAdapters(prepare_capability=prepare)
    )

    (call,) = seen
    assert call["execution_target_profile"] is package.profile
    assert call["inputs"].execution_target_profile is None
    assert call["inputs"].target_observations is None


def test_obligation_provider_prefers_the_supplied_adapter(tmp_path: Path) -> None:
    supplied = object()
    runtime = _runtime(object())

    assert (
        _resolve_obligation_provider(
            replace(_inputs(tmp_path), obligation_adapter=supplied), tmp_path, runtime
        )
        is supplied
    )
    assert _resolve_obligation_provider(_inputs(tmp_path), str(tmp_path), runtime) == (
        "runtime-adapter",
        tmp_path,
    )


def test_default_revision_accepts_bare_missing_concepts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from asago_scenario_generator.models.obligation_consideration import (
        MissingStructuralConcept,
    )

    calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.obligation_aware.revision.revise_structure_once",
        lambda provider, **kwargs: calls.append(kwargs) or "revised",
    )
    triggered = MissingStructuralConcept(
        concept_type="responsibility",
        description="A reviewing responsibility is missing.",
        evidence_refs=("review-gap",),
        obligation_id="ob:v1:" + "a" * 64,
    )
    untriggered = MissingStructuralConcept(
        concept_type="feedback_channel",
        description="Review outcomes are not fed back.",
        evidence_refs=("feedback-gap",),
    )
    provider = SimpleNamespace(controls="controls")

    result = _default_revision(
        gaps=(triggered, untriggered),
        plan=None,
        loss_analysis="loss",
        control_structure="structure",
        inputs=_inputs(tmp_path),
        obligation_adapter=provider,
        output_dir=tmp_path,
    )

    assert result == "revised"
    assert calls[0]["gaps"] == [triggered, untriggered]
    assert calls[0]["trigger_obligation_ids"] == [triggered.obligation_id]
    assert calls[0]["controls"] == "controls"


def test_default_target_realization_runs_both_passes_with_the_run_client(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from asago_scenario_generator.models.target_realization import (
        SystemicStpaBaseline,
    )

    built: list[tuple[object, ...]] = []
    passes: list[tuple[object, ...]] = []

    def interpreter(client, run_dir, *, temperature, call_variant):
        built.append(("interpreter", client, run_dir, temperature, call_variant))
        return "interpreter"

    def finder(client, run_dir, *, temperature):
        built.append(("finder", client, run_dir, temperature))
        return "finder"

    rows = ("row-1",)

    def realize_operations(baseline, profile, factory, *, baseline_rows):
        assert baseline_rows is rows
        passes.append(("operations", baseline, profile, factory()))
        return "mapped"

    def realize_icas(baseline, mapped, factory):
        passes.append(("icas", baseline, mapped, factory()))
        return "realized"

    module = "asago_scenario_generator.stpa.target_realization"
    monkeypatch.setattr(f"{module}.TargetRealizationLlmInterpreter", interpreter)
    monkeypatch.setattr(f"{module}.TargetDerivedICALlmFinder", finder)
    module = "asago_scenario_generator.pipeline.target_realization"
    monkeypatch.setattr(f"{module}.realize_target_operations", realize_operations)
    monkeypatch.setattr(f"{module}.realize_target_derived_icas", realize_icas)
    package = _miniklarna_target_package(tmp_path)
    client = object()
    enumeration = ICAEnumeration(slots=[])

    result = _default_target_realize(
        loss_analysis=baseline_loss_analysis(),
        control_structure=baseline_control_structure(),
        ica_enumeration=enumeration,
        capability_profile=synthesis_capability_profile(),
        execution_target_profile=package.profile,
        operation_enrichment=SimpleNamespace(rows=rows),
        inputs=package.inputs,
        output_dir=tmp_path,
        model_runtime=_runtime(client),
    )

    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=baseline_loss_analysis(),
        control_structure=baseline_control_structure(),
        ica_enumeration=enumeration,
        declared_capabilities=_declared_capability_labels(
            synthesis_capability_profile()
        ),
    )
    assert result == "realized"
    assert built == [
        ("interpreter", client, tmp_path, 0.25, "target_realization"),
        ("finder", client, tmp_path, 0.25),
    ]
    assert passes == [
        ("operations", baseline, package.profile, "interpreter"),
        ("icas", baseline, "mapped", "finder"),
    ]


def test_default_scenarios_use_the_family_plan_threats(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class _Threats(SimpleNamespace):
        def model_copy(self, *, update):
            return _Threats(**{**vars(self), **update})

    captured: dict[str, object] = {}
    planned = SimpleNamespace(threats=[], candidates=("family",))
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.threat_enum.catalog_enrichment.enrich_threats",
        lambda *a, **k: _Threats(structural_threats=["dropped"]),
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.condition_family."
        "plan_family_candidates",
        lambda *a: planned,
    )
    monkeypatch.setattr(
        "asago_scenario_generator.stpa.scenario_prod.run.run_sp3",
        lambda **kwargs: captured.update(kwargs) or "sp3",
    )

    result = _default_scenarios(
        ica_enumeration=final_ica_result(),
        control_structure=baseline_control_structure(),
        loss_analysis=baseline_loss_analysis(),
        inputs=_inputs(tmp_path),
        capability_profile=None,
        output_dir=tmp_path,
        model_runtime=_runtime(object()),
    )

    assert result == "sp3"
    assert captured["enriched_threat_set"].structural_threats == []
    assert captured["condition_families"] == ("family",)
