"""Public seam tests for the obligation-aware synthesis composition root."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from html import escape
from pathlib import Path
from types import SimpleNamespace

import yaml
import pytest

from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
from asago_scenario_generator.pipeline.obligation_contracts import RiskCardInput
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    SynthesisInputs,
    SynthesisRunStatus,
    _default_baseline,
    _scenario_generation_status,
    _systemic_inputs,
    run_synthesis,
)
from asago_scenario_generator.report.synthesis import _candidate_outcomes_html
from asago_scenario_generator.models.target_realization import (
    TargetRealizationResult,
    TargetRealizationSummary,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
    RequestedEnvironmentBasis,
)


def _plan(*, gap: bool = False) -> SimpleNamespace:
    obligations = (
        SimpleNamespace(
            obligation_id="ob-1",
            scope_disposition="applicable",
            qualification_disposition="missing_evidence",
        ),
        SimpleNamespace(
            obligation_id="ob-2",
            scope_disposition="capability_excluded",
            qualification_disposition="not_attempted",
        ),
        SimpleNamespace(
            obligation_id="ob-3",
            scope_disposition="governance_only",
            qualification_disposition="not_attempted",
        ),
    )
    routes = [
        SimpleNamespace(
            obligation_id="ob-1",
            disposition="upstream_gap" if gap else "targeted",
            slot_ids=("RESP-1:CA-1:NOT_PROVIDED",),
        )
    ]
    return SimpleNamespace(
        obligations=obligations,
        semantic_digest="plan-digest",
        model_dump=lambda **_: {
            "schema_version": "taxonomy-obligation-plan-v1",
            "obligations": [],
        },
        assert_integrity=lambda: None,
        initial_routes=routes,
    )


@dataclass
class _FakeAdapters:
    calls: list[tuple[str, object]]
    gap: bool = False
    with_evidence: bool = False
    revision_result: object | None = None
    scenario_errors: tuple[str, ...] = ()
    candidate_outcomes: tuple[object, ...] | None = None
    scenario_envelopes: tuple[object, ...] | None = None
    phase2_failure: bool = False
    phase1_inputs: object = "typed-taxonomy-inputs"

    def prepare_capability(self, **_) -> object:
        return "profile"

    def build_taxonomy_inputs(self, **_) -> object:
        return self.phase1_inputs

    def plan(self, *, taxonomy_inputs, **_) -> object:
        self.calls.append(("plan", taxonomy_inputs))
        return _plan(gap=self.gap)

    def baseline(self, *, inputs, capability_snapshot, **_) -> object:
        self.calls.append(("baseline", (inputs, capability_snapshot)))
        return SimpleNamespace(
            loss_analysis="baseline-loss",
            control_structure="baseline-control",
        )

    def consider(self, *, briefs, loss_analysis, control_structure, **_) -> object:
        self.calls.append(
            ("consider", (tuple(briefs), loss_analysis, control_structure))
        )
        route = SimpleNamespace(
            obligation_id="ob-1",
            disposition="upstream_gap"
            if self.gap and control_structure == "baseline-control"
            else "targeted",
            slot_ids=("RESP-1:CA-1:NOT_PROVIDED",),
        )
        result = SimpleNamespace(
            initial_routes=(route,),
            final_routes=(route,),
            revision=SimpleNamespace(status="not_required"),
            model_dump=lambda **_: {
                "schema_version": "stpa-obligation-consideration-v1",
                "initial_routes": [],
            },
        )
        if self.with_evidence:
            result.call_evidence = (
                SimpleNamespace(
                    call_id="stpa-route:batch-0",
                    request_digest="request-digest",
                    response_digest="response-digest",
                    attempt_count=2,
                    outcome="accepted",
                ),
            )
        return result

    def revise(self, *, gaps, loss_analysis, control_structure, **_) -> object:
        self.calls.append(("revise", (tuple(gaps), loss_analysis, control_structure)))
        if self.revision_result is not None:
            return self.revision_result
        return SimpleNamespace(
            loss_analysis="revised-loss",
            control_structure="revised-control",
            revision=SimpleNamespace(status="applied"),
        )

    def recheck(self, *, briefs, loss_analysis, control_structure, **_) -> object:
        self.calls.append(
            ("recheck", (tuple(briefs), loss_analysis, control_structure))
        )
        route = SimpleNamespace(
            obligation_id="ob-1",
            disposition="targeted",
            slot_ids=("RESP-1:CA-1:NOT_PROVIDED",),
        )
        return SimpleNamespace(final_routes=(route,))

    def fill_icas(self, *, routes, loss_analysis, control_structure, **_) -> object:
        self.calls.append(
            ("fill_icas", (tuple(routes), loss_analysis, control_structure))
        )
        if self.with_evidence:
            return SimpleNamespace(
                ica_enumeration="final-ica",
                call_evidence=(
                    SimpleNamespace(
                        call_id="stpa-slot:RESP-1",
                        request_digest="slot-request",
                        response_digest="slot-response",
                        attempt_count=1,
                        outcome="accepted",
                    ),
                ),
            )
        return "final-ica"

    def scenarios(
        self, *, ica_enumeration, loss_analysis, control_structure, **_
    ) -> object:
        self.calls.append(
            ("scenarios", (ica_enumeration, loss_analysis, control_structure))
        )
        return SimpleNamespace(
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

    def verify_phase2(self, **_) -> object:
        self.calls.append(("verify_phase2", None))
        if self.phase2_failure:
            raise ValueError("deterministic Phase 2 failure")
        return SimpleNamespace(
            status="awaiting_evidence",
            assessment=None,
            artifact_paths={},
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
        return TargetRealizationResult(
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

    def enrich_control_actions(self, **_):
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
        return SimpleNamespace(
            loss_analysis="baseline-loss",
            control_structure="baseline-control",
        )

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
    return SynthesisInputs(
        use_case="A system that handles requests",
        risk_cards=(SimpleNamespace(risk_id="risk-1"),),
        qualification_facts={"facts": []},
        output_dir=tmp_path,
    )


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
        "verify_phase2",
    ]
    baseline_inputs, snapshot = fake.calls[1][1]
    assert baseline_inputs is result.inputs
    assert snapshot.profile == "profile"


def test_failed_baseline_retains_stage_diagnostic_before_obligation_calls(
    tmp_path: Path,
) -> None:
    fake = _FakeAdapters(calls=[])
    error = "stage_2/call_3_coordination: provider rejected unsupported response schema"
    adapters = replace(
        SynthesisAdapters.from_object(fake),
        baseline=lambda **_: SimpleNamespace(
            loss_analysis="baseline-loss", control_structure=None, stage_errors=[error]
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
        return SimpleNamespace(
            loss_analysis="baseline-loss",
            control_structure="baseline-control",
        )

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
        baseline=lambda **_: SimpleNamespace(
            loss_analysis="baseline-loss",
            control_structure="baseline-control",
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
    assert systemic.requested_environment_basis is None
    assert inputs.execution_target_profile is package.profile
    assert inputs.target_observations is package.observations


def _miniklarna_target_package(tmp_path: Path) -> SimpleNamespace:
    """Load the byte-pinned MiniKlarna target package through production validators."""
    from asago_scenario_generator.stpa.scenario_prod.target_observations import (
        TargetObservationSnapshot,
    )

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
        requested_environment_basis=RequestedEnvironmentBasis.target_profile,
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
    fake.provider_adapter = provider_adapter
    provider_factory_calls: list[object] = []
    client_factory_calls: list[object] = []

    def forbid_provider_factory(*args, **kwargs):
        provider_factory_calls.append((args, kwargs))
        raise AssertionError("deterministic composition constructed a provider")

    def forbid_client_factory(*args, **kwargs):
        client_factory_calls.append((args, kwargs))
        raise AssertionError("deterministic composition constructed a client")

    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.synthesis._resolve_obligation_provider",
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

    fake.provider_adapter = provider_adapter
    client = object()
    client_resolutions: list[tuple[object, ...]] = []
    baseline_calls: list[dict[str, object]] = []

    def resolve_client(*args):
        client_resolutions.append(args)
        return client, "deterministic"

    def run_sp1(**kwargs):
        baseline_calls.append(kwargs)
        assert kwargs["llm_client"] is client
        return SimpleNamespace(
            loss_analysis="baseline-loss",
            control_structure="baseline-control",
        )

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
    assert systemic.requested_environment_basis is None
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
    prepared_profile_path = tmp_path / "prepared-profile.json"
    pinned_loss_analysis_path = tmp_path / "pinned-loss-analysis.yaml"

    result = _default_baseline(
        inputs=inputs,
        capability_profile="profile",
        capability_profile_path=prepared_profile_path,
        loss_analysis_path=pinned_loss_analysis_path,
        output_dir=tmp_path,
    )

    assert result is baseline_result
    assert len(baseline_calls) == 1
    call = baseline_calls[0]
    assert call["risk_cards"] is reviewed_risks
    assert call["profile_path"] is prepared_profile_path
    assert call["loss_analysis_path"] is pinned_loss_analysis_path


def test_phase2_failure_is_last_and_does_not_erase_scenarios(tmp_path: Path) -> None:
    fake = _FakeAdapters(calls=[], phase2_failure=True)

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert [name for name, _ in fake.calls][-1] == "verify_phase2"
    assert result.scenario_envelopes == ("scenario-1",)
    assert result.phase2_verification.status == "failed"
    assert any("Phase 2 verification failed" in item for item in result.stage_errors)
    assert result.accounting is not None
    assert {
        "taxonomy-obligation-plan.yaml",
        "obligation-consideration.yaml",
        "obligation-accounting.yaml",
        "scenario-realization.yaml",
        "synthesis-manifest.yaml",
    }.issubset({path.name for path in tmp_path.iterdir()})


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
    assert len(recheck_briefs) == 1
    assert loss_analysis == "revised-loss"
    assert control_structure == "revised-control"


def test_synthesis_manifest_retains_taxonomy_pins_and_stage_call_evidence(
    tmp_path: Path,
) -> None:
    """The manifest names Phase 1 pins and preserves typed provider evidence."""
    taxonomy_inputs = SimpleNamespace(
        catalog_pins={
            "atlas": SimpleNamespace(release="2026.1", digest="a" * 64),
        },
        mapping_pins={
            "sssom": SimpleNamespace(release="2026.1", digest="b" * 64),
            "obligation_edges": SimpleNamespace(release="2026.1", digest="c" * 64),
        },
    )
    inputs = _inputs(tmp_path)
    (tmp_path / "calls.jsonl").write_text(
        json.dumps(
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
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    run_synthesis(
        inputs,
        SynthesisAdapters.from_object(
            _FakeAdapters(calls=[], with_evidence=True, phase1_inputs=taxonomy_inputs)
        ),
    )

    manifest = yaml.safe_load(
        (tmp_path / "synthesis-manifest.yaml").read_text(encoding="utf-8")
    )
    assert manifest["catalog_pins"]["atlas"]["release"] == "2026.1"
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
    assert result.manifest["scenario_counts"] == {
        "generated": 0,
        "failed": 0,
        "requested": 0,
        "attempted": 0,
        "skipped": 0,
        "functional_test": 0,
        "diagnostic_count": 0,
    }
    assert result.status == "no_candidates"
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
    assert result.status == "failed"
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


def test_synthesis_manifest_keeps_revision_as_compact_evidence_mapping(
    tmp_path: Path,
) -> None:
    """Revision manifests retain decisions and evidence, not provider objects."""

    @dataclass(slots=True)
    class SlotRevision:
        status: str
        trigger_obligation_ids: tuple[str, ...]
        trigger_gap_ids: tuple[str, ...]
        diagnostics: tuple[str, ...]
        request: object
        response: object
        call_evidence: object
        baseline_loss_analysis: object
        final_loss_analysis: object

    revision = SlotRevision(
        status="technical_failure",
        trigger_obligation_ids=("ob-1",),
        trigger_gap_ids=("gap-1",),
        diagnostics=("compile failure",),
        request=SimpleNamespace(
            semantic_digest="request-digest",
            request_ref="memory://revision/request",
        ),
        response=SimpleNamespace(
            status="completed",
            request_digest="request-digest",
            response_digest="response-digest",
            response_ref="memory://revision/response",
        ),
        call_evidence=SimpleNamespace(
            call_id="stpa-revision:one-round",
            outcome="technical_failure",
            request_digest="request-digest",
            response_digest="response-digest",
            attempt_count=1,
        ),
        baseline_loss_analysis=SimpleNamespace(
            __repr__=lambda self: "LossAnalysis(should-not-be-serialized)"
        ),
        final_loss_analysis=SimpleNamespace(
            __repr__=lambda self: "LossAnalysis(should-not-be-serialized)"
        ),
    )
    result = run_synthesis(
        _inputs(tmp_path),
        SynthesisAdapters.from_object(
            _FakeAdapters(
                calls=[],
                gap=True,
                revision_result=revision,
                phase1_inputs=SimpleNamespace(),
            )
        ),
    )

    revision_record = result.manifest["revision"]
    assert isinstance(revision_record, dict)
    assert revision_record["status"] == "technical_failure"
    assert revision_record["trigger_obligation_ids"] == ["ob-1"]
    assert revision_record["trigger_gap_ids"] == ["gap-1"]
    assert revision_record["diagnostics"] == ["compile failure"]
    assert revision_record["request"] == {
        "semantic_digest": "request-digest",
        "request_ref": "memory://revision/request",
    }
    assert revision_record["response"] == {
        "status": "completed",
        "request_digest": "request-digest",
        "response_digest": "response-digest",
        "response_ref": "memory://revision/response",
    }
    assert revision_record["call_evidence"] == [
        {
            "call_id": "stpa-revision:one-round",
            "outcome": "technical_failure",
            "request_digest": "request-digest",
            "response_digest": "response-digest",
            "attempt_count": 1,
        }
    ]
    rendered = yaml.safe_dump(revision_record, sort_keys=False)
    assert "RevisionRunResult(" not in rendered
    assert "LossAnalysis(" not in rendered
    assert len(rendered) < 1000


def test_synthesis_manifest_records_that_no_run_resumes(tmp_path: Path) -> None:
    """The manifest keeps its resume and model-control keys at fixed values."""
    fake = _FakeAdapters(calls=[])

    result = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))

    assert result.manifest["resume"] == {
        "requested": False,
        "state": "not_requested",
        "reused_stages": [],
        "checkpoint": None,
    }
    assert result.manifest["model_controls"]["temperature"] is None


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
        ObligationIcaConsideration,
        MissingStructuralConcept,
        ObligationRoute,
    )
    from asago_scenario_generator.stpa.obligation_aware.contracts import (
        AnalysisControls,
        RevisionDraft,
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
    from asago_scenario_generator.stpa.models.ica_enumeration import ICA, ICASlot
    from asago_scenario_generator.stpa.models.loss_analysis import (
        Hazard,
        Loss,
        LossAnalysis,
        LossProvenance,
        SecurityConstraint,
    )
    from asago_scenario_generator.stpa.models.execution_envelope import candidate_id_for
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
            ProcessModelPart(pm_id="PM-1-1", description="Request state."),
        ),
        control_actions=(
            ControlAction(
                ca_id="CA-1-1",
                description="Validate request.",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
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

        def route(self, request):
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
                request_digest=request.semantic_digest,
                routes=routes,
            )

        def revise(self, request):
            self.stage_provider_ids.append(id(self))
            return StructuralRevisionResponse(
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
            pairs = []
            for slot in request.slots:
                if slot.slot_id == slot_id and request.routed_routes:
                    filled.append(
                        ICASlot(
                            slot_id=slot.slot_id,
                            responsibility=slot.responsibility,
                            coordination_link=slot.coordination_link,
                            control_action=slot.control_action,
                            uca_type=slot.uca_type,
                            is_na=False,
                            icas=(
                                ICA(
                                    ica_id="placeholder",
                                    ica_text="The action is issued unsafely.",
                                    hazardous_context="Unsafe request state.",
                                    loss_scenario="The protected operation is harmed.",
                                    related_hazards=["H-1"],
                                    related_constraints=["SC-1"],
                                ),
                            ),
                        )
                    )
                    for route in request.routed_routes:
                        pairs.append(
                            ObligationIcaConsideration(
                                route_id=route.route_id,
                                obligation_id=route.obligation_id,
                                slot_id=slot.slot_id,
                                disposition="finding",
                                ica_ids=(f"{slot.slot_id}:1",),
                                exec_candidate_ids=(
                                    candidate_id_for(
                                        slot.responsibility or slot.coordination_link,
                                        slot.control_action,
                                        slot.uca_type,
                                    ),
                                ),
                                hazard_ids=("H-1",),
                                constraint_ids=("SC-1",),
                                evidence=("ica-analysis",),
                            )
                        )
                else:
                    filled.append(
                        ICASlot(
                            slot_id=slot.slot_id,
                            responsibility=slot.responsibility,
                            coordination_link=slot.coordination_link,
                            control_action=slot.control_action,
                            uca_type=slot.uca_type,
                            is_na=True,
                            na_justification="No routed concern applies.",
                        )
                    )
            return SynthesisSlotResponse(
                request_digest=request.semantic_digest,
                filled_slots=tuple(filled),
                considerations=tuple(pairs),
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
                }
                for request in requests
            )

        def correct_ica(self, request, verdict):
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
        baseline=lambda **_: SimpleNamespace(
            loss_analysis=loss_analysis,
            control_structure=control_structure,
        ),
        scenarios=lambda **_: SimpleNamespace(scenario_envelopes=()),
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
    assert result.ica_considerations
    assert result.ica_enumeration is not None
    assert (tmp_path / "obligation-consideration.yaml").exists()
    assert (tmp_path / "obligation-accounting.yaml").exists()


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
    assert names[-1] == "verify_phase2"
    assert result.accounting is not None


def test_accounting_receives_the_verified_ordinary_ica_enumeration() -> None:
    """Verifier metadata must not masquerade as the ICA enumeration."""
    from asago_scenario_generator.pipeline.synthesis import _run_accounting

    ordinary = SimpleNamespace(slots=("slot",))
    verification = SimpleNamespace(records=())
    wrapped = SimpleNamespace(
        ica_enumeration=ordinary,
        considerations=(),
        ica_hazard_verification=verification,
    )
    received: dict[str, object] = {}
    expected = object()

    def account(**kwargs: object) -> object:
        received.update(kwargs)
        return expected

    result = _run_accounting(
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
        calls=[],
    )

    assert result is expected
    assert received["ica_enumeration"] is ordinary
    assert received["ica_verification"] is verification


def test_synthesis_context_preparation_supports_typed_agent_messages() -> None:
    """A responsibility-target action becomes a typed agent-message path."""
    from asago_scenario_generator.pipeline.synthesis import (
        _build_synthesis_scenario_contexts,
    )
    from asago_scenario_generator.stpa.models.control_structure import (
        ControlAction,
        ControlStructure,
        ControlledProcess,
        ElementRef,
        ReferenceType,
        Responsibility,
    )
    from asago_scenario_generator.stpa.models.enriched_threat_set import (
        StructuralThreat,
    )
    from asago_scenario_generator.stpa.models.loss_analysis import (
        Hazard,
        Loss,
        LossAnalysis,
        LossProvenance,
        SecurityConstraint,
    )

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
