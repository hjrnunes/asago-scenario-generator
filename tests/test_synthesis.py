"""Public seam tests for the obligation-aware synthesis composition root."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import yaml

from asago_scenario_generator.data.loaders import load_reviewed_risk_extraction
from asago_scenario_generator.pipeline.obligation_contracts import RiskCardInput
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    SynthesisInputs,
    run_synthesis,
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
            scenario_envelopes=("scenario-1",),
            stage_errors=self.scenario_errors,
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


def _inputs(tmp_path: Path) -> SynthesisInputs:
    return SynthesisInputs(
        use_case="A system that handles requests",
        risk_cards=(SimpleNamespace(risk_id="risk-1"),),
        qualification_facts={"facts": []},
        output_dir=tmp_path,
        capability_profile="profile",
        taxonomy_inputs="typed-taxonomy-inputs",
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
    ]
    baseline_inputs, snapshot = fake.calls[1][1]
    assert baseline_inputs is result.inputs
    assert snapshot.profile == "profile"
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
    inputs = replace(_inputs(tmp_path), taxonomy_inputs=taxonomy_inputs)
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
        SynthesisAdapters.from_object(_FakeAdapters(calls=[], with_evidence=True)),
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

    assert result.manifest["scenario_counts"] == {"generated": 1, "failed": 1}
    assert result.manifest["scenario_errors"] == [
        "Stage 6 context failed for SCN-001: ambiguous constraint"
    ]
    assert result.manifest["stage_errors"] == []


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
        replace(_inputs(tmp_path), taxonomy_inputs=SimpleNamespace()),
        SynthesisAdapters.from_object(
            _FakeAdapters(calls=[], gap=True, revision_result=revision)
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


def test_synthesis_manifest_resume_state_does_not_claim_reused_stages(
    tmp_path: Path,
) -> None:
    """Resume records checkpoint validation separately from stage reuse."""
    fake = _FakeAdapters(calls=[])
    first = run_synthesis(_inputs(tmp_path), SynthesisAdapters.from_object(fake))
    resumed_dir = tmp_path / "resumed"
    result = run_synthesis(
        replace(
            _inputs(resumed_dir),
            resume=True,
            prebuilt_plan=first.obligation_plan,
        ),
        SynthesisAdapters.from_object(_FakeAdapters(calls=[])),
    )

    resume = result.manifest["resume"]
    assert resume["requested"] is True
    assert resume["state"] == "phase1_checkpoint_validated"
    assert resume["reused_stages"] == []
    assert resume["checkpoint"]["artifact_id"] == "taxonomy-obligation-plan"


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
                description="Requests must satisfy policy.",
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

    provider = FakeProvider()
    inputs = SynthesisInputs(
        use_case="A system that handles requests",
        risk_cards=pattern_inputs.risk_cards,
        qualification_facts=pattern_inputs.qualification_facts,
        output_dir=tmp_path,
        capability_profile=pattern_inputs.capability_snapshot.profile,
        capability_snapshot=pattern_inputs.capability_snapshot,
        taxonomy_inputs=pattern_inputs,
    )
    adapters = SynthesisAdapters(
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
    assert names[-1] == "realize"
    assert result.accounting is not None


def test_synthesis_context_preparation_keeps_valid_siblings() -> None:
    """One unsupported hierarchical control path must not erase valid scenarios."""
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
                description="Every request must be validated.",
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

    unsupported = threat("RESP-2", "CA-2-1")
    supported = threat("RESP-1", "CA-1-1")

    contexts = _build_synthesis_scenario_contexts(
        (unsupported, supported),
        control_structure,
        loss_analysis,
        briefs=(),
        ica_considerations=(),
    )

    assert tuple(contexts) == (supported.ica_id,)
    assert contexts[supported.ica_id].scenario_identity.scenario_id == "SCN-002"
