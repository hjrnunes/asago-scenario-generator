"""Unit tests for SP3 Stage 7 — Validators."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ControlledProcess,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    EnrichedThreatSet,
    StructuralThreat,
    CoverageAnalysis,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod.validators import (
    validate_bdi_grounding,
    validate_traceability,
    validate_vulnerability_completeness,
    detect_orphan_elements,
    detect_orphan_icas,
)


def _make_cs(
    include_resp2: bool = False,
) -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    resp1 = Responsibility(
        resp_id="RESP-1",
        description="R1",
        process_model_parts=[
            ProcessModelPart(pm_id="PM-1-1", description="State"),
        ],
        control_actions=[
            ControlAction(
                ca_id="CA-1-1",
                description="Action",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Feedback",
                updates="PM-1-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ],
    )
    responsibilities = [resp1]
    if include_resp2:
        responsibilities.append(
            Responsibility(
                resp_id="RESP-2",
                description="R2",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-2-1", description="State2")
                ],
                control_actions=[
                    ControlAction(
                        ca_id="CA-2-1",
                        description="Action2",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-2-1",
                        description="Feedback2",
                        updates="PM-2-1",
                        source=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                    ),
                ],
            )
        )
    return ControlStructure(responsibilities=responsibilities, controlled_processes=cps)


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            ),
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1", rule="Constraint", related_hazards=["H-1"]
            ),
        ],
    )


def _make_scenario_spec(
    pm_id: str = "PM-1-1",
    resp_id: str = "RESP-1",
    ca_id: str = "CA-1-1",
    vulnerability: str = "exploitable",
    target_controller: str = "RESP-1",
    target_control_action: str = "CA-1-1",
    ica_id: str = "RESP-1:CA-1-1:NOT_PROVIDED:1",
    provenance: str = "structural",
) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance=provenance,
            ica_id=ica_id,
        ),
        target_controller=target_controller,
        target_control_action=target_control_action,
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id=pm_id, content="State", vulnerability=vulnerability
                )
            ],
            desires=[DefenderDesire(resp_id=resp_id, content="R1")],
            intentions=[DefenderIntention(ca_id=ca_id, content="Action")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="Loss",
    )


def _make_envelope(
    attack_tree: dict | None = None,
    gherkin_spec: GherkinSpec | str | None = None,
    spec: ScenarioSpec | None = None,
) -> ScenarioEnvelope:
    return ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec or _make_scenario_spec(),
        narrative="Narrative text",
        attack_tree=attack_tree or {"root": "r", "branches": [], "leaves": []},
        gherkin_spec=gherkin_spec
        or GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        ),
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )


def _make_threat(
    ica_id: str = "RESP-1:CA-1-1:NOT_PROVIDED:1",
    related_hazards: list[str] | None = None,
    related_constraints: list[str] | None = None,
) -> StructuralThreat:
    return StructuralThreat(
        ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
        provenance="structural",
        ica_id=ica_id,
        ica_text="ICA text",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=related_hazards or ["H-1"],
        related_constraints=related_constraints or ["SC-1"],
    )


def _make_enriched_threat_set(
    threats: list[StructuralThreat] | None = None,
) -> EnrichedThreatSet:
    return EnrichedThreatSet(
        structural_threats=threats or [_make_threat()],
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 1,
                "non_na": 1,
                "na": 0,
                "coverage_rate": 1.0,
            },
        ),
    )


class TestBDIGroundingValidator:
    """SP3-VAL-01 through SP3-VAL-04."""

    def test_passes_with_valid_ids(self):
        cs = _make_cs()
        spec = _make_scenario_spec()
        result = validate_bdi_grounding(spec, cs)
        assert result.passed

    def test_fails_on_invalid_pm(self):
        cs = _make_cs()
        spec = _make_scenario_spec(pm_id="PM-99-1")
        result = validate_bdi_grounding(spec, cs)
        assert not result.passed
        assert any("pm_id" in e for e in result.errors)

    def test_fails_on_invalid_resp(self):
        cs = _make_cs()
        spec = _make_scenario_spec(resp_id="RESP-99")
        result = validate_bdi_grounding(spec, cs)
        assert not result.passed
        assert any("resp_id" in e for e in result.errors)

    def test_fails_on_invalid_ca(self):
        cs = _make_cs()
        spec = _make_scenario_spec(ca_id="CA-99-1")
        result = validate_bdi_grounding(spec, cs)
        assert not result.passed
        assert any("ca_id" in e for e in result.errors)

    def test_fails_on_ca_not_belonging_to_controller(self):
        cs = _make_cs(include_resp2=True)
        spec = _make_scenario_spec(
            target_controller="RESP-1", target_control_action="CA-2-1"
        )
        result = validate_bdi_grounding(spec, cs)
        assert not result.passed
        assert any("target_control_action" in e for e in result.errors)


class TestVulnerabilityCompleteness:
    """SP3-VAL-05, SP3-VAL-06."""

    def test_fails_on_empty_vulnerability(self):
        spec = _make_scenario_spec(vulnerability="")
        result = validate_vulnerability_completeness(spec)
        assert not result.passed
        assert any("vulnerability" in e for e in result.errors)

    def test_fails_on_whitespace_only_vulnerability(self):
        """Whitespace-only vulnerability must be treated as empty."""
        spec = _make_scenario_spec(vulnerability="   ")
        result = validate_vulnerability_completeness(spec)
        assert not result.passed
        assert any("vulnerability" in e for e in result.errors)

    def test_passes_with_all_filled(self):
        spec = _make_scenario_spec(vulnerability="exploitable via injection")
        result = validate_vulnerability_completeness(spec)
        assert result.passed


class TestTraceability:
    """SP3-VAL-12 through SP3-VAL-18."""

    def test_passes_on_complete_chain(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_enriched_threat_set()
        env = _make_envelope()
        errors = validate_traceability([env], ets, cs, la)
        assert len(errors) == 0

    def test_fails_on_broken_hazard(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        threat = _make_threat(related_hazards=["H-99"])
        ets = _make_enriched_threat_set(threats=[threat])
        env = _make_envelope()
        errors = validate_traceability([env], ets, cs, la)
        assert any(e.broken_link == "hazard" for e in errors)

    def test_fails_on_broken_constraint(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        threat = _make_threat(related_constraints=["SC-99"])
        ets = _make_enriched_threat_set(threats=[threat])
        env = _make_envelope()
        errors = validate_traceability([env], ets, cs, la)
        assert any(e.broken_link == "constraint" for e in errors)

    def test_fails_on_broken_responsibility(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_enriched_threat_set()
        spec = _make_scenario_spec(target_controller="RESP-99")
        env = _make_envelope(spec=spec)
        errors = validate_traceability([env], ets, cs, la)
        assert any(e.broken_link == "responsibility" for e in errors)

    def test_fails_on_broken_ica_link(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_enriched_threat_set()
        spec = _make_scenario_spec(ica_id="RESP-1:CA-1-1:NOT_PROVIDED:99")
        env = _make_envelope(spec=spec)
        errors = validate_traceability([env], ets, cs, la)
        assert any(e.broken_link == "ica" for e in errors)

    def test_accepts_legal_provenance_root(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_enriched_threat_set()
        spec = _make_scenario_spec(provenance="structural")
        env = _make_envelope(spec=spec)
        errors = validate_traceability([env], ets, cs, la)
        assert not any(e.broken_link == "provenance_root" for e in errors)

    def test_rejects_illegal_provenance_root(self):
        cs = _make_cs()
        la = _make_loss_analysis()
        ets = _make_enriched_threat_set()
        # Use model_construct to bypass Literal validation on ThreatSource
        threat_source = ThreatSource.model_construct(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="unknown_source",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        )
        spec = _make_scenario_spec()
        spec = spec.model_copy(update={"threat_source": threat_source})
        env = _make_envelope(spec=spec)
        errors = validate_traceability([env], ets, cs, la)
        assert any(e.broken_link == "provenance_root" for e in errors)


class TestOrphanDetection:
    """SP3-VAL-19, SP3-VAL-20."""

    def test_finds_orphan_elements(self):
        cs = _make_cs()
        cs.responsibilities[0].process_model_parts.append(
            ProcessModelPart(pm_id="PM-1-2", description="Extra PM")
        )
        threat = _make_threat()
        ets = _make_enriched_threat_set(threats=[threat])
        orphans = detect_orphan_elements(cs, ets)
        assert "PM-1-2" in orphans

    def test_no_false_positive_orphans_for_referenced_elements(self):
        """Referenced resp/ca must not be flagged as orphans."""
        cs = _make_cs()
        threat = _make_threat()
        ets = _make_enriched_threat_set(threats=[threat])
        orphans = detect_orphan_elements(cs, ets)
        assert "RESP-1" not in orphans
        assert "CA-1-1" not in orphans

    def test_collects_ids_from_two_part_slot_id(self):
        """A 2-part slot ID must still yield resp and ca references."""
        cs = _make_cs()
        threat = _make_threat()
        threat = threat.model_copy(update={"ica_slot_id": "RESP-1:CA-1-1"})
        ets = _make_enriched_threat_set(threats=[threat])
        orphans = detect_orphan_elements(cs, ets)
        assert "RESP-1" not in orphans
        assert "CA-1-1" not in orphans

    def test_finds_orphan_icas(self):
        threats = [
            _make_threat(ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i}") for i in range(1, 6)
        ]
        ets = _make_enriched_threat_set(threats=threats)
        env = _make_envelope()
        # Only 3 scenarios produced out of 5 threats
        orphans = detect_orphan_icas(ets, [env])
        assert len(orphans) == 4  # 4 threats not concretized (env has ica_id :1)
