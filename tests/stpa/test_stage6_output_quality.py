"""Unit tests for Stage 6 output quality (jpkw, gddi).

Covers:
  - jpkw: GherkinSpec structured model, assembly, .feature text
  - gddi: Loss/Hazard ID hallucination validation
"""

from __future__ import annotations


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
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.validators import validate_loss_hazard_id_references


# ---------------------------------------------------------------------------
# Fixture builders
# ---------------------------------------------------------------------------


def _make_scenario_spec(
    ica_type: UCAType = UCAType.not_provided,
    ca_id: str = "CA-1-1",
) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=f"RESP-1:{ca_id}:{ica_type.value}",
            provenance="structural",
            ica_id=f"RESP-1:{ca_id}:{ica_type.value}:1",
        ),
        target_controller="RESP-1",
        target_control_action=ca_id,
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(
                    pm_id="PM-1-1", content="State", vulnerability="exploitable"
                ),
            ],
            desires=[DefenderDesire(resp_id="RESP-1", content="R1")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Action")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["Knows PM-1-1 is weak"],
            desires=["Induce NOT_PROVIDED"],
            intentions=["Poison PM-1-1 via FB-1-1"],
        ),
        loss_scenario="Loss scenario text",
    )


def _make_loss_analysis(
    loss_ids: list[str] | None = None,
    hazard_ids: list[str] | None = None,
) -> LossAnalysis:
    loss_ids = loss_ids or ["L-1", "L-2"]
    hazard_ids = hazard_ids or ["H-1", "H-2"]
    risk_card_losses = [
        Loss(
            loss_id=lid,
            description=f"Loss {lid}",
            provenance=LossProvenance.risk_card,
            source_risk_cards=[f"r{i}"],
        )
        for i, lid in enumerate(loss_ids)
    ]
    hazards = [
        Hazard(
            hazard_id=hid,
            description=f"Hazard {hid}",
            related_losses=[loss_ids[0]],
        )
        for hid in hazard_ids
    ]
    return LossAnalysis(
        risk_card_losses=risk_card_losses,
        use_case_losses=[],
        hazards=hazards,
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="The system must validate before action",
                related_hazards=[hazard_ids[0]],
            ),
        ],
    )


def _make_gherkin_spec(
    feature: str = "Safe orchestration",
    scenario: str = "SCN-001",
    given: list[str] | None = None,
    when: list[str] | None = None,
    then_expected: list[str] | None = None,
    then_actual: list[str] | None = None,
) -> GherkinSpec:
    return GherkinSpec(
        feature=feature,
        scenario=scenario,
        given=given if given is not None else ["Given PM-1-1 is active"],
        when=when if when is not None else ["When a revoked user requests access"],
        then_expected=then_expected
        if then_expected is not None
        else ["Then the system should reject the request"],
        then_actual=then_actual
        if then_actual is not None
        else [
            "But the system approves the request",
            "And loss L-1 is realized",
        ],
    )


def _make_envelope(
    gherkin_spec: GherkinSpec | None = None,
    gherkin_raw: str = "",
    spec: ScenarioSpec | None = None,
) -> ScenarioEnvelope:
    return ScenarioEnvelope(
        scenario_id="SCN-001",
        scenario_spec=spec or _make_scenario_spec(),
        narrative="Narrative text",
        attack_tree={
            "root": "Induce ICA NOT_PROVIDED on CA-1-1",
            "branches": [
                {"category": "controller_side", "label": "l", "children": []},
                {"category": "path_side", "label": "l", "children": []},
            ],
            "leaves": [],
        },
        gherkin_spec=gherkin_spec or _make_gherkin_spec(),
        gherkin_raw=gherkin_raw,
        target_responsibility="RESP-1",
        ica_type=UCAType.not_provided,
        provenance="structural",
    )


# ===========================================================================
# JPKW — GherkinSpec structured output
# ===========================================================================


class TestGherkinSpecModel:
    """JPKW-01: GherkinSpec model has structured fields."""

    def test_jpkw_01_fields_and_types(self):
        spec = _make_gherkin_spec()
        assert isinstance(spec.feature, str)
        assert isinstance(spec.scenario, str)
        assert isinstance(spec.given, list)
        assert all(isinstance(s, str) for s in spec.given)
        assert isinstance(spec.when, list)
        assert all(isinstance(s, str) for s in spec.when)
        assert isinstance(spec.then_expected, list)
        assert all(isinstance(s, str) for s in spec.then_expected)
        assert isinstance(spec.then_actual, list)
        assert all(isinstance(s, str) for s in spec.then_actual)


class TestScenarioEnvelopeGherkinFields:
    """JPKW-02: ScenarioEnvelope has gherkin_spec of type GherkinSpec and gherkin_raw of type str."""

    def test_jpkw_02_gherkin_spec_is_gherkin_spec_type(self):
        envelope = _make_envelope()
        assert isinstance(envelope.gherkin_spec, GherkinSpec)

    def test_jpkw_02_gherkin_raw_is_str_type(self):
        envelope = _make_envelope(gherkin_raw="Feature: Test\n")
        assert isinstance(envelope.gherkin_raw, str)


class TestAssembleEnvelopeGherkinSpec:
    """JPKW-06: assemble_envelope accepts a GherkinSpec and gherkin_raw."""

    def test_jpkw_06_assemble_with_gherkin_spec_and_raw(self):
        spec = _make_scenario_spec()
        ghk = _make_gherkin_spec(feature="Safe orchestration", scenario="SCN-001")
        raw = "Feature: Safe orchestration\nScenario: SCN-001\n"

        envelope = assemble_envelope(
            scenario_id="SCN-001",
            scenario_spec=spec,
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec=ghk,
            gherkin_raw=raw,
        )
        assert envelope.gherkin_spec == ghk
        assert envelope.gherkin_raw == raw


class TestGherkinSpecToFeatureText:
    """JPKW-10: raw Gherkin text is reconstructable from structured fields."""

    def test_jpkw_10_to_feature_text(self):
        spec = GherkinSpec(
            feature="Safe orchestration",
            scenario="SCN-001",
            given=["Given PM-1-1 is active"],
            when=["When a revoked user requests access"],
            then_expected=["Then the system should reject the request"],
            then_actual=["But the system approves"],
        )
        text = spec.to_feature_text()
        assert "Feature: Safe orchestration" in text
        assert "Scenario: SCN-001" in text
        assert "Given PM-1-1 is active" in text
        assert "When a revoked user requests access" in text
        assert "Then the system should reject the request" in text

# ===========================================================================
# GDDI — Loss/Hazard ID validation
# ===========================================================================


class TestLossHazardIdValidator:
    """GDDI-05 through GDDI-08: validator catches hallucinated IDs."""

    def _la_with_ids(self, loss_ids=None, hazard_ids=None):
        return _make_loss_analysis(
            loss_ids=loss_ids or ["L-1", "L-2"],
            hazard_ids=hazard_ids or ["H-1", "H-2"],
        )

    def test_gddi_05_catches_hallucinated_loss_l99(self):
        text = "Scenario: Test\n  But loss L-99 is realized\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("L-99" in e for e in result.errors)

    def test_gddi_05_catches_hallucinated_loss_l100(self):
        text = "Scenario: Test\n  But loss L-100 is realized\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("L-100" in e for e in result.errors)

    def test_gddi_05_catches_hallucinated_hazard_h99(self):
        text = "Scenario: Test\n  And hazard H-99 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("H-99" in e for e in result.errors)

    def test_gddi_05_catches_hallucinated_hazard_h100(self):
        text = "Scenario: Test\n  And hazard H-100 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("H-100" in e for e in result.errors)

    def test_gddi_06_catches_multiple_hallucinated_ids(self):
        text = "Scenario: Test\n  But loss L-99 is realized\n  And hazard H-88 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert not result.passed
        assert any("L-99" in e for e in result.errors)
        assert any("H-88" in e for e in result.errors)

    def test_gddi_07_passes_with_valid_ids(self):
        text = "Scenario: Test\n  But loss L-1 is realized\n  And hazard H-1 occurs\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert result.passed

    def test_gddi_08_passes_with_no_id_references(self):
        text = "Scenario: Test\n  Given PM-1-1 is active\n  When x\n  Then should reject\n  But approves\n"
        result = validate_loss_hazard_id_references(text, self._la_with_ids())
        assert result.passed

    def test_gddi_validator_accepts_gherkin_spec(self):
        """Validator also works with GherkinSpec objects."""
        spec = _make_gherkin_spec(
            then_actual=["But the system approves", "And loss L-99 is realized"],
        )
        result = validate_loss_hazard_id_references(spec, self._la_with_ids())
        assert not result.passed
        assert any("L-99" in e for e in result.errors)


class TestLossHazardIdValidationInStage7:
    """GDDI-10: Loss/Hazard ID validation runs during Stage 7 envelope validation."""

    def test_gddi_10_stage7_validation_catches_hallucinated_id(self):
        from asago_scenario_generator.stpa.scenario_prod.run import (
            _validate_envelope_stage7,
        )

        la = _make_loss_analysis(loss_ids=["L-1"], hazard_ids=["H-1"])
        envelope = _make_envelope(
            gherkin_spec=_make_gherkin_spec(
                then_actual=["But the system approves", "And hazard H-99 occurs"],
            ),
            gherkin_raw="Scenario: Test\n  But hazard H-99 occurs\n",
        )
        errors: list[str] = []
        _validate_envelope_stage7(envelope, la, errors)
        assert any("H-99" in e for e in errors)


class TestEnvelopeGherkinTextHelper:
    """JPKW-16: _envelope_gherkin_text extracts text correctly.

    Prefers the structured spec's rendered feature text (guaranteed valid
    Gherkin syntax) over gherkin_raw (the raw LLM response, which may be
    YAML rather than Gherkin). Falls back to gherkin_raw only when the
    spec failed to parse (empty feature name).
    """

    def test_jpkw_16_prefers_spec_text_when_spec_parsed(self):
        from asago_scenario_generator.stpa.scenario_prod.run import (
            _envelope_gherkin_text,
        )

        envelope = _make_envelope(gherkin_raw="feature: Raw text\nscenario: X\n")
        assert (
            _envelope_gherkin_text(envelope) == _make_gherkin_spec().to_feature_text()
        )

    def test_jpkw_16_falls_back_to_raw_when_spec_not_parsed(self):
        from asago_scenario_generator.stpa.scenario_prod.run import (
            _envelope_gherkin_text,
        )

        envelope = _make_envelope(
            gherkin_spec=_make_gherkin_spec(feature=""),
            gherkin_raw="feature: Raw text\nscenario: X\n",
        )
        assert _envelope_gherkin_text(envelope) == "feature: Raw text\nscenario: X\n"

    def test_jpkw_16_falls_back_to_spec_when_no_raw(self):
        from asago_scenario_generator.stpa.scenario_prod.run import (
            _envelope_gherkin_text,
        )

        envelope = _make_envelope(gherkin_raw="")
        text = _envelope_gherkin_text(envelope)
        assert "Feature: Safe orchestration" in text

    def test_jpkw_16_returns_empty_when_neither_available(self):
        from asago_scenario_generator.stpa.scenario_prod.run import (
            _envelope_gherkin_text,
        )

        envelope = ScenarioEnvelope.model_construct(
            scenario_id="SCN-001",
            scenario_spec=_make_scenario_spec(),
            narrative="Narrative",
            attack_tree={"root": "r", "branches": [], "leaves": []},
            gherkin_spec="not a GherkinSpec instance",
            gherkin_raw="",
            target_responsibility="RESP-1",
            ica_type=UCAType.not_provided,
            provenance="structural",
        )
        assert _envelope_gherkin_text(envelope) == ""


# ===========================================================================
# Hardening tests — kill surviving mutants from mutation testing
# ===========================================================================


class TestHardeningTreeBranchCoverage:
    """Hardening: validate_tree_branch_coverage and get_branch_categories.

    Kills mutants:
      - line 139: cat in BRANCH_CATEGORIES -> cat not in BRANCH_CATEGORIES
      - branch validation rejects zero supported categories
    """

    def test_one_valid_category_passes(self):
        """A single evidence-backed category is sufficient."""
        from asago_scenario_generator.stpa.scenario_prod.validators import (
            validate_tree_branch_coverage,
        )

        tree = {
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": "l1", "children": []},
            ],
            "leaves": [],
        }
        assert validate_tree_branch_coverage(tree).passed

    def test_zero_valid_categories_fails(self):
        """A tree still needs one supported causal category."""
        from asago_scenario_generator.stpa.scenario_prod.validators import (
            validate_tree_branch_coverage,
        )

        tree = {"root": "r", "branches": [], "leaves": []}
        result = validate_tree_branch_coverage(tree)
        assert not result.passed
        assert result.errors == [
            "Attack tree uses no supported branch category; need at least 1."
        ]

    def test_two_valid_categories_passes(self):
        """A tree with exactly 2 valid branch categories must pass."""
        from asago_scenario_generator.stpa.scenario_prod.validators import (
            validate_tree_branch_coverage,
        )

        tree = {
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": "l1", "children": []},
                {"category": "path_side", "label": "l2", "children": []},
            ],
            "leaves": [],
        }
        result = validate_tree_branch_coverage(tree)
        assert result.passed

    def test_three_valid_categories_passes(self):
        """A tree with all 3 valid branch categories must pass."""
        from asago_scenario_generator.stpa.scenario_prod.validators import (
            validate_tree_branch_coverage,
        )

        tree = {
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": "l1", "children": []},
                {"category": "path_side", "label": "l2", "children": []},
                {"category": "coordination_gap", "label": "l3", "children": []},
            ],
            "leaves": [],
        }
        result = validate_tree_branch_coverage(tree)
        assert result.passed

    def test_get_branch_categories_returns_valid_only(self):
        """get_branch_categories only returns categories in BRANCH_CATEGORIES."""
        from asago_scenario_generator.stpa.scenario_prod.validators import (
            get_branch_categories,
            BRANCH_CATEGORIES,
        )

        tree = {
            "root": "r",
            "branches": [
                {"category": "controller_side", "label": "l1", "children": []},
                {"category": "invalid_category", "label": "l2", "children": []},
            ],
            "leaves": [],
        }
        cats = get_branch_categories(tree)
        assert cats == {"controller_side"}
        assert cats.issubset(set(BRANCH_CATEGORIES))
