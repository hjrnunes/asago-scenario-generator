"""Tests for Stream B Slice 4 — validator-derived Stage 6 prompt alignment.

Covers STPA-PROJ-04-01 through STPA-PROJ-04-05 from the Gherkin feature
file: every narrative, tree, and Gherkin Stage 6 prompt renders the same
projection alignment table derived from the validated projection, and the
tables cannot drift from the causal-factor validator mappings.
"""

from __future__ import annotations

import json

import pytest

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.execution_envelope import (
    CandidateExecutionEnvelope,
    CausalFactor,
    CausalFactorKind,
    predicate_for,
    step_kind_for,
)
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
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
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.scenario_prod.assembly import (
    assemble_candidate_envelope,
)
from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
    build_attack_tree_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.gherkin import build_gherkin_prompts
from asago_scenario_generator.stpa.scenario_prod.narrative import (
    build_narrative_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.projection import (
    canonical_projection_data,
)
from asago_scenario_generator.stpa.scenario_prod.prompt_alignment import (
    PROJECTION_ALIGNMENT_COLUMNS,
    derive_projection_alignment_rows,
    render_projection_alignment_table,
)
from tests.stpa.helpers import make_minimal_control_structure

CONTROLLER = "RESP-1"
CONTROL_ACTION = "CA-1-1"
UCA_TYPE = UCAType.wrong_timing


def _factor(kind: CausalFactorKind, source_id: str) -> CausalFactor:
    return CausalFactor(kind=kind, source_id=source_id, description=source_id)


def _envelope(
    factors: list[CausalFactor],
) -> CandidateExecutionEnvelope:
    return assemble_candidate_envelope(
        make_minimal_control_structure(),
        controller_id=CONTROLLER,
        control_action_id=CONTROL_ACTION,
        uca_type=UCA_TYPE,
        causal_factors=factors,
        derive_temporal_vector=True,
    )


def _doc(factors: list[CausalFactor]) -> dict:
    return canonical_projection_data(_envelope(factors))


def _spec(control_structure: ControlStructure | None = None) -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=f"{CONTROLLER}:{CONTROL_ACTION}:{UCA_TYPE.value}",
            provenance="structural",
        ),
        target_controller=CONTROLLER,
        target_control_action=CONTROL_ACTION,
        ica_type=UCA_TYPE,
        defender_bdi=DefenderBDI(
            beliefs=[
                DefenderBelief(pm_id="PM-1-1", content="b", vulnerability="v")
            ],
            desires=[DefenderDesire(resp_id=CONTROLLER, content="d")],
            intentions=[DefenderIntention(ca_id=CONTROL_ACTION, content="i")],
        ),
        attacker_bdi=AttackerBDI(beliefs=["b"], desires=["d"], intentions=["i"]),
        loss_scenario="loss",
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Constraint",
                related_hazards=["H-1"],
            )
        ],
    )


def _loader() -> TemplateLoader:
    return TemplateLoader(PROMPTS_DIR)


ROW_CELL_KEYS = (
    "projection_id",
    "source_kind",
    "source_id",
    "assertion_id",
    "assertion_predicate",
    "step_id",
    "step_kind",
    "order",
    "required_reference",
)


def _row_cells(row: dict) -> list[str]:
    """Flatten one derived row into its column-order cell values."""
    return [str(row[column]) for column in ROW_CELL_KEYS]


def _contains_tokens(row_cells: list[str], tokens: list[str]) -> bool:
    """True if the row cells contain the tokens in order (subsequence)."""
    iterator = iter(row_cells)
    return all(any(token == cell for cell in iterator) for token in tokens)


def _rows_from_table(table_text: str) -> list[list[str]]:
    """Parse the rendered markdown table into per-row cell lists."""
    lines = [
        line.strip()
        for line in table_text.splitlines()
        if line.strip().startswith("|")
    ]
    rows: list[list[str]] = []
    for line in lines:
        cells = [cell.strip() for cell in line.strip("|").split("|")]
        if cells == ["---"] * len(cells):
            continue
        rows.append(cells)
    return rows[1:]  # skip the header


class TestProj0401AlignmentTable:
    """STPA-PROJ-04-01: one derived alignment table per Stage 6 call."""

    def test_columns_are_exact(self):
        """The table uses the exact nine-column contract."""
        assert PROJECTION_ALIGNMENT_COLUMNS == (
            "projection ID",
            "source kind",
            "source ID",
            "assertion ID",
            "assertion predicate",
            "step ID",
            "step kind",
            "order",
            "required reference",
        )

    def test_one_row_per_assertion_and_final_uca_step(self):
        """Two factors plus the UCA final step render exactly three rows."""
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        rows = derive_projection_alignment_rows(doc)
        assert len(rows) == 3

    def test_rows_preserve_factor_order_and_place_uca_last(self):
        """Causal-factor order is preserved and the UCA row is last."""
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        rows = derive_projection_alignment_rows(doc)
        assert [row["source_id"] for row in rows] == ["PM-1-1", "FB-1-1", "CA-1-1"]
        assert rows[-1]["step_kind"] == "UNSAFE_CONTROL_ACTION"

    def test_rows_contain_the_required_cell_sequences(self):
        """The PM, FB, and CA rows contain the specified structural sequences."""
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        rows = derive_projection_alignment_rows(doc)
        assert _contains_tokens(
            _row_cells(rows[0]),
            ["PM-1-1", "PROCESS_MODEL_FLAW", "TA-1", "MODEL_FLAWED", "S-1"],
        )
        assert _contains_tokens(
            _row_cells(rows[1]),
            ["FB-1-1", "FEEDBACK_DELAY", "TA-2", "FEEDBACK_DELAYED", "S-2"],
        )
        assert _contains_tokens(
            _row_cells(rows[2]),
            ["CA-1-1", "UNSAFE_CONTROL_ACTION", "S-3"],
        )

    def test_table_contains_candidate_identifier(self):
        """The rendered table names the projection candidate identifier."""
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        table = render_projection_alignment_table(doc)
        assert "EXEC:RESP-1:CA-1-1:WRONG_TIMING" in table
        assert "RESP-1:CA-1-1:WRONG_TIMING" in table

    def test_projection_ids_are_semantic_structural_ids(self):
        """Projection IDs are PM/FB/CA structural IDs, not positional labels."""
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        table = render_projection_alignment_table(doc)
        assert "semantic structural IDs" in table
        rows = _rows_from_table(table)
        assert rows[0][0] == "PM-1-1"
        assert rows[1][0] == "FB-1-1"
        assert rows[2][0] == "CA-1-1"

    def test_render_round_trips_rows(self):
        """Rendered rows match the derived row cell values exactly."""
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        rows = derive_projection_alignment_rows(doc)
        table_rows = _rows_from_table(render_projection_alignment_table(doc))
        assert table_rows == [_row_cells(row) for row in rows]


class TestProj0401PromptRendering:
    """STPA-PROJ-04-01: every Stage 6 prompt contains the alignment table."""

    @pytest.mark.parametrize(
        "render_prompts",
        [
            lambda loader, spec, table: build_narrative_prompts(
                spec, loader, projection_alignment=table
            ),
            lambda loader, spec, table: build_attack_tree_prompts(
                spec, make_minimal_control_structure(), loader,
                projection_alignment=table,
            ),
            lambda loader, spec, table: build_gherkin_prompts(
                spec,
                _loss_analysis().security_constraints[0],
                _loss_analysis(),
                loader,
                projection_alignment=table,
            ),
        ],
        ids=["narrative", "tree", "gherkin"],
    )
    def test_system_and_user_prompts_contain_the_table(self, render_prompts):
        """Both the system and the user prompt of each call carry the table."""
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        table = render_projection_alignment_table(doc)
        system_prompt, user_prompt = render_prompts(_loader(), _spec(), table)
        for prompt in (system_prompt, user_prompt):
            assert "Projection Alignment" in prompt
            assert "| projection ID |" in prompt
            assert "EXEC:RESP-1:CA-1-1:WRONG_TIMING" in prompt
            assert "semantic structural IDs" in prompt

    def test_default_builders_have_no_table(self):
        """Without the optional argument the builders stay backward compatible."""
        system_prompt, user_prompt = build_narrative_prompts(
            _spec(), _loader()
        )
        assert "Projection Alignment" not in system_prompt
        assert "Projection Alignment" not in user_prompt


class TestProj0402NarrativeConstraints:
    """STPA-PROJ-04-02: narrative prompt constraints."""

    def _narrative_text(self) -> str:
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        system_prompt, user_prompt = build_narrative_prompts(
            _spec(),
            _loader(),
            projection_alignment=render_projection_alignment_table(doc),
        )
        return system_prompt + "\n" + user_prompt

    def test_requires_factor_order(self):
        """The narrative prompt requires PM-1-1 before FB-1-1 before CA-1-1."""
        text = self._narrative_text()
        assert "strictly in table order" in text
        body = text[text.index("Projection Alignment"):]
        rows = _rows_from_table(body)
        order_by_id = {
            cells[0]: int(cells[7]) for cells in rows if cells[7].isdigit()
        }
        assert order_by_id["PM-1-1"] < order_by_id["FB-1-1"]
        assert order_by_id["FB-1-1"] < order_by_id["CA-1-1"]

    def test_requires_exact_uca_type(self):
        """The narrative prompt requires the exact UCA type WRONG_TIMING."""
        text = self._narrative_text()
        assert "exact ICA type" in text
        assert "WRONG_TIMING" in text

    def test_forbids_inventing_projection_elements(self):
        """The narrative prompt forbids inventing factors, assertions, steps."""
        text = self._narrative_text()
        assert "Do not invent any causal factor, temporal assertion, or scenario step" in text

    def test_preserves_feedback_transport_distinction(self):
        """FB-1-1 stays a logical dependency, never an inferred transport."""
        text = self._narrative_text()
        assert "FB-1-1" in text
        assert "logical information dependency" in text
        assert "Never infer" in text


class TestProj0403AttackTreeConstraints:
    """STPA-PROJ-04-03: attack-tree prompt constraints."""

    def _tree_text(self) -> str:
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
            ]
        )
        system_prompt, user_prompt = build_attack_tree_prompts(
            _spec(),
            make_minimal_control_structure(),
            _loader(),
            projection_alignment=render_projection_alignment_table(doc),
        )
        return system_prompt + "\n" + user_prompt

    def test_requires_exact_root(self):
        """The tree prompt requires root 'Induce ICA WRONG_TIMING on CA-1-1'."""
        text = self._tree_text()
        assert "Induce ICA WRONG_TIMING on CA-1-1" in text

    def test_requires_known_structural_references(self):
        """The tree prompt requires the known references PM-1-1 and CA-1-1."""
        text = self._tree_text()
        body = text[text.index("Projection Alignment"):]
        rows = _rows_from_table(body)
        row_ids = {cells[0] for cells in rows}
        assert "PM-1-1" in row_ids
        assert "CA-1-1" in row_ids

    def test_requires_temporal_leaf_order(self):
        """Temporal-factor leaf references preserve projection order."""
        text = self._tree_text()
        assert "preserve the projection order" in text
        body = text[text.index("Projection Alignment"):]
        rows = _rows_from_table(body)
        order_by_id = {
            cells[0]: int(cells[7]) for cells in rows if cells[7].isdigit()
        }
        assert order_by_id["PM-1-1"] < order_by_id["CA-1-1"]

    def test_forbids_unproven_infrastructure_mechanisms(self):
        """The tree prompt forbids infrastructure without attacker evidence."""
        text = self._tree_text()
        assert "explicitly attacker-accessible" in text


class TestProj0404GherkinConstraints:
    """STPA-PROJ-04-04: Gherkin prompt constraints."""

    def _gherkin_text(self) -> str:
        doc = _doc(
            [
                _factor(CausalFactorKind.process_model_flaw, "PM-1-1"),
                _factor(CausalFactorKind.feedback_delay, "FB-1-1"),
            ]
        )
        loss_analysis = _loss_analysis()
        system_prompt, user_prompt = build_gherkin_prompts(
            _spec(),
            loss_analysis.security_constraints[0],
            loss_analysis,
            _loader(),
            projection_alignment=render_projection_alignment_table(doc),
        )
        return system_prompt + "\n" + user_prompt

    def test_requires_given_reference_to_pm(self):
        """The Gherkin prompt requires a Given reference to PM-1-1."""
        text = self._gherkin_text()
        assert "process model state IDs (PM-*)" in text
        assert "PM-1-1" in text

    def test_requires_exact_ica_type_and_control_action(self):
        """The actual outcome must state WRONG_TIMING on CA-1-1 exactly."""
        text = self._gherkin_text()
        assert "actual outcome" in text
        assert "WRONG_TIMING" in text
        assert "CA-1-1" in text

    def test_forbids_unknown_structural_ids(self):
        """The Gherkin prompt forbids IDs outside projection or structure."""
        text = self._gherkin_text()
        assert "outside the projection alignment table or the control structure" in text

    def test_retains_independent_loss_id_validation(self):
        """Independent valid Loss ID validation is retained."""
        text = self._gherkin_text()
        assert "valid Loss IDs" in text
        assert "L-1" in text


class TestProj0405NoDrift:
    """STPA-PROJ-04-05: alignment tables cannot drift from validator rules."""

    def _doc_with_anomalies(self) -> dict:
        return _doc(
            [
                _factor(CausalFactorKind.sensor_anomaly, "FB-1-1"),
                _factor(CausalFactorKind.actuator_anomaly, "CA-1-1"),
            ]
        )

    def test_double_derivation_is_byte_identical(self):
        """Deriving the table twice yields byte-identical output."""
        doc = self._doc_with_anomalies()
        first_rows = derive_projection_alignment_rows(doc)
        second_rows = derive_projection_alignment_rows(doc)
        first_payload = json.dumps(
            first_rows, sort_keys=True, separators=(",", ":")
        )
        second_payload = json.dumps(
            second_rows, sort_keys=True, separators=(",", ":")
        )
        assert first_payload == second_payload
        assert (
            render_projection_alignment_table(doc)
            == render_projection_alignment_table(doc)
        )

    def test_assertion_rows_follow_validator_mapping(self):
        """Each assertion row source and predicate equals the validator mapping."""
        doc = self._doc_with_anomalies()
        factors = [
            CausalFactor(kind=CausalFactorKind.sensor_anomaly, source_id="FB-1-1",
                         description="f"),
            CausalFactor(kind=CausalFactorKind.actuator_anomaly, source_id="CA-1-1",
                         description="f"),
        ]
        rows = derive_projection_alignment_rows(doc)
        for index, row in enumerate(rows[:-1]):
            factor = factors[index]
            assert row["source_id"] == factor.source_id
            assert row["assertion_id"] == f"TA-{index + 1}"
            assert row["assertion_predicate"] == predicate_for(factor.kind).value

    def test_factor_step_rows_follow_validator_mapping(self):
        """Each factor step row source and kind equals the validator mapping."""
        doc = self._doc_with_anomalies()
        factors = [
            CausalFactor(kind=CausalFactorKind.sensor_anomaly, source_id="FB-1-1",
                         description="f"),
            CausalFactor(kind=CausalFactorKind.actuator_anomaly, source_id="CA-1-1",
                         description="f"),
        ]
        rows = derive_projection_alignment_rows(doc)
        for index, row in enumerate(rows[:-1]):
            factor = factors[index]
            assert row["source_id"] == factor.source_id
            assert row["step_id"] == f"S-{index + 1}"
            assert row["step_kind"] == step_kind_for(factor.kind).value
            assert row["order"] == index + 1

    def test_final_row_is_uca_step_for_control_action(self):
        """The final row is the unsafe-control-action step for CA-1-1."""
        doc = self._doc_with_anomalies()
        rows = derive_projection_alignment_rows(doc)
        assert rows[-1]["source_id"] == "CA-1-1"
        assert rows[-1]["step_kind"] == "UNSAFE_CONTROL_ACTION"
        assert rows[-1]["step_id"] == "S-3"

    def test_no_row_is_hand_authored_by_a_stage6_prompt(self):
        """Stage 6 templates contain none of the derived row identifiers."""
        doc = self._doc_with_anomalies()
        rows = derive_projection_alignment_rows(doc)
        # "-" is the neutral placeholder for cells the UCA row cannot carry;
        # the check covers values that identify a specific projection row.
        row_literals = {
            cell
            for row in rows
            for cell in (
                row["assertion_id"],
                row["assertion_predicate"],
                row["step_id"],
            )
            if cell != "-"
        }
        templates = sorted(PROMPTS_DIR.glob("stage6*.j2")) + [
            PROMPTS_DIR / "_stage6_projection_alignment.j2"
        ]
        for template in templates:
            text = template.read_text()
            for literal in row_literals:
                assert literal not in text, (
                    f"{template.name} hand-authors row literal {literal!r}"
                )
