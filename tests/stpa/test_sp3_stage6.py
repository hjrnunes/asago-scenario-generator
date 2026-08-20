"""Unit tests for SP3 Stage 6 — Narrative, attack tree, Gherkin, and assembly."""

from __future__ import annotations

import json
from pathlib import Path
from tempfile import TemporaryDirectory

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
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.scenario_envelope import GherkinSpec
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.scenario_prod.narrative import generate_narrative
from asago_scenario_generator.stpa.scenario_prod.attack_tree import (
    generate_attack_tree,
    parse_attack_tree,
)
from asago_scenario_generator.stpa.scenario_prod.gherkin import generate_gherkin
from asago_scenario_generator.stpa.scenario_prod.assembly import assemble_envelope
from asago_scenario_generator.stpa.scenario_prod.run import _write_scenario_artifacts

from tests.stpa.sp1_helpers import MockLLMClient, read_calls_jsonl


def _make_cs() -> ControlStructure:
    cps = [ControlledProcess(cp_id="CP-1", description="Interface")]
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="R1",
                process_model_parts=[ProcessModelPart(pm_id="PM-1-1", description="State")],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1", description="Action",
                        target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                    ),
                ],
                feedback_channels=[
                    FeedbackChannel(
                        fb_id="FB-1-1", description="Feedback", updates="PM-1-1",
                        source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
                    ),
                ],
            ),
        ],
        controlled_processes=cps,
    )


def _make_scenario_spec() -> ScenarioSpec:
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
            provenance="structural",
            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=UCAType.not_provided,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="State", vulnerability="exploitable")],
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


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(loss_id="L-1", description="Loss", provenance=LossProvenance.risk_card, source_risk_cards=["r1"]),
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="The system must validate before action",
                related_hazards=["H-1"],
            ),
        ],
    )


class TestNarrative:
    """SP3-NAR-01 through SP3-NAR-07."""

    def test_one_llm_call(self):
        spec = _make_scenario_spec()
        client = MockLLMClient()
        client.set_response_for(None, "A 7-step narrative text.")

        with TemporaryDirectory() as tmpdir:
            result, error = generate_narrative(client, spec, Path(tmpdir))
            assert error is None
            assert result is not None
            assert client.call_count == 1

    def test_call_logged_with_stage_6(self):
        spec = _make_scenario_spec()
        client = MockLLMClient()
        client.set_response_for(None, "Narrative text.")

        with TemporaryDirectory() as tmpdir:
            generate_narrative(client, spec, Path(tmpdir))
            calls = read_calls_jsonl(Path(tmpdir))
            assert len(calls) == 1
            assert calls[0]["stage"] == "stage_6"
            assert calls[0]["step"] == "narrative"

    def test_narrative_is_non_empty_string(self):
        spec = _make_scenario_spec()
        client = MockLLMClient()
        client.set_response_for(None, "Step 1: The defender's process model starts correct...")

        with TemporaryDirectory() as tmpdir:
            result, _ = generate_narrative(client, spec, Path(tmpdir))
            assert isinstance(result, str)
            assert len(result) > 0

    def test_user_prompt_contains_scenario_spec(self):
        spec = _make_scenario_spec()
        client = MockLLMClient()
        client.set_response_for(None, "Narrative.")

        with TemporaryDirectory() as tmpdir:
            generate_narrative(client, spec, Path(tmpdir))
            call = client.calls[0]
            assert "SCN-001" in call.user_prompt
            assert "PM-1-1" in call.user_prompt
            assert "Loss scenario text" in call.user_prompt

    def test_system_prompt_contains_7_step_structure(self):
        spec = _make_scenario_spec()
        client = MockLLMClient()
        client.set_response_for(None, "Narrative.")

        with TemporaryDirectory() as tmpdir:
            generate_narrative(client, spec, Path(tmpdir))
            sys_prompt = client.calls[0].system_prompt
            assert "7-step" in sys_prompt.lower() or "seven" in sys_prompt.lower()
            assert "belief" in sys_prompt.lower()


class TestAttackTree:
    """SP3-TREE-01 through SP3-TREE-14."""

    def test_one_llm_call(self):
        spec = _make_scenario_spec()
        cs = _make_cs()
        tree = {"root": "Induce ICA", "branches": [{"category": "controller_side", "label": "l", "children": []}], "leaves": []}
        client = MockLLMClient()
        client.set_response_for(None, json.dumps(tree))

        with TemporaryDirectory() as tmpdir:
            result, error = generate_attack_tree(client, spec, cs, Path(tmpdir))
            assert error is None
            assert result is not None
            assert client.call_count == 1

    def test_call_logged_with_stage_6(self):
        spec = _make_scenario_spec()
        cs = _make_cs()
        tree = {"root": "r", "branches": [], "leaves": []}
        client = MockLLMClient()
        client.set_response_for(None, json.dumps(tree))

        with TemporaryDirectory() as tmpdir:
            generate_attack_tree(client, spec, cs, Path(tmpdir))
            calls = read_calls_jsonl(Path(tmpdir))
            assert len(calls) == 1
            assert calls[0]["stage"] == "stage_6"
            assert calls[0]["step"] == "attack_tree"

    def test_result_is_dict_with_keys(self):
        spec = _make_scenario_spec()
        cs = _make_cs()
        tree = {"root": "Induce ICA NOT_PROVIDED on CA-1-1", "branches": [{"category": "controller_side", "label": "l", "children": []}], "leaves": ["leaf1"]}
        client = MockLLMClient()
        client.set_response_for(None, json.dumps(tree))

        with TemporaryDirectory() as tmpdir:
            result, _ = generate_attack_tree(client, spec, cs, Path(tmpdir))
            assert isinstance(result, dict)
            assert "root" in result
            assert "branches" in result
            assert "leaves" in result

    def test_system_prompt_contains_branch_categories(self):
        spec = _make_scenario_spec()
        cs = _make_cs()
        client = MockLLMClient()
        client.set_response_for(None, json.dumps({"root": "r", "branches": [], "leaves": []}))

        with TemporaryDirectory() as tmpdir:
            generate_attack_tree(client, spec, cs, Path(tmpdir))
            sys_prompt = client.calls[0].system_prompt
            assert "controller_side" in sys_prompt
            assert "path_side" in sys_prompt
            assert "coordination_gap" in sys_prompt

    def test_system_prompt_contains_sub_branches(self):
        spec = _make_scenario_spec()
        cs = _make_cs()
        client = MockLLMClient()
        client.set_response_for(None, json.dumps({"root": "r", "branches": [], "leaves": []}))

        with TemporaryDirectory() as tmpdir:
            generate_attack_tree(client, spec, cs, Path(tmpdir))
            sys_prompt = client.calls[0].system_prompt
            assert "Corrupt process model" in sys_prompt
            assert "Actuator/executor failure" in sys_prompt
            assert "Desynchronize shared PM" in sys_prompt

    def test_system_prompt_contains_pruning_instructions(self):
        spec = _make_scenario_spec()
        cs = _make_cs()
        client = MockLLMClient()
        client.set_response_for(None, json.dumps({"root": "r", "branches": [], "leaves": []}))

        with TemporaryDirectory() as tmpdir:
            generate_attack_tree(client, spec, cs, Path(tmpdir))
            sys_prompt = client.calls[0].system_prompt
            assert "prune" in sys_prompt.lower()

    def test_user_prompt_contains_scenario_spec_and_cs(self):
        spec = _make_scenario_spec()
        cs = _make_cs()
        client = MockLLMClient()
        client.set_response_for(None, json.dumps({"root": "r", "branches": [], "leaves": []}))

        with TemporaryDirectory() as tmpdir:
            generate_attack_tree(client, spec, cs, Path(tmpdir))
            user_prompt = client.calls[0].user_prompt
            assert "SCN-001" in user_prompt
            assert "RESP-1" in user_prompt

    def test_parse_attack_tree_from_dict(self):
        tree = {"root": "r", "branches": [], "leaves": []}
        assert parse_attack_tree(tree) == tree

    def test_parse_attack_tree_from_json_string(self):
        tree = {"root": "r", "branches": [], "leaves": []}
        assert parse_attack_tree(json.dumps(tree)) == tree

    def test_parse_attack_tree_from_yaml_string(self):
        tree = "root: r\nbranches: []\nleaves: []\n"
        result = parse_attack_tree(tree)
        assert result is not None
        assert result["root"] == "r"

    def test_parse_attack_tree_none(self):
        assert parse_attack_tree(None) is None

    def test_parse_attack_tree_from_invalid_string(self):
        """Non-JSON, non-YAML string returns None."""
        assert parse_attack_tree("not valid json or yaml: : :") is None

    def test_parse_attack_tree_from_non_string_non_dict(self):
        """Non-string, non-dict input (e.g. int) returns None."""
        assert parse_attack_tree(42) is None

    def test_parse_attack_tree_json_list_returns_none(self):
        """JSON that parses to a list (not dict) returns None."""
        assert parse_attack_tree("[1, 2, 3]") is None

    def test_parse_attack_tree_yaml_list_returns_none(self):
        """YAML that parses to a list (not dict) returns None."""
        assert parse_attack_tree("- a\n- b\n") is None

    def test_parse_attack_tree_json_in_code_fence(self):
        """JSON wrapped in markdown code fence is parsed correctly."""
        tree = {"root": "r", "branches": [], "leaves": []}
        fenced = f"```json\n{json.dumps(tree)}\n```"
        assert parse_attack_tree(fenced) == tree

    def test_parse_attack_tree_yaml_in_code_fence(self):
        """YAML wrapped in markdown code fence is parsed correctly."""
        fenced = "```yaml\nroot: r\nbranches: []\nleaves: []\n```"
        result = parse_attack_tree(fenced)
        assert result is not None
        assert result["root"] == "r"

    def test_parse_attack_tree_bare_code_fence(self):
        """Content in a bare code fence (no language tag) is parsed."""
        tree = {"root": "r", "branches": [], "leaves": []}
        fenced = f"```\n{json.dumps(tree)}\n```"
        assert parse_attack_tree(fenced) == tree

    def test_parse_attack_tree_fence_with_surrounding_prose(self):
        """Code fence surrounded by explanatory prose is parsed correctly."""
        text = "Here is the attack tree:\n\n```yaml\nroot: r\nbranches: []\nleaves: []\n```\n\nHope this helps!"
        result = parse_attack_tree(text)
        assert result is not None
        assert result["root"] == "r"

    def test_parse_attack_tree_no_fence_unchanged(self):
        """Text without code fences is parsed unchanged."""
        tree = {"root": "r", "branches": [], "leaves": []}
        assert parse_attack_tree(json.dumps(tree)) == tree

    def test_generate_attack_tree_llm_error(self):
        """LLM failure returns (None, error_message)."""
        spec = _make_scenario_spec()
        cs = _make_cs()
        client = MockLLMClient()
        client.set_exception_for(None, RuntimeError("LLM unavailable"))

        with TemporaryDirectory() as tmpdir:
            result, error = generate_attack_tree(client, spec, cs, Path(tmpdir))
            assert result is None
            assert error is not None
            assert "LLM unavailable" in error

    def test_generate_attack_tree_unparseable_response(self):
        """Unparseable LLM response returns (None, error_message)."""
        spec = _make_scenario_spec()
        cs = _make_cs()
        client = MockLLMClient()
        client.set_response_for(None, "this is not json or yaml: : :")

        with TemporaryDirectory() as tmpdir:
            result, error = generate_attack_tree(client, spec, cs, Path(tmpdir))
            assert result is None
            assert error is not None
            assert "Failed to parse" in error


class TestGherkin:
    """SP3-GHK-01 through SP3-GHK-12."""

    _GHERKIN_YAML = (
        "feature: Test\n"
        "scenario: Test\n"
        "given:\n"
        "  - Given PM-1-1 is valid\n"
        "when:\n"
        "  - When x\n"
        "then_expected:\n"
        "  - Then should reject\n"
        "then_actual:\n"
        "  - But approves\n"
    )

    def test_one_llm_call(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, self._GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            result, raw, error = generate_gherkin(client, spec, la, Path(tmpdir))
            assert error is None
            assert result is not None
            assert client.call_count == 1

    def test_generate_gherkin_llm_error(self):
        """LLM failure returns (None, None, error_message)."""
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_exception_for(None, RuntimeError("LLM unavailable"))

        with TemporaryDirectory() as tmpdir:
            result, raw, error = generate_gherkin(client, spec, la, Path(tmpdir))
            assert result is None
            assert raw is None
            assert error is not None
            assert "LLM unavailable" in error

    def test_generate_gherkin_unparseable_response(self):
        """Unparseable LLM response returns (None, raw, error_message)."""
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, ": : not gherkin yaml : :")

        with TemporaryDirectory() as tmpdir:
            result, raw, error = generate_gherkin(client, spec, la, Path(tmpdir))
            assert result is None
            assert raw is not None
            assert error is not None
            assert "Failed to parse" in error

    def test_call_logged_with_stage_6(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, self._GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            generate_gherkin(client, spec, la, Path(tmpdir))
            calls = read_calls_jsonl(Path(tmpdir))
            assert len(calls) == 1
            assert calls[0]["stage"] == "stage_6"
            assert calls[0]["step"] == "gherkin"

    def test_result_is_gherkin_spec(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, self._GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            result, _, _ = generate_gherkin(client, spec, la, Path(tmpdir))
            assert isinstance(result, GherkinSpec)
            assert result.feature == "Test"

    def test_system_prompt_contains_should_but_structure(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, self._GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            generate_gherkin(client, spec, la, Path(tmpdir))
            sys_prompt = client.calls[0].system_prompt
            assert "should" in sys_prompt.lower()
            assert "but" in sys_prompt.lower()

    def test_user_prompt_contains_security_constraint(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, self._GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            generate_gherkin(client, spec, la, Path(tmpdir))
            user_prompt = client.calls[0].user_prompt
            assert "SC-1" in user_prompt
            assert "validate" in user_prompt.lower()

    def test_user_prompt_contains_ica_type(self):
        spec = _make_scenario_spec()
        la = _make_loss_analysis()
        client = MockLLMClient()
        client.set_response_for(None, self._GHERKIN_YAML)

        with TemporaryDirectory() as tmpdir:
            generate_gherkin(client, spec, la, Path(tmpdir))
            user_prompt = client.calls[0].user_prompt
            assert "NOT_PROVIDED" in user_prompt
            assert "CA-1-1" in user_prompt


class TestAssembly:
    """Tests for ScenarioEnvelope assembly."""

    def test_assemble_envelope(self):
        spec = _make_scenario_spec()
        narrative = "A narrative text."
        attack_tree = {"root": "r", "branches": [{"category": "controller_side", "label": "l", "children": []}], "leaves": []}
        gherkin_spec = GherkinSpec(
            feature="Test",
            scenario="Test",
            given=["Given PM-1-1 is valid"],
            when=["When x"],
            then_expected=["Then should reject"],
            then_actual=["But approves"],
        )
        gherkin_raw = "feature: Test\nscenario: Test\n"

        envelope = assemble_envelope(
            "SCN-001", spec, narrative, attack_tree, gherkin_spec, gherkin_raw,
        )
        assert envelope.scenario_id == "SCN-001"
        assert envelope.scenario_spec.scenario_id == "SCN-001"
        assert envelope.narrative == narrative
        assert envelope.attack_tree == attack_tree
        assert envelope.gherkin_spec == gherkin_spec
        assert envelope.gherkin_raw == gherkin_raw
        assert envelope.target_responsibility == "RESP-1"
        assert envelope.ica_type == UCAType.not_provided
        assert envelope.provenance == "structural"


class TestScenarioArtifactWriting:
    """JPKW-07 artifact rendering contracts."""

    def test_structured_gherkin_wins_over_conflicting_raw_text(self):
        spec = _make_scenario_spec()
        gherkin_spec = GherkinSpec(
            feature="Safe orchestration",
            scenario="SCN-001",
            given=["Given PM-1-1 is active"],
            when=["When a revoked user requests access"],
            then_expected=["Then the system should reject the request"],
            then_actual=["But the system approves the request"],
        )
        envelope = assemble_envelope(
            "SCN-001",
            spec,
            "Narrative",
            {"root": "r"},
            gherkin_spec,
            "Feature: Legacy raw text\nScenario: LEGACY-001\n",
        )

        with TemporaryDirectory() as tmpdir:
            _write_scenario_artifacts(envelope, Path(tmpdir))

            feature_text = (Path(tmpdir) / "SCN-001.feature").read_text(
                encoding="utf-8"
            )

        assert feature_text == gherkin_spec.to_feature_text()
        assert "Legacy raw text" not in feature_text

    def test_raw_gherkin_is_used_when_structured_feature_is_unavailable(self):
        spec = _make_scenario_spec()
        unavailable = GherkinSpec(
            feature="",
            scenario="",
            given=[],
            when=[],
            then_expected=[],
            then_actual=[],
        )
        raw = "Feature: Legacy compatibility\nScenario: LEGACY-001\n"
        envelope = assemble_envelope(
            "SCN-001",
            spec,
            "Narrative",
            {"root": "r"},
            unavailable,
            raw,
        )

        with TemporaryDirectory() as tmpdir:
            _write_scenario_artifacts(envelope, Path(tmpdir))

            feature_text = (Path(tmpdir) / "SCN-001.feature").read_text(
                encoding="utf-8"
            )

        assert feature_text == raw
