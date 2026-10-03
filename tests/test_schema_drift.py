"""Drift detection test for the hand-maintained JSON Schema.

Compares key structural elements from ScenarioEnvelope.model_json_schema()
against the hand-maintained schema at
src/asago_scenario_generator/data/schemas/scenario-envelope.schema.json
to flag divergences when the Pydantic model changes.

This test does NOT require exact equality -- the hand-maintained schema
may add constraints that Pydantic cannot express (e.g. conditional
gate/children rules). Instead, it checks that:

1. All required fields in the Pydantic schema are required in the JSON Schema.
2. All top-level property names in the Pydantic schema appear in the JSON Schema.
3. All $defs (model names) in the Pydantic schema appear in the JSON Schema.
4. Persisted EntryPoint structure exactly matches the generated nested definition.
"""

from __future__ import annotations

import json
from datetime import UTC
from pathlib import Path

import pytest

from asago_scenario_generator.models.scenario import ScenarioEnvelope
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block

_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1]
    / "src"
    / "asago_scenario_generator"
    / "data"
    / "schemas"
    / "scenario-envelope.schema.json"
)


@pytest.fixture
def pydantic_schema() -> dict:
    """Generate the JSON Schema from the Pydantic model."""
    return ScenarioEnvelope.model_json_schema()


@pytest.fixture
def hand_schema() -> dict:
    """Load the hand-maintained JSON Schema."""
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


class TestSchemaDrift:
    """Drift detection between Pydantic model and hand-maintained schema."""

    def test_required_fields_present(self, pydantic_schema, hand_schema):
        """All fields that Pydantic marks as required appear in the hand schema's required list."""
        pydantic_required = set(pydantic_schema.get("required", []))
        hand_required = set(hand_schema.get("required", []))

        missing = pydantic_required - hand_required
        assert not missing, (
            f"Fields required in Pydantic model but missing from hand schema's required list: {missing}. "
            f"Update scenario-envelope.schema.json to include them."
        )

    def test_top_level_properties_present(self, pydantic_schema, hand_schema):
        """All top-level properties in the Pydantic schema appear in the hand schema."""
        pydantic_props = set(pydantic_schema.get("properties", {}).keys())
        hand_props = set(hand_schema.get("properties", {}).keys())

        missing = pydantic_props - hand_props
        assert not missing, (
            f"Properties in Pydantic model but missing from hand schema: {missing}. "
            f"Update scenario-envelope.schema.json to include them."
        )

    def test_defs_present(self, pydantic_schema, hand_schema):
        """All object-type $defs in the Pydantic schema appear in the hand schema.

        Note: Pydantic generates enum types as separate $defs, but the hand
        schema deliberately inlines them as ``enum`` arrays on their parent
        properties.  We only check object-type defs (actual sub-models),
        not enum defs.
        """
        pydantic_all_defs = pydantic_schema.get("$defs", {})
        hand_defs = set(hand_schema.get("$defs", {}).keys())

        # Filter to only object-type defs (models with properties).
        pydantic_object_defs = {
            name
            for name, defn in pydantic_all_defs.items()
            if defn.get("type") == "object" or "properties" in defn
        }

        missing = pydantic_object_defs - hand_defs
        assert not missing, (
            f"Sub-models in Pydantic schema but missing from hand schema $defs: {missing}. "
            f"Update scenario-envelope.schema.json to include them."
        )

    def test_persisted_entry_point_definition_has_exact_model_parity(
        self, pydantic_schema, hand_schema
    ):
        """Persisted capability snapshots must retain typed ingress semantics."""
        assert (
            hand_schema["$defs"]["EntryPoint"] == pydantic_schema["$defs"]["EntryPoint"]
        )

    def test_hand_schema_is_valid_json_schema(self, hand_schema):
        """The hand-maintained schema is a syntactically valid JSON Schema."""
        import jsonschema

        # Validate the meta-schema of the hand schema itself.
        # Draft 2020-12 is used by the hand schema.
        validator_cls = jsonschema.Draft202012Validator
        validator_cls.check_schema(hand_schema)

    def test_pydantic_model_validates_against_hand_schema(self, hand_schema):
        """A Pydantic-serialized envelope validates against the hand schema."""
        from datetime import datetime

        from asago_scenario_generator.models.attack_tree import (
            AiSystemAction,
            AttackTree,
            AttackTreeNode,
            GateType,
        )
        from asago_scenario_generator.models.scenario import (
            ArchitectureMatch,
            AttackComplexity,
            CallMetadata,
            CallName,
            CapabilityProfileRef,
            FacetingMetadata,
            GenerationMetadata,
            LikelihoodLevel,
            NarrativeLayer,
            NarrativeStep,
            Priority,
            PrioritySignals,
            ProjectedStepRealization,
            RiskCardRef,
            SeverityLevel,
            StructuralExposureSignal,
            TaxonomyChain,
            TechniqueMaturity,
        )

        envelope = ScenarioEnvelope(
            projection=make_projection_block(),
            scenario_id="scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0",
            candidate_id="cand:v2:11111111111111111111111111111111",
            initial_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            generated_at=datetime.now(tz=UTC),
            generator_version="0.1.0",
            narrative=NarrativeLayer(
                title="Test",
                summary="Summary",
                entry_point="user prompts",
                zone_sequence=["input"],
                steps=[
                    NarrativeStep(
                        step_number=1,
                        zone="input",
                        action="Test action",
                        effect="Test effect",
                        projected_step_ids=("step.1",),
                        realizations=(
                            ProjectedStepRealization(
                                projected_step_id="step.1",
                                action_kind="prepare",
                                executor_role="attacker",
                                boundary_position="crossing",
                                resource_ref_ids=(),
                                consumed_ref_ids=(),
                                produced_ref_ids=(),
                                produced_effect_ids=(),
                                outcome_link_pc_ids=(),
                                postcondition_ids=(),
                            ),
                        ),
                    )
                ],
            ),
            attack_tree=AttackTree(
                id="tree-AP-T1-01",
                seed_id="AP-T1-01",
                goal="Test goal",
                root=AttackTreeNode(
                    id="n1",
                    label="Root",
                    gate=GateType.OR,
                    zone="input",
                    children=[
                        AttackTreeNode(
                            id="n1.1",
                            label="A",
                            gate=GateType.LEAF,
                            zone="input",
                            action=AiSystemAction(),
                        ),
                        AttackTreeNode(
                            id="n1.2",
                            label="B",
                            gate=GateType.LEAF,
                            zone="input",
                            action=AiSystemAction(),
                        ),
                    ],
                ),
            ),
            behavior_spec=make_behavior_spec("Feature: Test"),
            faceting=FacetingMetadata(
                risk_card=RiskCardRef(
                    risk_id="r1",
                    risk_name="Risk",
                    risk_description="Desc",
                    taxonomy="ibm-risk-atlas",
                    confidence=0.9,
                    grounding_confidence="high",
                ),
                taxonomy_chain=TaxonomyChain(
                    owasp_llm_ids=["LLM01"],
                    agentic_threat_ids=["T1"],
                    scenario_seed="AP-T1-01",
                ),
                capability_profile=CapabilityProfileRef(
                    zones_traversed=["input"],
                    architecture_match=ArchitectureMatch.explicit,
                    entry_point="user prompts",
                ),
                maestro_layers=[1],
            ),
            priority=Priority(
                composite=0.5,
                signals=PrioritySignals(
                    technique_maturity=TechniqueMaturity.feasible,
                    risk_impact=SeverityLevel.medium,
                    risk_likelihood=LikelihoodLevel.medium,
                    attack_complexity=AttackComplexity.medium,
                    architecture_match=ArchitectureMatch.explicit,
                    structural_exposure=StructuralExposureSignal.none,
                ),
            ),
            generation=GenerationMetadata(
                model="test-model",
                call_metadata=[
                    CallMetadata(
                        call=CallName.narrative,
                        prompt_tokens=100,
                        completion_tokens=200,
                        duration_ms=1000,
                    )
                ],
            ),
        )

        import jsonschema

        envelope_dict = envelope.model_dump(mode="json")
        jsonschema.validate(envelope_dict, hand_schema)


_YAML_SCHEMA_PATH = (
    Path(__file__).resolve().parents[1] / "data" / "schemas" / "scenario-envelope.yaml"
)


def _yaml_required_fields(section: str, sub: str | None = None) -> set[str]:
    """Extract required field names from a YAML schema section."""
    import yaml

    doc = yaml.safe_load(_YAML_SCHEMA_PATH.read_text(encoding="utf-8"))
    fields = doc["fields"]
    section_def = fields[section]
    if sub is not None:
        section_def = section_def["fields"][sub]
    sub_fields = section_def.get("fields", {})
    return {
        name for name, spec in sub_fields.items() if spec.get("required", False) is True
    }


def _json_schema_required(defs: dict, def_name: str) -> set[str]:
    """Extract required field names from a JSON Schema $def."""
    defn = defs.get(def_name, {})
    return set(defn.get("required", []))


class TestNestedRequirednessParity:
    """Nested required-field parity across Pydantic JSON, hand JSON, and YAML.

    Ensures that requiredness of projection-traceability fields on
    NarrativeStep, BehaviorAction, BehaviorAssertion, and BehaviorSpec
    is consistent across all three schema representations.
    """

    def test_narrative_step_required_parity(self, pydantic_schema, hand_schema):
        """NarrativeStep projection fields are required in all schemas.

        ``projected_step_ids`` is required everywhere.
        ``realizations`` has a default (derived in post-processing) so it
        is NOT required in any schema — parity is that all three agree.
        """
        pyd_req = _json_schema_required(
            pydantic_schema.get("$defs", {}), "NarrativeStep"
        )
        hand_req = _json_schema_required(hand_schema.get("$defs", {}), "NarrativeStep")
        yaml_req = _yaml_required_fields("NarrativeStep")

        # projected_step_ids must be required everywhere.
        for field in ("projected_step_ids",):
            assert field in pyd_req, (
                f"NarrativeStep.{field} must be required in Pydantic schema, "
                f"got required={sorted(pyd_req)}"
            )
            assert field in hand_req, (
                f"NarrativeStep.{field} must be required in hand JSON schema, "
                f"got required={sorted(hand_req)}"
            )
            assert field in yaml_req, (
                f"NarrativeStep.{field} must be required in YAML schema, "
                f"got required={sorted(yaml_req)}"
            )

        # realizations has a default (post-processing derived) — NOT required.
        assert "realizations" not in pyd_req, (
            "NarrativeStep.realizations must NOT be required in Pydantic "
            "(has default=())"
        )
        assert "realizations" not in hand_req, (
            "NarrativeStep.realizations must NOT be required in hand JSON (has default)"
        )
        assert "realizations" not in yaml_req, (
            "NarrativeStep.realizations must NOT be required in YAML (has default)"
        )

    def test_narrative_step_no_empty_default_projected_step_ids(self):
        """YAML schema must not give projected_step_ids an empty default."""
        import yaml

        doc = yaml.safe_load(_YAML_SCHEMA_PATH.read_text(encoding="utf-8"))
        psids = doc["fields"]["NarrativeStep"]["fields"]["projected_step_ids"]
        assert "default" not in psids or psids["default"] != [], (
            "projected_step_ids must not have an empty-list default in YAML schema"
        )
        assert psids.get("required") is True, (
            "projected_step_ids must be required in YAML schema"
        )

    def test_behavior_action_required_parity(self, pydantic_schema, hand_schema):
        """BehaviorAction required fields match exactly across all schemas."""
        pyd_req = _json_schema_required(
            pydantic_schema.get("$defs", {}), "BehaviorAction"
        )
        hand_req = _json_schema_required(hand_schema.get("$defs", {}), "BehaviorAction")
        yaml_req = _yaml_required_fields("BehaviorAction")
        assert pyd_req == hand_req == yaml_req, (
            f"BehaviorAction required fields differ: "
            f"pydantic={sorted(pyd_req)}, hand={sorted(hand_req)}, "
            f"yaml={sorted(yaml_req)}"
        )

    def test_behavior_assertion_required_parity(self, pydantic_schema, hand_schema):
        """BehaviorAssertion required fields match exactly across all schemas.

        gherkin_keyword has default="Then" so it's not required in any
        schema; the other fields must be required everywhere.
        """
        pyd_req = _json_schema_required(
            pydantic_schema.get("$defs", {}), "BehaviorAssertion"
        )
        hand_req = _json_schema_required(
            hand_schema.get("$defs", {}), "BehaviorAssertion"
        )
        yaml_req = _yaml_required_fields("BehaviorAssertion")
        assert pyd_req == hand_req == yaml_req, (
            f"BehaviorAssertion required fields differ: "
            f"pydantic={sorted(pyd_req)}, hand={sorted(hand_req)}, "
            f"yaml={sorted(yaml_req)}"
        )

    def test_behavior_spec_required_parity(self, pydantic_schema, hand_schema):
        """BehaviorSpec top-level fields match exactly across all schemas."""
        pyd_req = _json_schema_required(
            pydantic_schema.get("$defs", {}), "BehaviorSpec"
        )
        hand_req = _json_schema_required(hand_schema.get("$defs", {}), "BehaviorSpec")
        yaml_req = _yaml_required_fields("BehaviorSpec")
        assert pyd_req == hand_req == yaml_req, (
            f"BehaviorSpec required fields differ: "
            f"pydantic={sorted(pyd_req)}, hand={sorted(hand_req)}, "
            f"yaml={sorted(yaml_req)}"
        )

    def test_projection_required_at_top_level(self, pydantic_schema, hand_schema):
        """projection is required at the top level in all schemas."""
        pyd_req = set(pydantic_schema.get("required", []))
        hand_req = set(hand_schema.get("required", []))
        assert "projection" in pyd_req, "projection must be required in Pydantic schema"
        assert "projection" in hand_req, (
            "projection must be required in hand JSON schema"
        )

    def test_projected_step_realization_required_parity(
        self, pydantic_schema, hand_schema
    ):
        """ProjectedStepRealization all 10 fields required in all schemas."""
        pyd_req = _json_schema_required(
            pydantic_schema.get("$defs", {}), "ProjectedStepRealization"
        )
        hand_req = _json_schema_required(
            hand_schema.get("$defs", {}), "ProjectedStepRealization"
        )
        yaml_req = _yaml_required_fields("ProjectedStepRealization")
        all_fields = {
            "projected_step_id",
            "action_kind",
            "executor_role",
            "boundary_position",
            "resource_ref_ids",
            "consumed_ref_ids",
            "produced_ref_ids",
            "produced_effect_ids",
            "outcome_link_pc_ids",
            "postcondition_ids",
        }
        for field in all_fields:
            assert field in pyd_req, (
                f"ProjectedStepRealization.{field} must be required in Pydantic, "
                f"got {sorted(pyd_req)}"
            )
            assert field in hand_req, (
                f"ProjectedStepRealization.{field} must be required in hand JSON, "
                f"got {sorted(hand_req)}"
            )
            assert field in yaml_req, (
                f"ProjectedStepRealization.{field} must be required in YAML, "
                f"got {sorted(yaml_req)}"
            )

    def test_attack_tree_node_required_parity(self, pydantic_schema, hand_schema):
        """AttackTreeNode required fields match exactly across all schemas.

        projected_step_ids and realizations are NOT required in any schema
        (Pydantic/JSON default to empty; requiredness is enforced
        conditionally by semantic validation, not by the schema).
        """
        pyd_req = _json_schema_required(
            pydantic_schema.get("$defs", {}), "AttackTreeNode"
        )
        hand_req = _json_schema_required(hand_schema.get("$defs", {}), "AttackTreeNode")
        yaml_req = _yaml_required_fields("AttackTreeNode")
        assert pyd_req == hand_req == yaml_req, (
            f"AttackTreeNode required fields differ: "
            f"pydantic={sorted(pyd_req)}, hand={sorted(hand_req)}, "
            f"yaml={sorted(yaml_req)}"
        )

    def test_behavior_action_realizations_required_parity(
        self, pydantic_schema, hand_schema
    ):
        """BehaviorAction.realizations is required in all schemas."""
        pyd_req = _json_schema_required(
            pydantic_schema.get("$defs", {}), "BehaviorAction"
        )
        hand_req = _json_schema_required(hand_schema.get("$defs", {}), "BehaviorAction")
        yaml_req = _yaml_required_fields("BehaviorAction")
        assert "realizations" in pyd_req, (
            f"BehaviorAction.realizations must be required in Pydantic, "
            f"got {sorted(pyd_req)}"
        )
        assert "realizations" in hand_req, (
            f"BehaviorAction.realizations must be required in hand JSON, "
            f"got {sorted(hand_req)}"
        )
        assert "realizations" in yaml_req, (
            f"BehaviorAction.realizations must be required in YAML, "
            f"got {sorted(yaml_req)}"
        )

    def test_yaml_attack_tree_not_opaque(self):
        """YAML attack_tree must have structured fields, not be opaque."""
        yaml_req = _yaml_required_fields("attack_tree")
        assert "id" in yaml_req, "attack_tree.id must be required in YAML"
        assert "root" in yaml_req, "attack_tree.root must be required in YAML"

    def test_yaml_behavior_spec_not_opaque(self):
        """YAML behavior_spec must have structured fields, not be opaque."""
        yaml_req = _yaml_required_fields("BehaviorSpec")
        assert "actions" in yaml_req, "BehaviorSpec.actions must be required in YAML"
        assert "assertions" in yaml_req, (
            "BehaviorSpec.assertions must be required in YAML"
        )
        assert "gherkin_text" in yaml_req, (
            "BehaviorSpec.gherkin_text must be required in YAML"
        )
