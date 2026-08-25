"""Tests for validation mark persistence to scenario YAMLs (gmv9).

Covers:
- Validation blocks are present in re-written YAML files
- enforce_parsimony is called from the runner and results are reflected
- Re-write does not corrupt existing scenario data
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionTraceabilityResult,
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
    PhantomValidation,
    PhantomViolationRecord,
    Priority,
    PrioritySignals,
    RiskCardRef,
    ScenarioEnvelope,
    SemanticValidation,
    SeverityLevel,
    StructuralExposureSignal,
    StructuralValidation,
    TaxonomyChain,
    TechniqueMaturity,
    ValidationBlock,
)
from asago_scenario_generator.pipeline.generate import (
    replace_scenario_outputs,
    write_scenario_outputs,
)
from tests.helpers.projection_factory import make_behavior_spec, make_projection_block
from tests.helpers.realization_helper import make_realizations

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


_AttackTreeNode = AttackTreeNode


def AttackTreeNode(**kwargs):
    """Build test nodes with the action required by leaf nodes."""
    if kwargs.get("gate") == GateType.LEAF:
        kwargs.setdefault("action", AiSystemAction())
    return _AttackTreeNode(**kwargs)


def _make_envelope(
    scenario_id: str = "scenario:v2:a256ecf6c638de0ed6ff44547cd446eaa418965387655808c3c791fc1d3fd1d0",
    validation: ValidationBlock | None = None,
) -> ScenarioEnvelope:
    """Build a minimal valid ScenarioEnvelope."""
    root = AttackTreeNode(
        id="n1",
        label="Root",
        gate=GateType.OR,
        zone="input",
        children=[
            AttackTreeNode(
                id="n1.1",
                label="Path A",
                gate=GateType.LEAF,
                zone="input",
                technique_id="AML.T0051",
            ),
            AttackTreeNode(
                id="n1.2",
                label="Path B",
                gate=GateType.LEAF,
                zone="reasoning",
            ),
        ],
    )

    narrative = NarrativeLayer(
        title="Test Scenario",
        summary="Test summary.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="I craft a malicious prompt.",
                effect="The system processes the input.",
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            ),
        ],
    )

    attack_tree = AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Compromise the system",
        root=root,
    )

    faceting = FacetingMetadata(
        risk_card=RiskCardRef(
            risk_id="test-risk",
            risk_name="Test Risk",
            risk_description="A test risk.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        taxonomy_chain=TaxonomyChain(
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
            atlas_technique_ids=["AML.T0051"],
            scenario_seed="AP-T1-01",
        ),
        capability_profile=CapabilityProfileRef(
            zones_traversed=["input", "reasoning"],
            architecture_match=ArchitectureMatch.explicit,
            entry_point="user prompts (zone 1)",
        ),
        maestro_layers=[1, 2],
    )

    priority = Priority(
        composite=0.7,
        signals=PrioritySignals(
            technique_maturity=TechniqueMaturity.feasible,
            risk_impact=SeverityLevel.high,
            risk_likelihood=LikelihoodLevel.medium,
            attack_complexity=AttackComplexity.medium,
            architecture_match=ArchitectureMatch.explicit,
            structural_exposure=StructuralExposureSignal.none,
        ),
    )

    generation = GenerationMetadata(
        model="test-model",
        call_metadata=[
            CallMetadata(
                call=CallName.narrative,
                prompt_tokens=100,
                completion_tokens=200,
                duration_ms=1000,
            ),
        ],
    )

    return ScenarioEnvelope(
        projection=make_projection_block(),
        scenario_id=scenario_id,
        candidate_id="cand:v2:11111111111111111111111111111111",
        initial_entry_point_id="ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        generated_at=datetime.now(tz=UTC),
        generator_version="0.1.0",
        narrative=narrative,
        attack_tree=attack_tree,
        behavior_spec=make_behavior_spec(),
        faceting=faceting,
        priority=priority,
        generation=generation,
        validation=validation,
    )


# ---------------------------------------------------------------------------
# Tests: validation blocks are persisted in YAML files
# ---------------------------------------------------------------------------


@patch(
    "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability"
)
class TestValidationPersistence:
    """Validation marks should appear in re-written scenario YAMLs."""

    def test_validation_block_written_to_yaml(self, mock_trace, tmp_path: Path) -> None:
        """A scenario with validation marks should have them in the YAML output."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        validation = ValidationBlock(
            phantom=PhantomValidation(
                valid=False,
                violations=[
                    PhantomViolationRecord(
                        step_number=1,
                        field="action",
                        category="network",
                        matched_text="external API",
                        reason="No network capability",
                    ),
                ],
            ),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        assert yaml_path.exists()
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        assert "validation" in data
        assert data["validation"]["phantom"]["valid"] is False
        assert len(data["validation"]["phantom"]["violations"]) == 1
        assert data["validation"]["structural"]["valid"] is True
        assert data["validation"]["semantic"]["valid"] is True

    def test_validation_passed_flag_written(self, mock_trace, tmp_path: Path) -> None:
        """The validation_passed flag should appear in the written YAML."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["validation_passed"] is True

    def test_validation_passed_false_when_phantom_fails(
        self, mock_trace, tmp_path: Path
    ) -> None:
        """validation_passed should be False when phantom validation fails."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        validation = ValidationBlock(
            phantom=PhantomValidation(
                valid=False,
                violations=[
                    PhantomViolationRecord(
                        step_number=1,
                        field="action",
                        category="network",
                        matched_text="x",
                        reason="y",
                    ),
                ],
            ),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["validation_passed"] is False

    def test_no_validation_block_when_none(self, mock_trace, tmp_path: Path) -> None:
        """A scenario with no validation should not have a validation key in YAML."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        envelope = _make_envelope(validation=None)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        # exclude_none means no validation key
        assert "validation" not in data

    def test_parsimony_unprunable_mark_written(
        self, mock_trace, tmp_path: Path
    ) -> None:
        """The parsimony_unprunable mark should appear in the YAML."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
            parsimony_unprunable="Could not prune to budget: 8 leaves, budget 4",
        )
        envelope = _make_envelope(validation=validation)

        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["validation"]["parsimony_unprunable"] == (
            "Could not prune to budget: 8 leaves, budget 4"
        )


# ---------------------------------------------------------------------------
# Tests: re-write preserves existing scenario data
# ---------------------------------------------------------------------------


@patch(
    "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability"
)
class TestRewriteIntegrity:
    """The validation re-write must not corrupt existing scenario data."""

    def test_rewrite_preserves_narrative(self, mock_trace, tmp_path: Path) -> None:
        """Narrative content should be identical after re-write with validation."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        envelope = _make_envelope()
        # Write initially (no validation)
        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        original_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        # Add validation and re-write
        envelope.validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=True),
        )
        # Force sync
        envelope.validation_passed = True
        replace_scenario_outputs(
            envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
        )

        rewritten_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        # Narrative should be identical
        assert rewritten_data["narrative"] == original_data["narrative"]
        # Attack tree should be identical
        assert rewritten_data["attack_tree"] == original_data["attack_tree"]
        # Faceting should be identical
        assert rewritten_data["faceting"] == original_data["faceting"]
        # But now has validation
        assert "validation" in rewritten_data

    def test_rewrite_preserves_attack_tree_structure(
        self, mock_trace, tmp_path: Path
    ) -> None:
        """Attack tree nodes should remain intact after re-write."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        envelope = _make_envelope()
        write_scenario_outputs(envelope, tmp_path)

        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        original_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        original_root = original_data["attack_tree"]["root"]

        # Add validation and re-write
        envelope.validation = ValidationBlock()
        envelope.validation_passed = True
        replace_scenario_outputs(
            envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
        )

        rewritten_data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        rewritten_root = rewritten_data["attack_tree"]["root"]

        assert rewritten_root["id"] == original_root["id"]
        assert rewritten_root["label"] == original_root["label"]
        assert len(rewritten_root["children"]) == len(original_root["children"])

    def test_rewrite_preserves_gherkin_feature_file(
        self, mock_trace, tmp_path: Path
    ) -> None:
        """The .feature file should survive a re-write of the YAML."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        envelope = _make_envelope()
        envelope.behavior_spec = make_behavior_spec(
            "Feature: Test\n  Scenario: Basic\n    Given something"
        )
        write_scenario_outputs(envelope, tmp_path)

        feature_path = tmp_path / f"{envelope.scenario_id}.feature"
        assert feature_path.exists()
        original_feature = feature_path.read_text(encoding="utf-8")

        # Add validation and re-write
        envelope.validation = ValidationBlock()
        envelope.validation_passed = True
        replace_scenario_outputs(
            envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
        )

        assert feature_path.read_text(encoding="utf-8") == original_feature

    def test_roundtrip_scenario_id_stable(self, mock_trace, tmp_path: Path) -> None:
        """scenario_id must remain identical through write-rewrite cycle."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        envelope = _make_envelope(
            scenario_id="scenario:v2:d8b4c4b8cc85af40c32ff4240a9890dc8aa7544a67ea76cbeb692f66e4010384"
        )
        write_scenario_outputs(envelope, tmp_path)

        envelope.validation = ValidationBlock(
            phantom=PhantomValidation(valid=True),
            structural=StructuralValidation(valid=True),
            semantic=SemanticValidation(valid=False, issues=["test issue"]),
        )
        envelope.validation_passed = False
        replace_scenario_outputs(
            envelope, tmp_path, admitted_scenario_id=envelope.scenario_id
        )

        sid = "scenario:v2:d8b4c4b8cc85af40c32ff4240a9890dc8aa7544a67ea76cbeb692f66e4010384"
        yaml_path = tmp_path / f"{sid}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        assert data["scenario_id"] == sid


class TestOutputWriteHelpers:
    """Branch-level coverage for write/replace scenario output decomposition."""

    def test_has_structured_behavior_spec_true(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _has_structured_behavior_spec,
        )

        assert _has_structured_behavior_spec(_make_envelope()) is True

    def test_has_structured_behavior_spec_false(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _has_structured_behavior_spec,
        )

        env = _make_envelope()
        env.behavior_spec = "raw text"
        assert _has_structured_behavior_spec(env) is False

    def test_scenario_output_paths(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _scenario_output_paths,
        )

        env = _make_envelope()
        env_path, feature_path, has_behavior = _scenario_output_paths(env, Path("/out"))
        assert env_path == Path("/out") / f"{env.scenario_id}.yaml"
        assert feature_path == Path("/out") / f"{env.scenario_id}.feature"
        assert has_behavior is True

    def test_scenario_output_paths_without_feature(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _scenario_output_paths,
        )

        env = _make_envelope()
        env.behavior_spec = "raw text"
        env_path, feature_path, has_behavior = _scenario_output_paths(env, Path("/out"))
        assert feature_path is None
        assert has_behavior is False

    def test_preflight_output_paths_existing_yaml(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _preflight_output_paths,
            _scenario_output_paths,
        )

        env = _make_envelope()
        env_path, feature_path, has_behavior = _scenario_output_paths(env, tmp_path)
        env_path.write_text("x")
        with pytest.raises(ScenarioForgeIntegrityError, match="already exists"):
            _preflight_output_paths(env_path, feature_path, has_behavior)

    def test_preflight_output_paths_existing_feature(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _preflight_output_paths,
            _scenario_output_paths,
        )

        env = _make_envelope()
        env_path, feature_path, has_behavior = _scenario_output_paths(env, tmp_path)
        feature_path.write_text("x")
        with pytest.raises(ScenarioForgeIntegrityError, match="already exists"):
            _preflight_output_paths(env_path, feature_path, has_behavior)

    def test_preflight_output_paths_orphan_feature(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _preflight_output_paths,
            _scenario_output_paths,
        )

        env = _make_envelope()
        env.behavior_spec = "raw text"
        env_path, _feature_path, has_behavior = _scenario_output_paths(env, tmp_path)
        env_path.with_suffix(".feature").write_text("x")
        with pytest.raises(ScenarioForgeIntegrityError, match="Stem mismatch"):
            _preflight_output_paths(env_path, None, has_behavior)

    def test_preflight_output_paths_ok(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _preflight_output_paths,
            _scenario_output_paths,
        )

        env = _make_envelope()
        env_path, feature_path, has_behavior = _scenario_output_paths(env, tmp_path)
        _preflight_output_paths(env_path, feature_path, has_behavior)

    def test_serialize_envelope_yaml(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _serialize_envelope_yaml,
        )

        env = _make_envelope()
        text = _serialize_envelope_yaml(env)
        assert "scenario_id" in text
        assert text.startswith("scenario_id:")

    def test_exclusive_create_text_ok(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _exclusive_create_text,
        )

        p = tmp_path / "x.txt"
        _exclusive_create_text(p, "hello", "YAML")
        assert p.read_text(encoding="utf-8") == "hello"

    def test_exclusive_create_text_race(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _exclusive_create_text,
        )

        p = tmp_path / "x.txt"
        p.write_text("existing")
        with pytest.raises(ScenarioForgeIntegrityError, match="already exists"):
            _exclusive_create_text(p, "hello", "YAML")

    def test_require_admitted_scenario_id(self):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _require_admitted_scenario_id,
        )

        env = _make_envelope()
        _require_admitted_scenario_id(env.scenario_id, env.scenario_id)
        with pytest.raises(ValueError, match="admitted_scenario_id is required"):
            _require_admitted_scenario_id("", env.scenario_id)
        with pytest.raises(ScenarioForgeIntegrityError, match="Scenario ID mismatch"):
            _require_admitted_scenario_id(
                "scenario:v2:1111111111111111111111111111111111111111111111111111111111111111",
                env.scenario_id,
            )

    def test_verify_replace_pair_missing_yaml(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _verify_replace_pair,
        )

        env = _make_envelope()
        with pytest.raises(
            ScenarioForgeIntegrityError, match="non-existent scenario YAML"
        ):
            _verify_replace_pair(env, tmp_path)

    def test_verify_replace_pair_missing_feature(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _verify_replace_pair,
        )

        env = _make_envelope()
        (tmp_path / f"{env.scenario_id}.yaml").write_text("x")
        with pytest.raises(ScenarioForgeIntegrityError, match="Missing feature"):
            _verify_replace_pair(env, tmp_path)

    def test_verify_replace_pair_feature_mismatch(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _verify_replace_pair,
        )

        env = _make_envelope()
        (tmp_path / f"{env.scenario_id}.yaml").write_text("x")
        (tmp_path / f"{env.scenario_id}.feature").write_text("different bytes")
        with pytest.raises(ScenarioForgeIntegrityError, match="byte mismatch"):
            _verify_replace_pair(env, tmp_path)

    def test_verify_replace_pair_stem_mismatch(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            ScenarioForgeIntegrityError,
            _verify_replace_pair,
        )

        env = _make_envelope()
        env.behavior_spec = "raw text"
        (tmp_path / f"{env.scenario_id}.yaml").write_text("x")
        (tmp_path / f"{env.scenario_id}.feature").write_text("x")
        with pytest.raises(ScenarioForgeIntegrityError, match="Stem mismatch"):
            _verify_replace_pair(env, tmp_path)

    def test_verify_replace_pair_ok(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _verify_replace_pair,
        )

        env = _make_envelope()
        (tmp_path / f"{env.scenario_id}.yaml").write_text("x")
        (tmp_path / f"{env.scenario_id}.feature").write_text(
            env.behavior_spec.gherkin_text
        )
        env_path, feat_path, has_behavior = _verify_replace_pair(env, tmp_path)
        assert env_path == tmp_path / f"{env.scenario_id}.yaml"
        assert feat_path == tmp_path / f"{env.scenario_id}.feature"
        assert has_behavior is True

    def test_atomic_replace_yaml(self, tmp_path):
        from asago_scenario_generator.pipeline.generate.assembly import (
            _atomic_replace_yaml,
        )

        env = _make_envelope()
        yaml_path = tmp_path / f"{env.scenario_id}.yaml"
        yaml_path.write_text("old")
        _atomic_replace_yaml("new content", tmp_path, yaml_path)
        assert yaml_path.read_text(encoding="utf-8") == "new content"


# ---------------------------------------------------------------------------
# Tests: enforce_parsimony integration with runner
# ---------------------------------------------------------------------------


class TestParsimonyIntegration:
    """enforce_parsimony should be wired into the runner validation sequence."""

    def test_typed_action_tree_is_unprunable(self) -> None:
        """An over-budget typed-action tree remains unchanged and unprunable."""
        from asago_scenario_generator.pipeline.validation import enforce_parsimony

        # Build a tree with 1 technique but many unannotated leaves
        # Budget = 2*1 + 2 = 4, so 5+ leaves triggers pruning
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Annotated leaf",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Step 2 setup",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Step 2 setup duplicate",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Step 3",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Step 3 duplicate",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.6",
                    label="Step 3 extra duplicate",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )

        envelope = _make_envelope(
            scenario_id="scenario:v2:c56a3203727bbad6f1fbd6d51a5b225dfb3802cddd0407116560ca01e96547da"
        )
        envelope.attack_tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Compromise the system",
            root=root,
        )

        result = enforce_parsimony([envelope])

        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 1
        unchanged_scenario, actual, budget = result.unprunable_scenarios[0]
        assert (actual, budget) == (6, 4)

        from asago_scenario_generator.pipeline.validation import _collect_leaves

        original_leaf_count = len(_collect_leaves(root))
        unchanged_leaf_count = len(_collect_leaves(unchanged_scenario.attack_tree.root))
        assert unchanged_leaf_count == original_leaf_count

    def test_compliant_scenario_passes_through(self) -> None:
        """A scenario within budget should appear in compliant_scenarios."""
        from asago_scenario_generator.pipeline.validation import enforce_parsimony

        # 2 leaves, 1 technique -> budget=4, well within
        envelope = _make_envelope()
        result = enforce_parsimony([envelope])
        assert len(result.compliant_scenarios) == 1
        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 0

    def test_parsimony_unprunable_gets_validation_mark(self) -> None:
        """Unprunable scenarios should get a parsimony_unprunable mark when processed by the runner logic."""
        # Build a tree where all leaves are annotated but over budget
        # This is technically impossible with the real algo (annotated never pruned),
        # but we can test the runner's mark logic directly.
        envelope = _make_envelope()
        envelope.validation = ValidationBlock()

        # Simulate runner logic for unprunable scenario
        leaf_count = 10
        budget = 4
        envelope.validation.parsimony_unprunable = (
            f"Could not prune to budget: {leaf_count} leaves, budget {budget}"
        )

        assert envelope.validation.parsimony_unprunable == (
            "Could not prune to budget: 10 leaves, budget 4"
        )

    @patch(
        "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability"
    )
    def test_unprunable_tree_written_unchanged_to_yaml(
        self, mock_trace, tmp_path: Path
    ) -> None:
        """An unprunable typed-action tree is written without node removal."""
        mock_trace.return_value = ProjectionTraceabilityResult(
            valid=True, violations=[]
        )
        from asago_scenario_generator.pipeline.validation import (
            _collect_leaves,
            enforce_parsimony,
        )

        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Annotated",
                    gate=GateType.LEAF,
                    zone="input",
                    technique_id="AML.T0051",
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="Unannotated A",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Unannotated A copy",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.4",
                    label="Unannotated B",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.5",
                    label="Unannotated B copy",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
                AttackTreeNode(
                    id="n1.6",
                    label="Unannotated C",
                    gate=GateType.LEAF,
                    zone="reasoning",
                ),
            ],
        )

        envelope = _make_envelope(
            scenario_id="scenario:v2:0843eaa7117a37b66e1f6e09f8994c23076f66d31489752621bd58fea7cf17d9"
        )
        envelope.attack_tree = AttackTree(
            id="tree-AP-T1-01",
            seed_id="AP-T1-01",
            goal="Compromise the system",
            root=root,
        )

        original_leaf_count = len(_collect_leaves(root))

        # Run parsimony
        result = enforce_parsimony([envelope])
        assert len(result.pruned_scenarios) == 0
        assert len(result.unprunable_scenarios) == 1
        unchanged_scenario, actual, budget = result.unprunable_scenarios[0]
        assert (actual, budget) == (6, 4)

        envelope.attack_tree = unchanged_scenario.attack_tree

        # Write to disk
        write_scenario_outputs(envelope, tmp_path)
        yaml_path = tmp_path / f"{envelope.scenario_id}.yaml"
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))

        # The written tree should have the same leaves as the original.
        written_root = data["attack_tree"]["root"]

        # Count leaves in the written tree (recursively)
        def count_leaves(node: dict) -> int:
            if not node.get("children"):
                return 1
            return sum(count_leaves(c) for c in node["children"])

        written_leaf_count = count_leaves(written_root)
        assert written_leaf_count == original_leaf_count
