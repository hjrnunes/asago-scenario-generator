"""Acceptance tests for the cmps.9 typed-action contract."""

from unittest.mock import patch

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    ExternalPreconditionAction,
    GateType,
    ImpactAction,
    InitialIngressAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import (
    AuthMethod,
    CapabilityProfile,
    ConfidenceLevel,
    DataSensitivity,
    EntryPoint,
    ExternalIntegration,
    IntegrationType,
    InventoryCompleteness,
    Stage1Profile,
    ToolInventoryEntry,
    compute_integration_id,
    compute_tool_id,
    deduplicate_external_integrations,
    deduplicate_tool_inventory,
)
from asago_scenario_generator.pipeline.generate.gherkin import (
    _STEP_KIND_GIVEN,
    _STEP_KIND_THEN,
    _STEP_KIND_WHEN,
    _build_gherkin_template,
    _leaf_step_kind,
)
from asago_scenario_generator.pipeline.generate.tree import (
    _enumerate_root_to_leaf_paths,
    _validate_pinned_ingress,
    resolve_action_ids,
)
from asago_scenario_generator.report.template import _build_attack_tree_node
from tests.helpers.realization_helper import make_realizations

TOOL_ID = compute_tool_id("test_tool", "A test tool")
UNKNOWN_TOOL_ID = "tool:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
UNKNOWN_ENTRY_POINT_ID = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
UNKNOWN_INTEGRATION_ID = "int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"


def leaf(action, zone, *, label="Step", node_id="n1"):
    return AttackTreeNode(
        id=node_id, label=label, gate=GateType.LEAF, zone=zone, action=action
    )


def tree(node):
    return AttackTree(id="tree-AP-T1-01", seed_id="AP-T1-01", goal="Test", root=node)


def integration(name="Test CRM"):
    return ExternalIntegration(
        name=name,
        integration_type=IntegrationType.api,
        auth_method=AuthMethod.oauth,
        data_sensitivity=DataSensitivity.high,
    )


def profile():
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[EntryPoint(name="User chat", direction="input")],
        confidence="high",
        kc_subcodes=["KC1.1", "KC6.1.1"],
        tool_inventory=[
            ToolInventoryEntry(name="test_tool", description="A test tool")
        ],
        external_integrations=[integration()],
    )


def stage1(**extra):
    return Stage1Profile(
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        entry_points=[EntryPoint(name="User chat", direction="input")],
        confidence="high",
        kc_subcodes=["KC1.1"],
        **extra,
    )


class TestActionConditionalValidation:
    @pytest.mark.parametrize(
        ("action", "zone"),
        [
            (ExternalPreconditionAction(), None),
            (AiSystemAction(), "input"),
            (ToolInvocationAction(tool_id=TOOL_ID), "tool_execution"),
            (ImpactAction(boundary="internal", target="Data"), "input"),
            (ImpactAction(boundary="external", target="Reputation"), None),
            (InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), "input"),
            (
                IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
                "tool_execution",
            ),
        ],
    )
    def test_valid_action_zone_combinations(self, action, zone):
        assert leaf(action, zone).zone == zone

    @pytest.mark.parametrize(
        ("action", "zone"),
        [
            (ExternalPreconditionAction(), "input"),
            (AiSystemAction(), None),
            (ToolInvocationAction(tool_id=TOOL_ID), "input"),
            (ImpactAction(boundary="internal", target="Data"), None),
            (ImpactAction(boundary="external", target="Reputation"), "input"),
            (InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), None),
            (
                IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
                None,
            ),
        ],
    )
    def test_invalid_action_zone_combinations(self, action, zone):
        with pytest.raises(ValidationError):
            leaf(action, zone)

    def test_leaf_requires_action(self):
        with pytest.raises(ValidationError):
            AttackTreeNode(id="n1", label="No action", gate=GateType.LEAF)

    @pytest.mark.parametrize("gate", [GateType.AND, GateType.OR])
    def test_internal_node_forbids_action(self, gate):
        children = [
            leaf(AiSystemAction(), "input", node_id="n1.1"),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        with pytest.raises(ValidationError):
            AttackTreeNode(
                id="n1",
                label="Internal",
                gate=gate,
                action=AiSystemAction(),
                children=children,
            )


class TestTypedLeafSemantics:
    def test_external_precondition_has_no_zone_and_provenance(self):
        node = leaf(ExternalPreconditionAction(access_provenance="phishing"), None)
        assert node.zone is None
        assert node.action.access_provenance == "phishing"

    def test_initial_ingress_accepts_canonical_pattern(self):
        node = leaf(
            InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), "input"
        )
        assert node.action.entry_point_id == UNKNOWN_ENTRY_POINT_ID

    def test_tool_invocation_with_optional_integration(self):
        node = leaf(
            ToolInvocationAction(
                tool_id=TOOL_ID, integration_id=UNKNOWN_INTEGRATION_ID
            ),
            "tool_execution",
        )
        assert node.action.tool_id.startswith("tool:v1:")
        assert node.action.integration_id == UNKNOWN_INTEGRATION_ID

    def test_direct_integration_interaction(self):
        node = leaf(
            IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
            "tool_execution",
        )
        assert node.action.integration_id.startswith("int:v1:")

    def test_internal_and_external_impacts(self):
        internal = leaf(ImpactAction(boundary="internal", target="Model"), "reasoning")
        external = leaf(ImpactAction(boundary="external", target="Customer"), None)
        assert internal.zone == "reasoning"
        assert external.zone is None


class TestActionIdResolution:
    def test_unknown_tool_id_is_violation(self):
        violations = resolve_action_ids(
            tree(leaf(ToolInvocationAction(tool_id=UNKNOWN_TOOL_ID), "tool_execution")),
            profile(),
        )
        assert any("unresolved-tool-id" in violation for violation in violations)

    def test_unknown_entry_point_id_is_violation(self):
        violations = resolve_action_ids(
            tree(
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID), "input"
                )
            ),
            profile(),
        )
        assert any("unresolved-entry-point-id" in violation for violation in violations)

    def test_unknown_integration_id_is_violation(self):
        violations = resolve_action_ids(
            tree(
                leaf(
                    IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
                    "tool_execution",
                )
            ),
            profile(),
        )
        assert any("unresolved-integration-id" in violation for violation in violations)

    def test_all_ids_resolve(self):
        prof = profile()
        children = [
            leaf(
                InitialIngressAction(
                    entry_point_id=prof.entry_points[0].entry_point_id
                ),
                "input",
                node_id="n1.1",
            ),
            leaf(
                ToolInvocationAction(
                    tool_id=prof.tool_inventory[0].tool_id,
                    integration_id=prof.external_integrations[0].integration_id,
                ),
                "tool_execution",
                node_id="n1.2",
            ),
            leaf(
                IntegrationInteractionAction(
                    integration_id=prof.external_integrations[0].integration_id
                ),
                "tool_execution",
                node_id="n1.3",
            ),
        ]
        root = AttackTreeNode(
            id="n1", label="Path", gate=GateType.AND, children=children
        )
        assert resolve_action_ids(tree(root), prof) == []


class TestCanonicalIdentity:
    def test_tools_and_integrations_are_distinct_concepts(self):
        tool = ToolInventoryEntry(name="CRM", description="Customer records")
        integ = integration("CRM")
        assert isinstance(tool, ToolInventoryEntry)
        assert isinstance(integ, ExternalIntegration)
        assert tool.tool_id.startswith("tool:v1:")
        assert integ.integration_id.startswith("int:v1:")

    def test_tool_id_is_stable(self):
        assert compute_tool_id("test_tool", "A test tool") == TOOL_ID

    def test_tool_id_is_stable_under_description_edits(self):
        assert compute_tool_id("test_tool", "Original") == compute_tool_id(
            "test_tool", "Updated"
        )

    def test_tool_ids_are_order_independent(self):
        tools = [
            ToolInventoryEntry(name="A", description="first"),
            ToolInventoryEntry(name="B", description="second"),
        ]
        assert {item.tool_id for item in tools} == {
            item.tool_id for item in reversed(tools)
        }

    def test_tool_deduplication(self):
        tools = [
            ToolInventoryEntry(name="Test Tool", description="Does work"),
            ToolInventoryEntry(name="Test Tool", description="Does work"),
        ]
        assert len(deduplicate_tool_inventory(tools)) == 1

    def test_tool_duplicate_with_conflicting_description_is_rejected(self):
        tools = [
            ToolInventoryEntry(name="Test Tool", description="Reads records"),
            ToolInventoryEntry(name="test tool", description="Deletes records"),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate tool"):
            deduplicate_tool_inventory(tools)

    def test_tool_duplicate_empty_nonempty_description_rejected(self):
        """Empty/non-empty description mismatch must be rejected, not silently deduplicated."""
        tools = [
            ToolInventoryEntry(name="Test Tool", description=""),
            ToolInventoryEntry(name="test tool", description="Reads records"),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_tool_inventory(tools)

    def test_tool_dedup_reversed_order_identical_outcome(self):
        """Reversed order of exact duplicates produces identical complete
        ``model_dump(mode='json')`` output (no information loss).

        Raw metadata differences (e.g. ``Search`` vs ``search``) are now
        rejected — only exact raw duplicates deduplicate (cmps.9 third
        review correction 3).
        """
        tools_a = [
            ToolInventoryEntry(name="Search", description="Search tool"),
            ToolInventoryEntry(name="Search", description="Search tool"),
        ]
        tools_b = list(reversed(tools_a))
        result_a = deduplicate_tool_inventory(tools_a)
        result_b = deduplicate_tool_inventory(tools_b)
        assert len(result_a) == 1
        assert len(result_b) == 1
        # Complete JSON dumps must be identical regardless of input order.
        assert result_a[0].model_dump(mode="json") == result_b[0].model_dump(
            mode="json"
        )

    def test_tool_dedup_raw_name_difference_rejected(self):
        """Raw name differences (same canonical name) are rejected to
        ensure deterministic serialization (cmps.9 third review correction 3)."""
        tools = [
            ToolInventoryEntry(name="Search", description="Search tool"),
            ToolInventoryEntry(name="search", description="Search tool"),
        ]
        with pytest.raises(ValueError, match="raw names differ"):
            deduplicate_tool_inventory(tools)

    def test_tool_dedup_raw_description_difference_rejected(self):
        """Raw description differences (same canonical description) are
        rejected to ensure deterministic serialization (cmps.9 third
        review correction 3)."""
        tools = [
            ToolInventoryEntry(name="Search", description="Search tool"),
            ToolInventoryEntry(name="Search", description="search tool"),
        ]
        with pytest.raises(ValueError, match="raw descriptions differ"):
            deduplicate_tool_inventory(tools)

    def test_tool_dedup_empty_nonempty_reversed_order_rejected(self):
        """Reversed order of empty/non-empty mismatch still rejects."""
        tools = [
            ToolInventoryEntry(name="Test Tool", description="Reads records"),
            ToolInventoryEntry(name="test tool", description=""),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_tool_inventory(tools)

    def test_tool_collision_guard(self):
        with patch(
            "asago_scenario_generator.models.capability_profile.compute_tool_id",
            return_value=UNKNOWN_TOOL_ID,
        ):
            tools = [
                ToolInventoryEntry(name="A", description="first"),
                ToolInventoryEntry(name="B", description="second"),
            ]
            with pytest.raises(ValueError, match="Ambiguous tool identity"):
                deduplicate_tool_inventory(tools)

    def test_integration_id_is_stable_and_order_independent(self):
        args = ("CRM", "api", "oauth", "high")
        assert compute_integration_id(*args) == compute_integration_id(*args)
        integrations = [integration("A"), integration("B")]
        assert {item.integration_id for item in integrations} == {
            item.integration_id for item in reversed(integrations)
        }

    def test_integration_id_is_stable_under_metadata_edits(self):
        assert compute_integration_id(
            "CRM", "api", "oauth", "high"
        ) == compute_integration_id("CRM", "api", "api_key", "low")

    def test_integration_deduplication(self):
        assert (
            len(deduplicate_external_integrations([integration(), integration()])) == 1
        )

    def test_integration_duplicate_with_conflicting_metadata_is_rejected(self):
        integrations = [
            integration("CRM"),
            ExternalIntegration(
                name="crm",
                integration_type=IntegrationType.api,
                auth_method=AuthMethod.api_key,
                data_sensitivity=DataSensitivity.low,
            ),
        ]
        with pytest.raises(
            ValueError, match="Ambiguous semantic duplicate integration"
        ):
            deduplicate_external_integrations(integrations)

    def test_integration_collision_guard(self):
        with patch(
            "asago_scenario_generator.models.capability_profile.compute_integration_id",
            return_value=UNKNOWN_INTEGRATION_ID,
        ):
            integrations = [integration("A"), integration("B")]
            with pytest.raises(ValueError, match="Ambiguous integration identity"):
                deduplicate_external_integrations(integrations)


class TestInventoryCompleteness:
    def test_default_is_inferred_partial(self):
        p = profile()
        assert p.entry_point_completeness == InventoryCompleteness.inferred_partial
        assert p.tool_inventory_completeness == InventoryCompleteness.inferred_partial

    def test_stage1_conversion_forces_inferred_partial(self):
        p = stage1().to_capability_profile()
        assert p.entry_point_completeness == InventoryCompleteness.inferred_partial
        assert p.tool_inventory_completeness == InventoryCompleteness.inferred_partial

    def test_operator_confirmed_complete_requires_evidence(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        confirmed = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["manual architecture review"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API documentation audit"],
        )
        assert confirmed.is_inventory_complete
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
                entry_point_evidence=[],
                tool_inventory_completeness=InventoryCompleteness.inferred_partial,
            )
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.inferred_partial,
                tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
                tool_inventory_evidence=[],
            )

    def test_stage1_cannot_self_promote(self):
        inferred = stage1(
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["LLM claim"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["LLM claim"],
        ).to_capability_profile()
        assert (
            inferred.entry_point_completeness == InventoryCompleteness.inferred_partial
        )
        assert inferred.entry_point_evidence == []
        assert (
            inferred.tool_inventory_completeness
            == InventoryCompleteness.inferred_partial
        )
        assert inferred.tool_inventory_evidence == []


class TestGherkinProjection:
    @pytest.mark.parametrize(
        ("action", "zone", "label", "expected"),
        [
            (ExternalPreconditionAction(), None, "Execute tool", _STEP_KIND_GIVEN),
            (
                ImpactAction(boundary="internal", target="Data"),
                "input",
                "Inject prompt",
                _STEP_KIND_THEN,
            ),
            (AiSystemAction(), "input", "Given precondition", _STEP_KIND_WHEN),
            (
                ToolInvocationAction(tool_id=TOOL_ID),
                "tool_execution",
                "Then system",
                _STEP_KIND_WHEN,
            ),
        ],
    )
    def test_step_kind_ignores_misleading_label(self, action, zone, label, expected):
        assert _leaf_step_kind(leaf(action, zone, label=label)) == expected

    def test_adversarial_tool_label_does_not_change_semantics(self):
        node = leaf(
            ToolInvocationAction(tool_id=TOOL_ID),
            "tool_execution",
            label="Given the system processes input",
        )
        assert node.zone == "tool_execution"
        assert node.action.kind == "tool_invocation"

    def test_adversarial_external_label_does_not_change_semantics(self):
        node = leaf(
            ExternalPreconditionAction(), None, label="Execute query_database tool"
        )
        assert node.zone is None
        assert node.action.kind == "external_precondition"


class TestReportResolution:
    def test_report_resolves_tool_id_to_name(self):
        prof = profile()
        node = leaf(
            ToolInvocationAction(tool_id=prof.tool_inventory[0].tool_id),
            "tool_execution",
        )
        html = _build_attack_tree_node(node.model_dump(), prof.model_dump())
        assert "Tool: test_tool" in html

    @pytest.mark.parametrize(
        "node",
        [
            leaf(ExternalPreconditionAction(), None),
            leaf(ImpactAction(boundary="external", target="Reputation"), None),
        ],
    )
    def test_report_shows_external_boundary(self, node):
        assert ">External<" in _build_attack_tree_node(node.model_dump())


# ---------------------------------------------------------------------------
# Raw Draft 2020-12 JSON Schema adversarial tests (independent correction 1)
# ---------------------------------------------------------------------------


class TestRawJsonSchemaAdversarial:
    """Raw Draft 2020-12 validation of the hand-authored schema."""

    @staticmethod
    def _node_validator():
        """Build a Draft 2020-12 validator for the AttackTreeNode sub-schema."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        # Build a standalone schema that includes $defs so $ref resolves.
        node_schema = {
            **full_schema["$defs"]["AttackTreeNode"],
            "$defs": full_schema["$defs"],
        }
        return jsonschema.Draft202012Validator(node_schema)

    _SENTINEL = object()

    def _make_leaf_node(self, action=_SENTINEL, **overrides):
        node = {
            "id": "n1",
            "label": "Test",
            "gate": "LEAF",
            "zone": "input",
        }
        if action is not self._SENTINEL:
            node["action"] = action
        elif "action" not in overrides:
            node["action"] = {"kind": "ai_system_action"}
        # Map node_id= to id= for convenience
        if "node_id" in overrides:
            overrides["id"] = overrides.pop("node_id")
        node.update(overrides)
        return node

    def _make_tree(self, root_node):
        return {
            "id": "tree-AP-T1-01",
            "seed_id": "AP-T1-01",
            "goal": "Test",
            "root": root_node,
        }

    def test_leaf_with_null_action_rejected(self):
        """LEAF node with action:null must be rejected."""
        node = self._make_leaf_node(action=None)
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "action" in str(e.path) or "action" in str(e.message) for e in errors
        )

    def test_leaf_with_omitted_action_rejected(self):
        """LEAF node without action field must be rejected."""
        node = {"id": "n1", "label": "Test", "gate": "LEAF", "zone": "input"}
        errors = list(self._node_validator().iter_errors(node))
        assert any("action" in str(e.message) for e in errors)

    def test_leaf_with_omitted_kind_rejected(self):
        """Action object without kind field must be rejected."""
        node = self._make_leaf_node(action={"tool_id": "tool:v1:abc"})
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "kind" in str(e.message)
            or any("kind" in str(ctx.message) for ctx in (e.context or []))
            for e in errors
        )

    def test_foreign_resource_field_rejected(self):
        """Action with a foreign field (e.g. tool_id on ai_system_action) must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "ai_system_action", "tool_id": "tool:v1:abc"}
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "additional" in str(e.message).lower()
            or any(
                "additional" in str(ctx.message).lower() for ctx in (e.context or [])
            )
            for e in errors
        )

    def test_internal_node_with_action_payload_rejected(self):
        """AND/OR node with a non-null action must be rejected."""
        node = {
            "id": "n1",
            "label": "Internal",
            "gate": "AND",
            "children": [
                self._make_leaf_node(node_id="n1.1"),
                self._make_leaf_node(node_id="n1.2"),
            ],
            "action": {"kind": "ai_system_action"},
        }
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "action" in str(e.path)
            or "action" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_internal_node_with_insufficient_children_rejected(self):
        """AND/OR node with fewer than 2 children must be rejected."""
        node = {
            "id": "n1",
            "label": "Internal",
            "gate": "OR",
            "action": None,
            "children": [self._make_leaf_node(node_id="n1.1")],
        }
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "children" in str(e.path)
            or "children" in str(e.message)
            or "minItems" in str(e.message)
            for e in errors
        )

    def test_external_precondition_with_zone_rejected(self):
        """external_precondition with a non-null zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "external_precondition"},
            zone="input",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_tool_invocation_with_wrong_zone_rejected(self):
        """tool_invocation with zone other than tool_execution must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "tool_invocation", "tool_id": "tool:v1:abc"},
            zone="input",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_integration_interaction_in_tool_execution_accepted(self):
        """integration_interaction in tool_execution must be accepted (independent correction 6)."""
        node = self._make_leaf_node(
            action={
                "kind": "integration_interaction",
                "integration_id": "int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            zone="tool_execution",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert not errors, f"Expected no errors but got: {[str(e) for e in errors]}"

    def test_integration_interaction_without_zone_rejected(self):
        """integration_interaction with zone:null must be rejected."""
        node = self._make_leaf_node(
            action={
                "kind": "integration_interaction",
                "integration_id": "int:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            },
            zone=None,
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_internal_impact_without_zone_rejected(self):
        """internal impact without zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "impact", "boundary": "internal", "target": "Data"},
            zone=None,
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_external_impact_with_zone_rejected(self):
        """external impact with a zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "impact", "boundary": "external", "target": "Reputation"},
            zone="input",
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )

    def test_initial_ingress_without_zone_rejected(self):
        """initial_ingress without zone must be rejected."""
        node = self._make_leaf_node(
            action={"kind": "initial_ingress", "entry_point_id": "ep:v1:abc"},
            zone=None,
        )
        errors = list(self._node_validator().iter_errors(node))
        assert any(
            "zone" in str(e.path)
            or "zone" in str(e.message)
            or "null" in str(e.message)
            for e in errors
        )


# ---------------------------------------------------------------------------
# Per-path pinned ingress validation (independent correction 3)
# ---------------------------------------------------------------------------


class TestPerPathIngressValidation:
    """Every root-to-leaf path must contain an initial_ingress leaf."""

    def test_and_tree_single_path_has_ingress(self):
        """AND tree with ingress in one leaf — single merged path has it."""
        children = [
            leaf(
                InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                "input",
                node_id="n1.1",
            ),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.AND, children=children
        )
        t = tree(root)
        assert _validate_pinned_ingress(t, None) == []

    def test_or_tree_one_path_missing_ingress(self):
        """OR tree where one branch lacks ingress — must be a violation."""
        branch_a = AttackTreeNode(
            id="n1.1",
            label="A",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                    "input",
                    node_id="n1.1.1",
                ),
                leaf(AiSystemAction(), "reasoning", node_id="n1.1.2"),
            ],
        )
        branch_b = AttackTreeNode(
            id="n1.2",
            label="B",
            gate=GateType.AND,
            children=[
                leaf(AiSystemAction(), "reasoning", node_id="n1.2.1"),
                leaf(AiSystemAction(), "input", node_id="n1.2.2"),
            ],
        )
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=[branch_a, branch_b]
        )
        t = tree(root)
        violations = _validate_pinned_ingress(t, None)
        assert any("missing-initial-ingress" in v for v in violations)

    def test_pinned_mismatch_rejected(self):
        """Ingress with a different entry_point_id than pinned must be rejected."""
        ep_id = "ep:v1:cccccccccccccccccccccccccccccccc"
        children = [
            leaf(
                InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                "input",
                node_id="n1.1",
            ),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.AND, children=children
        )
        t = tree(root)
        violations = _validate_pinned_ingress(t, ep_id)
        assert any("pinned-entry-point-mismatch" in v for v in violations)

    def test_all_paths_have_ingress_passes(self):
        """OR tree where both branches have ingress — no violations."""
        branch_a = AttackTreeNode(
            id="n1.1",
            label="A",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                    "input",
                    node_id="n1.1.1",
                ),
                leaf(AiSystemAction(), "reasoning", node_id="n1.1.2"),
            ],
        )
        branch_b = AttackTreeNode(
            id="n1.2",
            label="B",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=UNKNOWN_ENTRY_POINT_ID),
                    "input",
                    node_id="n1.2.1",
                ),
                leaf(AiSystemAction(), "reasoning", node_id="n1.2.2"),
            ],
        )
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=[branch_a, branch_b]
        )
        t = tree(root)
        assert _validate_pinned_ingress(t, None) == []

    def test_path_enumeration_and_merges(self):
        """AND gate merges children into one path."""
        children = [
            leaf(AiSystemAction(), "input", node_id="n1.1"),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.AND, children=children
        )
        paths = _enumerate_root_to_leaf_paths(root)
        assert len(paths) == 1
        assert len(paths[0]) == 2

    def test_path_enumeration_or_branches(self):
        """OR gate creates separate branches."""
        children = [
            leaf(AiSystemAction(), "input", node_id="n1.1"),
            leaf(AiSystemAction(), "reasoning", node_id="n1.2"),
        ]
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=children
        )
        paths = _enumerate_root_to_leaf_paths(root)
        assert len(paths) == 2


# ---------------------------------------------------------------------------
# Evidence nonblank check (independent correction 2)
# ---------------------------------------------------------------------------


class TestEvidenceNonblank:
    """Operator-confirmed complete requires nonblank evidence."""

    def test_whitespace_only_evidence_rejected(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
                entry_point_evidence=["   "],
                tool_inventory_completeness=InventoryCompleteness.inferred_partial,
            )

    def test_whitespace_only_tool_evidence_rejected(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        with pytest.raises(ValidationError):
            CapabilityProfile(
                **data,
                entry_point_completeness=InventoryCompleteness.inferred_partial,
                tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
                tool_inventory_evidence=["\t", "  "],
            )

    def test_nonblank_evidence_accepted(self):
        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        confirmed = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["  manual review  "],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API audit"],
        )
        assert confirmed.is_inventory_complete


# ---------------------------------------------------------------------------
# Closed-world corpus claim applicability (independent correction 2)
# ---------------------------------------------------------------------------


class TestCorpusClaimApplicability:
    """Closed-world claims must be typed and category-specific (cmps.9 review 2)."""

    def test_partial_inventory_marks_not_applicable(self):
        from asago_scenario_generator.models.scenario import (
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from asago_scenario_generator.pipeline.validation import check_corpus_claims_applicability

        prof = profile()
        result = check_corpus_claims_applicability(None, prof)
        # Must produce two typed records, one per category
        assert len(result) == 2
        cats = {r.category for r in result}
        assert cats == {
            CorpusClaimCategory.entry_points,
            CorpusClaimCategory.tool_inventory,
        }
        # Both must be not_applicable under inferred_partial
        for r in result:
            assert r.status == CorpusClaimStatus.not_applicable
            assert r.reason is not None and r.reason.strip()

    def test_complete_inventory_marks_applicable(self):
        from asago_scenario_generator.models.scenario import (
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from asago_scenario_generator.pipeline.validation import check_corpus_claims_applicability

        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        prof = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["manual review"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API audit"],
        )
        result = check_corpus_claims_applicability(None, prof)
        assert len(result) == 2
        cats = {r.category for r in result}
        assert cats == {
            CorpusClaimCategory.entry_points,
            CorpusClaimCategory.tool_inventory,
        }
        # Both must be applicable under operator_confirmed_complete
        for r in result:
            assert r.status == CorpusClaimStatus.applicable
        # Evidence is carried for applicable records
        ep_rec = next(
            r for r in result if r.category == CorpusClaimCategory.entry_points
        )
        assert "manual review" in ep_rec.evidence
        tool_rec = next(
            r for r in result if r.category == CorpusClaimCategory.tool_inventory
        )
        assert "API audit" in tool_rec.evidence

    def test_corpus_claim_extra_fields_forbidden(self):
        """CorpusClaimApplicability must forbid extra fields."""
        from asago_scenario_generator.models.scenario import CorpusClaimApplicability

        with pytest.raises(ValidationError):
            CorpusClaimApplicability(
                category="entry_points",
                status="not_applicable",
                foreign_field="bad",
            )

    def test_corpus_claim_serialization_roundtrip(self):
        """Typed records serialize and round-trip correctly."""
        from asago_scenario_generator.models.scenario import CorpusClaimApplicability

        rec = CorpusClaimApplicability(
            category="entry_points",
            status="not_applicable",
            reason="Partial inventory",
        )
        dumped = rec.model_dump(mode="json")
        restored = CorpusClaimApplicability(**dumped)
        assert restored.category.value == "entry_points"
        assert restored.status.value == "not_applicable"
        assert restored.reason == "Partial inventory"

    def test_partial_means_structurally_not_applicable(self):
        """Partial inventory record validates against JSON Schema def."""
        import json
        from pathlib import Path

        import jsonschema

        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        schema_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        rec = CorpusClaimApplicability(
            category=CorpusClaimCategory.entry_points,
            status=CorpusClaimStatus.not_applicable,
            reason="inferred_partial",
        )
        dumped = rec.model_dump(mode="json")
        jsonschema.validate(dumped, schema["$defs"]["CorpusClaimApplicability"])

    def test_complete_means_applicable_in_schema(self):
        """Complete inventory record validates against JSON Schema def."""
        import json
        from pathlib import Path

        import jsonschema

        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        schema_path = (
            Path(__file__).resolve().parents[1]
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        schema = json.loads(schema_path.read_text(encoding="utf-8"))

        rec = CorpusClaimApplicability(
            category=CorpusClaimCategory.tool_inventory,
            status=CorpusClaimStatus.applicable,
            evidence=["API audit"],
        )
        dumped = rec.model_dump(mode="json")
        jsonschema.validate(dumped, schema["$defs"]["CorpusClaimApplicability"])

    def test_corpus_claim_independent_of_phantom(self):
        """Corpus claim applicability does not conflate with phantom.valid."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        # A not_applicable corpus claim record can coexist with any
        # phantom validation state — they are independent.
        rec = CorpusClaimApplicability(
            category=CorpusClaimCategory.tool_inventory,
            status=CorpusClaimStatus.not_applicable,
            reason="Tool inventory is inferred_partial.",
        )
        assert rec.status == CorpusClaimStatus.not_applicable
        # The record has no phantom-related field
        assert not hasattr(rec, "valid")


# ---------------------------------------------------------------------------
# Gherkin OR-branch precondition projection (independent correction 5)
# ---------------------------------------------------------------------------


class TestGherkinOrBranchPreconditions:
    """Branch-only preconditions stay in Scenario, not Background."""

    def _make_narrative(self):
        from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep

        return NarrativeLayer(
            title="Test Scenario",
            summary="Test summary",
            entry_point="user chat",
            zone_sequence=["input"],
            steps=[
                NarrativeStep(
                    step_number=1,
                    zone="input",
                    action="Test action",
                    effect="Test effect",
                    projected_step_ids=("step.1",),
                    realizations=make_realizations(
                        ("step.1",),
                        action_kind="prepare",
                        executor_role="attacker",
                        boundary_position="crossing",
                    ),
                )
            ],
        )

    def _make_seed(self):
        from asago_scenario_generator.models.scenario import (
            RiskCardRef,
        )
        from asago_scenario_generator.pipeline.seeds import ScenarioSeed

        return ScenarioSeed(
            seed_id="AP-T1-01",
            threat_id="T1",
            threat_name="Test Threat",
            attack_pattern_name="Test Pattern",
            attack_pattern_description="Test description",
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="Risk",
                risk_description="Desc",
                taxonomy="ibm-risk-atlas",
                confidence=0.9,
                grounding_confidence="high",
            ),
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T1"],
        )

    def test_branch_only_precondition_not_global_background(self):
        """A precondition on only one OR branch must not appear in Background."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        branch_a = AttackTreeNode(
            id="n1.1",
            label="Branch A",
            gate=GateType.AND,
            children=[
                leaf(
                    ExternalPreconditionAction(access_provenance="phishing"),
                    None,
                    label="Phishing setup",
                    node_id="n1.1.1",
                ),
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Ingress",
                    node_id="n1.1.2",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.1.3"),
            ],
        )
        branch_b = AttackTreeNode(
            id="n1.2",
            label="Branch B",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Ingress",
                    node_id="n1.2.1",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.2.2"),
            ],
        )
        root = AttackTreeNode(
            id="n1", label="Root", gate=GateType.OR, children=[branch_a, branch_b]
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        # Background should not contain the branch-only precondition
        bg_section = gherkin.split("Scenario:")[0]
        assert "Phishing setup" not in bg_section
        # But it should appear in the branch Scenario
        assert "Phishing setup" in gherkin

    def test_intersection_precondition_becomes_background(self):
        """A precondition in an AND parent of an OR appears in Background."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        or_branch = AttackTreeNode(
            id="n1.2",
            label="OR Branches",
            gate=GateType.OR,
            children=[
                AttackTreeNode(
                    id="n1.2.1",
                    label="A",
                    gate=GateType.AND,
                    children=[
                        leaf(
                            InitialIngressAction(entry_point_id=ep_id),
                            "input",
                            label="Ingress",
                            node_id="n1.2.1.1",
                        ),
                        leaf(
                            AiSystemAction(),
                            "reasoning",
                            label="Reason",
                            node_id="n1.2.1.2",
                        ),
                    ],
                ),
                AttackTreeNode(
                    id="n1.2.2",
                    label="B",
                    gate=GateType.AND,
                    children=[
                        leaf(
                            InitialIngressAction(entry_point_id=ep_id),
                            "input",
                            label="Ingress",
                            node_id="n1.2.2.1",
                        ),
                        leaf(
                            AiSystemAction(),
                            "reasoning",
                            label="Reason",
                            node_id="n1.2.2.2",
                        ),
                    ],
                ),
            ],
        )
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            children=[
                leaf(
                    ExternalPreconditionAction(access_provenance="recon"),
                    None,
                    label="Recon setup",
                    node_id="n1.1",
                ),
                or_branch,
            ],
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        bg_section = gherkin.split("Scenario:")[0]
        assert "Recon setup" in bg_section

    def test_ingress_step_from_typed_id_not_label(self):
        """Ingress step display name must come from typed entry_point_id, not label."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            children=[
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Misleading label about tools",
                    node_id="n1.1",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.2"),
            ],
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        # The entry point name is "User chat" — must appear, not the misleading label
        assert "User chat" in gherkin
        assert "Misleading label" not in gherkin

    def test_given_when_then_ordering_per_path(self):
        """Given/When/And/Then/But ordering must be action-derived per path."""
        prof = profile()
        ep_id = prof.entry_points[0].entry_point_id
        root = AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            children=[
                leaf(
                    ExternalPreconditionAction(),
                    None,
                    label="External setup",
                    node_id="n1.1",
                ),
                leaf(
                    InitialIngressAction(entry_point_id=ep_id),
                    "input",
                    label="Ingress",
                    node_id="n1.2",
                ),
                leaf(AiSystemAction(), "reasoning", label="Reason", node_id="n1.3"),
                leaf(
                    ImpactAction(boundary="internal", target="Model"),
                    "reasoning",
                    label="Impact",
                    node_id="n1.4",
                ),
            ],
        )
        t = tree(root)
        gherkin = _build_gherkin_template(
            self._make_narrative(), t, prof, self._make_seed(), "scenario:v2:test"
        )
        # Extract the scenario section (after Background)
        scenario_section = (
            gherkin.split("Scenario:")[1] if "Scenario:" in gherkin else gherkin
        )
        # Given must come before When, When before Then
        given_pos = scenario_section.find("Given the system")
        when_pos = scenario_section.find("When ")
        then_pos = scenario_section.find("Then ")
        assert 0 <= given_pos < when_pos < then_pos


# ---------------------------------------------------------------------------
# Integration interaction in tool_execution with adversarial labels (independent correction 6)
# ---------------------------------------------------------------------------


class TestIntegrationInteractionToolExecution:
    """integration_interaction in tool_execution must not be rejected (independent review 6)."""

    def test_integration_in_tool_execution_model_valid(self):
        """Model-level: integration_interaction with tool_execution zone is valid."""
        node = leaf(
            IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
            "tool_execution",
            label="Execute query_database tool via API",
        )
        assert node.zone == "tool_execution"
        assert node.action.kind == "integration_interaction"

    def test_adversarial_label_does_not_change_action_kind(self):
        """A label containing tool keywords must not change the action semantics."""
        node = leaf(
            IntegrationInteractionAction(integration_id=UNKNOWN_INTEGRATION_ID),
            "tool_execution",
            label="Given the system processes input and exfiltrates data",
        )
        assert _leaf_step_kind(node) == _STEP_KIND_WHEN
        assert node.action.kind == "integration_interaction"

    def test_financial_tool_label_does_not_affect_consequence(self):
        """A tool_invocation with financial label must not be treated as consequence."""
        node = leaf(
            ToolInvocationAction(tool_id=TOOL_ID),
            "tool_execution",
            label="refund payment billing transaction",
        )
        from asago_scenario_generator.pipeline.validation import _is_consequence_leaf

        assert not _is_consequence_leaf(node)
        assert _leaf_step_kind(node) == _STEP_KIND_WHEN


# ---------------------------------------------------------------------------
# Report corpus applicability display (independent correction 2/6)
# ---------------------------------------------------------------------------


class TestReportCorpusApplicability:
    """Report must display separate category status and corpus applicability."""

    def test_report_shows_category_completeness(self):
        prof = profile()
        from asago_scenario_generator.report.template import build_capability_profile_section

        html = build_capability_profile_section(prof.model_dump())
        assert "Entry-Point Inventory Completeness" in html
        assert "Tool Inventory Completeness" in html
        assert "Inferred Partial" in html

    def test_report_shows_corpus_applicability(self):
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from asago_scenario_generator.report.template import build_capability_profile_section

        prof = profile()
        claims = [
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.not_applicable,
                reason="inferred_partial",
            ),
            CorpusClaimApplicability(
                category=CorpusClaimCategory.tool_inventory,
                status=CorpusClaimStatus.not_applicable,
                reason="inferred_partial",
            ),
        ]
        html = build_capability_profile_section(
            prof.model_dump(),
            corpus_claims=[c.model_dump(mode="json") for c in claims],
        )
        assert "Corpus Claim Applicability" in html
        assert "not_applicable" in html

    def test_report_shows_applicable_when_complete(self):
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )
        from asago_scenario_generator.report.template import build_capability_profile_section

        data = profile().model_dump(
            exclude={
                "entry_point_completeness",
                "entry_point_evidence",
                "tool_inventory_completeness",
                "tool_inventory_evidence",
            }
        )
        prof = CapabilityProfile(
            **data,
            entry_point_completeness=InventoryCompleteness.operator_confirmed_complete,
            entry_point_evidence=["manual review"],
            tool_inventory_completeness=InventoryCompleteness.operator_confirmed_complete,
            tool_inventory_evidence=["API audit"],
        )
        claims = [
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                evidence=["manual review"],
            ),
            CorpusClaimApplicability(
                category=CorpusClaimCategory.tool_inventory,
                status=CorpusClaimStatus.applicable,
                evidence=["API audit"],
            ),
        ]
        html = build_capability_profile_section(
            prof.model_dump(),
            corpus_claims=[c.model_dump(mode="json") for c in claims],
        )
        assert "Corpus Claim Applicability" in html
        assert "applicable" in html
        assert "not_applicable" not in html


# ---------------------------------------------------------------------------
# ID stability under metadata edits and ambiguous duplicate rejection (independent correction 7)
# ---------------------------------------------------------------------------


class TestIdStabilityAndDuplicateSemantics:
    """IDs must be stable under non-identity edits and reject ambiguous duplicates."""

    def test_tool_id_ignores_description(self):
        """Tool ID is computed from name only — description changes don't affect ID."""
        id1 = compute_tool_id("my_tool", "Original description")
        id2 = compute_tool_id("my_tool", "Completely different description")
        assert id1 == id2

    def test_tool_id_ignores_evidence(self):
        """Tool ID is computed from name only — evidence/provenance doesn't affect ID."""
        id1 = compute_tool_id("my_tool", "desc")
        id2 = compute_tool_id("my_tool", "")
        assert id1 == id2

    def test_integration_id_ignores_auth_and_sensitivity(self):
        """Integration ID is computed from name + type only."""
        id1 = compute_integration_id("CRM", "api", "oauth", "high")
        id2 = compute_integration_id("CRM", "api", "api_key", "low")
        assert id1 == id2

    def test_integration_id_changes_with_type(self):
        """Integration ID changes when type differs (part of identity)."""
        id1 = compute_integration_id("CRM", "api", "oauth", "high")
        id2 = compute_integration_id("CRM", "database", "oauth", "high")
        assert id1 != id2

    def test_tool_id_is_128_bit(self):
        """Tool ID must be at least 128 bits (32 hex chars)."""
        tid = compute_tool_id("test", "desc")
        hex_part = tid.split(":")[-1]
        assert len(hex_part) >= 32

    def test_integration_id_is_128_bit(self):
        """Integration ID must be at least 128 bits (32 hex chars)."""
        iid = compute_integration_id("CRM", "api", "oauth", "high")
        hex_part = iid.split(":")[-1]
        assert len(hex_part) >= 32

    def test_ambiguous_same_name_conflicting_description_rejected(self):
        """Same canonical name with conflicting descriptions must be rejected."""
        tools = [
            ToolInventoryEntry(name="Payment API", description="Reads transactions"),
            ToolInventoryEntry(name="payment api", description="Deletes transactions"),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_tool_inventory(tools)

    def test_ambiguous_integration_conflicting_auth_rejected(self):
        """Same identity integration with conflicting auth must be rejected."""
        integrations = [
            ExternalIntegration(
                name="CRM",
                integration_type=IntegrationType.api,
                auth_method=AuthMethod.oauth,
                data_sensitivity=DataSensitivity.high,
            ),
            ExternalIntegration(
                name="crm",
                integration_type=IntegrationType.api,
                auth_method=AuthMethod.api_key,
                data_sensitivity=DataSensitivity.high,
            ),
        ]
        with pytest.raises(ValueError, match="Ambiguous semantic duplicate"):
            deduplicate_external_integrations(integrations)

    def test_exact_duplicate_deduplication_preserves_provenance(self):
        """Exact raw duplicates deduplicate, preserving the first entry.

        Raw metadata differences (e.g. ``Search`` vs ``search``) are now
        rejected — only exact raw duplicates deduplicate (cmps.9 third
        review correction 3).
        """
        tools = [
            ToolInventoryEntry(name="Search", description="Search tool"),
            ToolInventoryEntry(name="Search", description="Search tool"),
        ]
        result = deduplicate_tool_inventory(tools)
        assert len(result) == 1
        assert result[0].name == "Search"


# ---------------------------------------------------------------------------
# Ingress zone validation — independent correction 3
# ---------------------------------------------------------------------------


class TestIngressZoneValidation:
    """Initial ingress zone must match the entry point's canonical ingress zone."""

    def test_ingress_zone_mismatch_is_violation(self):
        """An initial_ingress leaf with a zone that doesn't match the entry
        point's canonical ingress_zone must produce a violation, not be
        silently repaired."""
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        # Create a tree with an initial_ingress leaf that has the wrong zone
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate="LEAF",
                        zone="reasoning",  # WRONG — should be "input"
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate="LEAF",
                        action=ImpactAction(boundary="internal", target="system"),
                        zone="reasoning",
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert any("ingress-zone-mismatch" in v for v in violations)

    def test_ingress_zone_match_no_violation(self):
        """An initial_ingress leaf with the correct zone produces no violation."""
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate="LEAF",
                        zone="input",  # CORRECT — matches canonical
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate="LEAF",
                        action=ImpactAction(boundary="internal", target="system"),
                        zone="reasoning",
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert not any("ingress-zone-mismatch" in v for v in violations)

    def test_adversarial_label_does_not_affect_ingress_zone(self):
        """A label containing 'reasoning' does not change the canonical ingress zone."""
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="Reasoning manipulation via reasoning zone",  # adversarial label
                        gate="LEAF",
                        zone="input",  # CORRECT — label doesn't change zone
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                    AttackTreeNode(
                        id="n1.3",
                        label="impact",
                        gate="LEAF",
                        action=ImpactAction(boundary="internal", target="system"),
                        zone="reasoning",
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert not any("ingress-zone-mismatch" in v for v in violations)


# ---------------------------------------------------------------------------
# Zone enforcement rejection — independent correction 4
# ---------------------------------------------------------------------------


class TestZoneEnforcementRejection:
    """Zone enforcement must reject invalid zones, not prune/collapse."""

    def test_disallowed_zone_raises_not_prunes(self):
        """A tree with a disallowed zone must raise ValueError, not silently prune."""
        from asago_scenario_generator.pipeline.generate.zones import _enforce_zones_attack_tree

        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="ok",
                    gate="LEAF",
                    zone="input",
                    action=AiSystemAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="bad",
                    gate="LEAF",
                    zone="memory",
                    action=AiSystemAction(),
                ),
            ],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=root,
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_attack_tree(tree, zones_active=["input", "reasoning"])

    def test_no_collapse_on_disallowed_zone(self):
        """The tree must not be collapsed when a zone is disallowed — it must reject."""
        from asago_scenario_generator.pipeline.generate.zones import _enforce_zones_attack_tree

        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="OR",
            zone="input",
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="keep",
                    gate="LEAF",
                    zone="input",
                    action=AiSystemAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="drop",
                    gate="LEAF",
                    zone="memory",
                    action=AiSystemAction(),
                ),
            ],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=root,
        )
        with pytest.raises(ValueError, match="disallowed-zone"):
            _enforce_zones_attack_tree(tree, zones_active=["input"])

    def test_external_precondition_zone_none_not_rejected(self):
        """Zone=None (external precondition) must never be rejected by zone enforcement."""
        from asago_scenario_generator.pipeline.generate.zones import _enforce_zones_attack_tree

        root = AttackTreeNode(
            id="n1",
            label="root",
            gate="AND",
            zone=None,
            action=None,
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="external",
                    gate="LEAF",
                    zone=None,
                    action=ExternalPreconditionAction(),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="internal",
                    gate="LEAF",
                    zone="input",
                    action=AiSystemAction(),
                ),
            ],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=root,
        )
        # Should pass — zone=None is always allowed
        result = _enforce_zones_attack_tree(tree, zones_active=["input"])
        assert result is tree


# ---------------------------------------------------------------------------
# Authored YAML schema alignment — independent correction 1
# ---------------------------------------------------------------------------


class TestAuthoredYamlSchemaZones:
    """Authored YAML schemas must use string zones, not integer zones."""

    def test_attack_tree_yaml_uses_string_zones(self):
        """The attack-tree.yaml schema must define zone as string with named values."""
        import yaml

        with open("data/schemas/attack-tree.yaml") as f:
            doc = yaml.safe_load(f)
        zone_def = doc["schema"]["node"]["properties"]["zone"]
        assert zone_def["type"] == "string", (
            f"attack-tree.yaml zone type should be 'string', got '{zone_def['type']}'"
        )
        assert set(zone_def["enum"]) == {
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        }

    def test_capability_profile_yaml_uses_string_zones(self):
        """The capability-profile.yaml schema must define zones_active as string list."""
        import yaml

        with open("data/schemas/capability-profile.yaml") as f:
            doc = yaml.safe_load(f)
        zones_def = doc["stage_1"]["zones_active"]
        assert "string" in zones_def["type"], (
            f"capability-profile.yaml zones_active type should contain 'string', "
            f"got '{zones_def['type']}'"
        )
        assert set(zones_def["valid_values"]) == {
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        }

    def test_scenario_envelope_yaml_uses_string_zones(self):
        """The scenario-envelope.yaml schema must define zone_sequence as string list."""
        import yaml

        with open("data/schemas/scenario-envelope.yaml") as f:
            doc = yaml.safe_load(f)
        zs_def = doc["fields"]["narrative"]["fields"]["zone_sequence"]
        assert "string" in zs_def["type"], (
            f"scenario-envelope.yaml zone_sequence type should contain 'string', "
            f"got '{zs_def['type']}'"
        )
        step_def = doc["fields"]["NarrativeStep"]
        assert step_def["fields"]["zone"]["type"] == "string"
        assert set(step_def["fields"]["zone"]["enum"]) == {
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        }

    def test_attack_tree_yaml_example_uses_string_zones(self):
        """The attack-tree.yaml example must use string zone values, not integers."""
        import yaml

        with open("data/schemas/attack-tree.yaml") as f:
            doc = yaml.safe_load(f)
        example = doc.get("example", {}).get("attack_tree", {})
        root = example.get("root", {})
        # Check the root zone
        assert root.get("zone") in (
            "input",
            "reasoning",
            "tool_execution",
            "memory",
            "inter_agent",
        ), f"Example root zone should be a string, got '{root.get('zone')}'"


# ---------------------------------------------------------------------------
# Tests: canonical ingress tightening (cmps.9 second review correction 5)
# ---------------------------------------------------------------------------


class TestIngressZoneDeclarations:
    """EntryPoint.ingress_zone must be a valid Schneider zone Literal,
    and output-only entries have contradictory zones removed (cmps.9 review 5)."""

    def test_invalid_ingress_zone_rejected(self):
        """A non-Schneider ingress_zone value is rejected by Pydantic."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        with pytest.raises(ValidationError):
            EntryPoint(
                name="test entry",
                direction="input",
                ingress_zone="invalid_zone",
            )

    def test_output_zone_is_cleared(self):
        """An output-only entry point with an ingress zone is corrected."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        ep = EntryPoint(
            name="dashboard alerts",
            direction="output",
            ingress_zone="input",
        )
        assert ep.ingress_zone is None

    def test_output_only_without_ingress_zone_accepted(self):
        """An output-only entry point without an ingress zone is accepted."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        ep = EntryPoint(
            name="dashboard alerts",
            direction="output",
            ingress_zone=None,
        )
        assert ep.ingress_zone is None

    def test_valid_ingress_zone_accepted(self):
        """A valid Schneider zone for ingress_zone is accepted."""
        from asago_scenario_generator.models.capability_profile import EntryPoint

        for zone in ("input", "reasoning", "tool_execution", "memory", "inter_agent"):
            ep = EntryPoint(
                name=f"entry_{zone}",
                direction="input",
                ingress_zone=zone,
            )
            assert ep.ingress_zone == zone


class TestIngressZoneActiveAdmission:
    """An ingress-capable entry point whose effective canonical ingress zone
    is not active in the profile must be rejected at admission (cmps.9 review 5).
    """

    def test_inactive_ingress_zone_rejected_at_admission(self):
        """An initial_ingress leaf whose canonical ingress zone is not active
        in the profile produces a violation."""
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="tool API gateway",
            direction="input",
            ingress_zone="tool_execution",
        )
        # Profile has tool_execution NOT active
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T2-01",
            seed_id="AP-T2-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress via tool API",
                        gate="LEAF",
                        zone="tool_execution",
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert any("inaccessible-ingress-entry-point" in v for v in violations)

    def test_active_ingress_zone_accepted_at_admission(self):
        """An initial_ingress leaf whose canonical ingress zone is active
        in the profile produces no violation."""
        from asago_scenario_generator.models.capability_profile import EntryPoint
        from asago_scenario_generator.pipeline.generate.tree import _validate_pinned_ingress

        ep = EntryPoint(
            name="user chat",
            direction="input",
            ingress_zone="input",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[ep],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
        )
        tree = AttackTree(
            id="tree-AP-T7-01",
            seed_id="AP-T7-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate="LEAF",
                        zone="input",
                        action=InitialIngressAction(
                            entry_point_id=ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert not any("inaccessible-ingress-entry-point" in v for v in violations)
        assert not any("ingress-zone-mismatch" in v for v in violations)


class TestSystemControllabilityCandidateExclusion:
    """System-controlled entry points must not enter candidate expansion
    (cmps.9 second review correction 5).

    Explicit controllability='system' from a reviewed profile is preserved
    and excluded from the candidate cross-product.  Heuristics only apply
    when controllability is None.
    """

    def test_explicit_system_excluded_from_candidates(self):
        """An explicit system-controlled entry point does not appear in
        expanded candidates."""
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            EntryPoint,
        )
        from asago_scenario_generator.models.scenario import RiskCardRef
        from asago_scenario_generator.pipeline.candidates import (
            ScenarioSeed,
            expand_candidates,
        )

        system_ep = EntryPoint(
            name="internal backend scheduler API",
            direction="input",
            controllability="system",
        )
        direct_ep = EntryPoint(
            name="user chat interface",
            direction="input",
            controllability="direct",
        )
        profile = CapabilityProfile(
            zones_active=["input", "reasoning"],
            entry_points=[system_ep, direct_ep],
            confidence="medium",
            kc_subcodes=["KC1.1"],
        )
        seed = ScenarioSeed(
            seed_id="AP-T2-01",
            threat_id="T2",
            threat_name="Test",
            attack_pattern_name="Test pattern",
            attack_pattern_description="A test",
            atlas_technique_ids=["AML.T0051"],
            owasp_llm_ids=["LLM01"],
            agentic_threat_ids=["T2"],
            risk_card_ref=RiskCardRef(
                risk_id="r1",
                risk_name="Risk",
                risk_description="Desc",
                taxonomy="ibm-risk-atlas",
                confidence=0.9,
                grounding_confidence="high",
            ),
        )
        candidates = expand_candidates([seed], profile)
        # system_ep must NOT appear in any candidate
        ep_names = {c.entry_point for c in candidates}
        assert "internal backend scheduler API" not in ep_names
        # direct_ep should appear
        assert "user chat interface" in ep_names

    def test_explicit_system_preserved_not_downgraded(self):
        """Explicit 'system' controllability is preserved, not downgraded
        to 'indirect' or 'direct' by heuristics."""
        from asago_scenario_generator.models.capability_profile import (
            classify_entry_point,
        )

        # bidirectional + system → system (preserved)
        assert (
            classify_entry_point("backend API", "bidirectional", "system") == "system"
        )
        # input + system → system (preserved)
        assert classify_entry_point("data feed", "input", "system") == "system"
        # output + system → system (preserved)
        assert classify_entry_point("alerts", "output", "system") == "system"

    def test_none_controllability_uses_heuristic(self):
        """When controllability is None, the keyword heuristic applies."""
        from asago_scenario_generator.models.capability_profile import (
            classify_entry_point,
        )

        # system keyword + input + None → system (heuristic)
        assert classify_entry_point("internal backend API", "input", None) == "system"
        # no keyword + input + None → direct (heuristic)
        assert classify_entry_point("user chat", "input", None) == "direct"


# ---------------------------------------------------------------------------
# Third review adversarial tests (cmps.9)
# ---------------------------------------------------------------------------


class TestCorpusApplicabilityCategoryCompleteness:
    """Corpus claim applicability must be category-complete and coherent
    (cmps.9 third review correction 1)."""

    def test_pydantic_missing_category_rejected(self):
        """Missing a required category record is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
            SemanticValidation,
        )

        # min_length=2 catches the too-short list before the model
        # validator; either error is acceptable as long as it is rejected.
        with pytest.raises(Exception, match="missing required category|too_short"):
            SemanticValidation(
                valid=True,
                corpus_claim_applicability=[
                    CorpusClaimApplicability(
                        category=CorpusClaimCategory.entry_points,
                        status=CorpusClaimStatus.not_applicable,
                        reason="Partial.",
                    ),
                ],
            )

    def test_pydantic_duplicate_category_rejected(self):
        """Duplicate category records are rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
            SemanticValidation,
        )

        # max_length=2 catches the too-long list before the model
        # validator; either error is acceptable as long as it is rejected.
        with pytest.raises(Exception, match="duplicate category|too_long"):
            SemanticValidation(
                valid=True,
                corpus_claim_applicability=[
                    CorpusClaimApplicability(
                        category=CorpusClaimCategory.entry_points,
                        status=CorpusClaimStatus.not_applicable,
                        reason="Partial.",
                    ),
                    CorpusClaimApplicability(
                        category=CorpusClaimCategory.tool_inventory,
                        status=CorpusClaimStatus.not_applicable,
                        reason="Partial.",
                    ),
                    CorpusClaimApplicability(
                        category=CorpusClaimCategory.entry_points,
                        status=CorpusClaimStatus.not_applicable,
                        reason="Partial.",
                    ),
                ],
            )

    def test_pydantic_applicable_without_evidence_rejected(self):
        """applicable status without nonblank evidence is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="nonblank evidence"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
            )

    def test_pydantic_not_applicable_without_reason_rejected(self):
        """not_applicable status without a nonblank reason is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="nonblank reason"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.not_applicable,
            )

    def test_pydantic_not_applicable_with_evidence_rejected(self):
        """not_applicable status with evidence is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="must not carry evidence"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.not_applicable,
                reason="Partial inventory.",
                evidence=["some evidence"],
            )

    def test_pydantic_applicable_with_reason_rejected(self):
        """applicable status with a nonblank reason is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="must not carry a reason"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                reason="Some reason.",
                evidence=["evidence"],
            )

    def test_json_schema_null_action_on_leaf_rejected(self):
        """Raw JSON Schema: LEAF without an action is rejected."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        # Build a standalone schema that includes $defs so $ref resolves.
        node_schema = {
            **full_schema["$defs"]["AttackTreeNode"],
            "$defs": full_schema["$defs"],
        }
        validator = jsonschema.Draft202012Validator(node_schema)
        # A LEAF node with no action and no children should be invalid.
        leaf_no_action = {
            "id": "n1",
            "label": "leaf",
            "gate": "LEAF",
            "zone": "reasoning",
        }
        errors = list(validator.iter_errors(leaf_no_action))
        assert errors, "LEAF without action should be rejected by schema"

    def test_json_schema_corpus_claim_min_max_items(self):
        """Raw JSON Schema: corpus_claim_applicability enforces min/max items."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        # Build a standalone schema that includes $defs so $ref resolves.
        sem_schema = {
            **full_schema["$defs"]["SemanticValidation"],
            "$defs": full_schema["$defs"],
        }
        sem_validator = jsonschema.Draft202012Validator(sem_schema)

        # Only one record → should fail (minItems: 2)
        one_record = {
            "valid": True,
            "corpus_claim_applicability": [
                {
                    "category": "entry_points",
                    "status": "not_applicable",
                    "reason": "Partial.",
                }
            ],
        }
        errors = list(sem_validator.iter_errors(one_record))
        assert errors, "One record should fail minItems/minContains"

        # Three records → should fail (maxItems: 2)
        three_records = {
            "valid": True,
            "corpus_claim_applicability": [
                {
                    "category": "entry_points",
                    "status": "not_applicable",
                    "reason": "Partial.",
                },
                {
                    "category": "tool_inventory",
                    "status": "not_applicable",
                    "reason": "Partial.",
                },
                {
                    "category": "entry_points",
                    "status": "not_applicable",
                    "reason": "Partial.",
                },
            ],
        }
        errors = list(sem_validator.iter_errors(three_records))
        assert errors, "Three records should fail maxItems/maxContains"

    def test_report_consistent_multi_scenario_records_succeed(self):
        """Report reconciliation succeeds when all scenarios have consistent records."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        scenario = {
            "validation": {
                "semantic": {
                    "valid": True,
                    "violations": [],
                    "corpus_claim_applicability": [
                        {
                            "category": "entry_points",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                        {
                            "category": "tool_inventory",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                    ],
                }
            }
        }
        result = _reconcile_corpus_claims([scenario, dict(scenario)])
        assert len(result) == 2
        assert result[0]["category"] == "entry_points"
        assert result[1]["category"] == "tool_inventory"

    def test_report_conflicting_multi_scenario_records_fail(self):
        """Report reconciliation fails on conflicting status across scenarios."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        s1 = {
            "validation": {
                "semantic": {
                    "valid": True,
                    "violations": [],
                    "corpus_claim_applicability": [
                        {
                            "category": "entry_points",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                        {
                            "category": "tool_inventory",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                    ],
                }
            }
        }
        s2 = {
            "validation": {
                "semantic": {
                    "valid": True,
                    "violations": [],
                    "corpus_claim_applicability": [
                        {
                            "category": "entry_points",
                            "status": "applicable",
                            "evidence": ["reviewed"],
                        },
                        {
                            "category": "tool_inventory",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                    ],
                }
            }
        }
        with pytest.raises(ValueError, match="conflicts"):
            _reconcile_corpus_claims([s1, s2])

    def test_report_missing_validation_block_fails(self):
        """Report reconciliation fails when a scenario lacks a validation block."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        with pytest.raises(ValueError, match="missing a validation block"):
            _reconcile_corpus_claims([{"scenario_id": "s1"}])

    def test_report_missing_corpus_claims_fails(self):
        """Report reconciliation fails when corpus claims are absent."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        with pytest.raises(ValueError, match="missing corpus_claim_applicability"):
            _reconcile_corpus_claims([{"validation": {"semantic": {"valid": True}}}])

    def test_report_empty_falsy_blocks_fail_with_exact_messages(self):
        """Report reconciliation pins exact messages for falsy-but-typed blocks."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        with pytest.raises(ValueError, match="missing a validation block"):
            _reconcile_corpus_claims([{"scenario_id": "s1", "validation": {}}])
        with pytest.raises(ValueError, match="missing a semantic validation block"):
            _reconcile_corpus_claims(
                [{"scenario_id": "s1", "validation": {"semantic": {}}}]
            )
        with pytest.raises(ValueError, match="missing corpus_claim_applicability"):
            _reconcile_corpus_claims(
                [
                    {
                        "scenario_id": "s1",
                        "validation": {"semantic": {"corpus_claim_applicability": []}},
                    }
                ]
            )

    def test_report_reason_only_conflict_fails(self):
        """Report reconciliation fails when only the reason differs."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        s1 = {
            "validation": {
                "semantic": {
                    "valid": True,
                    "violations": [],
                    "corpus_claim_applicability": [
                        {
                            "category": "entry_points",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                        {
                            "category": "tool_inventory",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                    ],
                }
            }
        }
        s2 = {
            "validation": {
                "semantic": {
                    "valid": True,
                    "violations": [],
                    "corpus_claim_applicability": [
                        {
                            "category": "entry_points",
                            "status": "not_applicable",
                            "reason": "Revised.",
                        },
                        {
                            "category": "tool_inventory",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                    ],
                }
            }
        }
        with pytest.raises(
            ValueError,
            match=r"conflicts between scenario 0 .* and scenario 1 \(",
        ):
            _reconcile_corpus_claims([s1, s2])

    # --- Schema-parity: strict reason/evidence blank semantics ---

    def test_pydantic_applicable_with_empty_string_reason_rejected(self):
        """applicable status with reason='' (not None) is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="must not carry a reason"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                reason="",
                evidence=["evidence"],
            )

    def test_pydantic_applicable_with_whitespace_reason_rejected(self):
        """applicable status with reason='   ' (not None) is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="must not carry a reason"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                reason="   ",
                evidence=["evidence"],
            )

    def test_pydantic_applicable_all_whitespace_evidence_rejected(self):
        """applicable with all-whitespace evidence items is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="blank/whitespace-only evidence"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                evidence=["  ", "\t\n"],
            )

    def test_pydantic_applicable_mixed_blank_nonblank_evidence_rejected(self):
        """applicable with mixed blank and nonblank evidence is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="blank/whitespace-only evidence"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.applicable,
                evidence=["real evidence", "  "],
            )

    def test_pydantic_not_applicable_whitespace_reason_rejected(self):
        """not_applicable with whitespace-only reason is rejected."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        with pytest.raises(Exception, match="nonblank reason"):
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.not_applicable,
                reason="   ",
            )

    def test_pydantic_applicable_valid_with_nonblank_evidence(self):
        """applicable with all-nonblank evidence and reason=None is accepted."""
        from asago_scenario_generator.models.scenario import (
            CorpusClaimApplicability,
            CorpusClaimCategory,
            CorpusClaimStatus,
        )

        record = CorpusClaimApplicability(
            category=CorpusClaimCategory.entry_points,
            status=CorpusClaimStatus.applicable,
            evidence=["operator review", "audit log"],
        )
        assert record.reason is None
        assert len(record.evidence) == 2

    def test_json_schema_applicable_empty_string_reason_rejected(self):
        """Raw JSON Schema: applicable with reason='' is rejected (must be null)."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        record_schema = {
            **full_schema["$defs"]["CorpusClaimApplicability"],
            "$defs": full_schema["$defs"],
        }
        validator = jsonschema.Draft202012Validator(record_schema)
        errors = list(
            validator.iter_errors(
                {
                    "category": "entry_points",
                    "status": "applicable",
                    "reason": "",
                    "evidence": ["evidence"],
                }
            )
        )
        assert errors, "applicable with reason='' should be rejected"

    def test_json_schema_applicable_whitespace_evidence_rejected(self):
        """Raw JSON Schema: applicable with whitespace-only evidence is rejected."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        record_schema = {
            **full_schema["$defs"]["CorpusClaimApplicability"],
            "$defs": full_schema["$defs"],
        }
        validator = jsonschema.Draft202012Validator(record_schema)
        errors = list(
            validator.iter_errors(
                {
                    "category": "entry_points",
                    "status": "applicable",
                    "evidence": ["   "],
                }
            )
        )
        assert errors, "applicable with whitespace-only evidence should be rejected"

    def test_json_schema_applicable_mixed_blank_evidence_rejected(self):
        """Raw JSON Schema: applicable with mixed blank/nonblank evidence is rejected."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        record_schema = {
            **full_schema["$defs"]["CorpusClaimApplicability"],
            "$defs": full_schema["$defs"],
        }
        validator = jsonschema.Draft202012Validator(record_schema)
        errors = list(
            validator.iter_errors(
                {
                    "category": "entry_points",
                    "status": "applicable",
                    "evidence": ["real evidence", "\t"],
                }
            )
        )
        assert errors, (
            "applicable with mixed blank/nonblank evidence should be rejected"
        )

    def test_json_schema_not_applicable_whitespace_reason_rejected(self):
        """Raw JSON Schema: not_applicable with whitespace-only reason is rejected."""
        import json
        from pathlib import Path

        import jsonschema

        schema_path = (
            Path(__file__).resolve().parent.parent
            / "src"
            / "asago_scenario_generator"
            / "data"
            / "schemas"
            / "scenario-envelope.schema.json"
        )
        with open(schema_path) as f:
            full_schema = json.load(f)
        record_schema = {
            **full_schema["$defs"]["CorpusClaimApplicability"],
            "$defs": full_schema["$defs"],
        }
        validator = jsonschema.Draft202012Validator(record_schema)
        errors = list(
            validator.iter_errors(
                {
                    "category": "entry_points",
                    "status": "not_applicable",
                    "reason": "   ",
                }
            )
        )
        assert errors, "not_applicable with whitespace-only reason should be rejected"

    def test_report_applicable_empty_string_reason_fails(self):
        """Report reconciliation rejects applicable with reason=''."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        scenario = {
            "validation": {
                "semantic": {
                    "valid": True,
                    "violations": [],
                    "corpus_claim_applicability": [
                        {
                            "category": "entry_points",
                            "status": "applicable",
                            "reason": "",
                            "evidence": ["evidence"],
                        },
                        {
                            "category": "tool_inventory",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                    ],
                }
            }
        }
        with pytest.raises(Exception, match="must not carry a reason"):
            _reconcile_corpus_claims([scenario])

    def test_report_applicable_whitespace_evidence_fails(self):
        """Report reconciliation rejects applicable with whitespace-only evidence."""
        from asago_scenario_generator.report.generator import _reconcile_corpus_claims

        scenario = {
            "validation": {
                "semantic": {
                    "valid": True,
                    "violations": [],
                    "corpus_claim_applicability": [
                        {
                            "category": "entry_points",
                            "status": "applicable",
                            "evidence": ["  "],
                        },
                        {
                            "category": "tool_inventory",
                            "status": "not_applicable",
                            "reason": "Partial.",
                        },
                    ],
                }
            }
        }
        with pytest.raises(Exception, match="blank/whitespace-only evidence"):
            _reconcile_corpus_claims([scenario])


class TestAttackerAccessibleIngressPredicate:
    """Centralized attacker-accessible ingress predicate must be used
    consistently across all routes (cmps.9 third review correction 2)."""

    def _make_profile_with_mixed_entry_points(self):
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            EntryPoint,
            InventoryCompleteness,
        )

        return CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=[
                # Attacker-accessible
                EntryPoint(
                    name="user chat",
                    direction="input",
                    ingress_zone="input",
                ),
                # Output-only
                EntryPoint(
                    name="system alerts",
                    direction="output",
                ),
                # System-controlled
                EntryPoint(
                    name="backend API",
                    direction="input",
                    controllability="system",
                    ingress_zone="input",
                ),
                # Inactive zone
                EntryPoint(
                    name="admin console",
                    direction="input",
                    ingress_zone="memory",
                ),
            ],
            confidence="high",
            kc_subcodes=["KC1.1"],
            entry_point_completeness=InventoryCompleteness.inferred_partial,
            tool_inventory_completeness=InventoryCompleteness.inferred_partial,
        )

    def test_system_ep_not_in_coverage_gaps(self):
        """System-controlled EPs do not become coverage gaps."""
        from asago_scenario_generator.models.capability_profile import (
            compute_entry_point_id,
        )
        from asago_scenario_generator.pipeline.coverage import analyze_coverage_gaps

        profile = self._make_profile_with_mixed_entry_points()
        threats = _make_minimal_threat_surface()
        gaps = analyze_coverage_gaps(profile, threats, [])
        ep_ids = [g.entry_point_id for g in gaps.uncovered_entry_points]
        # Only the accessible "user chat" EP should be in the denominator
        accessible_ep = profile.resolve_entry_point(
            compute_entry_point_id("user chat", "input", None, "input")
        )
        assert accessible_ep is not None
        assert accessible_ep.entry_point_id in ep_ids
        # System EP should NOT be in gaps
        system_ep = next(ep for ep in profile.entry_points if ep.name == "backend API")
        assert system_ep.entry_point_id not in ep_ids
        # Output EP should NOT be in gaps
        output_ep = next(
            ep for ep in profile.entry_points if ep.name == "system alerts"
        )
        assert output_ep.entry_point_id not in ep_ids
        # Inactive zone EP should NOT be in gaps
        inactive_ep = next(
            ep for ep in profile.entry_points if ep.name == "admin console"
        )
        assert inactive_ep.entry_point_id not in ep_ids

    def test_inaccessible_ep_not_in_candidates(self):
        """Inaccessible EPs do not enter candidate expansion."""
        from asago_scenario_generator.pipeline.candidates import expand_candidates

        profile = self._make_profile_with_mixed_entry_points()
        seeds = [
            _make_minimal_seed("AP-T5-01"),
        ]
        candidates = expand_candidates(seeds, profile)
        # No candidates should reference the system, output, or inactive EPs
        for c in candidates:
            assert c.entry_point != "backend API"
            assert c.entry_point != "system alerts"
            assert c.entry_point != "admin console"

    def test_inaccessible_ep_excluded_from_coverage_universe(self):
        """Inaccessible EPs are excluded from the coverage universe."""
        from asago_scenario_generator.pipeline.coverage_planning import (
            CoverageExclusionReason,
            build_coverage_universe,
        )

        profile = self._make_profile_with_mixed_entry_points()
        system_ep = next(ep for ep in profile.entry_points if ep.name == "backend API")

        universe = build_coverage_universe(profile)

        excluded = next(
            target
            for target in universe.excluded_targets
            if target.entry_point_id == system_ep.entry_point_id
        )
        assert excluded.reason is CoverageExclusionReason.SYSTEM_CONTROLLED
        assert system_ep.entry_point_id not in universe.feasible_target_ids

    def test_inaccessible_ep_not_in_eval_denominator(self):
        """Inaccessible EPs do not count in eval expected-entry-point denominator."""
        from asago_scenario_generator.models.capability_profile import (
            is_attacker_accessible_ingress,
        )

        profile = self._make_profile_with_mixed_entry_points()
        active_zones = set(profile.zones_active)
        accessible = [
            ep
            for ep in profile.entry_points
            if is_attacker_accessible_ingress(ep, active_zones)
        ]
        # Only one EP should be accessible
        assert len(accessible) == 1
        assert accessible[0].name == "user chat"

    def test_inaccessible_ep_rejected_at_admission(self):
        """Inaccessible EPs cannot be admitted as initial_ingress actions."""
        from asago_scenario_generator.models.attack_tree import (
            AiSystemAction,
            AttackTree,
            AttackTreeNode,
            InitialIngressAction,
        )
        from asago_scenario_generator.pipeline.generate.tree import _validate_pinned_ingress

        profile = self._make_profile_with_mixed_entry_points()
        system_ep = next(ep for ep in profile.entry_points if ep.name == "backend API")
        tree = AttackTree(
            id="tree-AP-T5-01",
            seed_id="AP-T5-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="AND",
                children=[
                    AttackTreeNode(
                        id="n1.1",
                        label="ingress",
                        gate="LEAF",
                        zone="input",
                        action=InitialIngressAction(
                            entry_point_id=system_ep.entry_point_id,
                        ),
                    ),
                    AttackTreeNode(
                        id="n1.2",
                        label="action",
                        gate="LEAF",
                        zone="reasoning",
                        action=AiSystemAction(),
                    ),
                ],
            ),
        )
        violations = _validate_pinned_ingress(tree, None, profile)
        assert any("inaccessible-ingress-entry-point" in v for v in violations)


class TestToolExecutionZonePromptParity:
    """Prompt and consistency must allow integration_interaction in
    tool_execution (cmps.9 third review correction 4)."""

    def test_prompt_allows_integration_in_tool_execution(self):
        """call2_system.j2 Tool Execution Zone Scope explicitly permits
        direct canonical integration interactions, even when there are no
        tools (integration-only profile)."""
        from asago_scenario_generator.prompts import render_prompt

        # Integration-only profile (no tool_inventory)
        external_integrations = [
            {
                "integration_id": "int:v1:xyz",
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ]
        html = render_prompt(
            "call2_system.j2",
            use_case="Test",
            tool_inventory=[],
            external_integrations=external_integrations,
            entry_points=[],
            pinned_entry_point_id=None,
            skeleton_section="",
            technique_context="",
            technique_constraint="",
            narrative=None,
            technique_count=0,
            leaf_budget=10,
            ontology_context={},
            kill_chain="",
            consistency_feedback=None,
            actor_section="",
            arch_section="",
            seed=None,
        )
        assert "integration_interaction" in html
        assert "integration_id" in html
        # The Tool Execution Zone Scope invariant must render even with
        # an integration-only profile (guard is tool_inventory or
        # external_integrations).
        assert "Tool Execution Zone Scope" in html

    def test_consistency_accepts_integration_in_tool_execution(self):
        """Consistency check accepts a resolvable integration_interaction in
        tool_execution zone."""
        from asago_scenario_generator.models.attack_tree import (
            AttackTree,
            AttackTreeNode,
            IntegrationInteractionAction,
        )
        from asago_scenario_generator.models.capability_profile import (
            CapabilityProfile,
            ExternalIntegration,
            ToolInventoryEntry,
        )
        from asago_scenario_generator.pipeline.generate.tree import (
            _check_tool_execution_leaf_grounding,
        )

        integration = ExternalIntegration(
            name="CRM",
            integration_type="api",
            auth_method="oauth",
            data_sensitivity="high",
        )
        _profile = CapabilityProfile(
            zones_active=["input", "reasoning", "tool_execution"],
            entry_points=["user chat"],
            confidence="high",
            kc_subcodes=["KC1.1", "KC6.1.1"],
            tool_inventory=[
                ToolInventoryEntry(name="Search", description="Search tool")
            ],
            external_integrations=[integration],
        )
        # Verify the integration resolves from the profile.
        assert _profile.resolve_integration(integration.integration_id) is not None
        tree = AttackTree(
            id="tree-AP-T5-01",
            seed_id="AP-T5-01",
            goal="test",
            root=AttackTreeNode(
                id="n1",
                label="root",
                gate="LEAF",
                zone="tool_execution",
                action=IntegrationInteractionAction(
                    integration_id=integration.integration_id,
                ),
            ),
        )
        violations: list[str] = []
        _check_tool_execution_leaf_grounding(tree.root, violations)
        assert not any("untyped-tool-execution" in v for v in violations)


def _make_minimal_seed(seed_id: str = "AP-T5-01"):
    from asago_scenario_generator.models.scenario import RiskCardRef
    from asago_scenario_generator.pipeline.seeds import ScenarioSeed

    risk_card = RiskCardRef(
        risk_id="R1",
        risk_name="Test Risk",
        risk_description="A test risk.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id="T5",
        threat_name="Test Threat",
        attack_pattern_name="Test Attack Pattern",
        attack_pattern_description="Description of test attack pattern.",
        risk_card_ref=risk_card,
        contributing_risk_cards=[risk_card],
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T5"],
        atlas_technique_ids=["AML.T0051"],
        laaf_technique_ids=[],
    )


def _make_minimal_threat_surface():
    from asago_scenario_generator.models import ThreatSurface, ThreatSurfaceEntry
    from asago_scenario_generator.models.scenario import RiskCardRef

    risk_card = RiskCardRef(
        risk_id="R1",
        risk_name="Test Risk",
        risk_description="A test risk.",
        taxonomy="ibm-risk-atlas",
        confidence=0.9,
        grounding_confidence="high",
    )
    return ThreatSurface(
        entries=[
            ThreatSurfaceEntry(
                risk_card=risk_card,
                owasp_llm_ids=["LLM01"],
                agentic_threat_ids=["T5"],
                attack_pattern_ids=["AP-T5-01"],
            )
        ],
        governance_only=[],
    )
