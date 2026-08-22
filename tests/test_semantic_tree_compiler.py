"""Public-interface tests for semantic attack-tree compilation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_tree import InitialIngressAction
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep
from asago_scenario_generator.pipeline.generate.tree_semantics import (
    AttackTreeDraftNode,
    AttackTreeDraftGroupV3,
    AttackTreeDraftV2,
    AttackTreeDraftV3,
    build_attack_tree_draft_response_model,
    _coalesce_canonical_leaf_specs,
    compile_flat_attack_tree_draft,
    compile_attack_tree_draft,
    derive_canonical_leaf_specs,
    validate_attack_tree_draft,
)
from tests.helpers.realization_helper import make_realizations


def _profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"}
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


def _context(profile: CapabilityProfile) -> dict[str, object]:
    ingress_id = profile.entry_points[0].entry_point_id
    realizations = (
        make_realizations(("step.1",), action_kind="deliver")[0],
        make_realizations(
            ("step.2",),
            action_kind="transform",
            executor_role="system",
            boundary_position="inside",
        )[0],
    )
    return {
        "selected_step_ids": ["step.1", "step.2"],
        "canonical_ingress": {"kind": "entry_point", "entry_point_id": ingress_id},
        "selected_steps": [
            {
                "step_id": "step.1",
                "order": 1,
                "action_kind": "deliver",
                "executor_role": "attacker",
                "boundary_position": "crossing",
                "resource_links": [
                    {
                        "role": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": ingress_id,
                        },
                    }
                ],
                "observable_postconditions": [],
                "realization": realizations[0].model_dump(mode="json"),
                "technique_ids": ["AML.T0001"],
            },
            {
                "step_id": "step.2",
                "order": 2,
                "action_kind": "transform",
                "executor_role": "system",
                "boundary_position": "inside",
                "resource_links": [],
                "observable_postconditions": [
                    {
                        "postcondition_id": "post.2",
                        "description": "the model follows the injected instruction",
                        "security_relevant": True,
                        "terminal": True,
                    }
                ],
                "realization": realizations[1].model_dump(mode="json"),
            },
        ],
    }


def _narrative() -> NarrativeLayer:
    return NarrativeLayer(
        title="Injected instruction changes the response",
        summary="A crafted request crosses the input boundary and changes reasoning.",
        entry_point="chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Send a crafted request",
                effect="The request reaches the model",
                projected_step_ids=("step.1",),
                realizations=make_realizations(("step.1",), action_kind="deliver"),
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="Interpret the injected instruction",
                effect="The instruction changes the response",
                projected_step_ids=("step.2",),
                realizations=make_realizations(
                    ("step.2",),
                    action_kind="transform",
                    executor_role="system",
                    boundary_position="inside",
                ),
            ),
        ],
    )


def test_leaf_specs_derive_canonical_identity_before_topology_authorship() -> None:
    profile = _profile()

    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)

    assert [spec.leaf_handle for spec in specs] == ["l0", "l1"]
    assert specs[0].projected_step_ids == ("step.1",)
    assert isinstance(specs[0].action, InitialIngressAction)
    assert specs[0].action.entry_point_id == profile.entry_points[0].entry_point_id
    assert specs[0].zone == "input"
    assert specs[0].technique_id == "AML.T0001"
    assert specs[1].action.kind == "ai_system_action"
    assert specs[1].zone == "reasoning"


def test_indirect_system_invoke_crossing_boundary_is_canonical_ingress() -> None:
    profile = CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            {
                "name": "RAG entry point",
                "direction": "input",
                "controllability": "indirect",
            }
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )
    ingress_id = profile.entry_points[0].entry_point_id
    realization = make_realizations(
        ("ingest_malicious_content",),
        action_kind="invoke",
        executor_role="system",
        boundary_position="crossing",
    )[0]
    context = {
        "selected_step_ids": ["ingest_malicious_content"],
        "canonical_ingress": {
            "kind": "entry_point",
            "entry_point_id": ingress_id,
        },
        "selected_steps": [
            {
                "step_id": "ingest_malicious_content",
                "order": 1,
                "action_kind": "invoke",
                "executor_role": "system",
                "boundary_position": "crossing",
                "resource_links": [
                    {
                        "role": "source_influence",
                        "resource_ref": {
                            "kind": "integration",
                            "integration_id": "integration:rag-source",
                        },
                    }
                ],
                "observable_postconditions": [],
                "realization": realization.model_dump(mode="json"),
            }
        ],
    }
    narrative = NarrativeLayer(
        title="Poisoned source reaches retrieval",
        summary="The system ingests attacker-influenced source content.",
        entry_point="RAG entry point",
        zone_sequence=["input"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Ingest attacker-influenced content",
                effect="The content crosses into retrieval",
                projected_step_ids=("ingest_malicious_content",),
                realizations=(realization,),
            )
        ],
    )

    specs = derive_canonical_leaf_specs(context, narrative, profile)

    assert len(specs) == 1
    assert isinstance(specs[0].action, InitialIngressAction)
    assert specs[0].action.entry_point_id == ingress_id
    assert specs[0].initial_ingress is True


def test_provider_tree_schema_advertises_group_child_minimum_and_handle_enum() -> None:
    response_model = build_attack_tree_draft_response_model(("l0", "l1"))
    schema = response_model.model_json_schema()
    group_schema = schema["$defs"]["AttackTreeDraftGroupV3"]

    assert group_schema["properties"]["leaf_handles"]["minItems"] == 1
    assert group_schema["properties"]["leaf_handles"]["maxItems"] == 32
    assert group_schema["properties"]["leaf_handles"]["items"]["enum"] == [
        "l0",
        "l1",
    ]
    with pytest.raises(ValidationError, match="at least 1 item"):
        response_model.model_validate(
            {
                "root_label": "Invalid wrapper",
                "groups": [{"label": "Empty", "leaf_handles": []}],
            }
        )


def test_flat_tree_draft_compiles_provider_groups_without_single_child_groups() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV3(
        root_label="Change model behavior",
        groups=(
            AttackTreeDraftGroupV3(
                label="Establish and exploit access",
                leaf_handles=("l0", "l1"),
            ),
        ),
    )

    tree = compile_flat_attack_tree_draft(
        seed_id="AP-T1-01",
        goal="Cause an unsafe response",
        draft=draft,
        leaf_specs=specs,
        threat_id="T1",
    )

    assert tree.root.gate.value == "AND"
    assert [child.projected_step_ids for child in tree.root.children or []] == [
        ("step.1",),
        ("step.2",),
    ]


def test_adjacent_equivalent_leaf_specs_coalesce_without_losing_traceability() -> None:
    profile = _profile()
    original = list(derive_canonical_leaf_specs(_context(profile), _narrative(), profile))
    first = original[0]
    second_realization = first.realizations[0].model_copy(
        update={"projected_step_id": "step.1b"}
    )
    equivalent = first.model_copy(
        update={
            "leaf_handle": "l1",
            "label": "A second equivalent delivery occurs",
            "projected_step_ids": ("step.1b",),
            "realizations": (second_realization,),
        }
    )
    trailing = original[1].model_copy(update={"leaf_handle": "l2"})

    merged = _coalesce_canonical_leaf_specs([first, equivalent, trailing])

    assert [spec.leaf_handle for spec in merged] == ["l0", "l1"]
    assert merged[0].projected_step_ids == ("step.1", "step.1b")
    assert [item.projected_step_id for item in merged[0].realizations] == [
        "step.1",
        "step.1b",
    ]
    assert merged[1].projected_step_ids == ("step.2",)


def test_tree_draft_requires_every_leaf_handle_exactly_once() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV2(
        root=AttackTreeDraftNode(
            kind="group",
            label="Change model behavior",
            children=(
                AttackTreeDraftNode(kind="leaf", leaf_handle="l0"),
                AttackTreeDraftNode(kind="leaf", leaf_handle="l0"),
            ),
        )
    )

    validation = validate_attack_tree_draft(draft, specs)

    assert not validation.accepted
    assert [(v.code, v.handles) for v in validation.violations] == [
        ("duplicate_handle", ("l0",)),
        ("missing_handle", ("l1",)),
    ]


def test_tree_compiler_preserves_authored_grouping_and_expands_canonical_leaves() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV2(
        root=AttackTreeDraftNode(
            kind="group",
            label="Establish access",
            description="Establish access before changing model reasoning.",
            children=(
                AttackTreeDraftNode(kind="leaf", leaf_handle="l0"),
                AttackTreeDraftNode(kind="leaf", leaf_handle="l1"),
            ),
        )
    )

    tree = compile_attack_tree_draft(
        seed_id="AP-T1-01",
        goal="Cause an unsafe response",
        draft=draft,
        leaf_specs=specs,
        threat_id="T1",
    )

    assert tree.root.label == "Establish access"
    assert [child.projected_step_ids for child in tree.root.children or []] == [
        ("step.1",),
        ("step.2",),
    ]
    assert tree.root.children[0].action == specs[0].action
    assert tree.root.children[0].technique_id == "AML.T0001"
    assert tree.root.children[1].realizations == specs[1].realizations
