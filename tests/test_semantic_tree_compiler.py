"""Public-interface tests for semantic attack-tree compilation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_tree import (
    ExternalPreconditionAction,
    ImpactAction,
    InitialIngressAction,
    IntegrationInteractionAction,
    ToolInvocationAction,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
)
from asago_scenario_generator.models.scenario import NarrativeLayer, NarrativeStep
from asago_scenario_generator.pipeline.generate.canonical_projection import (
    _derive_action,
    derive_canonical_projection_semantics,
)
from asago_scenario_generator.pipeline.generate.tree_semantics import (
    AttackTreeDraftNode,
    AttackTreeDraftGroupV3,
    AttackTreeDraftV2,
    AttackTreeDraftV3,
    ProjectionInfeasible,
    build_attack_tree_draft_response_model,
    _coalesce_canonical_leaf_specs,
    _validate_flat_attack_tree_draft,
    compile_flat_attack_tree_draft,
    compile_attack_tree_draft,
    derive_canonical_leaf_specs,
    validate_tree_projection_realizability,
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


def test_canonical_semantics_assign_contiguous_narrative_regions() -> None:
    profile = _profile()
    context = _context(profile)
    third = make_realizations(
        ("step.3",),
        action_kind="observe",
        executor_role="system",
        boundary_position="inside",
    )[0]
    context["selected_step_ids"] = ["step.1", "step.2", "step.3"]
    context["selected_steps"].append(
        {
            "step_id": "step.3",
            "order": 3,
            "action_kind": "observe",
            "executor_role": "system",
            "boundary_position": "inside",
            "resource_links": [],
            "observable_postconditions": [],
            "realization": third.model_dump(mode="json"),
        }
    )

    semantics = derive_canonical_projection_semantics(context, profile)

    assert [step.zone for step in semantics.steps] == [
        "input",
        "reasoning",
        "reasoning",
    ]
    assert [step.narrative_region for step in semantics.steps] == [
        "r0",
        "r1",
        "r1",
    ]


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


def test_source_influence_activation_owns_ingress_when_fetch_is_inside() -> None:
    profile = CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            {
                "name": "RAG entry point",
                "direction": "input",
                "controllability": "indirect",
                "ingress_zone": "reasoning",
            }
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )
    ingress_id = profile.entry_points[0].entry_point_id
    realization = make_realizations(
        ("fetch_poisoned_content",),
        action_kind="invoke",
        executor_role="system",
        boundary_position="inside",
    )[0]
    context = {
        "selected_step_ids": ["fetch_poisoned_content"],
        "initial_ingress_slot_id": "ingress",
        "canonical_ingress": {
            "kind": "entry_point",
            "entry_point_id": ingress_id,
        },
        "selected_steps": [
            {
                "step_id": "fetch_poisoned_content",
                "order": 1,
                "action_kind": "invoke",
                "executor_role": "system",
                "boundary_position": "inside",
                "resource_links": [
                    {
                        "role": "source_influence",
                        "slot_id": "poisoned_source",
                        "target_ingress_slot_id": "ingress",
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
        summary="The system fetches attacker-influenced source content.",
        entry_point="RAG entry point",
        zone_sequence=["reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="reasoning",
                action="Fetch attacker-influenced content",
                effect="The poisoned content enters model context",
                projected_step_ids=("fetch_poisoned_content",),
                realizations=(realization,),
            )
        ],
    )

    specs = derive_canonical_leaf_specs(context, narrative, profile)

    assert len(specs) == 1
    assert isinstance(specs[0].action, InitialIngressAction)
    assert specs[0].action.entry_point_id == ingress_id
    assert specs[0].initial_ingress is True


def test_unlinked_inside_attacker_invoke_is_not_inferred_as_ingress() -> None:
    profile = _profile()
    context = _context(profile)
    ingress_id = profile.entry_points[0].entry_point_id
    realization = make_realizations(
        ("step.3",),
        action_kind="invoke",
        executor_role="attacker",
        boundary_position="inside",
    )[0]
    context["selected_step_ids"] = ["step.1", "step.3"]
    context["initial_ingress_slot_id"] = "ingress"
    context["selected_steps"] = [
        context["selected_steps"][0],
        {
            "step_id": "step.3",
            "order": 2,
            "action_kind": "invoke",
            "executor_role": "attacker",
            "boundary_position": "inside",
            "resource_links": [],
            "observable_postconditions": [],
            "realization": realization.model_dump(mode="json"),
        },
    ]
    narrative = NarrativeLayer(
        title="Injection activates after delivery",
        summary="A request crosses ingress before the attacker drives execution.",
        entry_point="chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            _narrative().steps[0],
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="Drive the injected instruction",
                effect="The model executes the instruction",
                projected_step_ids=("step.3",),
                realizations=(realization,),
            ),
        ],
    )

    specs = derive_canonical_leaf_specs(context, narrative, profile)

    assert [spec.action.kind for spec in specs] == [
        "initial_ingress",
        "attacker_action",
    ]
    assert sum(spec.initial_ingress for spec in specs) == 1
    assert specs[1].action.kind != "initial_ingress"
    assert specs[0].action.entry_point_id == ingress_id


def test_inside_attacker_observation_has_typed_attacker_action() -> None:
    profile = _profile()
    context = _context(profile)
    realization = make_realizations(
        ("step.3",),
        action_kind="observe",
        executor_role="attacker",
        boundary_position="inside",
    )[0]
    context["selected_step_ids"] = ["step.1", "step.3"]
    context["initial_ingress_slot_id"] = "ingress"
    context["selected_steps"] = [
        context["selected_steps"][0],
        {
            "step_id": "step.3",
            "order": 2,
            "action_kind": "observe",
            "executor_role": "attacker",
            "boundary_position": "inside",
            "resource_links": [],
            "observable_postconditions": [],
            "realization": realization.model_dump(mode="json"),
        },
    ]
    narrative = NarrativeLayer(
        title="Attacker discovers exposed data",
        summary="The attacker observes data after entering through chat.",
        entry_point="chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            _narrative().steps[0],
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="Inspect exposed data",
                effect="The attacker identifies useful records",
                projected_step_ids=("step.3",),
                realizations=(realization,),
            ),
        ],
    )

    specs = derive_canonical_leaf_specs(context, narrative, profile)

    assert specs[1].action.kind == "attacker_action"
    assert specs[1].zone == "reasoning"


def test_observation_that_owns_ingress_compiles_as_initial_ingress() -> None:
    profile = _profile()
    ingress_id = profile.entry_points[0].entry_point_id
    realization = make_realizations(
        ("discover_tools",),
        action_kind="observe",
        executor_role="attacker",
        boundary_position="crossing",
    )[0]
    context = {
        "selected_step_ids": ["discover_tools"],
        "initial_ingress_slot_id": "ingress",
        "canonical_ingress": {
            "kind": "entry_point",
            "entry_point_id": ingress_id,
        },
        "selected_steps": [
            {
                "step_id": "discover_tools",
                "order": 1,
                "action_kind": "observe",
                "executor_role": "attacker",
                "boundary_position": "crossing",
                "resource_links": [
                    {
                        "role": "ingress",
                        "slot_id": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": ingress_id,
                        },
                    }
                ],
                "observable_postconditions": [],
                "realization": realization.model_dump(mode="json"),
            }
        ],
    }
    narrative = NarrativeLayer(
        title="Discover exposed tools",
        summary="The actor observes the tool surface through canonical ingress.",
        entry_point="chat",
        zone_sequence=["input"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Inspect the exposed tool surface",
                effect="The actor learns which tools are available",
                projected_step_ids=("discover_tools",),
                realizations=(realization,),
            )
        ],
    )

    specs = derive_canonical_leaf_specs(context, narrative, profile)

    assert specs[0].action.kind == "initial_ingress"
    assert specs[0].initial_ingress is True


def _leaf(handle: str) -> AttackTreeDraftNode:
    return AttackTreeDraftNode(kind="leaf", leaf_handle=handle)


def _group(label: str, *children: AttackTreeDraftNode) -> AttackTreeDraftNode:
    return AttackTreeDraftNode(kind="group", label=label, children=children)


def test_flat_tree_draft_reports_unknown_duplicate_and_missing_handles() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV3(
        root_label="Bad coverage",
        groups=(
            AttackTreeDraftGroupV3(
                label="Mixed group", leaf_handles=("l0", "l9", "l0")
            ),
        ),
    )

    validation = _validate_flat_attack_tree_draft(draft, specs)

    assert not validation.accepted
    assert [(v.code, v.handles) for v in validation.violations] == [
        ("unknown_handle", ("l9",)),
        ("duplicate_handle", ("l0",)),
        ("missing_handle", ("l1",)),
    ]


def test_flat_tree_draft_rejects_reordered_leaf_handles() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV3(
        root_label="Reordered",
        groups=(AttackTreeDraftGroupV3(label="Group one", leaf_handles=("l1", "l0")),),
    )

    validation = _validate_flat_attack_tree_draft(draft, specs)

    assert not validation.accepted
    assert [(v.code, v.handles) for v in validation.violations] == [
        ("illegal_order", ("l1", "l0")),
    ]


def test_tree_draft_reports_unknown_handle_with_missing_partner() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV2(root=_group("Root", _leaf("l0"), _leaf("l9")))

    validation = validate_attack_tree_draft(draft, specs)

    assert not validation.accepted
    assert {(v.code, v.handles) for v in validation.violations} == {
        ("unknown_handle", ("l9",)),
        ("missing_handle", ("l1",)),
    }


def test_tree_draft_rejects_reordered_handles_without_coverage_noise() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV2(root=_group("Root", _leaf("l1"), _leaf("l0")))

    validation = validate_attack_tree_draft(draft, specs)

    assert not validation.accepted
    assert [(v.code, v.handles) for v in validation.violations] == [
        ("illegal_order", ("l1", "l0")),
    ]


def test_tree_draft_rejects_excessive_depth() -> None:
    profile = _profile()
    base = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)[0]
    spec_count = 32
    specs = tuple(
        base.model_copy(update={"leaf_handle": f"l{index}"})
        for index in range(spec_count)
    )
    handles = iter(specs)

    def balanced(depth: int) -> AttackTreeDraftNode:
        if depth == 0:
            return _leaf(next(handles).leaf_handle)
        return _group(f"level {depth}", balanced(depth - 1), balanced(depth - 1))

    draft = AttackTreeDraftV2(root=balanced(5))

    validation = validate_attack_tree_draft(draft, specs)

    assert not validation.accepted
    assert [(v.code, v.handles) for v in validation.violations] == [
        ("excessive_depth", ()),
    ]


def test_tree_draft_rejects_excessive_nodes() -> None:
    profile = _profile()
    specs = derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    draft = AttackTreeDraftV2(
        root=_group(
            "Root",
            _group("a", _leaf("l0"), _leaf("l0")),
            _group("b", _leaf("l1"), _leaf("l1")),
            _group("c", _leaf("l0"), _leaf("l1")),
        )
    )

    validation = validate_attack_tree_draft(draft, specs)

    assert not validation.accepted
    assert any(v.code == "excessive_nodes" for v in validation.violations)


# ---------------------------------------------------------------------------#
# _derive_action: canonical leaf action selection (CRAP slice 5)
# ---------------------------------------------------------------------------#


def _derive_step(**overrides: object) -> dict[str, object]:
    fields: dict[str, object] = {
        "step_id": "step.1",
        "action_kind": "transform",
        "executor_role": "attacker",
        "boundary_position": "inside",
        "resource_links": [],
        "observable_postconditions": [],
    }
    fields.update(overrides)
    return fields


def test_derive_action_outside_prepare_step_is_external_precondition() -> None:
    action = _derive_action(
        _derive_step(
            action_kind="prepare",
            executor_role="attacker",
            boundary_position="outside",
        ),
        {},
    )

    assert isinstance(action, ExternalPreconditionAction)


def test_derive_action_impact_step_carries_observable_target() -> None:
    action = _derive_action(
        _derive_step(
            action_kind="impact",
            executor_role="system",
            boundary_position="inside",
            observable_postconditions=[
                {
                    "postcondition_id": "post.3",
                    "description": "customer data leaves the tenant",
                    "security_relevant": True,
                    "terminal": True,
                }
            ],
        ),
        {},
    )

    assert isinstance(action, ImpactAction)
    assert action.boundary == "internal"
    assert action.target == "customer data leaves the tenant"


def test_derive_action_outside_impact_step_uses_default_target() -> None:
    action = _derive_action(
        _derive_step(
            action_kind="impact",
            executor_role="operator",
            boundary_position="outside",
        ),
        {},
    )

    assert isinstance(action, ImpactAction)
    assert action.boundary == "external"
    assert action.target == "Projected security impact"


def test_derive_action_invoke_with_tool_binding_is_tool_invocation() -> None:
    action = _derive_action(
        _derive_step(
            action_kind="invoke",
            executor_role="system",
            resource_links=[
                {
                    "role": "tool",
                    "resource_ref": {"kind": "tool", "tool_id": "tool:writer"},
                }
            ],
        ),
        {},
    )

    assert isinstance(action, ToolInvocationAction)
    assert action.tool_id == "tool:writer"
    assert action.integration_id is None


def test_derive_action_invoke_with_integration_binding_is_integration_interaction() -> (
    None
):
    action = _derive_action(
        _derive_step(
            action_kind="invoke",
            executor_role="system",
            resource_links=[
                {
                    "role": "source",
                    "resource_ref": {
                        "kind": "integration",
                        "integration_id": "integration:rag-source",
                    },
                }
            ],
        ),
        {},
    )

    assert isinstance(action, IntegrationInteractionAction)
    assert action.integration_id == "integration:rag-source"


def test_derive_action_incompatible_step_raises_projection_infeasible() -> None:
    with pytest.raises(ProjectionInfeasible, match="no canonical tree action"):
        _derive_action(
            _derive_step(action_kind="persist", executor_role="operator"),
            {},
        )


def test_derive_action_ingress_owning_step_must_be_ingress_compatible() -> None:
    with pytest.raises(ProjectionInfeasible, match="incompatible with initial_ingress"):
        _derive_action(
            _derive_step(
                action_kind="impact",
                executor_role="system",
                resource_links=[
                    {
                        "role": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": "ep:v1:chat",
                        },
                    }
                ],
            ),
            {},
        )


def test_derive_action_ingress_owning_step_requires_canonical_entry_point() -> None:
    with pytest.raises(ProjectionInfeasible, match="has no canonical entry point"):
        _derive_action(
            _derive_step(
                action_kind="deliver",
                executor_role="attacker",
                boundary_position="crossing",
                resource_links=[
                    {"role": "ingress", "resource_ref": {"kind": "entry_point"}}
                ],
            ),
            {},
        )


def test_post_ingress_attacker_delivery_compiles_as_attacker_action() -> None:
    profile = _profile()
    context = _context(profile)
    realization = make_realizations(
        ("deliver_injection",),
        action_kind="deliver",
        executor_role="attacker",
        boundary_position="crossing",
    )[0]
    context["selected_step_ids"] = ["step.1", "deliver_injection"]
    context["selected_steps"] = [
        context["selected_steps"][0],
        {
            "step_id": "deliver_injection",
            "order": 2,
            "action_kind": "deliver",
            "executor_role": "attacker",
            "boundary_position": "crossing",
            "resource_links": [],
            "observable_postconditions": [],
            "realization": realization.model_dump(mode="json"),
        },
    ]
    narrative = NarrativeLayer(
        title="Deliver a second-stage injection",
        summary="The actor enters through chat and delivers a later payload.",
        entry_point="chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            _narrative().steps[0],
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="Deliver the later payload",
                effect="The payload reaches the active session",
                projected_step_ids=("deliver_injection",),
                realizations=(realization,),
            ),
        ],
    )

    specs = derive_canonical_leaf_specs(context, narrative, profile)

    assert [spec.action.kind for spec in specs] == [
        "initial_ingress",
        "attacker_action",
    ]


def test_projection_realizability_preflight_rejects_missing_ingress() -> None:
    profile = _profile()
    context = _context(profile)
    context["initial_ingress_slot_id"] = "ingress"
    context["selected_steps"][0]["resource_links"] = []

    with pytest.raises(ProjectionInfeasible, match="no initial ingress"):
        validate_tree_projection_realizability(context, profile)


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
    original = list(
        derive_canonical_leaf_specs(_context(profile), _narrative(), profile)
    )
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


def test_tree_compiler_preserves_authored_grouping_and_expands_canonical_leaves() -> (
    None
):
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


def test_canonical_semantics_for_step_resolves_known_step() -> None:
    profile = _profile()
    semantics = derive_canonical_projection_semantics(_context(profile), profile)
    first = semantics.steps[0]

    assert semantics.for_step(first.projected_step_id) is first


def test_canonical_semantics_for_step_fails_with_ownership_for_unknown_step() -> None:
    profile = _profile()
    semantics = derive_canonical_projection_semantics(_context(profile), profile)

    with pytest.raises(ProjectionInfeasible, match="step.unknown.*absent"):
        semantics.for_step("step.unknown")
