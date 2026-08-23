"""Semantic draft/compiler contracts for actor and narrative generation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import ActorAccessProvenance
from asago_scenario_generator.pipeline.generate.actor import (
    ActorDraftContext,
    ActorDraftV2,
    ActorDraftV3,
    ActorSemanticDraftError,
    Call0Response,
    compile_actor_draft,
    create_actor_draft_model,
    create_actor_draft_v3_model,
    _call_actor_profile,
    _actor_choice_inventory,
    _actor_draft_inventories,
    _compile_projected_actor_draft,
    _derive_canonical_actor_access,
)
from asago_scenario_generator.pipeline.generate.narrative import (
    NarrativeDraftContext,
    NarrativeDraftV2,
    NarrativeDraftV3,
    NarrativeProjectedStep,
    NarrativeSemanticDraftError,
    compile_narrative_draft,
    create_narrative_draft_model,
    create_narrative_draft_v3_model,
    _call_narrative,
)


def _realization(step_id: str, boundary: str) -> ProjectedStepRealization:
    return ProjectedStepRealization(
        projected_step_id=step_id,
        action_kind="deliver" if boundary == "crossing" else "observe",
        executor_role="attacker",
        boundary_position=boundary,
        resource_ref_ids=(),
        consumed_ref_ids=(),
        produced_ref_ids=(),
        produced_effect_ids=(),
        outcome_link_pc_ids=(),
        postcondition_ids=(),
    )


def test_actor_draft_compiler_preserves_bdi_and_attaches_canonical_values() -> None:
    """The model authors intent; handles cannot replace canonical authority."""
    access = ActorAccessProvenance(
        initial_entry_point_id="ep:v1:canonical",
        ingress_mode="direct",
        access_class="public",
    )
    context = ActorDraftContext(
        actor_types={"a0": "adversarial-user"},
        capability_levels={"c0": "intermediate"},
        resources={"r0": "HTTP client", "r1": "Prompt corpus"},
        access=access,
    )
    draft = ActorDraftV2(
        actor_type_handle="a0",
        capability_level_handle="c0",
        beliefs=["The assistant accepts untrusted natural-language input."],
        desires=["Cause the assistant to ignore its governing policy."],
        intentions=["Iteratively refine an instruction-conflict payload."],
        resource_handles=["r1", "r0"],
    )

    actor = compile_actor_draft(context, draft)

    assert actor.beliefs == draft.beliefs
    assert actor.desires == draft.desires
    assert actor.intentions == draft.intentions
    assert actor.actor_type == "adversarial-user"
    assert actor.capability_level == "intermediate"
    assert actor.resources == ["Prompt corpus", "HTTP client"]
    assert actor.access == access
    assert actor.access is not access


def test_actor_draft_schema_is_finite_and_excludes_access_provenance() -> None:
    model = create_actor_draft_model(
        actor_type_handles=("a0", "a1"),
        capability_level_handles=("c0",),
        resource_handles=("r0",),
    )
    schema = model.model_json_schema()

    assert schema["properties"]["actor_type_handle"]["enum"] == ["a0", "a1"]
    assert schema["properties"]["capability_level_handle"]["const"] == "c0"
    assert "access" not in schema["properties"]
    assert "initial_entry_point_id" not in schema["properties"]
    assert schema["properties"]["beliefs"]["minItems"] == 1
    assert schema["properties"]["beliefs"]["maxItems"] == 4

    with pytest.raises(ValidationError):
        model.model_validate(
            {
                "actor_type_handle": "unknown",
                "capability_level_handle": "c0",
                "beliefs": ["b"],
                "desires": ["d"],
                "intentions": ["i"],
                "resource_handles": [],
            }
        )


def test_actor_v3_schema_excludes_below_floor_actor_pairs() -> None:
    choices = _actor_choice_inventory(
        {"a0": "supply-chain-actor"},
        {"c0": "intermediate", "c1": "advanced", "c2": "expert"},
    )

    assert set(choices.values()) == {
        ("supply-chain-actor", "advanced"),
        ("supply-chain-actor", "expert"),
    }
    model = create_actor_draft_v3_model(
        actor_choice_handles=tuple(choices), resource_handles=()
    )
    schema = model.model_json_schema()
    assert schema["properties"]["actor_choice_handle"]["enum"] == ["ac0", "ac1"]
    assert "actor_type_handle" not in schema["properties"]
    assert "capability_level_handle" not in schema["properties"]


def _narrative_context() -> NarrativeDraftContext:
    return NarrativeDraftContext(
        title_fallback="Canonical attack pattern",
        entry_point="Chat interface",
        ordered_step_handles=("s0", "s1", "s2"),
        projected_steps={
            "s0": NarrativeProjectedStep(
                projected_step_id="projected.prepare",
                order=1,
                zone="outside",
                realization=_realization("projected.prepare", "outside"),
            ),
            "s1": NarrativeProjectedStep(
                projected_step_id="projected.deliver",
                order=2,
                zone="input",
                realization=_realization("projected.deliver", "crossing"),
            ),
            "s2": NarrativeProjectedStep(
                projected_step_id="projected.observe",
                order=3,
                zone="input",
                realization=_realization("projected.observe", "crossing"),
            ),
        },
    )


def test_narrative_compiler_preserves_causal_grouping_and_attaches_projection() -> None:
    draft = NarrativeDraftV2.model_validate(
        {
            "title": "Indirect context manipulation",
            "summary": "A staged payload crosses into model context and changes output.",
            "beats": [
                {
                    "step_handles": ["s0"],
                    "action": "The actor prepares a payload in an upstream source.",
                    "consequence": "The payload remains available for retrieval.",
                    "transition": "A routine retrieval brings it to the boundary.",
                },
                {
                    "step_handles": ["s1", "s2"],
                    "action": "The system retrieves the payload and interprets it.",
                    "consequence": "The resulting output follows the planted instruction.",
                },
            ],
        }
    )

    narrative = compile_narrative_draft(_narrative_context(), draft)

    assert [step.projected_step_ids for step in narrative.steps] == [
        ("projected.prepare",),
        ("projected.deliver", "projected.observe"),
    ]
    assert narrative.steps[0].action == draft.beats[0].action
    assert narrative.steps[0].effect == (
        f"{draft.beats[0].consequence} {draft.beats[0].transition}"
    )
    assert narrative.steps[0].zone == "outside"
    assert narrative.steps[1].zone == "input"
    assert narrative.zone_sequence == ["outside", "input"]
    assert [r.projected_step_id for r in narrative.steps[1].realizations] == [
        "projected.deliver",
        "projected.observe",
    ]
    assert narrative.entry_point == "Chat interface"


def test_narrative_title_fallback_is_explicitly_allowable_or_forbidden() -> None:
    draft = NarrativeDraftV2(
        title=None,
        summary="A causally meaningful summary.",
        beats=[
            {
                "step_handles": [handle],
                "action": f"Action for {handle}",
                "consequence": f"Consequence for {handle}",
            }
            for handle in ("s0", "s1", "s2")
        ],
    )

    allowed = compile_narrative_draft(_narrative_context(), draft)
    assert allowed.title == "Canonical attack pattern"

    forbidden = _narrative_context()
    forbidden = NarrativeDraftContext(
        title_fallback=forbidden.title_fallback,
        entry_point=forbidden.entry_point,
        ordered_step_handles=forbidden.ordered_step_handles,
        projected_steps=forbidden.projected_steps,
        access_realization=forbidden.access_realization,
        presentation_fallback_allowed=False,
    )
    with pytest.raises(NarrativeSemanticDraftError) as excinfo:
        compile_narrative_draft(forbidden, draft)
    assert [item.code for item in excinfo.value.violations] == ["missing_title"]


@pytest.mark.parametrize(
    ("handles", "codes"),
    [
        (["s0", "s1"], {"missing_step_handle"}),
        (["s0", "s1", "s1", "s2"], {"duplicate_step_handle"}),
        (["s0", "unknown", "s2"], {"unknown_step_handle", "missing_step_handle"}),
        (["s1", "s0", "s2"], {"illegal_step_order"}),
    ],
)
def test_narrative_compiler_rejects_incomplete_or_illegal_handle_coverage(
    handles: list[str], codes: set[str]
) -> None:
    draft = NarrativeDraftV2(
        title="Draft",
        summary="A causally meaningful summary.",
        beats=[
            {
                "step_handles": [handle],
                "action": f"Action for {handle}",
                "consequence": f"Consequence for {handle}",
            }
            for handle in handles
        ],
    )

    with pytest.raises(NarrativeSemanticDraftError) as excinfo:
        compile_narrative_draft(_narrative_context(), draft)

    assert {violation.code for violation in excinfo.value.violations} == codes


def test_narrative_draft_schema_accepts_only_request_local_handles() -> None:
    model = create_narrative_draft_model(("s0", "s1"))
    schema = model.model_json_schema()
    beat_ref = schema["properties"]["beats"]["items"]["$ref"].split("/")[-1]
    beat_schema = schema["$defs"][beat_ref]
    handle_schema = beat_schema["properties"]["step_handles"]["items"]

    assert handle_schema["enum"] == ["s0", "s1"]
    assert "zone" not in beat_schema["properties"]
    assert "projected_step_ids" not in beat_schema["properties"]
    assert schema["properties"]["beats"]["maxItems"] == 2


def test_narrative_v3_schema_makes_cross_region_grouping_unrepresentable() -> None:
    base = _narrative_context()
    context = NarrativeDraftContext(
        title_fallback=base.title_fallback,
        entry_point=base.entry_point,
        ordered_step_handles=base.ordered_step_handles,
        projected_steps={
            "s0": NarrativeProjectedStep(
                projected_step_id="projected.prepare",
                order=1,
                zone="outside",
                realization=_realization("projected.prepare", "outside"),
                region="r0",
            ),
            "s1": NarrativeProjectedStep(
                projected_step_id="projected.deliver",
                order=2,
                zone="input",
                realization=_realization("projected.deliver", "crossing"),
                region="r1",
            ),
            "s2": NarrativeProjectedStep(
                projected_step_id="projected.observe",
                order=3,
                zone="input",
                realization=_realization("projected.observe", "crossing"),
                region="r1",
            ),
        },
    )
    model = create_narrative_draft_v3_model(context)

    valid = model.model_validate(
        {
            "title": "Partitioned narrative",
            "summary": "The payload moves from preparation to ingress.",
            "regions": {
                "r0": [
                    {
                        "step_handles": ["s0"],
                        "action": "Prepare the payload.",
                        "consequence": "The payload is ready.",
                    }
                ],
                "r1": [
                    {
                        "step_handles": ["s1", "s2"],
                        "action": "Deliver and observe the payload.",
                        "consequence": "The response reveals the effect.",
                    }
                ],
            },
        }
    )
    narrative = compile_narrative_draft(context, valid)
    assert [step.projected_step_ids for step in narrative.steps] == [
        ("projected.prepare",),
        ("projected.deliver", "projected.observe"),
    ]

    with pytest.raises(ValidationError):
        model.model_validate(
            {
                "title": "Invalid partition",
                "summary": "This tries to cross a canonical region.",
                "regions": {
                    "r0": [
                        {
                            "step_handles": ["s0", "s1"],
                            "action": "Combine incompatible steps.",
                            "consequence": "The invalid grouping is rejected.",
                        }
                    ],
                    "r1": [
                        {
                            "step_handles": ["s2"],
                            "action": "Observe the response.",
                            "consequence": "The response is visible.",
                        }
                    ],
                },
            }
        )


def test_narrative_draft_rejects_grouping_across_canonical_boundaries() -> None:
    draft = NarrativeDraftV2(
        title="Draft",
        summary="A semantic summary.",
        beats=[
            {
                "step_handles": ["s0", "s1"],
                "action": "Prepare and deliver the payload.",
                "consequence": "The payload crosses into the system.",
            },
            {
                "step_handles": ["s2"],
                "action": "Observe the response.",
                "consequence": "The actor learns how the system reacts.",
            },
        ],
    )

    with pytest.raises(NarrativeSemanticDraftError) as excinfo:
        compile_narrative_draft(_narrative_context(), draft)

    assert {item.code for item in excinfo.value.violations} == {
        "mixed_step_zones",
        "mixed_boundary_positions",
    }


def test_projected_actor_call_uses_v3_schema_and_compiles_provider_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.generate.actor.build_call0_context",
        lambda **_kwargs: {
            "tool_inventory": [],
            "minimum_capability_level": "intermediate",
            "compatible_actor_types": ["adversarial-user"],
            "diversity_limitation": None,
            "projection_context": {},
        },
    )
    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.generate.actor.render_prompt",
        lambda *_args, **_kwargs: "prompt",
    )
    client = MagicMock(max_completion_tokens=2048)

    def complete(**request):
        response_model = request["response_format"]
        return MagicMock(
            content=response_model(
                actor_choice_handle="ac0",
                beliefs=["The assistant accepts untrusted input."],
                desires=["Change its policy-governed response."],
                intentions=["Submit a tailored conflicting instruction."],
                resource_handles=[],
            )
        )

    client.complete.side_effect = complete
    projection = {
        "canonical_ingress": {"entry_point_id": "ep:v1:canonical"},
        "ingress_controllability": "direct",
        "selected_steps": [],
        "source_influence_paths": [],
    }

    actor, _, _ = _call_actor_profile(
        seed=MagicMock(min_complexity=None),
        profile=MagicMock(zones_active=[]),
        client=client,
        use_case="test",
        pinned_entry_point="Chat interface",
        pinned_entry_point_id="ep:v1:canonical",
        projection_context=projection,
        completion_length_feedback="\n(shorten the previous response)",
    )

    response_model = client.complete.call_args.kwargs["response_format"]
    assert issubclass(response_model, ActorDraftV3)
    assert actor.actor_type == "adversarial-user"
    assert actor.capability_level == "intermediate"
    assert actor.access is not None
    assert actor.access.initial_entry_point_id == "ep:v1:canonical"
    user_prompt = client.complete.call_args.kwargs["user_prompt"]
    assert "Semantic Draft V3" in user_prompt
    assert user_prompt.endswith("\n(shorten the previous response)")


def test_projected_actor_draft_compile_accepts_v2_handle_protocol() -> None:
    actor = _compile_projected_actor_draft(
        resp=ActorDraftV2(
            actor_type_handle="a0",
            capability_level_handle="c0",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
        ),
        actor_types={"a0": "adversarial-user"},
        capability_levels={"c0": "intermediate"},
        resources={},
        actor_choices={"ac0": ("adversarial-user", "intermediate")},
        minimum_capability_level="novice",
        projection_context={
            "canonical_ingress": {"entry_point_id": "ep:v1:canonical"},
            "ingress_controllability": "direct",
        },
    )

    assert actor.actor_type == "adversarial-user"
    assert actor.capability_level == "intermediate"
    assert actor.access.ingress_mode == "direct"
    assert actor.access.initial_entry_point_id == "ep:v1:canonical"


def test_direct_actor_inventory_does_not_invent_insider_advantage() -> None:
    actor_types, _, _ = _actor_draft_inventories(
        {
            "compatible_actor_types": [
                "adversarial-user",
                "malicious-insider",
                "negligent-insider",
            ],
            "minimum_capability_level": "novice",
        },
        {
            "ingress_controllability": "direct",
            "selected_steps": [],
        },
        MagicMock(),
    )

    assert set(actor_types.values()) == {"adversarial-user"}
    with pytest.raises(ValueError, match="insider advantage"):
        _derive_canonical_actor_access(
            {
                "canonical_ingress": {"entry_point_id": "ep:v1:canonical"},
                "ingress_controllability": "direct",
            },
            "malicious-insider",
        )


def test_projected_narrative_call_uses_v3_schema_and_compiles_provider_draft(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.generate.narrative.build_call1_context",
        lambda **_kwargs: {"tool_inventory": []},
    )
    monkeypatch.setattr(
        "asago_scenario_generator.pipeline.generate.narrative.render_prompt",
        lambda *_args, **_kwargs: "prompt",
    )
    client = MagicMock(max_completion_tokens=2048)

    def complete(**request):
        response_model = request["response_format"]
        return MagicMock(
            content=response_model(
                title="Payload reaches reasoning",
                summary="A crafted payload crosses the declared ingress.",
                regions={
                    "r0": [
                        {
                            "step_handles": ["s0"],
                            "action": "The actor submits the crafted payload.",
                            "consequence": (
                                "The assistant interprets it as instruction."
                            ),
                        }
                    ]
                },
            )
        )

    client.complete.side_effect = complete
    projection = {
        "canonical_ingress": {"entry_point_id": "ep:v1:canonical"},
        "ingress_controllability": "direct",
        "initial_ingress_slot_id": "ingress",
        "selected_step_ids": ["projected.deliver"],
        "selected_steps": [
            {
                "step_id": "projected.deliver",
                "order": 1,
                "action_kind": "deliver",
                "executor_role": "attacker",
                "boundary_position": "crossing",
                "resource_links": [
                    {
                        "role": "ingress",
                        "slot_id": "ingress",
                        "resource_ref": {
                            "kind": "entry_point",
                            "entry_point_id": "ep:v1:canonical",
                        },
                    }
                ],
                "realization": _realization("projected.deliver", "crossing").model_dump(
                    mode="json"
                ),
            }
        ],
        "source_influence_paths": [],
    }
    actor = compile_actor_draft(
        ActorDraftContext(
            actor_types={"a0": "adversarial-user"},
            capability_levels={"c0": "intermediate"},
            resources={},
            access=ActorAccessProvenance(
                initial_entry_point_id="ep:v1:canonical",
                ingress_mode="direct",
                access_class="public",
            ),
        ),
        ActorDraftV2(
            actor_type_handle="a0",
            capability_level_handle="c0",
            beliefs=["The assistant accepts input."],
            desires=["Change its response."],
            intentions=["Submit a payload."],
        ),
    )
    profile = MagicMock(
        zones_active=["input", "reasoning"],
        has_persistent_memory=False,
        multi_agent=False,
        hitl=False,
        kc_subcodes=[],
    )
    profile.resolve_entry_point.return_value = MagicMock(effective_ingress_zone="input")

    narrative, _ = _call_narrative(
        seed=MagicMock(),
        profile=profile,
        client=client,
        use_case="test",
        actor_profile=actor,
        pinned_entry_point="Chat interface",
        pinned_entry_point_id="ep:v1:canonical",
        projection_context=projection,
    )

    response_model = client.complete.call_args.kwargs["response_format"]
    assert issubclass(response_model, NarrativeDraftV3)
    assert narrative.steps[0].projected_step_ids == ("projected.deliver",)
    assert narrative.steps[0].zone == "input"
    assert narrative.entry_point == "Chat interface"
    assert "Semantic Draft V3" in client.complete.call_args.kwargs["user_prompt"]


# ---------------------------------------------------------------------------#
# Actor draft inventory, compile, and access derivation (CRAP slice 5)
# ---------------------------------------------------------------------------#


def _inventory_context(
    actor_types: list[str] | None = None,
    minimum_capability_level: str = "novice",
) -> dict[str, object]:
    return {
        "compatible_actor_types": actor_types or ["adversarial-user"],
        "minimum_capability_level": minimum_capability_level,
    }


def _inventory_projection(
    selected_steps: list[dict] | None = None,
) -> dict[str, object]:
    return {
        "ingress_controllability": "direct",
        "selected_steps": selected_steps or [],
    }


def _resource_profile() -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {
                "name": "chat",
                "direction": "input",
                "controllability": "direct",
            }
        ],
        confidence="high",
        kc_subcodes=["KC1.1"],
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
    )


def _draft_v2(**overrides) -> ActorDraftV2:
    fields = dict(
        actor_type_handle="a0",
        capability_level_handle="c0",
        beliefs=["The assistant accepts input."],
        desires=["Change its response."],
        intentions=["Submit a payload."],
        resource_handles=[],
    )
    fields.update(overrides)
    return ActorDraftV2(**fields)


def _compile_context(**overrides) -> ActorDraftContext:
    fields = dict(
        actor_types={"a0": "adversarial-user"},
        capability_levels={"c0": "novice", "c1": "intermediate"},
        resources={"r0": "HTTP client"},
        access=ActorAccessProvenance(
            initial_entry_point_id="ep:v1:canonical",
            ingress_mode="direct",
            access_class="public",
        ),
        minimum_capability_level="novice",
        actor_choices={"ac0": ("adversarial-user", "intermediate")},
    )
    fields.update(overrides)
    return ActorDraftContext(**fields)


class TestActorDraftInventories:
    def test_indirect_ingress_keeps_insider_actor_types(self) -> None:
        actor_types, _, _ = _actor_draft_inventories(
            _inventory_context(
                ["adversarial-user", "malicious-insider", "negligent-insider"]
            ),
            {"ingress_controllability": "indirect", "selected_steps": []},
            MagicMock(),
        )

        assert set(actor_types.values()) == {
            "adversarial-user",
            "malicious-insider",
            "negligent-insider",
        }
        assert list(actor_types) == ["a0", "a1", "a2"]

    def test_direct_ingress_with_only_insiders_raises(self) -> None:
        with pytest.raises(
            ValueError, match="no actor type with canonical direct-access provenance"
        ):
            _actor_draft_inventories(
                _inventory_context(["malicious-insider", "negligent-insider"]),
                _inventory_projection(),
                MagicMock(),
            )

    def test_minimum_capability_level_trims_level_inventory(self) -> None:
        _, capability_levels, _ = _actor_draft_inventories(
            _inventory_context(minimum_capability_level="advanced"),
            _inventory_projection(),
            MagicMock(),
        )

        assert list(capability_levels) == ["c0", "c1"]
        assert list(capability_levels.values()) == ["advanced", "expert"]

    def test_unknown_minimum_capability_level_defaults_to_novice(self) -> None:
        _, capability_levels, _ = _actor_draft_inventories(
            _inventory_context(minimum_capability_level="legendary"),
            _inventory_projection(),
            MagicMock(),
        )

        assert list(capability_levels.values()) == [
            "novice",
            "intermediate",
            "advanced",
            "expert",
        ]

    def test_resource_inventory_collects_attacker_controlled_names(self) -> None:
        profile = _resource_profile()
        tool_id = profile.tool_inventory[0].tool_id
        integration_id = profile.external_integrations[0].integration_id
        entry_point_id = profile.entry_points[0].entry_point_id

        _, _, resources = _actor_draft_inventories(
            _inventory_context(),
            {
                "ingress_controllability": "direct",
                "selected_steps": [
                    {
                        "step_id": "step.1",
                        "attacker_controlled": True,
                        "resource_links": [
                            {"resource_ref": {"kind": "agent_internal"}},
                            {"resource_ref": {"kind": "tool", "tool_id": tool_id}},
                        ],
                    },
                    {
                        "step_id": "step.2",
                        "attacker_controlled": True,
                        "resource_links": [
                            {
                                "resource_ref": {
                                    "kind": "integration",
                                    "integration_id": integration_id,
                                }
                            },
                            {
                                "resource_ref": {
                                    "kind": "entry_point",
                                    "entry_point_id": entry_point_id,
                                }
                            },
                        ],
                    },
                ],
            },
            profile,
        )

        assert list(resources) == ["r0", "r1", "r2", "r3"]
        assert list(resources.values()) == [
            "agent internal working context",
            "writer",
            "CRM",
            "chat",
        ]

    def test_resource_inventory_dedupes_and_skips_unbound_refs(self) -> None:
        profile = _resource_profile()
        tool_id = profile.tool_inventory[0].tool_id

        _, _, resources = _actor_draft_inventories(
            _inventory_context(),
            {
                "ingress_controllability": "direct",
                "selected_steps": [
                    {
                        "step_id": "step.1",
                        "attacker_controlled": True,
                        "resource_links": [
                            {"resource_ref": {"kind": "tool", "tool_id": tool_id}},
                            {"resource_ref": {"kind": "tool", "tool_id": tool_id}},
                            {"resource_ref": {"kind": "entry_point"}},
                            {"resource_ref": None},
                            {"resource_ref": "not-a-dict"},
                        ],
                    },
                    {
                        "step_id": "step.2",
                        "attacker_controlled": False,
                        "resource_links": [
                            {"resource_ref": {"kind": "tool", "tool_id": tool_id}}
                        ],
                    },
                ],
            },
            profile,
        )

        assert list(resources.values()) == ["writer"]

    def test_unknown_resource_kind_falls_back_to_resource_id(self) -> None:
        _, _, resources = _actor_draft_inventories(
            _inventory_context(),
            {
                "ingress_controllability": "direct",
                "selected_steps": [
                    {
                        "step_id": "step.1",
                        "attacker_controlled": True,
                        "resource_links": [
                            {
                                "resource_ref": {
                                    "kind": "mystery_surface",
                                    "mystery_surface_id": "surface:1",
                                }
                            }
                        ],
                    }
                ],
            },
            MagicMock(),
        )

        assert list(resources.values()) == ["surface:1"]


class TestCompileActorDraftViolations:
    def test_v2_unknown_actor_type_handle_rejected(self) -> None:
        with pytest.raises(ActorSemanticDraftError) as excinfo:
            compile_actor_draft(_compile_context(), _draft_v2(actor_type_handle="a9"))

        assert [v.code for v in excinfo.value.violations] == [
            "unknown_actor_type_handle"
        ]
        assert "a9" in excinfo.value.violations[0].detail

    def test_v2_unknown_capability_level_handle_rejected(self) -> None:
        with pytest.raises(ActorSemanticDraftError) as excinfo:
            compile_actor_draft(
                _compile_context(), _draft_v2(capability_level_handle="c9")
            )

        assert [v.code for v in excinfo.value.violations] == [
            "unknown_capability_level_handle"
        ]

    def test_v2_capability_below_actor_floor_rejected(self) -> None:
        context = _compile_context(
            actor_types={"a0": "supply-chain-actor"},
            capability_levels={"c0": "novice", "c1": "advanced"},
            minimum_capability_level="novice",
        )

        with pytest.raises(ActorSemanticDraftError) as excinfo:
            compile_actor_draft(context, _draft_v2(capability_level_handle="c0"))

        violation = excinfo.value.violations[0]
        assert violation.code == "capability_below_floor"
        assert "advanced" in violation.detail

    def test_unknown_resource_handles_rejected(self) -> None:
        with pytest.raises(ActorSemanticDraftError) as excinfo:
            compile_actor_draft(_compile_context(), _draft_v2(resource_handles=["r9"]))

        assert [v.code for v in excinfo.value.violations] == ["unknown_resource_handle"]
        assert "['r9']" in excinfo.value.violations[0].detail

    def test_multiple_violations_are_collected_and_joined(self) -> None:
        with pytest.raises(ActorSemanticDraftError) as excinfo:
            compile_actor_draft(
                _compile_context(),
                _draft_v2(actor_type_handle="a9", capability_level_handle="c9"),
            )

        assert [v.code for v in excinfo.value.violations] == [
            "unknown_actor_type_handle",
            "unknown_capability_level_handle",
        ]
        assert "; " in str(excinfo.value)

    def test_v3_choice_handle_resolves_canonical_pair(self) -> None:
        actor = compile_actor_draft(
            _compile_context(),
            ActorDraftV3(
                actor_choice_handle="ac0",
                beliefs=["b"],
                desires=["d"],
                intentions=["i"],
                resource_handles=["r0"],
            ),
        )

        assert actor.actor_type == "adversarial-user"
        assert actor.capability_level == "intermediate"
        assert actor.resources == ["HTTP client"]
        assert actor.access.initial_entry_point_id == "ep:v1:canonical"

    def test_v3_unknown_choice_handle_rejected(self) -> None:
        with pytest.raises(ActorSemanticDraftError) as excinfo:
            compile_actor_draft(
                _compile_context(),
                ActorDraftV3(
                    actor_choice_handle="ac9",
                    beliefs=["b"],
                    desires=["d"],
                    intentions=["i"],
                ),
            )

        assert [v.code for v in excinfo.value.violations] == [
            "unknown_actor_choice_handle"
        ]


class TestDeriveCanonicalActorAccess:
    def test_missing_entry_point_id_rejected(self) -> None:
        with pytest.raises(ValueError, match="lacks a canonical ingress entry-point"):
            _derive_canonical_actor_access({"canonical_ingress": {}}, "attacker")

    def test_missing_controllability_rejected(self) -> None:
        with pytest.raises(
            ValueError, match="lacks attacker-accessible ingress controllability"
        ):
            _derive_canonical_actor_access(
                {"canonical_ingress": {"entry_point_id": "ep:v1:canonical"}},
                "attacker",
            )

    def test_indirect_path_compiles_supply_chain_provenance(self) -> None:
        access = _derive_canonical_actor_access(
            {
                "canonical_ingress": {"entry_point_id": "ep:v1:ingress"},
                "ingress_controllability": "indirect",
                "source_influence_paths": [
                    {
                        "source_id": "ep:v1:source",
                        "source_identity_kind": "entry_point",
                        "boundary_id": "tb:v1:boundary",
                    }
                ],
            },
            "supply-chain-actor",
        )

        assert access.ingress_mode == "indirect"
        assert access.access_class == "supply_chain"
        assert access.initial_entry_point_id == "ep:v1:ingress"
        assert access.influence_source == "ep:v1:source"
        assert access.influence_source_kind == "entry_point"
        assert access.influence_source_id == "ep:v1:source"
        assert access.trust_boundary_id == "tb:v1:boundary"

    def test_indirect_requires_exactly_one_source_path(self) -> None:
        with pytest.raises(ValueError, match="exactly one source-influence path"):
            _derive_canonical_actor_access(
                {
                    "canonical_ingress": {"entry_point_id": "ep:v1:ingress"},
                    "ingress_controllability": "indirect",
                    "source_influence_paths": [
                        {
                            "source_id": "a",
                            "source_identity_kind": "b",
                            "boundary_id": "c",
                        },
                        {
                            "source_id": "d",
                            "source_identity_kind": "e",
                            "boundary_id": "f",
                        },
                    ],
                },
                "supply-chain-actor",
            )

    def test_indirect_incomplete_path_rejected(self) -> None:
        with pytest.raises(ValueError, match="incomplete canonical access path"):
            _derive_canonical_actor_access(
                {
                    "canonical_ingress": {"entry_point_id": "ep:v1:ingress"},
                    "ingress_controllability": "indirect",
                    "source_influence_paths": [
                        {"source_id": "ep:v1:source", "source_identity_kind": None}
                    ],
                },
                "supply-chain-actor",
            )


class TestLegacyActorCallFloors:
    """Legacy Call0Response path: normalization and capability floor hints."""

    @staticmethod
    def _call(
        monkeypatch: pytest.MonkeyPatch,
        capability_level: str,
        min_complexity: str | None = None,
        minimum_capability_level: str = "novice",
        actor_type: str = "supply-chain-actor",
    ):
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.actor.build_call0_context",
            lambda **_kwargs: {
                "tool_inventory": [],
                "minimum_capability_level": minimum_capability_level,
                "compatible_actor_types": [actor_type],
                "diversity_limitation": None,
            },
        )
        monkeypatch.setattr(
            "asago_scenario_generator.pipeline.generate.actor.render_prompt",
            lambda *_args, **_kwargs: "prompt",
        )
        client = MagicMock(max_completion_tokens=2048)
        client.complete.return_value = MagicMock(
            content=Call0Response(
                actor_type=actor_type,
                capability_level=capability_level,
                beliefs=["b"],
                desires=["d"],
                intentions=["i"],
                resources=["r"],
                access_class="public",
            )
        )
        actor, _, _ = _call_actor_profile(
            seed=MagicMock(min_complexity=min_complexity),
            profile=MagicMock(zones_active=[]),
            client=client,
            use_case="test",
            pinned_entry_point_id=None,
            projection_context=None,
        )
        return actor

    def test_actor_floor_bumps_below_floor_capability(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        actor = self._call(monkeypatch, "novice")

        assert actor.capability_level == "advanced"

    def test_estu_floor_bumps_above_actor_floor(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        actor = self._call(
            monkeypatch,
            "advanced",
            minimum_capability_level="expert",
        )

        assert actor.capability_level == "expert"
        assert actor.access is None

    def test_seed_min_complexity_bumps_capability(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        actor = self._call(
            monkeypatch,
            "intermediate",
            min_complexity="expert",
            actor_type="adversarial-user",
        )

        assert actor.capability_level == "expert"
