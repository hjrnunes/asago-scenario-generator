"""Semantic draft/compiler contracts for actor and narrative generation."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from unittest.mock import MagicMock

from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import ActorAccessProvenance
from asago_scenario_generator.pipeline.generate.actor import (
    ActorDraftContext,
    ActorDraftV2,
    compile_actor_draft,
    create_actor_draft_model,
    _call_actor_profile,
    _actor_draft_inventories,
    _derive_canonical_actor_access,
)
from asago_scenario_generator.pipeline.generate.narrative import (
    NarrativeDraftContext,
    NarrativeDraftV2,
    NarrativeProjectedStep,
    NarrativeSemanticDraftError,
    compile_narrative_draft,
    create_narrative_draft_model,
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


def test_projected_actor_call_uses_v2_schema_and_compiles_provider_draft(
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
                actor_type_handle="a0",
                capability_level_handle="c0",
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
    )

    response_model = client.complete.call_args.kwargs["response_format"]
    assert issubclass(response_model, ActorDraftV2)
    assert actor.actor_type == "adversarial-user"
    assert actor.capability_level == "intermediate"
    assert actor.access is not None
    assert actor.access.initial_entry_point_id == "ep:v1:canonical"
    assert "Semantic Draft V2" in client.complete.call_args.kwargs["user_prompt"]


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


def test_projected_narrative_call_uses_v2_schema_and_compiles_provider_draft(
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
                beats=[
                    {
                        "step_handles": ["s0"],
                        "action": "The actor submits the crafted payload.",
                        "consequence": "The assistant interprets it as instruction.",
                    }
                ],
            )
        )

    client.complete.side_effect = complete
    projection = {
        "canonical_ingress": {"entry_point_id": "ep:v1:canonical"},
        "ingress_controllability": "direct",
        "selected_step_ids": ["projected.deliver"],
        "selected_steps": [
            {
                "step_id": "projected.deliver",
                "order": 1,
                "action_kind": "deliver",
                "boundary_position": "crossing",
                "resource_links": [],
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
    assert issubclass(response_model, NarrativeDraftV2)
    assert narrative.steps[0].projected_step_ids == ("projected.deliver",)
    assert narrative.steps[0].zone == "input"
    assert narrative.entry_point == "Chat interface"
    assert "Semantic Draft V2" in client.complete.call_args.kwargs["user_prompt"]
