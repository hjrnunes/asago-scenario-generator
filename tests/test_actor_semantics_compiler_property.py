"""Property tests pinning the actor semantic compiler contracts.

The deterministic actor-draft compiler
(``pipeline/generate/actor_semantics.py``) owns several contracts worth
pinning under broad input ranges:

- **Handle inventories**: deterministic, unique handles; canonical actor
  types and capability levels only; insider actor types excluded under
  direct ingress; resource names distinct and restricted to
  attacker-controlled steps.
- **Choice inventories**: every compatible actor/capability choice honors
  the actor-type capability floor, every advertised actor and capability
  appears in at least one choice, and no choice is invented when no
  compatible pair exists.
- **Draft compilation**: compiling a provider draft round-trips the
  canonical actor identity, capability level, and resource names, and
  preserves the authored BDI lists verbatim.
- **Typed violations**: unknown handles, below-floor capability pairs, and
  unknown resources raise typed ``ActorSemanticDraftViolation`` codes.
- **Canonical access derivation**: direct ingress yields public access
  without influence fields (and never material insider advantage);
  indirect ingress yields supply-chain access whose typed identity comes
  only from the single authoritative source-influence path.

These properties are offline and deterministic; they never contact an
LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
)
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
)
from asago_scenario_generator.pipeline.generate.actor_rules import (
    _ep_controllability_to_ingress_mode,
)
from asago_scenario_generator.pipeline.generate.actor_semantics import (
    ActorDraftContext,
    ActorDraftV2,
    ActorDraftV3,
    ActorSemanticDraftError,
    _actor_choice_inventory,
    _actor_draft_inventories,
    _capability_level_inventory,
    _derive_canonical_actor_access,
    compile_actor_draft,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _CAPABILITY_FLOORS,
    _CAPABILITY_ORDER,
    _INSIDER_ACTOR_TYPES,
    ALL_ACTOR_TYPES,
)

_MAX_EXAMPLES = 60
_IDS = st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._", min_size=1, max_size=16)
_BDI_TEXT = st.text(alphabet="abcdefghijklmnopqrstuvwxyz 0123456789", min_size=1, max_size=40)


def _minimal_profile() -> CapabilityProfile:
    """A valid but bare capability profile for name lookups."""
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            EntryPoint(name="chat", direction="input", controllability="direct")
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


def _required_floor(actor_type: str) -> str:
    """Actor capability floor used by the choice and compile contracts."""
    return _CAPABILITY_FLOORS.get(actor_type, "novice")


def _order_index(level: str) -> int:
    return _CAPABILITY_ORDER.index(level)


@st.composite
def inventory_inputs(draw) -> tuple[dict[str, object], dict[str, object]]:
    """Arbitrary prompt/projection contexts for one actor request."""
    compatible = draw(
        st.lists(
            st.sampled_from(tuple(sorted(ALL_ACTOR_TYPES))),
            min_size=1,
            max_size=6,
            unique=True,
        )
    )
    controllability = draw(
        st.sampled_from(("direct", "indirect", "system", None))
    )
    minimum = draw(st.sampled_from((*_CAPABILITY_ORDER, "unknown-level")))
    steps: list[dict[str, object]] = []
    for _ in range(draw(st.integers(min_value=0, max_value=5))):
        refs: list[dict[str, object]] = []
        for _ in range(draw(st.integers(min_value=0, max_value=3))):
            kind = draw(
                st.sampled_from(
                    ("tool", "integration", "entry_point", "agent_internal", "mystery")
                )
            )
            ref: dict[str, object] = {"kind": kind}
            if kind != "agent_internal":
                ref[f"{kind}_id"] = draw(_IDS)
            refs.append({"resource_ref": ref})
        steps.append(
            {
                "attacker_controlled": draw(st.booleans()),
                "resource_links": refs,
            }
        )
    prompt_context: dict[str, object] = {
        "compatible_actor_types": compatible,
        "minimum_capability_level": minimum,
    }
    projection_context: dict[str, object] = {
        "ingress_controllability": controllability,
        "selected_steps": steps,
    }
    return prompt_context, projection_context


@st.composite
def draft_compile_inputs(
    draw,
) -> tuple[ActorDraftContext, tuple[str, ...], list[str], list[str], list[str]]:
    """A context plus a valid handle subset for a round-trip compilation.

    Returns (context, resource_handles, beliefs, desires, intentions).
    """
    actor_type = draw(st.sampled_from(tuple(sorted(ALL_ACTOR_TYPES))))
    minimum = draw(st.sampled_from(_CAPABILITY_ORDER))
    required = _required_floor(actor_type)
    required_index = max(_order_index(required), _order_index(minimum))
    capability_level = draw(
        st.sampled_from(_CAPABILITY_ORDER[required_index:])
    )
    resource_names = draw(
        st.lists(_IDS, min_size=0, max_size=4, unique=True)
    )
    resources = {f"r{i}": name for i, name in enumerate(resource_names)}
    if resources:
        resource_handles = draw(
            st.lists(
                st.sampled_from(tuple(resources)),
                min_size=0,
                max_size=len(resources),
                unique=True,
            )
        )
    else:
        resource_handles = []
    beliefs = draw(st.lists(_BDI_TEXT, min_size=1, max_size=3))
    desires = draw(st.lists(_BDI_TEXT, min_size=1, max_size=3))
    intentions = draw(st.lists(_BDI_TEXT, min_size=1, max_size=3))
    access = ActorAccessProvenance(
        initial_entry_point_id="ep-1",
        ingress_mode="direct",
        access_class="public",
    )
    context = ActorDraftContext(
        actor_types={"a0": actor_type},
        capability_levels={"c0": capability_level},
        resources=resources,
        access=access,
        minimum_capability_level=minimum,
        actor_choices={"ac0": (actor_type, capability_level)},
    )
    return context, tuple(resource_handles), beliefs, desires, intentions


@st.composite
def violating_drafts(
    draw,
) -> tuple[
    ActorDraftContext, str, ActorDraftV2 | ActorDraftV3
]:
    """A valid context plus a single-axis violating provider draft.

    The variant is one of: below_floor, unknown_actor_type,
    unknown_capability, unknown_resource, unknown_actor_choice.
    """
    actor_type = draw(
        st.sampled_from(
            tuple(
                sorted(
                    actor
                    for actor in ALL_ACTOR_TYPES
                    if _order_index(_required_floor(actor)) >= _order_index(
                        "intermediate"
                    )
                )
            )
        )
    )
    minimum = "novice"
    capability_level = "expert"
    resources = {"r0": "res-0"}
    access = ActorAccessProvenance(
        initial_entry_point_id="ep-1",
        ingress_mode="direct",
        access_class="public",
    )
    context = ActorDraftContext(
        actor_types={"a0": actor_type},
        capability_levels={"c0": capability_level, "c1": "novice"},
        resources=resources,
        access=access,
        minimum_capability_level=minimum,
        actor_choices={"ac0": (actor_type, capability_level)},
    )
    variant = draw(
        st.sampled_from(
            (
                "below_floor",
                "unknown_actor_type",
                "unknown_capability",
                "unknown_resource",
                "unknown_actor_choice",
            )
        )
    )
    if variant == "below_floor":
        draft: ActorDraftV2 | ActorDraftV3 = ActorDraftV2(
            actor_type_handle="a0",
            capability_level_handle="c1",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resource_handles=[],
        )
    elif variant == "unknown_actor_type":
        draft = ActorDraftV2(
            actor_type_handle="zz",
            capability_level_handle="c0",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resource_handles=[],
        )
    elif variant == "unknown_capability":
        draft = ActorDraftV2(
            actor_type_handle="a0",
            capability_level_handle="zz",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resource_handles=[],
        )
    elif variant == "unknown_resource":
        draft = ActorDraftV2(
            actor_type_handle="a0",
            capability_level_handle="c0",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resource_handles=["zz"],
        )
    else:
        draft = ActorDraftV3(
            actor_choice_handle="zz",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resource_handles=[],
        )
    return context, variant, draft


@st.composite
def access_derivation_inputs(
    draw,
) -> tuple[dict[str, object], str]:
    """A projection context plus the actor type to derive access for."""
    actor_type = draw(st.sampled_from(tuple(sorted(ALL_ACTOR_TYPES))))
    entry_point_id = draw(_IDS)
    controllability = draw(
        st.sampled_from(("direct", "indirect", "system", None, ""))
    )
    path_count = draw(st.integers(min_value=0, max_value=2))
    complete = draw(st.booleans())
    paths: list[dict[str, object]] = []
    for index in range(path_count):
        path: dict[str, object] = {
            "source_id": f"src-{index}",
            "source_identity_kind": "entry_point",
            "boundary_id": f"tb-{index}",
        }
        if not complete:
            del path["boundary_id"]
        paths.append(path)
    projection_context: dict[str, object] = {
        "canonical_ingress": {"entry_point_id": entry_point_id},
        "ingress_controllability": controllability,
        "source_influence_paths": paths,
    }
    return projection_context, actor_type


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=inventory_inputs())
def test_actor_draft_inventories_are_deterministic_unique_and_canonical(
    inputs: tuple[dict[str, object], dict[str, object]],
) -> None:
    """Inventories stay deterministic, unique, and canonically bounded."""
    prompt_context, projection_context = inputs
    expected_actors = [
        actor
        for actor in prompt_context["compatible_actor_types"]
        if not (
            projection_context.get("ingress_controllability") == "direct"
            and actor in _INSIDER_ACTOR_TYPES
        )
    ]
    minimum = str(prompt_context["minimum_capability_level"])
    minimum_index = (
        _order_index(minimum) if minimum in _CAPABILITY_ORDER else 0
    )
    try:
        actor_types, capability_levels, resources = _actor_draft_inventories(
            prompt_context, projection_context, _minimal_profile()
        )
    except ValueError:
        # Direct ingress with only insider actors has no canonical pool.
        assert not expected_actors
        assert projection_context.get("ingress_controllability") == "direct"
        return

    assert expected_actors, "direct ingress must not exhaust the actor pool"
    # Deterministic allocation: the same request shape yields the same maps.
    again = _actor_draft_inventories(
        prompt_context, projection_context, _minimal_profile()
    )
    assert again == (actor_types, capability_levels, resources)

    assert len(actor_types) == len(set(actor_types)) == len(expected_actors)
    assert set(actor_types.values()) <= set(ALL_ACTOR_TYPES)
    if projection_context.get("ingress_controllability") == "direct":
        assert not set(actor_types.values()) & _INSIDER_ACTOR_TYPES

    assert len(capability_levels) == len(set(capability_levels))
    assert set(capability_levels.values()) <= set(_CAPABILITY_ORDER)
    assert tuple(capability_levels.values()) == tuple(
        _CAPABILITY_ORDER[minimum_index:]
    )

    assert len(resources) == len(set(resources.values()))
    assert all(isinstance(name, str) for name in resources.values())
    assert all(
        handle.startswith("a") or handle.startswith("c") or handle.startswith("r")
        for handle in (*actor_types, *capability_levels, *resources)
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    actors=st.lists(
        st.sampled_from(tuple(sorted(ALL_ACTOR_TYPES))),
        min_size=1,
        max_size=6,
        unique=True,
    ),
    levels=st.lists(
        st.sampled_from(tuple(_CAPABILITY_ORDER)),
        min_size=1,
        max_size=4,
        unique=True,
    ),
)
def test_actor_choice_inventory_floor_compliance_coverage_and_determinism(
    actors: list[str],
    levels: list[str],
) -> None:
    """Choices only admit viable pairs and never strand an inventory item."""
    actor_types = {f"a{i}": actor for i, actor in enumerate(actors)}
    capability_levels = {f"c{i}": level for i, level in enumerate(levels)}
    try:
        choices = _actor_choice_inventory(actor_types, capability_levels)
    except ValueError:
        # No pair clears the actor floor: nothing compatible was invented.
        assert not any(
            _order_index(level) >= _order_index(_required_floor(actor))
            for actor in actors
            for level in levels
        )
        return

    assert choices, "non-empty inventories must advertise at least one choice"
    assert len(choices) == len(set(choices))
    for handle, (actor, capability) in choices.items():
        assert handle.startswith("ac")
        assert _order_index(capability) >= _order_index(_required_floor(actor))
    chosen_actors = {actor for actor, _ in choices.values()}
    chosen_levels = {capability for _, capability in choices.values()}
    # Coverage holds exactly for actors with a reachable floor and levels
    # at or above the cheapest reachable floor; below-floor levels are
    # legitimately never advertised.
    highest_level = max(_order_index(level) for level in levels)
    cheapest_floor = min(_order_index(_required_floor(actor)) for actor in actors)
    assert chosen_actors == {
        actor
        for actor in actors
        if _order_index(_required_floor(actor)) <= highest_level
    }
    assert chosen_levels == {
        level
        for level in levels
        if _order_index(level) >= cheapest_floor
    }
    # Deterministic allocation: the same inventories yield the same choices.
    assert choices == _actor_choice_inventory(actor_types, capability_levels)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(minimum=st.sampled_from((*_CAPABILITY_ORDER, "unknown-level")))
def test_capability_level_inventory_starts_at_the_minimum_floor(
    minimum: str,
) -> None:
    """The capability inventory is contiguous from the minimum floor onward."""
    minimum_index = _order_index(minimum) if minimum in _CAPABILITY_ORDER else 0
    expected = {
        f"c{i}": level for i, level in enumerate(_CAPABILITY_ORDER[minimum_index:])
    }

    inventory = _capability_level_inventory({"minimum_capability_level": minimum})

    assert inventory == expected
    assert inventory == _capability_level_inventory(
        {"minimum_capability_level": minimum}
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=draft_compile_inputs())
def test_compile_actor_draft_round_trips_canonical_identity_and_bdi(
    inputs: tuple[
        ActorDraftContext, tuple[str, ...], list[str], list[str], list[str]
    ],
) -> None:
    """Every valid draft compiles to the canonical pair, resources, and BDI."""
    context, resource_handles, beliefs, desires, intentions = inputs
    v2 = ActorDraftV2(
        actor_type_handle="a0",
        capability_level_handle="c0",
        beliefs=beliefs,
        desires=desires,
        intentions=intentions,
        resource_handles=list(resource_handles),
    )
    v3 = ActorDraftV3(
        actor_choice_handle="ac0",
        beliefs=beliefs,
        desires=desires,
        intentions=intentions,
        resource_handles=list(resource_handles),
    )
    for draft in (v2, v3):
        profile = compile_actor_draft(context, draft)
        assert profile.actor_type == context.actor_types["a0"]
        assert profile.capability_level == context.capability_levels["c0"]
        assert profile.resources == [
            context.resources[handle] for handle in resource_handles
        ]
        assert profile.beliefs == beliefs
        assert profile.desires == desires
        assert profile.intentions == intentions
        # Access provenance is inherited as an independent deep copy.
        assert profile.access == context.access
        assert profile.access is not context.access
        # Deterministic compilation: the same draft yields the same profile.
        assert compile_actor_draft(context, draft) == profile


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=violating_drafts())
def test_compile_actor_draft_raises_typed_violations(
    inputs: tuple[ActorDraftContext, str, ActorDraftV2 | ActorDraftV3],
) -> None:
    """Each violation axis raises its documented typed violation code."""
    context, variant, draft = inputs
    expected_codes = {
        "below_floor": {"capability_below_floor"},
        "unknown_actor_type": {"unknown_actor_type_handle"},
        "unknown_capability": {"unknown_capability_level_handle"},
        "unknown_resource": {"unknown_resource_handle"},
        "unknown_actor_choice": {"unknown_actor_choice_handle"},
    }[variant]

    def codes() -> set[str]:
        try:
            compile_actor_draft(context, draft)
        except ActorSemanticDraftError as error:
            return {violation.code for violation in error.violations}
        raise AssertionError(f"expected ActorSemanticDraftError for {variant}")

    assert codes() == expected_codes
    assert codes() == expected_codes  # deterministic violation reporting


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=access_derivation_inputs())
def test_derive_canonical_actor_access_follows_projection_ownership(
    inputs: tuple[dict[str, object], str],
) -> None:
    """Access provenance is derived only from the accepted projection."""
    projection_context, actor_type = inputs
    controllability = projection_context.get("ingress_controllability")
    paths = projection_context["source_influence_paths"]
    assert isinstance(paths, list)
    entry_point_id = projection_context["canonical_ingress"]["entry_point_id"]
    assert isinstance(entry_point_id, str)

    def derive() -> ActorAccessProvenance:
        return _derive_canonical_actor_access(projection_context, actor_type)

    if controllability != "direct" and controllability != "indirect":
        for target in (actor_type, "cybercriminal"):
            try:
                _derive_canonical_actor_access(projection_context, target)
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"unknown controllability {controllability!r} must fail"
                )
        return

    if controllability == "direct":
        if actor_type in _INSIDER_ACTOR_TYPES:
            try:
                derive()
            except ValueError as error:
                assert "insider" in str(error)
            else:
                raise AssertionError("direct insider access must fail")
            return
        access = derive()
        assert access == ActorAccessProvenance(
            initial_entry_point_id=entry_point_id,
            ingress_mode="direct",
            access_class="public",
        )
        assert access.influence_source is None
        assert access.influence_source_id is None
        assert access.trust_boundary_id is None
        assert access.material_insider_advantage is None
        assert derive() == access
        return

    complete_paths = [
        path
        for path in paths
        if isinstance(path, dict)
        and all(
            isinstance(path.get(key), str)
            for key in ("source_id", "source_identity_kind", "boundary_id")
        )
    ]
    if len(complete_paths) != 1:
        for _ in (0, 1):
            try:
                derive()
            except ValueError:
                pass
            else:
                raise AssertionError(
                    f"indirect access with {len(complete_paths)} paths must fail"
                )
        return
    path = complete_paths[0]
    access = derive()
    assert access.ingress_mode == "indirect"
    assert access.access_class == "supply_chain"
    assert access.influence_source == path["source_id"]
    assert access.influence_source_kind == path["source_identity_kind"]
    assert access.influence_source_id == path["source_id"]
    assert access.trust_boundary_id == path["boundary_id"]
    assert derive() == access
    # The ingress mode mapping is the same one used by the access policy.
    assert access.ingress_mode == _ep_controllability_to_ingress_mode(
        controllability
    )
