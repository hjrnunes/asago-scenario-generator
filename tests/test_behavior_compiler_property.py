"""Property tests pinning the deterministic behavior-compiler contracts.

The deterministic BehaviorSpec compiler
(``pipeline/generate/behavior_compiler.py``) owns three contracts worth
pinning under broad input ranges:

- **Leaf filters**: only leaves with non-empty projected step IDs fully
  inside the projection selection are compiled, in DFS order, with
  deterministic text precedence (description > label > node id).
- **Assertion IDs**: the stable ``assert-<step>-<pc>`` scheme, order
  following the projection's selected-step order, descriptions resolving
  from the chain or falling back to raw postcondition IDs.
- **Order preservation**: the rendered Gherkin emits every action then
  every assertion in structure order, and scenario groupings render their
  authored step IDs in order.

These properties are offline and deterministic; they never contact an
LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.attack_pattern import ObservablePostcondition
from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
)
from asago_scenario_generator.models.scenario import (
    BehaviorAction,
    BehaviorAssertion,
    BehaviorScenario,
)
from asago_scenario_generator.pipeline.generate.behavior_compiler import (
    _action_from_leaf,
    _assertions_from_block,
    _leaf_action_text,
    _postcondition_descriptions,
    _projected_leaves,
    _zone_map_for_tree,
    build_behavior_spec_from_tree,
    render_gherkin_from_behavior_spec,
)
from tests.helpers.projection_factory import (
    make_projection_block,
    make_step_realizations,
)

# Projected-step universe from the shared test projection; step-realization
# records can only be derived for these IDs.
_SIDS = ("step.1", "step.2", "step.3")
_ZONES = ("input", "reasoning", "tool_execution")
_PC_IDS = ("post.a", "post.b")
_KNOWN_PC_IDS = _PC_IDS + ("post.zz",)  # post.zz never declared -> fallback
_MAX_EXAMPLES = 60
# Step-text alphabet without parentheses or newlines, so step-line parsing
# (keyword + text, optional " (zone)" suffix) stays unambiguous.
_SAFE_TEXT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _-.,:;!?",
    min_size=0,
    max_size=24,
)


# ---------------------------------------------------------------------------#
# Fixture generators
# ---------------------------------------------------------------------------#


def _leaf_node(
    node_id: str,
    label: str,
    description: str | None,
    zone: str,
    step_ids: tuple[str, ...],
) -> AttackTreeNode:
    """Build a valid projected leaf with exactly matching realizations."""
    return AttackTreeNode(
        id=node_id,
        label=label,
        gate=GateType.LEAF,
        zone=zone,
        action=AiSystemAction(),
        description=description,
        projected_step_ids=step_ids,
        realizations=make_step_realizations(step_ids),
    )


def _dfs_leaf_ids(node: AttackTreeNode) -> list[str]:
    """Independent depth-first leaf walk (mirrors the compiler traversal)."""
    if node.children:
        leaves: list[str] = []
        for child in node.children:
            leaves.extend(_dfs_leaf_ids(child))
        return leaves
    return [node.id]


@st.composite
def projected_trees(draw) -> tuple[AttackTree, list[AttackTreeNode]]:
    """Arbitrary AND trees (one nested level) with unconstrained leaves."""
    top_count = draw(st.integers(min_value=2, max_value=5))
    children: list[AttackTreeNode] = []
    flat_leaves: list[AttackTreeNode] = []
    for i in range(1, top_count + 1):
        step_ids = tuple(
            draw(
                st.lists(
                    st.sampled_from(_SIDS),
                    min_size=0,
                    max_size=3,
                    unique=True,
                )
            )
        )
        label = draw(_SAFE_TEXT)
        description = draw(st.one_of(st.none(), _SAFE_TEXT))
        zone = draw(st.sampled_from(_ZONES))
        if draw(st.booleans()) and top_count >= 3:
            # One nested AND group of 2-3 leaves.
            sub_count = draw(st.integers(min_value=2, max_value=3))
            sub_children: list[AttackTreeNode] = []
            for k in range(1, sub_count + 1):
                sub_steps = tuple(
                    draw(
                        st.lists(
                            st.sampled_from(_SIDS),
                            min_size=0,
                            max_size=3,
                            unique=True,
                        )
                    )
                )
                sub = _leaf_node(
                    f"n1.{i}.{k}",
                    draw(_SAFE_TEXT),
                    draw(st.one_of(st.none(), _SAFE_TEXT)),
                    draw(st.sampled_from(_ZONES)),
                    sub_steps,
                )
                sub_children.append(sub)
                flat_leaves.append(sub)
            children.append(
                AttackTreeNode(
                    id=f"n1.{i}",
                    label=label,
                    gate=GateType.AND,
                    zone=zone,
                    action=None,
                    children=sub_children,
                )
            )
        else:
            leaf = _leaf_node(f"n1.{i}", label, description, zone, step_ids)
            children.append(leaf)
            flat_leaves.append(leaf)
    tree = AttackTree(
        id="tree-AP-T9-01",
        seed_id="AP-T9-01",
        goal="Project leaves deterministically",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            action=None,
            children=children,
        ),
    )
    return tree, flat_leaves


@st.composite
def selected_trees(draw) -> tuple[AttackTree, list[AttackTreeNode], tuple[str, ...]]:
    """Arbitrary trees whose leaves are realizable for the given selection."""
    selected = tuple(
        draw(st.lists(st.sampled_from(_SIDS), min_size=1, max_size=3, unique=True))
    )
    selected = tuple(selected)
    count = draw(st.integers(min_value=2, max_value=5))
    children: list[AttackTreeNode] = []
    flat_leaves: list[AttackTreeNode] = []
    for i in range(1, count + 1):
        step_ids = tuple(
            draw(
                st.lists(
                    st.sampled_from(selected),
                    min_size=0,
                    max_size=3,
                    unique=True,
                )
            )
        )
        leaf = _leaf_node(
            f"n1.{i}",
            draw(_SAFE_TEXT),
            draw(st.one_of(st.none(), _SAFE_TEXT)),
            draw(st.sampled_from(_ZONES)),
            step_ids,
        )
        children.append(leaf)
        flat_leaves.append(leaf)
    tree = AttackTree(
        id="tree-AP-T9-01",
        seed_id="AP-T9-01",
        goal="Compile selected leaves",
        root=AttackTreeNode(
            id="n1",
            label="Root",
            gate=GateType.AND,
            zone="input",
            action=None,
            children=children,
        ),
    )
    return tree, flat_leaves, selected


@st.composite
def chains_with_postconditions(
    draw,
) -> tuple[object, dict[str, list[tuple[str, str, bool]]]]:
    """A canonical chain copy with arbitrary per-step postconditions.

    Returns (chain, pc_spec) where pc_spec maps step_id to
    [(postcondition_id, description, security_relevant)] in authored order.
    """
    base = make_projection_block()
    chain = base.projection.source_chain
    steps = list(chain.steps)
    pc_spec: dict[str, list[tuple[str, str, bool]]] = {}
    new_steps: list[object] = []
    for step in steps:
        pcs = draw(
            st.lists(
                st.tuples(
                    st.sampled_from(_PC_IDS),
                    st.text(min_size=1, max_size=20),
                    st.booleans(),
                ),
                min_size=0,
                max_size=3,
                unique_by=lambda item: item[0],
            )
        )
        pc_spec[step.step_id] = pcs
        new_steps.append(
            step.model_copy(
                update={
                    "observable_postconditions": tuple(
                        ObservablePostcondition(
                            postcondition_id=pc_id,
                            description=description,
                            security_relevant=security_relevant,
                            terminal=False,
                        )
                        for pc_id, description, security_relevant in pcs
                    )
                }
            )
        )
    new_chain = chain.model_copy(update={"steps": tuple(new_steps)})
    return new_chain, pc_spec


@st.composite
def blocks_with_postconditions(
    draw,
) -> tuple[object, dict[str, list[tuple[str, str, bool]]]]:
    """A projection block copy with arbitrary selection and postconditions."""
    base = make_projection_block()
    selected = tuple(
        draw(st.lists(st.sampled_from(_SIDS), min_size=1, max_size=3, unique=True))
    )
    chain, pc_spec = draw(chains_with_postconditions())
    projection = base.projection.model_copy(
        update={"source_chain": chain, "selected_step_ids": selected}
    )
    block = base.model_copy(deep=True, update={"projection": projection})
    return block, pc_spec


@st.composite
def render_inputs(draw) -> tuple[list[BehaviorAction], list[BehaviorAssertion]]:
    """Arbitrary action/assertion lists with text equal to their IDs."""
    n = draw(st.integers(min_value=0, max_value=6))
    m = draw(st.integers(min_value=0, max_value=6))
    keywords = draw(
        st.lists(st.sampled_from(("Given", "When")), min_size=n, max_size=n)
    )
    step_ids = draw(st.lists(st.sampled_from(_SIDS), min_size=n, max_size=n))
    actions: list[BehaviorAction] = []
    for i in range(n):
        actions.append(
            BehaviorAction(
                action_id=f"ba-{i}",
                projected_step_ids=(step_ids[i],),
                source_leaf_id="n1.1",
                gherkin_keyword=keywords[i],
                text=f"ba-{i}",
                realizations=make_step_realizations((step_ids[i],)),
            )
        )
    assertions = [
        BehaviorAssertion(
            assertion_id=f"assert-{i}",
            source_step_ids=("step.1",),
            projected_postcondition_ids=("post.1",),
            gherkin_keyword="Then",
            text=f"assert-{i}",
        )
        for i in range(m)
    ]
    return actions, assertions


def _step_lines(rendered: str) -> list[tuple[str, str]]:
    """Extract (keyword, text) pairs from rendered scenario step lines.

    The informational Background step is ignored: only steps inside a
    ``Scenario:`` section belong to the structured behavior.
    """
    lines: list[tuple[str, str]] = []
    in_scenario = False
    for raw in rendered.splitlines():
        line = raw.strip()
        if line.startswith("Scenario: "):
            in_scenario = True
            continue
        if not in_scenario:
            continue
        for keyword in ("Given ", "When ", "Then ", "And "):
            if line.startswith(keyword):
                lines.append((keyword.strip(), line[len(keyword) :]))
                break
    return lines


# ---------------------------------------------------------------------------#
# Leaf filters
# ---------------------------------------------------------------------------#


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    tree_and_leaves=projected_trees(),
    selected=st.sets(st.sampled_from(_SIDS), max_size=3),
)
def test_projected_leaves_are_sound_complete_and_in_dfs_order(
    tree_and_leaves: tuple[AttackTree, list[AttackTreeNode]],
    selected: set[str],
) -> None:
    """Leaf filter keeps exactly the fully projected, fully selected leaves."""
    tree, flat_leaves = tree_and_leaves
    expected_ids = [
        leaf.id
        for leaf in flat_leaves
        if leaf.projected_step_ids
        and all(step_id in selected for step_id in leaf.projected_step_ids)
    ]

    compiled = _projected_leaves(tree, selected)

    assert [leaf.id for leaf in compiled] == expected_ids
    assert all(leaf.projected_step_ids for leaf in compiled)
    assert all(set(leaf.projected_step_ids) <= selected for leaf in compiled)
    # DFS order: compiled ids are the tree's leaf ids in walk order.
    assert expected_ids == [
        leaf_id for leaf_id in _dfs_leaf_ids(tree.root) if leaf_id in expected_ids
    ]
    # Determinism: the same inputs yield the same leaves.
    assert [leaf.id for leaf in _projected_leaves(tree, selected)] == expected_ids


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    node_id=st.sampled_from(("n1.1", "n1.2", "n1.2.1", "n1.9")),
    label=_SAFE_TEXT,
    description=st.one_of(st.none(), _SAFE_TEXT),
    step_ids=st.lists(st.sampled_from(_SIDS), min_size=1, max_size=2, unique=True),
    zone=st.sampled_from(_ZONES),
)
def test_leaf_action_text_precedence(
    node_id: str,
    label: str,
    description: str | None,
    step_ids: list[str],
    zone: str,
) -> None:
    """Step text prefers description, then label, then the node id."""
    leaf = _leaf_node(node_id, label, description, zone, tuple(step_ids))
    expected = description if description else (label if label else node_id)

    assert _leaf_action_text(leaf) == expected


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    node_id=st.sampled_from(("n1.1", "n1.2", "n1.2.1", "n1.9")),
    label=_SAFE_TEXT,
    description=st.one_of(st.none(), _SAFE_TEXT),
    step_ids=st.lists(st.sampled_from(_SIDS), min_size=1, max_size=2, unique=True),
    zone=st.sampled_from(_ZONES),
)
def test_action_from_leaf_carries_the_leaf_contract(
    node_id: str,
    label: str,
    description: str | None,
    step_ids: list[str],
    zone: str,
) -> None:
    """Every compiled action preserves the leaf's IDs, steps, and records."""
    leaf = _leaf_node(node_id, label, description, zone, tuple(step_ids))

    action = _action_from_leaf(leaf)

    assert action.action_id == f"ba-{leaf.id}"
    assert action.source_leaf_id == leaf.id
    assert action.projected_step_ids == leaf.projected_step_ids
    assert action.realizations == leaf.realizations
    assert action.gherkin_keyword == "When"
    assert action.text == _leaf_action_text(leaf)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(tree_and_leaves=projected_trees())
def test_zone_map_covers_only_projected_zoned_leaves(
    tree_and_leaves: tuple[AttackTree, list[AttackTreeNode]],
) -> None:
    """Zone annotations exist exactly for leaves with steps and a zone."""
    tree, flat_leaves = tree_and_leaves
    zone_map = _zone_map_for_tree(tree)

    expected = {
        f"ba-{leaf.id}": leaf.zone
        for leaf in flat_leaves
        if leaf.projected_step_ids and leaf.zone is not None
    }
    assert zone_map == expected


# ---------------------------------------------------------------------------#
# Assertion IDs
# ---------------------------------------------------------------------------#


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(chain_and_pcs=chains_with_postconditions())
def test_postcondition_descriptions_resolve_or_fallback_to_raw_ids(
    chain_and_pcs: tuple[object, dict[str, list[tuple[str, str, bool]]]],
) -> None:
    """Descriptions resolve from the chain; unknown postcondition IDs stay raw."""
    chain, pc_spec = chain_and_pcs
    step_id = chain.steps[0].step_id
    known = {pc_id: description for pc_id, description, _ in pc_spec[step_id]}

    query = ["post.a", "post.zz", "post.b", "post.never", "post.a"]

    resolved = _postcondition_descriptions(chain, step_id, query)

    assert len(resolved) == len(query)
    assert resolved == [known.get(pc_id, pc_id) for pc_id in query]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(block_and_pcs=blocks_with_postconditions())
def test_assertion_scheme_order_and_text(
    block_and_pcs: tuple[object, dict[str, list[tuple[str, str, bool]]]],
) -> None:
    """One stable-ID assertion per selected step with security postconditions."""
    block, pc_spec = block_and_pcs
    selected = block.projection.selected_step_ids

    assertions = _assertions_from_block(block)

    expected_steps = [
        step_id
        for step_id in selected
        if any(security for _, _, security in pc_spec[step_id])
    ]
    assert [a.source_step_ids for a in assertions] == [
        (step_id,) for step_id in expected_steps
    ]
    for assertion in assertions:
        step_id = assertion.source_step_ids[0]
        sec_pcs = [
            pc_id for pc_id, description, security in pc_spec[step_id] if security
        ]
        descriptions = [
            next(
                description for pc_id, description, _ in pc_spec[step_id] if pc_id == pc
            )
            for pc in sec_pcs
        ]
        assert assertion.assertion_id == f"assert-{step_id}-{'-'.join(sec_pcs)}"
        assert assertion.projected_postcondition_ids == tuple(sec_pcs)
        assert assertion.gherkin_keyword == "Then"
        assert assertion.text == "; ".join(descriptions)
    # No assertions for steps outside the selection, even with security PCs.
    unselected = [step_id for step_id in pc_spec if step_id not in set(selected)]
    assert not any(
        assertion.source_step_ids[0] in set(unselected) for assertion in assertions
    )


# ---------------------------------------------------------------------------#
# Order preservation: deterministic Gherkin rendering
# ---------------------------------------------------------------------------#


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(parts=render_inputs())
def test_legacy_render_preserves_action_then_assertion_order(
    parts: tuple[list[BehaviorAction], list[BehaviorAssertion]],
) -> None:
    """Every action renders once, in order, then every assertion once."""
    actions, assertions = parts
    expected_ids = [a.action_id for a in actions] + [a.assertion_id for a in assertions]

    rendered = render_gherkin_from_behavior_spec(actions, assertions)

    rendered_ids = [text for _, text in _step_lines(rendered)]
    assert rendered_ids == expected_ids
    # Deterministic rendering: same inputs, same text.
    assert render_gherkin_from_behavior_spec(actions, assertions) == rendered


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(parts=render_inputs())
def test_legacy_render_annotates_zones_and_shortens_repeated_keywords(
    parts: tuple[list[BehaviorAction], list[BehaviorAssertion]],
) -> None:
    """Zone suffixes and And-shorthand follow the documented rendering rules."""
    actions, assertions = parts
    zone_map = {
        action.action_id: "input"
        for action in actions[::2]  # arbitrary half of the actions
    }
    zone_map.update(
        {
            action.action_id: "reasoning"
            for i, action in enumerate(actions)
            if i % 3 == 0
        }
    )

    rendered = render_gherkin_from_behavior_spec(actions, assertions, zone_map=zone_map)

    lines = _step_lines(rendered)
    assert len(lines) == len(actions) + len(assertions)
    for position, (keyword, text) in enumerate(lines[: len(actions)]):
        action = actions[position]
        if (
            position == 0
            or actions[position - 1].gherkin_keyword != action.gherkin_keyword
        ):
            assert keyword == action.gherkin_keyword
        else:
            assert keyword == "And"
        if action.action_id in zone_map:
            assert text == f"{action.action_id} ({zone_map[action.action_id]})"
        else:
            assert text == action.action_id
    for position, (keyword, text) in enumerate(lines[len(actions) :]):
        assertion = assertions[position]
        assert keyword == assertion.gherkin_keyword
        assert text == assertion.assertion_id


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(parts=render_inputs())
def test_scenario_render_follows_authored_step_order(
    parts: tuple[list[BehaviorAction], list[BehaviorAssertion]],
) -> None:
    """Each scenario section renders its step IDs in authored order."""
    actions, assertions = parts
    all_ids = [a.action_id for a in actions] + [a.assertion_id for a in assertions]
    scenarios: list[BehaviorScenario] = []
    if not all_ids:
        return  # nothing to render; the legacy path is covered elsewhere
    # Disjoint, ordered slices of the available IDs, including the case
    # of more scenarios than IDs (empty slices are dropped).
    for i in range(3):
        step_ids = tuple(all_ids[i::3])
        if step_ids:
            scenarios.append(
                BehaviorScenario(
                    scenario_id=f"bs-{i}",
                    title=f"Scenario {i}",
                    step_ids=step_ids,
                )
            )

    rendered = render_gherkin_from_behavior_spec(
        actions, assertions, scenarios=scenarios
    )

    sections = _parse_sections(rendered)
    assert [title for title, _ in sections] == [s.title for s in scenarios]
    assert [step_ids for _, step_ids in sections] == [
        list(s.step_ids) for s in scenarios
    ]


def _parse_sections(rendered: str) -> list[tuple[str, list[str]]]:
    """Split rendered text into 'Scenario: <title>' sections with step IDs."""
    sections: list[tuple[str, list[str]]] = []
    current: tuple[str, list[str]] | None = None
    for raw in rendered.splitlines():
        line = raw.strip()
        if line.startswith("Scenario: "):
            current = (line[len("Scenario: ") :], [])
            sections.append(current)
        elif current is not None:
            for keyword in ("Given ", "When ", "Then ", "And "):
                if line.startswith(keyword):
                    current[1].append(line[len(keyword) :].split(" (")[0])
                    break
    return sections


# ---------------------------------------------------------------------------#
# End-to-end compiler determinism and authoritative rendering
# ---------------------------------------------------------------------------#


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(tree_input=selected_trees())
def test_build_behavior_spec_is_deterministic_and_authoritative(
    tree_input: tuple[AttackTree, list[AttackTreeNode], tuple[str, ...]],
) -> None:
    """Compiled actions/assertions match the tree and the rendered text."""
    tree, flat_leaves, selected = tree_input
    base = make_projection_block()
    projection = base.projection.model_copy(update={"selected_step_ids": selected})
    block = base.model_copy(deep=True, update={"projection": projection})

    spec = build_behavior_spec_from_tree(tree, block)
    again = build_behavior_spec_from_tree(tree, block)

    assert spec == again  # deterministic compilation

    expected_action_ids = [
        f"ba-{leaf.id}"
        for leaf in flat_leaves
        if leaf.projected_step_ids
        and all(step_id in set(selected) for step_id in leaf.projected_step_ids)
    ]
    assert [a.action_id for a in spec.actions] == expected_action_ids

    # Security-relevant postconditions of the shared fixture: step.3 -> post.3.
    if "step.3" in set(selected):
        assert [a.assertion_id for a in spec.assertions] == ["assert-step.3-post.3"]
        assert [a.text for a in spec.assertions] == ["observable"]
    else:
        assert spec.assertions == ()

    # Authoritative rendering: every action text appears in order, then
    # every assertion text, exactly once each.
    step_texts = [text.split(" (")[0] for _, text in _step_lines(spec.gherkin_text)]
    assert step_texts == [a.text for a in spec.actions] + [
        a.text for a in spec.assertions
    ]
