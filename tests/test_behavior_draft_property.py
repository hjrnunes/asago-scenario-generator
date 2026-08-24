"""Property tests pinning the behavior-draft validation contracts.

The deterministic behavior-draft validator
(``pipeline/generate/behavior_semantics.py``) owns three contracts worth
pinning under broad input ranges:

- **Order judgment at exact coverage**: a draft that authors every action
  and assertion exactly once is accepted if and only if the authored
  action order preserves the canonical projected-step order; otherwise it
  produces exactly one ``illegal_order`` violation.
- **Coverage gate**: unknown or duplicate handles are reported with their
  membership codes and suppress order judgment, so ordering is never
  judged over a corrupted handle sequence.
- **Parameter contract**: for arbitrary action parameter specs and example
  values, the unknown/missing/invalid-example-type violation codes fire
  exactly when the corresponding mismatch exists.
- **Shared membership core**: the ``_handle_membership_violations`` helper
  shared with tree drafts reports unknown and duplicate handles exactly,
  and nothing else at exact coverage.

These properties are offline and deterministic; they never contact an
LLM endpoint.
"""

from __future__ import annotations

from collections import Counter
from typing import Any

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.scenario import BehaviorAction
from asago_scenario_generator.pipeline.generate.behavior_semantics import (
    ActionHandle,
    AssertionHandle,
    BehaviorCompilationContext,
    BehaviorDraftStep,
    BehaviorDraftV2,
    BehaviorParameterSpec,
    BehaviorScenarioDraft,
    _example_matches,
    _step_parameter_violations,
    validate_behavior_draft,
)
from asago_scenario_generator.pipeline.generate.tree_semantics import (
    _handle_membership_violations,
)
from tests.helpers.projection_factory import make_step_realizations

_MAX_EXAMPLES = 60
_STEP_IDS = ("step.1", "step.2", "step.3")
_PARAMETER_NAMES = ("p0", "p1", "p2", "p3", "p4")
_VALUE_TYPES = ("string", "integer", "number", "boolean")
_EXAMPLE_KEYS = _PARAMETER_NAMES + ("x0", "x1", "x2")


def _canonical_order(action_count: int) -> tuple[str, ...]:
    return tuple(f"a{i}" for i in range(action_count))


def _make_context(
    action_count: int, assertion_count: int
) -> BehaviorCompilationContext:
    """A context where every assertion step is owned by exactly one action."""
    actions = tuple(
        ActionHandle(
            handle=f"a{i}",
            action=BehaviorAction(
                action_id=f"ba-{i}",
                projected_step_ids=(_STEP_IDS[i],),
                source_leaf_id="n1.1",
                gherkin_keyword="When",
                text="t",
                realizations=make_step_realizations((_STEP_IDS[i],)),
            ),
            parameters=(),
            zone="input",
        )
        for i in range(action_count)
    )
    assertions = tuple(
        AssertionHandle(
            handle=f"p{j}",
            assertion_id=f"assert-{j}",
            source_step_id=_STEP_IDS[j % action_count],
            postcondition_id=f"pc-{j}",
            description="d",
        )
        for j in range(assertion_count)
    )
    return BehaviorCompilationContext(
        action_handles=actions, assertion_handles=assertions
    )


@st.composite
def exact_drafts(draw) -> tuple[BehaviorDraftV2, BehaviorCompilationContext]:
    """An exact-coverage draft with an arbitrary authored handle order."""
    action_count = draw(st.integers(min_value=1, max_value=3))
    assertion_count = draw(st.integers(min_value=1, max_value=6))
    handles = [f"a{i}" for i in range(action_count)] + [
        f"p{j}" for j in range(assertion_count)
    ]
    ordered = tuple(draw(st.permutations(handles)))
    scenario_count = draw(
        st.integers(min_value=1, max_value=min(3, len(ordered)))
    )
    cut_count = scenario_count - 1
    cuts = sorted(
        draw(
            st.lists(
                st.integers(min_value=1, max_value=len(ordered) - 1),
                min_size=cut_count,
                max_size=cut_count,
                unique=True,
            )
        )
    )
    boundaries = [0, *cuts, len(ordered)]
    scenarios = tuple(
        BehaviorScenarioDraft(
            title=f"S{index}",
            steps=tuple(
                BehaviorDraftStep(
                    kind="action" if handle.startswith("a") else "assertion",
                    handle=handle,
                    text="t",
                )
                for handle in ordered[boundaries[index] : boundaries[index + 1]]
            ),
        )
        for index in range(scenario_count)
    )
    context = _make_context(action_count, assertion_count)
    return BehaviorDraftV2(scenarios=scenarios), context


@st.composite
def mutated_drafts(
    draw,
) -> tuple[
    BehaviorDraftV2, BehaviorCompilationContext, tuple[str, ...], str
]:
    """An exact-coverage draft mutated by one membership defect."""
    action_count = draw(st.integers(min_value=1, max_value=3))
    assertion_count = draw(st.integers(min_value=1, max_value=6))
    handles = [f"a{i}" for i in range(action_count)] + [
        f"p{j}" for j in range(assertion_count)
    ]
    ordered = list(draw(st.permutations(handles)))
    mutation = draw(st.sampled_from(("duplicate", "unknown", "drop")))
    if mutation == "duplicate":
        ordered.append("a0")
    elif mutation == "unknown":
        ordered[-1] = "x9"
    else:
        for index in range(len(ordered) - 1, -1, -1):
            if ordered[index].startswith("a"):
                del ordered[index]
                break
    mutated = tuple(ordered)
    scenarios = (
        BehaviorScenarioDraft(
            title="S0",
            steps=tuple(
                BehaviorDraftStep(
                    kind="action" if handle.startswith("a") else "assertion",
                    handle=handle,
                    text="t",
                )
                for handle in mutated
            ),
        ),
    )
    context = _make_context(action_count, assertion_count)
    return BehaviorDraftV2(scenarios=scenarios), context, mutated, mutation


@st.composite
def parameter_contracts(
    draw,
) -> tuple[
    BehaviorDraftStep,
    tuple[BehaviorParameterSpec, ...],
    set[str],
]:
    """A step with arbitrary examples against arbitrary parameter specs."""
    spec_names = draw(
        st.lists(
            st.sampled_from(_PARAMETER_NAMES),
            min_size=0,
            max_size=5,
            unique=True,
        )
    )
    specs = tuple(
        BehaviorParameterSpec(
            name=name,
            value_type=draw(st.sampled_from(_VALUE_TYPES)),  # type: ignore[arg-type]
            required=draw(st.booleans()),
        )
        for name in spec_names
    )
    example_keys = draw(
        st.lists(
            st.sampled_from(_EXAMPLE_KEYS),
            min_size=0,
            max_size=6,
            unique=True,
        )
    )
    examples: dict[str, Any] = {}
    for key in example_keys:
        examples[key] = draw(
            st.one_of(
                st.text(alphabet="abcdef0123456789", min_size=1, max_size=8),
                st.integers(min_value=-9, max_value=9),
                st.floats(min_value=-9.0, max_value=9.0, allow_nan=False),
                st.booleans(),
            )
        )
    step = BehaviorDraftStep(
        kind="action", handle="a0", text="t", examples=examples
    )
    return step, specs, set(examples)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(draft_and_context=exact_drafts())
def test_behavior_draft_accepts_exactly_the_canonical_action_order(
    draft_and_context: tuple[BehaviorDraftV2, BehaviorCompilationContext],
) -> None:
    """Exact coverage is accepted iff authored action order is canonical."""
    draft, context = draft_and_context
    action_handles = {item.handle for item in context.action_handles}
    authored_action_order = tuple(
        step.handle
        for scenario in draft.scenarios
        for step in scenario.steps
        if step.handle in action_handles
    )
    expected_actions = tuple(item.handle for item in context.action_handles)
    in_order = authored_action_order == expected_actions

    result = validate_behavior_draft(draft, context)

    assert result.accepted == in_order
    if in_order:
        assert result.violations == ()
    else:
        assert len(result.violations) == 1
        assert result.violations[0].code == "illegal_order"
        assert result.violations[0].handles == authored_action_order
    # Deterministic validation: the same draft yields the same verdict.
    again = validate_behavior_draft(draft, context)
    assert [
        (v.code, v.handles, v.message) for v in again.violations
    ] == [(v.code, v.handles, v.message) for v in result.violations]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=mutated_drafts())
def test_behavior_draft_membership_defects_are_reported_exactly(
    inputs: tuple[
        BehaviorDraftV2, BehaviorCompilationContext, tuple[str, ...], str
    ],
) -> None:
    """Unknown/duplicate/missing codes fire exactly; order is gated on them."""
    draft, context, actual, mutation = inputs
    expected_handles = tuple(
        item.handle
        for item in (*context.action_handles, *context.assertion_handles)
    )
    counts = Counter(actual)
    expected_unknown = tuple(sorted(set(actual) - set(expected_handles)))
    expected_duplicates = tuple(
        sorted(handle for handle, count in counts.items() if count > 1)
    )
    expected_missing = tuple(
        sorted(handle for handle in expected_handles if counts[handle] == 0)
    )
    expected_codes: set[str] = set()
    if expected_unknown:
        expected_codes.add("unknown_handle")
    if expected_duplicates:
        expected_codes.add("duplicate_handle")
    if expected_missing:
        expected_codes.add("missing_handle")
    action_handles = {item.handle for item in context.action_handles}
    authored_action_order = tuple(
        step.handle
        for scenario in draft.scenarios
        for step in scenario.steps
        if step.handle in action_handles
    )
    if (
        not expected_unknown
        and not expected_duplicates
        and authored_action_order
        != tuple(item.handle for item in context.action_handles)
    ):
        expected_codes.add("illegal_order")

    result = validate_behavior_draft(draft, context)

    assert {violation.code for violation in result.violations} == expected_codes
    assert result.accepted == (not expected_codes)
    assert mutation == "duplicate" or mutation == "unknown" or mutation == "drop"
    # Deterministic validation: the same draft yields the same verdict.
    assert [v.code for v in validate_behavior_draft(draft, context).violations] == [
        v.code for v in result.violations
    ]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    expected=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=8),
        min_size=1,
        max_size=6,
        unique=True,
    ),
    actual=st.lists(
        st.text(alphabet="abcdefghijklmnopqrstuvwxyz0123456789", min_size=1, max_size=8),
        min_size=0,
        max_size=8,
    ),
)
def test_shared_handle_membership_core_is_exact(
    expected: list[str], actual: list[str]
) -> None:
    """The tree/behavior shared membership pass reports exactly its defects."""
    violations, unknown, duplicates = _handle_membership_violations(
        tuple(expected), tuple(actual), "probe"
    )
    counts = Counter(actual)
    assert unknown == tuple(sorted(set(actual) - set(expected)))
    assert duplicates == tuple(
        sorted(handle for handle, count in counts.items() if count > 1)
    )
    assert {violation.code for violation in violations} == {
        code
        for code, present in (
            ("unknown_handle", bool(unknown)),
            ("duplicate_handle", bool(duplicates)),
        )
        if present
    }
    # Deterministic reporting: the same sequence yields the same defects.
    again = _handle_membership_violations(tuple(expected), tuple(actual), "probe")
    assert [(v.code, v.handles) for v in again[0]] == [
        (v.code, v.handles) for v in violations
    ]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=parameter_contracts())
def test_step_parameter_violations_match_the_example_contract(
    inputs: tuple[
        BehaviorDraftStep, tuple[BehaviorParameterSpec, ...], set[str]
    ],
) -> None:
    """Parameter violations fire exactly for unknown, missing, and invalid."""
    step, specs, example_keys = inputs
    spec_by_name = {spec.name: spec for spec in specs}
    action = ActionHandle(
        handle="a0",
        action=BehaviorAction(
            action_id="ba-0",
            projected_step_ids=("step.1",),
            source_leaf_id="n1.1",
            gherkin_keyword="When",
            text="t",
            realizations=make_step_realizations(("step.1",)),
        ),
        parameters=specs,
        zone="input",
    )

    expected_codes: set[str] = set()
    if example_keys - set(spec_by_name):
        expected_codes.add("unknown_example_parameter")
    if {
        name for name, spec in spec_by_name.items() if spec.required
    } - example_keys:
        expected_codes.add("missing_example_parameter")
    if {
        name
        for name, value in step.examples.items()
        if name in spec_by_name
        and not _example_matches(value, spec_by_name[name].value_type)
    }:
        expected_codes.add("invalid_example_type")

    violations = _step_parameter_violations(step, action)

    assert {violation.code for violation in violations} == expected_codes
    # Deterministic reporting: the same step yields the same violations.
    again = _step_parameter_violations(step, action)
    assert [(v.code, v.handles) for v in again] == [
        (v.code, v.handles) for v in violations
    ]
