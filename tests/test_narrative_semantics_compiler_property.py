"""Property tests pinning the narrative semantic compiler contracts.

The deterministic narrative-draft compiler
(``pipeline/generate/narrative_semantics.py``) owns several contracts worth
pinning under broad input ranges:

- **Context construction**: ordered handles are unique, match the projected
  inventory, resolve to unique canonical IDs, and keep regions contiguous.
- **Draft compilation**: a valid V2 or V3 draft preserves authored
  causality, attaches projection-owned IDs/zones/realizations, and
  inherits access realization as an independent copy.
- **Title fallback**: omitted titles use the context fallback only when
  presentation fallback is allowed.
- **Typed violations**: missing, unknown, duplicate, and out-of-order
  handles, mixed zones or boundaries, and missing titles raise typed
  ``NarrativeDraftViolation`` codes.

These properties are offline and deterministic; they never contact an
LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.scenario import NarrativeAccessRealization
from asago_scenario_generator.pipeline.generate.narrative_semantics import (
    NarrativeCausalBeatV2,
    NarrativeDraftContext,
    NarrativeDraftV2,
    NarrativeDraftV3,
    NarrativeProjectedStep,
    NarrativeSemanticDraftError,
    compile_narrative_draft,
)

_MAX_EXAMPLES = 60
_PROSE = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz 0123456789",
    min_size=1,
    max_size=40,
)
_ZONES = ("outside", "input", "reasoning")
_BOUNDARIES = ("outside", "crossing", "inside")


def _realization(
    step_id: str, boundary: str, action_kind: str = "observe"
) -> ProjectedStepRealization:
    """Minimal canonical realization for one projected step."""
    return ProjectedStepRealization(
        projected_step_id=step_id,
        action_kind=action_kind,
        executor_role="attacker",
        boundary_position=boundary,
        resource_ref_ids=(),
        consumed_ref_ids=(),
        produced_ref_ids=(),
        produced_effect_ids=(),
        outcome_link_pc_ids=(),
        postcondition_ids=(),
    )


def _projected_step(
    handle_index: int,
    zone: str,
    boundary: str,
    region: str,
) -> NarrativeProjectedStep:
    """One request-local projected step with a unique canonical ID."""
    step_id = f"projected.{handle_index}"
    return NarrativeProjectedStep(
        projected_step_id=step_id,
        order=handle_index + 1,
        zone=zone,
        realization=_realization(step_id, boundary),
        region=region,
    )


def _access() -> NarrativeAccessRealization:
    return NarrativeAccessRealization(
        initial_entry_point_id="ep:v1:canonical",
        responsible_step_number=1,
    )


def _context_from_steps(
    steps: dict[str, NarrativeProjectedStep],
    *,
    presentation_fallback_allowed: bool = True,
) -> NarrativeDraftContext:
    handles = tuple(f"s{index}" for index in range(len(steps)))
    return NarrativeDraftContext(
        title_fallback="Canonical attack pattern",
        entry_point="Chat interface",
        ordered_step_handles=handles,
        projected_steps=steps,
        access_realization=_access(),
        presentation_fallback_allowed=presentation_fallback_allowed,
    )


@st.composite
def valid_step_inventories(draw) -> dict[str, NarrativeProjectedStep]:
    """Contiguous region inventory with unique canonical IDs."""
    count = draw(st.integers(min_value=1, max_value=5))
    regions = ["r0"]
    current = 0
    for _ in range(1, count):
        if draw(st.booleans()):
            current += 1
        regions.append(f"r{current}")
    steps: dict[str, NarrativeProjectedStep] = {}
    for index in range(count):
        steps[f"s{index}"] = _projected_step(
            index,
            draw(st.sampled_from(_ZONES)),
            draw(st.sampled_from(_BOUNDARIES)),
            regions[index],
        )
    return steps


def _one_handle_beats(
    handles: tuple[str, ...],
    actions: list[str],
    consequences: list[str],
    transitions: list[str | None],
) -> list[NarrativeCausalBeatV2]:
    return [
        NarrativeCausalBeatV2(
            step_handles=[handle],
            action=actions[index],
            consequence=consequences[index],
            transition=transitions[index],
        )
        for index, handle in enumerate(handles)
    ]


@st.composite
def valid_compile_inputs(
    draw,
) -> tuple[
    NarrativeDraftContext,
    list[str],
    list[str],
    list[str | None],
    str | None,
]:
    """A valid context plus authored beat prose for a round-trip compile."""
    steps = draw(valid_step_inventories())
    context = _context_from_steps(steps)
    count = len(context.ordered_step_handles)
    actions = draw(st.lists(_PROSE, min_size=count, max_size=count))
    consequences = draw(st.lists(_PROSE, min_size=count, max_size=count))
    transitions = draw(
        st.lists(st.one_of(st.none(), _PROSE), min_size=count, max_size=count)
    )
    title = draw(st.one_of(st.none(), _PROSE))
    return context, actions, consequences, transitions, title


def _expected_effect(consequence: str, transition: str | None) -> str:
    if transition:
        return f"{consequence} {transition}"
    return consequence


def _expected_zone_sequence(steps: dict[str, NarrativeProjectedStep]) -> list[str]:
    sequence: list[str] = []
    for handle in (f"s{index}" for index in range(len(steps))):
        zone = steps[handle].zone
        if not sequence or sequence[-1] != zone:
            sequence.append(zone)
    return sequence


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=valid_compile_inputs())
def test_compile_narrative_draft_preserves_causality_and_projection(
    inputs: tuple[
        NarrativeDraftContext,
        list[str],
        list[str],
        list[str | None],
        str | None,
    ],
) -> None:
    """Valid V2 and V3 drafts attach projection truth without rewriting prose."""
    context, actions, consequences, transitions, title = inputs
    beats = _one_handle_beats(
        context.ordered_step_handles, actions, consequences, transitions
    )
    v2 = NarrativeDraftV2(title=title, summary="A causal summary.", beats=beats)
    regions: dict[str, list[NarrativeCausalBeatV2]] = {}
    for handle, beat in zip(context.ordered_step_handles, beats, strict=True):
        regions.setdefault(context.projected_steps[handle].region, []).append(beat)
    v3 = NarrativeDraftV3(title=title, summary="A causal summary.", regions=regions)
    for draft in (v2, v3):
        narrative = compile_narrative_draft(context, draft)
        assert narrative.title == (title or context.title_fallback)
        assert narrative.summary == "A causal summary."
        assert narrative.entry_point == context.entry_point
        assert [step.projected_step_ids for step in narrative.steps] == [
            (context.projected_steps[handle].projected_step_id,)
            for handle in context.ordered_step_handles
        ]
        assert [step.zone for step in narrative.steps] == [
            context.projected_steps[handle].zone
            for handle in context.ordered_step_handles
        ]
        assert [step.action for step in narrative.steps] == actions
        assert [step.effect for step in narrative.steps] == [
            _expected_effect(consequence, transition)
            for consequence, transition in zip(consequences, transitions, strict=True)
        ]
        assert narrative.zone_sequence == _expected_zone_sequence(
            context.projected_steps
        )
        assert narrative.access_realization == context.access_realization
        assert narrative.access_realization is not context.access_realization
        assert compile_narrative_draft(context, draft) == narrative


@st.composite
def violating_handle_drafts(
    draw,
) -> tuple[NarrativeDraftContext, str, NarrativeDraftV2]:
    """A valid context plus a single-axis handle-coverage violation."""
    steps = draw(valid_step_inventories())
    if len(steps) < 2:
        steps["s1"] = _projected_step(1, "input", "crossing", "r0")
    context = _context_from_steps(steps)
    handles = list(context.ordered_step_handles)
    variant = draw(
        st.sampled_from(
            ("missing", "duplicate", "unknown", "illegal_order", "missing_title")
        )
    )
    if variant == "missing":
        used = handles[:-1]
        codes = "missing_step_handle"
    elif variant == "duplicate":
        used = [handles[0], handles[0], *handles[1:]]
        codes = "duplicate_step_handle"
    elif variant == "unknown":
        used = [*handles[:-1], "unknown"]
        codes = "unknown_and_missing"
    elif variant == "illegal_order":
        used = [handles[1], handles[0], *handles[2:]]
        codes = "illegal_step_order"
    else:
        used = handles
        codes = "missing_title"
        context = _context_from_steps(steps, presentation_fallback_allowed=False)
    draft = NarrativeDraftV2(
        title=None if variant == "missing_title" else "Draft",
        summary="A causal summary.",
        beats=[
            NarrativeCausalBeatV2(
                step_handles=[handle],
                action=f"Action for {handle}",
                consequence=f"Consequence for {handle}",
            )
            for handle in used
        ],
    )
    return context, codes, draft


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=violating_handle_drafts())
def test_compile_narrative_draft_raises_typed_handle_violations(
    inputs: tuple[NarrativeDraftContext, str, NarrativeDraftV2],
) -> None:
    """Each handle-coverage axis raises its documented typed violation code."""
    context, variant, draft = inputs
    expected = {
        "missing_step_handle": {"missing_step_handle"},
        "duplicate_step_handle": {"duplicate_step_handle"},
        "unknown_and_missing": {"unknown_step_handle", "missing_step_handle"},
        "illegal_step_order": {"illegal_step_order"},
        "missing_title": {"missing_title"},
    }[variant]

    def codes() -> set[str]:
        try:
            compile_narrative_draft(context, draft)
        except NarrativeSemanticDraftError as error:
            return {violation.code for violation in error.violations}
        raise AssertionError(f"expected NarrativeSemanticDraftError for {variant}")

    assert codes() == expected
    assert codes() == expected


@st.composite
def mixed_grouping_drafts(
    draw,
) -> tuple[NarrativeDraftContext, set[str], NarrativeDraftV2]:
    """A two-step context whose first beat mixes incompatible semantics."""
    first_zone = draw(st.sampled_from(_ZONES))
    second_zone = draw(
        st.sampled_from(tuple(zone for zone in _ZONES if zone != first_zone))
    )
    first_boundary = draw(st.sampled_from(_BOUNDARIES))
    second_boundary = draw(
        st.sampled_from(
            tuple(boundary for boundary in _BOUNDARIES if boundary != first_boundary)
        )
    )
    mix_zones = draw(st.booleans())
    mix_boundaries = True if not mix_zones else draw(st.booleans())
    steps = {
        "s0": _projected_step(0, first_zone, first_boundary, "r0"),
        "s1": _projected_step(
            1,
            second_zone if mix_zones else first_zone,
            second_boundary if mix_boundaries else first_boundary,
            "r0",
        ),
    }
    context = _context_from_steps(steps)
    expected: set[str] = set()
    if mix_zones:
        expected.add("mixed_step_zones")
    if mix_boundaries:
        expected.add("mixed_boundary_positions")
    draft = NarrativeDraftV2(
        title="Draft",
        summary="A causal summary.",
        beats=[
            NarrativeCausalBeatV2(
                step_handles=["s0", "s1"],
                action="Combine incompatible steps.",
                consequence="The invalid grouping is rejected.",
            )
        ],
    )
    return context, expected, draft


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(inputs=mixed_grouping_drafts())
def test_compile_narrative_draft_rejects_mixed_canonical_grouping(
    inputs: tuple[NarrativeDraftContext, set[str], NarrativeDraftV2],
) -> None:
    """A beat that mixes zones or boundaries is a typed semantic failure."""
    context, expected, draft = inputs

    def codes() -> set[str]:
        try:
            compile_narrative_draft(context, draft)
        except NarrativeSemanticDraftError as error:
            return {violation.code for violation in error.violations}
        raise AssertionError("expected mixed-grouping NarrativeSemanticDraftError")

    assert expected <= codes()
    assert expected <= codes()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(steps=valid_step_inventories())
def test_narrative_draft_context_rejects_noncontiguous_or_mismatched_inventories(
    steps: dict[str, NarrativeProjectedStep],
) -> None:
    """Context construction owns uniqueness, inventory match, and contiguity."""
    handles = tuple(f"s{index}" for index in range(len(steps)))
    valid = NarrativeDraftContext(
        title_fallback="Canonical attack pattern",
        entry_point="Chat interface",
        ordered_step_handles=handles,
        projected_steps=steps,
    )
    assert valid.ordered_step_handles == handles
    assert set(valid.projected_steps) == set(handles)

    try:
        NarrativeDraftContext(
            title_fallback="Canonical attack pattern",
            entry_point="Chat interface",
            ordered_step_handles=handles + handles[:1],
            projected_steps=steps,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate handles must fail context construction")

    revisited = {
        "s0": _projected_step(0, "outside", "outside", "r0"),
        "s1": _projected_step(1, "input", "crossing", "r1"),
        "s2": _projected_step(2, "reasoning", "inside", "r0"),
    }
    try:
        NarrativeDraftContext(
            title_fallback="Canonical attack pattern",
            entry_point="Chat interface",
            ordered_step_handles=("s0", "s1", "s2"),
            projected_steps=revisited,
        )
    except ValueError:
        pass
    else:
        raise AssertionError("non-contiguous regions must fail")
