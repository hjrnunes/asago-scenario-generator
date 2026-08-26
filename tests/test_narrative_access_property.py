"""Property tests for the inward narrative-access leaf.

These properties pin Call-1 output-shape bounds and cmps.6 realization
matching. They are offline and deterministic.
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate.narrative_access import (
    MAX_NARRATIVE_STEPS,
    NARRATIVE_CONNECTOR_STEPS,
    validate_narrative_access_realization,
    validate_narrative_step_bounds,
)

_MAX_EXAMPLES = 60
_IDS = st.from_regex(r"[a-z][a-z0-9]{0,11}", fullmatch=True)
_EP_A = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _step(number: int, *projected: str) -> NarrativeStep:
    return NarrativeStep(
        step_number=number,
        zone="input",
        action=f"action-{number}",
        effect=f"effect-{number}",
        projected_step_ids=projected,
    )


def _narrative(*steps: NarrativeStep, realization: NarrativeAccessRealization | None = None) -> NarrativeLayer:
    return NarrativeLayer(
        title="Test",
        summary="A test scenario.",
        entry_point="user prompts",
        zone_sequence=["input"],
        steps=list(steps) or [_step(1, "step.1")],
        access_realization=realization,
    )


def _actor(access: ActorAccessProvenance | None) -> ActorProfile:
    return ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=["x"],
        desires=["y"],
        intentions=["z"],
        resources=["r"],
        access=access,
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    selected=st.lists(_IDS, min_size=1, max_size=8, unique=True),
    extra=st.integers(min_value=0, max_value=4),
)
def test_step_bounds_accept_covered_narratives_within_cap(
    selected: list[str], extra: int
) -> None:
    """Covered selected IDs stay valid until the connector/cap bound."""
    maximum = min(MAX_NARRATIVE_STEPS, len(selected) + NARRATIVE_CONNECTOR_STEPS)
    step_count = min(maximum, len(selected) + extra)
    steps = [
        _step(index + 1, selected[index] if index < len(selected) else f"extra.{index}")
        for index in range(step_count)
    ]
    for leftover in selected[step_count:]:
        steps[-1] = _step(steps[-1].step_number, *steps[-1].projected_step_ids, leftover)
    codes = {code for code, _detail in validate_narrative_step_bounds(_narrative(*steps), selected)}
    assert "narrative_step_coverage" not in codes
    assert "narrative_step_bound" not in codes


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(selected=st.lists(_IDS, min_size=1, max_size=6, unique=True))
def test_step_bounds_report_missing_selected_ids(selected: list[str]) -> None:
    """A narrative that omits a selected ID always reports coverage."""
    omitted = selected[0]
    remaining = selected[1:]
    steps = [_step(1, *remaining)] if remaining else [_step(1, "other")]
    violations = validate_narrative_step_bounds(_narrative(*steps), selected)
    codes = {code for code, _detail in violations}
    assert "narrative_step_coverage" in codes
    assert omitted in next(
        detail for code, detail in violations if code == "narrative_step_coverage"
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(selected_count=st.integers(min_value=1, max_value=8))
def test_step_bounds_report_overlong_narratives(selected_count: int) -> None:
    """More than selected + 2 steps, or more than 16, is always a bound error."""
    selected = [f"step.{index}" for index in range(selected_count)]
    maximum = min(MAX_NARRATIVE_STEPS, selected_count + NARRATIVE_CONNECTOR_STEPS)
    steps = [_step(index + 1, selected[index] if index < selected_count else f"x.{index}") for index in range(maximum + 1)]
    codes = {code for code, _detail in validate_narrative_step_bounds(_narrative(*steps), selected)}
    assert "narrative_step_bound" in codes


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(entry=_IDS)
def test_matching_direct_realization_is_empty(entry: str) -> None:
    """A matching direct realization never produces a violation."""
    ep_id = f"ep:v1:{entry}"
    access = ActorAccessProvenance(
        initial_entry_point_id=ep_id,
        ingress_mode="direct",
        access_class="public",
    )
    realization = NarrativeAccessRealization(
        initial_entry_point_id=ep_id,
        responsible_step_number=1,
    )
    assert validate_narrative_access_realization(_narrative(realization=realization), _actor(access)) == []


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(left=_IDS, right=_IDS)
def test_mismatched_entry_point_is_reported(left: str, right: str) -> None:
    """Divergent entry-point IDs are always a realization mismatch."""
    left_id = f"ep:v1:{left}"
    right_id = f"ep:v1:{right}"
    access = ActorAccessProvenance(
        initial_entry_point_id=left_id,
        ingress_mode="direct",
        access_class="public",
    )
    realization = NarrativeAccessRealization(
        initial_entry_point_id=right_id,
        responsible_step_number=1,
    )
    rules = {
        item.rule
        for item in validate_narrative_access_realization(
            _narrative(realization=realization), _actor(access)
        )
    }
    if left_id == right_id:
        assert "realization_entry_point_mismatch" not in rules
    else:
        assert "realization_entry_point_mismatch" in rules


def test_missing_realization_is_reported() -> None:
    """Actor provenance without a narrative realization is always a violation."""
    access = ActorAccessProvenance(
        initial_entry_point_id=_EP_A,
        ingress_mode="direct",
        access_class="public",
    )
    rules = {
        item.rule
        for item in validate_narrative_access_realization(_narrative(), _actor(access))
    }
    assert rules == {"missing_access_realization"}


def test_no_actor_access_skips_realization_checks() -> None:
    """Missing actor provenance leaves realization unchecked."""
    assert validate_narrative_access_realization(_narrative(), _actor(None)) == []
