"""Property tests for the normative system-resource-map public seam."""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from tests.system_resource_map_support import (
    TOOL,
    make_control_structure,
    make_link,
    make_map,
    make_snapshot,
)

_MAX_EXAMPLES = 60
_CONTROL_TARGETS = (
    ("CA", "CA-1-1", "acts_on"),
    ("RESP", "RESP-1", "represents"),
    ("PM", "PM-1-1", "represents"),
    ("CP", "CP-1", "represents"),
)


@st.composite
def _resource_maps(draw: st.DrawFn):
    """Generate content-addressed maps with typed, schema-valid links."""
    count = draw(st.integers(min_value=1, max_value=len(_CONTROL_TARGETS)))
    selected = draw(
        st.lists(
            st.integers(min_value=0, max_value=len(_CONTROL_TARGETS) - 1),
            min_size=count,
            max_size=count,
            unique=True,
        )
    )
    links = tuple(
        make_link(
            link_id=f"srm:v1:{index}",
            control_structure_ref={
                "kind": _CONTROL_TARGETS[target][0],
                "id": _CONTROL_TARGETS[target][1],
            },
            relation_kind=_CONTROL_TARGETS[target][2],
            capability_resource_ref={"kind": "tool", "tool_id": TOOL},
        )
        for index, target in enumerate(selected)
    )
    return make_map(*links)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_yaml_and_json_round_trips_are_lossless(resource_map) -> None:
    """Canonical persistence preserves every typed map value."""
    assert resource_map.from_yaml(resource_map.to_yaml()) == resource_map
    assert resource_map.from_json(resource_map.to_json()) == resource_map


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_serialization_is_byte_stable(resource_map) -> None:
    """Repeated serialization of a map is byte-identical."""
    assert resource_map.to_yaml() == resource_map.to_yaml()
    assert resource_map.to_json() == resource_map.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_canonical_map_order_is_invariant_under_presentation(resource_map) -> None:
    """Link presentation order cannot change the canonical map."""
    links = tuple(resource_map.links)
    reversed_map = make_map(*reversed(links))

    assert resource_map == reversed_map
    assert resource_map.to_json() == reversed_map.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_validation_is_total_and_offline(resource_map) -> None:
    """The public validator always reports typed offline diagnostics."""
    result = validate_system_resource_map(
        resource_map,
        make_snapshot(),
        make_control_structure(),
    )

    assert result.network_calls == 0
    assert result.model_calls == 0
    assert result.is_valid == (len(result.violations) == 0)
    for issue in result.violations + result.warnings:
        assert issue.code
        assert issue.message
