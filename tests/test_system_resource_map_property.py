"""Property tests for the system resource map and its validation.

These properties pin serialization round trips, byte stability,
canonical-order invariance, and validator totality for
``models.system_resource_map`` and ``pipeline.system_resource_map``.
They are offline and deterministic; they never contact an LLM endpoint.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from asago_scenario_generator.models.system_resource_map import (
    ActorControllerEntry,
    ControlActionEntry,
    ControlledProcessEntry,
    DataFlowEntry,
    FeedbackPathEntry,
    LossLinkEntry,
    ResourceAssertionEntry,
    ResourceMapSnapshot,
    SystemResourceEntry,
    SystemResourceMap,
    TrustBoundaryEntry,
    UseCaseFactEntry,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_resource_map,
)

_MAX_EXAMPLES = 60
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_",
    min_size=0,
    max_size=12,
)
_NAMES = st.text(min_size=0, max_size=24)

_KNOWN_STPA_IDS = ["RESP-1", "CP-2", "L-1", "H-1"]
_KNOWN_TAXONOMY_IDS = ["ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"]

_ENTRY_TYPES = {
    "system_resources": SystemResourceEntry,
    "actor_controllers": ActorControllerEntry,
    "controlled_processes": ControlledProcessEntry,
    "control_actions": ControlActionEntry,
    "feedback_paths": FeedbackPathEntry,
    "trust_boundaries": TrustBoundaryEntry,
    "data_flows": DataFlowEntry,
    "loss_links": LossLinkEntry,
    "use_case_facts": UseCaseFactEntry,
    "assertions": ResourceAssertionEntry,
}

_COLLECTIONS = tuple(_ENTRY_TYPES)


def _snapshot() -> ResourceMapSnapshot:
    return ResourceMapSnapshot(
        schema_version="1",
        stpa_version="stpa-v1",
        taxonomy_version="atlas-2026.05",
        stpa_identifiers=list(_KNOWN_STPA_IDS),
        taxonomy_identifiers=list(_KNOWN_TAXONOMY_IDS),
        facts={},
    )


def _make_entry_strategy(entry_type: type) -> st.SearchStrategy:
    """Draw entries of one typed collection with arbitrary content."""
    return st.builds(
        entry_type,
        element_id=_IDS,
        name=_NAMES,
    )


@st.composite
def _resource_maps(draw: st.DrawFn) -> SystemResourceMap:
    """Draw resource maps with arbitrary entry content per collection."""
    kwargs: dict[str, object] = {
        "schema_version": "1",
        "stpa_version": "stpa-v1",
        "taxonomy_version": "atlas-2026.05",
    }
    for collection, entry_type in _ENTRY_TYPES.items():
        kwargs[collection] = draw(
            st.lists(_make_entry_strategy(entry_type), max_size=4)
        )
    return SystemResourceMap(**kwargs)  # type: ignore[arg-type]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_yaml_and_json_round_trips_are_lossless(
    resource_map: SystemResourceMap,
) -> None:
    """YAML and JSON persistence preserve the authoritative map model."""
    assert SystemResourceMap.from_yaml(resource_map.to_yaml()) == resource_map
    assert SystemResourceMap.from_json(resource_map.to_json()) == resource_map


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_serialization_is_byte_stable(resource_map: SystemResourceMap) -> None:
    """Serializing the same map twice yields byte-identical artifacts."""
    assert resource_map.to_yaml() == resource_map.to_yaml()
    assert resource_map.to_json() == resource_map.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_canonical_map_order_is_invariant_under_presentation(
    resource_map: SystemResourceMap,
) -> None:
    """Canonical collections do not depend on snapshot presentation order."""
    result_a = validate_resource_map(resource_map, _snapshot())
    if not result_a.is_valid or result_a.canonical_map is None:
        return

    reversed_map = resource_map.model_copy(deep=True)
    for collection in _COLLECTIONS:
        getattr(reversed_map, collection).reverse()

    result_b = validate_resource_map(reversed_map, _snapshot())
    assert result_a.canonical_map == result_b.canonical_map
    assert result_a.canonical_map.to_json() == result_b.canonical_map.to_json()


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(resource_map=_resource_maps())
def test_validation_is_total_and_offline(
    resource_map: SystemResourceMap,
) -> None:
    """Validation never raises, always reports zero network/model calls."""
    result = validate_resource_map(resource_map, _snapshot())

    assert result.network_calls == 0
    assert result.model_calls == 0
    assert result.is_valid == (len(result.errors) == 0)
    for issue in result.errors + result.warnings:
        assert issue.code
        assert issue.message
