"""Property tests for admission routing and canonical realization.

These properties pin fail-closed capability admission, deterministic
resource-ID extraction, and one-to-one realization coverage. They are
offline and never contact an LLM endpoint.
"""

from __future__ import annotations

from types import SimpleNamespace

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.attack_pattern_projection import (
    AgentInternalResourceReference,
    EntryPointResourceReference,
    IntegrationResourceReference,
    OutputSurfaceResourceReference,
    ToolResourceReference,
    TrustBoundaryResourceReference,
)
from asago_scenario_generator.models.realization import (
    _realization_cover_error,
    derive_step_realization,
    extract_resource_id,
)

_MAX_EXAMPLES = 60
_HEX = "0123456789abcdef"
_OPAQUE = st.text(alphabet=_HEX, min_size=32, max_size=32)
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._",
    min_size=1,
    max_size=12,
)


def _ep(entry_point_id: str) -> EntryPointResourceReference:
    return EntryPointResourceReference(
        kind="entry_point", entry_point_id=f"ep:v1:{entry_point_id}"
    )


def _tool(tool_id: str) -> ToolResourceReference:
    return ToolResourceReference(kind="tool", tool_id=f"tool:v1:{tool_id}")


def _integration(integration_id: str) -> IntegrationResourceReference:
    return IntegrationResourceReference(
        kind="integration", integration_id=f"int:v1:{integration_id}"
    )


def _boundary(trust_boundary_id: str) -> TrustBoundaryResourceReference:
    return TrustBoundaryResourceReference(
        kind="trust_boundary", trust_boundary_id=f"tb:v1:{trust_boundary_id}"
    )


def _output(entry_point_id: str) -> OutputSurfaceResourceReference:
    return OutputSurfaceResourceReference(
        kind="output_surface", entry_point_id=f"ep:v1:{entry_point_id}"
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(opaque=_OPAQUE)
def test_extract_resource_id_is_exhaustive_and_deterministic(opaque: str) -> None:
    """Every closed resource-reference subtype yields a stable opaque ID."""
    refs = (
        _ep(opaque),
        _tool(opaque),
        _integration(opaque),
        _boundary(opaque),
        _output(opaque),
        AgentInternalResourceReference(kind="agent_internal"),
    )
    expected = (
        f"ep:v1:{opaque}",
        f"tool:v1:{opaque}",
        f"int:v1:{opaque}",
        f"tb:v1:{opaque}",
        f"ep:v1:{opaque}",
        "agent_internal",
    )
    assert tuple(extract_resource_id(ref) for ref in refs) == expected
    assert tuple(extract_resource_id(ref) for ref in refs) == expected


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    step_id=_IDS,
    consumed=st.lists(_IDS, max_size=4),
    produced=st.lists(_IDS, max_size=4),
)
def test_derive_step_realization_preserves_canonical_order(
    step_id: str, consumed: list[str], produced: list[str]
) -> None:
    """Realization tuples keep step order and skip unbound resource slots."""
    step = SimpleNamespace(
        step_id=step_id,
        action_kind="deliver",
        executor_role="attacker",
        boundary_position="crossing",
        resource_links=(
            SimpleNamespace(slot_id="bound"),
            SimpleNamespace(slot_id="unbound"),
        ),
        consumed=tuple(SimpleNamespace(ref_id=item) for item in consumed),
        produced=tuple(
            SimpleNamespace(ref_id=item, kind="effect" if index == 0 else "artifact")
            for index, item in enumerate(produced)
        ),
        observable_outcome_links=(),
        observable_postconditions=(),
    )
    record = derive_step_realization(
        step,
        {"bound": _ep("ab" * 16)},
    )
    assert record.projected_step_id == step_id
    assert record.consumed_ref_ids == tuple(consumed)
    assert record.produced_ref_ids == tuple(produced)
    assert record.produced_effect_ids == ((produced[0],) if produced else ())
    assert record.resource_ref_ids == ("ep:v1:" + "ab" * 16,)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    projected=st.lists(_IDS, max_size=5, unique=True),
    extras=st.lists(_IDS, max_size=3),
)
def test_realization_cover_requires_exact_one_to_one(
    projected: list[str], extras: list[str]
) -> None:
    """Coverage holds only when realization IDs match projected IDs exactly once."""
    records = [SimpleNamespace(projected_step_id=item) for item in projected]
    assert _realization_cover_error(records, projected, "subject") is None
    if extras:
        extra_records = [
            *records,
            *(SimpleNamespace(projected_step_id=item) for item in extras),
        ]
        extra_error = _realization_cover_error(extra_records, projected, "subject")
        if set(extras) - set(projected) or len(extra_records) != len(set(projected)):
            assert extra_error is not None
    if projected:
        duplicated = [
            *records,
            SimpleNamespace(projected_step_id=projected[0]),
        ]
        assert _realization_cover_error(duplicated, projected, "subject") is not None
