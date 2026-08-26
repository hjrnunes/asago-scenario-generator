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
from asago_scenario_generator.models.complexity import (
    AttackComplexityAssessment,
    Call0RegenerationRouting,
    ComplexityEvidenceReference,
    ComplexityPhaseAssessment,
    ComplexityReason,
    QuarantineRouting,
    RealizationRetryRouting,
    capability_level_rank,
)
from asago_scenario_generator.models.realization import (
    _realization_cover_error,
    derive_step_realization,
    extract_resource_id,
)
from asago_scenario_generator.models.scenario import _candidate_hex_error
from asago_scenario_generator.pipeline.complexity import evaluate_capability_admission

_MAX_EXAMPLES = 60
_LEVELS = ("novice", "intermediate", "advanced", "expert")
_HEX = "0123456789abcdef"
_OPAQUE = st.text(alphabet=_HEX, min_size=32, max_size=32)
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-._",
    min_size=1,
    max_size=12,
)


def _ep(entry_point_id: str) -> EntryPointResourceReference:
    return EntryPointResourceReference(kind="entry_point", entry_point_id=f"ep:v1:{entry_point_id}")


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


def _reason(rule_id: str, required_level: str, kind: str, ref_id: str) -> ComplexityReason:
    return ComplexityReason(
        rule_id=rule_id,  # type: ignore[arg-type]
        required_level=required_level,  # type: ignore[arg-type]
        detail="property fixture",
        evidence=(
            ComplexityEvidenceReference(kind=kind, ref_id=ref_id),  # type: ignore[arg-type]
        ),
    )


def _assessment(
    required: str,
    reasons: tuple[ComplexityReason, ...],
    *,
    include_final: bool,
) -> AttackComplexityAssessment:
    candidate = ComplexityPhaseAssessment(
        phase="candidate_lower_bound",
        required_level="novice",
        reasons=(),
    )
    final = None
    if include_final:
        final = ComplexityPhaseAssessment(
            phase="final",
            required_level=required,  # type: ignore[arg-type]
            reasons=reasons,
        )
    return AttackComplexityAssessment(
        rule_version="1",
        candidate_lower_bound=candidate,
        final=final,
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    actor=st.sampled_from(_LEVELS),
    include_final=st.booleans(),
)
def test_admission_is_fail_closed_and_monotonic(
    actor: str, include_final: bool
) -> None:
    """Equal-or-higher capability admits; a missing final phase quarantines."""
    required = "advanced"
    reasons = (
        _reason(
            "access.supply_chain_targeting",
            required,
            "actor_access_provenance",
            "ep:v1:" + "ab" * 16,
        ),
    )
    assessment = _assessment(required, reasons, include_final=include_final)
    decision = evaluate_capability_admission(actor, assessment, phase="final")
    if not include_final:
        assert decision.admitted is False
        assert decision.violation is not None
        assert decision.violation.rule_id == "complexity_assessment_phase_unavailable"
        assert isinstance(decision.violation.routing, QuarantineRouting)
        return
    if capability_level_rank(actor) >= capability_level_rank(required):  # type: ignore[arg-type]
        assert decision.admitted is True
        assert decision.violation is None
        return
    assert decision.admitted is False
    assert decision.violation is not None
    assert decision.violation.required_level == required
    assert isinstance(decision.violation.routing, Call0RegenerationRouting)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(actor=st.sampled_from(("novice",)))
def test_realization_evidence_routes_to_tree_retry(actor: str) -> None:
    """Typed realized-action evidence never remediates at Call 0."""
    reasons = (
        _reason(
            "action.external_precondition",
            "intermediate",
            "leaf_action",
            "n1.1",
        ),
    )
    assessment = _assessment("intermediate", reasons, include_final=True)
    decision = evaluate_capability_admission(actor, assessment, phase="final")
    assert decision.admitted is False
    assert decision.violation is not None
    assert isinstance(decision.violation.routing, RealizationRetryRouting)


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


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    hex_part=st.text(alphabet=_HEX + "ABCDEFG", min_size=0, max_size=40),
)
def test_candidate_hex_error_accepts_only_32_lowercase_hex(hex_part: str) -> None:
    """Only a 32-character lowercase hex suffix is a valid candidate identity."""
    error = _candidate_hex_error(hex_part)
    valid = (
        len(hex_part) == 32
        and hex_part == hex_part.lower()
        and all(char in _HEX for char in hex_part)
    )
    if valid:
        assert error is None
        return
    assert error is not None
