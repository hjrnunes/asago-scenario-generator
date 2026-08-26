"""Focused tests for cmps.6 narrative access realization validation.

Covers the pure validator ``validate_narrative_access_realization`` and
its enforcement through semantic validation (quarantine path).  These
tests ensure that persistent Call-1 realization mismatches are caught
by semantic validation and cause quarantine, not silent admission.
"""

from __future__ import annotations

from asago_scenario_generator.models.capability_profile import compute_trust_boundary_id
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate.narrative_access import (
    validate_narrative_access_realization,
)
from tests.helpers.realization_helper import make_realizations
from tests.test_actor_entry_point_validation import _make_envelope

# -- helpers -----------------------------------------------------------------


_EP_A = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
_EP_B = "ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
_TB = compute_trust_boundary_id("memory", "input", "memory-to-input")


def _actor(access: ActorAccessProvenance) -> ActorProfile:
    return ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=["x"],
        desires=["y"],
        intentions=["z"],
        resources=["r"],
        access=access,
    )


def _narrative(
    realization: NarrativeAccessRealization | None = None,
    steps: list[NarrativeStep] | None = None,
) -> NarrativeLayer:
    if steps is None:
        steps = [
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Craft malicious input.",
                effect="System processes it.",
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            ),
        ]
    return NarrativeLayer(
        title="Test",
        summary="A test scenario.",
        entry_point="user prompts (zone 1)",
        zone_sequence=["input"],
        steps=steps,
        access_realization=realization,
    )


def _direct_access() -> ActorAccessProvenance:
    return ActorAccessProvenance(
        initial_entry_point_id=_EP_A,
        ingress_mode="direct",
        access_class="public",
    )


def _indirect_access() -> ActorAccessProvenance:
    return ActorAccessProvenance(
        initial_entry_point_id=_EP_A,
        ingress_mode="indirect",
        access_class="supply_chain",
        influence_source=_EP_B,
        influence_mechanism="document poisoning",
        trust_boundary_id=_TB,
    )


# -- valid realizations ------------------------------------------------------


def test_valid_direct_realization():
    """Direct access with matching realization and no indirect refs is valid."""
    access = _direct_access()
    nar = _narrative(
        NarrativeAccessRealization(
            initial_entry_point_id=_EP_A,
            responsible_step_number=1,
        )
    )
    assert validate_narrative_access_realization(nar, _actor(access)) == []


def test_valid_indirect_realization():
    """Indirect access with matching source/boundary/step is valid."""
    access = _indirect_access()
    nar = _narrative(
        NarrativeAccessRealization(
            initial_entry_point_id=_EP_A,
            influence_source=_EP_B,
            trust_boundary_id=_TB,
            responsible_step_number=1,
        )
    )
    assert validate_narrative_access_realization(nar, _actor(access)) == []


# -- missing realization -----------------------------------------------------


def test_missing_realization():
    """Narrative without access_realization when actor has access is invalid."""
    nar = _narrative(realization=None)
    violations = validate_narrative_access_realization(nar, _actor(_direct_access()))
    assert len(violations) == 1
    assert violations[0].rule == "missing_access_realization"


def test_no_violations_when_actor_access_missing():
    """If actor has no access provenance, realization is not checked."""
    nar = _narrative(realization=None)
    actor = ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=[],
        desires=[],
        intentions=[],
        resources=[],
        access=None,
    )
    assert validate_narrative_access_realization(nar, actor) == []


# -- wrong fields ------------------------------------------------------------


def test_wrong_entry_point_id():
    """Realization with a divergent entry_point_id is invalid."""
    access = _direct_access()
    nar = _narrative(
        NarrativeAccessRealization(
            initial_entry_point_id="ep:v1:cccccccccccccccccccccccccccccccc",
            responsible_step_number=1,
        )
    )
    violations = validate_narrative_access_realization(nar, _actor(access))
    assert any(v.rule == "realization_entry_point_mismatch" for v in violations)


def test_wrong_influence_source():
    """Indirect realization with a divergent influence_source is invalid."""
    access = _indirect_access()
    nar = _narrative(
        NarrativeAccessRealization(
            initial_entry_point_id=_EP_A,
            influence_source="ep:v1:cccccccccccccccccccccccccccccccc",
            trust_boundary_id=_TB,
            responsible_step_number=1,
        )
    )
    violations = validate_narrative_access_realization(nar, _actor(access))
    assert any(v.rule == "realization_influence_source_mismatch" for v in violations)


def test_wrong_trust_boundary_id():
    """Indirect realization with a divergent trust_boundary_id is invalid."""
    access = _indirect_access()
    wrong_tb = compute_trust_boundary_id(
        "tool_execution", "input", "tool-exec-to-input"
    )
    nar = _narrative(
        NarrativeAccessRealization(
            initial_entry_point_id=_EP_A,
            influence_source=_EP_B,
            trust_boundary_id=wrong_tb,
            responsible_step_number=1,
        )
    )
    violations = validate_narrative_access_realization(nar, _actor(access))
    assert any(v.rule == "realization_trust_boundary_mismatch" for v in violations)


def test_nonexistent_responsible_step():
    """Realization pointing to a step that doesn't exist is invalid."""
    access = _direct_access()
    nar = _narrative(
        NarrativeAccessRealization(
            initial_entry_point_id=_EP_A,
            responsible_step_number=99,
        )
    )
    violations = validate_narrative_access_realization(nar, _actor(access))
    assert any(v.rule == "realization_step_not_found" for v in violations)


# -- direct access with indirect refs ----------------------------------------


def test_direct_realization_has_indirect_refs():
    """Direct access must not carry influence_source or trust_boundary_id."""
    access = _direct_access()
    nar = _narrative(
        NarrativeAccessRealization(
            initial_entry_point_id=_EP_A,
            influence_source=_EP_B,
            trust_boundary_id=_TB,
            responsible_step_number=1,
        )
    )
    violations = validate_narrative_access_realization(nar, _actor(access))
    assert any(v.rule == "direct_realization_has_indirect_ref" for v in violations)


# -- semantic validation enforcement -----------------------------------------


def test_semantic_validation_catches_missing_realization():
    """Semantic validation enforces narrative realization (quarantine path).

    A scenario with actor access but no narrative access_realization must
    produce a semantic violation, so persistent Call-1 realization
    mismatch is quarantined, not silently admitted.
    """
    from asago_scenario_generator.pipeline.validation import validate_scenario_semantics

    access = _direct_access()
    envelope = _make_envelope(
        entry_point_id=_EP_A,
        access=access,
    )
    # Remove realization to simulate persistent Call-1 mismatch.
    envelope.narrative.access_realization = None

    profile = _make_profile_for_semantic()
    validate_scenario_semantics([envelope], profile)
    assert envelope.validation is not None
    assert envelope.validation.semantic is not None
    rule_names = [v.rule for v in envelope.validation.semantic.violations]
    assert "missing_access_realization" in rule_names


def test_semantic_validation_catches_wrong_realization():
    """Semantic validation catches a wrong entry_point_id in realization."""
    from asago_scenario_generator.pipeline.validation import validate_scenario_semantics

    access = _direct_access()
    envelope = _make_envelope(
        entry_point_id=_EP_A,
        access=access,
    )
    # Set a wrong realization.
    envelope.narrative.access_realization = NarrativeAccessRealization(
        initial_entry_point_id="ep:v1:cccccccccccccccccccccccccccccccc",
        responsible_step_number=1,
    )

    profile = _make_profile_for_semantic()
    validate_scenario_semantics([envelope], profile)
    assert envelope.validation is not None
    assert envelope.validation.semantic is not None
    rule_names = [v.rule for v in envelope.validation.semantic.violations]
    assert "realization_entry_point_mismatch" in rule_names


def _make_profile_for_semantic():
    """Minimal profile for semantic validation of actor access."""
    from asago_scenario_generator.models.capability_profile import (
        BoundaryConfidence,
        CapabilityProfile,
        ConfidenceLevel,
        EntryPoint,
        TrustBoundary,
    )

    return CapabilityProfile(
        zones_active=["input", "reasoning"],
        entry_points=[
            EntryPoint(
                name="user prompts (zone 1)",
                direction="input",
                controllability="direct",
            ),
        ],
        trust_boundaries=[
            TrustBoundary(
                name="memory-to-input",
                from_zone="memory",
                to_zone="input",
                confidence=BoundaryConfidence.explicit,
            ),
        ],
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )
