"""Regression tests for the third cmps.6 correction pass."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.models.capability_profile import (
    BoundaryConfidence,
    ConfidenceLevel,
    TrustBoundary,
    compute_trust_boundary_id,
    deduplicate_trust_boundaries,
)
from asago_scenario_generator.models.projection_envelope import ProjectionTraceabilityResult
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
    ScenarioEnvelope,
)
from asago_scenario_generator.pipeline.generate import (
    compute_scenario_id,
    generate_scenario,
)
from asago_scenario_generator.pipeline.generate.actor import build_call0_context
from asago_scenario_generator.pipeline.generate.narrative_access import (
    validate_narrative_access_realization,
)
from asago_scenario_generator.pipeline.seeds import RiskCardRef, ScenarioSeed
from tests.helpers.projection_factory import get_projected_candidate, get_test_snapshot
from tests.helpers.realization_helper import make_realizations
from tests.test_actor_entry_point_validation import (
    _make_envelope,
    _make_indirect_profile,
    _make_profile,
)

RUN_ID = "20260101T000000_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def _seed() -> ScenarioSeed:
    return ScenarioSeed(
        seed_id="AP-T1-01",
        threat_id="T1",
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="A test attack pattern.",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk",
            risk_description="Risk description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=["T1"],
    )


def _result(content: object = "mock") -> LLMResult:
    return LLMResult(
        content=content,
        prompt_tokens=0,
        completion_tokens=0,
        duration_ms=0,
        system_prompt="mock",
        user_prompt="mock",
    )


def test_boundary_identity_collision_guard_and_call0_context() -> None:
    first = TrustBoundary(
        name="Vendor gateway",
        from_zone="memory",
        to_zone="input",
        confidence=BoundaryConfidence.explicit,
    )
    second = TrustBoundary(
        name="Document gateway",
        from_zone="memory",
        to_zone="input",
        confidence=BoundaryConfidence.explicit,
    )
    assert first.trust_boundary_id != second.trust_boundary_id
    assert first.trust_boundary_id == compute_trust_boundary_id(
        "memory", "input", "Vendor gateway"
    )
    assert deduplicate_trust_boundaries([first, second]) == [first, second]

    duplicate = first.model_copy()
    assert deduplicate_trust_boundaries([first, duplicate]) == [first]

    # Simulate a hash collision without weakening the production hash function.
    with patch.object(
        TrustBoundary,
        "trust_boundary_id",
        new_callable=MagicMock,
    ) as boundary_id:
        boundary_id.__get__ = MagicMock(return_value="tb:v1:" + "f" * 32)
        with pytest.raises(ValueError, match="Ambiguous trust boundary identity"):
            deduplicate_trust_boundaries([first, second])

    profile = _make_indirect_profile()
    target, upstream = profile.entry_points
    context = build_call0_context(
        _seed(),
        profile,
        "test use case",
        pinned_entry_point=target.name,
        pinned_entry_point_id=target.entry_point_id,
    )
    section = context["access_provenance_section"]
    # Phase 3: prompts now show human-readable names, not hex IDs
    assert upstream.name in section
    assert profile.trust_boundaries[0].name in section
    assert "Valid influence_source entry-point names" in section
    assert "Valid trust_boundary_id values" in section


def test_title_retry_cannot_bypass_realization_enforcement() -> None:
    profile = _make_profile()
    ep = profile.entry_points[0]
    access = ActorAccessProvenance(
        initial_entry_point_id=ep.entry_point_id,
        ingress_mode="direct",
        access_class="public",
    )
    actor = ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=["The interface accepts input."],
        desires=["Compromise the system."],
        intentions=["Submit crafted input."],
        resources=["Standard tools."],
        access=access,
    )
    valid = NarrativeLayer(
        title="Already Used",
        summary="A valid first response.",
        entry_point=ep.name,
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Inject",
                effect="Parse",
                projected_step_ids=("step.1",),
                realizations=make_realizations(
                    ("step.1",),
                    action_kind="prepare",
                    executor_role="attacker",
                    boundary_position="crossing",
                ),
            )
        ],
        access_realization=NarrativeAccessRealization(
            initial_entry_point_id=ep.entry_point_id,
            responsible_step_number=1,
        ),
    )
    invalid_retry = valid.model_copy(
        update={"title": "Fresh Title", "access_realization": None}
    )
    template = _make_envelope(entry_point_id=ep.entry_point_id, access=access)
    template.actor_profile = actor
    candidate_id = "cand:v2:11111111111111111111111111111111"

    def assemble(*args, narrative, **kwargs) -> ScenarioEnvelope:
        envelope = template.model_copy(deep=True)
        envelope.narrative = narrative
        envelope.candidate_id = candidate_id
        envelope.scenario_id = compute_scenario_id(RUN_ID, candidate_id)
        return envelope

    with (
        patch(
            "asago_scenario_generator.pipeline.generate._call_actor_profile",
            return_value=(actor, _result(), None),
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._validate_actor_type",
            side_effect=lambda value: value,
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.validate_actor_access_provenance",
            return_value=[],
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._call_narrative",
            side_effect=[
                (valid, _result()),
                (invalid_retry, _result()),
                (invalid_retry, _result()),
            ],
        ) as narrative_call,
        patch(
            "asago_scenario_generator.pipeline.generate._call_attack_tree",
            return_value=(template.attack_tree, _result()),
        ),
        patch("asago_scenario_generator.pipeline.generate._strip_non_skeleton_techniques"),
        patch(
            "asago_scenario_generator.pipeline.generate._validate_technique_zone_compatibility"
        ),
        patch(
            "asago_scenario_generator.pipeline.generate.assembly._check_consistency",
            return_value=[],
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._call_behavior_spec",
            return_value=(None, _result()),
        ),
        patch(
            "asago_scenario_generator.pipeline.generate._assemble_envelope", side_effect=assemble
        ),
        patch(
            "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
            return_value=ProjectionTraceabilityResult(valid=True, violations=[]),
        ),
    ):
        envelope, _ = generate_scenario(
            _seed(),
            profile,
            MagicMock(),
            "test",
            pinned_entry_point_id=ep.entry_point_id,
            pinned_entry_point=ep.name,
            prior_titles=["Already Used"],
            run_id=RUN_ID,
            candidate_id="",
            projected_candidate=get_projected_candidate(),
            capability_snapshot=get_test_snapshot(),
        )

    assert narrative_call.call_count >= 3
    violations = validate_narrative_access_realization(
        envelope.narrative, envelope.actor_profile
    )
    assert {violation.rule for violation in violations} == {
        "missing_access_realization"
    }
