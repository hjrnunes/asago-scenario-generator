"""Tests for the cmps.6 typed actor-access provenance policy."""

from __future__ import annotations

from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

from asago_scenario_generator.llm.client import LLMResult
from asago_scenario_generator.models.capability_profile import (
    BoundaryConfidence,
    CapabilityProfile,
    ConfidenceLevel,
    EntryPoint,
    TrustBoundary,
    compute_trust_boundary_id,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionTraceabilityResult,
)
from asago_scenario_generator.models.scenario import (
    ACTOR_TYPES,
    ActorAccessProvenance,
    ActorProfile,
)
from asago_scenario_generator.pipeline.generate.actor import (
    build_actor_access_provenance,
    build_call0_context,
    compute_compatible_actor_types,
    validate_actor_access_provenance,
)
from asago_scenario_generator.pipeline.generate.names import (
    access_provenance_block_with_names,
)
from asago_scenario_generator.pipeline.generate.constants import (
    _ACTOR_ACCESS_MAX_RETRIES,
    _INSIDER_ACTOR_TYPES,
    ALL_ACTOR_TYPES,
)
from asago_scenario_generator.pipeline.seeds import RiskCardRef, ScenarioSeed
from tests.helpers.projection_factory import get_projected_candidate, get_test_snapshot


def _make_entry_point(
    name: str = "user prompts (chat)",
    direction: str = "input",
    controllability: str = "direct",
) -> EntryPoint:
    return EntryPoint(name=name, direction=direction, controllability=controllability)


def _make_profile(
    entry_points: list[EntryPoint] | None = None,
    zones_active: list[str] | None = None,
    trust_boundaries: list[TrustBoundary] | None = None,
) -> CapabilityProfile:
    return CapabilityProfile(
        zones_active=zones_active or ["input", "reasoning", "tool_execution"],
        entry_points=entry_points or [_make_entry_point()],
        trust_boundaries=trust_boundaries,
        confidence=ConfidenceLevel.high,
        kc_subcodes=["KC1.1"],
    )


def _make_indirect_profile() -> tuple[CapabilityProfile, str, str, str]:
    """Build a profile with two indirect EPs and a trust boundary.

    Returns (profile, target_ep_id, source_ep_id, boundary_id).
    """
    target = _make_entry_point("RAG retrieval", controllability="indirect")
    source = EntryPoint(
        name="memory store feed",
        direction="input",
        controllability="indirect",
        ingress_zone="memory",
    )
    boundary = TrustBoundary(
        name="memory-to-input",
        from_zone="memory",
        to_zone="input",
        confidence=BoundaryConfidence.explicit,
    )
    profile = _make_profile(
        entry_points=[target, source],
        zones_active=["memory", "input", "reasoning", "tool_execution"],
        trust_boundaries=[boundary],
    )
    boundary_id = compute_trust_boundary_id("memory", "input", "memory-to-input")
    return profile, target.entry_point_id, source.entry_point_id, boundary_id


def _make_seed(
    threat_id: str = "T2", atlas_ids: list[str] | None = None
) -> ScenarioSeed:
    return ScenarioSeed(
        seed_id=f"AP-{threat_id}-01",
        threat_id=threat_id,
        threat_name="Test Threat",
        attack_pattern_name="Test Pattern",
        attack_pattern_description="Test description",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence=ConfidenceLevel.high,
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=[threat_id],
        atlas_technique_ids=atlas_ids or [],
    )


def _make_call0_response(
    actor_type: str = "cybercriminal",
    access_class: str = "public",
    influence_source: str | None = None,
    influence_mechanism: str | None = None,
    trust_boundary_id: str | None = None,
    material_insider_advantage: str | None = None,
):
    from asago_scenario_generator.pipeline.generate.actor import Call0Response

    return Call0Response(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=["The system exposes a chat interface."],
        desires=["I want to extract data."],
        intentions=["I will send crafted input."],
        resources=["Standard tools"],
        access_class=access_class,
        influence_source=influence_source,
        influence_mechanism=influence_mechanism,
        trust_boundary_id=trust_boundary_id,
        material_insider_advantage=material_insider_advantage,
    )


def _make_actor_with_access(
    actor_type: str = "cybercriminal",
    entry_point_id: str = "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    ingress_mode: str = "direct",
    access_class: str = "public",
    influence_source: str | None = None,
    influence_mechanism: str | None = None,
    trust_boundary_id: str | None = None,
    material_insider_advantage: str | None = None,
) -> ActorProfile:
    return ActorProfile(
        actor_type=actor_type,
        capability_level="intermediate",
        beliefs=["The system has a vulnerability."],
        desires=["Extract data."],
        intentions=["Send crafted input."],
        resources=["Tools"],
        access=ActorAccessProvenance(
            initial_entry_point_id=entry_point_id,
            ingress_mode=ingress_mode,
            access_class=access_class,
            influence_source=influence_source,
            influence_mechanism=influence_mechanism,
            trust_boundary_id=trust_boundary_id,
            material_insider_advantage=material_insider_advantage,
        ),
    )


class TestValidateActorAccessProvenance:
    def test_missing_access_provenance_flagged(self):
        actor = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        assert [v.rule for v in validate_actor_access_provenance(actor)] == [
            "missing_access_provenance"
        ]

    def test_direct_public_external_actor_passes_with_canonical_resolution(self):
        ep = _make_entry_point()
        profile = _make_profile([ep])
        actor = _make_actor_with_access(entry_point_id=ep.entry_point_id)
        assert validate_actor_access_provenance(actor, profile) == []

    def test_valid_indirect_influence_resolves_canonically(self):
        profile, target_id, source_id, boundary_id = _make_indirect_profile()
        actor = _make_actor_with_access(
            actor_type="cybercriminal",
            entry_point_id=target_id,
            ingress_mode="indirect",
            access_class="authenticated",
            influence_source=source_id,
            influence_mechanism="document poisoning",
            trust_boundary_id=boundary_id,
        )
        assert validate_actor_access_provenance(actor, profile) == []

    def test_unresolved_indirect_source_rejected(self):
        profile, target_id, _, boundary_id = _make_indirect_profile()
        actor = _make_actor_with_access(
            entry_point_id=target_id,
            ingress_mode="indirect",
            access_class="authenticated",
            influence_source="ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            influence_mechanism="poisoning",
            trust_boundary_id=boundary_id,
        )
        rules = [v.rule for v in validate_actor_access_provenance(actor, profile)]
        assert "unresolved_influence_source" in rules

    def test_indirect_without_evidence_flagged(self):
        actor = _make_actor_with_access(
            ingress_mode="indirect", access_class="authenticated"
        )
        assert "incomplete_indirect_evidence" in [
            v.rule for v in validate_actor_access_provenance(actor)
        ]

    def test_fabricated_trust_boundary_rejected(self):
        profile, target_id, source_id, _ = _make_indirect_profile()
        actor = _make_actor_with_access(
            entry_point_id=target_id,
            ingress_mode="indirect",
            access_class="supply_chain",
            influence_source=source_id,
            influence_mechanism="poisoning",
            trust_boundary_id="tb:v1:cccccccccccccccccccccccccccccccc",
        )
        assert "unresolved_trust_boundary" in [
            v.rule for v in validate_actor_access_provenance(actor, profile)
        ]

    def test_missing_initial_ingress_zone_does_not_invent_zone_mismatch(self):
        target = _make_entry_point(
            "output feed",
            direction="output",
            controllability="indirect",
        )
        source = EntryPoint(
            name="memory feed",
            direction="input",
            controllability="indirect",
            ingress_zone="memory",
        )
        boundary = TrustBoundary(
            name="memory-to-input",
            from_zone="memory",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            entry_points=[target, source],
            zones_active=["memory", "input"],
            trust_boundaries=[boundary],
        )
        actor = _make_actor_with_access(
            entry_point_id=target.entry_point_id,
            ingress_mode="indirect",
            access_class="supply_chain",
            influence_source=source.entry_point_id,
            influence_mechanism="document poisoning",
            trust_boundary_id=boundary.trust_boundary_id,
        )

        rules = {
            violation.rule
            for violation in validate_actor_access_provenance(actor, profile)
        }

        assert "ineligible_ingress_entry_point" in rules
        assert "trust_boundary_target_zone_mismatch" not in rules

    @pytest.mark.parametrize(
        ("ingress_mode", "access_class"),
        [("direct", "supply_chain"), ("indirect", "public")],
    )
    def test_access_class_ingress_mode_inconsistency(self, ingress_mode, access_class):
        actor = _make_actor_with_access(
            ingress_mode=ingress_mode,
            access_class=access_class,
            influence_source="ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            influence_mechanism="poisoning",
            trust_boundary_id="tb:v1:cccccccccccccccccccccccccccccccc",
        )
        assert "access_class_ingress_mode_incompatible" in [
            v.rule for v in validate_actor_access_provenance(actor)
        ]

    def test_insider_public_direct_requires_material_advantage(self):
        actor = _make_actor_with_access(actor_type="malicious-insider")
        assert "missing_insider_advantage" in [
            v.rule for v in validate_actor_access_provenance(actor)
        ]
        actor = _make_actor_with_access(
            actor_type="malicious-insider",
            material_insider_advantage="knowledge of internal validation bypass",
        )
        assert validate_actor_access_provenance(actor) == []

    def test_privileged_insider_still_requires_material_advantage(self):
        """Direct insiders require material advantage regardless of access_class."""
        actor = _make_actor_with_access(
            actor_type="malicious-insider", access_class="privileged"
        )
        assert "missing_insider_advantage" in [
            v.rule for v in validate_actor_access_provenance(actor)
        ]
        actor = _make_actor_with_access(
            actor_type="malicious-insider",
            access_class="privileged",
            material_insider_advantage="Internal admin credentials and network access.",
        )
        assert validate_actor_access_provenance(actor) == []


class TestBuildActorAccessProvenance:
    @pytest.mark.parametrize("controllability", ["direct", "indirect"])
    def test_ingress_derived_but_access_class_from_response(self, controllability):
        access_class = (
            "authenticated" if controllability == "direct" else "supply_chain"
        )
        _, _, _, boundary_id = _make_indirect_profile()
        resp = _make_call0_response(
            access_class=access_class,
            influence_source="ep:v1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
            influence_mechanism="poisoning",
            trust_boundary_id=boundary_id,
        )
        access = build_actor_access_provenance(
            "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            controllability,
            "cybercriminal",
            resp,
        )
        assert access.ingress_mode == controllability
        assert access.access_class == access_class

    def test_profile_resolves_human_names_to_canonical_ids(self):
        profile, target_id, source_id, boundary_id = _make_indirect_profile()
        target, source = profile.entry_points
        boundary = profile.trust_boundaries[0]
        resp = _make_call0_response(
            access_class="supply_chain",
            influence_source=source.name,
            influence_mechanism="document poisoning",
            trust_boundary_id=boundary.name,
        )

        access = build_actor_access_provenance(
            target_id,
            "indirect",
            "supply-chain-actor",
            resp,
            profile=profile,
        )

        assert access.initial_entry_point_id == target.entry_point_id == target_id
        assert access.influence_source == source.entry_point_id == source_id
        assert access.trust_boundary_id == boundary.trust_boundary_id == boundary_id

    @pytest.mark.parametrize("controllability", ["system", None])
    def test_ineligible_controllability_does_not_default_to_direct(
        self, controllability
    ):
        with pytest.raises(ValueError, match="not eligible ingress"):
            build_actor_access_provenance(
                "ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                controllability,
                "cybercriminal",
                _make_call0_response(),
            )


class TestCanonicalAccessChecks:
    """Rule coverage for the canonical-profile resolution helper.

    Each case drives ``validate_actor_access_provenance`` with a profile so
    the canonical checks (rules 5-8) run against real profile inventories.
    """

    def _actor(
        self,
        entry_point_id: str,
        *,
        ingress_mode: str = "indirect",
        access_class: str = "authenticated",
        source_id: str | None = None,
        source_kind: str | None = None,
        mechanism: str = "document poisoning",
        boundary_id: str | None = None,
    ) -> ActorProfile:
        return _make_actor_with_access(
            actor_type="cybercriminal",
            entry_point_id=entry_point_id,
            ingress_mode=ingress_mode,
            access_class=access_class,
            influence_source=source_id,
            influence_mechanism=mechanism,
            trust_boundary_id=boundary_id,
        )

    def _rules(self, actor: ActorProfile, profile: CapabilityProfile) -> list[str]:
        return [v.rule for v in validate_actor_access_provenance(actor, profile)]

    def test_system_controllability_ingress_flagged(self):
        profile = _make_profile([_make_entry_point(controllability="system")])
        actor = self._actor(
            profile.entry_points[0].entry_point_id,
            ingress_mode="direct",
            access_class="public",
        )

        rules = self._rules(actor, profile)

        assert "system_entry_point_as_ingress" in rules
        assert "ineligible_ingress_entry_point" in rules

    def test_ingress_mode_controllability_mismatch_flagged(self):
        profile = _make_profile([_make_entry_point()])
        target_id = profile.entry_points[0].entry_point_id
        source = EntryPoint(
            name="memory store feed",
            direction="input",
            controllability="indirect",
            ingress_zone="memory",
        )
        boundary = TrustBoundary(
            name="memory-to-input",
            from_zone="memory",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            [_make_entry_point(), source],
            trust_boundaries=[boundary],
        )
        actor = self._actor(
            target_id,
            source_id=source.entry_point_id,
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == ["ingress_mode_controllability_mismatch"]

    def _integration_actor(
        self,
        entry_point_id: str,
        *,
        source_id: str,
        boundary_id: str,
    ) -> ActorProfile:
        return ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
            access=ActorAccessProvenance(
                initial_entry_point_id=entry_point_id,
                ingress_mode="indirect",
                access_class="supply_chain",
                influence_source=source_id,
                influence_source_kind="integration",
                influence_mechanism="poisoned source data",
                trust_boundary_id=boundary_id,
            ),
        )

    def test_unresolved_integration_source_flagged(self):
        profile, target_id, _, _ = _make_indirect_profile()
        boundary = TrustBoundary(
            name="external-to-input",
            from_zone="input",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            profile.entry_points,
            trust_boundaries=[boundary],
        )
        actor = self._integration_actor(
            target_id,
            source_id="integration:missing",
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == ["unresolved_influence_source"]

    def test_resolved_integration_source_passes(self):
        profile, target_id, _, _ = _make_indirect_profile()
        integrations = [
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ]
        boundary = TrustBoundary(
            name="external-to-input",
            from_zone="input",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = CapabilityProfile(
            zones_active=profile.zones_active,
            entry_points=profile.entry_points,
            trust_boundaries=[boundary],
            confidence=ConfidenceLevel.high,
            kc_subcodes=["KC1.1"],
            external_integrations=integrations,
        )
        integration_id = profile.external_integrations[0].integration_id
        actor = self._integration_actor(
            target_id,
            source_id=integration_id,
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == []

    def test_self_relation_influence_source_flagged(self):
        profile = _make_profile([_make_entry_point(controllability="indirect")])
        target_id = profile.entry_points[0].entry_point_id
        actor = self._actor(
            target_id,
            source_id=target_id,
            boundary_id="tb:v1:cccccccccccccccccccccccccccccccc",
        )

        assert self._rules(actor, profile) == ["self_relation_influence_source"]

    def test_output_influence_source_flagged(self):
        target = _make_entry_point("RAG retrieval", controllability="indirect")
        source = EntryPoint(
            name="status notifications",
            direction="output",
            controllability="direct",
        )
        boundary = TrustBoundary(
            name="output-to-input",
            from_zone="output",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            [target, source],
            trust_boundaries=[boundary],
        )
        actor = self._actor(
            target.entry_point_id,
            source_id=source.entry_point_id,
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == ["output_influence_source"]

    def test_system_influence_source_flagged(self):
        target = _make_entry_point("RAG retrieval", controllability="indirect")
        source = EntryPoint(
            name="telemetry feed",
            direction="input",
            controllability="system",
        )
        boundary = TrustBoundary(
            name="telemetry-to-input",
            from_zone="input",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            [target, source],
            trust_boundaries=[boundary],
        )
        actor = self._actor(
            target.entry_point_id,
            source_id=source.entry_point_id,
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == ["system_influence_source"]

    def test_trust_boundary_target_zone_mismatch_flagged(self):
        target = EntryPoint(
            name="RAG retrieval",
            direction="input",
            controllability="indirect",
            ingress_zone="reasoning",
        )
        source = EntryPoint(
            name="memory store feed",
            direction="input",
            controllability="indirect",
            ingress_zone="memory",
        )
        boundary = TrustBoundary(
            name="memory-to-input",
            from_zone="memory",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            [target, source],
            trust_boundaries=[boundary],
        )
        actor = self._actor(
            target.entry_point_id,
            source_id=source.entry_point_id,
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == ["trust_boundary_target_zone_mismatch"]

    def test_trust_boundary_source_zone_mismatch_flagged(self):
        target = _make_entry_point("RAG retrieval", controllability="indirect")
        source = EntryPoint(
            name="memory store feed",
            direction="input",
            controllability="indirect",
            ingress_zone="memory",
        )
        boundary = TrustBoundary(
            name="input-to-input",
            from_zone="input",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            [target, source],
            trust_boundaries=[boundary],
        )
        actor = self._actor(
            target.entry_point_id,
            source_id=source.entry_point_id,
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == ["trust_boundary_source_zone_mismatch"]

    def test_external_boundary_source_not_indirect_flagged(self):
        target = _make_entry_point("RAG retrieval", controllability="indirect")
        source = _make_entry_point("batch upload")
        boundary = TrustBoundary(
            name="external-to-input",
            from_zone="external",
            to_zone="input",
            confidence=BoundaryConfidence.explicit,
        )
        profile = _make_profile(
            [target, source],
            trust_boundaries=[boundary],
        )
        actor = self._actor(
            target.entry_point_id,
            access_class="supply_chain",
            source_id=source.entry_point_id,
            boundary_id=boundary.trust_boundary_id,
        )

        assert self._rules(actor, profile) == ["external_boundary_source_not_indirect"]


class TestIngressAndDiversity:
    def test_system_and_output_entry_points_are_not_ingress(self):
        assert not is_attacker_accessible_ingress(
            _make_entry_point(controllability="system")
        )
        assert not is_attacker_accessible_ingress(
            _make_entry_point(direction="output", controllability="direct")
        )

    def test_no_blanket_indirect_actor_allowlist(self):
        compatible = compute_compatible_actor_types([], "indirect", "T2")
        assert {"cybercriminal", "adversarial-user", "hacktivist"} <= compatible

    def test_incompatible_forced_type_replaced_before_prompt_rendering(self):
        # This supply-chain technique restricts the feasible actor set.
        seed = _make_seed(atlas_ids=["AML.T0010"])
        ctx = build_call0_context(
            seed,
            _make_profile(),
            "test",
            pinned_technique_ids=["AML.T0010"],
            forced_actor_type="adversarial-user",
        )
        assert ctx["diversity_limitation"] == "adversarial-user"
        assert "actor_type: adversarial-user" not in ctx["diversity_section"]
        feasible = set(ctx["compatible_actor_types"])
        rendered_type = next(
            actor
            for actor in feasible
            if f"actor_type: {actor}" in ctx["diversity_section"]
        )
        assert rendered_type in feasible


@patch(
    "asago_scenario_generator.pipeline.projection_validation.validate_projection_traceability",
    new=MagicMock(return_value=ProjectionTraceabilityResult(valid=True, violations=[])),
)
class TestRetryRouting:
    """Tests retry routing; _assemble_envelope is mocked so traceability
    validation is patched to valid (covered by the dedicated suite)."""

    _PATCHES: ClassVar[list[str]] = [
        "asago_scenario_generator.pipeline.generate._assemble_envelope",
        "asago_scenario_generator.pipeline.generate._call_attack_tree",
        "asago_scenario_generator.pipeline.generate._call_behavior_spec",
        "asago_scenario_generator.pipeline.generate._call_narrative",
        "asago_scenario_generator.pipeline.generate._call_actor_profile",
    ]

    @staticmethod
    def _generate(profile, ep, actor_results, caplog=None):
        from asago_scenario_generator.pipeline.generate import generate_scenario

        llm_result = LLMResult(
            content=None, prompt_tokens=100, completion_tokens=50, duration_ms=500
        )
        with (
            patch(
                TestRetryRouting._PATCHES[4], side_effect=actor_results
            ) as mock_actor,
            patch(TestRetryRouting._PATCHES[3], return_value=(MagicMock(), llm_result)),
            patch(TestRetryRouting._PATCHES[2], return_value=(MagicMock(), llm_result)),
            patch(TestRetryRouting._PATCHES[1], return_value=(MagicMock(), llm_result)),
            patch(TestRetryRouting._PATCHES[0], return_value=MagicMock()) as assemble,
        ):
            generate_scenario(
                seed=_make_seed(),
                profile=profile,
                client=MagicMock(model="test"),
                use_case="test",
                pinned_entry_point=ep.name,
                pinned_entry_point_id=ep.entry_point_id,
                run_id="20240101T120000_abcdef1234567890abcdef1234567890",
                candidate_id="",
                projected_candidate=get_projected_candidate(),
                capability_snapshot=get_test_snapshot(),
            )
        return mock_actor, assemble

    def test_retry_passes_access_feedback_to_actor_call(self):
        ep = _make_entry_point()
        profile = _make_profile([ep])
        bad = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        good = _make_actor_with_access(entry_point_id=ep.entry_point_id)
        result = LLMResult(
            content=None, prompt_tokens=1, completion_tokens=1, duration_ms=1
        )
        mock_actor, _ = self._generate(
            profile, ep, [(bad, result, None), (good, result, None)]
        )
        assert mock_actor.call_count == 2
        assert (
            "no typed access provenance"
            in mock_actor.call_args_list[1].kwargs["access_feedback"]
        )

    def test_persistent_violations_warn_and_proceed_to_semantic_validation(
        self, caplog
    ):
        ep = _make_entry_point()
        profile = _make_profile([ep])
        bad = ActorProfile(
            actor_type="cybercriminal",
            capability_level="intermediate",
            beliefs=["b"],
            desires=["d"],
            intentions=["i"],
            resources=["r"],
        )
        result = LLMResult(
            content=None, prompt_tokens=1, completion_tokens=1, duration_ms=1
        )
        with caplog.at_level("WARNING"):
            mock_actor, assemble = self._generate(
                profile, ep, [(bad, result, None)] * (1 + _ACTOR_ACCESS_MAX_RETRIES)
            )
        assert mock_actor.call_count == 1 + _ACTOR_ACCESS_MAX_RETRIES
        assert assemble.called
        assert "proceeding to semantic validation" in caplog.text

    def test_diversity_limitation_persisted_in_assemble_notes(self):
        """Diversity limitation notes are passed to _assemble_envelope."""
        from asago_scenario_generator.pipeline.generate import generate_scenario

        ep = _make_entry_point()
        profile = _make_profile([ep])
        good = _make_actor_with_access(entry_point_id=ep.entry_point_id)
        result = LLMResult(
            content=None, prompt_tokens=1, completion_tokens=1, duration_ms=1
        )
        llm_result = LLMResult(
            content=None, prompt_tokens=100, completion_tokens=50, duration_ms=500
        )
        # Use a seed with supply-chain technique that restricts actors,
        # and force an incompatible actor type to trigger the limitation.
        seed = _make_seed(atlas_ids=["AML.T0010"])
        with (
            patch(
                TestRetryRouting._PATCHES[4],
                return_value=(good, result, "adversarial-user"),
            ),
            patch(TestRetryRouting._PATCHES[3], return_value=(MagicMock(), llm_result)),
            patch(TestRetryRouting._PATCHES[2], return_value=(MagicMock(), llm_result)),
            patch(TestRetryRouting._PATCHES[1], return_value=(MagicMock(), llm_result)),
            patch(TestRetryRouting._PATCHES[0], return_value=MagicMock()) as assemble,
        ):
            generate_scenario(
                seed=seed,
                profile=profile,
                client=MagicMock(model="test"),
                use_case="test",
                pinned_entry_point=ep.name,
                pinned_entry_point_id=ep.entry_point_id,
                pinned_technique_ids=["AML.T0010"],
                preferred_actor_type="adversarial-user",
                run_id="20240101T120000_abcdef1234567890abcdef1234567890",
                candidate_id="",
                projected_candidate=get_projected_candidate(),
                capability_snapshot=get_test_snapshot(),
            )
        _, assemble_kwargs = assemble.call_args
        notes = assemble_kwargs.get("notes", [])
        assert any("Diversity limitation" in n for n in notes)


def test_diversity_limitation_round_trip_serialization():
    """Diversity limitation notes survive model serialization round-trip."""
    from asago_scenario_generator.models.scenario import GenerationMetadata

    notes = [
        (
            "Diversity limitation: forced actor 'adversarial-user' was "
            "incompatible, replaced with feasible fallback."
        )
    ]
    gen = GenerationMetadata(model="test", call_metadata=[], notes=notes)
    dumped = gen.model_dump()
    restored = GenerationMetadata.model_validate(dumped)
    assert restored.notes == notes
    assert "Diversity limitation" in restored.notes[0]


def test_actor_type_constants_remain_complete():
    assert _INSIDER_ACTOR_TYPES == {"malicious-insider", "negligent-insider"}
    assert set(ACTOR_TYPES) == set(ALL_ACTOR_TYPES)
    assert len(ALL_ACTOR_TYPES) == 9


# ---------------------------------------------------------------------------#
# Zero-coverage internals: access provenance prompt block (CRAP slice 4)
# ---------------------------------------------------------------------------#


class TestAccessProvenanceBlockWithNames:
    """Rendering of the access provenance block with human-readable names."""

    def test_none_access_renders_empty_block(self) -> None:
        profile = _make_indirect_profile()[0]

        assert access_provenance_block_with_names(None, profile) == ""

    def test_full_record_renders_every_named_line(self) -> None:
        profile, target_id, source_id, boundary_id = _make_indirect_profile()
        access = ActorAccessProvenance(
            initial_entry_point_id=target_id,
            ingress_mode="indirect",
            access_class="public",
            influence_source=source_id,
            influence_source_kind="entry_point",
            influence_mechanism="poisoning",
            trust_boundary_id=boundary_id,
            material_insider_advantage="custodian of memory store",
        )

        block = access_provenance_block_with_names(access, profile)

        assert "- initial_entry_point_id: RAG retrieval\n" in block
        assert "- ingress_mode: indirect\n" in block
        assert "- access_class: public\n" in block
        assert "- influence_source: memory store feed\n" in block
        assert "- influence_mechanism: poisoning\n" in block
        assert "- trust_boundary_id: memory-to-input\n" in block
        assert "- material_insider_advantage: custodian of memory store\n" in block

    def test_absent_optional_fields_omit_their_lines(self) -> None:
        profile, target_id, _source_id, _boundary_id = _make_indirect_profile()
        access = ActorAccessProvenance(
            initial_entry_point_id=target_id,
            ingress_mode="direct",
            access_class="public",
        )

        block = access_provenance_block_with_names(access, profile)

        assert "- initial_entry_point_id: RAG retrieval\n" in block
        assert "- influence_source:" not in block
        assert "- influence_mechanism:" not in block
        assert "- trust_boundary_id:" not in block
        assert "- material_insider_advantage:" not in block

    def test_unknown_influence_source_kind_falls_back_to_entry_point(self) -> None:
        profile, target_id, source_id, _boundary_id = _make_indirect_profile()
        access = ActorAccessProvenance(
            initial_entry_point_id=target_id,
            ingress_mode="indirect",
            access_class="public",
            influence_source=source_id,
            influence_source_kind=None,
            influence_mechanism="poisoning",
            trust_boundary_id=_boundary_id,
        )

        block = access_provenance_block_with_names(access, profile)

        assert "- influence_source: memory store feed\n" in block

    def test_custom_header_is_respected(self) -> None:
        profile, target_id, source_id, boundary_id = _make_indirect_profile()
        access = ActorAccessProvenance(
            initial_entry_point_id=target_id,
            ingress_mode="indirect",
            access_class="public",
            influence_source=source_id,
            influence_source_kind="entry_point",
            influence_mechanism="poisoning",
            trust_boundary_id=boundary_id,
        )
        header = "## Custom narrative header\n"

        block = access_provenance_block_with_names(access, profile, header=header)

        assert block.startswith(header)
        assert "- initial_entry_point_id: RAG retrieval\n" in block
