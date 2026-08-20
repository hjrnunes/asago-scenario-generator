"""Shared deterministic fixtures for generate-path source-influence provenance.

Both the unit tests (``tests/test_source_influence_provenance.py``) and the
acceptance runtime handlers (``acceptance/runtime_features/taxonomy_risk.py``)
drive the real generate path with the same scripted inputs: a KCX capability
profile carrying capability-constraint sub-codes, the three-leaf/three-step
projection fixtures, and a builder seed.  These factories keep the two
surfaces in lockstep, so the generate-path acceptance scenarios (TSIP 10-12)
and the unit tests exercise identical artifact surfaces.
"""

from __future__ import annotations

from collections.abc import Sequence

from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    AuthoritativeFactReference,
    EvaluatedFactEvidence,
)
from asago_scenario_generator.models.attack_tree import (
    AiSystemAction,
    AttackTree,
    AttackTreeNode,
    GateType,
    ImpactAction,
    InitialIngressAction,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.scenario import (
    ActorAccessProvenance,
    ActorProfile,
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
    RiskCardRef,
)
from asago_scenario_generator.pipeline.projection import (
    CapabilityFactSnapshot,
    ProjectedCandidate,
    ProjectionBudget,
    capture_capability_snapshot,
    project_authoritative_candidates,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed
from tests.helpers.projection_factory import (
    get_test_raw_pattern,
    get_test_resolver,
    make_step_realizations,
)

__all__ = [
    "builder_seed",
    "kcx_profile",
    "kcx_snapshot",
    "make_actor",
    "make_narrative",
    "make_tree",
    "projected_candidate",
]


def builder_seed(
    *,
    seed_id: str = "AP-T12-01",
    threat_id: str = "T12",
    agentic: Sequence[str] = ("T12", "T13"),
) -> ScenarioSeed:
    """ScenarioSeed fixture for the generate-path provenance assembler."""
    return ScenarioSeed(
        seed_id=seed_id,
        threat_id=threat_id,
        threat_name="Unauthorized instructing",
        threat_description="Test threat description",
        attack_pattern_name="Pattern",
        attack_pattern_description="Test pattern description",
        risk_card_ref=RiskCardRef(
            risk_id="risk-1",
            risk_name="Risk 1",
            risk_description="Description",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
        ),
        owasp_llm_ids=["LLM01"],
        agentic_threat_ids=list(agentic),
        atlas_technique_ids=["AML.T0054"],
    )


def kcx_profile(
    *,
    kc_subcodes: Sequence[str] = ("KCX-MAGENT", "KCX-VSTORE"),
) -> CapabilityProfile:
    """Capability profile carrying KCX capability-constraint sub-codes.

    Mirrors the shared projection fixture's resource surface so the KCX
    profile yields a feasible projected candidate with the same bound
    resources.
    """
    return CapabilityProfile(
        zones_active=["input", "reasoning", "tool_execution"],
        entry_points=[
            {"name": "chat", "direction": "input", "controllability": "direct"},
            {
                "name": "RAG documents",
                "direction": "input",
                "controllability": "indirect",
            },
        ],
        confidence="high",
        kc_subcodes=list(kc_subcodes),
        tool_inventory=[{"name": "writer", "description": "changes state"}],
        tool_types=[
            {
                "name": "writer",
                "zone": "tool_execution",
                "can_modify_state": True,
                "data_sensitivity": "medium",
                "code_execution": False,
            }
        ],
        external_integrations=[
            {
                "name": "CRM",
                "integration_type": "api",
                "auth_method": "oauth",
                "data_sensitivity": "high",
            }
        ],
        trust_boundaries=[
            {
                "name": "user-to-agent",
                "from_zone": "input",
                "to_zone": "reasoning",
                "confidence": "explicit",
            }
        ],
    )


def kcx_snapshot(
    profile: CapabilityProfile | None = None,
) -> CapabilityFactSnapshot:
    """Content-addressed capability snapshot over the KCX profile."""
    return capture_capability_snapshot(
        profile if profile is not None else kcx_profile()
    )


def projected_candidate(
    profile: CapabilityProfile | None = None,
) -> tuple[ProjectedCandidate, CapabilityFactSnapshot]:
    """Projected candidate bound to the KCX capability snapshot."""
    profile = profile if profile is not None else kcx_profile()
    raw = get_test_raw_pattern()
    AttackPattern.model_validate(raw)
    resolver = get_test_resolver()
    evidence = EvaluatedFactEvidence(
        fact=AuthoritativeFactReference.model_validate(
            {
                "namespace": "profile",
                "fact_id": "mode",
                "value_type": "string",
                "property_path": [],
            }
        ),
        status="present",
        value="active",
    )
    snapshot = capture_capability_snapshot(profile, (evidence,))
    batch = project_authoritative_candidates(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=100),
    )
    assert len(batch.candidates) >= 1, "scripted projection emitted no candidates"
    return batch.candidates[0], snapshot


def make_tree(ingress_id: str) -> AttackTree:
    """Build the three-leaf projection-traceability attack tree."""
    return AttackTree(
        id="tree-AP-T1-01",
        seed_id="AP-T1-01",
        goal="Achieve attack objective",
        root=AttackTreeNode(
            id="n1",
            label="Attack goal",
            gate=GateType.AND,
            children=[
                AttackTreeNode(
                    id="n1.1",
                    label="Initial ingress",
                    gate=GateType.LEAF,
                    zone="input",
                    action=InitialIngressAction(entry_point_id=ingress_id),
                    projected_step_ids=("step.1",),
                    realizations=make_step_realizations(("step.1",)),
                ),
                AttackTreeNode(
                    id="n1.2",
                    label="System action",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=AiSystemAction(),
                    projected_step_ids=("step.2",),
                    realizations=make_step_realizations(("step.2",)),
                ),
                AttackTreeNode(
                    id="n1.3",
                    label="Impact",
                    gate=GateType.LEAF,
                    zone="reasoning",
                    action=ImpactAction(boundary="internal", target="data integrity"),
                    projected_step_ids=("step.3",),
                    realizations=make_step_realizations(("step.3",)),
                ),
            ],
        ),
    )


def make_narrative(ingress_id: str) -> NarrativeLayer:
    """Build the three-step fixture narrative for the generate path."""
    return NarrativeLayer(
        title="Test scenario",
        summary="Adversarial summary",
        entry_point="chat",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="gain access",
                effect="entry",
                projected_step_ids=("step.1",),
                realizations=make_step_realizations(("step.1",)),
            ),
            NarrativeStep(
                step_number=2,
                zone="reasoning",
                action="exploit",
                effect="control",
                projected_step_ids=("step.2",),
                realizations=make_step_realizations(("step.2",)),
            ),
            NarrativeStep(
                step_number=3,
                zone="reasoning",
                action="impact",
                effect="damage",
                projected_step_ids=("step.3",),
                realizations=make_step_realizations(("step.3",)),
            ),
        ],
        access_realization=NarrativeAccessRealization(
            initial_entry_point_id=ingress_id,
            responsible_step_number=1,
        ),
    )


def make_actor(ingress_id: str) -> ActorProfile:
    """Build the shared envelope actor fixture for provenance tests."""
    return ActorProfile(
        actor_type="cybercriminal",
        capability_level="intermediate",
        beliefs=["target has chat interface"],
        desires=["steal data"],
        intentions=["prompt injection"],
        resources=["open-source tools"],
        access=ActorAccessProvenance(
            initial_entry_point_id=ingress_id,
            ingress_mode="direct",
            access_class="public",
        ),
    )
