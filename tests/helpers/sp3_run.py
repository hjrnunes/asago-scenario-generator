"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.enriched_threat_set import (
    CoverageAnalysis,
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from tests.stpa.sp1_helpers import MockLLMClient


def _make_loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["r1"],
            ),
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Must validate",
                related_hazards=["H-1"],
            ),
        ],
    )


def _make_ets(num_threats: int = 2) -> EnrichedThreatSet:
    threats = []
    for i in range(num_threats):
        threats.append(
            StructuralThreat(
                ica_slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                ica_id=f"RESP-1:CA-1-1:NOT_PROVIDED:{i + 1}",
                ica_text=f"ICA text {i + 1}",
                hazardous_context="Context",
                loss_scenario="Loss scenario",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
        )
    return EnrichedThreatSet(
        structural_threats=threats,
        coverage_analysis=CoverageAnalysis(
            structural_coverage={
                "total_slots": 4,
                "non_na": 2,
                "na": 2,
                "coverage_rate": 0.5,
            },
            structural_consideration={"total_slots": 4, "considered": 4, "rate": 1.0},
            na_quality={"na_count": 2, "quality_count": 2, "quality_rate": 1.0},
        ),
    )


def _semantics_wire(payload: dict) -> dict:
    """Reduce an execution-design Stage 5 payload to the scenario-semantics wire.

    A product run requests scenario semantics only: no stimulus, execution
    route, route selection, or executable condition.
    """
    semantics = {
        key: value
        for key, value in payload.items()
        if key not in {"stimulus", "execution_route"}
    }
    semantics["causal_factors"] = [
        {key: value for key, value in factor.items() if key != "selected_for_route"}
        for factor in payload["causal_factors"]
    ]
    semantics["unsafe_outcome"] = {
        "semantic_proposition": payload["unsafe_outcome"]["semantic_proposition"],
        "observation_criteria": [
            {
                "criterion_id": "reply_outcome",
                "outcome": "The assistant reply omits the requested action.",
                "observable": True,
                "claim_level": "reply",
                "evidence": "assistant_message",
                "reason": "The qualification adapter captures assistant messages.",
            }
        ],
        "safe_observable_outcome": {
            "observable": True,
            "statement": "The assistant reply preserves the requested action.",
            "claim_level": "reply",
            "evidence": "assistant_message",
            "operation_name": None,
            "record_refs": [],
            "fact_refs": [],
        },
    }
    return semantics


def _setup_mock_client(num_threats: int = 2) -> MockLLMClient:
    """Set up a mock LLM client with one valid Stage 5 response per threat."""
    client = MockLLMClient()

    # Stage 5 responses — one per threat
    bdi_responses = []
    for i in range(num_threats):
        bdi_responses.append(
            {
                "stimulus": {
                    "category": "user_message",
                    "description": "One user message is the typed test stimulus.",
                },
                "adversary": {
                    "kind": "malicious_customer",
                    "gain": "Learns another customer's order details.",
                },
                "attacker_bdi": {
                    "beliefs": [f"attacker belief {i + 1}"],
                    "desires": ["induce ICA"],
                    "intentions": [
                        {
                            "description": "Exploit stale PM-1-1 state before CA-1-1.",
                            "source_handles": ["cause_1"],
                        }
                    ],
                },
                "causal_factors": [
                    {
                        "source_handle": "cause_1",
                        "evidence": f"The selected state can be stale ({i + 1}).",
                        "temporal_condition": None,
                        "evidence_status": "structural_failure",
                        "selected_for_route": True,
                    }
                ],
                "unsafe_outcome": {
                    "condition": {
                        "type": "action_presence",
                        "control_action_id": "CA-1-1",
                        "expected": "not_provided",
                    },
                    "semantic_proposition": (
                        "The response does not provide the requested action."
                    ),
                },
                "execution_route": {
                    "disposition": "executable_route",
                    "action_kind": "model_output",
                    "reason": "The selected structural factor supports the direct route.",
                },
            }
        )

    client.set_response_queue([_semantics_wire(payload) for payload in bdi_responses])
    return client
