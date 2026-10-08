"""Shared test builders moved out of test modules."""

from __future__ import annotations

import yaml


from pathlib import Path
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient
from tests.helpers.sp3_run import _make_ets


def _client(payloads: list[dict]) -> MockLLMClient:
    client = MockLLMClient()
    client.set_response_queue(payloads)
    return client


def _publish(payloads: list[dict], run_dir: Path, **kwargs: object):
    return run_sp3(
        llm_client=_client(payloads),
        enriched_threat_set=_make_ets(num_threats=len(payloads)),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=run_dir,
        **kwargs,
    )


def _profile_condition() -> dict:
    """A generic condition over the observed-profile fixture's facts."""
    return {
        "statement": "The refund names a customer other than the signed-in customer.",
        "comparisons": [
            {
                "kind": "value",
                "left": {
                    "source": "argument",
                    "operation": "process_refund",
                    "argument": "customer_id",
                },
                "op": "ne",
                "right": {
                    "source": "fact",
                    "path": "TARGET-STATE.authenticated_customer_id",
                },
            }
        ],
        "record_selection": {
            "status": "unavailable",
            "reason": "The supplied state holds no order record.",
        },
    }


def _normal_semantics_payload() -> dict:
    """The normal-path wire: scenario semantics and causal evidence only.

    Finding A1: the normal publication requests no stimulus category, no
    execution route, no factor-route binding and no executable condition.
    """
    return {
        "adversary": {
            "kind": "malicious_customer",
            "gain": "Learns another customer's order details.",
        },
        "attacker_bdi": {
            "beliefs": ["attacker belief 1"],
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
                "evidence": "The selected state can be stale.",
                "temporal_condition": None,
                "evidence_status": "structural_failure",
            }
        ],
        "unsafe_outcome": {
            "semantic_proposition": (
                "The response does not provide the requested action."
            ),
            "observation_criteria": [
                {
                    "criterion_id": "reply_outcome",
                    "outcome": "The assistant reply omits the requested action.",
                    "observable": True,
                    "claim_level": "reply",
                    "evidence": "assistant_message",
                    "reason": (
                        "The qualification adapter captures assistant messages."
                    ),
                }
            ],
            "safe_observable_outcome": {
                "observable": True,
                "statement": (
                    "The assistant reply preserves the requested action "
                    "without producing the unsafe response."
                ),
                "claim_level": "reply",
                "evidence": "assistant_message",
                "operation_name": None,
                "record_refs": [],
                "fact_refs": [],
            },
        },
    }


def _functional_payload() -> dict:
    payload = _normal_semantics_payload()
    payload["adversary"] = {
        "kind": "none",
        "gain": "The requested service completes as designed.",
    }
    payload["attacker_bdi"] = {
        "beliefs": [],
        "desires": [],
        "intentions": [],
    }
    return payload


def _published_handoff(run_dir: Path, scenario_id: str = "SCN-001") -> dict:
    path = run_dir / "scenarios" / f"{scenario_id}.yaml"
    assert path.is_file(), f"missing handoff {path}"
    return yaml.safe_load(path.read_text(encoding="utf-8"))
