"""What the target-realization prompts render from the systemic baseline.

Each test runs the realization the way a run does: baseline rows, the
bounded extension and its verifier, then the target-derived ICA draft and
its verifier, all through the LLM adapters and a recording mock client.
"""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import SystemicStpaBaseline
from asago_scenario_generator.pipeline.target_realization import (
    observed_operations,
    realize_baseline_rows,
    realize_target_derived_icas,
    realize_target_operations,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlledProcess,
    ControlStructure,
    ElementRef,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.target_realization import (
    TargetDerivedICALlmFinder,
    TargetRealizationLlmInterpreter,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.target_realization import _profile
from tests.stpa.sp1_helpers import MockLLMClient

_BASELINE_PROMPT_STEPS = {
    "extend_uncovered_operations",
    "enumerate_target_derived_icas",
    "verify_target_derived_icas",
}


def _baseline(**ica_fields) -> SystemicStpaBaseline:
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="payment loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="bad payment", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="payments are authorized",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="payment controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Controller approves a refund",
                        target=ElementRef(
                            type=ReferenceType.controlled_process, id="CP-1"
                        ),
                        effect_kind=ControlActionEffectKind.state_change,
                    )
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="payment ledger")
        ],
    )
    ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.not_provided,
                is_na=False,
                icas=[
                    ICA(
                        ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                        ica_text="Baseline unsafe action.",
                        hazardous_context="Baseline context.",
                        loss_scenario="Baseline loss scenario.",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                        **ica_fields,
                    )
                ],
            )
        ]
    )
    return SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ica_enumeration,
        baseline_id="baseline:prompts",
    )


def _responses() -> list[dict]:
    """Return one reply per call: map, extend, verify extension, draft, verify."""
    return [
        {"control_action_id": "CA-1-1", "disposition": "unmapped"},
        {
            "outcomes": [
                {
                    "operation": {
                        "resource_id": "mcp:target:mini:get_payment",
                        "operation_id": "get_payment",
                    },
                    "disposition": "rejected",
                    "evidence_refs": ["inventory:tool:get_payment"],
                    "rationale": "Reading a payment changes no state.",
                },
                {
                    "operation": {
                        "resource_id": "mcp:target:mini:schedule_payment",
                        "operation_id": "schedule_payment",
                    },
                    "disposition": "accepted",
                    "control_action": {
                        "controller_id": "RESP-1",
                        "target": {"type": "controlled_process", "id": "CP-1"},
                    },
                    "ica_slots": [
                        {
                            "uca_type": "NOT_PROVIDED",
                            "action_temporality": "instantaneous",
                        }
                    ],
                    "evidence_refs": ["inventory:tool:schedule_payment"],
                    "rationale": "The operation changes payment state.",
                },
            ]
        },
        {
            "decision": "verified",
            "detail": "The observed operation realizes the additive action.",
            "evidence_refs": ["inventory:tool:schedule_payment"],
            "effect_match": "exact",
            "recipient_match": "not_applicable",
            "completion_match": "established",
        },
        {"findings": []},
        {"decisions": []},
    ]


def _rendered_prompts(baseline: SystemicStpaBaseline, run_dir) -> list[dict]:
    """Run the realization and return each call's step and rendered prompts."""
    client = MockLLMClient()
    client.set_response_queue(_responses())
    interpreter = TargetRealizationLlmInterpreter(client, run_dir, temperature=0.4)
    profile = _profile()
    rows, _diagnostics = realize_baseline_rows(
        baseline, observed_operations(profile), interpreter
    )
    realization = realize_target_operations(
        baseline, profile, interpreter, baseline_rows=rows
    )
    realize_target_derived_icas(
        baseline,
        realization,
        TargetDerivedICALlmFinder(client, run_dir, temperature=0.4),
    )
    steps = [entry["step"] for entry in read_calls_jsonl(run_dir)]
    assert len(steps) == len(client.calls)
    return [
        {
            "step": step,
            "system": call.system_prompt,
            "user": call.user_prompt,
        }
        for step, call in zip(steps, client.calls, strict=True)
    ]


def test_no_target_realization_prompt_renders_the_baseline_digest(tmp_path):
    baseline = _baseline()
    prompts = _rendered_prompts(baseline, tmp_path)

    assert _BASELINE_PROMPT_STEPS <= {prompt["step"] for prompt in prompts}
    for prompt in prompts:
        rendered = prompt["system"] + prompt["user"]
        assert baseline.baseline_digest not in rendered, prompt["step"]
        assert "baseline_digest" not in rendered, prompt["step"]
    extension = next(p for p in prompts if p["step"] == "extend_uncovered_operations")
    assert "baseline_id: baseline:prompts" in extension["user"]
