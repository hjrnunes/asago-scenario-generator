"""The critic prompt shows what the control structure does, not bare IDs.

Every nested element renders with its description, the loss analysis renders
when supplied (with a stated fallback when not), and coordination-analysis
warnings get their own section only when present.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    run_completeness_critic,
)
from tests.helpers.stpa_builders import make_capability_profile
from tests.stpa.sp1_helpers import MockLLMClient, valid_critic_findings_dict_no_gaps

_WARNING = "CL-2 shares a process model part outside its source responsibility"


def _structure() -> ControlStructure:
    def responsibility(number: int, rc: str, pm: str, ca: str, fb: str):
        return Responsibility(
            resp_id=f"RESP-{number}",
            description=f"Retrieval controller {number}",
            responsibility_constraints=[
                ResponsibilityConstraint(rc_id=f"RC-{number}-1", description=rc)
            ],
            process_model_parts=[
                ProcessModelPart(pm_id=f"PM-{number}-1", description=pm)
            ],
            control_actions=[ControlAction(ca_id=f"CA-{number}-1", description=ca)],
            feedback_channels=[
                FeedbackChannel(
                    fb_id=f"FB-{number}-1",
                    description=fb,
                    updates=f"PM-{number}-1",
                    source=ElementRef(
                        type=ReferenceType.responsibility, id=f"RESP-{number}"
                    ),
                )
            ],
        )

    return ControlStructure(
        responsibilities=[
            responsibility(
                1,
                "retrieved content must carry provenance",
                "belief about retrieval source integrity",
                "reject unverified retrieved content",
                "provenance verdict from the index",
            ),
            responsibility(2, "scope rule", "session scope", "filter", "scope verdict"),
        ],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-2-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Shared session scope",
                    payload="session id",
                ),
                description="Scope handoff",
            )
        ],
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorised disclosure of customer records",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="Retrieval returns records outside the session scope",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Retrieval must be scoped to the active session",
                related_hazards=["H-1"],
            )
        ],
    )


def _critic_user_prompt(
    tmp_path: Path,
    *,
    loss_analysis: LossAnalysis | None = None,
    call3_warnings: list[str] | None = None,
) -> str:
    client = MockLLMClient()
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    run_completeness_critic(
        llm_client=client,
        control_structure=_structure(),
        capability_profile=make_capability_profile(),
        use_case_text="A retrieval assistant answers from customer records.",
        run_dir=tmp_path,
        loss_analysis=loss_analysis,
        call3_warnings=call3_warnings,
    )
    return client.calls[0].user_prompt


@pytest.mark.parametrize(
    "line",
    [
        "RC-1-1: retrieved content must carry provenance",
        "PM-1-1: belief about retrieval source integrity",
        "CA-1-1: reject unverified retrieved content",
        "FB-1-1: provenance verdict from the index",
        "(mechanism: CM-1 — Shared session scope)",
    ],
)
def test_nested_elements_render_with_their_descriptions(
    tmp_path: Path, line: str
) -> None:
    assert line in _critic_user_prompt(tmp_path)


def test_nested_elements_are_not_bare_identifier_lists(tmp_path: Path) -> None:
    prompt = _critic_user_prompt(tmp_path)

    assert "PM-1-1, PM-2-1" not in prompt
    assert "CA-1-1, CA-2-1" not in prompt
    assert "FB-1-1, FB-2-1" not in prompt


def test_loss_analysis_renders_losses_hazards_and_constraints(tmp_path: Path) -> None:
    prompt = _critic_user_prompt(
        tmp_path, loss_analysis=_loss_analysis(), call3_warnings=[_WARNING]
    )

    for fragment in (
        "**L-1**: Unauthorised disclosure of customer records",
        "**H-1**: Retrieval returns records outside the session scope (linked to: L-1)",
        "**SC-1**: Retrieval must be scoped to the active session (mitigates: H-1)",
    ):
        assert fragment in prompt
    assert "Loss analysis not available" not in prompt


def test_missing_loss_analysis_renders_the_stated_fallback(tmp_path: Path) -> None:
    prompt = _critic_user_prompt(tmp_path)

    assert "Loss analysis not available." in prompt
    assert "{{" not in prompt
    assert "{%" not in prompt


def test_coordination_warnings_get_a_section_only_when_present(tmp_path: Path) -> None:
    with_warning = _critic_user_prompt(tmp_path, call3_warnings=[_WARNING])
    without = _critic_user_prompt(tmp_path / "none", call3_warnings=[])

    assert "## Coordination Analysis Warnings" in with_warning
    assert f"- {_WARNING}" in with_warning
    assert "Coordination Analysis Warnings" not in without
