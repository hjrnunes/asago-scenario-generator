"""The revision prompt shows the structure it asks the model to extend.

The system prompt lists every nested element with its description and the
reference a new element must connect to, and states the next free mechanism
and process numbers. The user prompt carries only the critic findings and the
add-or-dismiss task.
"""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    CoordinationMechanism,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
    RevisionDelta,
    run_revision,
)
from tests.stpa.sp1_helpers import MockLLMClient

_EMPTY_DELTA = {
    "new_responsibilities": [],
    "new_controlled_processes": [],
    "new_coordination_links": [],
    "modified_responsibilities": [],
    "dismissed_gaps": ["the system has no multi-agent capability"],
}


def _responsibility(number: int, *, feedback_source: ElementRef | None):
    return Responsibility(
        resp_id=f"RESP-{number}",
        description=f"Retrieval controller {number}",
        responsibility_constraints=[
            ResponsibilityConstraint(
                rc_id=f"RC-{number}-1",
                description="retrieved content must carry provenance",
            )
        ],
        process_model_parts=[
            ProcessModelPart(
                pm_id=f"PM-{number}-1",
                description="belief about retrieval source integrity",
                feedback_source=feedback_source,
            )
        ],
        control_actions=[
            ControlAction(
                ca_id=f"CA-{number}-1",
                description="reject unverified retrieved content",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
        feedback_channels=[
            FeedbackChannel(
                fb_id=f"FB-{number}-1",
                description="provenance verdict from the index",
                updates=f"PM-{number}-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            )
        ],
    )


def _structure(*, pm_source: ElementRef | None) -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            _responsibility(1, feedback_source=pm_source),
            _responsibility(2, feedback_source=None),
        ],
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Index")],
        coordination_links=[
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-2-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-4",
                    description="Shared session scope",
                    payload="session id",
                ),
                description="Scope handoff",
            )
        ],
    )


def _findings() -> CriticFindings:
    return CriticFindings(
        gaps=[
            CriticGap(
                gap_type="missing_feedback",
                description="No provenance check on retrieved content",
                related_attack_path="Poisoned document reaches the answer",
                suggested_remedy="Add a provenance feedback channel",
            )
        ],
        checklist_results={"Outcome verification": "absent_unjustified"},
        taxonomy_probe_results={},
    )


def _prompts(tmp_path: Path, structure: ControlStructure) -> tuple[str, str]:
    client = MockLLMClient()
    client.set_response_for(RevisionDelta, _EMPTY_DELTA)
    run_revision(
        llm_client=client,
        control_structure=structure,
        critic_findings=_findings(),
        use_case_text="A retrieval assistant answers from customer records.",
        run_dir=tmp_path,
    )
    call = client.calls[0]
    return call.system_prompt, call.user_prompt


def test_system_prompt_lists_elements_with_descriptions_and_references(
    tmp_path: Path,
) -> None:
    system, _ = _prompts(
        tmp_path,
        _structure(
            pm_source=ElementRef(type=ReferenceType.responsibility, id="RESP-2")
        ),
    )

    pm_line = next(line for line in system.splitlines() if "PM-1-1:" in line)
    assert "PM-1-1: belief about retrieval source integrity (source: " in pm_line
    assert pm_line.endswith("responsibility RESP-2)")
    for fragment in (
        "RC-1-1: retrieved content must carry provenance",
        "CA-1-1: reject unverified retrieved content (target: controlled_process CP-1)",
        "FB-1-1: provenance verdict from the index (updates: PM-1-1, source: "
        "controlled_process CP-1",
        "(mechanism: CM-4 — Shared session scope)",
        "(next available: CM-5)",
        "(next available: CP-2)",
    ):
        assert fragment in system


def test_system_prompt_renders_a_missing_feedback_source(tmp_path: Path) -> None:
    system, _ = _prompts(tmp_path, _structure(pm_source=None))

    assert "PM-1-1: belief about retrieval source integrity\n" in system
    assert "{{" not in system
    assert "{%" not in system


def test_user_prompt_carries_findings_and_task_without_the_structure(
    tmp_path: Path,
) -> None:
    _, user = _prompts(tmp_path, _structure(pm_source=None))

    for fragment in (
        "## Critic Findings",
        "**missing_feedback**: No provenance check on retrieved content",
        "Attack path: Poisoned document reaches the answer",
        "Suggested remedy: Add a provenance feedback channel",
        "Outcome verification: absent_unjustified",
        "add the missing element(s) to the RevisionDelta",
        "dismiss it with a one-sentence justification in dismissed_gaps",
        "Focus on real behavioral deficiencies",
        "duplicate existing coverage or target capabilities the system does not have",
    ):
        assert fragment in user
    for absent in ("Current Control Structure", "RESP-1", "A retrieval assistant"):
        assert absent not in user
