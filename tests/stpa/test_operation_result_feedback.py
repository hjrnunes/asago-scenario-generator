"""Feedback a responsibility receives from the operations it invokes.

An observed operation that declares an output returns its result to the
caller.  A tool-call action bound to such an operation therefore has
feedback from the process it targets back to the responsibility that issues
it; the step adds that channel, and the variable it updates, only where the
structure has no channel from that process to that responsibility.
"""

from __future__ import annotations

import json
from pathlib import Path

from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlledProcess,
    ControlStructure,
    ElementRef,
    FeedbackChannel,
    FeedbackSourceKind,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.spec_diagnostics import (
    SpecCheck,
    diagnose_final_artifacts,
)
from asago_scenario_generator.stpa.system_model.operation_feedback import (
    add_operation_result_feedback,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    EvidenceOperation,
    TargetEvidence,
    build_target_evidence,
)
from tests.helpers.stpa_builders import make_loss_analysis

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "miniocciai-baseline-rev2"


def _cp(cp_id: str) -> ElementRef:
    return ElementRef(type=ReferenceType.controlled_process, id=cp_id)


def _evidence(*operations: tuple[str, bool]) -> TargetEvidence:
    return TargetEvidence(
        operations=tuple(
            EvidenceOperation(
                name=name,
                description="Observed.",
                arguments=(),
                returns_result=returns_result,
            )
            for name, returns_result in operations
        )
    )


def _action(
    ca_id: str,
    *,
    operation: str | None = "process_refund",
    target: ElementRef | None = None,
    effect_kind: ControlActionEffectKind = ControlActionEffectKind.tool_call,
) -> ControlAction:
    return ControlAction(
        ca_id=ca_id,
        description=f"Action {ca_id}",
        target=target or _cp("CP-2"),
        effect_kind=effect_kind,
        operation=operation,
        process_model_refs=["PM-1-1"],
    )


def _structure(
    *actions: ControlAction, channels: list[FeedbackChannel] | None = None
) -> ControlStructure:
    return ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Conversation"),
            ControlledProcess(cp_id="CP-2", description="Payment engine"),
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Execute refunds",
                process_model_parts=[
                    ProcessModelPart(
                        pm_id="PM-1-1",
                        description="Refund eligibility",
                        values=["eligible", "not eligible", "unknown"],
                    )
                ],
                control_actions=list(actions),
                feedback_channels=channels
                if channels is not None
                else [
                    FeedbackChannel(
                        fb_id="FB-1-1",
                        description="User request",
                        updates="PM-1-1",
                        source=_cp("CP-1"),
                        source_kind=FeedbackSourceKind.user_message,
                    )
                ],
            )
        ],
    )


def _feedback_findings(structure: ControlStructure) -> list[tuple[str, ...]]:
    diagnostics = diagnose_final_artifacts(
        loss_analysis=make_loss_analysis(),
        control_structure=structure,
        ica_enumeration=None,
    )
    return [
        finding.subject_ids
        for finding in diagnostics.findings
        if finding.check is SpecCheck.controlled_process_without_feedback
    ]


def test_tool_call_result_becomes_feedback_from_the_target_to_the_caller() -> None:
    structure = _structure(_action("CA-1-1"))
    assert _feedback_findings(structure) == [("CP-2", "RESP-1", "CA-1-1")]

    fed = add_operation_result_feedback(structure, _evidence(("process_refund", True)))

    resp = fed.responsibilities[0]
    part = resp.process_model_parts[-1]
    channel = resp.feedback_channels[-1]
    assert part.pm_id == "PM-1-2"
    assert "process_refund" in part.description
    assert "CA-1-1" in part.description
    # No finite set of outcomes is established by the evidence.
    assert part.values == []
    assert part.feedback_source is None
    assert channel.fb_id == "FB-1-2"
    assert channel.updates == "PM-1-2"
    assert channel.source == _cp("CP-2")
    assert channel.source_kind is FeedbackSourceKind.operation_result
    assert "process_refund" in channel.description
    # Authority over the variable is a semantic judgement the step leaves open.
    assert channel.authority_for_update is None
    # No action newly depends on the variable, so no context table changes.
    assert [ca.process_model_refs for ca in resp.control_actions] == [["PM-1-1"]]
    assert _feedback_findings(fed) == []


def test_each_bound_action_on_an_unobserved_process_gets_its_own_channel() -> None:
    structure = _structure(
        _action("CA-1-1"),
        _action("CA-1-2", operation="schedule_payment"),
    )

    fed = add_operation_result_feedback(
        structure,
        _evidence(("process_refund", True), ("schedule_payment", True)),
    )

    resp = fed.responsibilities[0]
    assert [pm.pm_id for pm in resp.process_model_parts] == [
        "PM-1-1",
        "PM-1-2",
        "PM-1-3",
    ]
    assert [(fb.fb_id, fb.updates) for fb in resp.feedback_channels] == [
        ("FB-1-1", "PM-1-1"),
        ("FB-1-2", "PM-1-2"),
        ("FB-1-3", "PM-1-3"),
    ]
    assert "schedule_payment" in resp.feedback_channels[-1].description


def test_a_process_the_responsibility_already_observes_is_left_alone() -> None:
    structure = _structure(
        _action("CA-1-1"),
        channels=[
            FeedbackChannel(
                fb_id="FB-1-1",
                description="Refund eligibility from the engine",
                updates="PM-1-1",
                source=_cp("CP-2"),
                source_kind=FeedbackSourceKind.operation_result,
            )
        ],
    )

    fed = add_operation_result_feedback(structure, _evidence(("process_refund", True)))

    assert fed == structure


def test_actions_without_a_returned_result_are_left_alone() -> None:
    structure = _structure(
        _action("CA-1-1", operation="silent_operation"),
        _action("CA-1-2", operation=None),
        _action(
            "CA-1-3",
            effect_kind=ControlActionEffectKind.model_output,
            target=_cp("CP-1"),
        ),
        _action(
            "CA-1-4",
            effect_kind=ControlActionEffectKind.model_output,
        ),
        _action("CA-1-5", operation="unobserved_operation"),
    )

    fed = add_operation_result_feedback(
        structure,
        _evidence(("process_refund", True), ("silent_operation", False)),
    )

    assert fed == structure


def test_no_evidence_leaves_the_structure_unchanged() -> None:
    structure = _structure(_action("CA-1-1"))

    assert add_operation_result_feedback(structure, None) is structure


def test_the_input_structure_is_not_mutated() -> None:
    structure = _structure(_action("CA-1-1"))
    before = structure.model_dump()

    add_operation_result_feedback(structure, _evidence(("process_refund", True)))

    assert structure.model_dump() == before


def test_evidence_records_whether_an_operation_declares_a_result() -> None:
    profile = ExecutionTargetProfile.model_validate(
        json.loads((FIXTURES / "execution-target-profile.json").read_text())
    )
    tools = profile.inventory.tools
    silent = tools[0].model_copy(update={"output_schema": None})
    profile = profile.model_copy(
        update={
            "inventory": profile.inventory.model_copy(
                update={"tools": (silent, *tools[1:])}
            )
        }
    )

    evidence = build_target_evidence(profile, None)

    assert evidence is not None
    returns = {item.name: item.returns_result for item in evidence.operations}
    assert returns[silent.name] is False
    assert all(returns[tool.name] for tool in tools[1:])
