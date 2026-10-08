"""Stage 2 placement of constraints whose obligations are violated via the reply."""

from __future__ import annotations

from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    CriticGap,
)
from asago_scenario_generator.stpa.system_model.reply_constraint_placement import (
    attach_to_sole_reply_responsibility,
    misplaced_reply_constraints,
    reply_placement_gaps,
    with_reply_placement_gaps,
)
from tests.stpa.sp1_helpers import valid_loss_analysis_dict

SOURCE_RULE = "The agent must only state facts the approved source supplies."


def _analysis(violated_via: str = "reply") -> LossAnalysis:
    payload = valid_loss_analysis_dict()
    payload["security_constraints"][1].update(
        rule=SOURCE_RULE,
        applies_when=[],
        obligations=[
            {
                "obligation_id": "O1",
                "kind": "forbidden",
                "rule_span": "only state facts the approved source supplies",
                "behavior": "state facts the approved source does not supply",
                "violated_via": violated_via,
            }
        ],
    )
    return LossAnalysis.model_validate(payload)


def _responsibility(
    resp_id: str, refs: list[str], effect_kind: str, operation: str | None = None
) -> dict:
    index = resp_id.split("-")[1]
    action = {
        "ca_id": f"CA-{index}-1",
        "description": "Answer the user" if effect_kind == "model_output" else "Fetch",
        "target": {"type": "controlled_process", "id": f"CP-{index}"},
        "effect_kind": effect_kind,
        "process_model_refs": [f"PM-{index}-1"],
    }
    if operation is not None:
        action["operation"] = operation
    return {
        "resp_id": resp_id,
        "description": f"Responsibility {index}",
        "security_constraint_refs": refs,
        "responsibility_constraints": [
            {"rc_id": f"RC-{index}-1", "description": "Follow the rules"}
        ],
        "process_model_parts": [
            {"pm_id": f"PM-{index}-1", "description": "Request state"}
        ],
        "control_actions": [action],
        "feedback_channels": [],
    }


def _structure(*responsibilities: dict) -> ControlStructure:
    return ControlStructure.model_validate(
        {
            "responsibilities": list(responsibilities),
            "controlled_processes": [
                {"cp_id": f"CP-{r['resp_id'].split('-')[1]}", "description": "Process"}
                for r in responsibilities
            ],
        }
    )


def _retrieval_owner_structure() -> ControlStructure:
    return _structure(
        _responsibility("RESP-1", ["SC-1"], "model_output"),
        _responsibility("RESP-2", ["SC-2"], "tool_call", operation="fetch_source"),
    )


class TestMisplacedReplyConstraints:
    def test_reply_constraint_on_a_retrieval_owner_is_misplaced(self) -> None:
        assert misplaced_reply_constraints(
            _retrieval_owner_structure(), _analysis()
        ) == ["SC-2"]

    def test_uncited_reply_constraint_is_misplaced(self) -> None:
        cs = _structure(
            _responsibility("RESP-1", ["SC-1"], "model_output"),
            _responsibility("RESP-2", [], "tool_call", operation="fetch_source"),
        )

        assert misplaced_reply_constraints(cs, _analysis()) == ["SC-2"]

    def test_reply_constraint_on_the_reply_owner_is_placed(self) -> None:
        cs = _structure(
            _responsibility("RESP-1", ["SC-1", "SC-2"], "model_output"),
            _responsibility("RESP-2", ["SC-2"], "tool_call", operation="fetch_source"),
        )

        assert misplaced_reply_constraints(cs, _analysis()) == []

    def test_constraint_violated_through_another_channel_is_ignored(self) -> None:
        assert (
            misplaced_reply_constraints(
                _retrieval_owner_structure(), _analysis(violated_via="tool_call")
            )
            == []
        )

    def test_structure_without_a_reply_action_has_nothing_to_report(self) -> None:
        cs = _structure(
            _responsibility("RESP-1", ["SC-1"], "tool_call", operation="pay"),
            _responsibility("RESP-2", ["SC-2"], "tool_call", operation="fetch_source"),
        )

        assert misplaced_reply_constraints(cs, _analysis()) == []


class TestReplyPlacementGaps:
    def test_gap_names_the_constraint_its_rule_and_the_reply_action(self) -> None:
        [gap] = reply_placement_gaps(_retrieval_owner_structure(), _analysis())

        assert gap.gap_type == "missing_pm_part"
        assert "SC-2" in gap.description
        assert SOURCE_RULE in gap.description
        assert "RESP-1" in gap.suggested_remedy
        assert "CA-1-1" in gap.suggested_remedy
        assert "security_constraint_refs" in gap.suggested_remedy
        # The gap is a valid critic gap for the existing revision request.
        CriticFindings(gaps=[gap])

    def test_remedy_feeds_the_source_variable_from_the_citing_step(self) -> None:
        [gap] = reply_placement_gaps(_retrieval_owner_structure(), _analysis())
        remedy = gap.suggested_remedy

        assert "source {type: responsibility, id: RESP-2}" in remedy
        assert "retrieved_content" in remedy
        assert "operation_result" in remedy
        assert "not what the reply says" in remedy

    def test_remedy_for_an_uncited_constraint_names_no_source_step(self) -> None:
        cs = _structure(
            _responsibility("RESP-1", ["SC-1"], "model_output"),
            _responsibility("RESP-2", [], "tool_call", operation="fetch_source"),
        )
        [gap] = reply_placement_gaps(cs, _analysis())

        assert "type: responsibility" not in gap.suggested_remedy
        assert "retrieved_content" in gap.suggested_remedy

    def test_placed_constraints_produce_no_gap(self) -> None:
        cs = _structure(_responsibility("RESP-1", ["SC-1", "SC-2"], "model_output"))

        assert reply_placement_gaps(cs, _analysis()) == []

    def test_gaps_join_the_critic_findings_and_trigger_the_revision(self) -> None:
        critic_gap = CriticGap(
            gap_type="missing_feedback",
            description="critic gap",
            related_attack_path="path",
            suggested_remedy="remedy",
        )
        findings = CriticFindings(
            gaps=[critic_gap], checklist_results={"Authorization": "present"}
        )

        merged = with_reply_placement_gaps(
            findings, _retrieval_owner_structure(), _analysis()
        )

        assert merged.gaps[0] == critic_gap
        assert "SC-2" in merged.gaps[1].description
        assert merged.checklist_results == {"Authorization": "present"}
        assert with_reply_placement_gaps(
            CriticFindings(), _retrieval_owner_structure(), _analysis()
        ).gaps

    def test_placed_structure_leaves_critic_findings_unchanged(self) -> None:
        cs = _structure(_responsibility("RESP-1", ["SC-1", "SC-2"], "model_output"))
        findings = CriticFindings()

        assert with_reply_placement_gaps(findings, cs, _analysis()) is findings


class TestAttachToSoleReplyResponsibility:
    def test_sole_reply_owner_receives_the_constraint(self) -> None:
        revised, warnings = attach_to_sole_reply_responsibility(
            _retrieval_owner_structure(), _analysis()
        )

        assert revised.responsibilities[0].security_constraint_refs == [
            "SC-1",
            "SC-2",
        ]
        # The prior citation stays: placement only adds.
        assert revised.responsibilities[1].security_constraint_refs == ["SC-2"]
        assert warnings == [
            "stage_2/reply_constraint_placement: security constraint SC-2 is "
            "violated through the reply but no responsibility owning a reply "
            "action cited it; code added it to RESP-1, the only one"
        ]

    def test_two_reply_owners_are_left_for_review(self) -> None:
        cs = _structure(
            _responsibility("RESP-1", ["SC-1"], "model_output"),
            _responsibility("RESP-2", [], "model_output"),
            _responsibility("RESP-3", ["SC-2"], "tool_call", operation="fetch_source"),
        )

        revised, warnings = attach_to_sole_reply_responsibility(cs, _analysis())

        assert revised == cs
        assert warnings == [
            "stage_2/reply_constraint_placement: security constraint SC-2 is "
            "violated through the reply but no responsibility owning a reply "
            "action cites it (reply owners: RESP-1, RESP-2)"
        ]

    def test_placed_structure_is_unchanged(self) -> None:
        cs = _structure(_responsibility("RESP-1", ["SC-1", "SC-2"], "model_output"))

        assert attach_to_sole_reply_responsibility(cs, _analysis()) == (cs, [])
