"""Per-constraint judgment of a derived Stage 1a graph against the supplied rules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import yaml

from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.loss_analysis import (
    LossAnalysis,
    Obligation,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.constraint_judgment import (
    ARTIFACT_FILENAME,
    ConstraintJudgmentResponse,
    constraint_digest,
    excluded_constraint_ids,
    judge_constraints,
    reconcile_with_final_graph,
)
from asago_scenario_generator.stpa.system_model.stated_rule_coverage import (
    StatedRuleCoverageArtifact,
    StatedRuleRow,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    EvidenceOperation,
    EvidencePolicy,
    TargetEvidence,
)

from tests.stpa.sp1_helpers import MockLLMClient, valid_loss_analysis_dict

USE_CASE = (
    "The assistant confirms every payment with the customer before it executes. "
    "Refund approval is decided by the payments service, never by the assistant."
)
OPERATION_TEXT = "Rejects any refund above the customer's remaining balance."


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis.model_validate(valid_loss_analysis_dict())


def _rules() -> StatedRuleCoverageArtifact:
    return StatedRuleCoverageArtifact(
        status="completed",
        use_case_digest="digest",
        rules=[
            StatedRuleRow(
                rule_id="R1",
                quote="confirms every payment with the customer",
                restatement="The system must confirm every payment.",
                modality="requires",
                status="covered",
                constraint_ids=["SC-1"],
            )
        ],
    )


def _evidence() -> TargetEvidence:
    return TargetEvidence(
        operations=(
            EvidenceOperation(
                name="issue_refund",
                description=OPERATION_TEXT,
                arguments=(),
            ),
        ),
        policies=(
            EvidencePolicy(
                observation_ref="obs-1",
                source_name="get_policy",
                query_label=None,
                text="Refunds are final once the payments service accepts them.",
            ),
        ),
    )


def _verdict(
    verdict: str, quoted_rule: str | None = None, reason: str = "One sentence."
) -> dict[str, Any]:
    return {"verdict": verdict, "quoted_rule": quoted_rule, "reason": reason}


def _judge(
    tmp_path: Path,
    responses: list[Any],
    *,
    loss_analysis: LossAnalysis | None = None,
    evidence: TargetEvidence | None = None,
    client: MockLLMClient | None = None,
):
    client = client or MockLLMClient()
    if responses:
        client.set_response_for(ConstraintJudgmentResponse, responses)
    artifact = judge_constraints(
        llm_client=client,
        loss_analysis=loss_analysis or _loss_analysis(),
        use_case_text=USE_CASE,
        stated_rules=_rules(),
        target_evidence=evidence,
        run_dir=tmp_path,
        template_loader=TemplateLoader(PROMPTS_DIR),
        temperature=0.0,
    )
    return artifact, client


def _calls(run_dir: Path) -> list[dict]:
    path = run_dir / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()]


def test_supported_constraints_stay_and_each_gets_one_request(tmp_path: Path) -> None:
    artifact, client = _judge(
        tmp_path, [_verdict("supported"), _verdict("supported")], evidence=_evidence()
    )

    assert len(client.calls) == 2
    assert [row.constraint_id for row in artifact.rows] == ["SC-1", "SC-2"]
    assert {row.verdict for row in artifact.rows} == {"supported"}
    assert artifact.excluded_constraint_ids == []
    assert artifact.request_count == 2
    assert artifact.status == "completed"
    assert all(row.request_count == 1 for row in artifact.rows)


def test_requests_are_recorded_under_their_own_call_kind(tmp_path: Path) -> None:
    _judge(tmp_path, [_verdict("supported"), _verdict("supported")])

    calls = _calls(tmp_path)
    assert [(c["stage"], c["step"]) for c in calls] == [
        ("stage_1a", "constraint_judgment")
    ] * 2


def test_contradicts_with_a_quote_from_the_use_case_excludes_the_constraint(
    tmp_path: Path,
) -> None:
    quote = "refund approval is decided by the PAYMENTS service"
    artifact, _ = _judge(
        tmp_path, [_verdict("supported"), _verdict("contradicts", quote)]
    )

    row = artifact.rows[1]
    assert row.verdict == "contradicts"
    assert row.model_verdict == "contradicts"
    assert row.excluded is True
    # The recorded span is the source's own wording, not the model's casing.
    assert row.quoted_rule == "Refund approval is decided by the payments service"
    assert artifact.excluded_constraint_ids == ["SC-2"]


def test_exceeds_with_a_quote_from_an_operation_description_excludes(
    tmp_path: Path,
) -> None:
    artifact, _ = _judge(
        tmp_path,
        [
            _verdict("exceeds", "Rejects any refund above the customer's remaining"),
            _verdict("supported"),
        ],
        evidence=_evidence(),
    )

    assert artifact.rows[0].excluded is True
    assert artifact.rows[0].quoted_rule == (
        "Rejects any refund above the customer's remaining"
    )


def test_a_quote_from_policy_text_counts_as_supplied_rule_text(
    tmp_path: Path,
) -> None:
    artifact, _ = _judge(
        tmp_path,
        [
            _verdict("contradicts", "Refunds are final once the payments service"),
            _verdict("supported"),
        ],
        evidence=_evidence(),
    )

    assert artifact.excluded_constraint_ids == ["SC-1"]


@pytest.mark.parametrize(
    "quote",
    [
        "The assistant never refunds anything at all",
        None,
        "   ",
        "never by",
    ],
    ids=["fabricated", "missing", "blank", "too-short-to-identify-a-rule"],
)
def test_an_unsubstantiated_drop_verdict_falls_back_to_supported(
    tmp_path: Path, quote: str | None
) -> None:
    artifact, _ = _judge(
        tmp_path, [_verdict("contradicts", quote), _verdict("supported")]
    )

    row = artifact.rows[0]
    assert row.verdict == "supported"
    assert row.model_verdict == "contradicts"
    assert row.outcome == "unsubstantiated"
    assert row.excluded is False
    assert row.quoted_rule is None
    assert artifact.excluded_constraint_ids == []
    assert any(
        "SC-1" in item and "unsubstantiated" in item for item in artifact.warnings
    )


def test_a_quote_not_in_the_supplied_text_is_rejected_even_if_the_model_saw_it(
    tmp_path: Path,
) -> None:
    # The evidence is not supplied here, so its text is not rule text.
    artifact, _ = _judge(
        tmp_path,
        [
            _verdict("exceeds", "Rejects any refund above the customer's remaining"),
            _verdict("supported"),
        ],
        evidence=None,
    )

    assert artifact.rows[0].outcome == "unsubstantiated"


@pytest.mark.parametrize("failure", ["invalid", "missing", "exception"])
def test_a_judge_failure_keeps_the_constraint_and_warns(
    tmp_path: Path, failure: str
) -> None:
    client = MockLLMClient()
    if failure == "invalid":
        client.set_invalid_response_for(ConstraintJudgmentResponse)
    elif failure == "missing":
        client.set_response_for(ConstraintJudgmentResponse, [])
    else:
        client.set_exception_for(ConstraintJudgmentResponse, RuntimeError("no replay"))
    artifact, _ = _judge(tmp_path, [], client=client)

    assert [row.outcome for row in artifact.rows] == ["unavailable", "unavailable"]
    assert {row.verdict for row in artifact.rows} == {"supported"}
    assert {row.model_verdict for row in artifact.rows} == {None}
    assert artifact.excluded_constraint_ids == []
    assert artifact.status == "partial"
    assert len(artifact.warnings) == 2
    assert (tmp_path / ARTIFACT_FILENAME).exists()


def test_one_failed_judgment_does_not_stop_the_others(tmp_path: Path) -> None:
    client = MockLLMClient()
    client.set_response_queue(
        [
            "not json{{{",
            "not json{{{",  # the one decode retry
            _verdict("contradicts", "never by the assistant"),
        ]
    )
    artifact, _ = _judge(tmp_path, [], client=client)

    assert artifact.rows[0].outcome == "unavailable"
    assert artifact.rows[0].request_count == 2
    assert artifact.rows[1].excluded is True
    assert artifact.request_count == 3


def test_the_artifact_is_written_with_the_exclusion_list(tmp_path: Path) -> None:
    artifact, _ = _judge(
        tmp_path,
        [_verdict("supported"), _verdict("contradicts", "never by the assistant")],
    )

    written = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
    assert written["schema_version"] == "constraint-judgments-v1"
    assert written["excluded_constraint_ids"] == ["SC-2"]
    assert [row["constraint_id"] for row in written["rows"]] == ["SC-1", "SC-2"]
    assert written["rows"][1]["text_digest"] == constraint_digest(
        _loss_analysis().security_constraints[1]
    )
    assert excluded_constraint_ids(artifact) == ("SC-2",)


def test_excluded_constraint_ids_of_no_judgment_is_empty() -> None:
    assert excluded_constraint_ids(None) == ()


def test_the_request_carries_the_constraint_its_links_and_the_rule_text(
    tmp_path: Path,
) -> None:
    _, client = _judge(
        tmp_path,
        [_verdict("supported"), _verdict("supported")],
        evidence=_evidence(),
    )

    first, second = client.calls[0].user_prompt, client.calls[1].user_prompt
    assert (
        "SC-1" in first and "The agent must confirm every unintended payment." in first
    )
    assert "before execution" in first
    assert "H-1" in first and "The agent executes an unintended payment." in first
    assert "L-1" in first and "Unauthorized transaction" in first
    assert USE_CASE in first
    assert "confirms every payment with the customer" in first
    assert OPERATION_TEXT in first
    assert "Refunds are final once the payments service accepts them." in first
    # Each request judges one constraint and shows no other constraint's text.
    assert "The agent must preserve user trust." not in first
    assert "The agent must confirm every unintended payment." not in second
    assert client.calls[0].response_format is ConstraintJudgmentResponse


def test_the_request_lists_the_obligations_with_their_channel(tmp_path: Path) -> None:
    graph = _loss_analysis()
    graph.security_constraints[0] = graph.security_constraints[0].model_copy(
        update={
            "obligations": [
                Obligation(
                    obligation_id="O1",
                    kind="required",
                    behavior="ask the customer to confirm the payment",
                    rule_span="must confirm every unintended payment",
                    realized_by="tool_call",
                ),
                Obligation(
                    obligation_id="O2",
                    kind="forbidden",
                    behavior="execute the payment unconfirmed",
                    rule_span="must confirm",
                    violated_via="reply",
                ),
            ]
        }
    )
    _, client = _judge(
        tmp_path,
        [_verdict("supported"), _verdict("supported")],
        loss_analysis=graph,
    )

    first = client.calls[0].user_prompt
    assert (
        "required: ask the customer to confirm the payment (channel: tool_call;"
        in first
    )
    assert "forbidden: execute the payment unconfirmed (channel: reply;" in first
    assert "Obligations" not in client.calls[1].user_prompt


def test_the_system_prompt_defines_the_verdicts_and_the_quote() -> None:
    loader = TemplateLoader(PROMPTS_DIR)
    system = loader.render_prompt("stage1a_constraint_judgment_system.j2")

    for verdict in ("supported", "contradicts", "exceeds"):
        assert f"`{verdict}`" in system
    assert "quoted_rule" in system


def test_without_target_evidence_the_request_has_no_evidence_section(
    tmp_path: Path,
) -> None:
    _, client = _judge(tmp_path, [_verdict("supported"), _verdict("supported")])

    assert OPERATION_TEXT not in client.calls[0].user_prompt


def test_a_constraint_changed_after_judgment_is_no_longer_excluded(
    tmp_path: Path,
) -> None:
    artifact, _ = _judge(
        tmp_path,
        [_verdict("supported"), _verdict("contradicts", "never by the assistant")],
    )
    revised = _loss_analysis()
    revised.security_constraints[1] = revised.security_constraints[1].model_copy(
        update={"rule": "The agent must keep every refund within the balance."}
    )

    reconciled = reconcile_with_final_graph(artifact, revised, tmp_path)

    assert reconciled.excluded_constraint_ids == []
    row = reconciled.rows[1]
    assert row.excluded is False
    assert row.outcome == "changed_after_judgment"
    assert row.model_verdict == "contradicts"
    assert any("SC-2" in item for item in reconciled.warnings)
    written = yaml.safe_load((tmp_path / ARTIFACT_FILENAME).read_text())
    assert written["excluded_constraint_ids"] == []


def test_a_constraint_removed_after_judgment_is_no_longer_excluded(
    tmp_path: Path,
) -> None:
    artifact, _ = _judge(
        tmp_path,
        [_verdict("supported"), _verdict("contradicts", "never by the assistant")],
    )
    revised = _loss_analysis()
    revised.security_constraints.pop()

    reconciled = reconcile_with_final_graph(artifact, revised, tmp_path)

    assert reconciled.excluded_constraint_ids == []


def test_an_unchanged_graph_leaves_the_artifact_alone(tmp_path: Path) -> None:
    artifact, _ = _judge(
        tmp_path,
        [_verdict("supported"), _verdict("contradicts", "never by the assistant")],
    )
    before = (tmp_path / ARTIFACT_FILENAME).read_text()

    reconciled = reconcile_with_final_graph(artifact, _loss_analysis(), tmp_path)

    assert reconciled == artifact
    assert (tmp_path / ARTIFACT_FILENAME).read_text() == before


def test_the_digest_covers_the_rule_and_its_conditions() -> None:
    base = _loss_analysis().security_constraints[0]

    assert constraint_digest(base) == constraint_digest(base.model_copy())
    assert constraint_digest(base) != constraint_digest(
        base.model_copy(update={"rule": base.rule + " Always."})
    )
    assert constraint_digest(base) != constraint_digest(
        base.model_copy(update={"applies_when": ["after execution"]})
    )
