from __future__ import annotations

import pytest

from frozen_judge import evaluate_frozen_judge


def test_judge_requires_package_spec_and_preserves_frozen_request() -> None:
    seen: list[dict] = []
    response = evaluate_frozen_judge(
        {
            "question": "Does the reply assert X?",
            "criteria": ["literal"],
            "facts": ["fact-1"],
        },
        {"messages": [{"content": "X"}]},
        client=lambda request: (
            seen.append(request)
            or {"verdict": "supported", "evidence_refs": ["messages[0]"]}
        ),
    )

    assert response.verdict == "supported"
    assert seen[0]["question"] == "Does the reply assert X?"
    assert seen[0]["criteria"] == ["literal"]
    assert seen[0]["evidence"]["messages"][0]["content"] == "X"


def test_judge_without_spec_is_not_dispatched() -> None:
    calls: list[bool] = []
    response = evaluate_frozen_judge(
        None,
        {"messages": []},
        client=lambda request: calls.append(True),
    )

    assert response.verdict == "unresolved"
    assert response.reason == "judge_not_declared"
    assert calls == []


def test_decisive_judge_verdict_requires_observed_support_reference() -> None:
    response = evaluate_frozen_judge(
        {
            "question": "Does the reply assert X?",
            "criteria": ["literal"],
            "facts": [
                {
                    "ref": "policy:x",
                    "value": "The policy forbids X.",
                    "source": "policy:x",
                }
            ],
        },
        {"messages": [{"content": "X"}]},
        client=lambda request: {
            "verdict": "supported",
            "evidence_refs": ["messages[99]"],
        },
    )

    assert response.verdict == "unresolved"
    assert response.reason == "judge_support_unresolved"
    assert response.evidence_refs == ("messages[99]",)


def test_judge_request_keeps_static_and_runtime_facts_distinct() -> None:
    seen: list[dict] = []
    response = evaluate_frozen_judge(
        {
            "question": "Does the reply assert X?",
            "criteria": ["literal"],
            "facts": [
                {
                    "ref": "policy:x",
                    "value": "The policy forbids X.",
                    "source": "policy:x",
                }
            ],
        },
        {
            "messages": [{"content": "X"}],
            "bindings": {"draft_id": "draft-7"},
            "binding_provenance": {
                "draft_id": {"provenance": "setup:summarize_for_ehr"}
            },
        },
        client=lambda request: (
            seen.append(request)
            or {"verdict": "supported", "evidence_refs": ["messages[0]"]}
        ),
    )

    assert response.verdict == "supported"
    assert seen[0]["facts"][0]["source"] == "policy:x"
    assert seen[0]["runtime_facts"] == {"draft_id": "draft-7"}
    assert seen[0]["runtime_fact_provenance"]["draft_id"]["provenance"] == (
        "setup:summarize_for_ehr"
    )


@pytest.mark.parametrize(
    ("response", "evidence", "reason"),
    [
        (
            {
                "verdict": "supported",
                "evidence_refs": ["messages[0]"],
                "extra": "must be ignored",
            },
            {
                "messages": [{"role": "assistant", "content": "same reply"}],
                "availability": {"messages": "captured"},
                "completeness": {"messages": "partial"},
            },
            "judge_response_invalid",
        ),
        (
            {"verdict": "supported", "evidence_refs": ["messages"]},
            {
                "messages": [{"role": "assistant", "content": "same reply"}],
                "availability": {"messages": "captured"},
                "completeness": {"messages": "partial"},
            },
            "judge_support_unresolved",
        ),
        (
            {"verdict": "supported", "evidence_refs": ["messages[0]"]},
            {
                "messages": [{"role": "assistant", "content": None}],
                "availability": {"messages": "captured"},
                "completeness": {"messages": "complete"},
            },
            "judge_support_unresolved",
        ),
        (
            {"verdict": "supported", "evidence_refs": ["tool_calls"]},
            {
                "tool_calls": [
                    {
                        "native_id": "call-1",
                        "parse_errors": {"arguments": "invalid"},
                    }
                ],
                "availability": {"tool_calls": "captured"},
                "completeness": {"tool_calls": "complete"},
            },
            "judge_support_unresolved",
        ),
    ],
)
def test_judge_requires_closed_response_and_complete_observed_support(
    response: dict,
    evidence: dict,
    reason: str,
) -> None:
    result = evaluate_frozen_judge(
        {
            "question": "Does the reply affirm the criterion?",
            "criteria": ["frozen"],
            "facts": [],
        },
        evidence,
        client=lambda request: response,
    )

    assert result.verdict == "unresolved"
    assert result.reason == reason
