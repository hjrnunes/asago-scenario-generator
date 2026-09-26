from __future__ import annotations

import json
from pathlib import Path

import pytest

from frozen_judge import evaluate_frozen_judge, normalize_evidence_packet


def test_normalized_packet_projects_only_detector_judge_fields() -> None:
    evidence = {
        "messages": [{"id": "message-0", "role": "assistant", "content": "X"}],
        "availability": {"messages": "captured"},
        "completeness": {"messages": "complete"},
        "judge": {
            "verdict": "supported",
            "evidence_refs": ["$.messages[0].content"],
            "reason": "judge_completed",
            "request": {"private": True},
            "output": {"private": True},
            "dispatched": True,
            "reused": False,
        },
    }

    normalized = normalize_evidence_packet(evidence, judge_enabled=True)

    assert normalized["judge"] == {
        "verdict": "supported",
        "evidence_refs": ["$.messages[0].content"],
        "reason": "judge_completed",
    }


@pytest.mark.parametrize(
    ("judge", "reason"),
    [
        (None, "judge_missing"),
        ({"verdict": "supported", "evidence_refs": "messages[0]"}, "judge_evidence_invalid"),
        ({"verdict": "supported", "evidence_refs": ["messages[99]"]}, "judge_support_unresolved"),
    ],
)
def test_normalized_packet_makes_invalid_judge_unresolved(
    judge: dict | None,
    reason: str,
) -> None:
    evidence = {
        "messages": [{"role": "assistant", "content": None}],
        "availability": {"messages": "captured"},
        "completeness": {"messages": "complete"},
    }
    if judge is not None:
        evidence["judge"] = judge

    normalized = normalize_evidence_packet(evidence, judge_enabled=True)

    assert normalized["judge"]["verdict"] == "unresolved"
    assert normalized["judge"]["reason"] == reason


def test_normalized_packet_omits_judge_for_non_judge_package() -> None:
    normalized = normalize_evidence_packet(
        {"judge": {"verdict": "supported"}, "messages": []},
        judge_enabled=False,
    )

    assert "judge" not in normalized


def test_normalized_packet_matches_shared_conformance_fixture() -> None:
    fixture = json.loads(
        (
            Path(__file__).parents[2]
            / "contracts"
            / "artifact-package"
            / "judge-normalization-v1"
            / "cases.json"
        ).read_text(encoding="utf-8")
    )

    for case in fixture["cases"]:
        normalized = normalize_evidence_packet(
            case["evidence"],
            judge_enabled=case["judge_enabled"],
        )
        if case["expected_judge"] is None:
            assert "judge" not in normalized, case["name"]
        else:
            assert normalized["judge"] == case["expected_judge"], case["name"]


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


@pytest.mark.parametrize("reference", ["messages[0].content", "/messages/0/content"])
def test_decisive_judge_accepts_captured_message_content_leaf(reference: str) -> None:
    response = evaluate_frozen_judge(
        {
            "question": "Does the reply assert X?",
            "criteria": ["literal"],
            "facts": [],
        },
        {
            "messages": [{"id": "message-0", "role": "assistant", "content": "X"}],
            "availability": {"messages": "captured"},
            "completeness": {"messages": "complete"},
        },
        client=lambda request: {
            "verdict": "supported",
            "evidence_refs": [reference],
        },
    )

    assert response.verdict == "supported"
    assert response.reason == "judge_completed"
    assert response.evidence_refs == (reference,)


@pytest.mark.parametrize(
    ("reference", "messages", "availability"),
    [
        (
            "messages[0].id",
            [{"id": "message-0", "role": "assistant", "content": "X"}],
            "captured",
        ),
        (
            "/messages/0/role",
            [{"id": "message-0", "role": "assistant", "content": "X"}],
            "captured",
        ),
        ("messages[99].content", [{"role": "assistant", "content": "X"}], "captured"),
        ("/messages/0/content", [{"role": "assistant", "content": None}], "captured"),
        ("messages[0].content", [{"role": "assistant", "content": 7}], "captured"),
        ("/messages/0/content", [{"role": "assistant", "content": "X"}], "unavailable"),
    ],
)
def test_message_content_support_rejects_metadata_missing_invalid_or_uncaptured(
    reference: str,
    messages: list[dict[str, object]],
    availability: str,
) -> None:
    response = evaluate_frozen_judge(
        {
            "question": "Does the reply assert X?",
            "criteria": ["literal"],
            "facts": [],
        },
        {
            "messages": messages,
            "availability": {"messages": availability},
            "completeness": {"messages": "complete"},
        },
        client=lambda request: {
            "verdict": "supported",
            "evidence_refs": [reference],
        },
    )

    assert response.verdict == "unresolved"
    assert response.reason == "judge_support_unresolved"
    assert response.evidence_refs == (reference,)


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
