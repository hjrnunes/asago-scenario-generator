"""The mechanism verifier judges each distinct request once per run."""

from __future__ import annotations

from tests.test_mechanism_verifier_handles import (
    _VerifierClient,
    _route,
    _single_brief,
    _verdict,
)


def _twin_briefs(*, same_mechanism: bool):
    """Two obligations; the second repeats the first's mechanism or renames it."""
    (first,) = _single_brief()
    changes = {"obligation_id": "ob:v1:" + "9" * 64}
    if not same_mechanism:
        changes["attack_pattern_name"] = first.attack_pattern_name + " variant"
    payload = first.model_dump(mode="python", exclude={"semantic_digest"})
    return [first, type(first).model_validate({**payload, **changes})]


def _assessments(result):
    return [route.semantic_assessment.mechanism_assessment for route in result.routes]


def test_identical_requests_in_one_call_are_sent_once(tmp_path) -> None:
    """Two routes with the same mechanism and path share one item and its verdict."""
    briefs = _twin_briefs(same_mechanism=True)
    client = _VerifierClient(briefs, [[_verdict("R1", "adjacent_control")]])

    result = _route(client, briefs, tmp_path, batch_size=2)

    assert len(client.verifier_prompts) == 1
    assert client.verifier_prompts[0].count("item_handle:") == 1
    assert _assessments(result) == ["insufficient_evidence", "insufficient_evidence"]


def test_a_verdict_is_reused_by_a_later_call_for_the_same_request(tmp_path) -> None:
    """The second batch repeats the first batch's request and asks nothing."""
    briefs = _twin_briefs(same_mechanism=True)
    client = _VerifierClient(briefs, [[_verdict("R1")]])

    result = _route(client, briefs, tmp_path, batch_size=1)

    assert len(client.verifier_prompts) == 1
    assert _assessments(result) == ["plausible_in_system", "plausible_in_system"]


def test_different_mechanisms_are_judged_separately(tmp_path) -> None:
    """A different mechanism name is a different request, so each gets its own item."""
    briefs = _twin_briefs(same_mechanism=False)
    client = _VerifierClient(
        briefs,
        [[_verdict("R1")], [_verdict("R1", "adjacent_control")]],
    )

    result = _route(client, briefs, tmp_path, batch_size=1)

    assert len(client.verifier_prompts) == 2
    assert _assessments(result) == ["plausible_in_system", "insufficient_evidence"]


def test_a_failed_verification_is_not_remembered(tmp_path) -> None:
    """A request whose verification failed is asked again in the next call."""
    briefs = _twin_briefs(same_mechanism=True)
    client = _VerifierClient(
        briefs,
        [[_verdict("R7")], [_verdict("R8")], [_verdict("R1")]],
    )

    result = _route(client, briefs, tmp_path, batch_size=1)

    assert len(client.verifier_prompts) == 3
    assert _assessments(result) == ["insufficient_evidence", "plausible_in_system"]


def test_each_adapter_keeps_its_own_verdicts(tmp_path) -> None:
    """A verdict never carries over to another run's adapter."""
    briefs = _twin_briefs(same_mechanism=True)[:1]
    first = _VerifierClient(briefs, [[_verdict("R1")]])
    second = _VerifierClient(briefs, [[_verdict("R1", "adjacent_control")]])

    for name in ("a", "b"):
        (tmp_path / name).mkdir()
    _route(first, briefs, tmp_path / "a")
    result = _route(second, briefs, tmp_path / "b")

    assert len(second.verifier_prompts) == 1
    assert _assessments(result) == ["insufficient_evidence"]
