"""Pin how routing batches split, and the call evidence each stage records.

Routing and governance routing split briefs greedily by batch size and rendered
prompt size.  Their batches decide every recorded request, so the cases fix the
grouping and the exact sequence of size probes.  The evidence cases fix the
response digest each stage records.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_governance_briefs,
)
from asago_scenario_generator.stpa.obligation_aware import governance_routing, routing
from asago_scenario_generator.stpa.obligation_aware.calls import call_with_feedback
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRevisionResponse,
    StructuralRoutingResponse,
    RevisionDraft,
    SynthesisSlotResponse,
)
from asago_scenario_generator.stpa.obligation_aware.revision import (
    _revision_call_evidence,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _record_request_unresolved,
    _unresolved_response_digest,
)
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    _provider_slot_request,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern

ORDER = ("e", "b", "d", "a", "c")


def _pattern_briefs():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    template = routing.build_neutral_briefs(make_plan(), (pattern,))[0]
    return tuple(
        template.model_copy(update={"obligation_id": "ob:v1:" + name * 64})
        for name in ORDER
    )


def _governance_briefs():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    mapping = {
        "source_id": "risk-a",
        "target_id": pattern.id,
        "relation": "exact_match",
        "confidence": 1.0,
    }
    plan = make_plan(risk_ids=("risk-a", "risk-b"), mappings=[mapping])
    template = build_governance_briefs(plan, ("risk-b",))[0]
    return tuple(
        template.model_copy(
            update={"risk_ref": template.risk_ref.model_copy(update={"risk_id": name})}
        )
        for name in ORDER
    )


def _risk(brief) -> str:
    return brief.risk_ref.risk_id


def _ob(brief) -> str:
    return brief.obligation_id[6]


class _Probe:
    """Prompt builder and budget that count one word per brief."""

    def __init__(self, limit: int, name_of) -> None:
        self.calls: list[str] = []
        self._name_of = name_of
        self.budget = SimpleNamespace(
            count=lambda text: len(text.split()), usable_input_tokens=limit
        )

    def prompts(self, *, briefs, **_):
        names = [self._name_of(brief) for brief in briefs]
        self.calls.append("".join(names))
        return " ".join(names), ""


def _routing_batches(monkeypatch, briefs, size, limit):
    probe = _Probe(limit, _ob)
    monkeypatch.setattr(routing, "build_structural_routing_prompts", probe.prompts)
    batches = routing._budgeted_obligation_batches(
        briefs,
        max_batch_size=size,
        budget=None if limit is None else probe.budget,
        loss_analysis=None,
        control_structure=None,
        slots=(),
    )
    return [[_ob(brief) for brief in batch] for batch in batches], probe.calls


def _governance_batches(monkeypatch, briefs, size, limit):
    probe = _Probe(limit, _risk)
    monkeypatch.setattr(
        governance_routing, "build_governance_routing_prompts", probe.prompts
    )
    batches = governance_routing._governance_batches(
        briefs,
        max_batch_size=size,
        budget=None if limit is None else probe.budget,
        loss_analysis=None,
        control_structure=None,
        slots=(),
    )
    return [[_risk(brief) for brief in batch] for batch in batches], probe.calls


# (max batch size, prompt limit in briefs or None, batches, size probes)
BATCH_CASES = [
    (2, None, [["a", "b"], ["c", "d"], ["e"]], []),
    (9, None, [["a", "b", "c", "d", "e"]], []),
    (1, None, [["a"], ["b"], ["c"], ["d"], ["e"]], []),
    (
        2,
        9,
        [["a", "b"], ["c", "d"], ["e"]],
        ["ab", "cd"],
    ),
    (
        9,
        3,
        [["a", "b", "c"], ["d", "e"]],
        ["ab", "abc", "abcd", "de"],
    ),
    (
        9,
        1,
        [["a"], ["b"], ["c"], ["d"], ["e"]],
        ["ab", "bc", "cd", "de"],
    ),
    (
        9,
        0,
        [["a"], ["b"], ["c"], ["d"], ["e"]],
        ["ab", "bc", "cd", "de"],
    ),
]


@pytest.mark.parametrize(("size", "limit", "batches", "probes"), BATCH_CASES)
def test_routing_batches_split_by_size_and_prompt_budget(
    monkeypatch, size, limit, batches, probes
):
    got, calls = _routing_batches(monkeypatch, _pattern_briefs(), size, limit)

    assert (got, calls) == (batches, probes)


@pytest.mark.parametrize(("size", "limit", "batches", "probes"), BATCH_CASES)
def test_governance_batches_split_by_size_and_prompt_budget(
    monkeypatch, size, limit, batches, probes
):
    got, calls = _governance_batches(monkeypatch, _governance_briefs(), size, limit)

    assert (got, calls) == (batches, probes)


def test_routing_without_a_budget_still_validates_the_briefs(monkeypatch):
    duplicated = (_pattern_briefs()[0],) * 2

    with pytest.raises(ValueError, match="unique obligation IDs"):
        routing._budgeted_obligation_batches(
            duplicated,
            max_batch_size=2,
            budget=None,
            loss_analysis=None,
            control_structure=None,
            slots=(),
        )


def test_governance_without_a_budget_does_not_validate_the_briefs():
    duplicated = (_governance_briefs()[0],) * 2

    batches = governance_routing._governance_batches(
        duplicated,
        max_batch_size=2,
        budget=None,
        loss_analysis=None,
        control_structure=None,
        slots=(),
    )

    assert [len(batch) for batch in batches] == [2]


REQUEST_DIGEST = "a" * 64
CONTROLS = _controls()
REQUEST = SimpleNamespace(
    batch_id="initial-batch-1", semantic_digest="b" * 64, controls=CONTROLS
)


def _evidence_fields(evidence) -> dict:
    return evidence.model_dump(mode="json")


def _expected(call_id, response_digest, attempts, outcome, request_digest="b" * 64):
    return {
        "call_id": call_id,
        "request_digest": request_digest,
        "response_digest": response_digest,
        "model_profile": "synthesis-test",
        "model_name": "fake-stpa-analyst",
        "attempt_count": attempts,
        "outcome": outcome,
    }


ROUTING_DIGEST = "69ba32f011d8d29e101694846fcef101b44167327b69417219e5140566fae9b1"
REVISION_DIGEST = "6937d271f8937491a5b64455abb0d35c860e4db8af2193af8c1f546af22c7e19"
SLOT_DIGEST = "f9cf967faab625c26c33173f5e047f068b9f0ccb0475082503c8087058e6e273"


def _routing_response(**fields):
    return StructuralRoutingResponse(
        request_digest=REQUEST_DIGEST, adapter_kind="fake", **fields
    )


def test_routing_evidence_digests_the_response_unless_it_carries_one():
    bare = routing._call_evidence(_routing_response(), REQUEST, 2)
    carried = routing._call_evidence(
        _routing_response(response_digest="c" * 64), REQUEST, 3, outcome="unresolved"
    )

    assert _evidence_fields(bare) == _expected(
        "stpa-route:initial-batch-1", ROUTING_DIGEST, 2, "accepted"
    )
    assert _evidence_fields(carried) == _expected(
        "stpa-route:initial-batch-1", "c" * 64, 3, "unresolved"
    )


def test_routing_evidence_of_an_exhausted_batch_has_no_response_digest():
    request = _real_routing_request()

    _, _, evidence, detail = routing._exhausted_batch_result(
        request, ValueError("bad"), 4
    )

    assert _evidence_fields(evidence) == _expected(
        "stpa-route:initial-batch-1", None, 4, "unresolved", request.semantic_digest
    )
    assert detail == "initial-batch-1 exhausted validation: ValueError: bad"


def _real_briefs():
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    return routing.build_neutral_briefs(make_plan(), (pattern,))[:1]


def _real_routing_request():
    return routing._request_for_batch(
        _real_briefs(),
        batch_index=0,
        purpose="initial",
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=(),
        controls=CONTROLS,
    )


def test_governance_evidence_always_digests_the_response():
    response = governance_routing.GovernanceRoutingResponse(
        request_digest=REQUEST_DIGEST
    )
    answered = governance_routing._BatchOutcome(response=response, attempts=2)
    unanswered = governance_routing._BatchOutcome(errors={"risk-a": "bad"}, attempts=1)

    got = governance_routing._evidence(REQUEST, answered)
    none = governance_routing._evidence(REQUEST, unanswered)

    assert _evidence_fields(got) == _expected(
        "stpa-governance-route:initial-batch-1", GOVERNANCE_DIGEST, 2, "accepted"
    )
    assert _evidence_fields(none) == _expected(
        "stpa-governance-route:initial-batch-1", None, 1, "unresolved"
    )


GOVERNANCE_DIGEST = "4572d5fb1c065d473329c0bc38fadeca829929245d084e22729231adb5d00004"


def _revision_response(**fields):
    return StructuralRevisionResponse(
        request_digest=REQUEST_DIGEST,
        adapter_kind="fake",
        draft=RevisionDraft(rationale="declined"),
        **fields,
    )


def test_revision_evidence_digests_the_response_unless_it_carries_one():
    kwargs = {"outcome": "rejected", "requests_sent": 1}
    bare = _revision_call_evidence(
        REQUEST, CONTROLS, response=_revision_response(status="rejected"), **kwargs
    )
    carried = _revision_call_evidence(
        REQUEST,
        CONTROLS,
        response=_revision_response(response_digest="c" * 64),
        **kwargs,
    )
    missing = _revision_call_evidence(
        REQUEST, CONTROLS, response=None, outcome="technical_failure", requests_sent=0
    )

    one_round = "stpa-revision:one-round"
    assert _evidence_fields(bare) == _expected(
        one_round, REVISION_DIGEST, 1, "rejected"
    )
    assert _evidence_fields(carried)["response_digest"] == "c" * 64
    assert _evidence_fields(missing) == _expected(
        one_round, None, 0, "technical_failure"
    )


def test_slot_evidence_digests_the_response_unless_it_carries_one():
    request = _provider_slot_request()
    response = SynthesisSlotResponse(request_digest=REQUEST_DIGEST, adapter_kind="fake")
    carried = response.model_copy(update={"response_digest": "c" * 64})

    assert _unresolved_response_digest(None) is None
    assert _unresolved_response_digest(response) == SLOT_DIGEST
    assert _unresolved_response_digest(carried) == "c" * 64

    evidence: list = []
    _record_request_unresolved(
        request,
        {},
        "why",
        response=response,
        all_filled={},
        all_pairs=[],
        evidence=evidence,
        diagnostics=[],
        requests_sent=2,
    )
    assert _evidence_fields(evidence[0]) == {
        "call_id": f"stpa-slot:{request.target_id}",
        "request_digest": request.semantic_digest,
        "response_digest": SLOT_DIGEST,
        "model_profile": "synthesis-test",
        "model_name": "fake-stpa-analyst",
        "attempt_count": 2,
        "outcome": "unresolved",
    }


def test_a_stage_call_passes_correction_feedback_only_when_there_is_some():
    seen: list[tuple] = []

    def stage(request, **kwargs):
        seen.append((request, kwargs))
        return "answer"

    assert call_with_feedback(stage, "r1", None) == "answer"
    assert call_with_feedback(stage, "r2", "fix it") == "answer"
    assert seen == [("r1", {}), ("r2", {"correction_feedback": "fix it"})]
