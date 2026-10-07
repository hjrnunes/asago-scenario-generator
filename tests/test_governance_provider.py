"""The governance-routing prompt and its provider call."""

from __future__ import annotations


import pytest

from asago_scenario_generator.stpa.infra.call_log import append_call_log
from asago_scenario_generator.stpa.infra.call_log import mark_call_published
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.provider_record import ProviderCallSession
from asago_scenario_generator.stpa.obligation_aware.governance_prompts import (
    build_governance_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.governance_routing import (
    route_governance_rows,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.governance import _controls, _setup


class _Client:
    model = "governance-provider-test"

    def __init__(self, *contents, session=None):
        self.session = session
        self.contents = list(contents)
        self.user_prompts: list[str] = []
        self.system_prompts: list[str] = []

    def complete(self, **kwargs):
        self.user_prompts.append(kwargs["user_prompt"])
        self.system_prompts.append(kwargs["system_prompt"])
        return LLMResult(
            content=self.contents.pop(0),
            prompt_tokens=1,
            completion_tokens=1,
            duration_ms=1,
            system_prompt=kwargs["system_prompt"],
            user_prompt=kwargs["user_prompt"],
        )


def _placement_content(briefs, target_id):
    return {
        "placements": [
            {
                "risk_id": brief.risk_ref.risk_id,
                "targets": [{"target_id": target_id, "reason": "bears on it"}]
                if target_id
                else [],
            }
            for brief in briefs
        ]
    }


def test_the_prompt_states_each_risk_and_explains_every_field() -> None:
    briefs, _, loss, structure = _setup("risk-b")

    system, user = build_governance_routing_prompts(
        briefs=briefs,
        loss_analysis=loss,
        control_structure=structure,
        slots=create_slots(structure),
    )

    assert "risk-b" in user
    assert "CA-1-1" in user
    for field in ("placements", "risk_id", "targets", "target_id", "reason"):
        assert f"`{field}`" in system
    assert "hypothesis" in system
    assert "exactly one entry for each" in system
    assert "mapping" not in (system + user).lower()
    assert "attack pattern" not in user.lower()


def test_the_provider_returns_one_placement_per_risk(tmp_path) -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    client = _Client(_placement_content(briefs, "CA-1-1"))
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    result = route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    )

    assert len(client.user_prompts) == 1
    assert len(result.routes) == 1
    assert result.call_evidence[0].attempt_count == 1
    assert result.requests[0].batch_id == "governance-batch-1"
    logged = (tmp_path / "calls.jsonl").read_text()
    assert "synthesis_obligation_aware_governance_routing" in logged
    assert "governance-batch-1" in logged


def test_a_placement_for_an_unsupplied_risk_fails_the_schema(tmp_path) -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    wrong = {
        "placements": [{"risk_id": "risk-z", "targets": []}],
    }
    client = _Client(wrong, wrong)
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    result = route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    )

    assert result.routes == ()
    assert list(result.unresolved) == ["risk-b"]
    assert len(client.user_prompts) == 2
    assert "Validation correction" in client.user_prompts[1]


def test_a_declined_risk_costs_no_route(tmp_path) -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    client = _Client(_placement_content(briefs, None))
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    result = route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    )

    assert result.declined == ("risk-b",)
    assert result.routes == ()


@pytest.mark.parametrize("target", ["CA-1-1"])
def test_the_provider_rejects_nothing_it_was_not_given(tmp_path, target) -> None:
    briefs, selection, loss, structure = _setup("risk-b", "risk-c")
    client = _Client(_placement_content(briefs, target))
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    result = route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    )

    assert len(result.routes) == 2
    assert len(client.user_prompts) == 1


def _file_entries(run_dir):
    return read_calls_jsonl(run_dir)


def test_a_routing_call_lands_in_the_session_records_published(tmp_path) -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    session = ProviderCallSession(record_dir=tmp_path)
    client = _Client(_placement_content(briefs, "CA-1-1"), session=session)
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())

    route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    )

    recorded = session.call_log.entries(tmp_path)
    assert [e["stage"] for e in recorded] == [
        "synthesis_obligation_aware_governance_routing"
    ]
    assert recorded[0]["published"] is True
    assert recorded == _file_entries(tmp_path)


def test_a_later_publish_keeps_the_routing_call_published_in_the_file(
    tmp_path,
) -> None:
    briefs, selection, loss, structure = _setup("risk-b")
    session = ProviderCallSession(record_dir=tmp_path)
    client = _Client(_placement_content(briefs, "CA-1-1"), session=session)
    adapter = ObligationAwareLLMAdapter(client, run_dir=tmp_path, controls=_controls())
    route_governance_rows(
        adapter,
        briefs=briefs,
        paths=selection.paths,
        loss_analysis=loss,
        control_structure=structure,
        controls=_controls(),
    )
    later = {
        "stage": "later",
        "step": "call",
        "semantic_validation_passed": True,
    }
    append_call_log([later], tmp_path, session.call_log)

    mark_call_published(tmp_path, "later", "call", session.call_log)

    assert all(entry["published"] is True for entry in _file_entries(tmp_path))
