"""The model Gherkin step that writes each published scenario's Gherkin.

Every test is offline and uses a fake client. Code checks each reply; a reply
that breaks a rule earns one correction naming every broken rule, and a reply
that still breaks one, a failed call, or a refused call keeps the
code-rendered Gherkin.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

import pytest

from asago_scenario_generator.report.scenario_panels import feature_matches
from asago_scenario_generator.stpa.infra.provider_record import (
    LiveRequestBudgetError,
)
from asago_scenario_generator.stpa.models.scenario_envelope import (
    render_feature_text,
)
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    HandoffGherkin,
    ScenarioHandoffV5,
    verify_handoff_digest,
)
from asago_scenario_generator.stpa.scenario_prod.model_gherkin import (
    GHERKIN_STAGE,
    GHERKIN_STEP,
    GHERKINS_FILENAME,
    SAFE_BEHAVIOR,
    GherkinReply,
    gherkin_facts,
    gherkin_failures,
    gherkin_spec_from_reply,
    render_gherkin_prompts,
    write_gherkin,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    NarrationReply,
    build_facts,
    plain,
    render_narration_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.presentation import (
    render_scenario_presentation,
)
from asago_scenario_generator.stpa.scenario_prod.run import run_sp3
from asago_scenario_generator.stpa.scenario_prod.stage5.shape_step import (
    ShapeProposal,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.scenario_handoff_publication import (
    _functional_payload,
    _normal_semantics_payload,
    _published_handoff,
)
from tests.helpers.shape_step_call import DIRECT_REPLY
from tests.helpers.sp3_run import _make_ets
from tests.helpers.stpa_builders import make_cs, make_loss_analysis
from tests.stpa.sp1_helpers import MockLLMClient
from tests.stpa.test_narration import adversarial, everyday, valid_reply

SAFE = "The agent refuses the refund until the operation:verify_customer check passes."
_CITATION = re.compile(r'^- "(\w+)": at least one step cites [^:]+: (.+)$', re.M)


def citations(user_prompt: str) -> dict[str, list[str]]:
    """Read the required citations the user prompt lists."""
    return {part: ids.split(", ") for part, ids in _CITATION.findall(user_prompt)}


def reply_for(user_prompt: str) -> dict[str, Any]:
    """Return a reply that keeps every rule for the prompt's facts."""
    cited = citations(user_prompt)
    return {
        "feature": "The agent keeps refunds for the right customer",
        "scenario": "A customer obtains a refund meant for someone else",
        "given": [
            {"text": "The agent handles refund requests", "facts": ["F1"]},
            {"text": "The AI agent trusts the stated customer", "facts": ["F1"]},
        ],
        "when": [
            {
                "text": "A refund request arrives for another customer",
                "facts": cited.get("when", ["F1"])[:1],
            }
        ],
        "then": [
            {"text": "The agent checks the customer first", "facts": cited["then"]}
        ],
        "unsafe": [
            {"text": "The agent refunds the wrong customer", "facts": cited["unsafe"]}
        ],
    }


def valid(spec: Any, safe: str = SAFE) -> dict[str, Any]:
    _, user = render_gherkin_prompts(gherkin_facts(spec, safe))
    return reply_for(user)


def failures_of(spec: Any, **changes: Any) -> list[str]:
    reply = {**valid(spec), **changes}
    return gherkin_failures(
        GherkinReply.model_validate(reply), gherkin_facts(spec, SAFE)
    )


def step(text: str, facts: list[str] | None = None) -> dict[str, Any]:
    return {"text": text, "facts": facts or ["F1"]}


class GherkinClient(MockLLMClient):
    """A fake client whose Gherkin replies follow each request's citations."""

    def __init__(
        self, gherkin: Callable[[str], Any] | None = reply_for, **kwargs: Any
    ) -> None:
        super().__init__(**kwargs)
        self.gherkin = gherkin

    def complete(self, system_prompt: str, user_prompt: str, **kwargs: Any) -> Any:
        if kwargs.get("response_format") is GherkinReply and self.gherkin:
            self.set_response_for(GherkinReply, self.gherkin(user_prompt))
        return super().complete(system_prompt, user_prompt, **kwargs)


# --- facts and prompts -------------------------------------------------------


def test_the_safe_behavior_is_appended_as_the_next_fact() -> None:
    spec = adversarial()
    narrate = build_facts(spec)

    facts = gherkin_facts(spec, SAFE)

    assert facts.facts[:-1] == narrate.facts
    last = facts.facts[-1]
    assert last.fact_id == f"F{len(narrate.facts) + 1}"
    assert last.category == SAFE_BEHAVIOR
    assert last.text == plain(SAFE)
    assert "operation:" not in last.text
    assert facts.glossary[: len(narrate.glossary)] == narrate.glossary
    # The narrate request does not change.
    assert render_narration_prompts(build_facts(spec)) == render_narration_prompts(
        narrate
    )


def test_the_user_prompt_lists_the_kind_facts_and_required_citations() -> None:
    spec = adversarial()
    facts = gherkin_facts(spec, SAFE)
    _, user = render_gherkin_prompts(facts)

    assert user.startswith("Scenario kind: adversarial\n")
    for fact in facts.facts:
        assert f"- {fact.fact_id} ({fact.category}): {fact.text}" in user
    assert citations(user) == {
        "then": facts.ids_in([SAFE_BEHAVIOR]),
        "unsafe": facts.ids_in(["failure"]),
        "when": facts.ids_in(["attack step"]),
    }


def test_an_everyday_prompt_requires_no_attack_step() -> None:
    _, user = render_gherkin_prompts(gherkin_facts(everyday(), SAFE))

    assert user.startswith("Scenario kind: everyday\n")
    assert set(citations(user)) == {"then", "unsafe"}


# --- checks --------------------------------------------------------------------


def test_a_reply_that_keeps_every_rule_has_no_failure() -> None:
    assert failures_of(adversarial()) == []
    assert failures_of(everyday()) == []


def test_step_counts_are_checked_for_each_list() -> None:
    spec = adversarial()
    reply = valid(spec)
    found = failures_of(
        spec,
        given=[step("The agent acts")] * 5,
        when=reply["when"] * 4,
        then=reply["then"] * 3,
        unsafe=reply["unsafe"] * 2,
    )

    assert '"given" has 5 steps; write 1 to 4' in found
    assert '"when" has 4 steps; write 1 to 3' in found
    assert '"then" has 3 steps; write 1 to 2' in found
    assert '"unsafe" has 2 steps; write exactly 1' in found


def test_names_and_steps_have_word_limits() -> None:
    long_name = " ".join(["word"] * 13)
    long_step = " ".join(["word"] * 26)

    found = failures_of(
        adversarial(),
        feature=long_name,
        scenario=long_name,
        given=[step(long_step)],
    )

    assert "the feature name has 13 words; use at most 12" in found
    assert "the scenario name has 13 words; use at most 12" in found
    assert '"given" step 1 has 26 words; use at most 25' in found


@pytest.mark.parametrize(
    ("text", "keyword"),
    [
        ("Given the agent acts", "Given"),
        ("when the agent acts", "when"),
        ("THEN the agent acts", "THEN"),
        ("And the agent acts", "And"),
        ("but the agent acts", "but"),
        ("* the agent acts", "*"),
    ],
)
def test_no_step_starts_with_a_gherkin_keyword(text: str, keyword: str) -> None:
    found = failures_of(adversarial(), given=[step(text)])

    assert (
        f'"given" step 1 starts with the Gherkin keyword "{keyword}"; code adds '
        "the keywords, so start with the subject"
    ) in found


def test_a_word_that_merely_begins_like_a_keyword_passes() -> None:
    assert failures_of(adversarial(), given=[step("Andrew handles refunds")]) == []


@pytest.mark.parametrize(
    "text",
    [
        "The attacker asks again in turn 2",
        "The attacker asks again in turn two",
        "The attacker asks again in the second turn",
        "The attacker asks again in the 3rd turn",
    ],
)
def test_no_step_names_a_turn_number(text: str) -> None:
    found = failures_of(adversarial(), given=[step(text)])

    assert any(item.startswith('"given" step 1 names a turn') for item in found)


def test_a_turn_without_a_number_passes() -> None:
    assert failures_of(adversarial(), given=[step("In turn the agent acts")]) == []


def test_every_cited_fact_must_exist() -> None:
    found = failures_of(adversarial(), given=[step("The agent acts", ["F99"])])

    assert '"given" step 1 cites F99, which the fact list does not have' in found


def test_then_must_cite_the_safe_behavior() -> None:
    spec = adversarial()
    safe = gherkin_facts(spec, SAFE).ids_in([SAFE_BEHAVIOR])

    found = failures_of(spec, then=[step("The agent checks first")])

    assert f'no "then" step cites the safe behavior; cite {safe[0]}' in found


def test_unsafe_must_cite_the_failure() -> None:
    spec = adversarial()
    failure = gherkin_facts(spec, SAFE).ids_in(["failure"])

    found = failures_of(spec, unsafe=[step("The agent refunds")])

    assert f'no "unsafe" step cites the failure; cite {failure[0]}' in found


def test_an_adversarial_when_must_cite_an_attack_step() -> None:
    spec = adversarial()
    attack = gherkin_facts(spec, SAFE).ids_in(["attack step"])

    found = failures_of(spec, when=[step("A request arrives")])

    assert (
        f'no "when" step cites an attack step; cite at least one of {", ".join(attack)}'
    ) in found
    assert not any('"when" step' in item for item in failures_of(everyday()))


def test_narrates_text_rules_hold_for_steps_and_names() -> None:
    found = failures_of(
        adversarial(),
        feature="RESP-1 fails",
        scenario="The agent refunds ORD-999",
        given=[step("The agent cites F1 and refunds 999")],
    )

    assert any(
        item.startswith("the feature name writes the identifier RESP-1")
        for item in found
    )
    assert any(item.startswith("the scenario name writes ORD-999") for item in found)
    assert any(
        item.startswith('"given" step 1 writes the fact identifier F1')
        for item in found
    )
    assert '"given" step 1 writes the number 999, which no fact gives' in found


def test_a_text_on_two_lines_or_blank_is_rejected() -> None:
    found = failures_of(adversarial(), feature="   ", given=[step("The agent\nacts")])

    assert "the feature name is blank" in found
    assert '"given" step 1 spans more than one line; write it on one line' in found


# --- mapping -------------------------------------------------------------------


def test_an_accepted_reply_maps_to_keyed_gherkin() -> None:
    reply = GherkinReply.model_validate(
        {
            "feature": "  The feature  ",
            "scenario": " The scenario ",
            "given": [step("The agent serves"), step("AI rules apply")],
            "when": [step("A request arrives"), step("The user insists")],
            "then": [step("The agent checks"), step("It escalates")],
            "unsafe": [step("The agent refunds")],
        }
    )

    gherkin = gherkin_spec_from_reply(reply)

    assert gherkin.feature == "The feature"
    assert gherkin.scenario == "The scenario"
    assert gherkin.given == ["Given the agent serves", "And AI rules apply"]
    assert gherkin.when == ["When a request arrives", "And the user insists"]
    assert gherkin.then_expected == ["Then the agent checks", "And it escalates"]
    assert gherkin.then_actual == ["But the agent refunds"]
    text = gherkin.to_feature_text()
    assert text.startswith("Feature: The feature\n  Background:\n    Given the agent")
    assert "    # Unsafe alternative (non-executable): But the agent refunds\n" in text


# --- the request -------------------------------------------------------------


def test_an_accepted_reply_costs_one_request(tmp_path: Path) -> None:
    spec = adversarial()
    client = GherkinClient()

    outcome = write_gherkin(spec, SAFE, llm_client=client, run_dir=tmp_path)

    assert len(client.calls) == 1
    assert client.calls[0].response_format is GherkinReply
    assert outcome.accepted and outcome.requests == 1
    assert outcome.reason is None and outcome.rejected == []
    assert outcome.reply == GherkinReply.model_validate(valid(spec)).model_dump()
    assert outcome.gherkin is not None
    assert outcome.gherkin.then_actual == ["But the agent refunds the wrong customer"]
    record = read_calls_jsonl(tmp_path)
    assert {(r["stage"], r["step"]) for r in record} == {(GHERKIN_STAGE, GHERKIN_STEP)}


def test_a_broken_reply_earns_one_correction_naming_every_rule(
    tmp_path: Path,
) -> None:
    spec = adversarial()
    broken = {**valid(spec), "unsafe": [step("Given the agent refunds in turn 2")]}
    client = GherkinClient(gherkin=None)
    client.set_response_for(GherkinReply, [broken, valid(spec)])

    outcome = write_gherkin(spec, SAFE, llm_client=client, run_dir=tmp_path)

    assert len(client.calls) == 2
    correction = client.calls[1].user_prompt
    assert "Code rejected the prior reply." in correction
    assert "the reply breaks these rules:" in correction
    assert '"unsafe" step 1 starts with the Gherkin keyword "Given"' in correction
    assert '"unsafe" step 1 names a turn ("turn 2")' in correction
    assert 'no "unsafe" step cites the failure' in correction
    assert outcome.accepted and outcome.requests == 2
    assert len(outcome.rejected) == 1


def test_a_reply_broken_twice_keeps_the_code_gherkin(tmp_path: Path) -> None:
    spec = adversarial()
    broken = {**valid(spec), "then": [step("The agent checks")]}
    client = GherkinClient(gherkin=None)
    client.set_response_for(GherkinReply, [broken, broken])

    outcome = write_gherkin(spec, SAFE, llm_client=client, run_dir=tmp_path)

    assert len(client.calls) == 2
    assert outcome.source == "fallback" and outcome.gherkin is None
    assert outcome.requests == 2
    assert len(outcome.rejected) == 2
    assert 'no "then" step cites the safe behavior' in (outcome.reason or "")
    assert outcome.reply == GherkinReply.model_validate(broken).model_dump()


def test_a_provider_error_keeps_the_code_gherkin(tmp_path: Path) -> None:
    client = GherkinClient()
    client.set_exception_for(GherkinReply, RuntimeError("connection reset"))

    outcome = write_gherkin(adversarial(), SAFE, llm_client=client, run_dir=tmp_path)

    assert outcome.source == "fallback" and outcome.gherkin is None
    assert "connection reset" in (outcome.reason or "")
    assert outcome.reply is None and outcome.rejected == []


def test_a_budget_refusal_keeps_the_code_gherkin(tmp_path: Path) -> None:
    client = GherkinClient()
    client.set_exception_for(
        GherkinReply, LiveRequestBudgetError("the budget of 0 live request(s) is spent")
    )

    outcome = write_gherkin(adversarial(), SAFE, llm_client=client, run_dir=tmp_path)

    assert len(client.calls) == 1
    assert outcome.source == "fallback"
    assert "the budget of 0 live request(s) is spent" in (outcome.reason or "")


# --- the run -------------------------------------------------------------------


def _publish(run_dir: Path, client: MockLLMClient | None = None, **kwargs: Any) -> Any:
    client = client or GherkinClient()
    client.set_response_queue([_normal_semantics_payload(), _functional_payload()])
    client.set_response_for(ShapeProposal, DIRECT_REPLY)
    result = run_sp3(
        llm_client=client,
        enriched_threat_set=_make_ets(num_threats=2),
        control_structure=make_cs(),
        loss_analysis=make_loss_analysis(),
        run_dir=run_dir,
        **kwargs,
    )
    return result, client


SCENARIOS = ("SCN-001", "SCN-002")


def _code_gherkin_run(run_dir: Path) -> Any:
    client = GherkinClient()
    client.set_exception_for(GherkinReply, RuntimeError("no model Gherkin"))
    result, _ = _publish(run_dir, client)
    return result


def test_a_scenario_without_a_model_gherkin_publishes_the_code_gherkin(
    tmp_path: Path,
) -> None:
    result = _code_gherkin_run(tmp_path)

    specs = {
        spec.scenario_id: spec
        for spec in (*result.scenario_specs, *result.functional_test_specs)
    }
    for scenario_id in SCENARIOS:
        expected = render_scenario_presentation(specs[scenario_id])[2]
        document = _published_handoff(tmp_path, scenario_id)
        assert document["gherkin"]["feature"] == expected.feature
        assert document["gherkin"]["scenario"] == expected.scenario


def _files(run_dir: Path) -> dict[str, bytes]:
    return {
        path.name: path.read_bytes()
        for path in sorted((run_dir / "scenarios").glob("SCN-*"))
    }


def test_a_run_publishes_each_accepted_gherkin_in_the_handoff_and_feature(
    tmp_path: Path,
) -> None:
    result, client = _publish(tmp_path)

    assert result.stage_errors == []
    requests = [call for call in client.calls if call.response_format is GherkinReply]
    assert len(requests) == 2
    for scenario_id in SCENARIOS:
        document = _published_handoff(tmp_path, scenario_id)
        verify_handoff_digest(ScenarioHandoffV5.model_validate(document))
        gherkin = document["gherkin"]
        assert gherkin["given"][0].startswith("Given the agent handles")
        assert gherkin["then_unsafe_alternative"] == [
            "But the agent refunds the wrong customer"
        ]
        feature = (tmp_path / "scenarios" / f"{scenario_id}.feature").read_text()
        assert feature == render_feature_text(
            gherkin["feature"],
            gherkin["scenario"],
            gherkin["given"],
            gherkin["when"],
            gherkin["then_expected"],
            gherkin["then_unsafe_alternative"],
        )
        assert feature_matches(HandoffGherkin.model_validate(gherkin), feature)
        # The safe-behavior fact is the published safe alternative.
        assert any(
            f"({SAFE_BEHAVIOR}): {plain(document['safe_alternative'])}\n"
            in call.user_prompt
            for call in requests
        )
    sidecar = json.loads((tmp_path / GHERKINS_FILENAME).read_text(encoding="utf-8"))
    assert list(sidecar) == ["stage", "step", "scenarios"]
    assert (sidecar["stage"], sidecar["step"]) == (GHERKIN_STAGE, GHERKIN_STEP)
    assert [entry["scenario_id"] for entry in sidecar["scenarios"]] == list(SCENARIOS)
    for entry in sidecar["scenarios"]:
        assert list(entry) == [
            "scenario_id",
            "source",
            "requests",
            "rejected",
            "reason",
            "reply",
        ]
        assert entry["source"] == "model" and entry["reason"] is None
        assert entry["requests"] == 1 and entry["rejected"] == []
        assert (
            entry["reply"]["unsafe"][0]["text"]
            == "The agent refunds the wrong customer"
        )


def test_the_gherkin_requests_follow_narrate_with_its_identity_and_temperature(
    tmp_path: Path,
) -> None:
    client = GherkinClient()
    client.set_response_for(NarrationReply, valid_reply(adversarial()))

    _publish(tmp_path, client)

    kinds = [
        call.response_format
        for call in client.calls
        if call.response_format in (NarrationReply, GherkinReply)
    ]
    # Narrate may spend a correction; every narrate request still comes first.
    first_gherkin = kinds.index(GherkinReply)
    assert set(kinds[:first_gherkin]) == {NarrationReply}
    assert kinds[first_gherkin:] == [GherkinReply] * 2
    temperatures = {
        call.temperature
        for call in client.calls
        if call.response_format in (NarrationReply, GherkinReply)
    }
    assert len(temperatures) == 1
    records = read_calls_jsonl(tmp_path)
    identity = {
        stage: list(
            dict.fromkeys(
                (r["scenario_id"], r.get("slot_id"))
                for r in records
                if r["stage"] == stage
            )
        )
        for stage in ("stage6_narrative", GHERKIN_STAGE)
    }
    assert identity[GHERKIN_STAGE] == identity["stage6_narrative"]
    assert {r["step"] for r in records if r["stage"] == GHERKIN_STAGE} == {GHERKIN_STEP}


@pytest.mark.parametrize(
    "error",
    [
        RuntimeError("connection reset"),
        LiveRequestBudgetError("the budget of 0 live request(s) is spent"),
    ],
    ids=["provider-error", "budget-refusal"],
)
def test_a_run_whose_gherkin_calls_fail_publishes_the_code_gherkin(
    tmp_path: Path, error: Exception
) -> None:
    _code_gherkin_run(tmp_path / "code")
    client = GherkinClient()
    client.set_exception_for(GherkinReply, error)

    result, _ = _publish(tmp_path / "failed", client)

    assert result.stage_errors == []
    assert _files(tmp_path / "failed") == _files(tmp_path / "code")
    sidecar = json.loads(
        (tmp_path / "failed" / GHERKINS_FILENAME).read_text(encoding="utf-8")
    )
    assert [entry["source"] for entry in sidecar["scenarios"]] == ["fallback"] * 2
    assert all(str(error) in entry["reason"] for entry in sidecar["scenarios"])


def test_a_run_whose_replies_fail_twice_publishes_the_code_gherkin(
    tmp_path: Path,
) -> None:
    _code_gherkin_run(tmp_path / "code")
    client = GherkinClient(gherkin=lambda _: {"feature": "x"})

    _publish(tmp_path / "broken", client)

    assert _files(tmp_path / "broken") == _files(tmp_path / "code")
    sidecar = json.loads((tmp_path / "broken" / GHERKINS_FILENAME).read_text())
    assert [entry["source"] for entry in sidecar["scenarios"]] == ["fallback"] * 2
    assert [entry["requests"] for entry in sidecar["scenarios"]] == [2, 2]
