"""The views that reason about a channel's variable show its authority for update.

A Stage 5 scenario context carries the assessment on its feedback elements;
the Stage 5 feedback source choices, the belief request, the obligation-aware
target index, the context-coverage request, and the Call 3 request show it,
and each request explains the field only when a listed channel has one.  A
context built without an assessment keeps the bytes and digest it had before
the field existed, and so does every request built without one.  The requests
are the ones the builders send; no request leaves the process.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.causal_factor import CausalFactorKind
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_revision_prompts,
    build_synthesis_slot_prompts,
    project_control_structure_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.belief_step import (
    belief_request,
    render_belief_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.generate import (
    generate_bdi_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.sources import (
    _causal_source_choices,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    _call_3_coordination,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    run_completeness_critic,
)
from tests.helpers.belief_step import belief_spec
from tests.helpers.feedback_authority import (
    AUTHORITY,
    FEEDBACK_HANDLE,
    authority_belief_spec,
    authority_context,
    authority_slot_request,
    authority_structure,
    call3_inputs,
    context_coverage_prompts,
    with_feedback_authority,
)
from tests.helpers.normal_authoring_wire import (
    _normal_payload,
    _wrong_timing_context,
    _wrong_timing_structure,
)
from tests.helpers.obligation_aware import (
    _control_structure as _obligation_structure,
)
from tests.helpers.obligation_aware import _loss_analysis as _obligation_losses
from tests.helpers.obligation_aware import _provider_slot_request
from tests.helpers.sp3_scenario_continuity import _threat_of_type
from tests.helpers.stage2_source_selection import USE_CASE
from tests.helpers.stage5_assembly import stage5_assembly
from tests.helpers.stpa_builders import make_capability_profile
from tests.stpa.sp1_helpers import MockLLMClient, valid_critic_findings_dict_no_gaps
from tests.stpa.test_ica_context_coverage import _structure as _coverage_structure
from tests.stpa.test_stage2_source_selection import _provider_payload

# The context digest and the SHA-256 of the JSON dump of
# ``_wrong_timing_context()`` as the code before the field produced them.
_EARLIER_CONTEXT_DIGEST = (
    "0fd74a17ce98c619e67f7e49ad0a0ab62e236fce85d05a8d8408934cc4f48bfb"
)
_EARLIER_CONTEXT_DUMP_SHA256 = (
    "e46210f2fc6d86df58bd7ca728d3ce9c0956ec1dfb03e17cdb9abfee39b5829f"
)
_AUTHORITY_VIEW = {"status": "non_authoritative", "basis": AUTHORITY.basis}


def _flat(text: str) -> str:
    return " ".join(text.split())


# ---------------------------------------------------------------------------
# The scenario context
# ---------------------------------------------------------------------------


def test_the_context_carries_the_assessment_on_its_feedback() -> None:
    context = authority_context()

    [feedback] = context.target_control_path.feedback
    assert feedback.authority_for_update == AUTHORITY
    assert context.target_control_path.process_model_parts[0].authority_for_update is (
        None
    )


def test_an_assessed_context_round_trips_with_its_digest() -> None:
    context = authority_context()

    loaded = ScenarioGenerationContext.model_validate_json(context.model_dump_json())

    assert loaded == context
    assert loaded.context_digest == context.context_digest
    assert context.context_digest != _wrong_timing_context().context_digest


def test_a_context_without_an_assessment_keeps_its_earlier_bytes_and_digest() -> None:
    context = _wrong_timing_context()

    dumped = context.model_dump_json()

    assert "authority_for_update" not in dumped
    assert context.context_digest == _EARLIER_CONTEXT_DIGEST
    assert hashlib.sha256(dumped.encode()).hexdigest() == _EARLIER_CONTEXT_DUMP_SHA256
    assert ScenarioGenerationContext.model_validate_json(dumped) == context


# ---------------------------------------------------------------------------
# Stage 5 source choices and request
# ---------------------------------------------------------------------------


def test_only_the_feedback_source_choices_carry_the_assessment() -> None:
    choices = _causal_source_choices(authority_context())

    carried = {
        (choice.kind, choice.source_id): choice.authority_for_update
        for choice in choices
    }
    assert carried == {
        (CausalFactorKind.process_model_flaw, "PM-1-1"): None,
        (CausalFactorKind.feedback_delay, "FB-1-1"): AUTHORITY,
        (CausalFactorKind.sensor_anomaly, "FB-1-1"): AUTHORITY,
        (CausalFactorKind.actuator_anomaly, "CA-1-1"): None,
        (CausalFactorKind.inadequate_control_algorithm, "RESP-1"): None,
    }


def test_unassessed_feedback_choices_carry_no_assessment() -> None:
    choices = _causal_source_choices(_wrong_timing_context())

    assert all(choice.authority_for_update is None for choice in choices)


def _stage5_request(context: ScenarioGenerationContext, structure, tmp_path: Path):
    client = MockLLMClient()
    client.set_response_queue([_normal_payload()])
    threat = _threat_of_type(UCAType.wrong_timing)
    generate_bdi_for_context(
        client,
        context,
        tmp_path,
        assembly=stage5_assembly(context, threat, structure),
    )
    return client.calls[0]


def _causal_sources(user_prompt: str) -> list[dict]:
    """The YAML list of causal source choices in a Stage 5 user prompt."""
    start = user_prompt.index("- source_handle: cause_1")
    end = user_prompt.index("\n\n", start)
    return yaml.safe_load(user_prompt[start:end])


def test_the_stage5_request_shows_the_assessment_on_feedback_sources(
    tmp_path: Path,
) -> None:
    call = _stage5_request(authority_context(), authority_structure(), tmp_path)

    sources = {
        item["source_handle"]: item for item in _causal_sources(call.user_prompt)
    }
    assert sources["cause_2"]["authority_for_update"] == _AUTHORITY_VIEW
    assert sources["cause_3"]["authority_for_update"] == _AUTHORITY_VIEW
    assert "authority_for_update" not in sources["cause_1"]
    assert "authority_for_update" not in sources["cause_4"]
    assert "A feedback source may carry `authority_for_update`" in _flat(
        call.system_prompt
    )


def test_the_stage5_request_without_an_assessment_does_not_mention_it(
    tmp_path: Path,
) -> None:
    call = _stage5_request(_wrong_timing_context(), _wrong_timing_structure(), tmp_path)

    assert "authority_for_update" not in call.system_prompt
    assert "authority_for_update" not in call.user_prompt


# ---------------------------------------------------------------------------
# Stage 5 belief request
# ---------------------------------------------------------------------------


def _belief_factors(user_prompt: str) -> list[dict]:
    start = user_prompt.index("- source_handle:")
    end = user_prompt.index("\n---", start)
    return yaml.safe_load(user_prompt[start:end])


def test_the_belief_request_shows_the_feedback_factor_assessment() -> None:
    spec, structure = authority_belief_spec()

    _, user = render_belief_prompts(spec, belief_request(spec, structure))

    [factor] = _belief_factors(user)
    assert factor["source_handle"] == FEEDBACK_HANDLE
    assert factor["authority_for_update"] == _AUTHORITY_VIEW
    assert "A feedback factor may carry `authority_for_update`" in _flat(user)


def test_the_belief_request_without_an_assessment_does_not_mention_it(
    tmp_path: Path,
) -> None:
    spec, structure = belief_spec(tmp_path)

    system, user = render_belief_prompts(spec, belief_request(spec, structure))

    assert "authority_for_update" not in system + user


# ---------------------------------------------------------------------------
# Obligation-aware target index
# ---------------------------------------------------------------------------


def _slot_prompts(request) -> tuple[str, str]:
    return build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )


def test_the_target_index_feedback_channel_carries_the_assessment() -> None:
    index = project_control_structure_context(
        with_feedback_authority(_obligation_structure()),
        loss_analysis=_obligation_losses(),
        target_id="RESP-1",
    )

    [channel] = index.feedback_channels
    assert channel.authority_for_update == AUTHORITY
    assert channel.model_dump(mode="json")["authority_for_update"] == _AUTHORITY_VIEW


def test_an_unassessed_target_index_channel_dumps_without_it() -> None:
    index = project_control_structure_context(
        _obligation_structure(), loss_analysis=_obligation_losses(), target_id="RESP-1"
    )

    [channel] = index.feedback_channels
    assert "authority_for_update" not in channel.model_dump(mode="json")


def test_the_ica_request_shows_and_explains_the_assessment() -> None:
    system, user = _slot_prompts(authority_slot_request())

    assert "A feedback channel may carry `authority_for_update`" in _flat(system)
    assert "authority_for_update:" in user
    assert f"basis: {AUTHORITY.basis}" in user
    assert "status: non_authoritative" in user


def test_the_ica_request_without_an_assessment_does_not_mention_it() -> None:
    system, user = _slot_prompts(_provider_slot_request())

    assert "authority_for_update" not in system + user


def _structural_revision(structure) -> tuple[str, str]:
    return build_structural_revision_prompts(
        gaps=(
            MissingStructuralConcept(
                concept_type="feedback_channel",
                description="An approval record is needed.",
                evidence_refs=("approval-gap",),
            ),
        ),
        loss_analysis=_obligation_losses(),
        control_structure=structure,
    )


def test_the_structural_revision_request_explains_a_shown_assessment() -> None:
    system, user = _structural_revision(
        with_feedback_authority(_obligation_structure())
    )

    assert "A feedback channel may carry `authority_for_update`" in _flat(system)
    assert "authority_for_update:" in user


def test_the_structural_revision_request_without_one_does_not_mention_it() -> None:
    system, user = _structural_revision(_obligation_structure())

    assert "authority_for_update" not in system + user


# ---------------------------------------------------------------------------
# Context-coverage request
# ---------------------------------------------------------------------------


def _coverage_gap(user_prompt: str) -> dict:
    start = user_prompt.index("## Context gaps\n\n") + len("## Context gaps\n\n")
    end = user_prompt.index("\nReturn one entry", start)
    [gap] = yaml.safe_load(user_prompt[start:end])
    return gap


def _assess(structure: ControlStructure, fb_id: str) -> ControlStructure:
    """``structure`` with ``AUTHORITY`` on the one channel ``fb_id``."""
    data = structure.model_dump(mode="json")
    for responsibility in data["responsibilities"]:
        for channel in responsibility["feedback_channels"]:
            if channel["fb_id"] == fb_id:
                channel["authority_for_update"] = _AUTHORITY_VIEW
    return ControlStructure.model_validate(data)


def test_the_context_coverage_request_shows_the_source_channel_assessment() -> None:
    system, user = context_coverage_prompts(
        with_feedback_authority(_coverage_structure())
    )

    gap = _coverage_gap(user)
    assert gap["source_variable"]["id"] == "PM-1-1"
    # FB-1-2 is assessed too but updates another variable, so it is not listed.
    assert gap["source_feedback"] == [
        {"id": "FB-1-1", "authority_for_update": _AUTHORITY_VIEW}
    ]
    assert gap["feedback_ids"] == ["FB-1-1", "FB-1-2"]
    assert "A gap may list `source_feedback`" in _flat(system)
    assert "a channel listed without it is unknown" in _flat(system)


def test_an_assessment_of_another_variable_leaves_the_coverage_request_unchanged() -> (
    None
):
    assessed = context_coverage_prompts(_assess(_coverage_structure(), "FB-1-2"))

    assert assessed == context_coverage_prompts(_coverage_structure())
    assert "authority_for_update" not in assessed[0] + assessed[1]


def test_the_coverage_gap_selection_ignores_the_assessment() -> None:
    """Selection keys on source kind; an assessment neither adds nor drops a gap."""
    unassessed = _coverage_gap(context_coverage_prompts(_coverage_structure())[1])
    assessed = _coverage_gap(
        context_coverage_prompts(with_feedback_authority(_coverage_structure()))[1]
    )

    assessed.pop("source_feedback")
    assert assessed == unassessed


# ---------------------------------------------------------------------------
# Call 3 request
# ---------------------------------------------------------------------------


def _call3_request(structure: ControlStructure, tmp_path: Path) -> tuple[str, str]:
    losses, _ = call3_inputs()
    client = MockLLMClient()
    client.set_response_queue([_provider_payload(losses, structure)])
    _call_3_coordination(
        llm_client=client,
        use_case_text=USE_CASE,
        control_structure=structure,
        loss_analysis=losses,
        run_dir=tmp_path,
        loader=TemplateLoader(PROMPTS_DIR),
        temperature=0,
    )
    [call] = client.calls
    return call.system_prompt, call.user_prompt


def test_the_call3_request_shows_the_assessment_beside_the_update_relation(
    tmp_path: Path,
) -> None:
    _, structure = call3_inputs()

    _, user = _call3_request(with_feedback_authority(structure), tmp_path)

    assert (
        "Feedback channels: FB-1-1 (updates PM-1-1, source: controlled_process "
        "CP-1, authority for update: non_authoritative, authority basis: "
        f"{AUTHORITY.basis})"
    ) in user
    flat = _flat(user)
    assert "A feedback channel shown with an authority for update" in flat
    assert "A channel shown without one is `unknown`." in flat


def test_the_call3_request_without_an_assessment_does_not_mention_it(
    tmp_path: Path,
) -> None:
    _, structure = call3_inputs()

    system, user = _call3_request(structure, tmp_path)

    assert "Feedback channels: FB-1-1 (updates PM-1-1, source: " in user
    assert "authority" not in (system + user).lower()


# ---------------------------------------------------------------------------
# Requests without an assessment keep their earlier bytes
# ---------------------------------------------------------------------------


def _critic_request(tmp_path: Path) -> tuple[str, str]:
    client = MockLLMClient()
    client.set_response_for(CriticFindings, valid_critic_findings_dict_no_gaps())
    run_completeness_critic(
        llm_client=client,
        control_structure=_wrong_timing_structure(),
        capability_profile=make_capability_profile(),
        use_case_text="A refund assistant issues refunds the finance reviewer approved.",
        run_dir=tmp_path,
    )
    return client.calls[0].system_prompt, client.calls[0].user_prompt


def _unassessed_stage5(tmp_path: Path) -> tuple[str, str]:
    call = _stage5_request(_wrong_timing_context(), _wrong_timing_structure(), tmp_path)
    return call.system_prompt, call.user_prompt


def _unassessed_belief(tmp_path: Path) -> tuple[str, str]:
    spec, structure = belief_spec(tmp_path)
    return render_belief_prompts(spec, belief_request(spec, structure))


# Each builder renders a request whose channels carry no assessment, every one
# with at least one feedback channel.  The values are the SHA-256 of the system
# and user prompt the code before the field produced for the same inputs.
# The Stage 5 context system value also carries the later stated-reason
# paragraph of ``stage5_context_system.j2``; both Stage 5 context values also
# carry the later decision-rule source (the controller's handle and the
# evidence sentence for it); the user value also carries that handle's later
# rule description and the misreading sentence of its selection guidance.
# The critic system value also carries the later evidence-source paragraph of
# ``critic_system.j2``.
_UNASSESSED_REQUESTS = {
    "stage5-context": (
        _unassessed_stage5,
        "f8f8eae6f53835beb0c6d000a89d79a7b8b654e2f0dda7a9357b681cf1ca0c27",
        "6b49574d804a66ffd7bb4b1967494a97d3570d470e1997471d8285c66071cded",
    ),
    "stage5-belief": (
        _unassessed_belief,
        "aea82473e3ad25b7e12aaad231b3d08314862a617e5890b21d26cfd3e5639676",
        "123691e3169975d879fb4511385f8d0cee34fe34ae251104150e5b12593ddb46",
    ),
    "ica-target-index": (
        lambda _: _slot_prompts(_provider_slot_request()),
        "1ee393a7d9379f7eb15e1f9950b39da4e4bc2cdc27dfb3e3566e0cd6280bd047",
        "c32bf77e27d2a65fbe355afc0074d49663e9d812023fd0c0c64ce74dcd6f0de2",
    ),
    "structural-revision": (
        lambda _: _structural_revision(_obligation_structure()),
        "4676294e97ec508634a3d474a918b1282a1c3b54482e0998f597754d54c08b51",
        "eba4393f2ee571970679ed1909848fdc8fb7b6d71f8df3ea8a4f8226d833b9a8",
    ),
    "critic": (
        _critic_request,
        "25e4dea6a98feb7c4807fdb2b51cfe59f59161a20e628d246f50b04661e6b98f",
        "e97dfb0f129e9eeba7df7335ef90c8f0dddae97b33ab6d6f9ce8a80ac71fee7f",
    ),
    "context-coverage": (
        lambda _: context_coverage_prompts(_coverage_structure()),
        "5a258d02de9b3456ac9cc4e487a0e5659d7b77a1d64246001b1834c84721bc4a",
        "e20681eff49655786044b347a090228c6c9b19ea5a4861d760523ccdb60a8de3",
    ),
    "call3": (
        lambda tmp_path: _call3_request(call3_inputs()[1], tmp_path),
        "62f48547a2a520ac14b0b841d9302518d01082765be7a5c3a9f2b43a86814283",
        "d8feda1152d1ddfe0c62516db991aa8c4f0ab9303534a91f7e99d675d9103177",
    ),
}


@pytest.mark.parametrize("request_name", sorted(_UNASSESSED_REQUESTS))
def test_a_request_without_an_assessment_keeps_its_earlier_bytes(
    request_name: str, tmp_path: Path
) -> None:
    build, system_sha256, user_sha256 = _UNASSESSED_REQUESTS[request_name]

    system, user = build(tmp_path)

    assert hashlib.sha256(system.encode()).hexdigest() == system_sha256
    assert hashlib.sha256(user.encode()).hexdigest() == user_sha256
