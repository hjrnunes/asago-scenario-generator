"""The views that reason about a channel's variable show its authority for update.

A Stage 5 scenario context carries the assessment on its feedback elements;
the Stage 5 feedback source choices, the belief request, and the
obligation-aware target index show it, and each request explains the field
only when a listed channel has one.  A context built without an assessment
keeps the bytes and digest it had before the field existed.  The requests
are the ones the builders send; no request leaves the process.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import yaml

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
)
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
from tests.helpers.belief_step import belief_spec
from tests.helpers.feedback_authority import (
    AUTHORITY,
    FEEDBACK_HANDLE,
    authority_belief_spec,
    authority_context,
    authority_slot_request,
    authority_structure,
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
from tests.helpers.stage5_assembly import stage5_assembly
from tests.stpa.sp1_helpers import MockLLMClient

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
