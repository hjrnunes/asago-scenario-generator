"""Phrase tables: fixed prompt wording checked against rendered prompts.

Each ``tests/phrases/<template stem>.yaml`` file holds the fixed phrases of one
prompt template. It names the template and, per rendering case, the phrases
of each kind:

- ``required``: the phrase appears.
- ``once``: the phrase appears exactly once.
- ``forbidden``: the phrase does not appear.
- ``ordered``: lists of phrases that appear, each list in its order.

A case renders the template the way a request does: through the template
loader for the Stage 1 and Stage 2 templates (whose builders pass the same
arguments to ``TemplateLoader.render_prompt``), and through
``build_context_bdi_prompts`` for the Stage 5 context templates, and through
the obligation-aware prompt builders (``OBLIGATION_AWARE_BUILDS``) for the
obligation-aware templates. Phrases and rendered text are compared with runs of
whitespace collapsed to one space, so template line wrapping does not matter.

A request built in Python rather than from one template (``REQUESTS``) has a
table named after it that gives ``request`` in place of ``template``; its cases
render the request the producer sends.

Wording that depends on a test's input (an identifier, a value or a list from
its fixture) stays as a code assert next to that fixture.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from functools import cache
from pathlib import Path
import tempfile
from types import SimpleNamespace

import yaml

from asago_scenario_generator.models.mechanism_suggestion import (
    MechanismSuggestion,
    MechanismSuggestionPath,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationReference,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlledProcess,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.stpa.observation_contract import (
    default_observation_contract,
)
from asago_scenario_generator.stpa.obligation_aware.context_coverage import (
    build_context_coverage_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.governance_prompts import (
    build_governance_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    PROMPT_TEMPLATES_DIR as OBLIGATION_AWARE_PROMPTS_DIR,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
    build_mechanism_suggestion_verification_prompts,
    build_mechanism_verification_prompts,
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.scenario_prod._constants import (
    PROMPTS_DIR as STAGE5_PROMPTS_DIR,
)
from asago_scenario_generator.stpa.scenario_prod.model_gherkin import (
    render_gherkin_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.narration import (
    Fact,
    ScenarioFacts,
    render_narration_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.belief_step import (
    belief_request,
    render_belief_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.stage5.prompt_view import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.system_model._constants import (
    PROMPTS_DIR as SYSTEM_MODEL_PROMPTS_DIR,
)
from asago_scenario_generator.stpa.system_model.control_structure import (
    DuplicateControlledProcess,
    UnknownReference,
)
from asago_scenario_generator.stpa.target_realization.provider import (
    PROMPTS_DIR as TARGET_REALIZATION_PROMPTS_DIR,
)
from tests.helpers.belief_step import belief_spec, decision_rule_belief_spec
from tests.helpers.known_mechanism import linked_brief
from tests.helpers.feedback_authority import (
    authority_belief_spec,
    authority_context,
    authority_slot_request,
    call3_inputs,
    context_coverage_prompts,
    with_feedback_authority,
)
from tests.helpers.stage2_source_selection import USE_CASE as CALL3_USE_CASE
from tests.stpa.test_ica_context_coverage import _structure as _coverage_structure
from tests.stpa.test_stage5_condition_contradictions import (
    _kind_mismatch_condition as _record_kind_mismatch_condition,
)
from tests.stpa.test_stage5_condition_contradictions import (
    _ordering_text_condition,
    correction_request,
)
from tests.helpers.stpa_builders import make_capability_profile
from tests.helpers.discriminating_condition import _placeholder_payload
from tests.helpers.normal_authoring_wire import (
    _record_observations,
    _target_operation,
    _tool_call_action_context,
    _wrong_timing_context,
)
from tests.stpa.condition_prompt_fixture import (
    realistic_observations,
    realistic_profile,
)
from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.governance import _setup as _governance_setup
from tests.helpers.ica_hazard_verification import _request as _verification_request
from tests.helpers.obligation_aware import (
    _control_structure as _obligation_structure,
)
from tests.helpers.obligation_aware import _loss_analysis as _obligation_losses
from tests.helpers.obligation_aware import _provider_slot_request
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern

PHRASES_DIR = Path(__file__).with_name("phrases")
KINDS = ("required", "once", "forbidden", "ordered")
PROMPT_DIRS = (
    SYSTEM_MODEL_PROMPTS_DIR,
    STAGE5_PROMPTS_DIR,
    OBLIGATION_AWARE_PROMPTS_DIR,
    TARGET_REALIZATION_PROMPTS_DIR,
)
# Requests built in Python, each pinned by the table of the same name.
REQUESTS = (
    "stage5_condition_correction",
    "stage2_call2b_authority_correction_request",
    "revision_authority_correction_request",
    "revision_merge_and_authority_correction_request",
)

_STAGE5_TEMPLATES = ("stage5_context_system.j2", "stage5_context_user.j2")
_NARRATE_TEMPLATES = ("stage6_narrate_system.j2", "stage6_narrate_user.j2")
_GHERKIN_TEMPLATES = ("stage6_gherkin_system.j2", "stage6_gherkin_user.j2")
_BELIEF_TEMPLATES = ("stage5_belief_system.j2", "stage5_belief_user.j2")

# Stage 1a user templates take the use case and the existing records; the
# system templates ignore these arguments.
RECORDS_SERVICE = {
    "use_case_text": "A records service retrieves authorized account records.",
    "risk_cards": [],
    "existing_losses": [],
    "existing_hazards": [],
    "existing_constraints": [],
    "next_loss_num": 1,
    "next_hazard_num": 1,
    "next_sc_num": 1,
    "kc_subcodes": [],
}

ACTIONABILITY_RISKS = {
    "use_case_text": "A records service retrieves authorized account records.",
    "target_evidence": None,
    "risk_cards": [
        RiskCard(
            risk_id="risk-records",
            risk_name="Disclosure of account records",
            risk_description="A reply discloses account records without authority.",
            taxonomy="ibm-risk-atlas",
            confidence=0.9,
            grounding_confidence="high",
            threat="Staff paste account records into an outside chat tool.",
            threat_source="Staff of the organization.",
            consequence="The records reach the outside tool's provider.",
        )
    ],
}

NEUTRAL_STATUS = {
    "use_case_text": "A neutral assistant returns status information.",
    "requirements": [],
    "capability_profile": None,
    "responsibilities": [],
}

ONE_RESPONSIBILITY = {
    **NEUTRAL_STATUS,
    "responsibilities": [
        Responsibility(
            resp_id="RESP-1",
            description="Authorizes requests",
            process_model_parts=[
                ProcessModelPart(pm_id="PM-1-1", description="Request state")
            ],
        )
    ],
}

UNKNOWN_REFERENCES = {
    "unknown_references": [
        UnknownReference("control_actions[0].target", "RESP-9"),
        UnknownReference("control_actions[0].process_model_refs", "PM-2-1", "RESP-1"),
    ],
    "responsibilities": ONE_RESPONSIBILITY["responsibilities"],
    "controlled_processes": [
        ControlledProcess(cp_id="CP-1", description="Request processor")
    ],
    "process_model_owners": ONE_RESPONSIBILITY["responsibilities"],
    "undeclared_controlled_processes": [],
    "duplicate_controlled_processes": [],
}

# A reply that left out `controlled_processes` and still targets CP-1 and CP-3.
UNDECLARED_CONTROLLED_PROCESSES = {
    "unknown_references": [
        UnknownReference("control_actions[0].target", "CP-1"),
        UnknownReference("feedback[0].source", "CP-3"),
    ],
    "responsibilities": ONE_RESPONSIBILITY["responsibilities"],
    "controlled_processes": [],
    "process_model_owners": [],
    "undeclared_controlled_processes": ["CP-1", "CP-3"],
    "duplicate_controlled_processes": [],
}

# A reply that declares CP-2 twice, with two descriptions, and targets it.
DUPLICATE_CONTROLLED_PROCESSES = {
    "unknown_references": [],
    "responsibilities": ONE_RESPONSIBILITY["responsibilities"],
    "controlled_processes": [
        ControlledProcess(cp_id="CP-1", description="Request processor"),
        ControlledProcess(cp_id="CP-2", description="Policy store"),
        ControlledProcess(cp_id="CP-2", description="Store of policies"),
    ],
    "process_model_owners": [],
    "undeclared_controlled_processes": [],
    "duplicate_controlled_processes": [
        DuplicateControlledProcess(
            "CP-2",
            (
                ("controlled_processes[1]", "Policy store"),
                ("controlled_processes[2]", "Store of policies"),
            ),
            ("control_actions[0].target", "feedback[0].source"),
        )
    ],
}

MISSING_CONTROL_ACTIONS = {
    "missing_owners": ONE_RESPONSIBILITY["responsibilities"],
    "controlled_processes": [
        ControlledProcess(cp_id="CP-1", description="Request processor")
    ],
}

EMPTY_STRUCTURE = {
    "use_case_text": "Test use case",
    "control_structure": SimpleNamespace(
        responsibilities=[], controlled_processes=[], coordination_links=[]
    ),
    "next_resp_num": 1,
    "next_pm_num": 1,
    "next_ca_num": 1,
    "next_fb_num": 1,
    "next_cl_num": 1,
    "next_cm_num": 1,
    "next_cp_num": 1,
}

# The revision request after a critic that reported no gaps.
NO_FINDINGS = {
    "use_case_text": "Test use case",
    "control_structure": EMPTY_STRUCTURE["control_structure"],
    "critic_findings": SimpleNamespace(
        gaps=[], checklist_results={}, taxonomy_probe_results={}
    ),
}


def _archive_item_facts() -> dict[str, object]:
    operation = TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id="items", operation_id="archive_item"
        ),
        description="Archive one item record.",
        input_schema={
            "type": "object",
            "properties": {"item_id": {"type": "string"}},
            "required": ["item_id"],
        },
    )
    observations = TargetObservationSnapshot.create(
        target_profile_digest="a" * 64,
        observations=(
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content='{"item_id":"ITEM-104","state":"PENDING"}',
            ),
        ),
    )
    return {"target_operation": operation, "target_observations": observations}


def _commit_operation_facts() -> dict[str, object]:
    return {
        "target_operation": TargetOperationObservation(
            reference=TargetOperationReference(
                resource_id="ehr", operation_id="commit_to_ehr"
            ),
            description="Commit a reviewed patient draft for a clinician.",
            input_schema={
                "type": "object",
                "properties": {"patient_id": {"type": "string"}},
            },
        )
    }


def _realistic_request_facts(tool_call: bool = True) -> dict[str, object]:
    """Return the six-operation synthetic target with the default captures."""
    contract = default_observation_contract()
    if not tool_call:
        contract = contract.model_copy(
            update={
                "capture": tuple(
                    item.model_copy(update={"available": False})
                    if item.kind == "tool_call"
                    else item
                    for item in contract.capture
                )
            }
        )
    profile = realistic_profile()
    return {
        "execution_target_profile": profile,
        "target_observations": realistic_observations(profile),
        "observation_contract": contract,
    }


def _authority_slot_request() -> tuple[str, str]:
    request = authority_slot_request()
    return build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )


def _routing_batch(pattern_id: str | None = None) -> tuple[str, str]:
    """Route one brief; with *pattern_id*, its concern is that bundled pattern."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    structure = _obligation_structure()
    briefs = build_neutral_briefs(make_plan(), (pattern,))[:1]
    if pattern_id is not None:
        briefs = [linked_brief(briefs[0], pattern_id)]
    return build_structural_routing_prompts(
        briefs=briefs,
        loss_analysis=_obligation_losses(),
        control_structure=structure,
        slots=create_slots(structure),
    )


def _slot_request() -> tuple[str, str]:
    request = _provider_slot_request()
    return build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
    )


def _mechanism_slot_request() -> tuple[str, str]:
    """Render a slot request that carries one verified mechanism suggestion."""
    request = _provider_slot_request()
    suggestion = MechanismSuggestion(
        mechanism_id="user_claim",
        slot_id=request.slots[0].slot_id,
        paths=(
            MechanismSuggestionPath(
                feedback_channel_id="FB-1-1",
                process_model_part_id="PM-1-1",
                end_id="CA-1-1",
            ),
        ),
    )
    return build_synthesis_slot_prompts(
        target_id=request.target_id,
        slots=request.slots,
        routed_briefs=request.routed_briefs,
        routed_routes=request.routed_routes,
        loss_analysis=request.loss_analysis,
        control_structure=request.control_structure,
        mechanism_suggestions=(suggestion,),
    )


def _governance_rows() -> tuple[str, str]:
    briefs, _, losses, structure = _governance_setup("risk-b")
    return build_governance_routing_prompts(
        briefs=briefs,
        loss_analysis=losses,
        control_structure=structure,
        slots=create_slots(structure),
    )


MECHANISM_ITEM = {
    "item_handle": "R1",
    "distinctive_mechanism": {"name": "Pattern", "description": "Canonical"},
    "selected_structural_path": [{"id": "CP-1", "description": "Request process."}],
}
MECHANISM_ITEM_WITH_KNOWN_MECHANISM = {
    **MECHANISM_ITEM,
    "known_mechanism_refs": ["retrieved_instructions"],
}
SUGGESTION_ITEM = {
    "item_handle": "S1",
    "distinctive_mechanism": {"name": "Mechanism", "description": "Question?"},
    "selected_structural_path": [{"id": "CA-1", "description": "Refund."}],
    "known_mechanism_refs": ["user_claim"],
}
SYSTEM_HAZARD = {
    "id": "H-1",
    "description": "A refund reaches the wrong party.",
    "governing_constraints": [{"id": "SC-1", "description": "Refund the payer."}],
}

# Each obligation-aware case calls the builder a request uses and names the
# templates of the (system, user) pair it returns.
OBLIGATION_AWARE_BUILDS: dict[
    str, tuple[Callable[[], tuple[str, str]], tuple[str, str]]
] = {
    "routing-batch": (
        _routing_batch,
        ("structural_routing_system.j2", "structural_routing_user.j2"),
    ),
    "routing-batch-known-mechanism": (
        lambda: _routing_batch("AP-T6-03"),
        ("structural_routing_system.j2", "structural_routing_user.j2"),
    ),
    "slot-request": (
        _slot_request,
        ("synthesis_ica_system.j2", "synthesis_ica_user.j2"),
    ),
    "slot-request-mechanism-suggestion": (
        _mechanism_slot_request,
        ("synthesis_ica_system.j2", "synthesis_ica_user.j2"),
    ),
    "slot-request-feedback-authority": (
        _authority_slot_request,
        ("synthesis_ica_system.j2", "synthesis_ica_user.j2"),
    ),
    "verification-request": (
        lambda: build_ica_hazard_verification_prompts((_verification_request(),)),
        ("ica_hazard_verification_system.j2", "ica_hazard_verification_user.j2"),
    ),
    "mechanism-item": (
        lambda: build_mechanism_verification_prompts([MECHANISM_ITEM]),
        ("mechanism_verification_system.j2", "mechanism_verification_user.j2"),
    ),
    "mechanism-item-known-mechanism": (
        lambda: build_mechanism_verification_prompts(
            [MECHANISM_ITEM_WITH_KNOWN_MECHANISM]
        ),
        ("mechanism_verification_system.j2", "mechanism_verification_user.j2"),
    ),
    "mechanism-suggestion": (
        lambda: build_mechanism_suggestion_verification_prompts(
            [SUGGESTION_ITEM], [SYSTEM_HAZARD]
        ),
        ("mechanism_verification_system.j2", "mechanism_verification_user.j2"),
    ),
    "governance-rows": (
        _governance_rows,
        ("governance_routing_system.j2", "governance_routing_user.j2"),
    ),
    "no-context-gaps": (
        lambda: build_context_coverage_prompts(
            target_id="RESP-1", gaps=(), filled_slots=(), request=None
        ),
        ("synthesis_ica_context_system.j2", "synthesis_ica_context_user.j2"),
    ),
    "context-gaps": (
        lambda: context_coverage_prompts(_coverage_structure()),
        ("synthesis_ica_context_system.j2", "synthesis_ica_context_user.j2"),
    ),
    "context-gaps-feedback-authority": (
        lambda: context_coverage_prompts(
            with_feedback_authority(_coverage_structure())
        ),
        ("synthesis_ica_context_system.j2", "synthesis_ica_context_user.j2"),
    ),
}


def _obligation_aware(case: str) -> Callable[[str], str]:
    def render(template: str) -> str:
        build, templates = OBLIGATION_AWARE_BUILDS[case]
        return dict(zip(templates, build()))[template]

    return render


def _system_model(**variables: object) -> Callable[[str], str]:
    def render(template: str) -> str:
        loader = TemplateLoader(SYSTEM_MODEL_PROMPTS_DIR)
        return loader.render_prompt(template, **variables)

    return render


def _target_realization(**variables: object) -> Callable[[str], str]:
    def render(template: str) -> str:
        loader = TemplateLoader(TARGET_REALIZATION_PROMPTS_DIR)
        return loader.render_prompt(template, **variables)

    return render


def _stage5(
    facts: Callable[[], dict[str, object]],
    context: Callable[[], object] = _wrong_timing_context,
) -> Callable[[str], str]:
    def render(template: str) -> str:
        system, user = build_context_bdi_prompts(
            context(), TemplateLoader(STAGE5_PROMPTS_DIR), **facts()
        )
        return dict(zip(_STAGE5_TEMPLATES, (system, user)))[template]

    return render


def _mechanism_context() -> object:
    """The WRONG_TIMING context with one mechanism suggestion finding."""
    from asago_scenario_generator.stpa.models.scenario_context import (
        ScenarioObligationConsideration,
    )
    from asago_scenario_generator.stpa.scenario_prod.context import (
        build_scenario_generation_context,
    )
    from asago_scenario_generator.stpa.mechanism_library import (
        bundled_mechanism_library,
    )
    from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
    from tests.helpers.normal_authoring_wire import _wrong_timing_structure
    from tests.helpers.sp3_scenario_continuity import (
        _loss_analysis as _continuity_losses,
        _threat_of_type,
    )

    threat = _threat_of_type(UCAType.wrong_timing)
    entry = bundled_mechanism_library().entry("user_claim")
    return build_scenario_generation_context(
        threat,
        _wrong_timing_structure(),
        _continuity_losses(),
        scenario_id="SCN-001",
        obligation_considerations=(
            ScenarioObligationConsideration(
                kind="mechanism",
                mechanism_id=entry.id.value,
                mechanism_name=entry.name,
                concise_concern=entry.question,
                disposition="finding",
                rationale="Finding 0 expresses the mechanism.",
                finding_ica_id=threat.ica_id,
            ),
        ),
    )


def _narrate_stated() -> Callable[[str], str]:
    facts = ScenarioFacts(
        scenario_id="SCN-001",
        kind="adversarial",
        facts=(
            Fact("F1", "situation", "RESP-1 receives a refund request"),
            Fact(
                "F2",
                "agent belief",
                "The agent wrongly believes that the refund is for the caller.",
            ),
            Fact("F3", "weak point", "Feedback is delayed."),
        ),
        glossary=(("RESP-1", "Handle customer service inquiries."),),
        coverage=(("the weak point", ("weak point", "agent belief")),),
        stated_beliefs=True,
    )

    def render(template: str) -> str:
        return dict(zip(_NARRATE_TEMPLATES, render_narration_prompts(facts)))[template]

    return render


def _narrate_rule_only() -> Callable[[str], str]:
    facts = ScenarioFacts(
        scenario_id="SCN-001",
        kind="everyday",
        facts=(
            Fact("F1", "situation", "RESP-1 receives a refund request"),
            Fact("F2", "decision rule", "The rule refunds any request under 50."),
        ),
        glossary=(("RESP-1", "Handle customer service inquiries."),),
        coverage=(("the weak point", ("weak point", "agent belief", "decision rule")),),
        rule_only=True,
    )

    def render(template: str) -> str:
        return dict(zip(_NARRATE_TEMPLATES, render_narration_prompts(facts)))[template]

    return render


def _narrate() -> Callable[[str], str]:
    facts = ScenarioFacts(
        scenario_id="SCN-001",
        kind="adversarial",
        facts=(
            Fact("F1", "situation", "RESP-1 receives a refund request"),
            Fact("F2", "weak point", "Feedback is delayed."),
        ),
        glossary=(("RESP-1", "Handle customer service inquiries."),),
        coverage=(
            ("the situation", ("situation",)),
            ("the weak point", ("weak point",)),
        ),
    )

    def render(template: str) -> str:
        return dict(zip(_NARRATE_TEMPLATES, render_narration_prompts(facts)))[template]

    return render


def _gherkin() -> Callable[[str], str]:
    facts = ScenarioFacts(
        scenario_id="SCN-001",
        kind="adversarial",
        facts=(
            Fact("F1", "attack step", "The attacker asks for a refund."),
            Fact("F2", "failure", "RESP-1 refunds the wrong customer."),
            Fact("F3", "safe behavior", "The agent escalates the request."),
        ),
        glossary=(("RESP-1", "Handle customer service inquiries."),),
        coverage=(),
    )

    def render(template: str) -> str:
        return dict(zip(_GHERKIN_TEMPLATES, render_gherkin_prompts(facts)))[template]

    return render


def _separate_beliefs() -> Callable[[str], str]:
    """Render the belief request of a spec with a code-filled and a chosen factor."""

    def render(template: str) -> str:
        # Compiling the Stage 5 spec writes its call log into a run directory.
        with tempfile.TemporaryDirectory() as run_dir:
            spec, structure = belief_spec(Path(run_dir))
        prompts = render_belief_prompts(spec, belief_request(spec, structure))
        return dict(zip(_BELIEF_TEMPLATES, prompts))[template]

    return render


def _decision_rule_beliefs() -> Callable[[str], str]:
    """Render the belief request of a spec with a PM and a decision-rule factor."""

    def render(template: str) -> str:
        with tempfile.TemporaryDirectory() as run_dir:
            spec, structure = decision_rule_belief_spec(Path(run_dir))
        prompts = render_belief_prompts(spec, belief_request(spec, structure))
        return dict(zip(_BELIEF_TEMPLATES, prompts))[template]

    return render


def _authority_beliefs() -> Callable[[str], str]:
    """Render the belief request of a spec whose factor has an assessed source."""

    def render(template: str) -> str:
        spec, structure = authority_belief_spec()
        prompts = render_belief_prompts(spec, belief_request(spec, structure))
        return dict(zip(_BELIEF_TEMPLATES, prompts))[template]

    return render


def _descriptive_literal_condition() -> dict:
    """A condition whose literal is a descriptive phrase, not a supplied value."""
    return _placeholder_payload()["unsafe_outcome"]["discriminating_condition"]


def _stage5_correction(condition: Callable[[], dict | None]) -> Callable[[str], str]:
    """Render the Stage 5 correction request that follows a refused condition."""

    def render(request: str) -> str:
        assert request == "stage5_condition_correction"
        # Stage 5 writes its call log into a run directory.
        with tempfile.TemporaryDirectory() as run_dir:
            return correction_request(condition(), Path(run_dir))

    return render


def _call_2b_authority_correction(request: str) -> str:
    """Render the Call 2b correction request that follows two failing bases."""
    assert request == "stage2_call2b_authority_correction_request"
    # Imported here: that test module reads CASES from this one.
    from tests.stpa.test_feedback_update_authority import (
        authority_correction_request,
    )

    with tempfile.TemporaryDirectory() as run_dir:
        return authority_correction_request(Path(run_dir))


def _revision_authority_correction(request: str) -> str:
    """Render the revision correction request that follows two failing bases."""
    assert request == "revision_authority_correction_request"
    # Imported here: that test module reads CASES from this one.
    from tests.stpa.test_feedback_update_authority import (
        revision_authority_correction_request,
    )

    with tempfile.TemporaryDirectory() as run_dir:
        return revision_authority_correction_request(Path(run_dir))


def _revision_merge_and_authority_correction(request: str) -> str:
    """Render the revision correction that follows a merge and an authority error."""
    assert request == "revision_merge_and_authority_correction_request"
    # Imported here, as above.
    from tests.stpa.test_revision_correction_names_every_error import (
        merge_and_authority_correction_request,
    )

    with tempfile.TemporaryDirectory() as run_dir:
        return merge_and_authority_correction_request(Path(run_dir))


# The critic request for a structure whose feedback channel is assessed.
FEEDBACK_AUTHORITY_CRITIC = {
    "use_case_text": "Test use case",
    "control_structure": with_feedback_authority(_obligation_structure()),
    "capability_profile": make_capability_profile(),
    "loss_analysis": None,
    "call3_warnings": None,
}


# The Call 3 request for a structure whose feedback channel is assessed.
FEEDBACK_AUTHORITY_CALL3 = {
    "use_case_text": CALL3_USE_CASE,
    "control_structure": with_feedback_authority(call3_inputs()[1]),
    "loss_analysis": None,
    "source_excerpts": (),
    "source_ref_by_canonical": {},
}


# A case renders one template; the table that names it supplies the template.
CASES: dict[str, Callable[[str], str]] = {
    "no-variables": _system_model(),
    "named-reply": _system_model(reply_name="control element set"),
    "no-target-variables": _target_realization(),
    "no-stated-rules": _system_model(stated_rules=False),
    "records-service": _system_model(**RECORDS_SERVICE),
    "actionability-risks": _system_model(**ACTIONABILITY_RISKS),
    "neutral-status": _system_model(**NEUTRAL_STATUS),
    "one-responsibility": _system_model(**ONE_RESPONSIBILITY),
    "test-use-case": _system_model(
        use_case_text="Test use case", selected_constraints=[]
    ),
    "no-probes": _system_model(taxonomy_probes=[]),
    "reference-repair": _system_model(
        use_case_text="Test use case",
        selected_lists=[],
        feedback="",
        unknown_ids=True,
        disposition_lists=False,
    ),
    "reference-repair-dispositions": _system_model(
        use_case_text="Test use case",
        selected_lists=[],
        feedback="",
        unknown_ids=True,
        disposition_lists=True,
    ),
    "empty-structure": _system_model(**EMPTY_STRUCTURE),
    "unknown-references": _system_model(**UNKNOWN_REFERENCES),
    "undeclared-controlled-processes": _system_model(**UNDECLARED_CONTROLLED_PROCESSES),
    "duplicate-controlled-processes": _system_model(**DUPLICATE_CONTROLLED_PROCESSES),
    "missing-control-actions": _system_model(**MISSING_CONTROL_ACTIONS),
    "no-declared-processes": _system_model(
        **{**MISSING_CONTROL_ACTIONS, "controlled_processes": []}
    ),
    "target-blind": _stage5(dict),
    "mechanism-consideration": _stage5(dict, _mechanism_context),
    "operation": _stage5(lambda: {"target_operation": _target_operation()}),
    "observations": _stage5(lambda: {"target_observations": _record_observations()}),
    "operation-and-observations": _stage5(
        lambda: {
            "target_operation": _target_operation(),
            "target_observations": _record_observations(),
        }
    ),
    "narrate": _narrate(),
    "narrate-stated": _narrate_stated(),
    "narrate-rule-only": _narrate_rule_only(),
    "gherkin": _gherkin(),
    "separate-beliefs": _separate_beliefs(),
    "decision-rule-beliefs": _decision_rule_beliefs(),
    "feedback-authority-beliefs": _authority_beliefs(),
    "feedback-authority": _stage5(dict, authority_context),
    "feedback-authority-critic": _system_model(**FEEDBACK_AUTHORITY_CRITIC),
    "unassessed-critic": _system_model(
        **{**FEEDBACK_AUTHORITY_CRITIC, "control_structure": _obligation_structure()}
    ),
    "feedback-authority-call3": _system_model(**FEEDBACK_AUTHORITY_CALL3),
    "unassessed-call3": _system_model(
        **{**FEEDBACK_AUTHORITY_CALL3, "control_structure": call3_inputs()[1]}
    ),
    "archive-item": _stage5(_archive_item_facts),
    "commit-operation": _stage5(_commit_operation_facts),
    "realistic-request": _stage5(_realistic_request_facts),
    "realistic-no-tool-call": _stage5(lambda: _realistic_request_facts(False)),
    "realistic-tool-call-action": _stage5(
        _realistic_request_facts, _tool_call_action_context
    ),
    "stated-rules": _system_model(stated_rules=True),
    "no-findings": _system_model(**NO_FINDINGS),
    "blank-hazard-records": _system_model(
        records=["hazard addition NEW-1", "hazard edit H-2"]
    ),
    "unknown-coordination-references": _system_model(
        references=[
            SimpleNamespace(
                location="coordination link CL-7 description",
                token="PM-3",
                candidate=None,
            ),
            SimpleNamespace(
                location="coordination link CL-7 description",
                token="PM-4",
                candidate="PM-4-3",
            ),
        ]
    ),
    "record-kind-mismatch-correction": _stage5_correction(
        _record_kind_mismatch_condition
    ),
    "ordering-not-numeric-correction": _stage5_correction(_ordering_text_condition),
    "missing-condition-correction": _stage5_correction(lambda: None),
    "literal-unsupported-correction": _stage5_correction(
        _descriptive_literal_condition
    ),
    "two-failing-authority-bases": _call_2b_authority_correction,
    "two-failing-revision-authority-bases": _revision_authority_correction,
    "unmergeable-revision-with-failing-authority-basis": (
        _revision_merge_and_authority_correction
    ),
    **{case: _obligation_aware(case) for case in OBLIGATION_AWARE_BUILDS},
}


@dataclass(frozen=True)
class PhraseCheck:
    """One kind of check for one case of one table."""

    table: str
    template: str
    case: str
    kind: str
    phrases: tuple[str | tuple[str, ...], ...]

    @property
    def id(self) -> str:
        return f"{self.table}/{self.case}/{self.kind}"


def normalize(text: str) -> str:
    return " ".join(text.split())


def table_paths() -> list[Path]:
    return sorted(PHRASES_DIR.glob("*.yaml"))


@cache
def load_table(path: Path) -> dict:
    with path.open(encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def template_path(template: str) -> Path:
    """Return the one prompt file named ``template`` across the prompt dirs."""
    matches = [d / template for d in PROMPT_DIRS if (d / template).is_file()]
    if len(matches) != 1:
        raise LookupError(f"{template}: found in {len(matches)} prompt directories")
    return matches[0]


def phrase_checks() -> list[PhraseCheck]:
    checks = []
    for path in table_paths():
        table = load_table(path)
        for case, kinds in table["cases"].items():
            for kind, phrases in kinds.items():
                checks.append(
                    PhraseCheck(
                        table=path.stem,
                        template=table.get("template") or table["request"],
                        case=case,
                        kind=kind,
                        phrases=tuple(
                            tuple(p) if isinstance(p, list) else p for p in phrases
                        ),
                    )
                )
    return checks


@cache
def render(template: str, case: str) -> str:
    return normalize(CASES[case](template))


def _ordered_failure(phrase: tuple[str, ...], rendered: str) -> str | None:
    markers = [normalize(marker) for marker in phrase]
    missing = [marker for marker in markers if marker not in rendered]
    if missing:
        return f"missing {missing[0]!r} (ordered {markers!r})"
    positions = [rendered.index(marker) for marker in markers]
    return None if positions == sorted(positions) else f"out of order {markers!r}"


def _count_failure(kind: str, phrase: str, rendered: str) -> str | None:
    text = normalize(phrase)
    count = rendered.count(text)
    if kind == "required" and count == 0:
        return f"missing {text!r}"
    if kind == "once" and count != 1:
        return f"expected once, found {count} times: {text!r}"
    if kind == "forbidden" and count:
        return f"forbidden {text!r}"
    return None


def failures(check: PhraseCheck, rendered: str) -> list[str]:
    """Return one message per phrase of ``check`` that ``rendered`` breaks."""
    if check.kind == "ordered":
        found = [_ordered_failure(phrase, rendered) for phrase in check.phrases]
    else:
        found = [_count_failure(check.kind, p, rendered) for p in check.phrases]
    return [f"{check.id}: {message}" for message in found if message]
