"""Public-seam tests for obligation-aware STPA analysis."""

from __future__ import annotations

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.artifact_pin import ArtifactPin
from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    ObligationIcaConsideration,
    ObligationSemanticAssessment,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionTemporality,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    FeedbackChannel,
    ProcessModelPart,
    ReferenceType,
    Responsibility,
    ResponsibilityConstraint,
    CoordinationLink,
    CoordinationMechanism,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    DraftControlAction,
    DraftCoordinationLink,
    DraftCoordinationMechanism,
    DraftControlledProcess,
    DraftFeedbackChannel,
    DraftHazard,
    DraftLoss,
    DraftProcessModelPart,
    DraftResponsibilityConstraint,
    DraftSecurityConstraint,
    DraftResponsibility,
    IcaDeviationDraft,
    IcaFindingDraft,
    ObligationIcaDraft,
    RevisionDraft,
    ObligationRoute,
    SlotIcaDraft,
    StructuralRoutingResponse,
    StructuralRevisionResponse,
    SynthesisSlotRequest,
    SynthesisSlotResponse,
    PromptReference,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
    project_revision_context,
    audit_prompt_contract,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    build_neutral_brief,
    build_neutral_briefs,
    create_obligation_batches,
    route_obligations,
    _reference_sets,
    _validate_route,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    _fallback_slot,
    _typed_response,
    _validate_pair,
    fill_synthesis_slots,
)
from asago_scenario_generator.stpa.obligation_aware.revision import (
    compile_revision_draft,
    revise_structure_once,
)
from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.provider_record import ProviderCallSession
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICASlot,
    UCAType,
    candidate_id_for,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import (
    create_slots,
    SlotPlaceholder,
)
from asago_scenario_generator.pipeline.obligation_consideration import (
    build_consideration_artifact,
    build_obligation_accounting,
)
from tests.helpers.calls_log import read_calls_jsonl
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern
from tests.helpers.request_dispatch import dispatch_requests
from pydantic import BaseModel
from types import SimpleNamespace
from asago_scenario_generator.stpa.infra.prompt_preflight import (
    PromptBudget,
    resolve_prompt_budget,
)
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    _provider_slot_request,
    _routed_slot_draft,
)


def test_neutral_briefs_and_batches_are_canonical_and_non_prescriptive() -> None:
    """Applicable obligations become neutral questions in stable batches."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan(risk_ids=("risk-b", "risk-a"))

    briefs = build_neutral_briefs(plan, (pattern,))
    assert [brief.obligation_id for brief in briefs] == sorted(
        brief.obligation_id for brief in briefs
    )
    assert all(brief.attack_pattern_id == pattern.id for brief in briefs)
    assert all(
        "canonical_steps" not in brief.model_dump(mode="json") for brief in briefs
    )

    system_prompt, user_prompt = build_structural_routing_prompts(
        briefs=briefs,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=(),
    )
    assert "hypothesis" in system_prompt.lower()
    assert "ordered attack" in system_prompt.lower()
    assert "RESP-*:CA-*:UCA_TYPE" in system_prompt
    assert "CL-*:CM-*:UCA_TYPE" in system_prompt
    assert "each namespace field" in system_prompt.lower()
    assert "coordination_link_ids" in system_prompt
    assert "source responsibility" in system_prompt.lower()
    assert "candidate" not in user_prompt.lower()
    assert all(brief.obligation_id in user_prompt for brief in briefs)

    batches = create_obligation_batches(tuple(reversed(briefs)), max_batch_size=1)
    assert [[brief.obligation_id for brief in batch] for batch in batches] == [
        [brief.obligation_id] for brief in briefs
    ]


def test_routing_accounts_for_each_applicable_obligation_once() -> None:
    """A valid adapter response is checked against exact input identities."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan(risk_ids=("risk-a", "risk-b"))
    briefs = build_neutral_briefs(plan, (pattern,))
    observed: list[str] = []

    class FakeAdapter:
        def route(self, request, *, correction_feedback=None):
            observed.append(request.semantic_digest)
            return StructuralRoutingResponse(
                request_digest=request.semantic_digest,
                routes=tuple(
                    ObligationRoute(
                        obligation_id=brief.obligation_id,
                        disposition="targeted",
                        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                        controller_ids=("RESP-1",),
                        responsibility_ids=("RESP-1",),
                        control_action_ids=("CA-1-1",),
                        controlled_process_ids=("CP-1",),
                        hazard_ids=("H-1",),
                        constraint_ids=("SC-1",),
                        rationale="The existing validation responsibility is relevant.",
                        evidence=("H-1", "SC-1", "RESP-1"),
                    )
                    for brief in request.briefs
                ),
                adapter_kind="fake",
                request_ref="memory://route/request",
                response_ref="memory://route/response",
            )

    result = route_obligations(
        FakeAdapter(),
        plan=plan,
        attack_pattern_catalog=(pattern,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
        controls=_controls(),
        max_batch_size=1,
    )

    assert len(observed) == len(briefs)
    assert [route.obligation_id for route in result.routes] == [
        brief.obligation_id for brief in briefs
    ]
    assert all(route.disposition == "targeted" for route in result.routes)


def test_routing_rejects_missing_or_duplicate_obligation_ids() -> None:
    """A batch cannot silently drop, duplicate, or invent an obligation."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()

    class BadAdapter:
        def route(self, request, *, correction_feedback=None):
            route = ObligationRoute(
                obligation_id=request.briefs[0].obligation_id,
                disposition="targeted",
                slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                rationale="Existing path.",
                evidence=("H-1", "SC-1"),
            )
            return StructuralRoutingResponse(
                request_digest=request.semantic_digest,
                routes=(route, route),
                adapter_kind="fake",
                request_ref="memory://route/request",
                response_ref="memory://route/response",
            )

    result = route_obligations(
        BadAdapter(),
        plan=plan,
        attack_pattern_catalog=(pattern,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
        max_batch_size=1,
    )
    assert result.routes[0].disposition == "unresolved"
    assert result.routes[0].diagnostics


def _coordination_structure() -> ControlStructure:
    """Build two controllers and one valid coordination link for slot tests."""
    first = _control_structure().responsibilities[0]
    second = Responsibility(
        resp_id="RESP-2",
        description="Review policy outcomes.",
        responsibility_constraints=(
            ResponsibilityConstraint(
                rc_id="RC-2-1", description="Reviews are required."
            ),
        ),
        process_model_parts=(
            ProcessModelPart(pm_id="PM-2-1", description="Review state."),
        ),
        control_actions=(
            ControlAction(
                ca_id="CA-2-1",
                description="Review outcome.",
                target=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ),
        feedback_channels=(
            FeedbackChannel(
                fb_id="FB-2-1",
                description="Review feedback.",
                updates="PM-2-1",
                source=ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            ),
        ),
    )

    return ControlStructure(
        responsibilities=(first, second),
        controlled_processes=(
            ControlledProcess(cp_id="CP-1", description="Request process."),
        ),
        coordination_links=(
            CoordinationLink(
                link_id="CL-1",
                source="RESP-1",
                target="RESP-2",
                shared_pm="PM-1-1",
                coordination_mechanism=CoordinationMechanism(
                    cm_id="CM-1",
                    description="Shared review signal.",
                    payload="review outcome",
                ),
                description="Coordinate request review.",
            ),
        ),
    )


def test_slot_fill_targets_coordination_and_ordinary_routes_only() -> None:
    """Every final slot is filled while each target sees only its routed brief."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan(risk_ids=("risk-a", "risk-b"))
    briefs = build_neutral_briefs(plan, (pattern,))
    control_structure = _coordination_structure()
    slots = create_slots(control_structure)
    ordinary = next(slot for slot in slots if slot.responsibility == "RESP-1")
    coordination = next(slot for slot in slots if slot.coordination_link == "CL-1")
    routes = (
        ObligationRoute(
            obligation_id=briefs[0].obligation_id,
            disposition="targeted",
            slot_ids=(ordinary.slot_id,),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("ordinary-route",),
        ),
        ObligationRoute(
            obligation_id=briefs[1].obligation_id,
            disposition="targeted",
            slot_ids=(coordination.slot_id,),
            coordination_link_ids=("CL-1",),
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            evidence=("coordination-route",),
        ),
    )
    observed: list[tuple[str, str, tuple[str, ...]]] = []

    class FakeAdapter:
        def fill(self, request):
            assert len(request.slots) == 1
            observed.append(
                (
                    request.target_id,
                    request.slots[0].slot_id,
                    tuple(brief.obligation_id for brief in request.routed_briefs),
                )
            )
            return SynthesisSlotResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                filled_slots=tuple(
                    _routed_slot_draft(
                        slot,
                        [
                            r
                            for r in request.routed_routes
                            if slot.slot_id in r.slot_ids
                        ],
                    )
                    for slot in request.slots
                ),
            )

    result = fill_synthesis_slots(
        FakeAdapter(),
        briefs=briefs,
        routes=routes,
        loss_analysis=_loss_analysis(),
        control_structure=control_structure,
        controls=_controls(),
    )

    assert len(result.ica_enumeration.slots) == 12
    assert all(slot.unresolved_reason is None for slot in result.ica_enumeration.slots)
    assert all(len(request.slots) == 1 for request in result.result.requests)
    assert (
        "RESP-1",
        ordinary.slot_id,
        (briefs[0].obligation_id,),
    ) in observed
    assert (
        "CL-1",
        coordination.slot_id,
        (briefs[1].obligation_id,),
    ) in observed
    assert len(result.considerations) == 2


@pytest.mark.parametrize(
    ("sent", "answer", "outcome"),
    [
        (0, True, "accepted"),
        (2, True, "accepted"),
        (1, False, "unresolved"),
        (0, False, "unresolved"),
    ],
)
def test_slot_fill_evidence_counts_the_requests_the_adapter_sent(
    tmp_path, sent: int, answer: bool, outcome: str
) -> None:
    """An accepted or failed target records the requests sent for it, 0 included."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(make_plan(), (pattern,))
    control_structure = _control_structure()
    slot = create_slots(control_structure)[0]
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("ordinary-route",),
    )

    class Adapter:
        def fill(self, request):
            dispatch_requests(tmp_path, sent)
            if not answer:
                raise ValueError("provider answered with an unusable body")
            return SynthesisSlotResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                filled_slots=tuple(
                    _routed_slot_draft(
                        item,
                        [
                            r
                            for r in request.routed_routes
                            if item.slot_id in r.slot_ids
                        ],
                    )
                    for item in request.slots
                ),
            )

    result = fill_synthesis_slots(
        Adapter(),
        briefs=briefs,
        routes=(route,),
        loss_analysis=_loss_analysis(),
        control_structure=control_structure,
        controls=_controls(),
    )

    evidence = result.result.call_evidence
    assert {item.outcome for item in evidence} == {outcome}
    assert {item.attempt_count for item in evidence} == {sent}


def test_routing_accepts_coordination_path_with_source_controller() -> None:
    """A coordination slot resolves its link, endpoints, and mechanism exactly."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    brief = build_neutral_briefs(plan, (pattern,))[0]
    control_structure = _coordination_structure()
    coordination = next(
        slot
        for slot in create_slots(control_structure)
        if slot.coordination_link == "CL-1"
    )
    route = ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=(coordination.slot_id,),
        # The source responsibility issues the coordination mechanism.  The
        # CL identity belongs in coordination_link_ids, not in the RESP
        # controller namespace.
        controller_ids=("RESP-1",),
        responsibility_ids=("RESP-1", "RESP-2"),
        control_action_ids=("CM-1",),
        process_model_part_ids=("PM-1-1",),
        coordination_link_ids=("CL-1",),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("coordination path evidence",),
    )

    class CoordinationRouteAdapter:
        def route(self, request, *, correction_feedback=None):
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(route,),
            )

    result = route_obligations(
        CoordinationRouteAdapter(),
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=control_structure,
        slots=create_slots(control_structure),
        controls=_controls(),
    )

    assert result.routes == (route,)
    assert result.routes[0].controller_ids == ("RESP-1",)
    assert result.routes[0].control_action_ids == ("CM-1",)
    assert result.routes[0].responsibility_ids == ("RESP-1", "RESP-2")


@pytest.mark.parametrize(
    ("field_name", "value", "message"),
    (
        (
            "controller_ids",
            ("CL-1",),
            "controller references do not match",
        ),
        (
            "control_action_ids",
            ("CA-1-1",),
            "control action references do not match",
        ),
    ),
)
def test_routing_rejects_coordination_path_identity_relabelling(
    field_name: str,
    value: tuple[str, ...],
    message: str,
) -> None:
    """A CL/CM slot cannot be relabelled as a RESP/CA path."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    brief = build_neutral_briefs(plan, (pattern,))[0]
    control_structure = _coordination_structure()
    coordination = next(
        slot
        for slot in create_slots(control_structure)
        if slot.coordination_link == "CL-1"
    )
    route_values = {
        "obligation_id": brief.obligation_id,
        "disposition": "targeted",
        "slot_ids": (coordination.slot_id,),
        "controller_ids": ("RESP-1",),
        "responsibility_ids": ("RESP-1", "RESP-2"),
        "control_action_ids": ("CM-1",),
        "process_model_part_ids": ("PM-1-1",),
        "coordination_link_ids": ("CL-1",),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
        "evidence": ("coordination path evidence",),
    }
    route_values[field_name] = value
    route = ObligationRoute.model_validate(route_values)

    class CoordinationRouteAdapter:
        def route(self, request, *, correction_feedback=None):
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(route,),
            )

    result = route_obligations(
        CoordinationRouteAdapter(),
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=control_structure,
        slots=create_slots(control_structure),
        controls=_controls(),
    )

    assert result.routes[0].disposition == "unresolved"
    assert message in result.diagnostics[0]


def test_provider_routing_retry_has_one_owner(tmp_path) -> None:
    """Structural validation retries do not multiply inside the provider."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    briefs = build_neutral_briefs(plan, (pattern,))
    brief = briefs[0]
    prompts: list[str] = []
    compatibility_modes: list[bool] = []
    completion_caps: list[int | None] = []
    response_formats: list[type] = []

    class FakeLLM:
        model = "fake-stpa"
        calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            prompts.append(kwargs["user_prompt"])
            compatibility_modes.append(kwargs.get("allow_unvalidated", False))
            completion_caps.append(kwargs.get("max_completion_tokens"))
            response_formats.append(kwargs["response_format"])
            if self.calls == 1:
                # This is schema-valid provider output but fails the router's
                # exact one-route-per-obligation validation.
                content = {"routes": []}
            elif self.calls == 2:
                provider_route = ObligationRoute(
                    obligation_id=brief.obligation_id,
                    disposition="targeted",
                    semantic_assessment=ObligationSemanticAssessment(
                        mechanism_assessment="plausible_in_system",
                        risk_alignment="supported",
                        mapping_strength="direct_curated_pair",
                        mechanism_rationale="The supplied control path permits it.",
                        risk_alignment_rationale="The mechanism realizes the reviewed risk.",
                    ),
                    slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                    hazard_ids=("H-1",),
                    constraint_ids=("SC-1",),
                    rationale="The supplied control path is relevant to the concern.",
                    evidence=("provider-route",),
                ).model_dump(
                    mode="json",
                    exclude={
                        "route_id",
                        "missing_concepts",
                        "model_call_refs",
                        "trace_refs",
                        "diagnostics",
                    },
                )
                provider_route["semantic_assessment"].pop("mapping_strength", None)
                content = {"routes": [provider_route]}
            else:
                content = {
                    "verdicts": [
                        {
                            "item_handle": "R1",
                            "relationship": "mechanism_specific",
                            "rationale": "The selected path governs the mechanism.",
                        }
                    ]
                }
            return LLMResult(
                content=content,
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    client = FakeLLM()
    client.session = ProviderCallSession(record_dir=tmp_path)
    provider = ObligationAwareLLMAdapter(
        client,
        run_dir=tmp_path,
        controls=_controls(),
    )
    result = route_obligations(
        provider,
        briefs=briefs,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
        controls=_controls(),
    )

    assert client.calls == 3
    assert len(result.call_evidence) == 1
    assert result.call_evidence[0].attempt_count == 2
    assert "Validation correction" in prompts[1]
    assert compatibility_modes == [False, False, False]
    assert completion_caps == [8192, 8192, 1024]
    schema = response_formats[0].model_json_schema()
    assert "routes" in schema["required"]
    assert schema["properties"]["routes"]["minItems"] == 1
    assert schema["properties"]["routes"]["maxItems"] == 1
    route_schema = schema["$defs"]["_RoutingProviderRoute"]
    assert "route_id" not in route_schema["properties"]
    assert "semantic_assessment" in route_schema["required"]
    gap_schema = schema["$defs"]["_RoutingProviderMissingConcept"]
    assert "gap_id" not in gap_schema["properties"]
    assert result.routes[0].route_id.startswith("route:v1:")
    calls = read_calls_jsonl(tmp_path)
    assert "_uca_method.j2" in calls[-1]["prompt_template_hashes"]
    assert calls[-1]["compiled"] is True
    assert calls[-1]["published"] is True
    assert client.session.call_log.entries(tmp_path) == calls


def test_routing_retry_includes_exact_local_validation_error() -> None:
    """A bounded routing retry tells the adapter what local check failed."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    brief = build_neutral_briefs(plan, (pattern,))[0]
    feedbacks: list[str | None] = []

    class FeedbackAdapter:
        def route(self, request, *, correction_feedback=None):
            feedbacks.append(correction_feedback)
            if correction_feedback is None:
                route = ObligationRoute(
                    obligation_id=brief.obligation_id,
                    disposition="targeted",
                    # Deliberately use a hazard in the slot namespace.
                    slot_ids=("H-1",),
                    hazard_ids=("H-1",),
                    constraint_ids=("SC-1",),
                    evidence=("provider-route",),
                )
            else:
                assert "unknown slot IDs: H-1" in correction_feedback
                route = ObligationRoute(
                    obligation_id=brief.obligation_id,
                    disposition="targeted",
                    slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                    hazard_ids=("H-1",),
                    constraint_ids=("SC-1",),
                    evidence=("provider-route",),
                )
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(route,),
            )

    result = route_obligations(
        FeedbackAdapter(),
        briefs=(brief,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
        controls=_controls(),
    )

    assert len(feedbacks) == 2
    assert feedbacks[0] is None
    assert feedbacks[1] is not None
    assert "unknown slot IDs: H-1" in feedbacks[1]
    assert result.routes[0].disposition == "targeted"


def test_provider_slot_payload_requires_filled_slots(tmp_path) -> None:
    """A schema-success response cannot silently omit every supplied slot."""

    class EmptySlotProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            return LLMResult(
                content={"filled_slots": []},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        EmptySlotProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )

    with pytest.raises(ValueError, match="filled_slots"):
        provider.fill(_provider_slot_request())


def test_provider_slot_payload_uses_nested_typed_considerations(tmp_path) -> None:
    """Provider considerations are parsed beside their slot findings."""
    slot = create_slots(_control_structure())[0]
    response_formats: list[type] = []

    class ArbitraryConsiderationProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            response_formats.append(kwargs["response_format"])
            return LLMResult(
                content={
                    "filled_slots": [
                        {
                            "slot_id": slot.slot_id,
                            "is_na": True,
                            "na_rationale": "No provider finding was returned for this slot.",
                            "findings": [],
                            "consideration_results": [
                                {"freeform": "not typed evidence"}
                            ],
                        }
                    ],
                },
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        ArbitraryConsiderationProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )

    with pytest.raises(ValueError, match="consideration_results"):
        provider.fill(_provider_slot_request())

    schema = response_formats[0].model_json_schema()
    assert "considerations" not in schema["properties"]
    assert (
        "consideration_results" in schema["$defs"]["_SlotProviderDraft"]["properties"]
    )


def test_provider_slot_payload_materializes_canonical_exec_identity(tmp_path) -> None:
    """Provider output cannot invent derived pair or EXEC identities."""
    slot = create_slots(_control_structure())[0]
    filled_slot = SlotIcaDraft(
        slot_id=slot.slot_id,
        is_na=False,
        findings=(
            IcaFindingDraft(
                deviation=IcaDeviationDraft(
                    not_provided_context="the request is not reviewed"
                ),
                hazardous_context="the unreviewed request reaches the process",
                loss_consequence="the protected operation is harmed",
                related_hazard_ids=("H-1",),
                related_constraint_ids=("SC-1",),
            ),
        ),
        consideration_results=(
            ObligationIcaDraft(
                obligation_handle="R1",
                disposition="finding",
                finding_indexes=(0,),
                rationale="The routed concern is addressed by this finding.",
            ),
        ),
    )
    response_formats: list[type] = []
    obligation_id = "ob:v1:" + "a" * 64
    route = ObligationRoute(
        obligation_id=obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
    )

    class FindingProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            response_formats.append(kwargs["response_format"])
            return LLMResult(
                content={"filled_slots": [filled_slot.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        FindingProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )

    result = provider.fill(
        _provider_slot_request(routed_routes=(route,), validation_retries=1)
    )
    pair = result.considerations[0]
    assert pair.route_id == route.route_id
    assert pair.obligation_id == obligation_id
    assert pair.slot_id == slot.slot_id
    assert pair.ica_ids == (f"{slot.slot_id}:1",)
    assert pair.exec_candidate_ids == (
        candidate_id_for(
            slot.responsibility or slot.coordination_link,
            slot.control_action,
            slot.uca_type,
        ),
    )
    assert pair.disposition == "finding"
    assert pair.hazard_ids == ("H-1",)
    assert pair.constraint_ids == ("SC-1",)
    assert pair.pair_id is not None
    schema = response_formats[0].model_json_schema()
    assert schema["properties"]["filled_slots"]["items"]["$ref"].endswith(
        "/_SlotProviderDraft"
    )
    assert "considerations" not in schema["properties"]


@pytest.mark.parametrize(
    ("uca_type", "deviation", "expected_behavior"),
    (
        (UCAType.not_provided, "the request is not reviewed", "fails to provide"),
        (
            UCAType.incorrect,
            "an invalid request is treated as valid",
            "with an unsafe value/effect",
        ),
        (
            UCAType.wrong_timing,
            "authorization occurs before validation completes",
            "at an unsafe time or order",
        ),
        (
            UCAType.wrong_duration,
            "validation remains active for too long",
            "for an unsafe duration",
        ),
    ),
)
def test_provider_slot_payload_compiles_one_deviation_for_exact_slot_type(
    tmp_path, uca_type: UCAType, deviation: str, expected_behavior: str
) -> None:
    """The model supplies prose while the compiler owns the UCA category."""
    base_request = _provider_slot_request()
    slot = next(
        item for item in create_slots(_control_structure()) if item.uca_type is uca_type
    )
    if uca_type is UCAType.wrong_duration:
        slot = slot.model_copy(
            update={"action_temporality": ControlActionTemporality.continuous}
        )
    request = SynthesisSlotRequest(
        target_id=slot.responsibility or slot.coordination_link or "",
        target_kind="responsibility",
        slots=(slot,),
        loss_analysis=base_request.loss_analysis,
        control_structure=base_request.control_structure,
        controls=base_request.controls,
    )
    response_formats: list[type] = []

    class FindingProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            response_formats.append(kwargs["response_format"])
            return LLMResult(
                content={
                    "filled_slots": [
                        {
                            "slot_id": slot.slot_id,
                            "is_na": False,
                            "na_rationale": None,
                            "findings": [
                                {
                                    "deviation": deviation,
                                    "hazardous_context": (
                                        "the unreviewed request reaches the process"
                                    ),
                                    "loss_consequence": (
                                        "the protected operation is harmed"
                                    ),
                                    "related_hazard_ids": ["H-1"],
                                    "related_constraint_ids": ["SC-1"],
                                    "process_model_refs": [],
                                    "feedback_refs": [],
                                }
                            ],
                            "consideration_results": [],
                        }
                    ]
                },
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    result = ObligationAwareLLMAdapter(
        FindingProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    ).fill(request)

    assert expected_behavior in result.filled_slots[0].icas[0].ica_text
    assert deviation in result.filled_slots[0].icas[0].ica_text
    schema = response_formats[0].model_json_schema()
    finding_schema = schema["$defs"]["_SlotProviderFindingDraft"]
    deviation_schema = finding_schema["properties"]["deviation"]
    assert deviation_schema["type"] == "string"
    assert deviation_schema["minLength"] == 1
    constraint_schema = finding_schema["properties"]["related_constraint_ids"]
    assert constraint_schema["minItems"] == 1
    assert constraint_schema["maxItems"] == 1
    assert "not_provided_context" not in finding_schema["properties"]
    assert "incorrect_value_or_effect" not in finding_schema["properties"]
    assert "timing_deviation" not in finding_schema["properties"]
    assert "duration_deviation" not in finding_schema["properties"]


def test_provider_arbitrary_ica_id_survives_fill_and_accounting(tmp_path) -> None:
    """Provider findings become canonical addressed evidence and accounting."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    briefs = build_neutral_briefs(plan, (pattern,))
    control_structure = _control_structure()
    loss_analysis = _loss_analysis()
    slots = tuple(
        sorted(create_slots(control_structure), key=lambda item: item.slot_id)
    )
    target_slot = next(item for item in slots if item.uca_type is UCAType.not_provided)
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=(target_slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
    )

    class FindingProvider:
        model = "fake-stpa"

        calls = 0

        def complete(self, **kwargs):
            self.calls += 1
            slot = slots[self.calls - 1]
            if slot.slot_id == target_slot.slot_id:
                filled_slot = SlotIcaDraft(
                    slot_id=slot.slot_id,
                    is_na=False,
                    findings=(
                        IcaFindingDraft(
                            deviation=IcaDeviationDraft(
                                not_provided_context="the request is not reviewed"
                            ),
                            hazardous_context="the unreviewed request reaches the process",
                            loss_consequence="the protected operation is harmed",
                            related_hazard_ids=("H-1",),
                            related_constraint_ids=("SC-1",),
                        ),
                    ),
                    consideration_results=(
                        ObligationIcaDraft(
                            obligation_handle="R1",
                            disposition="finding",
                            finding_indexes=(0,),
                            rationale="The routed concern is addressed by this finding.",
                        ),
                    ),
                )
            else:
                filled_slot = SlotIcaDraft(
                    slot_id=slot.slot_id,
                    is_na=True,
                    na_rationale="No routed concern applies.",
                )
            return LLMResult(
                content={"filled_slots": [filled_slot.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        FindingProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )
    filled = fill_synthesis_slots(
        provider,
        briefs=briefs,
        routes=(route,),
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        controls=_controls(),
    )

    canonical_ica_id = f"{target_slot.slot_id}:1"
    assert filled.considerations[0].disposition == "finding"
    assert filled.considerations[0].ica_ids == (canonical_ica_id,)
    filled_target = next(
        item
        for item in filled.ica_enumeration.slots
        if item.slot_id == target_slot.slot_id
    )
    assert filled_target.icas[0].ica_id == canonical_ica_id

    consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(route,),
        final_routes=(route,),
    )
    accounting = build_obligation_accounting(
        plan=plan,
        consideration=consideration,
        ica_considerations=filled.considerations,
        source_pins=(
            ArtifactPin(
                artifact_id="taxonomy-obligation-plan",
                schema_version="taxonomy-obligation-plan-v1",
                semantic_digest=plan.semantic_digest,
            ),
            ArtifactPin(
                artifact_id="stpa-loss-analysis",
                schema_version="stpa-loss-analysis-v1",
                semantic_digest="2" * 64,
            ),
            ArtifactPin(
                artifact_id="stpa-control-structure",
                schema_version="stpa-control-structure-v1",
                semantic_digest="3" * 64,
            ),
            ArtifactPin(
                artifact_id="ica-enumeration",
                schema_version="ica-enumeration-v1",
                semantic_digest="4" * 64,
            ),
        ),
    )
    assert accounting.summary.addressed == 1
    assert accounting.rows[0].ica_ids == (canonical_ica_id,)

    mismatched_route = route.model_copy(
        update={
            "route_id": None,
            "semantic_assessment": ObligationSemanticAssessment(
                mechanism_assessment="plausible_in_system",
                risk_alignment="mismatch",
                mapping_strength="broad_category_expansion",
                mechanism_rationale="The batch-control mechanism exists.",
                risk_alignment_rationale=(
                    "Mass action does not realize restrictions on acquiring data."
                ),
            ),
        }
    )
    mismatched_route = ObligationRoute.model_validate(
        mismatched_route.model_dump(mode="python", exclude={"route_id"})
    )
    mismatched_pair = ObligationIcaConsideration.model_validate(
        {
            **filled.considerations[0].model_dump(mode="python"),
            "pair_id": None,
            "route_id": mismatched_route.route_id,
        }
    )
    mismatched_consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(mismatched_route,),
        final_routes=(mismatched_route,),
    )
    mismatch_accounting = build_obligation_accounting(
        plan=plan,
        consideration=mismatched_consideration,
        ica_considerations=(mismatched_pair,),
        source_pins=accounting.source_pins,
    )
    assert filled_target.icas  # the ordinary STPA finding is retained
    assert mismatch_accounting.summary.addressed == 0
    assert mismatch_accounting.summary.unresolved == 1
    assert mismatch_accounting.rows[0].ica_ids == ()
    assert mismatch_accounting.rows[0].diagnostics[0].code == "risk_pattern_mismatch"

    unsubstantiated_route = route.model_copy(
        update={
            "route_id": None,
            "semantic_assessment": ObligationSemanticAssessment(
                mechanism_assessment="insufficient_evidence",
                risk_alignment="supported",
                mapping_strength="direct_curated_pair",
                mechanism_rationale=(
                    "The selected path governs an adjacent control, not the mechanism."
                ),
                risk_alignment_rationale=(
                    "The mechanism would conceptually realize the reviewed risk."
                ),
            ),
        }
    )
    unsubstantiated_route = ObligationRoute.model_validate(
        unsubstantiated_route.model_dump(mode="python", exclude={"route_id"})
    )
    unsubstantiated_pair = ObligationIcaConsideration.model_validate(
        {
            **filled.considerations[0].model_dump(mode="python"),
            "pair_id": None,
            "route_id": unsubstantiated_route.route_id,
        }
    )
    unsubstantiated_consideration = build_consideration_artifact(
        plan=plan,
        briefs=briefs,
        initial_routes=(unsubstantiated_route,),
        final_routes=(unsubstantiated_route,),
    )
    unsubstantiated_accounting = build_obligation_accounting(
        plan=plan,
        consideration=unsubstantiated_consideration,
        ica_considerations=(unsubstantiated_pair,),
        source_pins=accounting.source_pins,
    )
    assert unsubstantiated_accounting.summary.addressed == 0
    assert unsubstantiated_accounting.summary.unresolved == 1
    assert unsubstantiated_accounting.rows[0].stop_reason == (
        "mechanism_path_unsubstantiated"
    )
    assert unsubstantiated_accounting.rows[0].ica_ids == ()


def test_provider_slot_payload_schema_matches_request_cardinality(tmp_path) -> None:
    """The provider schema requires every slot and every routed pair."""
    slot = create_slots(_control_structure())[0]
    obligation_id = "ob:v1:" + "b" * 64
    route = ObligationRoute(
        obligation_id=obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
    )
    response_formats: list[type] = []

    class CardinalityProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            response_formats.append(kwargs["response_format"])
            filled_slot = SlotIcaDraft(
                slot_id=slot.slot_id,
                is_na=True,
                na_rationale="No finding applies.",
                consideration_results=(
                    ObligationIcaDraft(
                        obligation_handle="R1",
                        disposition="proposed_not_applicable",
                        rationale="The complete structure excludes it.",
                    ),
                ),
            )
            return LLMResult(
                content={"filled_slots": [filled_slot.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        CardinalityProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )
    provider.fill(_provider_slot_request(routed_routes=(route,)))

    schema = response_formats[0].model_json_schema()
    assert schema["properties"]["filled_slots"]["minItems"] == 1
    assert schema["properties"]["filled_slots"]["maxItems"] == 1
    assert "considerations" not in schema["properties"]
    assert (
        "consideration_results" in schema["$defs"]["_SlotProviderDraft"]["properties"]
    )


def test_provider_slot_payload_zero_pairs_requires_empty_considerations(
    tmp_path,
) -> None:
    """A target with no routed pairs accepts exactly zero considerations."""
    response_formats: list[type] = []

    class ZeroPairProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            response_formats.append(kwargs["response_format"])
            slot = create_slots(_control_structure())[0]
            filled_slot = SlotIcaDraft(
                slot_id=slot.slot_id,
                is_na=True,
                na_rationale="No routed concern applies.",
            )
            return LLMResult(
                # Omitted nested considerations exercise the zero-valued default.
                content={"filled_slots": [filled_slot.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        ZeroPairProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )
    result = provider.fill(_provider_slot_request())

    schema = response_formats[0].model_json_schema()
    assert "considerations" not in schema["properties"]
    assert (
        "consideration_results" in schema["$defs"]["_SlotProviderDraft"]["properties"]
    )
    assert result.considerations == ()


def test_provider_slot_payload_retries_on_exact_pair_key_mismatch(tmp_path) -> None:
    """A pair-key mismatch uses the bounded provider validation retry."""
    slot = create_slots(_control_structure())[0]
    obligation_id = "ob:v1:" + "c" * 64
    route = ObligationRoute(
        obligation_id=obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("provider-route",),
    )
    calls = 0

    class PairKeyProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            nonlocal calls
            calls += 1
            filled_slot = SlotIcaDraft(
                slot_id=slot.slot_id,
                is_na=True,
                na_rationale="No finding applies.",
                consideration_results=(
                    ObligationIcaDraft(
                        obligation_handle="R1" if calls == 2 else "R9",
                        disposition="proposed_not_applicable",
                        rationale="The complete structure excludes it.",
                    ),
                ),
            )
            return LLMResult(
                content={"filled_slots": [filled_slot.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        PairKeyProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )
    result = provider.fill(
        _provider_slot_request(routed_routes=(route,), validation_retries=1)
    )

    assert calls == 2
    assert result.considerations[0].route_id == route.route_id
    assert result.provider_calls == 2


def test_provider_slot_response_reports_one_call_without_a_retry(tmp_path) -> None:
    slot = create_slots(_control_structure())[0]

    class OneCallProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            filled_slot = SlotIcaDraft(
                slot_id=slot.slot_id,
                is_na=True,
                na_rationale="The slot is not applicable to this structure.",
            )
            return LLMResult(
                content={"filled_slots": [filled_slot.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        OneCallProvider(), run_dir=tmp_path, controls=_controls()
    )

    assert provider.fill(_provider_slot_request()).provider_calls == 1


@pytest.mark.parametrize(
    ("response_type", "fields"),
    [
        (StructuralRoutingResponse, {}),
        (StructuralRevisionResponse, {"draft": RevisionDraft()}),
        (SynthesisSlotResponse, {}),
    ],
)
def test_provider_responses_report_every_sent_request(response_type, fields) -> None:
    def response(**changes):
        return response_type(request_digest="a" * 64, **fields, **changes)

    assert response(adapter_kind="provider", provider_calls=3).provider_calls == 3
    assert response(adapter_kind="fake").provider_calls == 0
    with pytest.raises(ValueError, match="at least one provider call"):
        response(adapter_kind="provider", provider_calls=0)
    with pytest.raises(ValueError, match="fake adapter"):
        response(adapter_kind="fake", provider_calls=1)


@pytest.mark.parametrize(
    ("response_type", "fields"),
    [
        (StructuralRoutingResponse, {}),
        (StructuralRevisionResponse, {"draft": RevisionDraft()}),
        (SynthesisSlotResponse, {}),
    ],
)
def test_provider_responses_require_an_explicit_adapter_kind(
    response_type, fields
) -> None:
    with pytest.raises(ValueError, match="adapter_kind"):
        response_type(request_digest="a" * 64, **fields)


@pytest.mark.parametrize(
    ("response_type", "fields"),
    [
        (StructuralRoutingResponse, {}),
        (StructuralRevisionResponse, {"draft": RevisionDraft()}),
        (SynthesisSlotResponse, {}),
    ],
)
def test_provider_responses_carry_one_request_count(response_type, fields) -> None:
    """provider_calls is the only request counter; network_calls is gone."""
    response = response_type(request_digest="a" * 64, adapter_kind="fake", **fields)

    assert "network_calls" not in response_type.model_fields
    assert "network_calls" not in response.model_dump(mode="json")
    with pytest.raises(ValueError, match="network_calls"):
        response_type(
            request_digest="a" * 64, adapter_kind="fake", **fields, network_calls=0
        )


def test_provider_slot_stage_uses_bounded_completion_cap(tmp_path) -> None:
    """Slot filling reserves enough bounded output for all target/pair rows."""
    caps: list[int | None] = []

    class NAPprovider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            caps.append(kwargs.get("max_completion_tokens"))
            slot = create_slots(_control_structure())[0]
            filled_slot = SlotIcaDraft(
                slot_id=slot.slot_id,
                is_na=True,
                na_rationale="The slot is not applicable to this structure.",
            )
            return LLMResult(
                content={"filled_slots": [filled_slot.model_dump(mode="json")]},
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        NAPprovider(),
        run_dir=tmp_path,
        controls=_controls(),
    )
    provider.fill(_provider_slot_request())
    assert caps == [8192]


def test_provider_slot_schema_leads_with_normative_structured_draft(tmp_path) -> None:
    """The model-facing schema exposes only the request-local slot draft."""
    response_formats: list[type] = []

    class DraftProvider:
        model = "fake-stpa"

        def complete(self, **kwargs):
            response_formats.append(kwargs["response_format"])
            slot = create_slots(_control_structure())[0]
            return LLMResult(
                content={
                    "filled_slots": [
                        {
                            "slot_id": slot.slot_id,
                            "is_na": True,
                            "na_rationale": "The complete structure excludes it.",
                            "findings": [],
                            "consideration_results": [],
                        }
                    ]
                },
                prompt_tokens=1,
                completion_tokens=1,
                duration_ms=1,
                system_prompt=kwargs["system_prompt"],
                user_prompt=kwargs["user_prompt"],
            )

    provider = ObligationAwareLLMAdapter(
        DraftProvider(),
        run_dir=tmp_path,
        controls=_controls(),
    )
    provider.fill(_provider_slot_request())

    schema = response_formats[0].model_json_schema()
    assert schema["properties"]["filled_slots"]["items"]["$ref"].endswith(
        "/_SlotProviderDraft"
    )
    assert "considerations" not in schema["properties"]


def test_revision_compiler_requires_new_security_constraint_assignment() -> None:
    """A new security constraint cannot enter the final LA unassigned."""
    with pytest.raises(
        ValueError, match="every new security constraint must be assigned"
    ):
        compile_revision_draft(
            RevisionDraft(
                security_constraints=(
                    DraftSecurityConstraint(
                        handle="new-policy",
                        description="Requests must satisfy the added policy.",
                        related_hazard_ids=("H-1",),
                    ),
                ),
            ),
            baseline_loss_analysis=_loss_analysis(),
            baseline_control_structure=_control_structure(),
        )


def test_revision_compiler_allocates_and_links_every_additive_record() -> None:
    """The deterministic compiler closes all request-local additions."""
    draft = RevisionDraft(
        losses=(
            DraftLoss(
                handle="new-loss",
                description="A new use-case consequence.",
                provenance="use_case",
            ),
        ),
        hazards=(
            DraftHazard(
                handle="new-hazard",
                description="A new unsafe system condition.",
                related_loss_handles=("new-loss",),
            ),
        ),
        security_constraints=(
            DraftSecurityConstraint(
                handle="new-constraint",
                description="The new condition must be controlled.",
                related_hazard_handles=("new-hazard",),
                responsibility_handles=("new-responsibility",),
            ),
        ),
        responsibilities=(
            DraftResponsibility(
                handle="new-responsibility",
                description="Review the new condition.",
                security_constraint_handles=("new-constraint",),
                responsibility_constraints=(
                    DraftResponsibilityConstraint(
                        handle="new-responsibility-constraint",
                        description="The review is required.",
                    ),
                ),
            ),
        ),
        controlled_processes=(
            DraftControlledProcess(
                handle="new-process", description="The reviewed process."
            ),
        ),
        process_model_parts=(
            DraftProcessModelPart(
                handle="new-process-model",
                responsibility_handle="new-responsibility",
                description="State of the reviewed process.",
                feedback_source_type="controlled_process",
                feedback_source_handle="new-process",
            ),
        ),
        control_actions=(
            DraftControlAction(
                handle="new-control-action",
                responsibility_handle="new-responsibility",
                description="Review the process.",
                target_type="controlled_process",
                target_handle="new-process",
            ),
        ),
        feedback_channels=(
            DraftFeedbackChannel(
                handle="new-feedback",
                responsibility_handle="new-responsibility",
                description="Report the process state.",
                updates_handle="new-process-model",
                source_type="controlled_process",
                source_handle="new-process",
            ),
        ),
        coordination_links=(
            DraftCoordinationLink(
                handle="new-link",
                description="Coordinate the review.",
                source_handle="new-responsibility",
                target_id="RESP-1",
                shared_pm_handle="new-process-model",
                mechanism=DraftCoordinationMechanism(
                    handle="new-mechanism",
                    description="Share the review state.",
                    payload="review-state",
                ),
            ),
        ),
    )

    result = compile_revision_draft(
        draft,
        baseline_loss_analysis=_loss_analysis(),
        baseline_control_structure=_control_structure(),
        trigger_gap_ids=("gap-1",),
    )

    assert result.handle_map == {
        "new-control-action": "CA-2-1",
        "new-constraint": "SC-2",
        "new-feedback": "FB-2-1",
        "new-hazard": "H-2",
        "new-link": "CL-1",
        "new-loss": "L-2",
        "new-mechanism": "CM-1",
        "new-process": "CP-2",
        "new-process-model": "PM-2-1",
        "new-responsibility": "RESP-2",
        "new-responsibility-constraint": "RC-2-1",
    }
    assert result.loss_analysis.use_case_losses[-1].loss_id == "L-2"
    assert result.loss_analysis.hazards[-1].related_losses == ["L-2"]
    assert result.loss_analysis.security_constraints[-1].related_hazards == ["H-2"]
    added = result.control_structure.responsibilities[-1]
    assert added.security_constraint_refs == ["SC-2"]
    assert added.responsibility_constraints[-1].rc_id == "RC-2-1"
    assert added.process_model_parts[-1].pm_id == "PM-2-1"
    assert added.control_actions[-1].ca_id == "CA-2-1"
    assert added.feedback_channels[-1].updates == "PM-2-1"
    assert result.control_structure.controlled_processes[-1].cp_id == "CP-2"
    assert result.control_structure.coordination_links[-1].link_id == "CL-1"
    assert sorted(item.concept_type for item in result.delta.additions) == sorted(
        (
            "loss",
            "hazard",
            "constraint",
            "responsibility",
            "responsibility",
            "process_model_part",
            "control_action",
            "feedback_channel",
            "controlled_process",
            "coordination_mechanism",
            "coordination_link",
        )
    )


def test_revision_explicit_rejection_is_distinct_from_technical_failure() -> None:
    """A valid adapter rejection is retained as a domain outcome."""
    gap = MissingStructuralConcept(
        concept_type="responsibility",
        description="A reviewing responsibility is missing.",
        evidence_refs=("review-gap",),
    )

    class RejectingAdapter:
        def revise(self, request):
            return StructuralRevisionResponse(
                adapter_kind="fake",
                status="rejected",
                request_digest=request.semantic_digest,
                draft=RevisionDraft(
                    rationale="No justified additive repair was found."
                ),
            )

    result = revise_structure_once(
        RejectingAdapter(),
        gaps=(gap,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        trigger_obligation_ids=("obligation-1",),
        controls=_controls(),
    )

    assert result.status == "rejected"
    assert result.final_control_structure == result.baseline_control_structure
    assert result.diagnostics == ("No justified additive repair was found.",)
    assert result.call_evidence is not None
    assert result.call_evidence.outcome == "rejected"


@pytest.mark.parametrize(
    ("adapter_kind", "expected_detail"),
    (
        ("provider", "provider/protocol failure"),
        ("protocol", "provider/protocol failure"),
        ("compile", "compile failure"),
    ),
)
def test_revision_failures_are_technical_and_keep_baseline(
    adapter_kind: str, expected_detail: str
) -> None:
    """Provider, protocol, and compiler errors are not domain rejections."""
    gap = MissingStructuralConcept(
        concept_type="responsibility",
        description="A reviewing responsibility is missing.",
        evidence_refs=("review-gap",),
    )

    class FailingAdapter:
        def revise(self, request):
            if adapter_kind == "provider":
                raise RuntimeError("provider timed out")
            if adapter_kind == "protocol":
                return object()
            return StructuralRevisionResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                draft=RevisionDraft(
                    security_constraints=(
                        DraftSecurityConstraint(
                            handle="unassigned",
                            description="An unassigned constraint.",
                            related_hazard_ids=("H-1",),
                        ),
                    ),
                ),
            )

    result = revise_structure_once(
        FailingAdapter(),
        gaps=(gap,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        trigger_obligation_ids=("obligation-1",),
        controls=_controls(),
    )

    assert result.status == "technical_failure"
    assert result.final_loss_analysis == result.baseline_loss_analysis
    assert result.final_control_structure == result.baseline_control_structure
    assert result.diagnostics[0].startswith(expected_detail)
    assert result.call_evidence is not None
    assert result.call_evidence.outcome == "technical_failure"


def test_routing_rejects_unknown_responsibility_reference() -> None:
    """Every route identity namespace is closed, including responsibilities."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    briefs = build_neutral_briefs(plan, (pattern,))

    class BadResponsibilityAdapter:
        def route(self, request, *, correction_feedback=None):
            return StructuralRoutingResponse(
                adapter_kind="fake",
                request_digest=request.semantic_digest,
                routes=(
                    ObligationRoute(
                        obligation_id=briefs[0].obligation_id,
                        disposition="targeted",
                        slot_ids=("RESP-1:CA-1-1:NOT_PROVIDED",),
                        responsibility_ids=("RESP-UNKNOWN",),
                        hazard_ids=("H-1",),
                        constraint_ids=("SC-1",),
                        evidence=("bad-responsibility",),
                    ),
                ),
            )

    result = route_obligations(
        BadResponsibilityAdapter(),
        briefs=briefs,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        slots=create_slots(_control_structure()),
        controls=_controls(),
    )

    assert result.routes[0].disposition == "unresolved"
    assert "responsibility" in result.routes[0].diagnostics[0].detail


def test_pair_hazard_and_constraint_refs_must_match_referenced_ica() -> None:
    """Pair evidence cannot add or omit refs owned by its referenced ICA."""
    slot = create_slots(_control_structure())[0]
    filled = ICASlot(
        slot_id=slot.slot_id,
        responsibility=slot.responsibility,
        coordination_link=slot.coordination_link,
        control_action=slot.control_action,
        uca_type=slot.uca_type,
        is_na=False,
        icas=[
            ICA(
                ica_id=f"{slot.slot_id}:1",
                ica_text="An unsafe action is issued.",
                hazardous_context="The request is unsafe.",
                loss_scenario="The operation is harmed.",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
        ],
    )
    route = ObligationRoute(
        obligation_id="ob:v1:" + "a" * 64,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route",),
    )
    pair = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=slot.slot_id,
        disposition="finding",
        ica_ids=(f"{slot.slot_id}:1",),
        exec_candidate_ids=(
            candidate_id_for(
                slot.responsibility or slot.coordination_link,
                slot.control_action,
                slot.uca_type,
            ),
        ),
        hazard_ids=("H-1", "H-extra"),
        constraint_ids=("SC-1",),
        evidence=("pair",),
    )

    with pytest.raises(ValueError, match="hazards must exactly match"):
        _validate_pair(pair, route, slot, {slot.slot_id: filled})


def test_slot_adapter_failure_becomes_request_local_unresolved_evidence() -> None:
    """A target timeout fills its slots with explicit unresolved evidence."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    briefs = build_neutral_briefs(plan, (pattern,))
    target_slot = create_slots(_control_structure())[0]
    route = ObligationRoute(
        obligation_id=briefs[0].obligation_id,
        disposition="targeted",
        slot_ids=(target_slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route",),
    )

    class TimeoutAdapter:
        def fill(self, request):
            raise TimeoutError("slot deadline expired")

    result = fill_synthesis_slots(
        TimeoutAdapter(),
        briefs=briefs,
        routes=(route,),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
        controls=_controls(),
    )

    assert len(result.ica_enumeration.slots) == 4
    provider_slots = [
        slot
        for slot in result.ica_enumeration.slots
        if slot.uca_type.value != "WRONG_DURATION"
    ]
    assert all(not slot.is_na and slot.unresolved_reason for slot in provider_slots)
    assert [pair.disposition for pair in result.considerations] == ["unresolved"]
    assert result.considerations[0].model_call_refs == ("stpa-slot:RESP-1:part-2",)
    assert any(
        item.code == "slot_response_unresolved" for item in result.result.diagnostics
    )


def test_revision_context_relates_loss_gaps_to_loss_records_and_resolved_evidence() -> (
    None
):
    loss_gap = MissingStructuralConcept(
        concept_type="hazard",
        description="A hazard for unsafe acceptance is missing.",
        evidence_refs=("CA-1-1", "unresolved-observation"),
    )
    structure_gap = MissingStructuralConcept(
        concept_type="feedback_channel",
        description="A feedback channel is missing.",
        evidence_refs=("SC-1",),
    )

    context = project_revision_context(
        gaps=(loss_gap, structure_gap),
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
    )

    related = {
        gap.expected_concept_kind: [item.id for item in gap.related_existing_context]
        for gap in context.gaps
    }
    assert related["hazard"] == ["CA-1-1", "H-1", "L-1", "SC-1"]
    assert related["feedback_channel"] == [
        "CA-1-1",
        "CP-1",
        "FB-1-1",
        "PM-1-1",
        "RC-1-1",
        "RESP-1",
    ]


def test_obligation_prompt_audit_reports_each_contract_defect() -> None:

    untyped = audit_prompt_contract(
        {"semantic_digest": "leak"},
        system_prompt="Answer in prose.",
        user_prompt="Read /Users/someone/file and the raw mapping.",
        opaque_handles=("handle-1",),
    )
    assert untyped.view_type == "dict"
    assert not untyped.valid
    assert untyped.issues == (
        "prompt view is not a closed typed model",
        "absolute local path appears in rendered prompt",
        "raw mapping payload appears in rendered prompt",
        "opaque handles are not marked copy-only",
        "requested JSON output schema is absent from system prompt",
    )

    clean = audit_prompt_contract(
        PromptReference(id="RESP-1", description="Validate requests."),
        system_prompt="Return JSON.",
        user_prompt="Copy each handle unchanged.",
        stage="fixture",
        opaque_handles=("handle-1",),
    )
    assert clean.valid
    assert clean.issues == ()
    assert clean.view_type == "PromptReference"
    assert clean.prompt_digest


def test_obligation_prompt_audit_reports_prohibited_typed_fields() -> None:
    class Leaky(BaseModel):
        plan_digest: str
        nested: dict[str, str]

    audit = audit_prompt_contract(
        Leaky(plan_digest="x", nested={"scores": "y"}),
        system_prompt="Return JSON.",
    )

    assert audit.view_type == "Leaky"
    assert audit.issues == (
        "prohibited prompt field leaked: plan_digest",
        "prohibited prompt field leaked: scores",
    )


@pytest.mark.parametrize(
    ("target", "message"),
    (
        ({"target_id": "CP-1"}, "target requires a reference type"),
        (
            {
                "target_type": "controlled_process",
                "target_id": "CP-1",
                "target_handle": "new-process",
            },
            "cannot specify both ID and handle",
        ),
        ({"target_type": "controlled_process"}, "requires an ID or handle"),
        (
            {"target_type": "responsibility", "target_id": "RESP-9"},
            "unknown responsibility 'RESP-9'",
        ),
        (
            {"target_type": "controlled_process", "target_id": "CP-9"},
            "unknown controlled process 'CP-9'",
        ),
    ),
)
def test_revision_compiler_rejects_unresolvable_control_action_targets(
    target: dict, message: str
) -> None:
    draft = RevisionDraft(
        control_actions=(
            DraftControlAction(
                handle="new-control-action",
                responsibility_id="RESP-1",
                description="Escalate the request.",
                **target,
            ),
        ),
    )

    with pytest.raises(ValueError, match=message):
        compile_revision_draft(
            draft,
            baseline_loss_analysis=_loss_analysis(),
            baseline_control_structure=_control_structure(),
        )


def test_revision_compiler_resolves_responsibility_control_action_target() -> None:
    draft = RevisionDraft(
        control_actions=(
            DraftControlAction(
                handle="new-control-action",
                responsibility_id="RESP-1",
                description="Escalate the request.",
                target_type="responsibility",
                target_id="RESP-1",
            ),
        ),
    )

    result = compile_revision_draft(
        draft,
        baseline_loss_analysis=_loss_analysis(),
        baseline_control_structure=_control_structure(),
    )

    added = result.control_structure.responsibilities[0].control_actions[-1]
    assert added.target == ElementRef(type=ReferenceType.responsibility, id="RESP-1")


def _targeted_route_for(slot_id: str) -> ObligationRoute:
    return ObligationRoute(
        obligation_id="ob:v1:" + "1" * 64,
        disposition="targeted",
        slot_ids=(slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence=("route evidence",),
    )


@pytest.mark.parametrize(
    ("slot_fields", "message"),
    (
        (
            {"responsibility": "RESP-9", "control_action": "CA-1-1"},
            "unknown owning responsibility RESP-9",
        ),
        (
            {"responsibility": "RESP-1", "control_action": "CA-9-9"},
            "action CA-9-9 is not owned by responsibility RESP-1",
        ),
        (
            {"coordination_link": "CL-9", "control_action": "CM-9"},
            "unknown coordination link CL-9",
        ),
        ({"control_action": "CA-1-1"}, "has no owner or coordination path"),
    ),
)
def test_targeted_route_requires_a_slot_path_proven_by_the_structure(
    slot_fields: dict, message: str
) -> None:

    slot = SlotPlaceholder(
        slot_id="SLOT-X", uca_type=UCAType.not_provided, **slot_fields
    )
    route = _targeted_route_for("SLOT-X")
    references = _reference_sets(_control_structure(), _loss_analysis(), (slot,))

    with pytest.raises(ValueError, match=message):
        _validate_route(
            route,
            route.obligation_id,
            references,
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            slots=(slot,),
        )


def test_targeted_route_rejects_an_action_without_a_process_target() -> None:

    structure = _control_structure()
    responsibility = structure.responsibilities[0]
    retargeted = responsibility.model_copy(
        update={
            "control_actions": [
                responsibility.control_actions[0].model_copy(
                    update={
                        "target": ElementRef(
                            type=ReferenceType.responsibility, id="RESP-1"
                        )
                    }
                )
            ]
        }
    )
    structure = structure.model_copy(update={"responsibilities": [retargeted]})
    slot = SlotPlaceholder(
        slot_id="SLOT-X",
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type=UCAType.not_provided,
    )
    route = _targeted_route_for("SLOT-X")
    references = _reference_sets(structure, _loss_analysis(), (slot,))

    with pytest.raises(ValueError, match="has no controlled-process target"):
        _validate_route(
            route,
            route.obligation_id,
            references,
            loss_analysis=_loss_analysis(),
            control_structure=structure,
            slots=(slot,),
        )


@pytest.mark.parametrize(
    ("disposition", "indexes", "message"),
    [
        ("finding", (-1,), "must be non-negative"),
        ("finding", (0, 0), "must be unique"),
        ("finding", (), "requires finding_indexes"),
        ("unresolved", (0,), "may retain finding_indexes"),
    ],
)
def test_obligation_ica_draft_rejects_inconsistent_finding_indexes(
    disposition, indexes, message
):
    with pytest.raises(ValueError, match=message):
        ObligationIcaDraft(
            obligation_handle="OBL-1",
            disposition=disposition,
            finding_indexes=indexes,
            rationale="why",
        )


@pytest.mark.parametrize(
    ("control_updates", "configured", "client_attrs", "expected"),
    [
        ({"context_window": 9000, "safety_margin": 7}, None, {}, (9000, 7)),
        ({}, (8000, 11), {"context_window": 1}, (8000, 11)),
        ({"context_window": 8000}, None, {"safety_margin": 13}, (8000, 13)),
        ({}, None, {"context_window": 7000}, (7000, None)),
        ({}, None, {"model_context_window": 6000}, (6000, None)),
        ({}, None, {}, None),
    ],
)
def test_prompt_budget_resolves_context_window_and_margin_by_precedence(
    control_updates, configured, client_attrs, expected
) -> None:

    configured_budget = (
        PromptBudget(
            context_window=configured[0],
            maximum_completion_tokens=1,
            safety_margin=configured[1],
        )
        if configured
        else None
    )

    budget = resolve_prompt_budget(
        SimpleNamespace(**client_attrs),
        _controls().model_copy(update=control_updates),
        configured_budget,
        maximum_completion_tokens=500,
    )

    if expected is None:
        assert budget is None
    else:
        assert (budget.context_window, budget.maximum_completion_tokens) == (
            expected[0],
            500,
        )
        assert budget.safety_margin == (
            expected[1] or max(1_024, -(-expected[0] // 10))
        )


@pytest.mark.parametrize(
    ("which", "update", "error", "message"),
    [
        ("plan", None, TypeError, "plan must be"),
        ("row", None, TypeError, "row must be"),
        (
            "row_update",
            {"scope_disposition": "not_applicable"},
            ValueError,
            "applicable",
        ),
        ("row_update", {"attack_pattern_id": "other"}, ValueError, "pattern does not"),
        (
            "row_update",
            {"attack_pattern_semantic_digest": "0" * 64},
            ValueError,
            "digest does not",
        ),
    ],
)
def test_build_neutral_brief_rejects_mismatched_inputs(which, update, error, message):
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    plan = make_plan()
    row = plan.obligations[0]
    if which == "plan":
        plan = object()
    elif which == "row":
        row = object()
    else:
        row = row.model_copy(update=update)

    with pytest.raises(error, match=message):
        build_neutral_brief(plan, row, pattern)


@pytest.mark.parametrize(
    ("max_batch_size", "use_foreign", "use_duplicate", "error", "message"),
    [
        ("2", False, False, TypeError, "must be an integer"),
        (0, False, False, ValueError, "must be positive"),
        (2, True, False, TypeError, "NeutralObligationBrief values"),
        (2, False, True, ValueError, "unique obligation IDs"),
    ],
)
def test_create_obligation_batches_rejects_invalid_inputs(
    max_batch_size, use_foreign, use_duplicate, error, message
):
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    briefs = build_neutral_briefs(make_plan(), (pattern,))
    if use_foreign:
        briefs = (SimpleNamespace(obligation_id="x"),)
    elif use_duplicate:
        briefs = (briefs[0], briefs[0])

    with pytest.raises(error, match=message):
        create_obligation_batches(briefs, max_batch_size)


@pytest.mark.parametrize(
    ("update", "message"),
    [
        ({"route_id": "route:v1:other"}, "bound to another route"),
        ({"obligation_id": "ob:v1:other"}, "bound to another route"),
        ({"slot_id": "SLOT-OTHER"}, "bound to another slot"),
        ({"ica_ids": ("ICA-1",)}, "cannot retain findings"),
    ],
)
def test_validate_pair_rejects_inconsistent_pair_evidence(update, message) -> None:
    slot = create_slots(_control_structure())[0]
    route = _targeted_route_for(slot.slot_id)
    pair = ObligationIcaConsideration(
        route_id=route.route_id,
        obligation_id=route.obligation_id,
        slot_id=slot.slot_id,
        disposition="unresolved",
        evidence=("pair",),
    )

    assert _validate_pair(pair, route, slot, {}) is pair
    with pytest.raises(ValueError, match=message):
        _validate_pair(pair.model_copy(update=update), route, slot, {})


@pytest.mark.parametrize("shape", ["typed", "mapping", "sequence", "unsupported"])
def test_typed_response_accepts_only_the_typed_slot_response(shape) -> None:
    request = _provider_slot_request()
    fallback = _fallback_slot(request.slots[0], "unresolved")
    typed = SynthesisSlotResponse(
        adapter_kind="fake",
        request_digest=request.semantic_digest,
        filled_slots=(fallback,),
    )
    raw = {
        "typed": typed,
        "mapping": typed.model_dump(mode="json"),
        "sequence": [fallback],
        "unsupported": "not a response",
    }[shape]

    if shape != "typed":
        with pytest.raises(TypeError, match="unsupported response"):
            _typed_response(raw)
        return
    assert _typed_response(raw) is typed
