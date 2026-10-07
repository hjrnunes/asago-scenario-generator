"""Focused contracts for independent final-ICA semantic verification."""

import pytest

from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    IcaConstraintContext,
    IcaHazardContext,
    IcaHazardVerificationBatch,
    IcaHazardVerificationCorrection,
    IcaHazardVerificationRecord,
    IcaHazardVerificationRequest,
    IcaHazardVerificationVerdict,
    IcaLossContext,
    build_ica_hazard_verification_request,
    filter_ica_considerations,
    verify_final_ica_batch,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from tests.helpers.request_dispatch import dispatch_requests
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _routing_provider_payload_type,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    CoordinationLink,
    CoordinationMechanism,
    ControlledProcess,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from pathlib import Path
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.system_model import control_structure


def _request() -> IcaHazardVerificationRequest:
    return IcaHazardVerificationRequest(
        slot_id="RESP-1:CA-1:INCORRECT",
        ica_id="RESP-1:CA-1:INCORRECT:1",
        responsibility_id="RESP-1",
        responsibility_description="The controller maintains the release gate.",
        control_action_id="CA-1",
        control_action_description="Approve a release for the controlled process.",
        uca_type="INCORRECT",
        uca_definition="The control action is provided in an unsafe form.",
        deviation="Approve a release without checking the release gate.",
        hazardous_context="The release gate is not satisfied.",
        loss_consequence="An unsafe release reaches the production process.",
        hazards=(
            IcaHazardContext(
                hazard_id="H-1",
                description="An unsafe release is accepted.",
                related_loss_ids=("L-1",),
            ),
        ),
        constraints=(
            IcaConstraintContext(
                constraint_id="SC-1",
                description="The release gate must be satisfied before approval.",
                related_hazard_ids=("H-1",),
            ),
        ),
        losses=(
            IcaLossContext(loss_id="L-1", description="Production integrity is lost."),
        ),
    )


def test_verification_request_is_closed_immutable_and_content_addressed() -> None:
    request = _request()

    assert request.semantic_digest == request.compute_semantic_digest()
    with pytest.raises((TypeError, ValueError)):
        request.deviation = "changed"
    with pytest.raises(ValueError, match="semantic digest"):
        IcaHazardVerificationRequest.model_validate(
            {**request.model_dump(mode="python"), "semantic_digest": "0" * 64}
        )


@pytest.mark.parametrize(
    ("field", "other_name"),
    [
        ("control_action_id", "action_id"),
        ("control_action_description", "action_description"),
        ("action_recipient", "control_action_recipient"),
        ("action_direction", "control_action_direction"),
        ("action_effect_kind", "control_action_effect_kind"),
        ("uca_definition", "uca_category_definition"),
        ("loss_consequence", "loss_scenario"),
        ("hazards", "selected_hazards"),
        ("constraints", "selected_constraints"),
        ("losses", "selected_losses"),
    ],
)
def test_verification_request_accepts_only_field_names(field, other_name) -> None:
    payload = _request().model_dump(mode="python")
    payload[other_name] = payload.pop(field)

    with pytest.raises(ValueError):
        IcaHazardVerificationRequest.model_validate(payload)


def test_verification_verdict_accepts_only_the_verdict_key() -> None:
    request = _request()

    with pytest.raises(ValueError):
        IcaHazardVerificationVerdict.model_validate(
            {
                "ica_id": request.ica_id,
                "request_digest": request.semantic_digest,
                "decision": "supported",
                "rationale": "The supplied path is complete.",
            }
        )


def test_verification_batch_retains_attempts_and_exact_counts() -> None:
    request = _request()
    verdict = IcaHazardVerificationVerdict(
        ica_id=request.ica_id,
        request_digest=request.semantic_digest,
        verdict="supported",
        rationale="The supplied action, hazard, constraint, and loss form one path.",
    )
    record = IcaHazardVerificationRecord(
        ica_id=request.ica_id,
        slot_id=request.slot_id,
        request=request,
        attempts=(
            {
                "attempt": 1,
                "request_digest": request.semantic_digest,
                "verdict": verdict,
                "provider_status": "semantic_verdict",
            },
        ),
        final_verdict=verdict,
    )
    batch = IcaHazardVerificationBatch(
        batch_id="ica-verification-1",
        records=(record,),
    )

    assert batch.supported_count == 1
    assert batch.unsupported_count == 0
    assert batch.semantic_digest == batch.compute_semantic_digest()


def test_verification_prompt_is_stpa_only_and_omits_provenance() -> None:
    system, user = build_ica_hazard_verification_prompts((_request(),))
    rendered = f"{system}\n{user}"

    assert "mapping_strength" not in rendered
    assert "taxonomy" not in rendered.lower()
    assert "capability" not in rendered.lower()
    assert "mechanism" not in rendered.lower()
    assert "RESP-1" in rendered
    assert "H-1" in rendered
    assert "SC-1" in rendered
    assert "L-1" in rendered


def test_routing_provider_wire_does_not_expose_mapping_strength() -> None:
    assessment = _routing_provider_payload_type(1).model_json_schema()["$defs"][
        "_RoutingProviderSemanticAssessment"
    ]
    assert "mapping_strength" not in assessment.get("properties", {})


def test_verification_prompt_explains_conditional_and_alternative_controls() -> None:
    system, _ = build_ica_hazard_verification_prompts((_request(),))

    assert '"if A, require B"' in system
    assert "supervisor signs OR an automated check passes" in system
    assert "missing supervisor sign-off alone" in system
    assert "unspecified specialist" in system
    assert "`insufficient_evidence`, not a repaired story" in system


def test_verification_request_projects_action_recipient_and_direction() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    action = ControlAction.model_validate(
        {
            **control_structure.responsibilities[0].control_actions[0].model_dump(),
            "effect_kind": "model_output",
        }
    )
    responsibility = control_structure.responsibilities[0].model_copy(
        update={"control_actions": [action]}
    )
    control_structure = control_structure.model_copy(
        update={"responsibilities": [responsibility]}
    )

    request = build_ica_hazard_verification_request(
        enumeration.slots[0].icas[0],
        enumeration.slots[0],
        loss_analysis,
        control_structure,
    )

    assert request.action_recipient == "Production"
    assert request.action_direction == "output"
    assert request.action_effect_kind == "model_output"


def test_verification_prompt_compares_provider_input_with_customer_output() -> None:
    base = _request().model_dump(mode="python", exclude={"semantic_digest"})
    negative_constraint = {
        **base["constraints"][0],
        "description": "Send the record to a storage provider for processing.",
    }
    negative_payload = {
        **base,
        "constraints": (negative_constraint,),
        "action_recipient": "the borrowing member",
        "action_direction": "output",
        "action_effect_kind": "model_output",
    }
    positive_constraint = {
        **negative_constraint,
        "description": "Show the record to the borrowing member.",
    }
    positive_payload = {
        **negative_payload,
        "constraints": (positive_constraint,),
    }
    negative = IcaHazardVerificationRequest.model_validate(negative_payload)
    positive = IcaHazardVerificationRequest.model_validate(positive_payload)

    system, user = build_ica_hazard_verification_prompts((negative, positive))

    assert "provider (provider input)" in system
    assert "customer (customer output)" in system
    assert "different_action" in system
    assert "action_recipient: the borrowing member" in user
    assert "action_direction: output" in user
    assert "Send the record to a storage provider" in user
    assert "Show the record to the borrowing member" in user


def test_loss_method_preserves_triggers_without_inventing_measurement() -> None:

    loader = TemplateLoader(Path(control_structure.__file__).parent / "prompts")
    for template in ("stage1a_risk_system.j2", "stage1a_gap_system.j2"):
        rendered = loader.render_prompt(template)
        assert (
            "Constraints are requirements, not observations of installed controls"
            in rendered
        )
        assert "identity-confidence score falls below 0.8" in rendered
        assert "unless that score and threshold were supplied" in rendered


def _stpa_inputs() -> tuple[ICAEnumeration, LossAnalysis, ControlStructure]:
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="Integrity loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(
                hazard_id="H-1", description="Unsafe release", related_losses=["L-1"]
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Gate releases",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Release controller",
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Approve release",
                        target={"type": "controlled_process", "id": "CP-1"},
                    )
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Production")
        ],
    )
    slot = ICASlot(
        slot_id="RESP-1:CA-1-1:INCORRECT",
        responsibility="RESP-1",
        control_action="CA-1-1",
        uca_type="INCORRECT",
        is_na=False,
        icas=[
            ICA(
                ica_id="RESP-1:CA-1-1:INCORRECT:1",
                ica_text="Approve without the gate",
                hazardous_context="The gate is unsatisfied",
                loss_scenario="Integrity is lost",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            ),
            ICA(
                ica_id="RESP-1:CA-1-1:INCORRECT:2",
                ica_text="Approve with the gate",
                hazardous_context="The gate is unsatisfied",
                loss_scenario="Integrity is lost",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            ),
        ],
    )
    return ICAEnumeration(slots=[slot]), loss_analysis, control_structure


def test_request_scopes_multi_hazard_constraint_to_ica_hazard() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    loss_analysis = loss_analysis.model_copy(
        update={
            "hazards": [
                *loss_analysis.hazards,
                Hazard(
                    hazard_id="H-2", description="Other hazard", related_losses=["L-1"]
                ),
            ],
            "security_constraints": [
                SecurityConstraint(
                    constraint_id="SC-1",
                    rule="Gate releases",
                    related_hazards=["H-1", "H-2"],
                )
            ],
        }
    )

    request = build_ica_hazard_verification_request(
        enumeration.slots[0].icas[0],
        enumeration.slots[0],
        loss_analysis,
        control_structure,
    )

    assert [item.hazard_id for item in request.hazards] == ["H-1"]
    assert [item.related_hazard_ids for item in request.constraints] == [("H-1",)]


def test_request_rejects_unknown_hazard_in_constraint_context() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    invalid_loss_analysis = LossAnalysis.model_construct(
        risk_card_losses=loss_analysis.risk_card_losses,
        use_case_losses=loss_analysis.use_case_losses,
        hazards=loss_analysis.hazards,
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="Gate releases",
                related_hazards=["H-1", "H-missing"],
            )
        ],
    )

    with pytest.raises(ValueError, match="unknown hazard.*H-missing"):
        build_ica_hazard_verification_request(
            enumeration.slots[0].icas[0],
            enumeration.slots[0],
            invalid_loss_analysis,
            control_structure,
        )


def test_verification_batches_are_isolated_by_responsibility() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    responsibility = Responsibility(
        resp_id="RESP-2",
        description="Independent release controller",
        control_actions=[
            ControlAction(
                ca_id="CA-2-1",
                description="Approve independent release",
                target={"type": "controlled_process", "id": "CP-1"},
            )
        ],
    )
    second_slot = ICASlot(
        slot_id="RESP-2:CA-2-1:INCORRECT",
        responsibility="RESP-2",
        control_action="CA-2-1",
        uca_type="INCORRECT",
        is_na=False,
        icas=[
            ICA(
                ica_id="RESP-2:CA-2-1:INCORRECT:1",
                ica_text="Approve the independent release without the gate",
                hazardous_context="The gate is unsatisfied",
                loss_scenario="Integrity is lost",
                related_hazards=["H-1"],
                related_constraints=["SC-1"],
            )
        ],
    )
    enumeration = ICAEnumeration(slots=[*enumeration.slots, second_slot])
    control_structure = control_structure.model_copy(
        update={
            "responsibilities": [
                *control_structure.responsibilities,
                responsibility,
            ]
        }
    )

    class IsolatedProvider:
        def __init__(self) -> None:
            self.calls: list[tuple[str, ...]] = []

        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            ids = tuple(request.responsibility_id for request in requests)
            self.calls.append(ids)
            if ids == ("RESP-1", "RESP-1"):
                raise RuntimeError("first responsibility is unavailable")
            return [
                {
                    "ica_id": request.ica_id,
                    "verdict": "supported",
                    "rationale": "The supplied STPA path is coherent.",
                }
                for request in requests
            ]

    adapter = IsolatedProvider()
    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    assert adapter.calls == [("RESP-1", "RESP-1"), ("RESP-2",)]
    assert batch.provider_failure_count == 2
    assert batch.supported_count == 1
    assert len(filtered.slots) == 2
    assert len(filtered.slots[0].icas) == 2
    assert len(filtered.slots[1].icas) == 1


class _CorrectionFake:
    def __init__(self) -> None:
        self.calls: list[bool] = []

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        self.calls.append(bool(correction_feedback))
        return [
            {
                "ica_id": request.ica_id,
                "verdict": (
                    "supported"
                    if correction_feedback or request.ica_id.endswith(":2")
                    else "insufficient_evidence"
                ),
                "rationale": "The supplied STPA path is coherent.",
            }
            for request in requests
        ]

    def correct_ica_hazard(self, request, verdict):
        return IcaHazardVerificationCorrection(
            ica_id=request.ica_id,
            deviation=request.deviation + " after the gate check",
            rationale="Add the missing typed gate check.",
        )


def test_unsupported_ica_gets_one_correction_and_siblings_continue() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    adapter = _CorrectionFake()

    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    assert adapter.calls == [False, True]
    assert batch.supported_count == 2
    assert batch.unsupported_count == 0
    corrected = next(record for record in batch.records if record.ica_id.endswith(":1"))
    assert corrected.corrected_request is not None
    assert corrected.attempts[0].request_digest != corrected.attempts[1].request_digest
    assert len(filtered.slots[0].icas) == 2
    assert filtered.slots[0].icas[0].ica_text.endswith("after the gate check")


class _SendingCorrectionFake(_CorrectionFake):
    """Sends 1 request per initial batch, 1 per correction, 2 per re-verification."""

    def __init__(self, run_dir) -> None:
        super().__init__()
        self.run_dir = run_dir

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        dispatch_requests(self.run_dir, 2 if correction_feedback else 1)
        return super().verify_ica_hazards(
            requests, correction_feedback=correction_feedback
        )

    def correct_ica_hazard(self, request, verdict):
        dispatch_requests(self.run_dir, 1)
        return super().correct_ica_hazard(request, verdict)


def _sent_by_call(batch) -> dict[str, int]:
    return {
        item.call_id.removeprefix("ica-hazard-verification:"): item.attempt_count
        for item in batch.call_evidence
    }


def test_call_evidence_counts_the_requests_each_verification_call_sent(
    tmp_path,
) -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()

    _, batch = verify_final_ica_batch(
        _SendingCorrectionFake(tmp_path),
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    sent = _sent_by_call(batch)
    corrected = next(
        record.ica_id for record in batch.records if record.corrected_request
    )
    assert sent == {
        "initial:1": 1,
        f"correction:{corrected}": 1,
        "correction-verification:1": 2,
    }


def test_call_evidence_of_an_adapter_that_sends_nothing_counts_zero() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()

    _, batch = verify_final_ica_batch(
        _CorrectionFake(),
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    assert batch.call_evidence
    assert set(_sent_by_call(batch).values()) == {0}


def test_a_missing_verification_adapter_sends_no_request() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()

    _, batch = verify_final_ica_batch(
        object(),
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    assert _sent_by_call(batch) == {"initial": 0}


class _ExhaustedFake:
    def __init__(self) -> None:
        self.calls = 0

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        self.calls += 1
        return [
            {
                "ica_id": request.ica_id,
                "verdict": "contradictory",
                "rationale": "The selected facts conflict.",
            }
            for request in requests
        ]


def test_exhausted_correction_excludes_only_affected_ica() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    adapter = _ExhaustedFake()
    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    assert batch.unsupported_count == 2
    assert batch.supported_count == 0
    assert adapter.calls == 1
    assert filtered.slots[0].is_na is False
    assert filtered.slots[0].unresolved_reason


def test_incomplete_lineage_excludes_only_unprojectable_ica() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    incomplete = (
        enumeration.slots[0]
        .icas[0]
        .model_copy(update={"related_hazards": ["H-missing"]})
    )
    slot = enumeration.slots[0].model_copy(
        update={"icas": [incomplete, enumeration.slots[0].icas[1]]}
    )
    enumeration = enumeration.model_copy(update={"slots": [slot]})

    class SupportsValidSibling:
        def verify_ica_hazards(self, requests, *, correction_feedback=None):
            return [
                {
                    "ica_id": request.ica_id,
                    "verdict": "supported",
                    "rationale": "The supplied STPA path is coherent.",
                }
                for request in requests
            ]

    filtered, batch = verify_final_ica_batch(
        SupportsValidSibling(),
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    assert batch.incomplete_ica_ids == (incomplete.ica_id,)
    assert batch.supported_count == 1
    assert batch.unsupported_count == 1
    assert [item.ica_id for item in filtered.slots[0].icas] == [
        enumeration.slots[0].icas[1].ica_id
    ]


def _single_ica_inputs() -> tuple[ICAEnumeration, LossAnalysis, ControlStructure]:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    slot = enumeration.slots[0].model_copy(
        update={"icas": [enumeration.slots[0].icas[0]]}
    )
    return (
        enumeration.model_copy(update={"slots": [slot]}),
        loss_analysis,
        control_structure,
    )


def _finding_pair(enumeration: ICAEnumeration) -> ObligationIcaConsideration:
    slot = enumeration.slots[0]
    ica = slot.icas[0]
    return ObligationIcaConsideration(
        route_id="route:ica-verification-test",
        obligation_id="ob:v1:" + "a" * 64,
        slot_id=slot.slot_id,
        disposition="finding",
        ica_ids=(ica.ica_id,),
        exec_candidate_ids=("EXEC:RESP-1:CA-1-1:INCORRECT",),
        hazard_ids=tuple(ica.related_hazards),
        constraint_ids=tuple(ica.related_constraints),
        evidence=("ica-verification:test",),
        rationale="The STPA finding selects the exact ICA.",
    )


class _TerminalCorrectionFake:
    def __init__(self, disposition: str) -> None:
        self.disposition = disposition
        self.verification_calls = 0

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        self.verification_calls += 1
        assert correction_feedback is None
        return [
            {
                "ica_id": request.ica_id,
                "verdict": "contradictory",
                "rationale": "The first semantic judgement does not support the ICA.",
            }
            for request in requests
        ]

    def correct_ica_hazard(self, request, verdict):
        return IcaHazardVerificationCorrection(
            ica_id=request.ica_id,
            disposition=self.disposition,
            rationale="The author supplied an explicit terminal disposition.",
        )


@pytest.mark.parametrize(
    ("disposition", "pair_disposition"),
    (("not_applicable", "proposed_not_applicable"), ("unresolved", "unresolved")),
)
def test_terminal_correction_is_not_reverified_and_retains_typed_outcome(
    disposition: str,
    pair_disposition: str,
) -> None:
    enumeration, loss_analysis, control_structure = _single_ica_inputs()
    adapter = _TerminalCorrectionFake(disposition)

    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    record = batch.records[0]
    assert adapter.verification_calls == 1
    assert record.disposition == disposition
    assert record.final_verdict is None
    assert record.correction is not None
    assert record.correction.disposition == disposition
    assert len(record.attempts) == 1
    assert record.attempts[0].verdict is not None
    if disposition == "unresolved":
        assert filtered.slots[0].is_na is False
        assert filtered.slots[0].unresolved_reason
    else:
        assert filtered.slots[0].is_na is True

    pair = filter_ica_considerations(
        (_finding_pair(enumeration),), batch, enumeration=filtered
    )[0]
    assert pair.disposition == pair_disposition
    assert pair.ica_ids == ()


class _SecondVerificationFailureFake:
    def __init__(self, *, omit_verdict: bool) -> None:
        self.omit_verdict = omit_verdict
        self.verification_calls = 0

    def verify_ica_hazards(self, requests, *, correction_feedback=None):
        self.verification_calls += 1
        if correction_feedback:
            if self.omit_verdict:
                return []
            raise RuntimeError("second verifier unavailable")
        return [
            {
                "ica_id": request.ica_id,
                "verdict": "insufficient_evidence",
                "rationale": "The first semantic judgement needs one correction.",
            }
            for request in requests
        ]

    def correct_ica_hazard(self, request, verdict):
        return IcaHazardVerificationCorrection(
            ica_id=request.ica_id,
            deviation=request.deviation + " with the missing timing fact",
            rationale="Add the missing typed timing fact.",
        )


@pytest.mark.parametrize("omit_verdict", (False, True))
def test_second_verification_failure_keeps_failure_but_not_rejected_ica(
    omit_verdict: bool,
) -> None:
    enumeration, loss_analysis, control_structure = _single_ica_inputs()
    adapter = _SecondVerificationFailureFake(omit_verdict=omit_verdict)

    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )

    record = batch.records[0]
    assert adapter.verification_calls == 2
    assert record.disposition == "provider_failure"
    assert record.final_verdict is None
    assert batch.provider_failure_count == 1
    assert batch.unsupported_count == 0
    assert len(record.attempts) == 2
    assert record.attempts[0].verdict is not None
    assert record.attempts[0].verdict.verdict == "insufficient_evidence"
    assert record.attempts[1].verdict is None
    assert record.attempts[1].provider_status == "protocol_failure"
    assert filtered.slots[0].icas == []
    assert filtered.slots[0].unresolved_reason
    assert not filtered.slots[0].is_na


@pytest.mark.parametrize("correction_fails", (False, True))
def test_failed_or_unchanged_correction_cannot_admit_rejected_finding(
    correction_fails: bool,
) -> None:
    enumeration, loss_analysis, control_structure = _single_ica_inputs()

    class Adapter(_TerminalCorrectionFake):
        def correct_ica_hazard(self, request, verdict):
            if correction_fails:
                raise RuntimeError("correction unavailable")
            return IcaHazardVerificationCorrection(
                ica_id=request.ica_id,
                deviation=request.deviation,
                rationale="Repeating the rejected deviation does not correct it.",
            )

    adapter = Adapter("unresolved")
    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    record = batch.records[0]
    assert adapter.verification_calls == 1
    assert record.disposition == "provider_failure"
    assert record.final_verdict is None
    assert record.attempts[0].verdict.verdict == "contradictory"
    assert batch.provider_failure_count == 1
    assert any(call.outcome == "technical_failure" for call in batch.call_evidence)
    assert filtered.slots[0].icas == []
    assert filtered.slots[0].unresolved_reason
    assert not filtered.slots[0].is_na


def test_untyped_correction_is_a_failure_not_a_coerced_correction() -> None:
    enumeration, loss_analysis, control_structure = _single_ica_inputs()

    class Adapter(_TerminalCorrectionFake):
        def correct_ica_hazard(self, request, verdict):
            return {
                "ica_id": request.ica_id,
                "deviation": "A plausible but untyped corrected deviation.",
                "rationale": "Mappings are not accepted as corrections.",
            }

    adapter = Adapter("unresolved")
    filtered, batch = verify_final_ica_batch(
        adapter,
        enumeration,
        loss_analysis=loss_analysis,
        control_structure=control_structure,
    )
    record = batch.records[0]
    assert adapter.verification_calls == 1
    assert record.disposition == "provider_failure"
    assert any(
        "must return an IcaHazardVerificationCorrection" in item.detail
        for item in batch.diagnostics
    )
    assert filtered.slots[0].icas == []


def _coordination_inputs(
    *, link_source: str = "RESP-1", link_target: str = "RESP-2"
) -> tuple[ICAEnumeration, LossAnalysis, ControlStructure]:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    reviewer = control_structure.responsibilities[0].model_copy(
        update={"resp_id": "RESP-2", "description": "Release reviewer"}
    )
    link = CoordinationLink(
        link_id="CL-1",
        source=link_source,
        target=link_target,
        shared_pm="PM-1-1",
        coordination_mechanism=CoordinationMechanism(
            cm_id="CM-1", description="Release handoff message", payload="release id"
        ),
        description="The controller hands the release to the reviewer.",
    )
    control_structure = control_structure.model_copy(
        update={
            "responsibilities": [
                control_structure.responsibilities[0],
                reviewer,
            ],
            "coordination_links": [link],
        }
    )
    ica = (
        enumeration.slots[0]
        .icas[0]
        .model_copy(update={"ica_id": "CL-1:CM-1:INCORRECT:1"})
    )
    slot = ICASlot(
        slot_id="CL-1:CM-1:INCORRECT",
        coordination_link="CL-1",
        control_action="CM-1",
        action_temporality=None,
        uca_type="INCORRECT",
        is_na=False,
        icas=[ica],
    )
    return ICAEnumeration(slots=[slot]), loss_analysis, control_structure


def test_coordination_slot_projects_the_link_mechanism_as_an_internal_message() -> None:
    enumeration, loss_analysis, control_structure = _coordination_inputs()
    slot = enumeration.slots[0]

    request = build_ica_hazard_verification_request(
        slot.icas[0], slot, loss_analysis, control_structure
    )

    assert request.responsibility_id == "RESP-1"
    assert request.responsibility_description == "Release controller"
    assert request.control_action_id == "CM-1"
    assert request.control_action_description == "Release handoff message"
    assert request.action_recipient == "Release reviewer"
    assert request.action_direction == "internal"
    assert request.action_effect_kind == "agent_message"


def test_coordination_slot_names_the_target_id_when_it_has_no_responsibility() -> None:
    enumeration, loss_analysis, control_structure = _coordination_inputs(
        link_target="RESP-9"
    )
    slot = enumeration.slots[0]

    request = build_ica_hazard_verification_request(
        slot.icas[0], slot, loss_analysis, control_structure
    )

    assert request.action_recipient == "RESP-9"


def test_coordination_slot_with_unknown_link_is_rejected() -> None:
    enumeration, loss_analysis, control_structure = _coordination_inputs()
    slot = enumeration.slots[0].model_copy(update={"coordination_link": "CL-9"})

    with pytest.raises(ValueError, match="unknown coordination link CL-9"):
        build_ica_hazard_verification_request(
            slot.icas[0], slot, loss_analysis, control_structure
        )


def test_coordination_slot_with_unknown_source_is_rejected() -> None:
    enumeration, loss_analysis, control_structure = _coordination_inputs(
        link_source="RESP-9"
    )
    slot = enumeration.slots[0]

    with pytest.raises(ValueError, match="unknown coordination source RESP-9"):
        build_ica_hazard_verification_request(
            slot.icas[0], slot, loss_analysis, control_structure
        )
