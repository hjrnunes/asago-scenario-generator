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
    filter_ica_considerations,
    verify_final_ica_batch,
)
from asago_scenario_generator.models.obligation_consideration import (
    ObligationIcaConsideration,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_ica_hazard_verification_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _routing_provider_payload_type,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
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


def _stpa_inputs() -> tuple[ICAEnumeration, LossAnalysis, ControlStructure]:
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(loss_id="L-1", description="Integrity loss", provenance=LossProvenance.use_case)
        ],
        hazards=[Hazard(hazard_id="H-1", description="Unsafe release", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Gate releases",
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
        controlled_processes=[ControlledProcess(cp_id="CP-1", description="Production")],
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
                    if correction_feedback
                    or request.ica_id.endswith(":2")
                    else "insufficient_evidence"
                ),
                "rationale": "The supplied STPA path is coherent.",
            }
            for request in requests
        ]

    def correct_ica(self, request, verdict):
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
    corrected = next(
        record
        for record in batch.records
        if record.ica_id.endswith(":1")
    )
    assert corrected.corrected_request is not None
    assert corrected.attempts[0].request_digest != corrected.attempts[1].request_digest
    assert len(filtered.slots[0].icas) == 2
    assert filtered.slots[0].icas[0].ica_text.endswith("after the gate check")


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
    assert filtered.slots[0].is_na is True


def test_incomplete_lineage_excludes_only_unprojectable_ica() -> None:
    enumeration, loss_analysis, control_structure = _stpa_inputs()
    incomplete = enumeration.slots[0].icas[0].model_copy(
        update={"related_hazards": ["H-missing"]}
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
    return enumeration.model_copy(update={"slots": [slot]}), loss_analysis, control_structure


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

    def correct_ica(self, request, verdict):
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

    def correct_ica(self, request, verdict):
        return IcaHazardVerificationCorrection(
            ica_id=request.ica_id,
            deviation=request.deviation + " with the missing timing fact",
            rationale="Add the missing typed timing fact.",
        )


@pytest.mark.parametrize("omit_verdict", (False, True))
def test_second_verification_failure_is_provider_failure_without_final_verdict(
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
    assert filtered.slots[0].icas[0].ica_id == enumeration.slots[0].icas[0].ica_id
