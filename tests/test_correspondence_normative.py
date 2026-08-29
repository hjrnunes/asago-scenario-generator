"""Public-seam tests for the normative Task 3 correspondence contract."""

from __future__ import annotations

import json

import pytest
import yaml
from typer.testing import CliRunner

from asago_scenario_generator.cli import app

from asago_scenario_generator.models.correspondence import (
    AcceptedCorrespondenceRelation,
    AdjudicationSet,
    CorrespondenceAdjudication,
    CorrespondenceAuthority,
    CorrespondenceEvidence,
    CorrespondenceSourceArtifacts,
    ObligationAuthorityRecord,
    ProposalProvenance,
    ProposalSet,
    ReconciliationError,
    ReconciliationResult,
    SourceArtifactPins,
    StructuralAuthorityRecord,
    compute_loss_analysis_digest,
    compute_proposal_id,
    compute_relation_id,
)
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.models.system_resource_map import (
    SystemResourceMapValidation,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ResponsibilityConstraint,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICA,
    ICAEnumeration,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from tests.helpers.obligation_factory import make_inputs
from tests.system_resource_map_support import (
    TOOL,
    make_control_structure,
    make_link,
    make_map,
    make_snapshot,
)


OBLIGATION = "ob:v1:" + "1" * 64
RISK = "risk-1"
ATTACK_PATTERN = "AML.T0001"
TAXONOMY_CANDIDATE = "cand:v2:" + "a" * 32
ICA_SLOT = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = ICA_SLOT + ":1"
EXEC = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
CLI_RUNNER = CliRunner()


def _authoritative_artifacts() -> tuple[
    TaxonomyObligationPlan,
    object,
    ControlStructure,
    ICAEnumeration,
    LossAnalysis,
    object,
]:
    inputs = make_inputs()
    plan = plan_taxonomy_obligations(inputs)
    control_payload = make_control_structure().model_dump(mode="python")
    control_payload["responsibilities"][0]["responsibility_constraints"] = [
        ResponsibilityConstraint(rc_id="RC-1-1", description="Bound payments")
    ]
    control = ControlStructure.model_validate(control_payload)
    candidate_resource = next(
        binding.resource_ref.model_dump(mode="json")
        for binding in plan.obligations[0].candidate_records[0].resource_bindings
        if binding.resource_ref.kind == "tool"
    )
    resource_map = make_map(
        make_link(capability_resource_ref=candidate_resource),
        snapshot=inputs.capability_snapshot,
        control=control,
    )
    loss_analysis = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Payment loss",
                provenance=LossProvenance.risk_card,
                source_risk_cards=[plan.obligations[0].risk_ref.risk_id],
            )
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="Hazard", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                description="Constrain payment",
                related_hazards=["H-1"],
            )
        ],
    )
    ica_enumeration = ICAEnumeration(
        slots=[
            ICASlot(
                slot_id=ICA_SLOT,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=[
                    ICA(
                        ica_id=ICA_ID,
                        ica_text="Payment action occurs at the wrong time",
                        hazardous_context="Payment pending",
                        loss_scenario="Payment is lost",
                        related_hazards=["H-1"],
                        related_constraints=["RC-1-1"],
                    )
                ],
            )
        ]
    )
    return (
        plan,
        resource_map,
        control,
        ica_enumeration,
        loss_analysis,
        inputs.capability_snapshot,
    )


def test_authority_from_artifacts_validates_and_projects_exact_path_identities() -> (
    None
):
    plan, resource_map, control, enumeration, loss_analysis, snapshot = (
        _authoritative_artifacts()
    )
    unrelated_link = make_link(
        link_id="srm:v1:unrelated",
        control_structure_ref={"kind": "CP", "id": "CP-1"},
    )
    resource_map = make_map(
        *resource_map.links,
        unrelated_link,
        snapshot=snapshot,
        control=control,
    )

    authority = CorrespondenceAuthority.from_artifacts(
        resource_map, plan, control, enumeration, loss_analysis
    )

    obligation = authority.obligations[0]
    source_row = plan.obligations[0]
    assert obligation.risk_id == source_row.risk_ref.risk_id
    assert obligation.attack_pattern_id == source_row.attack_pattern_id
    assert obligation.taxonomy_candidate_ids == tuple(
        candidate.candidate_id for candidate in source_row.candidate_records
    )
    assert authority.structural_findings[0].resource_link_ids == ("srm:v1:1",)
    assert authority.constraint_ids == ("RC-1-1", "SC-1")
    assert authority.inventory_complete is True


def test_authority_from_artifacts_rejects_substituted_or_invalid_authority() -> None:
    plan, resource_map, control, enumeration, loss_analysis, _ = (
        _authoritative_artifacts()
    )
    other_control = make_control_structure().model_copy(
        update={"controlled_processes": []}
    )
    with pytest.raises(ValueError, match="control.structure digest"):
        CorrespondenceAuthority.from_artifacts(
            resource_map, plan, other_control, enumeration, loss_analysis
        )

    invalid_enumeration = enumeration.model_copy(
        update={
            "slots": [
                enumeration.slots[0].model_copy(
                    update={
                        "icas": [
                            enumeration.slots[0]
                            .icas[0]
                            .model_copy(update={"related_hazards": ["H-UNKNOWN"]})
                        ]
                    }
                )
            ]
        }
    )
    with pytest.raises(ValueError, match="non-existent hazard"):
        CorrespondenceAuthority.from_artifacts(
            resource_map, plan, control, invalid_enumeration, loss_analysis
        )

    unknown_slot = enumeration.model_copy(
        update={
            "slots": [
                enumeration.slots[0].model_copy(
                    update={
                        "slot_id": "RESP-9:CA-9-1:WRONG_TIMING",
                        "responsibility": "RESP-9",
                        "control_action": "CA-9-1",
                        "icas": [
                            enumeration.slots[0]
                            .icas[0]
                            .model_copy(
                                update={"ica_id": "RESP-9:CA-9-1:WRONG_TIMING:1"}
                            )
                        ],
                    }
                )
            ]
        }
    )
    with pytest.raises(ValueError, match="unknown control identities"):
        CorrespondenceAuthority.from_artifacts(
            resource_map, plan, control, unknown_slot, loss_analysis
        )

    with pytest.raises(ValueError, match="semantic_digest"):
        CorrespondenceAuthority.from_artifacts(
            resource_map.model_copy(update={"semantic_digest": "f" * 64}),
            plan,
            control,
            enumeration,
            loss_analysis,
        )
    with pytest.raises(ValueError, match="Digest mismatch"):
        CorrespondenceAuthority.from_artifacts(
            resource_map,
            plan.model_copy(update={"semantic_digest": "f" * 64}),
            control,
            enumeration,
            loss_analysis,
        )


def test_ica_enumeration_pin_is_invariant_to_slot_and_ica_order() -> None:
    plan, resource_map, control, enumeration, loss_analysis, _ = (
        _authoritative_artifacts()
    )
    first_ica = enumeration.slots[0].icas[0]
    second_ica = first_ica.model_copy(
        update={"ica_id": ICA_SLOT + ":2", "ica_text": "Second exact ICA"}
    )
    forward = ICAEnumeration(
        slots=[
            enumeration.slots[0].model_copy(update={"icas": [first_ica, second_ica]})
        ]
    )
    reverse = ICAEnumeration(
        slots=[
            enumeration.slots[0].model_copy(update={"icas": [second_ica, first_ica]})
        ]
    )

    forward_authority = CorrespondenceAuthority.from_artifacts(
        resource_map, plan, control, forward, loss_analysis
    )
    reverse_authority = CorrespondenceAuthority.from_artifacts(
        resource_map, plan, control, reverse, loss_analysis
    )

    assert (
        forward_authority.source_pins.ica_enumeration_digest
        == reverse_authority.source_pins.ica_enumeration_digest
    )


def test_loss_analysis_pin_is_invariant_to_set_like_collection_order() -> None:
    losses = (
        Loss(
            loss_id="L-1",
            description="First loss",
            provenance=LossProvenance.risk_card,
            source_risk_cards=["RISK-2", "RISK-1"],
        ),
        Loss(
            loss_id="L-2",
            description="Second loss",
            provenance=LossProvenance.risk_card,
            source_risk_cards=["RISK-3"],
        ),
    )
    hazards = (
        Hazard(
            hazard_id="H-1",
            description="First hazard",
            related_losses=["L-2", "L-1"],
        ),
        Hazard(
            hazard_id="H-2",
            description="Second hazard",
            related_losses=["L-1"],
        ),
    )
    constraints = (
        SecurityConstraint(
            constraint_id="SC-1",
            description="First constraint",
            related_hazards=["H-2", "H-1"],
        ),
        SecurityConstraint(
            constraint_id="SC-2",
            description="Second constraint",
            related_hazards=["H-1"],
        ),
    )
    forward = LossAnalysis(
        risk_card_losses=list(losses),
        use_case_losses=[],
        hazards=list(hazards),
        security_constraints=list(constraints),
    )
    reverse = LossAnalysis(
        risk_card_losses=[
            losses[1],
            losses[0].model_copy(update={"source_risk_cards": ["RISK-1", "RISK-2"]}),
        ],
        use_case_losses=[],
        hazards=[
            hazards[1],
            hazards[0].model_copy(update={"related_losses": ["L-1", "L-2"]}),
        ],
        security_constraints=[
            constraints[1],
            constraints[0].model_copy(update={"related_hazards": ["H-1", "H-2"]}),
        ],
    )

    assert compute_loss_analysis_digest(forward) == compute_loss_analysis_digest(
        reverse
    )


def _authority(resource_map, *, complete: bool = True) -> CorrespondenceAuthority:
    pins = SourceArtifactPins(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        obligation_plan_semantic_digest="2" * 64,
        control_structure_digest=resource_map.control_structure_digest,
        ica_enumeration_digest="3" * 64,
        loss_analysis_digest="4" * 64,
        taxonomy_version="atlas-v1",
        stpa_version="stpa-v1",
    )
    return CorrespondenceAuthority(
        source_pins=pins,
        obligations=(
            ObligationAuthorityRecord(
                obligation_id=OBLIGATION,
                risk_id=RISK,
                attack_pattern_id=ATTACK_PATTERN,
                taxonomy_candidate_ids=(TAXONOMY_CANDIDATE,),
                candidate_resource_refs=({"kind": "tool", "tool_id": TOOL},),
            ),
        ),
        structural_findings=(
            StructuralAuthorityRecord(
                ica_slot_id=ICA_SLOT,
                ica_id=ICA_ID,
                exec_candidate_id=EXEC,
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                resource_link_ids=("srm:v1:1",),
            ),
        ),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        inventory_complete=complete,
    )


def _validated_map(resource_map, *, snapshot=None, control=None):
    """Return the public validated-map attestation for a test map."""
    result = validate_system_resource_map(
        resource_map,
        snapshot or make_snapshot(),
        control or make_control_structure(),
    )
    assert result.is_valid, result.violations
    return result


def _evidence(resource_map, **overrides):
    authority = _authority(resource_map)
    fields = {
        "obligation_id": OBLIGATION,
        "risk_id": RISK,
        "attack_pattern_id": ATTACK_PATTERN,
        "taxonomy_candidate_ids": (TAXONOMY_CANDIDATE,),
        "ica_slot_id": ICA_SLOT,
        "ica_id": ICA_ID,
        "exec_candidate_id": EXEC,
        "relation_kind": "same_mechanism",
        "resource_link_ids": ("srm:v1:1",),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
        "evidence_source": "exact_id",
        "evidence_refs": ("id:obligation", "id:ica"),
        "confidence": 1.0,
        "evidence_strength": "high",
        "proposer_id": "exact-id-v1",
        "proposer_version": "1",
        "source_pins": authority.source_pins,
        "rationale": "exact reviewed identities",
    }
    fields.update(overrides)
    return CorrespondenceEvidence(**fields)


def _proposal_set(resource_map, *evidence, complete: bool = True) -> ProposalSet:
    authority = _authority(resource_map, complete=complete)
    source = CorrespondenceSourceArtifacts(
        authority=authority,
        evidence=tuple(evidence) if evidence else (_evidence(resource_map),),
    )
    return propose_correspondence(_validated_map(resource_map), source)


def test_proposer_emits_closed_unconfirmed_typed_proposals() -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    proposal = proposal_set.proposals[0]
    assert proposal.proposal_id.startswith("corrp:v1:")
    assert proposal.relation_kind == "same_mechanism"
    assert proposal.obligation_id == OBLIGATION
    assert proposal.ica_slot_id == ICA_SLOT
    assert proposal.ica_id == ICA_ID
    assert proposal.exec_candidate_id == EXEC
    assert proposal.provenance.evidence_source == "exact_id"
    assert (
        proposal.provenance.source_pins.capability_snapshot_digest
        == resource_map.capability_snapshot_digest
    )
    assert (
        proposal_set.capability_snapshot_digest
        == resource_map.capability_snapshot_digest
    )
    assert proposal_set.semantic_digest is not None
    with pytest.raises((TypeError, ValueError)):
        proposal.relation_kind = "mechanism_enables_ica"  # type: ignore[misc]


def test_public_seams_require_validated_map_attestation() -> None:
    resource_map = make_map()
    source = CorrespondenceSourceArtifacts(
        authority=_authority(resource_map),
        evidence=(_evidence(resource_map),),
    )
    with pytest.raises(TypeError, match="SystemResourceMapValidation"):
        propose_correspondence(resource_map, source)  # type: ignore[arg-type]

    unknown_map = make_map(
        make_link(
            capability_resource_ref={
                "kind": "tool",
                "tool_id": "tool:v1:" + "f" * 32,
            }
        )
    )
    invalid = validate_system_resource_map(
        unknown_map,
        make_snapshot(),
        make_control_structure(),
    )
    assert {item.code for item in invalid.violations} == {"unknown_capability_resource"}
    with pytest.raises(ValueError, match="blocking violations"):
        propose_correspondence(invalid, source)

    invalid_without_diagnostics = SystemResourceMapValidation(
        is_valid=False,
        canonical_map=resource_map,
    )
    with pytest.raises(ValueError, match="blocking violations"):
        propose_correspondence(invalid_without_diagnostics, source)

    missing_map = SystemResourceMapValidation(is_valid=True)
    with pytest.raises(ValueError, match="no canonical map"):
        propose_correspondence(missing_map, source)


def test_proposer_accepts_only_the_closed_source_contract_or_its_mapping() -> None:
    resource_map = make_map()
    source = CorrespondenceSourceArtifacts(
        authority=_authority(resource_map),
        evidence=(_evidence(resource_map),),
    )
    validated_map = _validated_map(resource_map)
    assert propose_correspondence(validated_map, source.model_dump(mode="json"))
    with pytest.raises(TypeError, match="typed authority"):
        propose_correspondence(validated_map, {"not": "the contract"})
    with pytest.raises(TypeError, match="CorrespondenceSourceArtifacts"):
        propose_correspondence(validated_map, object())  # type: ignore[arg-type]


def test_proposer_is_order_invariant_and_never_accepts_model_assisted_or_prose() -> (
    None
):
    resource_map = make_map()
    first = _proposal_set(resource_map, _evidence(resource_map))
    second = _proposal_set(resource_map, _evidence(resource_map))
    assert first.to_yaml() == second.to_yaml()
    with pytest.raises(Exception):
        _evidence(resource_map, evidence_source="model_assisted")
    with pytest.raises(Exception):
        CorrespondenceSourceArtifacts.model_validate(
            {
                "authority": _authority(resource_map).model_dump(mode="json"),
                "evidence": [{"prose": "looks similar"}],
            }
        )


def test_proposal_set_without_optional_authority_remains_canonical() -> None:
    resource_map = make_map()
    proposal_set = ProposalSet(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        proposals=(),
    )
    assert proposal_set.authority is None
    assert ProposalSet.from_yaml(proposal_set.to_yaml()) == proposal_set


@pytest.mark.parametrize("field", ("ica_slot_id", "ica_id"))
def test_structural_authority_requires_nonempty_ica_identity(field: str) -> None:
    resource_map = make_map()
    payload = _authority(resource_map).structural_findings[0].model_dump(mode="json")
    payload[field] = ""
    with pytest.raises(Exception):
        StructuralAuthorityRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("risk_id", ""),
        ("attack_pattern_id", ""),
    ),
)
def test_obligation_authority_requires_nonempty_taxonomy_identity(
    field: str, value: str
) -> None:
    payload = ObligationAuthorityRecord(
        obligation_id=OBLIGATION,
        risk_id=RISK,
        attack_pattern_id=ATTACK_PATTERN,
    ).model_dump(mode="json")
    payload[field] = value
    with pytest.raises(Exception):
        ObligationAuthorityRecord.model_validate(payload)


@pytest.mark.parametrize(
    "field",
    (
        "risk_id",
        "attack_pattern_id",
        "taxonomy_candidate_ids",
        "ica_slot_id",
        "ica_id",
        "evidence_refs",
        "proposer_id",
        "proposer_version",
        "rationale",
    ),
)
def test_evidence_requires_nonempty_identity_and_provenance(field: str) -> None:
    resource_map = make_map()
    payload = _evidence(resource_map).model_dump(mode="json")
    payload[field] = [] if field in {"evidence_refs", "taxonomy_candidate_ids"} else ""
    with pytest.raises(Exception):
        CorrespondenceEvidence.model_validate(payload)


@pytest.mark.parametrize(
    "field", ("resource_link_ids", "hazard_ids", "constraint_ids", "evidence_refs")
)
def test_evidence_rejects_duplicate_reference_values(field: str) -> None:
    resource_map = make_map()
    payload = _evidence(resource_map).model_dump(mode="json")
    value = payload[field][0]
    payload[field] = [value, value]
    with pytest.raises(Exception):
        CorrespondenceEvidence.model_validate(payload)


def test_authority_rejects_duplicate_global_references() -> None:
    resource_map = make_map()
    payload = _authority(resource_map).model_dump(mode="json")
    payload["hazard_ids"] = ["H-1", "H-1"]
    with pytest.raises(Exception):
        CorrespondenceAuthority.model_validate(payload)


def test_authority_defaults_to_complete_inventory() -> None:
    resource_map = make_map()
    payload = _authority(resource_map).model_dump(mode="json")
    payload.pop("inventory_complete")
    authority = CorrespondenceAuthority.model_validate(payload)
    assert authority.inventory_complete is True


def test_provenance_rejects_duplicate_evidence_references_and_empty_fields() -> None:
    resource_map = make_map()
    evidence = _evidence(resource_map)
    provenance = {
        "proposer_id": evidence.proposer_id,
        "proposer_version": evidence.proposer_version,
        "evidence_source": evidence.evidence_source,
        "evidence_refs": evidence.evidence_refs,
        "source_pins": evidence.source_pins,
        "rationale": evidence.rationale,
    }
    provenance["evidence_refs"] = ["same", "same"]
    with pytest.raises(Exception):
        ProposalProvenance.model_validate(provenance)
    invalid_refs = dict(provenance)
    invalid_refs["evidence_refs"] = []
    with pytest.raises(Exception):
        ProposalProvenance.model_validate(invalid_refs)
    for field in ("proposer_id", "proposer_version", "rationale"):
        invalid = dict(provenance)
        invalid["evidence_refs"] = ["id:one"]
        invalid[field] = ""
        with pytest.raises(Exception):
            ProposalProvenance.model_validate(invalid)


@pytest.mark.parametrize(
    "field",
    ("risk_id", "attack_pattern_id", "taxonomy_candidate_ids", "ica_slot_id", "ica_id"),
)
def test_proposal_requires_nonempty_ica_identity(field: str) -> None:
    resource_map = make_map()
    proposal = _proposal_set(resource_map).proposals[0]
    payload = proposal.model_dump(mode="json")
    payload[field] = [] if field == "taxonomy_candidate_ids" else ""
    payload["proposal_id"] = compute_proposal_id(
        obligation_id=payload["obligation_id"],
        ica_slot_id=payload["ica_slot_id"],
        ica_id=payload["ica_id"],
        exec_candidate_id=payload["exec_candidate_id"],
        relation_kind=payload["relation_kind"],
        resource_link_ids=payload["resource_link_ids"],
        hazard_ids=payload["hazard_ids"],
        constraint_ids=payload["constraint_ids"],
        evidence_source=payload["provenance"]["evidence_source"],
        evidence_refs=payload["provenance"]["evidence_refs"],
    )
    with pytest.raises(Exception):
        type(proposal).model_validate(payload)


@pytest.mark.parametrize("field", ("resource_link_ids", "hazard_ids", "constraint_ids"))
def test_proposal_rejects_duplicate_references(field: str) -> None:
    resource_map = make_map()
    payload = _proposal_set(resource_map).proposals[0].model_dump(mode="json")
    value = payload[field][0]
    payload[field] = [value, value]
    with pytest.raises(Exception):
        type(_proposal_set(resource_map).proposals[0]).model_validate(payload)


def test_proposal_set_rejects_duplicate_proposal_id_values() -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    with pytest.raises(Exception):
        ProposalSet(
            resource_map_semantic_digest=resource_map.semantic_digest,
            capability_snapshot_digest=resource_map.capability_snapshot_digest,
            authority=proposal_set.authority,
            proposals=(proposal_set.proposals[0], proposal_set.proposals[0]),
        )


def test_adjudication_models_reject_empty_and_duplicate_audit_data() -> None:
    history = {
        "status": "confirmed",
        "reason": "reviewed",
        "adjudicated_by": "operator",
        "evidence_refs": ["id:one", "id:one"],
    }
    from asago_scenario_generator.models.correspondence import AdjudicationHistoryItem

    with pytest.raises(Exception):
        AdjudicationHistoryItem.model_validate(history)
    for field in ("reason", "adjudicated_by"):
        invalid = dict(history)
        invalid["evidence_refs"] = []
        invalid[field] = ""
        with pytest.raises(Exception):
            AdjudicationHistoryItem.model_validate(invalid)

    decision = {
        "proposal_id": "corrp:v1:" + "a" * 64,
        "status": "confirmed",
        "reason": "reviewed",
        "adjudicated_by": "operator",
        "evidence_refs": ["id:one", "id:one"],
    }
    with pytest.raises(Exception):
        CorrespondenceAdjudication.model_validate(decision)
    for field in ("reason", "adjudicated_by"):
        invalid = dict(decision)
        invalid["evidence_refs"] = []
        invalid[field] = ""
        with pytest.raises(Exception):
            CorrespondenceAdjudication.model_validate(invalid)


@pytest.mark.parametrize(
    "field",
    ("risk_id", "attack_pattern_id", "taxonomy_candidate_ids", "ica_slot_id", "ica_id"),
)
def test_reconciled_and_accepted_records_require_nonempty_ica_identity(
    field: str,
) -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    proposal = proposal_set.proposals[0]
    decision = CorrespondenceAdjudication(
        proposal_id=proposal.proposal_id,
        status="confirmed",
        reason="reviewed",
        adjudicated_by="operator",
    )
    result = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(decisions=(decision,)),
    )
    reconciled = result.proposals[0].model_dump(mode="json")
    reconciled[field] = [] if field == "taxonomy_candidate_ids" else ""
    reconciled["proposal_id"] = compute_proposal_id(
        obligation_id=reconciled["obligation_id"],
        ica_slot_id=reconciled["ica_slot_id"],
        ica_id=reconciled["ica_id"],
        exec_candidate_id=reconciled["exec_candidate_id"],
        relation_kind=reconciled["relation_kind"],
        resource_link_ids=reconciled["resource_link_ids"],
        hazard_ids=reconciled["hazard_ids"],
        constraint_ids=reconciled["constraint_ids"],
        evidence_source=reconciled["provenance"]["evidence_source"],
        evidence_refs=reconciled["provenance"]["evidence_refs"],
    )
    with pytest.raises(Exception):
        type(result.proposals[0]).model_validate(reconciled)
    accepted = result.accepted_relations[0].model_dump(mode="json")
    accepted[field] = [] if field == "taxonomy_candidate_ids" else ""
    accepted["relation_id"] = compute_relation_id(
        obligation_id=accepted["obligation_id"],
        ica_slot_id=accepted["ica_slot_id"],
        ica_id=accepted["ica_id"],
        exec_candidate_id=accepted["exec_candidate_id"],
        relation_kind=accepted["relation_kind"],
        resource_link_ids=accepted["resource_link_ids"],
    )
    with pytest.raises(Exception):
        type(result.accepted_relations[0]).model_validate(accepted)
    accepted_valid = result.accepted_relations[0].model_dump(mode="json")
    accepted_valid["evidence_refs"] = []
    with pytest.raises(Exception):
        type(result.accepted_relations[0]).model_validate(accepted_valid)


def test_reconciliation_error_and_result_are_closed() -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    result = reconcile_correspondence(_validated_map(resource_map), proposal_set)
    error = {
        "proposal_id": proposal_set.proposals[0].proposal_id,
        "code": "",
        "message": "detail",
    }
    with pytest.raises(Exception):
        ReconciliationError.model_validate(error)
    error["code"] = "invalid"
    error["message"] = ""
    with pytest.raises(Exception):
        ReconciliationError.model_validate(error)
    payload = result.model_dump(mode="json")
    assert result.model_calls == 0
    payload["model_calls"] = 1
    with pytest.raises(Exception):
        type(result).model_validate(payload)


def test_reconciliation_without_authority_remains_auditable() -> None:
    resource_map = make_map()
    generated = _proposal_set(resource_map)
    proposals = ProposalSet(
        resource_map_semantic_digest=resource_map.semantic_digest,
        capability_snapshot_digest=resource_map.capability_snapshot_digest,
        proposals=generated.proposals,
    )
    result = reconcile_correspondence(_validated_map(resource_map), proposals)
    assert not result.is_valid
    assert result.proposals[0].validation_codes == ("missing_authority_inventory",)


def test_reconciliation_handles_missing_structural_finding_without_dereference() -> (
    None
):
    resource_map = make_map()
    payload = _authority(resource_map).model_dump(mode="json")
    payload["structural_findings"] = []
    authority = CorrespondenceAuthority.model_validate(payload)
    proposal_set = propose_correspondence(
        _validated_map(resource_map),
        CorrespondenceSourceArtifacts(
            authority=authority, evidence=(_evidence(resource_map),)
        ),
    )
    result = reconcile_correspondence(_validated_map(resource_map), proposal_set)
    assert result.proposals[0].status == "rejected"
    assert "dangling_structural_finding" in result.proposals[0].validation_codes


def test_empty_ica_path_does_not_create_a_false_path_violation() -> None:
    resource_map = make_map()
    payload = _authority(resource_map).model_dump(mode="json")
    payload["structural_findings"][0]["resource_link_ids"] = []
    authority = CorrespondenceAuthority.model_validate(payload)
    proposal_set = propose_correspondence(
        _validated_map(resource_map),
        CorrespondenceSourceArtifacts(
            authority=authority, evidence=(_evidence(resource_map),)
        ),
    )
    proposal = proposal_set.proposals[0]
    result = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="reviewed",
                    adjudicated_by="operator",
                ),
            )
        ),
    )
    assert not result.is_valid
    assert result.proposals[0].status == "rejected"
    assert result.proposals[0].validation_result == "rejected"
    assert "missing_ica_path_resource_authority" in (
        result.proposals[0].validation_codes
    )
    assert result.accepted_relations == ()


def test_missing_candidate_resource_authority_rejects_confirmation() -> None:
    resource_map = make_map()
    payload = _authority(resource_map).model_dump(mode="json")
    payload["obligations"][0]["candidate_resource_refs"] = []
    authority = CorrespondenceAuthority.model_validate(payload)
    proposal_set = propose_correspondence(
        _validated_map(resource_map),
        CorrespondenceSourceArtifacts(
            authority=authority, evidence=(_evidence(resource_map),)
        ),
    )
    proposal = proposal_set.proposals[0]

    result = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="attempted confirmation",
                    adjudicated_by="operator",
                ),
            )
        ),
    )

    assert result.proposals[0].status == "rejected"
    assert "missing_candidate_resource_authority" in (
        result.proposals[0].validation_codes
    )
    assert result.accepted_relations == ()


def test_substituted_taxonomy_identity_is_rejected_with_typed_code() -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(
        resource_map,
        _evidence(resource_map, risk_id="substituted-risk"),
    )
    proposal = proposal_set.proposals[0]

    result = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="attempted confirmation",
                    adjudicated_by="operator",
                ),
            )
        ),
    )

    assert result.proposals[0].status == "rejected"
    assert result.proposals[0].validation_result == "rejected"
    assert result.proposals[0].validation_codes == ("risk_id_mismatch",)


def test_missing_obligation_does_not_dereference_an_empty_authority_slot() -> None:
    resource_map = make_map()
    payload = _authority(resource_map).model_dump(mode="json")
    payload["obligations"] = []
    authority = CorrespondenceAuthority.model_validate(payload)
    proposal_set = propose_correspondence(
        _validated_map(resource_map),
        CorrespondenceSourceArtifacts(
            authority=authority, evidence=(_evidence(resource_map),)
        ),
    )
    result = reconcile_correspondence(_validated_map(resource_map), proposal_set)
    assert result.proposals[0].status == "rejected"
    assert "dangling_obligation" in result.proposals[0].validation_codes


def test_noncoverage_relation_stays_unresolved_without_adjudication() -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(
        resource_map, _evidence(resource_map, relation_kind="related_but_not_coverage")
    )
    result = reconcile_correspondence(_validated_map(resource_map), proposal_set)
    assert result.is_valid
    assert result.proposals[0].status == "unresolved"
    assert result.accepted_relations == ()


def test_confirmed_noncoverage_relation_is_accepted_but_not_coverage() -> None:
    """Explicit review may accept a typed noncoverage relation as a finding."""
    resource_map = make_map()
    proposal_set = _proposal_set(
        resource_map, _evidence(resource_map, relation_kind="related_but_not_coverage")
    )
    proposal = proposal_set.proposals[0]
    decision = CorrespondenceAdjudication(
        proposal_id=proposal.proposal_id,
        status="confirmed",
        reason="reviewed as related but outside coverage",
        adjudicated_by="operator-1",
    )

    result = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(decisions=(decision,)),
    )

    assert result.is_valid
    assert result.proposals[0].status == "confirmed"
    assert len(result.accepted_relations) == 1
    assert result.accepted_relations[0].relation_kind == "related_but_not_coverage"


def test_reconciliation_requires_typed_explicit_confirmation_and_retains_audit() -> (
    None
):
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    unresolved = reconcile_correspondence(_validated_map(resource_map), proposal_set)
    assert unresolved.proposals[0].status == "unresolved"
    assert unresolved.accepted_relations == ()
    assert unresolved.proposals[0].adjudication_history[0].adjudicated_by == "system"

    decision = CorrespondenceAdjudication(
        proposal_id=proposal_set.proposals[0].proposal_id,
        status="confirmed",
        reason="reviewed exact evidence",
        adjudicated_by="operator-1",
    )
    confirmed = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(decisions=(decision,)),
    )
    assert confirmed.is_valid
    assert (
        confirmed.capability_snapshot_digest == resource_map.capability_snapshot_digest
    )
    assert confirmed.proposals[0].status == "confirmed"
    assert len(confirmed.accepted_relations) == 1
    assert confirmed.accepted_relations[0].relation_id.startswith("correlation:v1:")
    assert (
        confirmed.to_yaml() == type(confirmed).from_yaml(confirmed.to_yaml()).to_yaml()
    )


def test_proposal_and_reconciliation_fail_closed_on_capability_pin_substitution() -> (
    None
):
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    proposal_payload = proposal_set.model_dump(mode="json")
    proposal_payload["capability_snapshot_digest"] = "f" * 64
    proposal_payload["semantic_digest"] = None
    with pytest.raises(ValueError, match="capability snapshot"):
        ProposalSet.model_validate(proposal_payload)

    decision = CorrespondenceAdjudication(
        proposal_id=proposal_set.proposals[0].proposal_id,
        status="confirmed",
        reason="reviewed exact evidence",
        adjudicated_by="operator-1",
    )
    reconciliation = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(decisions=(decision,)),
    )
    reconciliation_payload = reconciliation.model_dump(mode="json")
    reconciliation_payload["capability_snapshot_digest"] = "f" * 64
    reconciliation_payload["semantic_digest"] = None
    with pytest.raises(ValueError, match="capability snapshot"):
        ReconciliationResult.model_validate(reconciliation_payload)


def test_duplicate_confirmations_of_one_relation_are_typed_rejections() -> None:
    resource_map = make_map()
    first = _evidence(resource_map, evidence_refs=("id:obligation", "id:ica"))
    second = _evidence(
        resource_map,
        evidence_refs=("id:obligation", "id:ica", "review:independent"),
    )
    proposal_set = _proposal_set(resource_map, first, second)
    decisions = AdjudicationSet(
        decisions=tuple(
            CorrespondenceAdjudication(
                proposal_id=proposal.proposal_id,
                status="confirmed",
                reason="reviewed exact evidence",
                adjudicated_by="operator-1",
            )
            for proposal in proposal_set.proposals
        )
    )

    result = reconcile_correspondence(
        _validated_map(resource_map), proposal_set, decisions
    )

    assert not result.is_valid
    assert result.accepted_relations == ()
    assert {item.status for item in result.proposals} == {"rejected"}
    assert all(
        "duplicate_confirmed_relation" in item.validation_codes
        for item in result.proposals
    )
    assert len(result.errors) == 2


def test_reconciliation_accepts_typed_sequences_and_rejects_free_form_decisions() -> (
    None
):
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    decision = CorrespondenceAdjudication(
        proposal_id=proposal_set.proposals[0].proposal_id,
        status="confirmed",
        reason="reviewed",
        adjudicated_by="operator",
    )
    result = reconcile_correspondence(
        _validated_map(resource_map), proposal_set, (decision,)
    )
    assert result.proposals[0].status == "confirmed"
    with pytest.raises(TypeError, match="not a mapping"):
        reconcile_correspondence(
            _validated_map(resource_map), proposal_set, {"status": "confirmed"}
        )
    with pytest.raises(TypeError, match="typed decisions"):
        reconcile_correspondence(
            _validated_map(resource_map), proposal_set, (object(),)
        )
    unknown = decision.model_copy(update={"proposal_id": "corrp:v1:" + "f" * 64})
    with pytest.raises(ValueError, match="unknown proposal IDs"):
        reconcile_correspondence(_validated_map(resource_map), proposal_set, (unknown,))


def test_correspondence_cli_validates_map_and_loads_json_or_yaml(tmp_path) -> None:
    resource_map = make_map()
    source = CorrespondenceSourceArtifacts(
        authority=_authority(resource_map),
        evidence=(_evidence(resource_map),),
    )
    map_json = tmp_path / "system-resource-map.json"
    map_json.write_text(resource_map.to_json(), encoding="utf-8")
    map_yaml = tmp_path / "system-resource-map.yaml"
    map_yaml.write_text(resource_map.to_yaml(), encoding="utf-8")
    snapshot_json = tmp_path / "capability-snapshot.json"
    snapshot_json.write_text(
        json.dumps(make_snapshot().model_dump(mode="json")), encoding="utf-8"
    )
    control_yaml = tmp_path / "control-structure.yaml"
    control_yaml.write_text(
        yaml.dump(make_control_structure().model_dump(mode="json")),
        encoding="utf-8",
    )
    source_yaml = tmp_path / "source-artifacts.yaml"
    source_yaml.write_text(yaml.dump(source.model_dump(mode="json")), encoding="utf-8")
    proposal_output = tmp_path / "proposal-parent" / "proposals"

    propose_args = [
        "propose-correspondence",
        "--map",
        str(map_json),
        "--artifacts",
        str(source_yaml),
        "--capability-snapshot",
        str(snapshot_json),
        "--control-structure",
        str(control_yaml),
        "--output-dir",
        str(proposal_output),
        "--format",
        "both",
    ]
    proposed = CLI_RUNNER.invoke(app, propose_args)
    assert proposed.exit_code == 0, proposed.output
    assert "Network calls: 0" in proposed.output
    assert "Model calls:   0" in proposed.output
    proposal_json = proposal_output / "correspondence-proposals.json"
    assert (proposal_output / "correspondence-proposals.yaml").is_file()
    proposal_set = ProposalSet.from_json(proposal_json.read_bytes())
    repeated_proposal = CLI_RUNNER.invoke(app, propose_args)
    assert repeated_proposal.exit_code == 0, repeated_proposal.output
    adjudications = AdjudicationSet(
        decisions=(
            CorrespondenceAdjudication(
                proposal_id=proposal_set.proposals[0].proposal_id,
                status="confirmed",
                reason="reviewed",
                adjudicated_by="operator",
            ),
        )
    )
    adjudications_yaml = tmp_path / "adjudications.yaml"
    adjudications_yaml.write_text(
        yaml.dump(adjudications.model_dump(mode="json")), encoding="utf-8"
    )
    reconciliation_output = tmp_path / "reconciliation-parent" / "reconciliation"

    reconcile_args = [
        "reconcile-correspondence",
        "--map",
        str(map_yaml),
        "--proposals",
        str(proposal_json),
        "--adjudications",
        str(adjudications_yaml),
        "--capability-snapshot",
        str(snapshot_json),
        "--control-structure",
        str(control_yaml),
        "--output-dir",
        str(reconciliation_output),
        "--format",
        "both",
    ]
    reconciled = CLI_RUNNER.invoke(app, reconcile_args)
    assert reconciled.exit_code == 0, reconciled.output
    assert (reconciliation_output / "correspondence-reconciliation.yaml").is_file()
    result = ReconciliationResult.from_json(
        (reconciliation_output / "correspondence-reconciliation.json").read_bytes()
    )
    assert (
        result.accepted_relations[0].proposal_id
        == proposal_set.proposals[0].proposal_id
    )
    repeated_reconciliation = CLI_RUNNER.invoke(app, reconcile_args)
    assert repeated_reconciliation.exit_code == 0, repeated_reconciliation.output


def test_accepted_relation_retains_exact_taxonomy_identity() -> None:
    plan, resource_map, control, enumeration, loss_analysis, snapshot = (
        _authoritative_artifacts()
    )
    source = CorrespondenceSourceArtifacts.from_artifacts(
        resource_map,
        plan,
        control,
        enumeration,
        loss_analysis,
    )
    obligation = source.authority.obligations[0]
    evidence = CorrespondenceEvidence(
        obligation_id=obligation.obligation_id,
        risk_id=obligation.risk_id,
        attack_pattern_id=obligation.attack_pattern_id,
        taxonomy_candidate_ids=obligation.taxonomy_candidate_ids,
        ica_slot_id=ICA_SLOT,
        ica_id=ICA_ID,
        exec_candidate_id=EXEC,
        relation_kind="same_mechanism",
        resource_link_ids=("srm:v1:1",),
        hazard_ids=("H-1",),
        constraint_ids=("RC-1-1",),
        evidence_source="exact_id",
        evidence_refs=("review:exact",),
        confidence=1.0,
        evidence_strength="high",
        proposer_id="exact-v1",
        proposer_version="1",
        source_pins=source.authority.source_pins,
        rationale="exact reviewed identities",
    )
    proposal_set = propose_correspondence(
        _validated_map(resource_map, snapshot=snapshot, control=control),
        source.model_copy(update={"evidence": (evidence,)}),
    )
    proposal = proposal_set.proposals[0]

    result = reconcile_correspondence(
        _validated_map(resource_map, snapshot=snapshot, control=control),
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="reviewed",
                    adjudicated_by="operator",
                ),
            )
        ),
    )

    relation = result.accepted_relations[0]
    assert relation.proposal_id == proposal.proposal_id
    assert relation.risk_id == obligation.risk_id
    assert relation.attack_pattern_id == obligation.attack_pattern_id
    assert relation.taxonomy_candidate_ids == obligation.taxonomy_candidate_ids


def test_closed_reconciliation_models_reject_fabricated_acceptance() -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    proposal = proposal_set.proposals[0]
    confirmed = reconcile_correspondence(
        _validated_map(resource_map),
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="reviewed",
                    adjudicated_by="operator",
                ),
            )
        ),
    )

    reconciled_payload = confirmed.proposals[0].model_dump(mode="json")
    reconciled_payload["adjudication_history"] = []
    with pytest.raises(ValueError, match="confirmed adjudication history"):
        type(confirmed.proposals[0]).model_validate(reconciled_payload)

    system_confirmation = confirmed.proposals[0].model_dump(mode="json")
    system_confirmation["adjudication_history"][0]["adjudicated_by"] = "system"
    with pytest.raises(ValueError, match="confirmed adjudication history"):
        type(confirmed.proposals[0]).model_validate(system_confirmation)

    inconsistent_rejection = confirmed.proposals[0].model_dump(mode="json")
    inconsistent_rejection["status"] = "unresolved"
    inconsistent_rejection["validation_result"] = "rejected"
    inconsistent_rejection["validation_codes"] = ["typed_defect"]
    with pytest.raises(ValueError, match="rejected validation requires"):
        type(confirmed.proposals[0]).model_validate(inconsistent_rejection)

    missing_relation = confirmed.model_dump(mode="json")
    missing_relation["accepted_relations"] = []
    missing_relation["semantic_digest"] = None
    with pytest.raises(ValueError, match="accepted relation.*confirmed proposal"):
        type(confirmed).model_validate(missing_relation)

    unsupported = confirmed.model_dump(mode="json")
    unsupported["proposals"][0]["status"] = "unresolved"
    unsupported["semantic_digest"] = None
    with pytest.raises(ValueError, match="accepted relation.*confirmed proposal"):
        type(confirmed).model_validate(unsupported)

    fabricated = confirmed.model_dump(mode="json")
    fabricated["accepted_relations"][0]["proposal_id"] = "corrp:v1:" + "f" * 64
    fabricated["semantic_digest"] = None
    with pytest.raises(ValueError, match="accepted relation.*confirmed proposal"):
        type(confirmed).model_validate(fabricated)

    mismatched = confirmed.model_dump(mode="json")
    mismatched["accepted_relations"][0]["risk_id"] = "fabricated-risk"
    mismatched["semantic_digest"] = None
    with pytest.raises(ValueError, match="does not match its confirmed proposal"):
        type(confirmed).model_validate(mismatched)

    duplicate_proposal = confirmed.model_dump(mode="json")
    duplicate_proposal["proposals"].append(duplicate_proposal["proposals"][0])
    duplicate_proposal["semantic_digest"] = None
    with pytest.raises(ValueError, match="unique proposal IDs"):
        type(confirmed).model_validate(duplicate_proposal)


def test_reconciliation_rejects_dangling_stale_advisory_and_incomplete_claims() -> None:
    resource_map = make_map()
    proposal_set = _proposal_set(resource_map)
    proposal = proposal_set.proposals[0]
    decision = CorrespondenceAdjudication(
        proposal_id=proposal.proposal_id,
        status="confirmed",
        reason="attempted confirmation",
        adjudicated_by="operator-1",
    )

    tampered_map = resource_map.model_copy(update={"semantic_digest": "f" * 64})
    with pytest.raises((TypeError, ValueError)):
        reconcile_correspondence(
            tampered_map, proposal_set, AdjudicationSet(decisions=(decision,))
        )

    incomplete = _proposal_set(resource_map, complete=False)
    incomplete_result = reconcile_correspondence(
        _validated_map(resource_map),
        incomplete,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=incomplete.proposals[0].proposal_id,
                    status="confirmed",
                    reason="attempted confirmation",
                    adjudicated_by="operator-1",
                ),
            )
        ),
    )
    assert not incomplete_result.is_valid
    assert (
        "incomplete_authority_inventory"
        in incomplete_result.proposals[0].validation_codes
    )


def test_confirmation_requires_every_source_pin() -> None:
    resource_map = make_map()
    for field in (
        "obligation_plan_semantic_digest",
        "control_structure_digest",
        "ica_enumeration_digest",
        "loss_analysis_digest",
        "taxonomy_version",
        "stpa_version",
    ):
        evidence_payload = _evidence(resource_map).model_dump(mode="json")
        evidence_payload["source_pins"][field] = None
        evidence = CorrespondenceEvidence.model_validate(evidence_payload)
        proposal_set = _proposal_set(resource_map, evidence)
        proposal = proposal_set.proposals[0]

        result = reconcile_correspondence(
            _validated_map(resource_map),
            proposal_set,
            AdjudicationSet(
                decisions=(
                    CorrespondenceAdjudication(
                        proposal_id=proposal.proposal_id,
                        status="confirmed",
                        reason="attempted confirmation",
                        adjudicated_by="operator",
                    ),
                )
            ),
        )

        assert result.proposals[0].status == "rejected"
        assert f"missing_{field}" in result.proposals[0].validation_codes


def test_conflicting_relation_kinds_are_unresolved_and_same_slot_icas_stay_distinct() -> (
    None
):
    resource_map = make_map()
    first = _evidence(resource_map, relation_kind="same_mechanism")
    second = _evidence(resource_map, relation_kind="mechanism_enables_ica")
    proposal_set = _proposal_set(resource_map, first, second)
    result = reconcile_correspondence(_validated_map(resource_map), proposal_set)
    assert len(result.proposals) == 2
    assert all(item.status == "unresolved" for item in result.proposals)
    assert all("conflict" in item.validation_codes for item in result.proposals)
    assert result.accepted_relations == ()


def test_relation_identity_retains_ica_slot_and_ica_id() -> None:
    relation_one = compute_relation_id(
        obligation_id=OBLIGATION,
        ica_slot_id=ICA_SLOT,
        ica_id=ICA_ID,
        exec_candidate_id=EXEC,
        relation_kind="same_mechanism",
        resource_link_ids=("srm:v1:1",),
    )
    relation_two = compute_relation_id(
        obligation_id=OBLIGATION,
        ica_slot_id=ICA_SLOT,
        ica_id=ICA_SLOT + ":2",
        exec_candidate_id=EXEC,
        relation_kind="same_mechanism",
        resource_link_ids=("srm:v1:1",),
    )
    assert relation_one != relation_two
    assert AcceptedCorrespondenceRelation is not None
