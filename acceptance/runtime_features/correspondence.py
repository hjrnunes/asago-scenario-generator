"""Offline acceptance handlers for normative Task 3 correspondence."""

from __future__ import annotations

import re
from typing import Any

from runtime_shared import World

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CorrespondenceAdjudication,
    CorrespondenceAuthority,
    CorrespondenceEvidence,
    CorrespondenceSourceArtifacts,
    ObligationAuthorityRecord,
    SourceArtifactPins,
    StructuralAuthorityRecord,
)
from asago_scenario_generator.models.system_resource_map import (
    ResourceLink,
    SystemResourceMap,
    compute_control_structure_digest,
    compute_resource_map_semantic_digest,
)
from asago_scenario_generator.pipeline.correspondence import (
    propose_correspondence,
    reconcile_correspondence,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlStructure,
    ControlledProcess,
    ProcessModelPart,
    Responsibility,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    capture_capability_snapshot,
)
from asago_scenario_generator.pipeline.system_resource_map import (
    validate_system_resource_map,
)
from acceptance.qa.taxonomy_risk.correspondence_support import (
    run_workflow_compatibility,
)

FEATURE_ID = "correspondence"
OBLIGATION_ID = "ob:v1:" + "1" * 64
ICA_SLOT_ID = "RESP-1:CA-1-1:WRONG_TIMING"
ICA_ID = ICA_SLOT_ID + ":1"
EXEC_ID = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
OBLIGATION_ID_2 = "ob:v1:" + "2" * 64
ICA_ID_2 = ICA_SLOT_ID + ":2"
ICA_SLOT_ID_2 = "RESP-1:CA-1-1:NOT_PROVIDED"
RISK_ID = "risk-1"
ATTACK_PATTERN_ID = "AML.T0001"
TAXONOMY_CANDIDATE_ID = "cand:v2:" + "a" * 32


def _state(world: World) -> dict[str, Any]:
    """Return isolated correspondence state for one scenario."""
    state = getattr(world, "correspondence_state", None)
    if state is None:
        state = {
            "resource_map": None,
            "proposal_set": None,
            "result": None,
            "serialized": None,
            "error": None,
            "compatibility": None,
            "gap_reason": None,
            "structural_ids": (),
        }
        world.correspondence_state = state
    return state


def _map() -> SystemResourceMap:
    """Build a minimal valid map with one authoritative resource link."""
    snapshot, control = _map_inputs()
    link = ResourceLink(
        link_id="srm:v1:1",
        capability_resource_ref={
            "kind": "tool",
            "tool_id": snapshot.profile.tool_inventory[0].tool_id,
        },
        control_structure_ref={"kind": "CA", "id": "CA-1-1"},
        relation_kind="acts_on",
        provenance="operator_declared",
        evidence_refs=("review:resource-link",),
        confidence=1.0,
        authority_status="authoritative",
    )
    control_digest = compute_control_structure_digest(control)
    map_digest = compute_resource_map_semantic_digest(
        schema_version="system-resource-map-v1",
        capability_snapshot_digest=snapshot.snapshot_digest,
        control_structure_digest=control_digest,
        links=(link,),
    )
    return SystemResourceMap(
        schema_version="system-resource-map-v1",
        semantic_digest=map_digest,
        capability_snapshot_digest=snapshot.snapshot_digest,
        control_structure_digest=control_digest,
        links=(link,),
    )


def _map_inputs() -> tuple[Any, ControlStructure]:
    """Build the exact capability and STPA authorities for the map fixture."""
    profile = CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "entry_points": [
                {
                    "name": "Customer input",
                    "entry_point_type": "user_input",
                    "direction": "input",
                    "controllability": "direct",
                    "ingress_zone": "input",
                }
            ],
            "confidence": "high",
            "kc_subcodes": ["KC1.1", "KC5.3"],
            "tool_inventory": [
                {"name": "Payment API", "description": "Mutates payments"}
            ],
        }
    )
    snapshot = capture_capability_snapshot(profile)
    control = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="Payment controller",
                process_model_parts=[
                    ProcessModelPart(pm_id="PM-1-1", description="Payment state")
                ],
                control_actions=[
                    ControlAction(ca_id="CA-1-1", description="Authorize payment")
                ],
            )
        ],
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="Payment process")
        ],
    )
    return snapshot, control


def _validated_map(resource_map: SystemResourceMap) -> Any:
    """Return the typed attestation required by the correspondence seam."""
    snapshot, control = _map_inputs()
    return validate_system_resource_map(resource_map, snapshot, control)


def _propose(
    resource_map: SystemResourceMap, source: CorrespondenceSourceArtifacts | dict
) -> Any:
    """Propose only through the validated-map boundary."""
    return propose_correspondence(_validated_map(resource_map), source)


def _reconcile(
    resource_map: SystemResourceMap,
    proposal_set: Any,
    adjudications: AdjudicationSet | None = None,
) -> Any:
    """Reconcile only through the validated-map boundary."""
    return reconcile_correspondence(
        _validated_map(resource_map), proposal_set, adjudications
    )


def _pins(map_value: SystemResourceMap) -> SourceArtifactPins:
    """Build stable source pins for one correspondence fixture."""
    return SourceArtifactPins(
        resource_map_semantic_digest=map_value.semantic_digest,
        capability_snapshot_digest=map_value.capability_snapshot_digest,
        obligation_plan_semantic_digest="2" * 64,
        control_structure_digest=map_value.control_structure_digest,
        ica_enumeration_digest="3" * 64,
        loss_analysis_digest="4" * 64,
        taxonomy_version="atlas-v1",
        stpa_version="stpa-v1",
    )


def _source(
    map_value: SystemResourceMap,
    *,
    obligation_ids: tuple[str, ...] = (OBLIGATION_ID,),
    findings: tuple[StructuralAuthorityRecord, ...] | None = None,
    evidence: tuple[CorrespondenceEvidence, ...] | None = None,
    inventory_complete: bool = True,
) -> CorrespondenceSourceArtifacts:
    """Build a typed authority/evidence fixture for acceptance scenarios."""
    pins = _pins(map_value)
    link_id = map_value.links[0].link_id
    if findings is None:
        findings = (
            StructuralAuthorityRecord(
                ica_slot_id=ICA_SLOT_ID,
                ica_id=ICA_ID,
                exec_candidate_id=EXEC_ID,
                hazard_ids=("H-1",),
                constraint_ids=("SC-1",),
                resource_link_ids=(link_id,),
            ),
        )
    authority = CorrespondenceAuthority(
        source_pins=pins,
        obligations=tuple(
            ObligationAuthorityRecord(
                obligation_id=obligation_id,
                risk_id=f"risk-{obligation_id[-1]}",
                attack_pattern_id=ATTACK_PATTERN_ID,
                taxonomy_candidate_ids=(TAXONOMY_CANDIDATE_ID,),
                candidate_resource_refs=(map_value.links[0].capability_resource_ref,),
            )
            for obligation_id in obligation_ids
        ),
        structural_findings=findings,
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        inventory_complete=inventory_complete,
    )
    if evidence is None:
        evidence = (_evidence(map_value, pins=pins),)
    return CorrespondenceSourceArtifacts(authority=authority, evidence=evidence)


def _evidence(
    map_value: SystemResourceMap,
    *,
    pins: SourceArtifactPins | None = None,
    obligation_id: str = OBLIGATION_ID,
    risk_id: str | None = None,
    attack_pattern_id: str = ATTACK_PATTERN_ID,
    taxonomy_candidate_ids: tuple[str, ...] = (TAXONOMY_CANDIDATE_ID,),
    ica_slot_id: str = ICA_SLOT_ID,
    ica_id: str = ICA_ID,
    exec_candidate_id: str = EXEC_ID,
    relation_kind: str = "same_mechanism",
    evidence_source: str = "exact_id",
    evidence_refs: tuple[str, ...] = ("id:obligation", "id:ica"),
    resource_link_ids: tuple[str, ...] | None = None,
) -> CorrespondenceEvidence:
    """Create one deterministic evidence record with exact identities."""
    return CorrespondenceEvidence(
        obligation_id=obligation_id,
        risk_id=risk_id or f"risk-{obligation_id[-1]}",
        attack_pattern_id=attack_pattern_id,
        taxonomy_candidate_ids=taxonomy_candidate_ids,
        ica_slot_id=ica_slot_id,
        ica_id=ica_id,
        exec_candidate_id=exec_candidate_id,
        relation_kind=relation_kind,  # type: ignore[arg-type]
        resource_link_ids=resource_link_ids or (map_value.links[0].link_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        evidence_source=evidence_source,  # type: ignore[arg-type]
        evidence_refs=evidence_refs,
        confidence=1.0,
        evidence_strength="high",
        proposer_id="exact-id-v1",
        proposer_version="1",
        source_pins=pins or _pins(map_value),
        rationale="exact reviewed identities",
    )


def _prepare(world: World) -> None:
    """Prepare a valid map and deterministic proposal set."""
    state = _state(world)
    resource_map = _map()
    state["resource_map"] = resource_map
    state["proposal_set"] = _propose(resource_map, _source(resource_map))


def _confirmed(world: World) -> None:
    """Reconcile the prepared proposal with one explicit decision."""
    state = _state(world)
    proposal_set = state["proposal_set"]
    proposal = proposal_set.proposals[0]
    adjudication = CorrespondenceAdjudication(
        proposal_id=proposal.proposal_id,
        status="confirmed",
        reason="reviewed exact evidence",
        adjudicated_by="operator-1",
    )
    state["result"] = _reconcile(
        state["resource_map"],
        proposal_set,
        AdjudicationSet(decisions=(adjudication,)),
    )


def _advisory_map() -> SystemResourceMap:
    """Build a valid map whose only link is advisory/model-proposed."""
    original = _map()
    link = ResourceLink.model_validate(
        original.links[0].model_dump(mode="json")
        | {
            "provenance": "model_proposed",
            "authority_status": "advisory",
            "evidence_refs": [],
        }
    )
    digest = compute_resource_map_semantic_digest(
        schema_version=original.schema_version,
        capability_snapshot_digest=original.capability_snapshot_digest,
        control_structure_digest=original.control_structure_digest,
        links=(link,),
    )
    return SystemResourceMap(
        schema_version=original.schema_version,
        semantic_digest=digest,
        capability_snapshot_digest=original.capability_snapshot_digest,
        control_structure_digest=original.control_structure_digest,
        links=(link,),
    )


def _prepare_advisory(world: World) -> None:
    """Prepare exact identities that cite an advisory resource link."""
    state = _state(world)
    resource_map = _advisory_map()
    state["resource_map"] = resource_map
    state["proposal_set"] = _propose(resource_map, _source(resource_map))


def _prepare_no_proposal(world: World) -> None:
    """Prepare complete authority with a shared resource and no proposal."""
    state = _state(world)
    resource_map = _map()
    source = _source(resource_map)
    from asago_scenario_generator.models.correspondence import ProposalSet

    state.update(
        {
            "resource_map": resource_map,
            "proposal_set": ProposalSet(
                resource_map_semantic_digest=resource_map.semantic_digest,
                capability_snapshot_digest=resource_map.capability_snapshot_digest,
                authority=source.authority,
                proposals=(),
            ),
            "gap_reason": "unresolved_no_proposal",
        }
    )


def _prepare_many_to_many(world: World) -> None:
    """Prepare four exact relations covering both directions of a 2x2 map."""
    state = _state(world)
    resource_map = _map()
    link_id = resource_map.links[0].link_id
    findings = (
        StructuralAuthorityRecord(
            ica_slot_id=ICA_SLOT_ID,
            ica_id=ICA_ID,
            exec_candidate_id=EXEC_ID,
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            resource_link_ids=(link_id,),
        ),
        StructuralAuthorityRecord(
            ica_slot_id=ICA_SLOT_ID_2,
            ica_id=ICA_SLOT_ID_2 + ":1",
            exec_candidate_id="EXEC:RESP-1:CA-1-1:NOT_PROVIDED",
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            resource_link_ids=(link_id,),
        ),
    )
    pins = _pins(resource_map)
    evidence = tuple(
        _evidence(
            resource_map,
            pins=pins,
            obligation_id=obligation_id,
            ica_slot_id=finding.ica_slot_id,
            ica_id=finding.ica_id,
            exec_candidate_id=finding.exec_candidate_id,
            evidence_refs=(f"id:{obligation_id}", f"id:{finding.ica_id}"),
        )
        for obligation_id in (OBLIGATION_ID, OBLIGATION_ID_2)
        for finding in findings
    )
    state.update(
        {
            "resource_map": resource_map,
            "proposal_set": _propose(
                resource_map,
                _source(
                    resource_map,
                    obligation_ids=(OBLIGATION_ID, OBLIGATION_ID_2),
                    findings=findings,
                    evidence=evidence,
                ),
            ),
        }
    )


def _prepare_same_slot(
    world: World, text: str = "", examples: dict[str, Any] | None = None
) -> None:
    """Prepare two ICAs that intentionally share a slot and EXEC identity."""
    del text, examples
    state = _state(world)
    resource_map = _map()
    link_id = resource_map.links[0].link_id
    findings = tuple(
        StructuralAuthorityRecord(
            ica_slot_id=ICA_SLOT_ID,
            ica_id=ica_id,
            exec_candidate_id=EXEC_ID,
            hazard_ids=("H-1",),
            constraint_ids=("SC-1",),
            resource_link_ids=(link_id,),
        )
        for ica_id in (ICA_ID, ICA_ID_2)
    )
    pins = _pins(resource_map)
    evidence = tuple(
        _evidence(
            resource_map,
            pins=pins,
            ica_id=ica_id,
            evidence_refs=("id:obligation", f"id:{ica_id}"),
        )
        for ica_id in (ICA_ID, ICA_ID_2)
    )
    state.update(
        {
            "resource_map": resource_map,
            "proposal_set": _propose(
                resource_map,
                _source(resource_map, findings=findings, evidence=evidence),
            ),
        }
    )


def _prepare_unmapped_ica(world: World) -> None:
    """Prepare an authoritative structural ICA with no taxonomy proposal."""
    state = _state(world)
    resource_map = _map()
    source = _source(resource_map)
    from asago_scenario_generator.models.correspondence import ProposalSet

    state.update(
        {
            "resource_map": resource_map,
            "proposal_set": ProposalSet(
                resource_map_semantic_digest=resource_map.semantic_digest,
                capability_snapshot_digest=resource_map.capability_snapshot_digest,
                authority=source.authority,
                proposals=(),
            ),
            "structural_ids": ((ICA_SLOT_ID, ICA_ID),),
        }
    )


def _prepare_dangling(world: World) -> None:
    """Prepare a proposal whose obligation is absent from typed authority."""
    state = _state(world)
    resource_map = _map()
    pins = _pins(resource_map)
    evidence = _evidence(
        resource_map,
        pins=pins,
        obligation_id=OBLIGATION_ID_2,
        evidence_refs=("id:unmatched-obligation", "id:ica"),
    )
    state.update(
        {
            "resource_map": resource_map,
            "proposal_set": _propose(
                resource_map, _source(resource_map, evidence=(evidence,))
            ),
        }
    )


def _prepare_related(world: World) -> None:
    """Prepare an explicitly reviewed noncoverage relation."""
    state = _state(world)
    resource_map = _map()
    pins = _pins(resource_map)
    evidence = _evidence(
        resource_map,
        pins=pins,
        relation_kind="related_but_not_coverage",
        evidence_refs=("id:obligation", "id:ica", "review:noncoverage"),
    )
    state.update(
        {
            "resource_map": resource_map,
            "proposal_set": _propose(
                resource_map, _source(resource_map, evidence=(evidence,))
            ),
        }
    )


def _prepare_duplicate_relation(world: World) -> None:
    """Prepare two independently evidenced proposals for one semantic relation."""
    state = _state(world)
    resource_map = _map()
    pins = _pins(resource_map)
    evidence = (
        _evidence(
            resource_map,
            pins=pins,
            evidence_refs=("id:obligation", "id:ica"),
        ),
        _evidence(
            resource_map,
            pins=pins,
            evidence_refs=("id:obligation", "id:ica", "review:independent"),
        ),
    )
    state.update(
        {
            "resource_map": resource_map,
            "proposal_set": _propose(
                resource_map, _source(resource_map, evidence=evidence)
            ),
        }
    )


def _reconcile_all(world: World, *, status: str = "confirmed") -> None:
    """Reconcile every prepared proposal with one explicit decision."""
    state = _state(world)
    proposal_set = state["proposal_set"]
    decisions = tuple(
        CorrespondenceAdjudication(
            proposal_id=proposal.proposal_id,
            status=status,  # type: ignore[arg-type]
            reason="reviewed acceptance fixture",
            adjudicated_by="operator-1",
        )
        for proposal in proposal_set.proposals
    )
    state["result"] = _reconcile(
        state["resource_map"],
        proposal_set,
        AdjudicationSet(decisions=decisions),
    )


def _register(api: Any) -> None:
    """Register the compact normative correspondence scenarios."""
    api.set_feature(FEATURE_ID)

    def ok(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare(world)
        return True, ""

    def prepare(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare(world)
        return True, ""

    def emit(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        # The prose-only scenario intentionally leaves the typed boundary in
        # a rejected state; the generic When step must not replace that
        # rejection with a fresh exact-ID proposal.
        if state.get("error") and state.get("proposal_set") is None:
            return True, ""
        _prepare(world)
        return True, ""

    def assert_one(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return (len(state["proposal_set"].proposals) == 1, "one proposal expected")

    def assert_unconfirmed(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        proposal = _state(world)["proposal_set"].proposals[0]
        return (not hasattr(proposal, "status"), "proposal must not carry a status")

    def assert_capability_pin(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return (
            state["proposal_set"].capability_snapshot_digest
            == state["resource_map"].capability_snapshot_digest,
            "proposal set capability snapshot digest changed",
        )

    def substitute_proposal_pin(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'proposal set "([^"]+)" is substituted', text)
        field = match.group(1) if match else ""
        if field != "capability_snapshot_digest":
            return False, f"unsupported proposal pin field {field!r}"
        state = _state(world)
        payload = state["proposal_set"].model_dump(mode="json")
        payload[field] = "f" * 64
        payload["semantic_digest"] = None
        try:
            type(state["proposal_set"]).model_validate(payload)
        except Exception as exc:  # noqa: BLE001 - expected closed-contract failure
            state["substitution_error"] = str(exc)
            state["substitution_field"] = field
            return True, ""
        return False, "substituted proposal capability pin was accepted"

    def assert_proposal_pin_rejected(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'rejects substituted "([^"]+)"', text)
        expected = match.group(1) if match else ""
        state = _state(world)
        return (
            expected == "capability_snapshot_digest"
            and state.get("substitution_field") == expected
            and "capability snapshot" in state.get("substitution_error", ""),
            "proposal capability pin substitution was not rejected",
        )

    def reconcile(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _confirmed(world)
        return True, ""

    def assert_confirmed(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        result = _state(world)["result"]
        return (len(result.accepted_relations) == 1, "one accepted relation expected")

    def assert_unresolved(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        result = _reconcile(state["resource_map"], state["proposal_set"])
        state["result"] = result
        return (
            result.proposals[0].status == "unresolved"
            and not result.accepted_relations,
            "proposal must remain unresolved",
        )

    def reconcile_without_proposal(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        """Reconcile an authority with no proposal and retain diagnostics."""
        del text, examples
        state = _state(world)
        state["result"] = _reconcile(state["resource_map"], state["proposal_set"])
        return True, ""

    def serialize(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        result = _state(world)["result"]
        _state(world)["serialized"] = result.to_yaml()
        return True, ""

    def assert_roundtrip(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        from asago_scenario_generator.models.correspondence import ReconciliationResult

        result = _state(world)["result"]
        restored = ReconciliationResult.from_yaml(_state(world)["serialized"])
        return (restored == result, "reconciliation round-trip changed the artifact")

    def assert_no_calls(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return (
            state["proposal_set"] is not None,
            "correspondence must be offline",
        )

    def prepare_prose_only(world: World, text: str, examples: dict) -> tuple[bool, str]:
        """Supply prose with no exact identifiers and retain the typed error."""
        del text, examples
        state = _state(world)
        resource_map = _map()
        source = _source(resource_map)
        try:
            _propose(
                resource_map,
                {
                    "authority": source.authority.model_dump(mode="json"),
                    "evidence": [
                        {
                            "prose": "The payment behavior sounds related to this ICA.",
                        }
                    ],
                },
            )
        except Exception as exc:  # noqa: BLE001 - expected typed-boundary rejection
            state.update(
                {
                    "resource_map": resource_map,
                    "proposal_set": None,
                    "error": str(exc),
                }
            )
            return True, ""
        return False, "prose-only evidence unexpectedly produced a proposal"

    def assert_typed_rejection(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        error = state.get("error", "")
        return (
            state.get("proposal_set") is None and bool(error),
            "prose-only input did not fail at the typed proposal boundary",
        )

    def assert_no_proposal_from_prose(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        return (
            state.get("proposal_set") is None,
            "prose-only input unexpectedly produced a proposal",
        )

    def prepare_advisory(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_advisory(world)
        return True, ""

    def reconcile_explicit(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _reconcile_all(world)
        return True, ""

    def assert_rejected_code(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'code "([^"]+)"', text)
        expected = match.group(1) if match else ""
        state = _state(world)
        result = state.get("result")
        codes = {item.code for item in (result.errors if result else ())}
        return expected in codes and not result.accepted_relations, (
            f"expected rejected code {expected!r}, got {sorted(codes)}"
        )

    def prepare_no_proposal(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        _prepare_no_proposal(world)
        return True, ""

    def prepare_many_to_many(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        _prepare_many_to_many(world)
        return True, ""

    def prepare_same_slot(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_same_slot(world)
        return True, ""

    def assert_unresolved_gap(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'gap "([^"]+)"', text)
        expected = match.group(1) if match else ""
        state = _state(world)
        result = state.get("result")
        return (
            state.get("gap_reason") == expected
            and result is not None
            and not result.accepted_relations,
            f"expected typed gap {expected!r} with no accepted relation",
        )

    def assert_relation_count(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r"contains (\d+) distinct accepted relations", text)
        expected = int(match.group(1)) if match else -1
        result = _state(world).get("result")
        return (
            result is not None
            and len(result.accepted_relations) == expected
            and len({item.relation_id for item in result.accepted_relations})
            == expected,
            "many-to-many relation identities collapsed",
        )

    def assert_identity_pairs(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        result = _state(world).get("result")
        if result is None:
            return False, "no reconciliation result"
        pairs = {
            (item.obligation_id, item.ica_id) for item in result.accepted_relations
        }
        expected = {
            (obligation_id, finding_ica)
            for obligation_id in (OBLIGATION_ID, OBLIGATION_ID_2)
            for finding_ica in (ICA_ID, ICA_SLOT_ID_2 + ":1")
        }
        return pairs == expected, f"relation identity pairs were {sorted(pairs)}"

    def assert_same_slot_distinct(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        result = _state(world).get("result")
        if result is None:
            return False, "no reconciliation result"
        identities = {
            (item.ica_slot_id, item.ica_id, item.exec_candidate_id)
            for item in result.accepted_relations
        }
        return (
            len(result.accepted_relations) == 2
            and len(identities) == 2
            and all(
                item.ica_slot_id == ICA_SLOT_ID for item in result.accepted_relations
            )
            and all(
                item.exec_candidate_id == EXEC_ID for item in result.accepted_relations
            ),
            "same-slot ICA identities or shared EXEC identity were collapsed",
        )

    def prepare_unmapped(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_unmapped_ica(world)
        return True, ""

    def assert_unmapped_retained(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        state = _state(world)
        result = state.get("result")
        return (
            state["structural_ids"] == ((ICA_SLOT_ID, ICA_ID),)
            and result is not None
            and not result.accepted_relations
            and result.proposals == (),
            "unmapped ICA was removed or treated as correspondence credit",
        )

    def prepare_dangling(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_dangling(world)
        return True, ""

    def reconcile_with_confirmation(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        _reconcile_all(world)
        return True, ""

    def prepare_related(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_related(world)
        return True, ""

    def reconcile_rejected(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _reconcile_all(world, status="rejected")
        return True, ""

    def assert_related_noncoverage(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        result = _state(world).get("result")
        return (
            result is not None
            and len(result.accepted_relations) == 1
            and result.accepted_relations[0].relation_kind
            == "related_but_not_coverage",
            "related-but-not-coverage relation was not retained as a finding",
        )

    def assert_rejected_retained(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        result = _state(world).get("result")
        return (
            result is not None
            and len(result.proposals) == 1
            and result.proposals[0].status == "rejected"
            and not result.accepted_relations,
            "rejected proposal was not retained or became accepted coverage",
        )

    def prepare_duplicate(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        _prepare_duplicate_relation(world)
        return True, ""

    def assert_duplicate_rejected(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'code "([^"]+)"', text)
        expected = match.group(1) if match else ""
        result = _state(world).get("result")
        return (
            result is not None
            and len(result.proposals) == 2
            and all(item.status == "rejected" for item in result.proposals)
            and all(expected in item.validation_codes for item in result.proposals),
            "duplicate confirmations were not retained as typed rejections",
        )

    def assert_no_duplicate_relation(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del text, examples
        result = _state(world).get("result")
        return (
            result is not None and not result.accepted_relations,
            "duplicate confirmation produced an accepted relation",
        )

    def assert_dangling(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(r'code "([^"]+)"', text)
        expected = match.group(1) if match else ""
        result = _state(world).get("result")
        codes = {item.code for item in (result.errors if result else ())}
        return (
            expected in codes and result is not None and not result.accepted_relations,
            f"expected dangling diagnostic {expected!r}, got {sorted(codes)}",
        )

    def compatibility_fixture(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'for "([^"]+)"', text)
        workflow = match.group(1) if match else ""
        if workflow not in {"taxonomy/risk", "STPA"}:
            return False, f"unsupported workflow fixture {workflow!r}"
        state = _state(world)
        state["compatibility_workflow"] = workflow
        return True, ""

    def compatibility_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del examples
        match = re.search(
            r'^correspondence "([^"]+)" runs before and after Phase 2 sidecars$',
            text,
        )
        command = match.group(1) if match else ""
        expected = {"taxonomy/risk": "generate", "STPA": "stpa-run"}.get(
            _state(world).get("compatibility_workflow")
        )
        if command != expected:
            return False, f"{command!r} is not the expected command {expected!r}"
        try:
            observation = run_workflow_compatibility(
                _state(world)["compatibility_workflow"]
            )
        except Exception as exc:  # pragma: no cover - acceptance diagnostic boundary
            return False, f"compatibility subprocesses failed: {exc}"
        _state(world)["compatibility"] = observation
        return observation["exit_match"], observation["detail"]

    def compatibility_assert(
        world: World, text: str, examples: dict
    ) -> tuple[bool, str]:
        del examples
        match = re.search(r'^the correspondence "([^"]+)" (.+)$', text)
        if match is None:
            return False, f"cannot parse compatibility assertion: {text}"
        kind = match.group(2)
        observation = _state(world).get("compatibility") or {}
        key = {
            "exit status is unchanged": "exit_match",
            "scenario artifacts are identical after normalization of known volatile fields": "artifacts_match",
            "generation counts are identical": "counts_match",
            "prompt contracts are identical": "prompts_match",
        }.get(kind)
        if key is None:
            return False, f"unknown compatibility assertion: {kind}"
        return bool(
            observation.get(key)
        ), f"compatibility {key} failed: {observation.get('detail')}"

    def no_phase2_output(world: World, text: str, examples: dict) -> tuple[bool, str]:
        del text, examples
        observation = _state(world).get("compatibility") or {}
        return (
            bool(observation.get("sidecars_present"))
            and bool(observation.get("no_phase2_output")),
            f"Phase 2 output leaked into workflow artifacts: {observation.get('detail')}",
        )

    registrations = (
        (r"^a valid typed correspondence authority is available$", ok),
        (r"^correspondence operations make no provider calls$", assert_no_calls),
        (r"^a deterministic exact-ID proposal is prepared$", prepare),
        (r"^correspondence proposals are produced$", emit),
        (r"^the proposal set contains exactly one proposal$", assert_one),
        (r"^the proposal is not confirmed$", assert_unconfirmed),
        (
            r"^the proposal set names the resource map capability snapshot digest$",
            assert_capability_pin,
        ),
        (r'^proposal set "[^"]+" is substituted$', substitute_proposal_pin),
        (
            r'^the proposal artifact rejects substituted "[^"]+"$',
            assert_proposal_pin_rejected,
        ),
        (r"^the proposal is reconciled with explicit confirmation$", reconcile),
        (r"^one accepted relation is returned$", assert_confirmed),
        (r"^the proposal remains unresolved without adjudication$", assert_unresolved),
        (r"^the reconciliation is serialized$", serialize),
        (r"^the reconciliation round-trips unchanged$", assert_roundtrip),
        (r"^a prose-only correspondence input is supplied$", prepare_prose_only),
        (
            r"^no proposal is produced from the prose-only input$",
            assert_no_proposal_from_prose,
        ),
        (
            r"^the prose-only input is rejected with typed diagnostics$",
            assert_typed_rejection,
        ),
        (r"^a deterministic advisory-only proposal is prepared$", prepare_advisory),
        (
            r"^the advisory proposal is reconciled with explicit confirmation$",
            reconcile_explicit,
        ),
        (
            r'^reconciliation rejects confirmation with code "([^"]+)"$',
            assert_rejected_code,
        ),
        (
            r"^a shared resource authority has no correspondence proposal$",
            prepare_no_proposal,
        ),
        (
            r"^correspondence is reconciled without a proposal$",
            reconcile_without_proposal,
        ),
        (
            r'^the obligation remains an unresolved typed gap "([^"]+)"$',
            assert_unresolved_gap,
        ),
        (
            r"^one obligation maps to two ICAs and one ICA maps to two obligations$",
            prepare_many_to_many,
        ),
        (r"^all many-to-many relations are explicitly confirmed$", reconcile_explicit),
        (
            r"^reconciliation contains \d+ distinct accepted relations$",
            assert_relation_count,
        ),
        (
            r"^accepted relation identities retain both obligation and ICA identities$",
            assert_identity_pairs,
        ),
        (r"^two ICAs share a slot and EXEC identity$", prepare_same_slot),
        (r"^both same-slot ICAs are explicitly confirmed$", reconcile_explicit),
        (
            r"^both same-slot ICAs remain distinct accepted relations$",
            assert_same_slot_distinct,
        ),
        (r"^an unmapped ICA is in structural authority$", prepare_unmapped),
        (
            r"^the unmapped ICA remains structurally retained and scenario-eligible$",
            assert_unmapped_retained,
        ),
        (r"^an unmatched obligation is in typed authority$", prepare_dangling),
        (
            r"^correspondence is reconciled with explicit confirmation$",
            reconcile_with_confirmation,
        ),
        (
            r'^the unmatched obligation remains a typed gap with code "([^"]+)"$',
            assert_dangling,
        ),
        (
            r"^a reviewed related-but-not-coverage proposal is prepared$",
            prepare_related,
        ),
        (
            r"^the related-but-not-coverage proposal is explicitly confirmed$",
            reconcile_explicit,
        ),
        (
            r"^the relation remains a finding and never coverage$",
            assert_related_noncoverage,
        ),
        (r"^a rejected correspondence proposal is prepared$", prepare),
        (r"^the proposal is explicitly rejected$", reconcile_rejected),
        (
            r"^the rejection remains retained with no accepted relation$",
            assert_rejected_retained,
        ),
        (r"^two proposals imply the same semantic relation$", prepare_duplicate),
        (
            r"^both duplicate relations are explicitly confirmed$",
            reconcile_explicit,
        ),
        (
            r'^both proposals are rejected with code "[^"]+"$',
            assert_duplicate_rejected,
        ),
        (
            r"^no duplicate accepted relation is returned$",
            assert_no_duplicate_relation,
        ),
        (
            r'^a deterministic correspondence compatibility fixture includes valid Phase 2 sidecars for "([^"]+)"$',
            compatibility_fixture,
        ),
        (
            r'^correspondence "([^"]+)" runs before and after Phase 2 sidecars$',
            compatibility_run,
        ),
        (
            r'^the correspondence "([^"]+)" exit status is unchanged$',
            compatibility_assert,
        ),
        (
            r'^the correspondence "([^"]+)" scenario artifacts are identical after normalization of known volatile fields$',
            compatibility_assert,
        ),
        (
            r'^the correspondence "([^"]+)" generation counts are identical$',
            compatibility_assert,
        ),
        (
            r'^the correspondence "([^"]+)" prompt contracts are identical$',
            compatibility_assert,
        ),
        (
            r"^no correspondence Phase 2 artifact is written into either workflow output$",
            no_phase2_output,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


register = _register

__all__ = ["FEATURE_ID", "register"]
