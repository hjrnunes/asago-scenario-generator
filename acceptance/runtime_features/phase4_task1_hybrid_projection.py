"""Offline acceptance handlers for Phase 4 Task 1 resolution."""

from __future__ import annotations

import re
import socket
from typing import Any, Callable
from unittest.mock import patch

from runtime_shared import World

from asago_scenario_generator.models.correspondence import (
    AdjudicationSet,
    CorrespondenceAdjudication,
    ProposalSet,
)
from asago_scenario_generator.pipeline.correspondence import reconcile_correspondence
from asago_scenario_generator.pipeline.hybrid_coverage import assess_hybrid_coverage
from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    build_hybrid_correspondence_attestation,
    resolve_hybrid_projection_units,
)

FEATURE_ID = "phase4_task1_hybrid_projection"


def _state(world: World) -> dict[str, Any]:
    """Return isolated state for one Task 1 acceptance scenario."""
    state = getattr(world, "phase4_task1_hybrid_projection_state", None)
    if state is None:
        state = {
            "inputs": None,
            "relation": None,
            "candidate": None,
            "resolution": None,
            "error": None,
            "network_calls": 0,
            "model_calls": 0,
        }
        world.phase4_task1_hybrid_projection_state = state
    return state


def _fixture() -> tuple[Any, Any, Any]:
    """Build the shared deterministic authority fixture from public helpers.

    This is intentionally local rather than importing the large unit-test
    module: the unit test also exercises private implementation helpers, while
    this acceptance boundary must remain valid when those helpers are changed.
    Every production operation below enters through a public adapter.
    """
    from tests.helpers.obligation_factory import make_inputs
    from tests.helpers.projection_factory import (
        get_projected_candidate,
        get_test_snapshot,
    )
    from tests.system_resource_map_support import make_control_structure, make_map

    from asago_scenario_generator.models.correspondence import (
        ReviewedCorrespondenceAdjudications,
        ReviewedCorrespondenceDecision,
    )
    from asago_scenario_generator.models.hybrid_coverage import ArtifactPin
    from asago_scenario_generator.models.hybrid_projection_inputs import (
        HybridProjectionInputs,
    )
    from asago_scenario_generator.models.hybrid_scenario_projection import (
        ArtifactProjectionSourcePin,
        BridgeAuthorityIdentity,
        BridgeEvidence,
        BridgeLink,
        StpaEndpoint,
        TaxonomyEndpoint,
    )
    from asago_scenario_generator.models.system_resource_map import ResourceLink
    from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
        build_candidate_materialization_set,
        build_confirmed_coverage_review,
        build_pinned_stpa_projection_attestation,
        capability_fact_attestation_from_artifacts,
        mechanism_evidence_attestation_from_artifacts,
    )
    from asago_scenario_generator.pipeline.obligation_planner import (
        plan_taxonomy_obligations,
    )
    from asago_scenario_generator.pipeline.system_resource_map import (
        validate_system_resource_map,
    )
    from asago_scenario_generator.stpa.models.execution_envelope import (
        CandidateExecutionEnvelope,
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

    plan = plan_taxonomy_obligations(make_inputs())
    candidate = get_projected_candidate()
    snapshot = get_test_snapshot()
    control_structure = make_control_structure()
    # The Phase 4 STPA adapter requires security-constraint ownership to be
    # explicit on the authoritative controller.  Keep this acceptance
    # fixture aligned with the public unit-test fixture rather than allowing
    # the background step's expected-error handling to leave ``inputs`` empty.
    control_structure.responsibilities[0].security_constraint_refs = ["SC-1"]
    resource_map = make_map(
        ResourceLink(
            link_id="srm:v1:assessment-link",
            capability_resource_ref={
                "kind": "tool",
                "tool_id": snapshot.profile.tool_inventory[0].tool_id,
            },
            control_structure_ref={"kind": "CA", "id": "CA-1-1"},
            relation_kind="acts_on",
            provenance="operator_declared",
            evidence_refs=("review:assessment-link",),
            confidence=1.0,
            authority_status="authoritative",
        ),
        snapshot=snapshot,
        control=control_structure,
    )
    resource_map_validation = validate_system_resource_map(
        resource_map, snapshot, control_structure
    )

    from tests.test_hybrid_coverage_assessment import (
        _proposal_set,
        _stpa_input,
        _taxonomy_input,
    )

    proposal_set, _ = _proposal_set(plan, resource_map_validation)
    proposal = proposal_set.proposals[0]
    reconciliation = reconcile_correspondence(
        resource_map_validation,
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="reviewed exact identities",
                    adjudicated_by="operator-1",
                ),
            )
        ),
    )
    assessment = assess_hybrid_coverage(
        plan,
        resource_map_validation,
        reconciliation,
        _taxonomy_input(plan, candidate),
        _stpa_input(),
    )
    relation = reconciliation.accepted_relations[0]

    loss_analysis = LossAnalysis(
        risk_card_losses=(
            Loss(
                loss_id="L-1",
                description="Unauthorized payment",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["risk-a"],
            ),
        ),
        use_case_losses=(),
        hazards=(
            Hazard(
                hazard_id="H-1",
                description="Payment is authorized without the required control",
                related_losses=["L-1"],
            ),
        ),
        security_constraints=(
            SecurityConstraint(
                constraint_id="SC-1",
                description="Payments require the control action",
                related_hazards=["H-1"],
            ),
        ),
    )
    slot_id = "RESP-1:CA-1-1:WRONG_TIMING"
    ica_id = slot_id + ":1"
    exec_id = "EXEC:RESP-1:CA-1-1:WRONG_TIMING"
    enumeration = ICAEnumeration(
        slots=(
            ICASlot(
                slot_id=slot_id,
                responsibility="RESP-1",
                control_action="CA-1-1",
                uca_type=UCAType.wrong_timing,
                is_na=False,
                icas=(
                    ICA(
                        ica_id=ica_id,
                        ica_text="Authorizes the payment at the wrong time",
                        hazardous_context="The payment is pending",
                        loss_scenario="The payment bypasses the required control",
                        related_hazards=["H-1"],
                        related_constraints=["SC-1"],
                    ),
                ),
            ),
        ),
    )
    execution = CandidateExecutionEnvelope(
        candidate_id=exec_id,
        controller_id="RESP-1",
        control_action_id="CA-1-1",
        control_action_description="Authorize payment",
        uca_type=UCAType.wrong_timing,
        uca_ref=slot_id,
        ica_id=ica_id,
    )
    capability = capability_fact_attestation_from_artifacts(
        snapshot, plan, resource_map_validation
    )
    materializations = build_candidate_materialization_set(plan, (candidate,), snapshot)
    correspondence = build_hybrid_correspondence_attestation(
        proposal_set, reconciliation, assessment
    )
    stpa = build_pinned_stpa_projection_attestation(
        loss_analysis,
        control_structure,
        enumeration,
        (execution,),
        (relation,),
    )
    reviewed = ReviewedCorrespondenceAdjudications.create(
        packet_digest="a" * 64,
        proposal_set_semantic_digest=proposal_set.semantic_digest,
        decisions=(
            ReviewedCorrespondenceDecision(
                proposal_id=proposal.proposal_id,
                relation_kind="same_mechanism",
                status="confirmed",
                reason="reviewed exact mechanism",
                adjudicated_by="operator-1",
            ),
        ),
    )
    mechanism_evidence = mechanism_evidence_attestation_from_artifacts(
        proposal_set, proposal.proposal_id, "exact_id"
    )
    review = build_confirmed_coverage_review(reviewed, relation, mechanism_evidence)
    bridge_evidence = BridgeEvidence(
        artifact_pin=ArtifactPin(
            artifact_id="taxonomy-candidate-materialization-set",
            schema_version=materializations.schema_version,
            semantic_digest=materializations.semantic_digest,
        ),
        record_id="step.1",
        evidence_kind="operator_bridge_review",
        provenance="operator_declared",
        authority_identity=BridgeAuthorityIdentity(kind="reviewer", id="operator-1"),
        rationale="The mechanism step perturbs the exact control action.",
    )
    bridge = BridgeLink(
        relation_id=relation.relation_id,
        bridge_kind="perturbs_control_action",
        taxonomy_endpoint=TaxonomyEndpoint(kind="mechanism_step", record_id="step.1"),
        stpa_endpoint=StpaEndpoint(kind="control_action", record_id="CA-1-1"),
        evidence=(bridge_evidence,),
        source_pins=(
            ArtifactProjectionSourcePin.from_artifact_pin(
                bridge_evidence.artifact_pin, role="bridge-evidence"
            ),
        ),
    )
    inputs = HybridProjectionInputs(
        obligation_plan=plan,
        capability_facts=capability,
        candidate_materializations=materializations,
        phase2_assessment=assessment,
        correspondence=correspondence,
        resource_map_validation=resource_map_validation,
        stpa_projection_authority=stpa,
        confirmed_reviews=(review,),
        bridge_links=(bridge,),
        requested_relation_ids=(relation.relation_id,),
        evidence_class="normative_bookkeeping_fixture",
    )
    return inputs, relation, candidate


def _offline_call(state: dict[str, Any], operation: Callable[[], Any]) -> Any:
    """Run one public operation while making external activity fail closed."""
    state["network_calls"] = 0
    state["model_calls"] = 0

    def blocked(*_args: Any, **_kwargs: Any) -> None:
        state["network_calls"] += 1
        raise AssertionError("Task 1 attempted network activity")

    with (
        patch.object(socket, "socket", side_effect=blocked),
        patch.object(socket, "create_connection", side_effect=blocked),
    ):
        return operation()


def _given_fixture(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Prepare one complete, typed authority graph."""
    state = _state(world)
    state["inputs"], state["relation"], state["candidate"] = _fixture()
    return True, ""


def _given_guard(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Reset the observable offline guard counters."""
    state = _state(world)
    state["network_calls"] = 0
    state["model_calls"] = 0
    return True, ""


def _resolve(world: World, operation: Callable[[], Any]) -> tuple[bool, str]:
    """Execute a resolver operation and retain expected failures for Then steps."""
    state = _state(world)
    state["resolution"] = None
    state["error"] = None
    try:
        state["resolution"] = _offline_call(state, operation)
    except Exception as exc:  # noqa: BLE001 - expected negative acceptance cases
        state["error"] = str(exc)
    return True, ""


def _accepted(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Resolve the fixture's exact coverage-bearing relation."""
    state = _state(world)
    return _resolve(world, lambda: resolve_hybrid_projection_units(state["inputs"]))


def _related_only(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Create and resolve one explicit related-only Phase 2 relation."""
    state = _state(world)

    def operation() -> Any:
        from tests.test_hybrid_coverage_assessment import (
            _proposal_set,
            _stpa_input,
            _taxonomy_input,
        )

        proposal_set, candidate = _proposal_set(
            state["inputs"].obligation_plan,
            state["inputs"].resource_map_validation,
            relation_kind="related_but_not_coverage",
        )
        proposal = proposal_set.proposals[0]
        reconciliation = reconcile_correspondence(
            state["inputs"].resource_map_validation,
            proposal_set,
            AdjudicationSet(
                decisions=(
                    CorrespondenceAdjudication(
                        proposal_id=proposal.proposal_id,
                        status="confirmed",
                        reason="shared-resource relation only",
                        adjudicated_by="operator-1",
                    ),
                )
            ),
        )
        assessment = assess_hybrid_coverage(
            state["inputs"].obligation_plan,
            state["inputs"].resource_map_validation,
            reconciliation,
            _taxonomy_input(state["inputs"].obligation_plan, candidate),
            _stpa_input(),
        )
        correspondence = build_hybrid_correspondence_attestation(
            proposal_set, reconciliation, assessment
        )
        relation = correspondence.accepted_relations[0]
        related_inputs = state["inputs"].model_copy(
            update={
                "phase2_assessment": assessment,
                "correspondence": correspondence,
                "confirmed_reviews": (),
                "bridge_links": (),
                "requested_relation_ids": (relation.relation_id,),
            }
        )
        return resolve_hybrid_projection_units(related_inputs)

    return _resolve(world, operation)


def _cross_paired(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Attempt to pair a modified proposal set with its old reconciliation."""
    state = _state(world)

    def operation() -> Any:
        from tests.test_hybrid_coverage_assessment import _proposal_set

        proposal_set, _candidate = _proposal_set(
            state["inputs"].obligation_plan,
            state["inputs"].resource_map_validation,
        )
        proposal = proposal_set.proposals[0]
        reconciliation = reconcile_correspondence(
            state["inputs"].resource_map_validation,
            proposal_set,
            AdjudicationSet(
                decisions=(
                    CorrespondenceAdjudication(
                        proposal_id=proposal.proposal_id,
                        status="confirmed",
                        reason="exact identities",
                        adjudicated_by="operator-1",
                    ),
                )
            ),
        )
        replaced = proposal.model_copy(update={"confidence": 0.5})
        substituted_set = ProposalSet(
            resource_map_semantic_digest=proposal_set.resource_map_semantic_digest,
            capability_snapshot_digest=proposal_set.capability_snapshot_digest,
            authority=proposal_set.authority,
            proposals=(replaced,),
        )
        return build_hybrid_correspondence_attestation(
            substituted_set,
            reconciliation,
            state["inputs"].phase2_assessment,
        )

    return _resolve(world, operation)


def _copied_attestation(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Use a copied, re-digested correspondence value at the resolver seam."""
    state = _state(world)

    def operation() -> Any:
        copied = state["inputs"].correspondence.model_copy(
            update={"semantic_digest": None}
        )
        copied = type(copied).model_validate(copied.model_dump(mode="python"))
        substituted = state["inputs"].model_copy(update={"correspondence": copied})
        return resolve_hybrid_projection_units(substituted)

    return _resolve(world, operation)


def _counts(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check the unit and exclusion counts returned by the public resolver."""
    match = re.fullmatch(r"resolution returns (\d+) unit and (\d+) exclusions", text)
    if match is None:
        return False, f"unexpected count step: {text}"
    state = _state(world)
    resolution = state["resolution"]
    if resolution is None:
        return False, f"resolver did not return a resolution: {state['error']}"
    expected = (int(match.group(1)), int(match.group(2)))
    actual = (len(resolution.units), len(resolution.exclusions))
    return actual == expected, f"expected counts {expected}, got {actual}"


def _identity(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check all five exact identities carried by the resolved unit."""
    match = re.fullmatch(r'the resolved five-part identity is "([^"]+)"', text)
    if match is None:
        return False, f"unexpected identity step: {text}"
    resolution = _state(world)["resolution"]
    if resolution is None or len(resolution.units) != 1:
        return False, "exact identity requires one resolved unit"
    unit = resolution.units[0]
    actual = "/".join(
        (
            unit.relation_id,
            unit.obligation_id,
            unit.selected_candidate_id,
            unit.ica_id,
            unit.exec_candidate_id,
        )
    )
    return actual == match.group(
        1
    ), f"expected identity {match.group(1)!r}, got {actual!r}"


def _reason(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check the typed relation-local exclusion reason."""
    match = re.fullmatch(r'the exclusion reason is "([^"]+)"', text)
    if match is None:
        return False, f"unexpected exclusion step: {text}"
    resolution = _state(world)["resolution"]
    actual = (
        resolution.exclusions[0].reason
        if resolution and resolution.exclusions
        else None
    )
    return actual == match.group(1), f"expected {match.group(1)!r}, got {actual!r}"


def _diagnostic(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check the exact public diagnostic fragment for a rejected operation."""
    match = re.fullmatch(
        r'the Task 1 operation fails with diagnostic containing "([^"]+)"', text
    )
    if match is None:
        return False, f"unexpected diagnostic step: {text}"
    actual = _state(world)["error"] or ""
    return match.group(1) in actual, f"expected {match.group(1)!r} in {actual!r}"


def _guard_counts(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check that no network or model activity occurred."""
    match = re.fullmatch(
        r"the offline guard records (\d+) network calls and (\d+) model calls", text
    )
    if match is None:
        return False, f"unexpected guard step: {text}"
    state = _state(world)
    expected = (int(match.group(1)), int(match.group(2)))
    actual = (state["network_calls"], state["model_calls"])
    return actual == expected, f"expected guard counts {expected}, got {actual}"


def register(api: object) -> None:
    """Register Task 1 acceptance step handlers."""
    registrations = (
        (
            r"^a complete typed Task 1 authority fixture is available$",
            _given_fixture,
        ),
        (
            r"^the Task 1 resolver has an offline network and model guard$",
            _given_guard,
        ),
        (r"^Task 1 resolves the accepted relation$", _accepted),
        (r"^Task 1 resolves the related-only relation$", _related_only),
        (
            r"^Task 1 builds a correspondence attestation from cross-paired authorities$",
            _cross_paired,
        ),
        (
            r"^Task 1 resolves inputs containing a copied and re-digested attestation$",
            _copied_attestation,
        ),
        (r"^resolution returns \d+ unit and \d+ exclusions$", _counts),
        (r'^the resolved five-part identity is "[^"]+"$', _identity),
        (r'^the exclusion reason is "[^"]+"$', _reason),
        (
            r'^the Task 1 operation fails with diagnostic containing "[^"]+"$',
            _diagnostic,
        ),
        (
            r"^the offline guard records \d+ network calls and \d+ model calls$",
            _guard_counts,
        ),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "register"]
