"""Tests for the deterministic target-derived Stage 2 control structure."""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest
import yaml

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.target_realization import (
    TargetRealizationDisposition,
)
from asago_scenario_generator.pipeline.target_realization import (
    realize_target_operations,
)
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml
from asago_scenario_generator.stpa.models.control_structure import (
    ControlActionEffectKind,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionTargetProfile,
    ExecutionSurface,
    InventoryAuthority,
    InventoryCompleteness,
    McpInventoryObservation,
    McpToolObservation,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
    TargetProfileOperation,
    TargetProfileResource,
    TargetSemanticInterpretation,
    mcp_resource_id,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.target_derived_structure import (
    CONSTRAINT_ACTION_RELEVANCE_FILENAME,
    TARGET_DERIVED_STRUCTURE_FILENAME,
    BeliefRecord,
    ConstraintActionRelevance,
    TargetDerivedStructure,
    control_structure_content_digest,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.system_model.target_derived_structure import (
    derive_target_structure,
    target_derived_stage2_mode,
)
from asago_scenario_generator.stpa.target_realization.identity import (
    TargetDerivedIdentityInterpreter,
)
from tests.stpa.sp1_helpers import MockLLMClient

USE_CASE = (
    "MiniKlarna is a customer-support assistant for a buy-now-pay-later "
    "service. Customers ask about orders, payment plans, refunds, and "
    "policies. The assistant answers with the supplied tools and escalates "
    "regulated topics to a human agent."
)


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorized refund execution",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[
            Hazard(
                hazard_id="H-1",
                description="The assistant executes a refund outside policy.",
                related_losses=["L-1"],
            )
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule=(
                    "The assistant must process a refund only for an eligible "
                    "order owned by the authenticated customer."
                ),
                related_hazards=["H-1"],
                qualifiers=["eligible order"],
            ),
            SecurityConstraint(
                constraint_id="SC-2",
                rule=(
                    "The assistant must disclose only authorized information "
                    "about another customer's orders."
                ),
                related_hazards=["H-1"],
                qualifiers=[],
            ),
        ],
    )


def _capability_profile(**overrides) -> CapabilityProfile:
    payload = {
        "zones_active": ["input", "reasoning", "tool_execution"],
        "entry_points": [
            {"name": "User chat", "direction": "input", "controllability": "direct"},
        ],
        "confidence": "medium",
        "kc_subcodes": ["KC1.1", "KC5.1", "KC6.1.1"],
        "tool_inventory": [
            {"name": "lookup_order", "description": "Look up an order"},
            {"name": "process_refund", "description": "Process a refund"},
        ],
    }
    payload.update(overrides)
    return CapabilityProfile.model_validate(payload)


def _tool(name: str, description: str | None) -> McpToolObservation:
    return McpToolObservation(
        name=name,
        description=description,
        source_observation_sha256="1" * 64,
        input_schema={
            "type": "object",
            "properties": {"customer_id": {"type": "string"}},
        },
    )


def _profile(
    *,
    tools=("lookup_order", "process_refund", "escalate_to_human", "retrieve_policy"),
    interpretations=True,
) -> ExecutionTargetProfile:
    observations = tuple(_tool(name, f"Observed {name} tool") for name in tools)
    inventory = McpInventoryObservation(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        tools=observations,
    )
    resources = tuple(
        TargetProfileResource(
            resource_id=mcp_resource_id("target:mini", tool.name),
            target_id="target:mini",
            tool_name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
            operations=(
                TargetProfileOperation(
                    operation_id=tool.name,
                    semantic_operation=tool.name,
                    argument_names=("customer_id",),
                ),
            ),
            evidence_refs=(f"inventory:tool:{tool.name}",),
        )
        for tool in observations
    )
    interpretation_rows = ()
    if interpretations:
        interpretation_rows = tuple(
            TargetSemanticInterpretation(
                resource_id=resource.resource_id,
                tool_name=resource.tool_name,
                disposition="supported",
                likely_effect=(
                    "escalate" if resource.tool_name == "escalate_to_human" else "read"
                ),
                likely_state_effect="none",
                semantic_roles=(
                    ("text_search",) if resource.tool_name == "retrieve_policy" else ()
                ),
                evidence_refs=(f"inventory:tool:{resource.tool_name}",),
                rationale="typed test interpretation",
            )
            for resource in resources
        )
    return ExecutionTargetProfile(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        basis=ProfileBasis.target,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.inferred,
        inventory_completeness=InventoryCompleteness.observed_complete,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="scanner:test",
            interpreter_id="interpreter:test",
            verifier_id="verifier:test",
        ),
        inventory=inventory,
        resources=resources,
        interpretations=interpretation_rows,
    )


def _observations() -> TargetObservationSnapshot:
    state = {"authenticated_customer_id": "CUST001", "orders": {}}
    return TargetObservationSnapshot.create(
        target_profile_digest=_profile().semantic_digest,
        observations=[
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            )
        ],
    )


def _beliefs_response() -> dict:
    return {
        "controller_purpose": (
            "Help customers resolve order, refund, and payment questions within policy."
        ),
        "beliefs": [
            "Which orders belong to the current customer",
            "Whether an order is eligible for a refund",
        ],
        "belief_feedback": [
            {"belief_index": 0, "tool_name": "lookup_order"},
            {"belief_index": 1, "tool_name": None},
        ],
    }


def _relevance_response() -> dict:
    return {
        "relevance": [
            {
                "constraint_id": "SC-1",
                "actions": [
                    {
                        "action": "process_refund",
                        "reason": "the tool executes the refund",
                    }
                ],
            },
            {
                "constraint_id": "SC-2",
                "actions": [
                    {
                        "action": "lookup_order",
                        "reason": "the tool reads another customer's order",
                    }
                ],
            },
        ],
        "unconstrained_actions": [
            {
                "action": "retrieve_policy",
                "reason": "no supplied constraint governs the policy text",
            }
        ],
    }


def _setup_client() -> MockLLMClient:
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )

    client = MockLLMClient()
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(_RelevanceResponse, _relevance_response())
    return client


def _derive(tmp_path: Path, **kwargs):
    client = _setup_client()
    defaults = dict(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        target_observations=None,
        run_dir=tmp_path,
        temperature=0.4,
    )
    defaults.update(kwargs)
    return derive_target_structure(**defaults)


def test_mode_trigger_selects_target_derived_only_for_single_controller_target():
    profile = _profile()
    assert (
        target_derived_stage2_mode(_capability_profile(), profile) == "target_derived"
    )
    assert target_derived_stage2_mode(_capability_profile(), None) == "target_blind"
    assert (
        target_derived_stage2_mode(_capability_profile(), profile.model_copy())
        == "target_derived"
    )
    multi = _capability_profile(kc_subcodes=["KC1.1", "KC2.3"])
    assert target_derived_stage2_mode(multi, profile) == "target_blind"
    simulation = _profile().model_copy(update={"basis": ProfileBasis.simulation})
    assert (
        target_derived_stage2_mode(_capability_profile(), simulation) == "target_blind"
    )


def test_derived_structure_shape_and_bindings(tmp_path: Path):
    result = _derive(tmp_path)
    structure = result.control_structure
    assert len(structure.responsibilities) == 1
    resp = structure.responsibilities[0]
    assert resp.resp_id == "RESP-1"
    profile = _profile()
    tool_count = len(profile.resources)
    # One action per tool plus respond.
    assert len(resp.control_actions) == tool_count + 1
    assert len(structure.controlled_processes) == tool_count + 1
    assert structure.coordination_links == []
    respond = resp.control_actions[-1]
    assert respond.effect_kind is ControlActionEffectKind.model_output
    assert resp.security_constraint_refs == ["SC-1", "SC-2"]
    # Deterministic process model: session, conversation, retrieved policy
    # (text-search role present), one tool_result per tool, two beliefs.
    pm_ids = [pm.pm_id for pm in resp.process_model_parts]
    assert pm_ids[:3] == ["PM-1-1", "PM-1-2", "PM-1-3"]
    assert (
        len(
            [pm for pm in resp.process_model_parts if "Result of the" in pm.description]
        )
        == tool_count
    )
    assert check_structural_heuristics(structure, _loss_analysis()).passed
    # Every tool action carries the exact observed binding.
    bindings = {binding.name: binding for binding in result.derived.actions}
    assert bindings["respond"].resource_id is None
    assert bindings["process_refund"].resource_id == mcp_resource_id(
        "target:mini", "process_refund"
    )
    assert bindings["process_refund"].operation_id == "process_refund"
    assert bindings["respond"].kind == "model_output"
    # Sidecar pins match the live artifacts.
    assert result.derived.profile_digest == profile.semantic_digest
    assert result.derived.control_structure_digest == control_structure_content_digest(
        structure
    )
    assert result.derived.model_call_count == 2


def test_derivation_persists_artifacts(tmp_path: Path):
    _derive(tmp_path)
    sidecar = read_yaml(
        tmp_path / TARGET_DERIVED_STRUCTURE_FILENAME, TargetDerivedStructure
    )
    sidecar.assert_integrity()
    assert sidecar.target_id == "target:mini"
    assert (tmp_path / "control-structure.yaml").is_file()
    assert (tmp_path / "loss-analysis.yaml").is_file()
    relevance = read_yaml(
        tmp_path / CONSTRAINT_ACTION_RELEVANCE_FILENAME, ConstraintActionRelevance
    )
    relevance.assert_integrity()
    assert {row.constraint_id for row in relevance.relevance} == {"SC-1", "SC-2"}


def test_session_identity_grounded_in_target_state(tmp_path: Path):
    observations = _observations()
    result = _derive(tmp_path, target_observations=observations)
    session = result.derived.process_model[0]
    assert session.source == "session_identity"
    assert session.observed_path == ("authenticated_customer_id",)
    assert "CUST001" in session.description


def _accepted_subject_model(
    *,
    session_path=("authenticated_customer_id",),
    observations: TargetObservationSnapshot | None = None,
):
    """A minimal accepted subject model pinned to this file's fixtures."""
    from asago_scenario_generator.stpa.models.target_subject_model import (
        TargetSubjectModel,
        TargetSubjectModelAcceptance,
    )

    model = TargetSubjectModel(
        session_path=session_path,
        subject_noun="account holder",
        acceptance=TargetSubjectModelAcceptance(
            reviewed_by="qa",
            reviewed_on=date(2026, 9, 12),
            observations_digest=(observations or _observations()).content_digest,
            execution_target_profile_digest=_profile().semantic_digest,
            content_digest="0" * 64,
        ),
    )
    digest = model.compute_content_digest()
    return model.model_copy(
        update={
            "acceptance": model.acceptance.model_copy(
                update={"content_digest": digest}
            )
        }
    )


def test_session_subject_wording_is_target_neutral(tmp_path: Path):
    """PM-1-1 is the closed spec sentence, never an authorization claim
    (correction spec 1.2)."""
    result = _derive(tmp_path, target_observations=_observations())
    description = result.derived.process_model[0].description
    assert description == (
        "Session identity: TARGET-STATE records the session subject string "
        "'CUST001' at path ['authenticated_customer_id'] (discovered rule)."
    )
    assert "which customer" not in description.lower()
    assert "authorized" not in description.lower()


def test_unobserved_session_subject_wording_is_target_neutral(tmp_path: Path):
    state = {"orders": {"ORD-1": {"customer_id": "CUST001"}}}
    observations = TargetObservationSnapshot.create(
        target_profile_digest=_profile().semantic_digest,
        observations=[
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            )
        ],
    )
    result = _derive(tmp_path, target_observations=observations)
    session = result.derived.process_model[0]
    assert session.observed_path is None
    assert session.description == (
        "Session identity: no unique session-subject string was observed "
        "in the supplied target state (discovered rule)."
    )
    assert "customer" not in session.description.lower()


def test_declared_session_path_overrides_discovery(tmp_path: Path):
    state = {
        "authenticated_customer_id": "CUST001",
        "account": {"holder_id": "HOLD-9"},
    }
    observations = TargetObservationSnapshot.create(
        target_profile_digest=_profile().semantic_digest,
        observations=[
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            )
        ],
    )
    model = _accepted_subject_model(
        session_path=("account", "holder_id"), observations=observations
    )
    result = _derive(
        tmp_path, target_observations=observations, target_subject_model=model
    )
    session = result.derived.process_model[0]
    assert session.observed_path == ("account", "holder_id")
    assert "HOLD-9" in session.description
    assert "declared" in session.description
    # The discovered key beside the declared path never warns.
    assert not any(
        "ambiguous session identity" in warning for warning in result.derived.warnings
    )


def test_ambiguous_session_identity_warns_without_guessing(tmp_path: Path):
    state = {"authenticated_customer_id": "C1", "authenticated_account_id": "A1"}
    observations = TargetObservationSnapshot.create(
        target_profile_digest=_profile().semantic_digest,
        observations=[
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            )
        ],
    )
    result = _derive(tmp_path, target_observations=observations)
    session = result.derived.process_model[0]
    assert session.observed_path is None
    assert session.description == (
        "Session identity: no unique session-subject string was observed "
        "in the supplied target state (discovered rule). "
        "The session subject is ambiguous."
    )
    # Neither candidate string is ever quoted.
    assert "C1" not in session.description
    assert "A1" not in session.description
    assert any(
        "Session subject discovery is ambiguous" in warning
        for warning in result.derived.warnings
    )


def test_declared_session_path_missing_states_the_declared_rule(tmp_path: Path):
    model = _accepted_subject_model(session_path=("account", "holder_id"))
    result = _derive(
        tmp_path, target_observations=_observations(), target_subject_model=model
    )
    session = result.derived.process_model[0]
    assert session.observed_path is None
    assert session.description == (
        "Session identity: no unique session-subject string was observed "
        "in the supplied target state (declared rule)."
    )
    # The discovered key beside the missing declaration is never used.
    assert "CUST001" not in session.description


def test_subject_model_stamps_ride_the_sidecar_only_when_accepted(tmp_path: Path):
    result = _derive(tmp_path, target_observations=_observations())
    sidecar = read_yaml(
        tmp_path / TARGET_DERIVED_STRUCTURE_FILENAME, TargetDerivedStructure
    )
    sidecar.assert_integrity()
    assert sidecar.target_subject_model_digest is None
    assert sidecar.target_subject_model_reviewed_by is None

    model = _accepted_subject_model()
    stamped_dir = tmp_path / "stamped"
    stamped_dir.mkdir()
    _derive(stamped_dir, target_observations=_observations(), target_subject_model=model)
    stamped = read_yaml(
        stamped_dir / TARGET_DERIVED_STRUCTURE_FILENAME, TargetDerivedStructure
    )
    stamped.assert_integrity()
    assert stamped.target_subject_model_digest == model.compute_content_digest()
    assert stamped.target_subject_model_reviewed_by == "qa"
    assert stamped.target_subject_model_reviewed_on == date(2026, 9, 12)


def test_ungrounded_purpose_falls_back(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    client = _setup_client()
    client.set_response_for(
        _BeliefsResponse,
        {
            "controller_purpose": "Quantum flux coordination across neutrino arrays.",
            "beliefs": [],
            "belief_feedback": [],
        },
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert result.derived.controller.source == "deterministic_fallback"
    assert any("not grounded" in warning for warning in result.derived.warnings)


def test_numeric_belief_is_rejected(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    client = _setup_client()
    client.set_response_for(
        _BeliefsResponse,
        {
            "controller_purpose": (
                "Help customers resolve order, refund, and payment questions."
            ),
            "beliefs": ["Refunds over 100.00 need approval"],
            "belief_feedback": [],
        },
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    rejected = [belief for belief in result.derived.beliefs if not belief.accepted]
    assert len(rejected) == 1
    assert "numeric threshold" in rejected[0].reason


def test_relevance_post_rules_add_respond_and_escalation(tmp_path: Path):
    result = _derive(tmp_path)
    rows = {row.constraint_id: row for row in result.relevance.relevance}
    # SC-2 is a disclosure constraint: respond is added by rule.
    sc2_actions = {item.action for item in rows["SC-2"].actions}
    assert "respond" in sc2_actions
    # SC-1 is an unauthorized_write constraint naming a tool_call action.
    sc1_actions = {item.action for item in rows["SC-1"].actions}
    assert "process_refund" in sc1_actions
    # The escalation tool is added to missed_escalation constraints by rule;
    # neither constraint is one, so escalate_to_human stays unconstrained
    # unless the model named it.
    unconstrained = {item.action for item in result.relevance.unconstrained_actions}
    # Every action is either relevant or explicitly unconstrained by rule.
    named = sc1_actions | sc2_actions | unconstrained
    tool_names = {binding.name for binding in result.derived.actions}
    assert named == tool_names
    assert "escalate_to_human" in unconstrained
    assert "retrieve_policy" in unconstrained


def test_unauthorized_write_without_tool_action_gets_one_revision(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )

    client = MockLLMClient()
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    bad_relevance = {
        "relevance": [
            {
                "constraint_id": "SC-1",
                "actions": [{"action": "respond", "reason": "reply mentions refunds"}],
            },
            {
                "constraint_id": "SC-2",
                "actions": [{"action": "respond", "reason": "reply discloses orders"}],
            },
        ],
        "unconstrained_actions": [],
    }
    good_relevance = _relevance_response()
    client.set_response_for(
        _RelevanceResponse, [bad_relevance, bad_relevance, good_relevance]
    )
    with pytest.raises(Exception) as exc_info:
        derive_target_structure(
            llm_client=client,
            use_case_text=USE_CASE,
            loss_analysis=_loss_analysis(),
            capability_profile=_capability_profile(),
            execution_target_profile=_profile(),
            run_dir=tmp_path,
            temperature=0.4,
        )
    # SC-1 requires a tool_call action; the model twice named only respond,
    # so the second deterministic failure is fatal.
    assert "SC-1 is an unauthorized_write" in str(exc_info.value)


def test_conditional_actions_follow_capability_facts(tmp_path: Path):
    result = _derive(
        tmp_path,
        capability_profile=_capability_profile(kc_subcodes=["KC1.1", "KC4.3", "KC6.5"]),
    )
    names = {binding.name: binding for binding in result.derived.actions}
    assert "memory_write" in names
    assert "has_persistent_memory" in names["memory_write"].justification
    assert "KC6.5" in names["file_output"].justification
    assert names["memory_write"].kind == "state_change"
    assert names["file_output"].kind == "environment_action"


def test_identity_interpreter_replays_bindings(tmp_path: Path):
    result = _derive(tmp_path)
    interpreter = TargetDerivedIdentityInterpreter(result.derived)
    actions = result.control_structure.responsibilities[0].control_actions
    respond = actions[-1]
    tool_action = actions[0]
    unmapped = interpreter(action={"control_action_id": respond.ca_id}, operations=())
    assert unmapped.disposition is TargetRealizationDisposition.unmapped
    mapped = interpreter(action={"control_action_id": tool_action.ca_id}, operations=())
    assert mapped.disposition is TargetRealizationDisposition.supported
    assert mapped.selected_operation is not None
    assert mapped.verifier is not None and mapped.verifier.status == "verified"


def test_identity_realization_runs_through_the_pure_seam(tmp_path: Path):
    from asago_scenario_generator.models.target_realization import (
        SystemicStpaBaseline,
    )
    from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration

    result = _derive(tmp_path)
    structure = result.control_structure
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=result.loss_analysis,
        control_structure=structure,
        ica_enumeration=ICAEnumeration(slots=[]),
    )
    profile = _profile()
    realization = realize_target_operations(
        baseline,
        profile,
        lambda: TargetDerivedIdentityInterpreter(result.derived),
    )
    realization.assert_integrity()
    assert realization.profile_digest == profile.semantic_digest
    supported = {
        row.control_action_id
        for row in realization.rows
        if row.disposition is TargetRealizationDisposition.supported
    }
    tool_actions = {
        action.ca_id
        for action in structure.responsibilities[0].control_actions
        if action.effect_kind is ControlActionEffectKind.tool_call
    }
    assert supported == tool_actions
    respond_binding = result.derived.binding_for(
        structure.responsibilities[0].control_actions[-1].ca_id
    )
    assert respond_binding is not None and respond_binding.name == "respond"
    respond_row = next(
        row
        for row in realization.rows
        if row.control_action_id
        == structure.responsibilities[0].control_actions[-1].ca_id
    )
    assert respond_row.disposition is TargetRealizationDisposition.unmapped


def test_rejected_belief_requires_reason():
    with pytest.raises(ValueError, match="requires a reason"):
        BeliefRecord(pm_id="rejected-1", text="x", accepted=False, reason=None)


def test_sidecar_rejects_tampering(tmp_path: Path):
    result = _derive(tmp_path)
    payload = result.derived.model_dump(mode="json", exclude_none=True)
    payload["semantic_digest"] = "0" * 64
    tampered = TargetDerivedStructure.model_validate(payload)
    with pytest.raises(ValueError, match="digest mismatch"):
        tampered.assert_integrity()


def test_run_sp1_routes_stage2_to_the_derived_path(tmp_path: Path):
    from asago_scenario_generator.models.capability_profile import Stage1Profile
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
    from asago_scenario_generator.stpa.system_model.run import run_sp1
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )
    from tests.stpa.sp1_helpers import (
        read_calls_jsonl,
        valid_gap_draft_dict,
        valid_risk_draft_dict,
        valid_stage1_profile_dict,
    )

    client = MockLLMClient()
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(
        LossAnalysisDraft, [valid_risk_draft_dict(), valid_gap_draft_dict()]
    )
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(_RelevanceResponse, _relevance_response())

    result = run_sp1(
        llm_client=client,
        use_case_text=USE_CASE,
        risk_cards=[],
        run_dir=tmp_path,
        profile_path=None,
        execution_target_profile=_profile(),
        target_observations=None,
    )
    assert result.stage_errors == []
    assert result.control_structure is not None
    assert len(result.control_structure.responsibilities) == 1
    assert result.target_derived_structure is not None
    assert result.target_derived_structure.model_call_count == 2
    assert result.critic_findings is None
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    stage_2 = manifest["stage_summary"]["stage_2"]
    assert stage_2 == {"call_count": 2, "mode": "target_derived"}
    steps = [entry["step"] for entry in read_calls_jsonl(tmp_path)]
    # The four target-blind Stage 2 call steps never ran.
    assert "call_1_requirements" not in steps
    assert "call_3_coordination" not in steps
    assert "target_beliefs" in steps
    assert "target_relevance" in steps


def _sp1_client():
    from asago_scenario_generator.models.capability_profile import Stage1Profile
    from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysisDraft
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )
    from tests.stpa.sp1_helpers import (
        valid_gap_draft_dict,
        valid_risk_draft_dict,
        valid_stage1_profile_dict,
    )

    client = MockLLMClient()
    client.set_response_for(Stage1Profile, valid_stage1_profile_dict())
    client.set_response_for(
        LossAnalysisDraft, [valid_risk_draft_dict(), valid_gap_draft_dict()]
    )
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(_RelevanceResponse, _relevance_response())
    return client


def test_run_sp1_hashes_and_stamps_the_accepted_subject_model(tmp_path: Path):
    import hashlib

    from asago_scenario_generator.stpa.system_model.run import run_sp1

    model = _accepted_subject_model()
    model_path = tmp_path / "target-subject-model.yaml"
    model_path.write_text(
        yaml.safe_dump(model.model_dump(mode="json", exclude_none=True))
    )
    result = run_sp1(
        llm_client=_sp1_client(),
        use_case_text=USE_CASE,
        risk_cards=[],
        run_dir=tmp_path,
        profile_path=None,
        execution_target_profile=_profile(),
        target_observations=_observations(),
        target_subject_model=model,
        target_subject_model_path=model_path,
    )
    assert result.stage_errors == []
    manifest = yaml.safe_load((tmp_path / "run-manifest.yaml").read_text())
    assert manifest["input_hashes"]["target_subject_model"] == hashlib.sha256(
        model_path.read_bytes()
    ).hexdigest()
    sidecar = read_yaml(
        tmp_path / TARGET_DERIVED_STRUCTURE_FILENAME, TargetDerivedStructure
    )
    sidecar.assert_integrity()
    assert sidecar.target_subject_model_digest == model.compute_content_digest()
    assert sidecar.target_subject_model_reviewed_by == "qa"


def test_run_sp1_rejects_a_subject_model_without_a_target(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.run import run_sp1

    result = run_sp1(
        llm_client=_sp1_client(),
        use_case_text=USE_CASE,
        risk_cards=[],
        run_dir=tmp_path,
        profile_path=None,
        target_subject_model=_accepted_subject_model(),
    )
    assert any(
        "subject model" in error and "target-derived" in error
        for error in result.stage_errors
    )


def _relevance_payload(**overrides) -> dict:
    payload = _relevance_response()
    payload.update(overrides)
    return payload


def test_identity_ids_start_at_one(tmp_path: Path):
    result = _derive(tmp_path)
    structure = result.control_structure
    assert structure.responsibilities[0].control_actions[0].ca_id == "CA-1-1"
    assert structure.controlled_processes[0].cp_id == "CP-1"
    assert structure.responsibilities[0].feedback_channels[0].fb_id == "FB-1-1"
    relevance = read_yaml(
        tmp_path / CONSTRAINT_ACTION_RELEVANCE_FILENAME, ConstraintActionRelevance
    )
    assert relevance.model_call_count == 1
    assert result.derived.model_call_count == 2


def test_grounded_purpose_is_accepted(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    client = _setup_client()
    client.set_response_for(
        _BeliefsResponse,
        {
            "controller_purpose": (
                "Help customers ask about orders, payment plans, and refunds."
            ),
            "beliefs": [],
            "belief_feedback": [],
        },
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert result.derived.controller.source == "grounded_model"
    assert not any("not grounded" in warning for warning in result.derived.warnings)


def _default_realize(result, tmp_path: Path, *, profile=None, structure=None):
    """Call the synthesis-side sidecar realization branch."""
    from types import SimpleNamespace

    from asago_scenario_generator.pipeline.synthesis import _default_target_realize
    from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration

    return _default_target_realize(
        loss_analysis=result.loss_analysis,
        control_structure=structure or result.control_structure,
        ica_enumeration=ICAEnumeration(slots=[]),
        capability_profile=_capability_profile(),
        execution_target_profile=profile or _profile(),
        inputs=SimpleNamespace(),
        output_dir=tmp_path,
    )


def test_default_target_realize_replays_the_pinned_sidecar(tmp_path: Path):
    """The synthesis seam replays the sidecar with zero model calls."""
    result = _derive(tmp_path)
    structure = result.control_structure
    realization = _default_realize(result, tmp_path)
    realization.assert_integrity()
    assert realization.profile_digest == _profile().semantic_digest
    supported = {
        row.control_action_id
        for row in realization.rows
        if row.disposition is TargetRealizationDisposition.supported
    }
    unmapped = {
        row.control_action_id
        for row in realization.rows
        if row.disposition is TargetRealizationDisposition.unmapped
    }
    actions = structure.responsibilities[0].control_actions
    tool_actions = {
        action.ca_id
        for action in actions
        if action.effect_kind is ControlActionEffectKind.tool_call
    }
    respond_id = actions[-1].ca_id
    assert supported == tool_actions
    assert unmapped == {respond_id}


def test_default_target_realize_fails_closed_on_profile_mismatch(tmp_path: Path):
    from asago_scenario_generator.stpa.infra.llm_helpers import StageError

    result = _derive(tmp_path)
    other_profile = _profile(tools=("lookup_order", "process_refund"))
    with pytest.raises(StageError, match="does not match the execution target profile"):
        _default_realize(result, tmp_path, profile=other_profile)


def test_default_target_realize_fails_closed_on_structure_mismatch(tmp_path: Path):
    from asago_scenario_generator.stpa.infra.llm_helpers import StageError

    result = _derive(tmp_path)
    structure = result.control_structure
    resp = structure.responsibilities[0]
    tampered_action = resp.control_actions[0].model_copy(
        update={"description": "tampered description"}
    )
    tampered_resp = resp.model_copy(
        update={"control_actions": [tampered_action, *resp.control_actions[1:]]}
    )
    tampered = structure.model_copy(update={"responsibilities": [tampered_resp]})
    with pytest.raises(StageError, match="does not match the live control structure"):
        _default_realize(result, tmp_path, structure=tampered)


def test_bindings_carry_the_observed_argument_names(tmp_path: Path):
    result = _derive(tmp_path)
    bindings = {binding.name: binding for binding in result.derived.actions}
    assert bindings["process_refund"].argument_names == ("customer_id",)
    assert bindings["respond"].argument_names == ()


def test_session_identity_requires_json_and_string_id(tmp_path: Path):
    def snapshot(content_format: str, content: str) -> TargetObservationSnapshot:
        return TargetObservationSnapshot.create(
            target_profile_digest=_profile().semantic_digest,
            observations=[
                TargetObservation(
                    observation_ref="TARGET-STATE",
                    kind="state",
                    content_format=content_format,
                    content=content,
                )
            ],
        )

    # Valid JSON carried under a non-json format is not session identity.
    text_format = snapshot("text", json.dumps({"authenticated_customer_id": "C1"}))
    result = _derive(tmp_path, target_observations=text_format)
    assert result.derived.process_model[0].observed_path != (
        "authenticated_customer_id",
    )
    # A non-string authenticated_customer_id is not session identity either.
    numeric = snapshot("json", json.dumps({"authenticated_customer_id": 17}))
    result = _derive(tmp_path, target_observations=numeric)
    assert result.derived.process_model[0].observed_path != (
        "authenticated_customer_id",
    )


def test_belief_feedback_unknown_tool_is_dropped(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    client = _setup_client()
    payload = _beliefs_response()
    payload["belief_feedback"] = [
        {"belief_index": 0, "tool_name": "not_a_real_tool"},
        {"belief_index": 1, "tool_name": None},
    ]
    client.set_response_for(_BeliefsResponse, payload)
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert any("unknown tool" in warning for warning in result.derived.warnings)
    accepted = [record for record in result.derived.beliefs if record.accepted]
    assert all(record.feedback_tool is None for record in accepted)


def test_belief_feedback_known_tool_is_kept(tmp_path: Path):
    result = _derive(tmp_path)
    assert not any("unknown tool" in warning for warning in result.derived.warnings)
    feedback_tools = {
        record.feedback_tool for record in result.derived.beliefs if record.accepted
    }
    assert "lookup_order" in feedback_tools


def test_belief_feedback_out_of_range_index_warns(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    client = _setup_client()
    payload = _beliefs_response()
    payload["belief_feedback"] = [{"belief_index": 2, "tool_name": "lookup_order"}]
    client.set_response_for(_BeliefsResponse, payload)
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert any(
        "out-of-range belief index" in warning for warning in result.derived.warnings
    )
    accepted = [record for record in result.derived.beliefs if record.accepted]
    assert all(record.feedback_tool is None for record in accepted)


def test_duplicate_belief_is_rejected_as_duplicate(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    client = _setup_client()
    payload = _beliefs_response()
    payload["beliefs"] = [
        "Which orders belong to the current customer",
        "which orders belong to the current customer",
    ]
    client.set_response_for(_BeliefsResponse, payload)
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    rejected = [record for record in result.derived.beliefs if not record.accepted]
    assert any("duplicate" in (record.reason or "") for record in rejected)


def test_tool_without_description_has_no_none_placeholder(tmp_path: Path):
    tool = _tool("lookup_order", None)
    observations = (tool,)
    inventory = McpInventoryObservation(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        tools=observations,
    )
    resource = TargetProfileResource(
        resource_id=mcp_resource_id("target:mini", tool.name),
        target_id="target:mini",
        tool_name=tool.name,
        description=None,
        input_schema=tool.input_schema,
        surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
        operations=(
            TargetProfileOperation(
                operation_id=tool.name,
                semantic_operation=tool.name,
                argument_names=("customer_id",),
            ),
        ),
        evidence_refs=(f"inventory:tool:{tool.name}",),
    )
    base = _profile(tools=("lookup_order",))
    profile = base.model_copy(update={"resources": (resource,), "inventory": inventory})
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )

    client = _setup_client()
    client.set_response_for(
        _RelevanceResponse,
        {
            "relevance": [
                {
                    "constraint_id": "SC-1",
                    "actions": [
                        {
                            "action": "lookup_order",
                            "reason": "the tool reads the order",
                        }
                    ],
                },
                {
                    "constraint_id": "SC-2",
                    "actions": [
                        {
                            "action": "lookup_order",
                            "reason": "the tool reads another customer's order",
                        }
                    ],
                },
            ],
            "unconstrained_actions": [],
        },
    )
    result = _derive(
        tmp_path,
        llm_client=client,
        execution_target_profile=profile,
    )
    descriptions = [
        process.description for process in result.control_structure.controlled_processes
    ]
    assert all("None" not in description for description in descriptions)


def _patch_safe_llm_call(monkeypatch, behavior):
    """Replace safe_llm_call with a step-keyed scripted behavior."""
    import asago_scenario_generator.stpa.system_model.target_derived_structure as mod

    monkeypatch.setattr(mod, "safe_llm_call", behavior)


def test_beliefs_error_with_result_is_treated_as_failure(monkeypatch, tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    def behavior(**kwargs):
        if kwargs["step"] == "target_beliefs":
            return _BeliefsResponse.model_validate(_beliefs_response()), "", "boom"
        from asago_scenario_generator.stpa.system_model.target_derived_structure import (
            _RelevanceResponse,
        )

        return _RelevanceResponse.model_validate(_relevance_response()), "", None

    _patch_safe_llm_call(monkeypatch, behavior)
    result = _derive(tmp_path)
    assert any("Beliefs call failed" in warning for warning in result.derived.warnings)
    assert result.derived.controller.source == "deterministic_fallback"


def test_relevance_error_with_result_triggers_revision(monkeypatch, tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _RelevanceResponse,
    )

    calls = {"relevance": 0}

    def behavior(**kwargs):
        if kwargs["step"] == "target_relevance":
            calls["relevance"] += 1
            if calls["relevance"] == 1:
                return (
                    _RelevanceResponse.model_validate(_relevance_response()),
                    "",
                    "boom",
                )
            return _RelevanceResponse.model_validate(_relevance_response()), "", None
        return None, "", "no-op"

    _patch_safe_llm_call(monkeypatch, behavior)
    result = _derive(tmp_path)
    assert any(
        "failed deterministic checks" in warning for warning in result.derived.warnings
    )
    # The exact first-attempt error text is retained in the revision warning.
    assert any("boom" in warning for warning in result.derived.warnings)
    assert calls["relevance"] == 2
    assert result.relevance.model_call_count == 2
    assert result.derived.model_call_count == 3


def test_relevance_revision_error_with_result_fails_the_stage(
    monkeypatch, tmp_path: Path
):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _RelevanceResponse,
    )
    from asago_scenario_generator.stpa.system_model.run import StageError

    calls = {"relevance": 0}

    def behavior(**kwargs):
        if kwargs["step"] == "target_relevance":
            calls["relevance"] += 1
            if calls["relevance"] == 1:
                return None, "", "first attempt failed"
            return _RelevanceResponse.model_validate(_relevance_response()), "", "boom"
        return None, "", "no-op"

    _patch_safe_llm_call(monkeypatch, behavior)
    with pytest.raises(StageError, match="failed twice"):
        _derive(tmp_path)


def test_empty_row_without_reason_fails_validation_and_retries(
    tmp_path: Path,
):
    """An empty actions list without a reason is a schema failure, not a
    defect: the provider must state why it asserts no relevant action."""
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )

    client = MockLLMClient()
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(
        _RelevanceResponse,
        [
            _relevance_payload(
                relevance=[
                    {"constraint_id": "SC-1", "actions": []},
                    {
                        "constraint_id": "SC-2",
                        "actions": [
                            {
                                "action": "lookup_order",
                                "reason": "the tool reads another customer's order",
                            }
                        ],
                    },
                ],
            ),
            _relevance_response(),
        ],
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert any(
        "no_relevant_action_reason" in warning for warning in result.derived.warnings
    )
    assert result.relevance.model_call_count == 2


def test_classified_empty_row_with_reason_defects_and_triggers_revision(
    tmp_path: Path,
):
    """A typed empty row is only honest for unclassified constraints; a
    classified constraint has post-rules that must be able to name an action.
    """
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )

    client = MockLLMClient()
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(
        _RelevanceResponse,
        [
            _relevance_payload(
                relevance=[
                    {
                        "constraint_id": "SC-1",
                        "actions": [],
                        "no_relevant_action_reason": (
                            "no supplied action can cause a refund"
                        ),
                    },
                    {
                        "constraint_id": "SC-2",
                        "actions": [
                            {
                                "action": "lookup_order",
                                "reason": "the tool reads another customer's order",
                            }
                        ],
                    },
                ],
            ),
            _relevance_response(),
        ],
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert any(
        "classified constraint and must name at least one action" in warning
        for warning in result.derived.warnings
    )
    assert result.relevance.model_call_count == 2


def test_missing_relevance_row_is_a_defect():
    """A constraint absent from the provider table fails the row rule."""
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _RelevanceResponse,
        _augment_relevance,
        _relevance_defects,
    )

    loss = _loss_analysis()
    rows, _unconstrained = _augment_relevance(
        _RelevanceResponse.model_validate(_relevance_payload()),
        loss,
        [],
        {},
        [],
    )
    defects = _relevance_defects(rows[:1], loss, [], {})
    assert any("SC-2 has no relevant action" in defect for defect in defects), defects


def test_unclassified_empty_row_with_reason_is_accepted(tmp_path: Path):
    """An unclassified constraint may carry a typed honest empty row: no
    defect, no revision, and the reason is published with the row."""
    from asago_scenario_generator.stpa.models.target_derived_structure import (
        ConstraintRelevanceRow,
    )
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )

    loss_analysis = _loss_analysis()
    unclassified = SecurityConstraint(
        constraint_id="SC-3",
        rule="The assistant must respond within five seconds.",
        related_hazards=["H-1"],
        qualifiers=[],
    )
    loss_analysis.security_constraints.append(unclassified)

    client = MockLLMClient()
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(
        _RelevanceResponse,
        _relevance_payload(
            relevance=[
                *_relevance_response()["relevance"],
                {
                    "constraint_id": "SC-3",
                    "actions": [],
                    "no_relevant_action_reason": (
                        "no supplied action changes response latency"
                    ),
                },
            ],
        ),
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=loss_analysis,
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert result.relevance.model_call_count == 1
    row = next(
        item for item in result.relevance.relevance if item.constraint_id == "SC-3"
    )
    assert row.actions == ()
    assert row.no_relevant_action_reason == (
        "no supplied action changes response latency"
    )
    published = read_yaml(
        tmp_path / CONSTRAINT_ACTION_RELEVANCE_FILENAME, ConstraintActionRelevance
    )
    published_row = next(
        item for item in published.relevance if item.constraint_id == "SC-3"
    )
    assert isinstance(published_row, ConstraintRelevanceRow)
    assert published_row.no_relevant_action_reason == (
        "no supplied action changes response latency"
    )


def test_missed_escalation_constraint_does_not_gain_respond(tmp_path: Path):
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
        _RelevanceResponse,
    )

    client = MockLLMClient()
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(
        _RelevanceResponse,
        _relevance_payload(
            relevance=[
                {
                    "constraint_id": "SC-1",
                    "actions": [
                        {
                            "action": "escalate_to_human",
                            "reason": "the escalation tool satisfies it",
                        }
                    ],
                },
                {
                    "constraint_id": "SC-2",
                    "actions": [
                        {
                            "action": "lookup_order",
                            "reason": "the tool reads another customer's order",
                        }
                    ],
                },
            ],
        ),
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    rows = {row.constraint_id: row for row in result.relevance.relevance}
    assert [item.action for item in rows["SC-1"].actions] == ["escalate_to_human"]


def test_purpose_grounding_share_boundary_is_grounded(tmp_path: Path):
    """A purpose with exactly the grounding threshold stays the model's."""
    from asago_scenario_generator.stpa.system_model.target_derived_structure import (
        _BeliefsResponse,
    )

    client = _setup_client()
    client.set_response_for(
        _BeliefsResponse,
        {
            "controller_purpose": "Refunds elephantously.",
            "beliefs": [],
            "belief_feedback": [],
        },
    )
    result = derive_target_structure(
        llm_client=client,
        use_case_text=USE_CASE,
        loss_analysis=_loss_analysis(),
        capability_profile=_capability_profile(),
        execution_target_profile=_profile(),
        run_dir=tmp_path,
        temperature=0.4,
    )
    assert result.derived.controller.source == "grounded_model"
