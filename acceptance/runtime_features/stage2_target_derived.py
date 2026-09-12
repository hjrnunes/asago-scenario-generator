"""Offline acceptance handlers for the Phase 2 target-derived Stage 2 path."""

from __future__ import annotations

import json
from pathlib import Path

import yaml
from runtime_shared import _SP1MockLLM, _tempfile

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
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
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.target_derived_structure import (
    CONSTRAINT_ACTION_RELEVANCE_FILENAME,
    TARGET_DERIVED_STRUCTURE_FILENAME,
    control_structure_content_digest,
)
from asago_scenario_generator.stpa.scenario_prod.target_observations import (
    TargetObservation,
    TargetObservationSnapshot,
)
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.target_derived_structure import (
    _BeliefsResponse,
    _RelevanceResponse,
    derive_target_structure,
)
from tests.stpa.sp1_helpers import (
    setup_sp1_mock_client,
)

FEATURE_ID = "stage2_target_derived"

_USE_CASE = (
    "MiniKlarna is a customer-support assistant for a buy-now-pay-later "
    "service. Customers ask about orders, payment plans, refunds, and "
    "policies. The assistant answers with the supplied tools and escalates "
    "regulated topics to a human agent."
)

_TOOLS = ("lookup_order", "process_refund", "escalate_to_human", "retrieve_policy")


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis.model_validate(
        {
            "risk_card_losses": [
                {
                    "loss_id": "L-1",
                    "description": "Unauthorized refund execution",
                    "provenance": "risk_card",
                    "source_risk_cards": ["atlas-001"],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-1",
                    "description": (
                        "The assistant executes a refund outside the refund policy."
                    ),
                    "related_losses": ["L-1"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-1",
                    "rule": (
                        "The assistant must process a refund only for an "
                        "eligible order owned by the authenticated customer."
                    ),
                    "related_hazards": ["H-1"],
                    "qualifiers": ["eligible order"],
                    "applies_when": [],
                },
                {
                    "constraint_id": "SC-2",
                    "rule": (
                        "The assistant must escalate every regulated topic to "
                        "a human agent instead of improvising."
                    ),
                    "related_hazards": ["H-1"],
                    "applies_when": [],
                },
                {
                    "constraint_id": "SC-3",
                    "rule": (
                        "The assistant must not disclose another customer's "
                        "order information to an unauthorized recipient."
                    ),
                    "related_hazards": ["H-1"],
                    "qualifiers": ["unauthorized recipient"],
                    "applies_when": [],
                },
            ],
        }
    )


def _capability_profile(kc_subcodes=None) -> CapabilityProfile:
    return CapabilityProfile.model_validate(
        {
            "zones_active": ["input", "reasoning", "tool_execution"],
            "entry_points": [
                {
                    "name": "User chat",
                    "direction": "input",
                    "controllability": "direct",
                },
            ],
            "confidence": "medium",
            "kc_subcodes": kc_subcodes or ["KC1.1", "KC5.1", "KC6.1.1"],
            "tool_inventory": [
                {"name": "lookup_order", "description": "Look up an order"},
                {"name": "process_refund", "description": "Process a refund"},
            ],
        }
    )


def _target_profile() -> ExecutionTargetProfile:
    observations = tuple(
        McpToolObservation(
            name=name,
            description=f"Observed {name} tool",
            source_observation_sha256="1" * 64,
            input_schema={
                "type": "object",
                "properties": {"customer_id": {"type": "string"}},
            },
        )
        for name in _TOOLS
    )
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
    interpretations = tuple(
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
            rationale="typed acceptance interpretation",
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
            scanner_id="scanner:acceptance",
            interpreter_id="interpreter:acceptance",
            verifier_id="verifier:acceptance",
        ),
        inventory=inventory,
        resources=resources,
        interpretations=interpretations,
    )


def _beliefs_response() -> dict:
    return {
        "controller_purpose": (
            "Help customers resolve order, refund, and payment questions within policy."
        ),
        "beliefs": [
            {
                "text": "Which orders belong to the current customer",
                "feedback_tool": "lookup_order",
            }
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
                "actions": [{"action": "respond", "reason": "the reply can improvise"}],
            },
            {
                "constraint_id": "SC-3",
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


def _observations_snapshot() -> TargetObservationSnapshot:
    state = {"authenticated_customer_id": "CUST001", "orders": {}}
    return TargetObservationSnapshot.create(
        target_profile_digest=_target_profile().semantic_digest,
        observations=[
            TargetObservation(
                observation_ref="TARGET-STATE",
                kind="state",
                content_format="json",
                content=json.dumps(state),
            )
        ],
    )


def _setup_client(world) -> _SP1MockLLM:
    client = _SP1MockLLM()
    client.set_response_for(_BeliefsResponse, _beliefs_response())
    client.set_response_for(_RelevanceResponse, _relevance_response())
    return client


def _given_profile(world, step, examples):
    del step, examples
    world.tds_dir = Path(_tempfile.mkdtemp(prefix="target_derived_stage2_"))
    world.tds_client = _setup_client(world)
    world.tds_error = None
    return True, ""


def _derive(world, **kwargs):
    try:
        world.tds_result = derive_target_structure(
            llm_client=world.tds_client,
            use_case_text=_USE_CASE,
            loss_analysis=kwargs.get("loss_analysis") or _loss_analysis(),
            capability_profile=kwargs.get("capability_profile")
            or _capability_profile(),
            execution_target_profile=kwargs.get("execution_target_profile")
            or _target_profile(),
            target_observations=kwargs.get("target_observations"),
            run_dir=world.tds_dir,
            template_loader=TemplateLoader(PROMPTS_DIR),
            temperature=0.4,
        )
    except Exception as exc:  # noqa: BLE001 - acceptance records the failure
        world.tds_error = exc
        world.tds_result = None
    return world.tds_result


def _when_derivation_runs(world, step, examples):
    del step, examples
    _derive(world)
    return True, ""


def _then_one_controller(world, step, examples):
    del step, examples
    structure = world.tds_result.control_structure
    assert len(structure.responsibilities) == 1
    return True, ""


def _then_actions_per_tool(world, step, examples):
    del step, examples
    structure = world.tds_result.control_structure
    actions = structure.responsibilities[0].control_actions
    assert len(actions) == len(_TOOLS) + 1
    respond = actions[-1]
    assert respond.effect_kind.value == "model_output"
    return True, ""


def _then_no_links(world, step, examples):
    del step, examples
    assert world.tds_result.control_structure.coordination_links == []
    return True, ""


def _then_bindings(world, step, examples):
    del step, examples
    structure = world.tds_result.control_structure
    bindings = {binding.ca_id: binding for binding in world.tds_result.derived.actions}
    for action in structure.responsibilities[0].control_actions:
        binding = bindings[action.ca_id]
        if action.effect_kind.value == "tool_call":
            assert binding.resource_id is not None
            assert binding.operation_id is not None
            assert action.description.startswith(binding.name)
        else:
            assert binding.resource_id is None
    return True, ""


def _then_sidecar_pins(world, step, examples):
    del step, examples
    sidecar = world.tds_result.derived
    sidecar.assert_integrity()
    assert sidecar.profile_digest == _target_profile().semantic_digest
    assert sidecar.control_structure_digest == control_structure_content_digest(
        world.tds_result.control_structure
    )
    persisted = yaml.safe_load(
        (world.tds_dir / TARGET_DERIVED_STRUCTURE_FILENAME).read_text()
    )
    assert persisted["target_id"] == "target:mini"
    return True, ""


def _then_two_calls(world, step, examples):
    del step, examples
    assert world.tds_result.derived.model_call_count == 2
    steps = [entry["step"] for entry in _read_calls(world.tds_dir)]
    assert steps.count("target_beliefs") == 1
    assert steps.count("target_relevance") == 1
    return True, ""


def _then_no_blind_steps(world, step, examples):
    del step, examples
    steps = [entry["step"] for entry in _read_calls(world.tds_dir)]
    for step_name in (
        "call_1_requirements",
        "call_2a_responsibilities",
        "call_2b_control_elements",
        "call_3_coordination",
    ):
        assert step_name not in steps
    return True, ""


def _read_calls(run_dir: Path) -> list[dict]:
    calls_file = run_dir / "calls.jsonl"
    if not calls_file.exists():
        return []
    return [json.loads(line) for line in calls_file.read_text().splitlines()]


def _given_capability_facts(world, step, examples):
    del step, examples
    world.tds_dir = Path(_tempfile.mkdtemp(prefix="target_derived_stage2_"))
    world.tds_client = _setup_client(world)
    world.tds_error = None
    world.tds_capability = _capability_profile(kc_subcodes=["KC1.1", "KC4.3", "KC6.5"])
    return True, ""


def _derive_with_capability(world, step, examples):
    del step, examples
    _derive(world, capability_profile=world.tds_capability)
    return True, ""


def _then_memory_write(world, step, examples):
    del step, examples
    bindings = {item.name: item for item in world.tds_result.derived.actions}
    assert "memory_write" in bindings
    assert "has_persistent_memory" in bindings["memory_write"].justification
    return True, ""


def _then_file_output(world, step, examples):
    del step, examples
    bindings = {item.name: item for item in world.tds_result.derived.actions}
    assert "file_output" in bindings
    assert "KC6.5" in bindings["file_output"].justification
    return True, ""


def _given_observations(world, step, examples):
    del step, examples
    world.tds_dir = Path(_tempfile.mkdtemp(prefix="target_derived_stage2_"))
    world.tds_client = _setup_client(world)
    world.tds_error = None
    world.tds_observations = _observations_snapshot()
    return True, ""


def _derive_with_observations(world, step, examples):
    del step, examples
    _derive(world, target_observations=world.tds_observations)
    return True, ""


def _then_session_identity(world, step, examples):
    del step, examples
    session = world.tds_result.derived.process_model[0]
    assert session.source == "session_identity"
    assert session.observed_path == ("authenticated_customer_id",)
    assert "CUST001" in session.description
    return True, ""


def _then_relevance_respond(world, step, examples):
    del step, examples
    relevance = world.tds_result.relevance
    rows = {row.constraint_id: row for row in relevance.relevance}
    actions = {item.action for item in rows["SC-3"].actions}
    assert "respond" in actions
    origins = {item.action: item.origin for item in rows["SC-3"].actions}
    assert origins["respond"] == "rule"
    return True, ""


def _then_relevance_escalation(world, step, examples):
    del step, examples
    relevance = world.tds_result.relevance
    rows = {row.constraint_id: row for row in relevance.relevance}
    actions = {item.action for item in rows["SC-2"].actions}
    assert "escalate_to_human" in actions
    return True, ""


def _then_relevance_pinned(world, step, examples):
    del step, examples
    relevance = world.tds_result.relevance
    relevance.assert_integrity()
    assert (world.tds_dir / CONSTRAINT_ACTION_RELEVANCE_FILENAME).is_file()
    persisted = yaml.safe_load(
        (world.tds_dir / CONSTRAINT_ACTION_RELEVANCE_FILENAME).read_text()
    )
    assert persisted["control_structure_digest"] == (
        control_structure_content_digest(world.tds_result.control_structure)
    )
    return True, ""


def _given_no_profile(world, step, examples):
    del step, examples
    world.tds_blind_dir = Path(_tempfile.mkdtemp(prefix="target_blind_stage2_"))
    world.tds_blind_client = setup_sp1_mock_client()
    return True, ""


def _when_sp1_runs(world, step, examples):
    del step, examples
    from asago_scenario_generator.stpa.system_model.run import run_sp1

    world.tds_blind_result = run_sp1(
        llm_client=world.tds_blind_client,
        use_case_text="A service receives a request and records its result.",
        risk_cards=[],
        run_dir=world.tds_blind_dir,
    )
    return True, ""


def _then_blind_mode(world, step, examples):
    del step, examples
    manifest = yaml.safe_load((world.tds_blind_dir / "run-manifest.yaml").read_text())
    stage_2 = manifest["stage_summary"]["stage_2"]
    assert stage_2["mode"] == "target_blind"
    assert stage_2["call_count"] >= 4
    return True, ""


def _then_blind_steps(world, step, examples):
    del step, examples
    steps = [entry["step"] for entry in _read_calls(world.tds_blind_dir)]
    for step_name in (
        "call_1_requirements",
        "call_2a_responsibilities",
        "call_2b_control_elements",
        "call_3_coordination",
    ):
        assert step_name in steps
    return True, ""


def register(api):
    """Register the Phase 2 target-derived Stage 2 acceptance steps."""
    api.register(
        r"^an observed execution target profile for a single-controller system$",
        _given_profile,
    )
    api.register(
        r"^the target-derived Stage 2 derivation runs against a mock provider$",
        _when_derivation_runs,
    )
    api.register(
        r"^the derived control structure has exactly one controller$",
        _then_one_controller,
    )
    api.register(
        r"^the derived control structure has one action per observed tool "
        r"plus a reply action$",
        _then_actions_per_tool,
    )
    api.register(
        r"^the derived control structure has no coordination links$",
        _then_no_links,
    )
    api.register(
        r"^every tool action records its exact observed operation binding$",
        _then_bindings,
    )
    api.register(
        r"^the target-derived sidecar pins the target profile and control "
        r"structure digests$",
        _then_sidecar_pins,
    )
    api.register(
        r"^the derivation records exactly two model calls$",
        _then_two_calls,
    )
    api.register(
        r"^no target-blind Stage 2 call step is recorded$",
        _then_no_blind_steps,
    )
    api.register(
        r"^a capability profile declaring persistent memory and filesystem "
        r"operations$",
        _given_capability_facts,
    )
    api.register(
        r"^the derived structure adds a memory_write action justified by "
        r"persistent memory$",
        _then_memory_write,
    )
    api.register(
        r"^the derived structure adds a file_output action justified by the "
        r"filesystem subcode$",
        _then_file_output,
    )
    api.register(
        r"^a target-observations snapshot naming the authenticated customer$",
        _given_observations,
    )
    api.register(
        r"^the session identity process model cites the observed authenticated "
        r"customer$",
        _then_session_identity,
    )
    api.register(
        r"^the reply action is relevant to every disclosure constraint$",
        _then_relevance_respond,
    )
    api.register(
        r"^the escalation tool is named by the escalation constraint$",
        _then_relevance_escalation,
    )
    api.register(
        r"^the relevance artifact is pinned to the loss analysis and control "
        r"structure$",
        _then_relevance_pinned,
    )
    api.register(
        r"^no execution target profile$",
        _given_no_profile,
    )
    api.register(
        r"^the ordinary SP1 pipeline runs against a mock provider$",
        _when_sp1_runs,
    )
    api.register(
        r"^the manifest records the target-blind Stage 2 mode$",
        _then_blind_mode,
    )
    api.register(
        r"^the target-blind Stage 2 call steps are recorded$",
        _then_blind_steps,
    )
    # Capability-fact and observation scenarios need a different When.
    api.register(
        r"^the target-derived Stage 2 derivation runs with the declared "
        r"capability facts$",
        _derive_with_capability,
    )
    api.register(
        r"^the target-derived Stage 2 derivation runs with the observed "
        r"session state$",
        _derive_with_observations,
    )
