"""Tests for the STPA producer seams around Stage 5 and target-profile publication."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_spec import (
    AttackerBDI,
    DefenderBDI,
    DefenderBelief,
    DefenderDesire,
    DefenderIntention,
    ScenarioSpec,
    ThreatSource,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ControlledProcess,
    ElementRef,
    ReferenceType,
)
from asago_scenario_generator.models.canonical import canonical_json_bytes
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
)
from tests.stpa.helpers import make_minimal_loss_analysis
from asago_scenario_generator.stpa.models.semantic_conditions import (
    DelayCondition,
    SemanticBindingPlaceholder,
    SemanticBindingValueType,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionActionKind,
    ExecutionDeliveryClass,
    ExecutionTargetProfile,
    DiscoveryProvenance,
    InventoryAuthority,
    InventoryCompleteness,
    McpInventoryObservation,
    McpToolObservation,
    ProfileBasis,
    RequestedEnvironmentBasis,
    SemanticAuthority,
    SourceProtocol,
    TargetInterpretationDisposition,
    TargetOperationEffect,
    TargetProfileOperation,
    TargetProfileResource,
    TargetStateEffect,
    mcp_resource_id,
    SemanticExecutionContract,
    SemanticExecutionDelivery,
)
from asago_scenario_generator.models.target_realization import (
    TargetOperationObservation,
    TargetOperationRecord,
    TargetOperationReference,
    TargetRealizationDisposition,
    TargetRealizationResult,
    TargetRealizationRow,
    TargetRealizationSummary,
)
from asago_scenario_generator.stpa.scenario_prod.target_profile_publication import (
    publish_execution_target_profile,
)
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    build_context_bdi_prompts,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.scenario_prod._constants import PROMPTS_DIR
from tests.stpa.helpers import make_minimal_control_structure
from asago_scenario_generator.stpa.scenario_prod.run import (
    _target_operation_for_context,
)
from asago_scenario_generator.stpa.scenario_prod.realized_operation import (
    operation_for_supported_row,
)


CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/target-profile"


def _control_structure() -> ControlStructure:
    base = make_minimal_control_structure()
    action = (
        base.responsibilities[0]
        .control_actions[0]
        .model_copy(
            update={
                "target": ElementRef(
                    type=ReferenceType.controlled_process,
                    id="CP-1",
                )
            }
        )
    )
    responsibility = base.responsibilities[0].model_copy(
        update={"control_actions": [action]}
    )
    return base.model_copy(
        update={
            "responsibilities": [responsibility],
            "controlled_processes": [
                ControlledProcess(cp_id="CP-1", description="Process")
            ],
        }
    )


def _spec(
    *,
    ica_type: UCAType = UCAType.wrong_timing,
    unsafe_outcome_condition=None,
) -> ScenarioSpec:
    control_structure = _control_structure()
    slot = f"RESP-1:CA-1-1:{ica_type.value}"
    threat = StructuralThreat(
        ica_slot_id=slot,
        provenance="structural",
        ica_id=f"{slot}:1",
        ica_text="Unsafe control action",
        hazardous_context="Context",
        loss_scenario="Loss scenario",
        related_hazards=["H-1"],
        related_constraints=["SC-1"],
    )
    context = build_scenario_generation_context(
        threat,
        control_structure,
        make_minimal_loss_analysis(),
        scenario_id="SCN-001",
    )
    return ScenarioSpec(
        scenario_id="SCN-001",
        threat_source=ThreatSource(
            ica_slot_id=threat.ica_slot_id,
            provenance=threat.provenance,
            ica_id=threat.ica_id,
        ),
        target_controller="RESP-1",
        target_control_action="CA-1-1",
        ica_type=ica_type,
        defender_bdi=DefenderBDI(
            beliefs=[DefenderBelief(pm_id="PM-1-1", content="State", vulnerability="")],
            desires=[DefenderDesire(resp_id="RESP-1", content="Controller")],
            intentions=[DefenderIntention(ca_id="CA-1-1", content="Action")],
        ),
        attacker_bdi=AttackerBDI(
            beliefs=["belief"], desires=["desire"], intentions=["intent"]
        ),
        loss_scenario="Loss scenario",
        causal_factors=[
            CausalFactor(
                kind=CausalFactorKind.feedback_delay,
                source_id="FB-1-1",
                description="Feedback is delayed.",
            )
        ],
        unsafe_outcome_condition=unsafe_outcome_condition
        or DelayCondition(
            reference_ref="FB-1-1",
            delay_ms=SemanticBindingPlaceholder(
                binding_ref="SEM-1",
                value_type="integer",
                description="Maximum supported feedback delay.",
                minimum=0,
            ),
        ),
        unsafe_outcome_semantic_proposition=(
            "The response exhibits the unsafe semantic behavior."
        ),
        unsafe_outcome_hazard_refs=[item.hazard_id for item in context.hazards],
        unsafe_outcome_constraint_refs=[
            item.constraint_id for item in context.constraints
        ],
        scenario_context=context,
        execution_contract=SemanticExecutionContract(
            requested_environment_basis=RequestedEnvironmentBasis.target_agnostic,
            delivery=SemanticExecutionDelivery(
                delivery_class=ExecutionDeliveryClass.direct_prompt,
                factor_id="CF-1",
                source_role="direct_user_input",
            ),
            action_kind=ExecutionActionKind.model_output,
        ),
    )


def _target_profile_fixture() -> ExecutionTargetProfile:
    """Load the producer-owned target profile contract fixture."""
    payload = json.loads(
        (CONTRACT_ROOT / "target-profile-v1/valid/minimal.json").read_text(
            encoding="utf-8"
        )
    )
    for tool in payload["inventory"]["tools"]:
        tool.setdefault(
            "source_observation_sha256",
            hashlib.sha256(
                canonical_json_bytes(
                    {
                        key: value
                        for key, value in tool.items()
                        if key != "source_observation_sha256"
                    }
                )
            ).hexdigest(),
        )
    payload["inventory"].pop("semantic_digest", None)
    inventory = McpInventoryObservation.model_validate(payload["inventory"])
    payload["inventory"] = inventory.model_dump(mode="json")
    payload["source_inventory_digest"] = inventory.semantic_digest
    payload.pop("semantic_digest", None)
    return ExecutionTargetProfile.model_validate(payload)


def _target_realization_fixture(
    profile: ExecutionTargetProfile,
) -> TargetRealizationResult:
    """Build an empty, digest-bearing realization for pin-only tests."""
    return TargetRealizationResult(
        baseline_id="baseline-fixture",
        baseline_digest="b" * 64,
        profile_id=profile.profile_id,
        profile_digest=profile.semantic_digest,
        summary=TargetRealizationSummary(
            baseline_control_actions=0,
            observed_operations=0,
            supported=0,
            ambiguous=0,
            unmapped=0,
            contradictory=0,
        ),
    )


def _supported_target_realization_fixture(
    profile: ExecutionTargetProfile,
) -> TargetRealizationResult:
    """Build the exact supported row needed by a target-bound contract."""
    operation_ref = TargetOperationReference(
        resource_id="mcp:fixture-target:process_refund",
        operation_id="process_refund",
    )
    operation = TargetOperationObservation(
        reference=operation_ref,
        description="Process a refund.",
        argument_names=("amount", "order_id"),
        effect="update",
        state_effect="changes",
        state_changing=True,
        evidence_refs=("inventory:tool:process_refund",),
    )
    return TargetRealizationResult(
        baseline_id="baseline-fixture",
        baseline_digest="b" * 64,
        profile_id=profile.profile_id,
        profile_digest=profile.semantic_digest,
        rows=(
            TargetRealizationRow(
                control_action_id="CA-1-1",
                controller_id="RESP-1",
                disposition=TargetRealizationDisposition.supported,
                candidate_operations=(operation_ref,),
                selected_operation=operation_ref,
                evidence_refs=("inventory:tool:process_refund",),
            ),
        ),
        operation_records=(
            TargetOperationRecord(
                operation=operation,
                disposition=TargetRealizationDisposition.supported,
                baseline_control_action_ids=("CA-1-1",),
                evidence_refs=("inventory:tool:process_refund",),
            ),
        ),
        summary=TargetRealizationSummary(
            baseline_control_actions=1,
            observed_operations=1,
            supported=1,
            ambiguous=0,
            unmapped=0,
            contradictory=0,
        ),
    )


def test_stage5_target_operation_resolver_uses_supported_baseline_row() -> None:
    """Stage 5 receives the exact operation selected for a baseline action."""
    realization = _supported_target_realization_fixture(_target_profile_fixture())
    context = SimpleNamespace(
        target_control_path=SimpleNamespace(
            control_action=SimpleNamespace(action_id="CA-1-1")
        )
    )

    operation = _target_operation_for_context(realization, context)

    assert operation is not None
    assert operation.operation_id == "process_refund"


def test_stage5_target_operation_resolver_returns_none_without_a_selection() -> None:
    """An action without a baseline or derived selection remains unbound."""
    realization = _target_realization_fixture(_target_profile_fixture())
    context = SimpleNamespace(
        target_control_path=SimpleNamespace(
            control_action=SimpleNamespace(action_id="CA-1-1")
        )
    )

    assert _target_operation_for_context(realization, context) is None


def test_stage5_target_operation_resolver_rejects_unrecorded_selection() -> None:
    """A selected operation must have exactly one corresponding observation."""
    operation_ref = TargetOperationReference(
        resource_id="mcp:fixture-target:process_refund",
        operation_id="process_refund",
    )
    row = TargetRealizationRow(
        control_action_id="CA-1-1",
        controller_id="RESP-1",
        disposition=TargetRealizationDisposition.supported,
        candidate_operations=(operation_ref,),
        selected_operation=operation_ref,
    )

    with pytest.raises(ValueError, match="not uniquely recorded"):
        operation_for_supported_row(
            _target_realization_fixture(_target_profile_fixture()), row
        )


def test_target_profile_publication_uses_canonical_shared_writer(tmp_path) -> None:
    tool = McpToolObservation(
        name="process_refund",
        source_observation_sha256=hashlib.sha256(
            canonical_json_bytes(
                {
                    "name": "process_refund",
                    "description": "Process a refund.",
                    "input_schema": {
                        "type": "object",
                        "properties": {"order_id": {"type": "string"}},
                    },
                    "output_schema": "opaque",
                }
            )
        ).hexdigest(),
        description="Process a refund.",
        input_schema={
            "type": "object",
            "properties": {"order_id": {"type": "string"}},
        },
        output_schema="opaque",
    )
    inventory = McpInventoryObservation(
        target_id="target-profile-1",
        authorization_scope_id="target-scope",
        tools=(tool,),
    )
    resource = TargetProfileResource(
        resource_id=mcp_resource_id("target-profile-1", tool.name),
        resource_kind="tool",
        target_id="target-profile-1",
        tool_name=tool.name,
        description=tool.description,
        input_schema=tool.input_schema,
        output_schema=tool.output_schema,
        argument_names=tool.argument_names,
        surfaces=("tool_call", "tool_result"),
        operations=(
            TargetProfileOperation(
                operation_id=tool.name,
                semantic_operation=tool.name,
                argument_names=tool.argument_names,
            ),
        ),
        evidence_refs=("inventory:tool:process_refund",),
    )
    profile = ExecutionTargetProfile(
        target_id="target-profile-1",
        authorization_scope_id="target-scope",
        basis=ProfileBasis.target,
        inventory_authority=InventoryAuthority.observed,
        semantic_authority=SemanticAuthority.inferred,
        inventory_completeness=InventoryCompleteness.observed_complete,
        source_protocol=SourceProtocol.mcp,
        source_inventory_digest=inventory.semantic_digest,
        discovery_provenance=DiscoveryProvenance(
            scanner_id="fixture-scanner",
            interpreter_id="fixture-interpreter",
            verifier_id="fixture-verifier",
        ),
        inventory=inventory,
        resources=(resource,),
        interpretations=(
            {
                "resource_id": resource.resource_id,
                "tool_name": tool.name,
                "disposition": TargetInterpretationDisposition.supported,
                "likely_effect": TargetOperationEffect.update,
                "likely_state_effect": TargetStateEffect.changes,
                "evidence_refs": ("inventory:tool:process_refund:description",),
                "rationale": "The observed description names a refund operation.",
            },
        ),
    )

    path = publish_execution_target_profile(tmp_path, profile)

    assert path == tmp_path / "execution-target-profile.json"
    assert json.loads(path.read_text(encoding="utf-8")) == profile.model_dump(
        mode="json"
    )


def test_context_stage5_prompt_describes_constructible_typed_unsafe_condition() -> None:
    context = _spec().scenario_context
    assert context is not None
    system_prompt, user_prompt = build_context_bdi_prompts(
        context,
        TemplateLoader(PROMPTS_DIR),
    )

    assert "semantic_binding_required" not in system_prompt
    assert '"binding_ref": "SEM-outcome-value"' in system_prompt
    assert '"value_type": "integer"' in system_prompt
    assert '"minimum": 0' in system_prompt
    assert '"maximum": null' in system_prompt
    assert "must be exactly `CA-1-1`" in user_prompt


@pytest.mark.parametrize(
    "value_type, minimum, maximum",
    [
        (SemanticBindingValueType.integer, 0, 10),
        (SemanticBindingValueType.number, 0, 1.5),
        (SemanticBindingValueType.string, None, None),
    ],
    ids=["integer", "number", "string"],
)
def test_placeholder_numeric_bounds_are_strict(
    value_type: SemanticBindingValueType,
    minimum: int | float | None,
    maximum: int | float | None,
) -> None:
    """Numeric placeholder bounds retain their declared type and ordering."""
    placeholder = SemanticBindingPlaceholder(
        binding_ref="SEM-BOUNDS",
        value_type=value_type,
        description="bound",
        minimum=minimum,
        maximum=maximum,
    )
    assert placeholder.minimum == minimum
    assert placeholder.maximum == maximum


@pytest.mark.parametrize(
    "value_type, minimum, maximum",
    [
        (SemanticBindingValueType.integer, 1.5, 3),
        (SemanticBindingValueType.number, -1, 3),
        (SemanticBindingValueType.string, 0, None),
        (SemanticBindingValueType.number, 5, 1),
    ],
    ids=["integer-float-bound", "negative-bound", "string-bound", "reversed"],
)
def test_placeholder_invalid_bounds_fail_closed(
    value_type: SemanticBindingValueType,
    minimum: int | float | None,
    maximum: int | float | None,
) -> None:
    """Malformed or unsafe placeholder bounds are rejected before publication."""
    with pytest.raises(ValueError):
        SemanticBindingPlaceholder(
            binding_ref="SEM-INVALID",
            value_type=value_type,
            description="bound",
            minimum=minimum,
            maximum=maximum,
        )


def test_target_profile_lock_pins_every_kit_file() -> None:
    """The consumer-shaped lock pins exactly the files in the target-profile kit."""
    lock = json.loads((CONTRACT_ROOT / "CONTRACT.lock").read_text(encoding="utf-8"))
    assert lock["contract"] == "target-profile"
    assert lock["schema_version"] == "execution-target-profile-v1"
    assert lock["digest_domain"] == "execution-target-profile-v1"
    kit_files = {
        path.relative_to(CONTRACT_ROOT).as_posix(): hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        for path in (CONTRACT_ROOT / "target-profile-v1").rglob("*")
        if path.is_file()
    }
    assert lock["files"] == kit_files
