"""Acceptance-first tests for the v2 producer public seam."""

from __future__ import annotations

import json
import hashlib
from pathlib import Path
from types import SimpleNamespace

import pytest
from jsonschema import Draft202012Validator

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    CausalFactorKind,
    CausalEvidenceStatus,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import StructuralThreat
from asago_scenario_generator.stpa.models.execution_projection_v2 import (
    ExecutionCausalFactor,
    ExecutionProjectionV2,
    ExecutionRunIdentity,
)
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
    AttackerInfluence,
    BindingCompleteness,
    EnvironmentBasis,
    ExecutionActionKind,
    ExecutionClassification,
    ExecutionClaimScope,
    ExecutionDeliveryClass,
    ExecutionProfileFit,
    ExecutionResourceKind,
    ExecutionResourcePurpose,
    ExecutionSurface,
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
from asago_scenario_generator.stpa.scenario_prod.execution_projection import (
    prepare_execution_projection,
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


CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "data/contracts/stpa-execution"


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


def _exact_target_contract() -> SemanticExecutionContract:
    """Build one indirect route with an exact target operation requirement."""
    return SemanticExecutionContract(
        requested_environment_basis=RequestedEnvironmentBasis.target_profile,
        delivery=SemanticExecutionDelivery(
            delivery_class=ExecutionDeliveryClass.indirect_content,
            factor_id="CF-1",
            source_role="attacker_influenced_content",
            carrier_requirement_id="REQ-1",
        ),
        action_kind=ExecutionActionKind.model_output,
        resource_requirements=(
            {
                "requirement_id": "REQ-1",
                "purpose": ExecutionResourcePurpose.stimulus_carrier,
                "factor_id": "CF-1",
                "owner_ref": "PM-1-1",
                "acceptable_resource_kinds": (ExecutionResourceKind.tool,),
                "role_id": "attacker_influenced_content_source",
                "operation": "process_refund",
                "required_surfaces": (ExecutionSurface.tool_result,),
                "required_attacker_influence": AttackerInfluence.indirect,
                "exact_resource_id": "mcp:fixture-target:process_refund",
                "late_bindable": False,
                "evidence_refs": ("CF-1",),
            },
        ),
    )


def test_projection_rejects_outcome_ordered_before_itself() -> None:
    projection = prepare_execution_projection(
        _spec(), _control_structure(), ExecutionRunIdentity(run_id="run-1")
    ).projection.model_dump(mode="json")
    projection.pop("semantic_digest")
    projection["unsafe_outcome"]["condition"] = {
        "type": "ordering",
        "reference_step_id": projection["steps"][-1]["step_id"],
        "relation": "before",
    }
    projection["unsafe_outcome"]["semantic_binding_required"] = False
    with pytest.raises(ValueError, match="ordering cannot compare.*itself"):
        ExecutionProjectionV2.model_validate(projection)


@pytest.mark.parametrize("authority", ["profile", "realization"])
def test_prepare_rejects_unpaired_target_authority_without_exact_requirements(
    authority: str,
) -> None:
    """Target lineage is paired even when the route has no exact resource."""
    profile = _target_profile_fixture()
    realization = _target_realization_fixture(profile)
    kwargs = {
        "target_profile": profile if authority == "profile" else None,
        "target_realization": realization if authority == "realization" else None,
    }

    with pytest.raises(ValueError, match="must be supplied together"):
        prepare_execution_projection(
            _spec(),
            _control_structure(),
            ExecutionRunIdentity(run_id=f"run-unpaired-{authority}"),
            **kwargs,
        )


@pytest.mark.parametrize("authority", ["profile", "realization"])
def test_prepare_rejects_tampered_target_authority_without_exact_requirements(
    authority: str,
) -> None:
    """Both target authorities are integrity-checked before pin-only output."""
    profile = _target_profile_fixture()
    realization = _target_realization_fixture(profile)
    if authority == "profile":
        profile = profile.model_copy(update={"target_id": "tampered-target"})
    else:
        realization = realization.model_copy(update={"profile_id": "tampered-profile"})

    with pytest.raises(ValueError, match="semantic_digest"):
        prepare_execution_projection(
            _spec(),
            _control_structure(),
            ExecutionRunIdentity(run_id=f"run-tampered-{authority}"),
            target_profile=profile,
            target_realization=realization,
        )


def test_prepare_pins_both_target_authorities_without_exact_requirements() -> None:
    """A resource-free projection preserves a supplied target lineage pair."""
    profile = _target_profile_fixture()
    realization = _target_realization_fixture(profile)

    validated = prepare_execution_projection(
        _spec(),
        _control_structure(),
        ExecutionRunIdentity(run_id="run-paired-pin-only"),
        target_profile=profile,
        target_realization=realization,
    )

    pins = validated.projection.trace_refs.source_pins
    assert pins.execution_target_profile == profile.semantic_digest
    assert pins.target_realization == realization.semantic_digest
    assert validated.projection.execution_classification.target_profile_digest == (
        profile.semantic_digest
    )
    assert (
        validated.projection.execution_classification.environment_basis.value
        == "target_agnostic"
    )


def test_prepare_validates_exact_target_selection_and_operation() -> None:
    """A target-bound contract must match its attested selected operation."""
    profile = _target_profile_fixture()
    realization = _supported_target_realization_fixture(profile)
    spec = _spec().model_copy(update={"execution_contract": _exact_target_contract()})

    validated = prepare_execution_projection(
        spec,
        _control_structure(),
        ExecutionRunIdentity(run_id="run-exact-target"),
        target_profile=profile,
        target_realization=realization,
    )

    assert validated.projection.trace_refs.source_pins.target_realization == (
        realization.semantic_digest
    )


def test_prepare_accepts_exact_target_derived_operation_lineage() -> None:
    """A target-derived action resolves through its supported operation record."""
    profile = _target_profile_fixture()
    payload = _supported_target_realization_fixture(profile).model_dump(
        mode="python", exclude={"semantic_digest"}
    )
    payload["rows"] = ()
    record = dict(payload["operation_records"][0])
    record.update(
        {
            "baseline_control_action_ids": (),
            "target_derived_control_action_id": "CA-1-1",
            "provenance": "target_derived",
        }
    )
    payload["operation_records"] = (record,)
    payload["target_derived_control_actions"] = (
        {
            "control_action_id": "CA-1-1",
            "controller_id": "RESP-1",
            "description": "Process the exact target refund operation.",
            "effect_kind": "tool_call",
            "temporality": "instantaneous",
            "provenance": "target_derived",
        },
    )
    payload["summary"].update(
        {
            "baseline_control_actions": 0,
            "supported": 0,
            "target_derived": 1,
        }
    )
    realization = TargetRealizationResult.model_validate(payload)
    spec = _spec().model_copy(update={"execution_contract": _exact_target_contract()})

    validated = prepare_execution_projection(
        spec,
        _control_structure(),
        ExecutionRunIdentity(run_id="run-exact-target-derived"),
        target_profile=profile,
        target_realization=realization,
    )

    assert validated.projection.trace_refs.source_pins.target_realization == (
        realization.semantic_digest
    )


@pytest.mark.parametrize(
    "realization_update, expected_message",
    [
        ({"rows": ()}, "supported realization row"),
        (
            {
                "rows": (
                    TargetRealizationRow(
                        control_action_id="CA-1-1",
                        controller_id="RESP-1",
                        disposition=TargetRealizationDisposition.ambiguous,
                    ),
                )
            },
            "supported realization row",
        ),
    ],
    ids=["missing-row", "unsupported-row"],
)
def test_prepare_rejects_non_supported_exact_target_selection(
    realization_update: dict, expected_message: str
) -> None:
    """Exact target requirements cannot fall back from an absent selection."""
    profile = _target_profile_fixture()
    realization_payload = _supported_target_realization_fixture(profile).model_dump(
        mode="python", exclude={"semantic_digest"}
    )
    realization_payload.update(realization_update)
    if not realization_payload["rows"]:
        realization_payload["summary"]["baseline_control_actions"] = 0
    realization = TargetRealizationResult.model_validate(realization_payload)
    spec = _spec().model_copy(update={"execution_contract": _exact_target_contract()})

    with pytest.raises(ValueError, match=expected_message):
        prepare_execution_projection(
            spec,
            _control_structure(),
            ExecutionRunIdentity(run_id="run-exact-target-invalid-selection"),
            target_profile=profile,
            target_realization=realization,
        )


def test_prepare_rejects_exact_target_operation_mismatch() -> None:
    """The contract's exact operation must equal the selected realization."""
    profile = _target_profile_fixture()
    realization = _supported_target_realization_fixture(profile)
    base_contract = _exact_target_contract()
    requirement = base_contract.resource_requirements[0].model_copy(
        update={"operation": "different_operation"}
    )
    contract_payload = base_contract.model_dump(
        mode="python", exclude={"semantic_digest"}
    )
    contract_payload["resource_requirements"] = (requirement,)
    contract = SemanticExecutionContract.model_validate(contract_payload)
    spec = _spec().model_copy(update={"execution_contract": contract})

    with pytest.raises(ValueError, match="does not match target realization"):
        prepare_execution_projection(
            spec,
            _control_structure(),
            ExecutionRunIdentity(run_id="run-exact-target-mismatch"),
            target_profile=profile,
            target_realization=realization,
        )


def test_stage5_target_operation_resolver_uses_supported_baseline_row() -> None:
    """Stage 5 receives the exact operation selected for a baseline action."""
    from asago_scenario_generator.stpa.scenario_prod.run import (
        _target_operation_for_context,
    )

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
    from asago_scenario_generator.stpa.scenario_prod.run import (
        _target_operation_for_context,
    )

    realization = _target_realization_fixture(_target_profile_fixture())
    context = SimpleNamespace(
        target_control_path=SimpleNamespace(
            control_action=SimpleNamespace(action_id="CA-1-1")
        )
    )

    assert _target_operation_for_context(realization, context) is None


def test_stage5_target_operation_resolver_rejects_unrecorded_selection() -> None:
    """A selected operation must have exactly one corresponding observation."""
    from asago_scenario_generator.stpa.scenario_prod.realized_operation import (
        operation_for_supported_row,
    )

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


def test_prepare_rejects_empty_contextual_lineage_instead_of_broadening() -> None:
    spec = _spec().model_copy(
        update={
            "unsafe_outcome_hazard_refs": [],
            "unsafe_outcome_constraint_refs": [],
        }
    )

    with pytest.raises(ValueError, match="must equal scenario context|cannot be empty"):
        prepare_execution_projection(
            spec,
            _control_structure(),
            ExecutionRunIdentity(run_id="run-no-lineage-fallback"),
        )


def test_projection_rejects_bindings_on_analytical_classification() -> None:
    validated = prepare_execution_projection(
        _spec(),
        _control_structure(),
        ExecutionRunIdentity(run_id="run-analytical-classification"),
    )
    classification = ExecutionClassification(
        binding_completeness=BindingCompleteness.analytical_only,
        environment_basis=EnvironmentBasis.none,
        profile_fit=ExecutionProfileFit.invalid,
        claim_scope=ExecutionClaimScope.no_execution_claim,
        unresolved_requirement_ids=("REQ-1",),
        target_profile_digest="a" * 64,
    )
    payload = validated.projection.model_dump(mode="json", exclude={"semantic_digest"})
    payload["execution_contract"] = {
        **payload["execution_contract"],
        "disposition": "analytical_only",
        "requested_environment_basis": None,
        "delivery": None,
        "action_kind": None,
        "resource_requirements": [],
        "gaps": [
            {
                "code": "operation_missing",
                "detail": "No operation was established.",
                "evidence_refs": ["CF-1"],
            }
        ],
    }
    payload["execution_contract"].pop("semantic_digest")
    payload["execution_classification"] = classification.model_dump(mode="json")
    payload["stimulus_requirements"] = []

    with pytest.raises(ValueError, match="analytical_only classifications"):
        ExecutionProjectionV2.model_validate(payload)


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


def test_projection_contract_schema_requires_paired_target_lineage() -> None:
    """The portable schema rejects either target authority without its pair."""
    schema = json.loads(
        (CONTRACT_ROOT / "projection-v2/schema.json").read_text(encoding="utf-8")
    )
    payload = json.loads(
        (CONTRACT_ROOT / "projection-v2/valid/fully-bound.json").read_text(
            encoding="utf-8"
        )
    )
    source_pins = payload["trace_refs"]["source_pins"]
    source_pins["execution_target_profile"] = "a" * 64
    source_pins["target_realization"] = "b" * 64
    validator = Draft202012Validator(schema)

    assert not list(validator.iter_errors(payload))
    del source_pins["target_realization"]
    assert list(validator.iter_errors(payload))


@pytest.mark.parametrize(
    "status, extra",
    [
        (CausalEvidenceStatus.structural_failure, {}),
        (
            CausalEvidenceStatus.reachable_capability,
            {"capability_refs": ("CAP-1",), "access_refs": ("ACCESS-1",)},
        ),
        (
            CausalEvidenceStatus.bounded_assumption,
            {"bounded_assumption": "review is pending"},
        ),
    ],
    ids=["structural", "reachable-capability", "bounded-assumption"],
)
def test_projection_factor_evidence_variants_are_typed(
    status: CausalEvidenceStatus,
    extra: dict,
) -> None:
    """Each closed causal-evidence basis can be represented without inference."""
    factor = ExecutionCausalFactor(
        factor_id="CF-1",
        order=1,
        kind=CausalFactorKind.process_model_flaw,
        structural_source_id="PM-1-1",
        description="evidence",
        evidence_status=status,
        **extra,
    )
    assert factor.evidence_status is status


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
