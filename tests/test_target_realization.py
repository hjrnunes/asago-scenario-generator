from __future__ import annotations

from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.target_realization import (
    CapabilityClaim,
    CapabilityExposureDisposition,
    SystemicControlledProcess,
    SystemicElementReference,
    TargetDerivedICARequest,
    TargetDerivedICASlot,
    TargetDerivedICAFinding,
    TargetDerivedICAProviderResponse,
    TargetRealizationDisposition,
    TargetRealizationEffectiveView,
    TargetRealizationExtensionProviderResponse,
    TargetRealizationExtensionRequest,
    SystemicStpaBaseline,
    TargetOperationObservation,
    TargetOperationReference,
    TargetRealizationProviderResponse,
    TargetRealizationResult,
    canonical_baseline,
    canonical_effective_view,
    canonical_target_realization,
    verified_operations,
)
from asago_scenario_generator.pipeline.target_realization import (
    project_target_realization_to_stpa,
    reconcile_declared_observed_capabilities,
    realize_target_derived_icas,
    realize_target_operations,
)
from asago_scenario_generator.pipeline import (
    target_realization as target_realization_module,
)
from asago_scenario_generator.pipeline.target_realization_persistence import (
    TARGET_REALIZATION_FILENAME,
    write_target_realization,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlStructure,
    ControlledProcess,
    ElementRef,
    ReferenceType,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionTargetProfile,
    InventoryAuthority,
    InventoryCompleteness,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
    McpInventoryObservation,
    mcp_resource_id,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.ica_enumeration import (
    ICAEnumeration,
    ICA,
    ICASlot,
    UCAType,
)
from asago_scenario_generator.stpa.threat_enum.catalog_enrichment import enrich_threats
from asago_scenario_generator.stpa.scenario_prod.context import (
    build_scenario_generation_context,
    execution_implementation_kind,
)
from asago_scenario_generator.stpa.scenario_prod.run import (
    _target_operation_for_context,
)
from tests.helpers.target_realization import (
    _realize,
    _ExtensionFactory,
    _ExtensionInterpreter,
    _Interpreter,
    _UnmappedInterpreter,
    _baseline,
    _baseline_with_actions,
    _profile,
    _target_extended_result,
)


class _NoVerifierEvidenceInterpreter(_Interpreter):
    def __call__(self, *, action, operations):
        response = super().__call__(action=action, operations=operations)
        response["verifier"] = {
            "status": "verified",
            "detail": "The exact selected pair was checked.",
            "evidence_refs": (),
        }
        return response


def test_systemic_description_lookup_preserves_exact_namespace_and_wire_shape():
    structure = _baseline().control_structure
    before = structure.model_dump(mode="json")
    responsibility = structure.responsibilities[0]

    assert (
        structure.element_description("responsibility", responsibility.resp_id)
        == responsibility.description
    )
    assert structure.element_description("responsibility", "unknown") is None
    assert (
        structure.element_description("controlled_process", responsibility.resp_id)
        is None
    )
    assert structure.model_dump(mode="json") == before


def test_realize_target_operations_selects_one_exact_observed_operation_and_is_additive():
    baseline = _baseline()
    before = baseline.model_dump(mode="json")
    interpreter = _Interpreter()

    result = _realize(baseline, _profile(), lambda: interpreter)

    assert result.rows[0].disposition is TargetRealizationDisposition.supported
    assert result.rows[0].selected_operation == TargetOperationReference(
        resource_id=mcp_resource_id("target:mini", "schedule_payment"),
        operation_id="schedule_payment",
    )
    assert result.rows[0].provenance == "systemic_baseline"
    assert baseline.model_dump(mode="json") == before
    assert len(interpreter.calls) == 1
    assert result.summary.supported == 1


@pytest.mark.parametrize(
    ("target", "controlled_processes", "expected_target"),
    (
        (
            ElementRef(type=ReferenceType.responsibility, id="RESP-1"),
            (),
            {
                "type": "responsibility",
                "id": "RESP-1",
                "description": "payment controller",
            },
        ),
        (
            ElementRef(type=ReferenceType.controlled_process, id="CP-1"),
            (ControlledProcess(cp_id="CP-1", description="payment ledger"),),
            {
                "type": "controlled_process",
                "id": "CP-1",
                "description": "payment ledger",
            },
        ),
        (None, (), None),
    ),
)
def test_realize_target_operations_captures_attested_recipient_context(
    target, controlled_processes, expected_target
):
    baseline = _baseline_with_actions(
        [
            ControlAction(
                ca_id="CA-1-1",
                description="Controller sends a payment instruction",
                target=target,
                effect_kind=ControlActionEffectKind.agent_message,
            )
        ],
        controlled_processes=controlled_processes,
        baseline_id="baseline:recipient-context",
    )
    interpreter = _Interpreter()

    _realize(baseline, _profile(), lambda: interpreter)

    action_view = interpreter.calls[0][0]
    assert action_view["target"] == expected_target
    assert action_view["controller"] == {
        "id": "RESP-1",
        "description": "payment controller",
    }


def test_verified_pair_gets_compiler_owned_evidence_when_provider_omits_refs():
    result = _realize(_baseline(), _profile(), lambda: _NoVerifierEvidenceInterpreter())

    row = result.rows[0]
    assert row.disposition is TargetRealizationDisposition.supported
    assert row.verifier.evidence_refs == (
        "target-realization:verified-pair:CA-1-1:"
        f"{mcp_resource_id('target:mini', 'schedule_payment')}/schedule_payment",
    )
    record = next(
        item
        for item in result.operation_records
        if item.operation_ref.operation_id == "schedule_payment"
    )
    assert row.verifier.evidence_refs[0] in record.evidence_refs


def test_handoff_mapping_retains_typed_operation_without_claiming_approval():
    profile_payload = _profile().model_dump(mode="json")
    profile_payload.pop("semantic_digest")
    for interpretation in profile_payload["interpretations"]:
        if interpretation["resource_id"].endswith(":schedule_payment"):
            interpretation["likely_effect"] = "escalate"
            interpretation["likely_state_effect"] = "none"
    escalation_profile = ExecutionTargetProfile.model_validate(profile_payload)
    baseline = _baseline_with_actions(
        [
            ControlAction(
                ca_id="CA-1-1",
                description="Escalate the conversation to a human agent",
                effect_kind=ControlActionEffectKind.agent_message,
            )
        ],
        baseline_id="baseline:approval-counterexample",
    )

    result = _realize(baseline, escalation_profile, lambda: _Interpreter())

    assert result.rows[0].disposition is TargetRealizationDisposition.supported
    assert result.rows[0].selected_operation is not None
    assert (
        result.rows[0]
        .verifier.evidence_refs[0]
        .startswith("target-realization:verified-pair:")
    )
    operation = next(
        item.operation
        for item in result.operation_records
        if item.operation_ref.operation_id == "schedule_payment"
    )
    assert operation.effect == "escalate"
    assert operation.state_effect == "none"


def test_exact_observation_selects_tool_call_without_changing_conceptual_effect():
    action = SimpleNamespace(
        effect_kind=ControlActionEffectKind.agent_message,
    )
    operation = TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id="mcp:target:mini",
            operation_id="refund_payment",
        ),
        description="Refund a payment.",
    )

    assert (
        execution_implementation_kind(action) is ControlActionEffectKind.agent_message
    )
    assert (
        execution_implementation_kind(action, operation)
        is ControlActionEffectKind.tool_call
    )


def test_every_observed_operation_gets_one_accounting_record():
    result = _realize(_baseline(), _profile(), lambda: _Interpreter())

    assert {record.operation_ref.identity for record in result.operation_records} == {
        (mcp_resource_id("target:mini", "schedule_payment"), "schedule_payment"),
        (mcp_resource_id("target:mini", "get_payment"), "get_payment"),
    }
    assert result.summary.observed_operations == 2
    assert result.summary.supported == 1
    assert result.summary.unmapped == 1
    assert result.uncovered_operations == (
        TargetOperationReference(
            resource_id=mcp_resource_id("target:mini", "get_payment"),
            operation_id="get_payment",
        ),
    )


def test_target_absence_keeps_every_baseline_action_unmapped():
    inventory = McpInventoryObservation(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        tools=(),
    )
    profile = ExecutionTargetProfile(
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
        resources=(),
        interpretations=(),
    )

    result = _realize(_baseline(), profile, lambda: _Interpreter())

    assert len(result.rows) == 1
    assert result.rows[0].disposition is TargetRealizationDisposition.unmapped
    assert result.summary.baseline_control_actions == 1
    assert result.summary.observed_operations == 0


def test_public_seam_rejects_untyped_baseline_or_profile_values():
    with pytest.raises(TypeError, match="SystemicStpaBaseline"):
        realize_target_operations(
            {}, _profile(), lambda: _Interpreter(), baseline_rows=()
        )
    with pytest.raises(TypeError, match="ExecutionTargetProfile"):
        realize_target_operations(
            _baseline(), {}, lambda: _Interpreter(), baseline_rows=()
        )
    with pytest.raises(TypeError, match="SystemicStpaBaseline"):
        realize_target_operations(
            SimpleNamespace(), _profile(), lambda: _Interpreter(), baseline_rows=()
        )
    with pytest.raises(TypeError, match="ExecutionTargetProfile"):
        realize_target_operations(
            _baseline(), SimpleNamespace(), lambda: _Interpreter(), baseline_rows=()
        )


def test_closed_models_reject_legacy_aliases_and_embedded_arbitrary_objects():
    with pytest.raises(ValidationError):
        SystemicStpaBaseline.model_validate(
            {
                "baseline_id": "baseline:alias",
                "loss_analysis": SimpleNamespace(),
                "control_structure": SimpleNamespace(),
                "ica_enumeration": SimpleNamespace(),
                "control_actions": (),
            }
        )
    with pytest.raises(ValidationError):
        SystemicStpaBaseline.model_validate(
            {
                **_baseline().model_dump(mode="json"),
                "control_actions": [
                    {
                        "ca_id": "CA-1-1",
                        "controller_id": "RESP-1",
                        "description": "legacy alias",
                    }
                ],
            }
        )
    with pytest.raises(ValidationError):
        TargetOperationReference.model_validate(
            {"resource": "mcp:target:mini:tool", "operation": "tool"}
        )
    with pytest.raises(ValidationError):
        TargetRealizationProviderResponse.model_validate(
            {
                "action_id": "CA-1-1",
                "disposition": "unmapped",
                "candidates": (),
            }
        )


def test_from_stpa_requires_exact_typed_authorities():
    baseline = _baseline()
    with pytest.raises(TypeError, match="typed LossAnalysis"):
        SystemicStpaBaseline.from_stpa(
            loss_analysis=baseline.loss_analysis,
            control_structure=SimpleNamespace(),
            ica_enumeration=SimpleNamespace(),
        )


def test_snapshot_field_without_a_snapshot_model_is_rejected():
    from asago_scenario_generator.models import target_realization as models

    with pytest.raises(TypeError, match="names no snapshot model"):
        models._snapshot_model(tuple[str, ...])


def test_realization_keeps_ambiguous_and_unmapped_rows_visible():
    baseline = _baseline_with_actions(
        [
            ControlAction(ca_id="CA-1-1", description="Do one thing"),
            ControlAction(ca_id="CA-1-2", description="Do another thing"),
        ],
        baseline_id="baseline:two",
    )

    def interpret(*, action, operations):
        disposition = (
            "ambiguous" if action["control_action_id"] == "CA-1-1" else "unmapped"
        )
        return {
            "control_action_id": action["control_action_id"],
            "disposition": disposition,
            "candidate_operations": (
                {
                    "resource_id": mcp_resource_id("target:mini", "schedule_payment"),
                    "operation_id": "schedule_payment",
                },
            ),
            "evidence_refs": ("inventory:mcp:payments",),
            "rationale": "No unique exact relationship was established.",
        }

    result = _realize(baseline, _profile(), lambda: interpret)

    assert [row.disposition for row in result.rows] == [
        TargetRealizationDisposition.ambiguous,
        TargetRealizationDisposition.unmapped,
    ]
    assert all(row.selected_operation is None for row in result.rows)
    assert result.summary.supported == 0
    assert result.summary.ambiguous == 1
    assert result.summary.unmapped == 1


def test_reconcile_declared_and_observed_capabilities_retains_four_dispositions():
    declared = ("schedule_payment", "cancel_payment", "refund_payment")
    observed = ("schedule_payment", "refund_payment", "get_payment")

    rows = reconcile_declared_observed_capabilities(declared, observed)

    assert {row.capability for row in rows} == set(declared) | {"get_payment"}
    by_capability = {row.capability: row.disposition for row in rows}
    assert by_capability == dict.fromkeys(
        ("schedule_payment", "cancel_payment", "refund_payment", "get_payment"),
        CapabilityExposureDisposition.not_comparable,
    )


def test_reconcile_classifies_verified_labels_and_complete_inventory_absence():
    declared = ("schedule_payment", "cancel_payment")
    observed = ("schedule_payment", "get_payment")
    disposition = CapabilityExposureDisposition

    verified = reconcile_declared_observed_capabilities(
        declared, observed, verified_observed=(*declared, "get_payment")
    )
    complete = reconcile_declared_observed_capabilities(
        declared, observed, inventory_complete=True
    )

    assert {row.capability: row.disposition for row in verified} == {
        "schedule_payment": disposition.confirmed_exposure,
        "cancel_payment": disposition.declared_not_observed,
        "get_payment": disposition.undocumented_exposure,
    }
    assert {row.capability: row.disposition for row in complete} == {
        "schedule_payment": disposition.not_comparable,
        "cancel_payment": disposition.declared_not_observed,
        "get_payment": disposition.not_comparable,
    }


def test_interpreter_cannot_select_an_operation_outside_the_observed_inventory():
    def interpret(*, action, operations):
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "supported",
            "candidate_operations": (
                {
                    "resource_id": mcp_resource_id("target:mini", "schedule_payment"),
                    "operation_id": "erase_everything",
                },
            ),
            "selected_operation": {
                "resource_id": mcp_resource_id("target:mini", "schedule_payment"),
                "operation_id": "erase_everything",
            },
            "evidence_refs": ("inventory:mcp:payments",),
            "rationale": "unsupported claim",
        }

    with pytest.raises(ValueError, match="observed inventory"):
        _realize(_baseline(), _profile(), lambda: interpret)


class _DerivedFindingInterpreter:
    def __init__(self, *, verification_status="verified"):
        self.requests = []
        self.verification_status = verification_status

    def __call__(self, request):
        self.requests.append(request)
        slot = request.target_derived_ica_slots[0]
        return {
            "findings": (
                {
                    "slot_id": slot.slot_id,
                    "ica_id": f"{slot.slot_id}:1",
                    "ica_text": "The target operation is issued without a required check.",
                    "deviation": "The operation is issued without a required check.",
                    "hazardous_context": "The observed operation is available to the controller.",
                    "loss_scenario": "An unauthorized payment is scheduled.",
                    "related_hazards": ("H-1",),
                    "related_constraints": ("SC-1",),
                    "verification": {
                        "status": self.verification_status,
                        "detail": "typed target-derived finding verification",
                        "evidence_refs": ("verification:target-derived",),
                    },
                },
            )
        }


class _DerivedFindingFactory:
    def __init__(self, *, verification_status="verified"):
        self.calls = 0
        self.interpreter = _DerivedFindingInterpreter(
            verification_status=verification_status
        )

    def __call__(self):
        self.calls += 1
        return self.interpreter


def test_bounded_extension_is_one_call_and_additive_for_uncovered_operations():
    baseline = _baseline()
    before = baseline.model_dump(mode="json")
    extension_factory = _ExtensionFactory()

    result = _realize(
        baseline,
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    assert extension_factory.calls == 1
    assert len(extension_factory.interpreter.requests) == 1
    request = extension_factory.interpreter.requests[0]
    assert request.baseline == baseline
    assert tuple(item.operation_id for item in request.operations) == (
        "get_payment",
        "schedule_payment",
    )
    assert baseline.model_dump(mode="json") == before
    assert result.rows[0].disposition is TargetRealizationDisposition.unmapped
    assert result.target_derived_control_actions[0].control_action_id == "CA-1-2"
    assert result.target_derived_control_actions[0].description == (
        "Schedule a payment (arguments: customer_id)"
    )
    assert result.target_derived_control_actions[0].effect_kind == "tool_call"
    assert result.target_derived_control_actions[0].temporality == "instantaneous"
    assert tuple(slot.uca_type for slot in result.target_derived_ica_slots) == (
        "INCORRECT",
        "NOT_PROVIDED",
        "WRONG_TIMING",
    )
    assert all(
        slot.action_temporality == "instantaneous"
        for slot in result.target_derived_ica_slots
    )
    records = {item.operation_ref.identity: item for item in result.operation_records}
    schedule = records[
        (mcp_resource_id("target:mini", "schedule_payment"), "schedule_payment")
    ]
    assert schedule.disposition is TargetRealizationDisposition.supported
    assert schedule.provenance.value == "target_derived"
    assert schedule.target_derived_control_action_id == "CA-1-2"
    assert result.uncovered_operations == (
        TargetOperationReference(
            resource_id=mcp_resource_id("target:mini", "get_payment"),
            operation_id="get_payment",
        ),
    )
    assert any(
        "target extension rejected operation" in item and "get_payment" in item
        for item in result.diagnostics
    )
    assert result.summary.target_derived == 1


def test_bounded_extension_enumerates_all_eligible_ordinary_uca_categories():
    class _NoSlotProposal(_ExtensionInterpreter):
        def extend(self, request):
            response = super().extend(request)
            response["outcomes"][0]["ica_slots"] = ()
            return response

    extension_factory = _ExtensionFactory()
    extension_factory.interpreter = _NoSlotProposal()

    result = _realize(
        _baseline(),
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    assert tuple(slot.uca_type for slot in result.target_derived_ica_slots) == (
        "INCORRECT",
        "NOT_PROVIDED",
        "WRONG_TIMING",
    )


def test_bounded_extension_retains_unanswered_operations_and_calls_factory_once():
    extension_factory = _ExtensionFactory()

    class _EmptyExtension:
        def extend(self, request):
            del request
            return {"outcomes": ()}

    extension_factory.interpreter = _EmptyExtension()
    result = _realize(
        _baseline(),
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    assert extension_factory.calls == 1
    assert result.target_derived_control_actions == ()
    assert result.target_derived_ica_slots == ()
    assert set(result.uncovered_operations) == {
        TargetOperationReference(
            resource_id=mcp_resource_id("target:mini", "schedule_payment"),
            operation_id="schedule_payment",
        ),
        TargetOperationReference(
            resource_id=mcp_resource_id("target:mini", "get_payment"),
            operation_id="get_payment",
        ),
    }
    assert any("no extension outcome" in item for item in result.diagnostics)


def test_bounded_extension_batches_all_uncovered_operations_into_one_request():
    profile_payload = _profile().model_dump(mode="json")
    profile_payload.pop("semantic_digest")
    for interpretation in profile_payload["interpretations"]:
        if interpretation["resource_id"].endswith(":get_payment"):
            interpretation["likely_effect"] = "update"
            interpretation["likely_state_effect"] = "changes"
    profile = ExecutionTargetProfile.model_validate(profile_payload)
    extension_factory = _ExtensionFactory()

    _realize(
        _baseline(),
        profile,
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    assert extension_factory.calls == 1
    assert len(extension_factory.interpreter.requests) == 1
    assert tuple(
        item.operation_id
        for item in extension_factory.interpreter.requests[0].operations
    ) == ("get_payment", "schedule_payment")


def test_bounded_extension_rescues_an_uncovered_read_only_operation():
    extension_factory = _ExtensionFactory()
    extension_factory.interpreter.accepted_operation_id = "get_payment"

    result = _realize(
        _baseline(),
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    request = extension_factory.interpreter.requests[0]
    read_view = next(
        item for item in request.operations if item.operation_id == "get_payment"
    )
    assert read_view.state_changing is False
    assert read_view.effect == "read"
    assert read_view.state_effect == "none"
    records = {item.operation_ref.identity: item for item in result.operation_records}
    read_record = records[
        (mcp_resource_id("target:mini", "get_payment"), "get_payment")
    ]
    assert read_record.disposition is TargetRealizationDisposition.supported
    assert read_record.provenance.value == "target_derived"
    assert read_record.target_derived_control_action_id == "CA-1-2"
    action = result.target_derived_control_actions[0]
    assert action.control_action_id == "CA-1-2"
    assert action.effect_kind == "tool_call"
    assert result.uncovered_operations == (
        TargetOperationReference(
            resource_id=mcp_resource_id("target:mini", "schedule_payment"),
            operation_id="schedule_payment",
        ),
    )


def test_bounded_extension_keeps_a_rejected_read_only_operation_uncovered():
    extension_factory = _ExtensionFactory()
    extension_factory.interpreter.accepted_operation_id = None

    result = _realize(
        _baseline(),
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    read_ref = TargetOperationReference(
        resource_id=mcp_resource_id("target:mini", "get_payment"),
        operation_id="get_payment",
    )
    assert result.target_derived_control_actions == ()
    assert read_ref in result.uncovered_operations
    assert (
        "target extension rejected operation "
        f"{read_ref.resource_id}/get_payment: "
        "No systemic hazard depends on this operation."
    ) in result.diagnostics


def test_bounded_extension_treats_an_ambiguous_read_only_operation_as_eligible():
    read_ref = {
        "resource_id": mcp_resource_id("target:mini", "get_payment"),
        "operation_id": "get_payment",
    }

    def interpret(*, action, operations):
        del operations
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "ambiguous",
            "candidate_operations": (read_ref,),
            "evidence_refs": ("inventory:mcp:payments",),
            "rationale": "No unique exact relationship was established.",
        }

    extension_factory = _ExtensionFactory()
    extension_factory.interpreter.accepted_operation_id = None

    result = _realize(
        _baseline(),
        _profile(),
        lambda: interpret,
        extension_factory=extension_factory,
    )

    records = {item.operation_ref.identity: item for item in result.operation_records}
    read_record = records[(read_ref["resource_id"], "get_payment")]
    assert read_record.disposition is TargetRealizationDisposition.ambiguous
    assert "get_payment" in tuple(
        item.operation_id
        for item in extension_factory.interpreter.requests[0].operations
    )


def test_bounded_extension_uses_the_interpreter_extend_without_a_factory():
    class _DualAdapter:
        def __init__(self):
            self.extension_calls = 0

        def __call__(self, **kwargs):
            action = kwargs["action"]
            return {
                "control_action_id": action["control_action_id"],
                "disposition": "unmapped",
                "candidate_operations": (),
                "selected_operation": None,
                "evidence_refs": (),
                "rationale": "No baseline match.",
            }

        def extend(self, request):
            self.extension_calls += 1
            return {
                "outcomes": tuple(
                    {
                        "operation": item.reference.model_dump(mode="json"),
                        "disposition": "rejected",
                        "evidence_refs": item.evidence_refs,
                        "rationale": "No additive action is justified.",
                    }
                    for item in request.operations
                )
            }

    adapter = _DualAdapter()

    _realize(_baseline(), _profile(), lambda: adapter)

    assert adapter.extension_calls == 1


def test_extension_factory_must_return_an_adapter_with_extend():
    class _PlainCallableExtension:
        def __call__(self, request):
            raise AssertionError("a plain callable is not an extension adapter")

    with pytest.raises(TypeError, match="adapter with extend"):
        _realize(
            _baseline(),
            _profile(),
            lambda: _UnmappedInterpreter(),
            extension_factory=lambda: _PlainCallableExtension(),
        )


def test_bounded_extension_rejects_invented_operation_identity():
    class _InventedExtension:
        def extend(self, request):
            del request
            return {
                "outcomes": (
                    {
                        "operation": {
                            "resource_id": "mcp:target:mini:payments",
                            "operation_id": "erase_everything",
                        },
                        "disposition": "rejected",
                        "evidence_refs": ("inventory:mcp:payments",),
                        "rationale": "invented operation",
                    },
                )
            }

    with pytest.raises(ValueError, match="observed target operation"):
        _realize(
            _baseline(),
            _profile(),
            lambda: _UnmappedInterpreter(),
            extension_factory=lambda: _InventedExtension(),
        )


def test_bounded_extension_rejects_provider_authored_action_identity():
    class _CollidingExtension:
        def extend(self, request):
            operation = request.operations[0]
            return {
                "outcomes": (
                    {
                        "operation": {
                            "resource_id": operation.resource_id,
                            "operation_id": operation.operation_id,
                        },
                        "disposition": "accepted",
                        "control_action": {
                            "control_action_id": "CA-1-1",
                            "controller_id": "RESP-1",
                            "description": "colliding action",
                        },
                        "ica_slots": (
                            {
                                "uca_type": "NOT_PROVIDED",
                            },
                        ),
                        "evidence_refs": ("inventory:mcp:payments",),
                        "rationale": "colliding action",
                    },
                )
            }

    with pytest.raises(ValidationError, match="control_action_id"):
        _realize(
            _baseline(),
            _profile(),
            lambda: _UnmappedInterpreter(),
            extension_factory=lambda: _CollidingExtension(),
        )


def _multi_controller_authorities():
    """Return typed authorities with RESP-4 (one action) and target RESP-3."""
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="payment loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="bad payment", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="payments are authorized",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="payment controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Controller schedules a payment",
                        effect_kind=ControlActionEffectKind.state_change,
                    )
                ],
            ),
            Responsibility(
                resp_id="RESP-3",
                description="review controller",
                security_constraint_refs=["SC-1"],
            ),
            Responsibility(
                resp_id="RESP-4",
                description="refund controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-4-1",
                        description="Controller reviews refund requests",
                        effect_kind=ControlActionEffectKind.state_change,
                    )
                ],
            ),
        ],
    )
    ica_enumeration = ICAEnumeration(slots=[])
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ica_enumeration,
        baseline_id="baseline:extension-hold",
    )
    return baseline, loss_analysis, control_structure, ica_enumeration


def _both_state_changing_profile():
    payload = _profile().model_dump(mode="json")
    payload.pop("semantic_digest")
    for interpretation in payload["interpretations"]:
        interpretation["likely_effect"] = "create"
        interpretation["likely_state_effect"] = "changes"
    return ExecutionTargetProfile.model_validate(payload)


class _Attempt4ShapeExtension(_ExtensionInterpreter):
    """Replay the preserved attempt-4 extension outcome shape.

    The accepted outcome proposes controller RESP-4 (next action identity
    CA-4-2) whose target is the responsibility RESP-3: the exact shape that
    crashed run m2-e2e-first-run-attempt4.  A sibling outcome keeps a plain
    tool-target (no explicit target) proposal so the test also proves sibling
    actions are unaffected by the hold.
    """

    def extend(self, request):
        self.requests.append(request)
        outcomes = []
        for operation in request.operations:
            if operation.operation_id == "schedule_payment":
                control_action = {
                    "controller_id": "RESP-4",
                    "target": {"type": "responsibility", "id": "RESP-3"},
                    "target_new_controlled_process": False,
                }
            else:
                control_action = {"controller_id": "RESP-1"}
            outcomes.append(
                {
                    "operation": {
                        "resource_id": operation.resource_id,
                        "operation_id": operation.operation_id,
                    },
                    "disposition": "accepted",
                    "control_action": control_action,
                    "ica_slots": ({"uca_type": "INCORRECT"},),
                    "evidence_refs": (f"inventory:tool:{operation.operation_id}",),
                    "rationale": "The observed state-changing operation is additive.",
                    "verification": {
                        "status": "verified",
                        "detail": (
                            "Exact observed operation meaning and identity agree."
                        ),
                        "evidence_refs": (
                            f"verification:tool:{operation.operation_id}",
                        ),
                    },
                }
            )
        return {"outcomes": tuple(outcomes)}


def test_bounded_extension_holds_responsibility_target_with_typed_reason():
    baseline = _multi_controller_authorities()[0]
    before = baseline.model_dump(mode="json")
    extension_factory = _ExtensionFactory()
    extension_factory.interpreter = _Attempt4ShapeExtension()

    result = _realize(
        baseline,
        _both_state_changing_profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    held = [
        action
        for action in result.target_derived_control_actions
        if action.controller_id == "RESP-4"
    ]
    assert held == []
    sibling = [
        action
        for action in result.target_derived_control_actions
        if action.control_action_id == "CA-1-2"
    ]
    assert len(sibling) == 1
    assert sibling[0].effect_kind == "tool_call"
    assert any(
        "held" in item and "RESP-3" in item and "schedule_payment" in item
        for item in result.diagnostics
    )
    assert result.summary.target_derived == 1
    records = {
        item.operation_ref.operation_id: item for item in result.operation_records
    }
    assert records["schedule_payment"].provenance.value == "systemic_baseline"
    assert records["schedule_payment"].target_derived_control_action_id is None
    assert baseline.model_dump(mode="json") == before


def test_held_responsibility_target_extension_keeps_stpa_projection_valid():
    baseline, loss_analysis, control_structure, ica_enumeration = (
        _multi_controller_authorities()
    )
    extension_factory = _ExtensionFactory()
    extension_factory.interpreter = _Attempt4ShapeExtension()
    realization = _realize(
        baseline,
        _both_state_changing_profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )
    realization = realize_target_derived_icas(
        baseline,
        realization,
        _DerivedFindingFactory(),
    )

    projection = project_target_realization_to_stpa(
        baseline,
        loss_analysis,
        control_structure,
        ica_enumeration,
        realization,
    )

    by_controller = {
        responsibility.resp_id: responsibility
        for responsibility in projection.control_structure.responsibilities
    }
    assert [action.ca_id for action in by_controller["RESP-4"].control_actions] == [
        "CA-4-1"
    ]
    assert [action.ca_id for action in by_controller["RESP-1"].control_actions] == [
        "CA-1-1",
        "CA-1-2",
    ]


def test_bounded_extension_tool_target_still_compiles_unchanged():
    class _ProcessTargetExtension(_ExtensionInterpreter):
        def extend(self, request):
            response = super().extend(request)
            response["outcomes"][0]["control_action"] = {
                "controller_id": "RESP-1",
                "target": {"type": "controlled_process", "id": "CP-1"},
                "target_new_controlled_process": False,
            }
            return response

    baseline = _baseline_with_actions(
        [
            ControlAction(
                ca_id="CA-1-1",
                description="Controller schedules a payment",
                effect_kind=ControlActionEffectKind.state_change,
            )
        ],
        controlled_processes=(
            ControlledProcess(cp_id="CP-1", description="payment ledger"),
        ),
        baseline_id="baseline:tool-target",
    )
    extension_factory = _ExtensionFactory()
    extension_factory.interpreter = _ProcessTargetExtension()

    result = _realize(
        baseline,
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=extension_factory,
    )

    assert result.target_derived_control_actions[0].control_action_id == "CA-1-2"
    assert result.target_derived_control_actions[0].effect_kind == "tool_call"
    assert result.target_derived_control_actions[0].target == SystemicElementReference(
        type="controlled_process", id="CP-1"
    )
    assert result.summary.target_derived == 1
    assert not any("held" in item for item in result.diagnostics)


def test_extension_contract_rejects_compact_aliases_and_unknown_objects():
    with pytest.raises(ValidationError):
        TargetRealizationExtensionProviderResponse.model_validate({"proposals": ()})
    with pytest.raises(ValidationError):
        TargetRealizationExtensionProviderResponse.model_validate(
            {
                "outcomes": (
                    {
                        "operation_ref": SimpleNamespace(),
                        "disposition": "rejected",
                    },
                )
            }
        )
    with pytest.raises(ValidationError):
        TargetDerivedICASlot.model_validate(
            {
                "slot_id": "RESP-1:CA-TARGET-1:NOT_PROVIDED",
                "responsibility": "RESP-1",
                "control_action_id": "CA-TARGET-1",
                "uca_type": "NOT_PROVIDED",
            }
        )


def test_target_derived_slots_compile_to_verified_findings_and_effective_union():
    baseline = _baseline()
    before = baseline.model_dump(mode="json")
    realization = _target_extended_result(baseline)
    finder_factory = _DerivedFindingFactory()

    enhanced = realize_target_derived_icas(
        baseline,
        realization,
        finder_factory,
    )

    assert finder_factory.calls == 1
    assert len(finder_factory.interpreter.requests) == 1
    request = finder_factory.interpreter.requests[0]
    assert request.baseline == baseline
    assert tuple(item.slot_id for item in request.target_derived_ica_slots) == (
        "RESP-1:CA-1-2:INCORRECT",
        "RESP-1:CA-1-2:NOT_PROVIDED",
        "RESP-1:CA-1-2:WRONG_TIMING",
    )
    assert baseline.model_dump(mode="json") == before
    assert len(enhanced.target_derived_ica_findings) == 1
    finding = enhanced.target_derived_ica_findings[0]
    assert isinstance(finding, TargetDerivedICAFinding)
    assert finding.provenance == "target_derived"
    assert finding.verification.status == "verified"
    assert finding.deviation == "The operation is issued without a required check."

    effective = enhanced.effective_view
    assert effective is not None
    action_ids = {
        action.control_action_id
        for responsibility in effective.effective_control_structure.responsibilities
        for action in responsibility.control_actions
    }
    assert action_ids == {"CA-1-1", "CA-1-2"}
    assert {slot.slot_id for slot in effective.effective_ica_enumeration.slots} == {
        "RESP-1:CA-1-2:INCORRECT",
        "RESP-1:CA-1-2:NOT_PROVIDED",
        "RESP-1:CA-1-2:WRONG_TIMING",
    }
    derived_slot = next(
        slot
        for slot in effective.effective_ica_enumeration.slots
        if slot.slot_id == "RESP-1:CA-1-2:INCORRECT"
    )
    assert derived_slot.is_na is False
    assert [ica.ica_id for ica in derived_slot.icas] == [finding.ica_id]
    assert effective.denominators.baseline_control_actions == 1
    assert effective.denominators.target_derived_control_actions == 1
    assert effective.denominators.baseline_ica_slots == 0
    assert effective.denominators.target_derived_ica_slots == 3
    assert effective.denominators.baseline_ica_findings == 0
    assert effective.denominators.target_derived_ica_findings == 1


def test_target_derived_action_resolves_its_exact_stage5_operation():
    realization = _target_extended_result()
    context = SimpleNamespace(
        target_control_path=SimpleNamespace(
            control_action=SimpleNamespace(action_id="CA-1-2")
        )
    )

    operation = _target_operation_for_context(realization, context)

    assert operation is not None
    assert operation.operation_id == "schedule_payment"


def test_target_derived_both_operations_reach_stage5_with_exact_constraints():
    profile_payload = _profile().model_dump(mode="json")
    profile_payload.pop("semantic_digest")
    for interpretation in profile_payload["interpretations"]:
        if interpretation["resource_id"].endswith(":get_payment"):
            interpretation["likely_effect"] = "update"
            interpretation["likely_state_effect"] = "changes"
    profile = ExecutionTargetProfile.model_validate(profile_payload)

    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="payment loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="bad payment", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="payments are authorized",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        controlled_processes=[
            ControlledProcess(cp_id="CP-1", description="payment service")
        ],
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="payment controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Controller schedules a payment",
                        effect_kind=ControlActionEffectKind.state_change,
                    )
                ],
            )
        ],
    )
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ICAEnumeration(slots=[]),
        baseline_id="baseline:both-target-operations",
    )

    class _BothExtensionInterpreter:
        def extend(self, request):
            return {
                "outcomes": tuple(
                    {
                        "operation": operation.reference.model_dump(mode="json"),
                        "disposition": "accepted",
                        "control_action": {
                            "controller_id": "RESP-1",
                            "target": {
                                "type": "controlled_process",
                                "id": "CP-1",
                            },
                        },
                        "ica_slots": (),
                        "evidence_refs": (
                            f"inventory:mcp:payments/{operation.operation_id}",
                        ),
                        "rationale": "The observed state-changing operation is additive.",
                        "verification": {
                            "status": "verified",
                            "detail": "Exact observed operation meaning and identity agree.",
                            "evidence_refs": (
                                f"verification:{operation.operation_id}",
                            ),
                        },
                    }
                    for operation in request.operations
                )
            }

    before = baseline.model_dump(mode="json")
    realization = _realize(
        baseline,
        profile,
        lambda: _UnmappedInterpreter(),
        extension_factory=lambda: _BothExtensionInterpreter(),
    )

    class _BothDerivedFindingInterpreter:
        def __call__(self, request):
            findings = []
            for action in request.target_derived_control_actions:
                slot = next(
                    item
                    for item in request.target_derived_ica_slots
                    if item.control_action == action.control_action_id
                    and item.uca_type == "INCORRECT"
                )
                findings.append(
                    {
                        "slot_id": slot.slot_id,
                        "ica_id": f"{slot.slot_id}:1",
                        "ica_text": (
                            f"The {action.description} is issued without a required check."
                        ),
                        "hazardous_context": "The observed operation is available to the controller.",
                        "loss_scenario": "An unauthorized payment operation is executed.",
                        "related_hazards": ("H-1",),
                        "related_constraints": (),
                        "verification": {
                            "status": "verified",
                            "detail": "typed target-derived finding verification",
                            "evidence_refs": ("verification:target-derived",),
                        },
                    }
                )
            return {"findings": tuple(findings)}

    enhanced = realize_target_derived_icas(
        baseline,
        realization,
        lambda: _BothDerivedFindingInterpreter(),
    )
    assert baseline.model_dump(mode="json") == before
    assert {
        record.operation_ref.operation_id
        for record in enhanced.operation_records
        if record.provenance.value == "target_derived"
    } == {"get_payment", "schedule_payment"}
    assert {
        finding.related_constraints for finding in enhanced.target_derived_ica_findings
    } == {("SC-1",)}

    projection = project_target_realization_to_stpa(
        baseline,
        loss_analysis,
        control_structure,
        ICAEnumeration(slots=[]),
        enhanced,
    )
    enriched = enrich_threats(
        projection.ica_enumeration,
        projection.control_structure,
    )

    derived_action_ids = {
        action.control_action_id for action in enhanced.target_derived_control_actions
    }
    seen_operations = set()
    for threat in enriched.structural_threats:
        if threat.ica_id is None:
            continue
        context = build_scenario_generation_context(
            threat,
            projection.control_structure,
            loss_analysis,
            scenario_id=f"scenario:{threat.ica_id}",
        )
        action_id = context.target_control_path.control_action.action_id
        if action_id not in derived_action_ids:
            continue
        operation = _target_operation_for_context(
            enhanced,
            SimpleNamespace(
                target_control_path=SimpleNamespace(
                    control_action=SimpleNamespace(action_id=action_id)
                )
            ),
        )
        assert operation is not None
        seen_operations.add(operation.operation_id)
        assert tuple(item.constraint_id for item in context.constraints) == ("SC-1",)

    assert seen_operations == {"get_payment", "schedule_payment"}


def test_target_derived_effective_view_keeps_baseline_findings_in_union():
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="payment loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="bad payment", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="payments are authorized",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="payment controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Controller schedules a payment",
                        effect_kind=ControlActionEffectKind.state_change,
                    )
                ],
            )
        ]
    )
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ICAEnumeration(
            slots=[
                ICASlot(
                    slot_id="RESP-1:CA-1-1:NOT_PROVIDED",
                    responsibility="RESP-1",
                    control_action="CA-1-1",
                    uca_type=UCAType.not_provided,
                    is_na=False,
                    icas=[
                        ICA(
                            ica_id="RESP-1:CA-1-1:NOT_PROVIDED:1",
                            ica_text="Baseline unsafe action.",
                            hazardous_context="Baseline context.",
                            loss_scenario="Baseline loss scenario.",
                            related_hazards=["H-1"],
                            related_constraints=["SC-1"],
                        )
                    ],
                )
            ]
        ),
        baseline_id="baseline:with-ica",
    )
    realization = _target_extended_result(baseline)
    enhanced = realize_target_derived_icas(
        baseline,
        realization,
        _DerivedFindingFactory(),
    )

    effective = enhanced.effective_view
    assert effective is not None
    assert effective.denominators.baseline_ica_slots == 1
    assert effective.denominators.baseline_ica_findings == 1
    assert effective.denominators.target_derived_ica_slots == 3
    assert effective.denominators.target_derived_ica_findings == 1
    assert {
        ica.ica_id
        for slot in effective.effective_ica_enumeration.slots
        for ica in slot.icas
    } == {
        "RESP-1:CA-1-1:NOT_PROVIDED:1",
        "RESP-1:CA-1-2:INCORRECT:1",
    }


def test_target_derived_finder_is_not_called_without_target_derived_slots():
    result = _realize(_baseline(), _profile(), lambda: _Interpreter())
    finder_factory = _DerivedFindingFactory()

    enhanced = realize_target_derived_icas(
        _baseline(),
        result,
        finder_factory,
    )

    assert finder_factory.calls == 0
    assert enhanced.target_derived_ica_findings == ()
    assert enhanced.effective_view is not None
    assert enhanced.effective_view.denominators.target_derived_ica_slots == 0


def test_effective_view_validation_checks_order_and_canonicalization_attests_it():
    enhanced = realize_target_derived_icas(
        _baseline(),
        _target_extended_result(),
        _DerivedFindingFactory(verification_status="unverified"),
    )
    view = enhanced.effective_view
    assert view is not None and view.diagnostics
    payload = view.model_dump(mode="json", exclude={"semantic_digest"})
    payload["diagnostics"] = [*reversed(view.diagnostics), view.diagnostics[0]]

    draft = TargetRealizationEffectiveView.model_validate(payload)

    assert draft.semantic_digest is None
    assert draft.diagnostics == tuple(payload["diagnostics"])
    assert canonical_effective_view(draft) == view
    assert canonical_effective_view(view) == view
    with pytest.raises(ValidationError, match="semantic_digest does not match"):
        TargetRealizationEffectiveView.model_validate(
            {**payload, "semantic_digest": "other"}
        )
    denominators = {**payload["denominators"], "baseline_ica_findings": 99}
    with pytest.raises(ValidationError, match="denominators do not reconcile"):
        TargetRealizationEffectiveView.model_validate(
            {**payload, "denominators": denominators}
        )
    result_payload = enhanced.model_dump(mode="json")
    result_payload["effective_view"] = payload
    nested = TargetRealizationResult.model_validate(result_payload)
    assert nested.effective_view == draft
    assert canonical_target_realization(nested) == enhanced


def test_unverified_target_derived_finding_is_excluded_but_slot_remains_traceable():
    realization = _target_extended_result()
    enhanced = realize_target_derived_icas(
        _baseline(),
        realization,
        _DerivedFindingFactory(verification_status="unverified"),
    )

    assert enhanced.target_derived_ica_findings == ()
    assert any("not independently verified" in item for item in enhanced.diagnostics)
    effective = enhanced.effective_view
    assert effective is not None
    assert effective.denominators.target_derived_ica_slots == 3
    assert effective.denominators.target_derived_ica_findings == 0
    target_slot = next(
        slot
        for slot in effective.effective_ica_enumeration.slots
        if slot.slot_id == "RESP-1:CA-1-2:INCORRECT"
    )
    assert target_slot.is_na is False
    assert target_slot.icas == ()
    assert target_slot.unresolved_reason is not None


def test_target_derived_finding_compiles_exact_owner_constraint_when_provider_omits_it():
    baseline_payload = _baseline().model_dump(mode="json")
    baseline_payload.pop("baseline_digest")
    baseline_payload["control_structure"]["responsibilities"][0][
        "security_constraint_refs"
    ] = ["SC-1"]
    baseline = canonical_baseline(SystemicStpaBaseline.model_validate(baseline_payload))
    realization = _target_extended_result(baseline)

    class _OmittedConstraint:
        def __call__(self, request):
            slot = request.target_derived_ica_slots[0]
            return {
                "findings": (
                    {
                        "slot_id": slot.slot_id,
                        "ica_id": f"{slot.slot_id}:1",
                        "ica_text": "The target operation is issued without a required check.",
                        "hazardous_context": "The observed operation is available to the controller.",
                        "loss_scenario": "An unauthorized payment is scheduled.",
                        "related_hazards": ("H-1",),
                        "related_constraints": (),
                        "verification": {
                            "status": "verified",
                            "detail": "typed target-derived finding verification",
                            "evidence_refs": ("verification:target-derived",),
                        },
                    },
                )
            }

    enhanced = realize_target_derived_icas(
        baseline,
        realization,
        lambda: _OmittedConstraint(),
    )

    assert len(enhanced.target_derived_ica_findings) == 1
    assert enhanced.target_derived_ica_findings[0].related_constraints == ("SC-1",)


def test_target_derived_finding_without_owner_constraint_is_explicitly_unresolved():
    baseline_payload = _baseline().model_dump(mode="json")
    baseline_payload.pop("baseline_digest")
    baseline_payload["control_structure"]["responsibilities"][0][
        "security_constraint_refs"
    ] = []
    baseline = canonical_baseline(SystemicStpaBaseline.model_validate(baseline_payload))
    realization = _target_extended_result(baseline)

    class _UnownedConstraint:
        def __call__(self, request):
            slot = request.target_derived_ica_slots[0]
            return {
                "findings": (
                    {
                        "slot_id": slot.slot_id,
                        "ica_id": f"{slot.slot_id}:1",
                        "ica_text": "The target operation is issued without a required check.",
                        "hazardous_context": "The observed operation is available to the controller.",
                        "loss_scenario": "An unauthorized payment is scheduled.",
                        "related_hazards": ("H-1",),
                        "related_constraints": ("SC-1",),
                        "verification": {
                            "status": "verified",
                            "detail": "typed target-derived finding verification",
                            "evidence_refs": ("verification:target-derived",),
                        },
                    },
                )
            }

    enhanced = realize_target_derived_icas(
        baseline,
        realization,
        lambda: _UnownedConstraint(),
    )

    assert enhanced.target_derived_ica_findings == ()
    assert any(
        "owner-compatible governing constraint" in item for item in enhanced.diagnostics
    )
    target_slot = next(
        slot
        for slot in enhanced.effective_view.effective_ica_enumeration.slots
        if slot.slot_id == "RESP-1:CA-1-2:INCORRECT"
    )
    assert target_slot.is_na is False
    assert target_slot.icas == ()
    assert "owner-compatible governing constraint" in target_slot.unresolved_reason


def test_target_derived_finder_rejects_invented_slot_and_alias_fields():
    realization = _target_extended_result()

    class _InventedSlot:
        def __call__(self, request):
            del request
            return {
                "findings": (
                    {
                        "slot_id": "RESP-1:CA-1-2:INVENTED",
                        "ica_id": "RESP-1:CA-1-2:INVENTED:1",
                        "ica_text": "invented",
                        "hazardous_context": "invented",
                        "loss_scenario": "invented",
                        "action_id": "CA-1-2",
                        "verification": {"status": "verified"},
                    },
                )
            }

    with pytest.raises(ValidationError):
        realize_target_derived_icas(
            _baseline(),
            realization,
            lambda: _InventedSlot(),
        )


def test_target_derived_finder_rejects_unknown_hazard_reference():
    realization = _target_extended_result()

    class _UnknownHazard:
        def __call__(self, request):
            slot = request.target_derived_ica_slots[0]
            return TargetDerivedICAProviderResponse(
                findings=(
                    TargetDerivedICAFinding(
                        slot_id=slot.slot_id,
                        ica_id=f"{slot.slot_id}:1",
                        ica_text="derived",
                        hazardous_context="context",
                        loss_scenario="loss",
                        related_hazards=("H-INVENTED",),
                        verification={"status": "verified"},
                    ),
                )
            )

    with pytest.raises(ValueError, match="hazard"):
        realize_target_derived_icas(
            _baseline(),
            realization,
            lambda: _UnknownHazard(),
        )


def test_target_realization_persistence_is_atomic_and_exactly_named(tmp_path):
    artifact = _realize(_baseline(), _profile(), lambda: _Interpreter())

    path = write_target_realization(tmp_path, artifact)

    assert path == tmp_path / TARGET_REALIZATION_FILENAME
    assert path.name == "target-realization.yaml"
    loaded = TargetRealizationResult.from_yaml(path.read_text(encoding="utf-8"))
    loaded.assert_integrity()
    assert loaded == artifact


def test_realization_validation_checks_without_rewriting_the_result():
    canonical = _target_extended_result()
    payload = canonical.model_dump(mode="json", exclude={"semantic_digest"})
    payload["operation_records"].reverse()
    payload["uncovered_operations"].reverse()
    payload["diagnostics"] = ["z diagnostic", "a diagnostic", "z diagnostic"]
    assert len(payload["operation_records"]) == 2

    draft = TargetRealizationResult.model_validate(payload)

    assert draft.semantic_digest is None
    assert draft.operation_records == canonical.operation_records[::-1]
    assert draft.diagnostics == ("z diagnostic", "a diagnostic", "z diagnostic")
    attested = canonical_target_realization(draft)
    assert attested.diagnostics == ("a diagnostic", "z diagnostic")
    assert attested.operation_records == canonical.operation_records
    assert attested.semantic_digest == attested.compute_semantic_digest()
    assert canonical_target_realization(canonical) == canonical
    with pytest.raises(ValidationError, match="semantic_digest does not match"):
        TargetRealizationResult.model_validate(
            {**payload, "semantic_digest": canonical.semantic_digest}
        )
    reordered = TargetRealizationResult.model_validate(
        {**payload, "semantic_digest": attested.semantic_digest}
    )
    assert canonical_target_realization(reordered) == attested


def test_baseline_validation_checks_order_and_canonical_baseline_attests_it():
    canonical = _baseline()
    payload = canonical.model_dump(mode="json", exclude={"baseline_digest"})
    payload["reference_inventory"].reverse()

    draft = SystemicStpaBaseline.model_validate(payload)

    assert draft.baseline_digest is None
    assert draft.reference_inventory == ("RESP-1", "CA-1-1")
    assert canonical_baseline(draft) == canonical
    assert canonical_baseline(canonical) == canonical
    with pytest.raises(
        ValidationError, match="reference_inventory must contain unique"
    ):
        SystemicStpaBaseline.model_validate(
            {**payload, "reference_inventory": ["RESP-1", "RESP-1"]}
        )
    with pytest.raises(ValidationError, match="baseline_digest does not match"):
        SystemicStpaBaseline.model_validate({**payload, "baseline_digest": "other"})
    reordered = SystemicStpaBaseline.model_validate(
        {**payload, "baseline_digest": canonical.baseline_digest}
    )
    assert reordered.reference_inventory == ("RESP-1", "CA-1-1")
    with pytest.raises(ValueError, match="target-blind baseline digest mismatch"):
        reordered.assert_integrity()


def _observation() -> TargetOperationObservation:
    return TargetOperationObservation(
        reference=TargetOperationReference(
            resource_id="mcp:mini:pay", operation_id="pay"
        ),
        evidence_refs=("inventory:tool:pay",),
    )


def _extension_request_payload(baseline: dict) -> dict:
    return {
        "baseline": baseline,
        "operations": [_observation().model_dump(mode="json")],
    }


def _derived_ica_request_payload(baseline: dict) -> dict:
    return {
        "baseline": baseline,
        "target_derived_control_actions": [
            {
                "control_action_id": "CA-9-1",
                "controller_id": "RESP-1",
                "description": "Pay in the target.",
                "provenance": "target_derived",
            }
        ],
        "target_derived_ica_slots": [
            {
                "slot_id": "RESP-1:CA-9-1:NOT_PROVIDED",
                "responsibility": "RESP-1",
                "control_action": "CA-9-1",
                "uca_type": "NOT_PROVIDED",
            }
        ],
    }


_REQUEST_PAYLOADS = pytest.mark.parametrize(
    ("request_type", "payload"),
    (
        (TargetRealizationExtensionRequest, _extension_request_payload),
        (TargetDerivedICARequest, _derived_ica_request_payload),
    ),
)


def _draft_baseline_payload() -> dict:
    payload = _baseline().model_dump(mode="json", exclude={"baseline_digest"})
    payload["reference_inventory"].reverse()
    return payload


@_REQUEST_PAYLOADS
def test_request_accepts_the_canonical_baseline(request_type, payload):
    canonical = _baseline()

    request = request_type.model_validate(payload(canonical.model_dump(mode="json")))

    assert request.baseline == canonical
    assert request_type(**{**payload({}), "baseline": canonical}).baseline == canonical


@_REQUEST_PAYLOADS
def test_request_rejects_a_baseline_without_its_digest(request_type, payload):
    draft = _baseline().model_dump(mode="json", exclude={"baseline_digest"})

    with pytest.raises(ValidationError, match="request baseline must be canonical"):
        request_type.model_validate(payload(draft))


@_REQUEST_PAYLOADS
def test_request_rejects_a_baseline_in_non_canonical_order(request_type, payload):
    reordered = {
        **_draft_baseline_payload(),
        "baseline_digest": _baseline().baseline_digest,
    }

    with pytest.raises(ValidationError, match="request baseline must be canonical"):
        request_type.model_validate(payload(reordered))


@_REQUEST_PAYLOADS
def test_request_rejects_a_non_canonical_baseline_object(request_type, payload):
    draft = SystemicStpaBaseline.model_validate(_draft_baseline_payload())

    with pytest.raises(ValidationError, match="request baseline must be canonical"):
        request_type(**{**payload({}), "baseline": draft})


def test_stpa_projection_returns_valid_additive_models_without_mutating_authorities():
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="payment loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="bad payment", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="payments are authorized",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="payment controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Controller schedules a payment",
                        effect_kind=ControlActionEffectKind.state_change,
                    )
                ],
            )
        ]
    )
    ica_enumeration = ICAEnumeration(slots=[])
    baseline = SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ica_enumeration,
        baseline_id="baseline:projection",
    )
    realization = _target_extended_result(baseline)
    realization = realize_target_derived_icas(
        baseline,
        realization,
        _DerivedFindingFactory(),
    )
    before_loss = loss_analysis.model_dump(mode="json")
    before_structure = control_structure.model_dump(mode="json")
    before_icas = ica_enumeration.model_dump(mode="json")

    projection = project_target_realization_to_stpa(
        baseline,
        loss_analysis,
        control_structure,
        ica_enumeration,
        realization,
    )

    assert isinstance(projection.control_structure, ControlStructure)
    assert isinstance(projection.ica_enumeration, ICAEnumeration)
    assert [
        action.ca_id
        for action in projection.control_structure.responsibilities[0].control_actions
    ] == ["CA-1-1", "CA-1-2"]
    assert projection.ica_enumeration.slots[0].slot_id == ("RESP-1:CA-1-2:INCORRECT")
    assert projection.ica_enumeration.slots[0].icas[0].ica_id == (
        "RESP-1:CA-1-2:INCORRECT:1"
    )
    enriched = enrich_threats(
        projection.ica_enumeration,
        projection.control_structure,
    )
    assert [item.ica_id for item in enriched.structural_threats] == [
        "RESP-1:CA-1-2:INCORRECT:1"
    ]
    assert loss_analysis.model_dump(mode="json") == before_loss
    assert control_structure.model_dump(mode="json") == before_structure
    assert ica_enumeration.model_dump(mode="json") == before_icas


def test_target_realization_small_closed_helpers_cover_unmapped_branches():
    assert target_realization_module._capability_value("read") == ("read", False)
    assert target_realization_module._capability_value(
        CapabilityClaim(capability="write", conflicting=True)
    ) == ("write", True)
    with pytest.raises(TypeError, match="strings or CapabilityClaim"):
        target_realization_module._capability_value(1)

    assert target_realization_module._next_process_ordinal([]) == 1
    assert (
        target_realization_module._next_process_ordinal(
            [
                SystemicControlledProcess(cp_id="CP-4", description="four"),
                SystemicControlledProcess(cp_id="not-canonical", description="skip"),
            ]
        )
        == 5
    )

    state = SimpleNamespace(
        element_ids={("responsibility", "RESP-1")},
        derived_processes=(),
    )
    assert target_realization_module._validated_extension_target(state, None) is None
    target = SystemicElementReference(type="responsibility", id="RESP-1")
    assert target_realization_module._validated_extension_target(state, target) == {
        "type": "responsibility",
        "id": "RESP-1",
    }
    with pytest.raises(ValueError, match="not in the baseline"):
        target_realization_module._validated_extension_target(
            state,
            SystemicElementReference(type="controlled_process", id="CP-999"),
        )
    with pytest.raises(ValueError, match="type"):
        SystemicElementReference(type="controlled-process", id="CP-1")

    target_realization_module._require_known_target_reference(
        ReferenceType.controlled_process,
        "CP-1",
        {"CP-1"},
    )
    target_realization_module._require_known_target_reference(
        ReferenceType.responsibility,
        "RESP-1",
        set(),
    )
    with pytest.raises(ValueError, match="unknown controlled process"):
        target_realization_module._require_known_target_reference(
            ReferenceType.controlled_process,
            "CP-2",
            {"CP-1"},
        )


def test_verified_target_ica_findings_retain_empty_and_unverified_diagnostics():
    verified, diagnostics = target_realization_module._verified_slot_findings(
        "RESP-1:CA-1-1:NOT_PROVIDED", ()
    )
    assert verified == []
    assert diagnostics == (
        "no target-derived ICA finding for accepted slot RESP-1:CA-1-1:NOT_PROVIDED",
    )


@pytest.mark.parametrize(
    ("input_schema", "error", "message"),
    [
        ({"properties": {"limit": {"maximum": float("nan")}}}, ValueError, "NaN"),
        ({"properties": {1: {"type": "string"}}}, TypeError, "keys must be strings"),
        ({"enum": [{"value"}]}, TypeError, "only JSON values"),
    ],
    ids=["nan", "non-string-key", "set"],
)
def test_operation_input_schema_rejects_non_json_values(
    input_schema: dict, error: type[Exception], message: str
) -> None:
    with pytest.raises(error, match=message):
        TargetOperationObservation(
            reference=TargetOperationReference(resource_id="R-1", operation_id="op"),
            input_schema=input_schema,
        )


def _verified_pair(action: str) -> str:
    return f"target-realization:verified-pair:{action}:mcp:r/op"


def _baseline_row(action: str, **changes: object) -> SimpleNamespace:
    fields = {
        "provenance": "systemic_baseline",
        "disposition": "supported",
        "control_action_id": action,
        "selected_operation": SimpleNamespace(resource_id="mcp:r", operation_id="op"),
        "verifier": SimpleNamespace(
            status="verified", evidence_refs=(_verified_pair(action),)
        ),
    }
    return SimpleNamespace(**(fields | changes))


def _derived_record(action: str, **changes: object) -> SimpleNamespace:
    fields = {
        "provenance": "target_derived",
        "disposition": "supported",
        "target_derived_control_action_id": action,
        "operation": SimpleNamespace(resource_id="mcp:r", operation_id="op"),
        "evidence_refs": (_verified_pair(action),),
    }
    return SimpleNamespace(**(fields | changes))


def test_verified_target_operations_require_one_exact_verified_pair() -> None:
    realization = SimpleNamespace(
        rows=(
            _baseline_row("CA-1"),
            _baseline_row("CA-2"),
            _baseline_row("CA-2", disposition="ambiguous"),
            _baseline_row("CA-3", provenance="target_derived"),
            _baseline_row("CA-4", verifier=SimpleNamespace(status="pending")),
            _baseline_row("CA-5", selected_operation=None),
            _baseline_row("CA-6", verifier=SimpleNamespace(status="verified")),
            _baseline_row(""),
        ),
        operation_records=(
            _derived_record("TD-1"),
            _derived_record("TD-1", disposition="ambiguous"),
            _derived_record("TD-2"),
            _derived_record("TD-2"),
            _derived_record("TD-3", provenance="systemic_baseline"),
            _derived_record("TD-4", operation=SimpleNamespace(resource_id=None)),
            _derived_record("TD-5", evidence_refs=None),
        ),
    )
    assert verified_operations(realization) == {"CA-1": "op", "TD-1": "op"}
    assert verified_operations(None) == {}
    assert verified_operations(SimpleNamespace(rows=(_baseline_row("TD-1"),))) == {
        "TD-1": "op"
    }


def test_verified_baseline_operations_win_over_target_derived_ones() -> None:
    realization = SimpleNamespace(
        rows=(_baseline_row("CA-1"),),
        operation_records=(
            _derived_record(
                "CA-1",
                operation=SimpleNamespace(resource_id="mcp:r", operation_id="other"),
                evidence_refs=("target-realization:verified-pair:CA-1:mcp:r/other",),
            ),
            _derived_record("TD-1"),
        ),
    )
    assert list(verified_operations(realization).items()) == [
        ("CA-1", "op"),
        ("TD-1", "op"),
    ]
