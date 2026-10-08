"""Shared test builders moved out of test modules."""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import SystemicStpaBaseline
from asago_scenario_generator.pipeline.target_realization import (
    observed_operations,
    realize_baseline_rows,
    realize_target_operations,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionTargetProfile,
    ExecutionSurface,
    InventoryAuthority,
    InventoryCompleteness,
    ProfileBasis,
    SemanticAuthority,
    SourceProtocol,
    TargetSemanticInterpretation,
    TargetProfileOperation,
    TargetProfileResource,
    McpInventoryObservation,
    McpToolObservation,
    mcp_resource_id,
)
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration


def _operation(resource_id: str, operation_id: str, *, state_changing: bool = False):
    del resource_id, state_changing
    return TargetProfileOperation(
        operation_id=operation_id,
        semantic_operation=operation_id,
        argument_names=("customer_id",),
    )


def _profile():
    tools = (
        McpToolObservation(
            name="schedule_payment",
            description="Schedule a payment",
            source_observation_sha256="1" * 64,
            input_schema={
                "type": "object",
                "properties": {"customer_id": {"type": "string"}},
            },
        ),
        McpToolObservation(
            name="get_payment",
            description="Read a payment",
            source_observation_sha256="2" * 64,
            input_schema={
                "type": "object",
                "properties": {"customer_id": {"type": "string"}},
            },
        ),
    )
    inventory = McpInventoryObservation(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        tools=tools,
    )
    resources = tuple(
        TargetProfileResource(
            resource_id=mcp_resource_id("target:mini", tool.name),
            target_id="target:mini",
            tool_name=tool.name,
            description=tool.description,
            input_schema=tool.input_schema,
            surfaces=(ExecutionSurface.tool_call, ExecutionSurface.tool_result),
            operations=(_operation("unused", tool.name, state_changing=False),),
            evidence_refs=(f"inventory:tool:{tool.name}",),
        )
        for tool in tools
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
        interpretations=tuple(
            TargetSemanticInterpretation(
                resource_id=resource.resource_id,
                tool_name=resource.tool_name,
                disposition="supported",
                likely_effect=(
                    "create" if resource.tool_name == "schedule_payment" else "read"
                ),
                likely_state_effect=(
                    "changes" if resource.tool_name == "schedule_payment" else "none"
                ),
                evidence_refs=(f"inventory:tool:{resource.tool_name}",),
                rationale="typed test interpretation",
            )
            for resource in resources
        ),
    )


def _baseline():
    return _baseline_with_actions(
        [
            ControlAction(
                ca_id="CA-1-1",
                description="Controller schedules a payment",
                effect_kind=ControlActionEffectKind.state_change,
            )
        ],
        baseline_id="baseline:one",
        prompt_hashes=("baseline-prompt-hash",),
        reference_inventory=("CA-1-1", "RESP-1"),
    )


def _baseline_with_actions(
    actions,
    *,
    controlled_processes=(),
    baseline_id,
    prompt_hashes=(),
    reference_inventory=(),
):
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
                control_actions=actions,
            )
        ],
        controlled_processes=controlled_processes,
    )
    return SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ICAEnumeration(slots=[]),
        baseline_id=baseline_id,
        prompt_hashes=prompt_hashes,
        reference_inventory=reference_inventory,
    )


class _Interpreter:
    def __init__(self):
        self.calls = []

    def __call__(self, *, action, operations):
        self.calls.append((action, operations))
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "supported",
            "candidate_operations": (
                {
                    "resource_id": mcp_resource_id("target:mini", "schedule_payment"),
                    "operation_id": "schedule_payment",
                },
            ),
            "selected_operation": {
                "resource_id": mcp_resource_id("target:mini", "schedule_payment"),
                "operation_id": "schedule_payment",
            },
            "verifier": {
                "status": "verified",
                "detail": "typed test verification",
                "evidence_refs": ("verification:test",),
            },
            "evidence_refs": ("inventory:mcp:payments/schedule_payment",),
            "rationale": "The observed state-changing operation sends a payment.",
        }


class _UnmappedInterpreter:
    def __call__(self, *, action, operations):
        del operations
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "unmapped",
            "candidate_operations": (),
            "evidence_refs": ("inventory:mcp:payments",),
            "rationale": "The baseline action has no supported mapping.",
        }


class _ExtensionInterpreter:
    def __init__(self):
        self.requests = []

    accepted_operation_id = "schedule_payment"

    def extend(self, request):
        self.requests.append(request)
        accepted = [
            operation
            for operation in request.operations
            if operation.operation_id == self.accepted_operation_id
        ]
        rejected = [
            operation
            for operation in request.operations
            if operation.operation_id != self.accepted_operation_id
        ]
        return {
            "outcomes": tuple(
                [
                    {
                        "operation": {
                            "resource_id": operation.resource_id,
                            "operation_id": operation.operation_id,
                        },
                        "disposition": "accepted",
                        "control_action": {
                            "controller_id": "RESP-1",
                        },
                        "ica_slots": (
                            {
                                "uca_type": "INCORRECT",
                            },
                        ),
                        "evidence_refs": (
                            f"inventory:mcp:payments/{operation.operation_id}",
                        ),
                        "rationale": "The observed operation is additive.",
                        "verification": {
                            "status": "verified",
                            "detail": (
                                "Exact observed operation meaning and identity agree."
                            ),
                            "evidence_refs": (
                                f"verification:mcp:payments/{operation.operation_id}",
                            ),
                        },
                    }
                    for operation in accepted
                ]
                + [
                    {
                        "operation": {
                            "resource_id": operation.resource_id,
                            "operation_id": operation.operation_id,
                        },
                        "disposition": "rejected",
                        "evidence_refs": (
                            f"inventory:mcp:payments/{operation.operation_id}",
                        ),
                        "rationale": "No systemic hazard depends on this operation.",
                    }
                    for operation in rejected
                ]
            )
        }


class _ExtensionFactory:
    def __init__(self):
        self.calls = 0
        self.interpreter = _ExtensionInterpreter()

    def __call__(self):
        self.calls += 1
        return self.interpreter


def _realize(baseline, profile, interpreter_factory, *, extension_factory=None):
    """Match the baseline the way enrichment does, then realize with its rows.

    Production realization always receives the pre-ICA enrichment rows; this
    builds those rows with the same interpreter before calling the seam.  The
    extension adapter is that interpreter unless ``extension_factory`` is given.
    """
    observations = observed_operations(profile)
    interpreter = interpreter_factory() if observations else None
    rows, _diagnostics = realize_baseline_rows(baseline, observations, interpreter)
    return realize_target_operations(
        baseline,
        profile,
        extension_factory or (lambda: interpreter),
        baseline_rows=rows,
    )


def _target_extended_result(baseline=None):
    return _realize(
        baseline or _baseline(),
        _profile(),
        lambda: _UnmappedInterpreter(),
        extension_factory=_ExtensionFactory(),
    )
