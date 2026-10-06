"""Enrichment grounding: observed operations enrich logical control actions.

Owner decision for the M2 unified path: known operations enrich the logical
control actions; they never replace the control model with tool enumeration.
These tests pin the seam that matches observed operations to the systemic
control actions before ICA enumeration and specializes the supported matches'
descriptions with the exact documented operation identity.
"""

from __future__ import annotations

import pytest
from types import SimpleNamespace

from asago_scenario_generator.models.canonical import ClosedCanonicalModel
from asago_scenario_generator.models.target_realization import (
    TargetOperationReference,
    TargetRealizationDisposition,
    TargetRealizationProvenance,
    TargetRealizationRow,
    TargetRealizationVerification,
)
from asago_scenario_generator.pipeline.control_action_enrichment import (
    CONTROL_ACTION_ENRICHMENT_FILENAME,
    ControlActionOperationEnrichmentRecord,
    enrich_control_actions,
    ControlActionEnrichmentRow,
)
from asago_scenario_generator.pipeline.synthesis import (
    SynthesisAdapters,
    _default_enrich_control_actions,
    _resolve_adapters,
    _verified_enriched_operations,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    DiscoveryProvenance,
    ExecutionSurface,
    ExecutionTargetProfile,
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

_OPERATION_RESOURCE = mcp_resource_id("target:mini", "process_refund")
_READ_RESOURCE = mcp_resource_id("target:mini", "lookup_order")


def _operation(
    operation_id: str, argument_names: tuple[str, ...]
) -> TargetProfileOperation:
    return TargetProfileOperation(
        operation_id=operation_id,
        semantic_operation=operation_id,
        argument_names=argument_names,
    )


def _profile(*, basis: ProfileBasis = ProfileBasis.target) -> ExecutionTargetProfile:
    tools = (
        McpToolObservation(
            name="process_refund",
            description="Process a refund against an order.",
            source_observation_sha256="1" * 64,
            input_schema={
                "type": "object",
                "properties": {
                    "order_id": {"type": "string"},
                    "amount": {"type": "number"},
                },
            },
        ),
        McpToolObservation(
            name="lookup_order",
            description="Read one order.",
            source_observation_sha256="2" * 64,
            input_schema={
                "type": "object",
                "properties": {"order_id": {"type": "string"}},
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
            operations=(
                _operation(
                    tool.name,
                    ("order_id", "amount")
                    if tool.name == "process_refund"
                    else ("order_id",),
                ),
            ),
            evidence_refs=(f"inventory:tool:{tool.name}",),
        )
        for tool in tools
    )
    return ExecutionTargetProfile(
        target_id="target:mini",
        authorization_scope_id="scope:test",
        basis=basis,
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
                    "execute" if resource.tool_name == "process_refund" else "read"
                ),
                likely_state_effect=(
                    "changes" if resource.tool_name == "process_refund" else "none"
                ),
                evidence_refs=(f"inventory:tool:{resource.tool_name}",),
                rationale="typed test interpretation",
            )
            for resource in resources
        ),
    )


def _control_structure() -> ControlStructure:
    return ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="refund controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Execute refund processing",
                        effect_kind=ControlActionEffectKind.tool_call,
                    ),
                    ControlAction(
                        ca_id="CA-1-2",
                        description="Reply to the user",
                        effect_kind=ControlActionEffectKind.model_output,
                    ),
                ],
            )
        ],
        controlled_processes=[],
    )


def _loss_analysis() -> LossAnalysis:
    return LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="financial loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="bad refund", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="refunds are authorized",
                related_hazards=["H-1"],
            )
        ],
    )


class _VerifiedInterpreter:
    """Maps the refund action to the observed operation with verification."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    def __call__(self, *, action, operations):
        self.calls.append(action)
        if "refund" not in str(action.get("description", "")):
            return {
                "control_action_id": action["control_action_id"],
                "disposition": "unmapped",
                "candidate_operations": (),
                "selected_operation": None,
                "evidence_refs": (),
                "rationale": "No observed operation completes this action's effect.",
            }
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "supported",
            "candidate_operations": (
                {"resource_id": _OPERATION_RESOURCE, "operation_id": "process_refund"},
            ),
            "selected_operation": {
                "resource_id": _OPERATION_RESOURCE,
                "operation_id": "process_refund",
            },
            "verifier": {
                "status": "verified",
                "detail": "the operation completes the action's effect",
                "evidence_refs": ("verification:test",),
            },
            "evidence_refs": ("inventory:tool:process_refund",),
            "rationale": "The observed state-changing operation issues a refund.",
        }


class _UnsupportedInterpreter:
    """Refuses every match the way an honest provider would."""

    def __call__(self, *, action, operations):
        return {
            "control_action_id": action["control_action_id"],
            "disposition": "unmapped",
            "candidate_operations": (),
            "selected_operation": None,
            "evidence_refs": (),
            "rationale": "No observed operation completes this action's effect.",
        }


class TestEnrichControlActions:
    def test_supported_match_names_the_documented_operation_on_the_action(self):
        structure = _control_structure()
        before = structure.model_dump(mode="json")

        enrichment = enrich_control_actions(
            loss_analysis=_loss_analysis(),
            control_structure=structure,
            profile=_profile(),
            interpreter_factory=_VerifiedInterpreter,
        )

        action = next(
            item
            for item in enrichment.control_structure.responsibilities[0].control_actions
            if item.ca_id == "CA-1-1"
        )
        assert "process_refund" in action.description
        assert action.description.startswith("Execute refund processing")
        # The unmatched action keeps its exact description.
        reply = next(
            item
            for item in enrichment.control_structure.responsibilities[0].control_actions
            if item.ca_id == "CA-1-2"
        )
        assert reply.description == "Reply to the user"
        # The input authority is never mutated.
        assert structure.model_dump(mode="json") == before

    def test_every_matching_row_is_recorded_with_disposition_and_evidence(self):
        enrichment = enrich_control_actions(
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            profile=_profile(),
            interpreter_factory=_VerifiedInterpreter,
        )

        record = enrichment.record
        assert isinstance(record, ControlActionOperationEnrichmentRecord)
        assert isinstance(record, ClosedCanonicalModel)
        assert record.schema_version == "control-action-operation-enrichment-v1"
        assert record.observed_operations == 2
        by_action = {row.control_action_id: row for row in record.rows}
        assert by_action["CA-1-1"].disposition == "supported"
        assert by_action["CA-1-1"].operation_id == "process_refund"
        assert by_action["CA-1-1"].enriched is True
        assert by_action["CA-1-1"].verification_status == "verified"
        assert by_action["CA-1-1"].evidence_refs == ("inventory:tool:process_refund",)
        assert by_action["CA-1-2"].enriched is False
        assert record.enriched_action_ids == ("CA-1-1",)

    def test_unverified_selection_never_specializes_the_action(self):
        class _NoVerifierEvidence(_VerifiedInterpreter):
            def __call__(self, *, action, operations):
                response = super().__call__(action=action, operations=operations)
                response["verifier"] = {
                    "status": "unverified",
                    "detail": "the independent verifier could not confirm the pair",
                    "evidence_refs": ("verification:test",),
                }
                return response

        enrichment = enrich_control_actions(
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            profile=_profile(),
            interpreter_factory=_NoVerifierEvidence,
        )

        action = enrichment.control_structure.responsibilities[0].control_actions[0]
        assert action.description == "Execute refund processing"
        assert enrichment.record.enriched_action_ids == ()
        row = enrichment.record.rows[0]
        assert row.disposition != TargetRealizationDisposition.supported.value
        assert row.enriched is False

    def test_unmapped_match_keeps_the_action_and_is_recorded(self):
        enrichment = enrich_control_actions(
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            profile=_profile(),
            interpreter_factory=_UnsupportedInterpreter,
        )

        assert (
            enrichment.control_structure.responsibilities[0]
            .control_actions[0]
            .description
            == "Execute refund processing"
        )
        assert enrichment.record.enriched_action_ids == ()
        assert all(row.disposition == "unmapped" for row in enrichment.record.rows)

    def test_selection_outside_the_observed_inventory_fails_closed(self):
        class _InventedInterpreter(_VerifiedInterpreter):
            def __call__(self, *, action, operations):
                response = super().__call__(action=action, operations=operations)
                invented = {
                    "resource_id": "mcp:other:delete_everything",
                    "operation_id": "delete_everything",
                }
                response["candidate_operations"] = (
                    *response["candidate_operations"],
                    invented,
                )
                response["selected_operation"] = invented
                return response

        with pytest.raises(ValueError, match="observed inventory"):
            enrich_control_actions(
                loss_analysis=_loss_analysis(),
                control_structure=_control_structure(),
                profile=_profile(),
                interpreter_factory=_InventedInterpreter,
            )

    def test_provider_failure_is_fatal(self):
        class _BrokenInterpreter:
            def __call__(self, *, action, operations):
                raise RuntimeError("provider unavailable")

        with pytest.raises(Exception, match="provider unavailable"):
            enrich_control_actions(
                loss_analysis=_loss_analysis(),
                control_structure=_control_structure(),
                profile=_profile(),
                interpreter_factory=_BrokenInterpreter,
            )


class TestEnrichmentAdapterWiring:
    def test_enrich_actions_port_is_resolved_from_its_field_name(self):
        class _Fake:
            def enrich_actions(self, **kwargs):
                return "enriched"

        resolved = _resolve_adapters(_Fake())
        assert resolved.enrich_actions is not None
        assert resolved.enrich_actions(**{"loss_analysis": None}) == "enriched"
        assert "enrich_actions" in SynthesisAdapters.__dataclass_fields__

    def test_default_adapter_skips_profileless_and_simulation_inputs(self):
        inputs = SimpleNamespace(
            profile="unused",
            profiles_file="config/model-profiles.yaml",
            temperature=0.4,
            output_dir="/tmp/unused",
        )
        assert (
            _default_enrich_control_actions(
                loss_analysis=_loss_analysis(),
                control_structure=_control_structure(),
                capability_profile=None,
                execution_target_profile=None,
                inputs=inputs,
                output_dir="/tmp/unused",
            )
            is None
        )
        simulation = SimpleNamespace(basis=ProfileBasis.simulation)
        assert (
            _default_enrich_control_actions(
                loss_analysis=_loss_analysis(),
                control_structure=_control_structure(),
                capability_profile=None,
                execution_target_profile=simulation,
                inputs=inputs,
                output_dir="/tmp/unused",
            )
            is None
        )

    def test_default_adapter_grounds_an_observed_profile_with_the_run_client(
        self, monkeypatch, tmp_path
    ):
        built = []

        def llm_interpreter(client, run_dir, *, temperature, call_variant):
            built.append((client, run_dir, temperature, call_variant))
            return _VerifiedInterpreter()

        monkeypatch.setattr(
            "asago_scenario_generator.stpa.target_realization."
            "TargetRealizationLlmInterpreter",
            llm_interpreter,
        )
        client = object()

        enrichment = _default_enrich_control_actions(
            loss_analysis=_loss_analysis(),
            control_structure=_control_structure(),
            capability_profile=None,
            execution_target_profile=_profile(),
            inputs=None,
            output_dir=tmp_path,
            model_runtime=SimpleNamespace(client=client, temperature=lambda: 0.25),
        )

        assert built == [(client, tmp_path, 0.25, "control_action_enrichment")]
        actions = enrichment.control_structure.responsibilities[0].control_actions
        assert any("process_refund" in item.description for item in actions)

    def test_sidecar_filename_is_the_run_directory_name(self):
        assert CONTROL_ACTION_ENRICHMENT_FILENAME == ("control-action-enrichment.yaml")


class TestVerifiedEnrichedOperations:
    """Only verified enriched rows may name a documented operation."""

    @staticmethod
    def _row(control_action_id: str, **overrides: object):
        values: dict = {
            "control_action_id": control_action_id,
            "controller_id": "RESP-1",
            "disposition": "unmapped",
            "enriched": False,
        }
        values.update(overrides)
        return ControlActionEnrichmentRow.model_validate(values)

    def test_only_verified_enriched_rows_contribute(self):

        record = ControlActionOperationEnrichmentRecord(
            profile_digest="profile-digest",
            control_structure_digest="structure-digest",
            observed_operations=2,
            rows=(
                self._row(
                    "CA-1-1",
                    disposition="supported",
                    operation_id="process_refund",
                    verification_status="verified",
                    enriched=True,
                ),
                # An unverified selection never specializes and never names.
                self._row(
                    "CA-1-2",
                    disposition="contradictory",
                    verification_status="unverified",
                    enriched=False,
                ),
                # An unmapped row has no operation identity to name.
                self._row("CA-1-3"),
            ),
            enriched_action_ids=("CA-1-1",),
        )

        assert _verified_enriched_operations(record) == {"CA-1-1": "process_refund"}

    def test_wrapped_enrichment_and_none_contribute_nothing(self):
        assert _verified_enriched_operations(None) == {}
        wrapped = SimpleNamespace(
            record=SimpleNamespace(
                rows=(
                    SimpleNamespace(
                        control_action_id="CA-1-1",
                        operation_id="process_refund",
                        verification_status="verified",
                        enriched=True,
                    ),
                )
            )
        )
        assert _verified_enriched_operations(wrapped) == {"CA-1-1": "process_refund"}

    def test_verified_target_derived_records_merge_with_baseline_operations(self):
        target_realization = SimpleNamespace(
            operation_records=(
                SimpleNamespace(
                    provenance="target_derived",
                    disposition="supported",
                    target_derived_control_action_id="CA-1-2",
                    operation=SimpleNamespace(
                        resource_id=_OPERATION_RESOURCE,
                        operation_id="schedule_payment",
                    ),
                    evidence_refs=(
                        "target-realization:verified-pair:CA-1-2:"
                        f"{_OPERATION_RESOURCE}/schedule_payment",
                    ),
                ),
            )
        )

        assert _verified_enriched_operations(
            SimpleNamespace(
                record=SimpleNamespace(
                    rows=(
                        self._row(
                            "CA-1-1",
                            disposition="supported",
                            operation_id="process_refund",
                            verification_status="verified",
                            enriched=True,
                        ),
                    )
                )
            ),
            target_realization,
        ) == {
            "CA-1-1": "process_refund",
            "CA-1-2": "schedule_payment",
        }

    def test_verified_baseline_row_recovers_an_unmapped_enrichment(self):
        operation_resource = mcp_resource_id("miniklarna", "get_account_details")
        operation_id = "get_account_details"
        evidence = (
            "target-realization:verified-pair:CA-3-1:"
            f"{operation_resource}/{operation_id}"
        )
        operation_reference = TargetOperationReference(
            resource_id=operation_resource,
            operation_id=operation_id,
        )
        target_realization = SimpleNamespace(
            rows=(
                TargetRealizationRow(
                    control_action_id="CA-3-1",
                    controller_id="RESP-3",
                    provenance=TargetRealizationProvenance.systemic_baseline,
                    disposition=TargetRealizationDisposition.supported,
                    candidate_operations=(operation_reference,),
                    selected_operation=operation_reference,
                    verifier=TargetRealizationVerification(
                        status="verified",
                        evidence_refs=(evidence,),
                    ),
                ),
            ),
            operation_records=(),
        )
        enrichment = SimpleNamespace(
            record=SimpleNamespace(
                rows=(
                    self._row(
                        "CA-3-1",
                        disposition="unmapped",
                        enriched=False,
                    ),
                )
            )
        )

        assert _verified_enriched_operations(enrichment, target_realization) == {
            "CA-3-1": operation_id
        }

    @pytest.mark.parametrize(
        "row",
        (
            SimpleNamespace(
                control_action_id="CA-3-1",
                provenance=TargetRealizationProvenance.systemic_baseline,
                disposition="supported",
                selected_operation=SimpleNamespace(
                    resource_id="mcp:miniklarna:get_account_details",
                    operation_id="get_account_details",
                ),
                verifier=SimpleNamespace(
                    status="unverified",
                    evidence_refs=(
                        "target-realization:verified-pair:CA-3-1:"
                        "mcp:miniklarna:get_account_details/get_account_details",
                    ),
                ),
            ),
            SimpleNamespace(
                control_action_id="CA-3-1",
                provenance=TargetRealizationProvenance.systemic_baseline,
                disposition="supported",
                selected_operation=SimpleNamespace(
                    resource_id="mcp:miniklarna:get_account_details",
                    operation_id="get_account_details",
                ),
                verifier=SimpleNamespace(
                    status="verified",
                    evidence_refs=("target-realization:verified-pair:CA-3-1:other",),
                ),
            ),
            SimpleNamespace(
                control_action_id="CA-3-1",
                provenance=TargetRealizationProvenance.systemic_baseline,
                disposition="ambiguous",
                selected_operation=None,
                verifier=SimpleNamespace(
                    status="verified",
                    evidence_refs=(
                        "target-realization:verified-pair:CA-3-1:"
                        "mcp:miniklarna:get_account_details/get_account_details",
                    ),
                ),
            ),
        ),
    )
    def test_unverified_or_ambiguous_baseline_rows_contribute_nothing(self, row):
        assert (
            _verified_enriched_operations(
                None,
                SimpleNamespace(rows=(row,), operation_records=()),
            )
            == {}
        )

    def test_duplicate_verified_baseline_rows_contribute_nothing(self):
        rows = tuple(
            SimpleNamespace(
                control_action_id="CA-3-1",
                provenance=TargetRealizationProvenance.systemic_baseline,
                disposition="supported",
                selected_operation=SimpleNamespace(
                    resource_id=resource_id,
                    operation_id=operation_id,
                ),
                verifier=SimpleNamespace(
                    status="verified",
                    evidence_refs=(
                        f"target-realization:verified-pair:CA-3-1:"
                        f"{resource_id}/{operation_id}",
                    ),
                ),
            )
            for resource_id, operation_id in (
                ("mcp:miniklarna:get_account_details", "get_account_details"),
                ("mcp:miniklarna:lookup_order", "lookup_order"),
            )
        )

        assert (
            _verified_enriched_operations(
                None,
                SimpleNamespace(rows=rows, operation_records=()),
            )
            == {}
        )

    @pytest.mark.parametrize(
        "record",
        (
            # The operation is not independently verified.
            SimpleNamespace(
                provenance="target_derived",
                disposition="supported",
                target_derived_control_action_id="CA-1-2",
                operation=SimpleNamespace(
                    resource_id=_OPERATION_RESOURCE,
                    operation_id="schedule_payment",
                ),
                evidence_refs=(),
            ),
            # An ambiguous realization cannot choose an operation.
            SimpleNamespace(
                provenance="target_derived",
                disposition="ambiguous",
                target_derived_control_action_id="CA-1-2",
                operation=SimpleNamespace(
                    resource_id=_OPERATION_RESOURCE,
                    operation_id="schedule_payment",
                ),
                evidence_refs=(
                    "target-realization:verified-pair:CA-1-2:"
                    f"{_OPERATION_RESOURCE}/schedule_payment",
                ),
            ),
            # Evidence for a different operation does not attest this record.
            SimpleNamespace(
                provenance="target_derived",
                disposition="supported",
                target_derived_control_action_id="CA-1-2",
                operation=SimpleNamespace(
                    resource_id=_OPERATION_RESOURCE,
                    operation_id="schedule_payment",
                ),
                evidence_refs=(
                    "target-realization:verified-pair:CA-1-2:"
                    f"{_OPERATION_RESOURCE}/process_refund",
                ),
            ),
        ),
    )
    def test_unverified_ambiguous_or_mismatched_target_records_contribute_nothing(
        self, record
    ):
        target_realization = SimpleNamespace(operation_records=(record,))

        assert _verified_enriched_operations(None, target_realization) == {}
