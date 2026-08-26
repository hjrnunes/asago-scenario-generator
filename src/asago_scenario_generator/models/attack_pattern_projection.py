"""Projection resource bindings and immutable projection snapshots."""

from __future__ import annotations

from typing import Annotated, Literal, TypeAlias

from pydantic import Field, model_validator

from .attack_pattern_chain import (
    CanonicalAttackChain,
    CanonicalChainStep,
    Digest,
    Identifier,
    ResourceSlot,
    _slots_by_id,
)
from .attack_pattern_contracts import (
    ConditionEvaluationResult,
    ContractModel,
    SourceInfluencePath,
    evaluate_condition,
)
from .attack_pattern_digests import compute_projection_digest


class EntryPointResourceReference(ContractModel):
    kind: Literal["entry_point"]
    entry_point_id: str = Field(pattern=r"^ep:v1:[0-9a-f]{32}$")


class ToolResourceReference(ContractModel):
    kind: Literal["tool"]
    tool_id: str = Field(pattern=r"^tool:v1:[0-9a-f]{32}$")


class IntegrationResourceReference(ContractModel):
    kind: Literal["integration"]
    integration_id: str = Field(pattern=r"^int:v1:[0-9a-f]{32}$")


class TrustBoundaryResourceReference(ContractModel):
    kind: Literal["trust_boundary"]
    trust_boundary_id: str = Field(pattern=r"^tb:v1:[0-9a-f]{32}$")


class OutputSurfaceResourceReference(ContractModel):
    """Canonical reference to an output-direction entry point.

    An output surface is the agent's rendered-response surface — the
    model's output that a client renders or fetches.  It is distinct from
    an input entry point (``EntryPointResourceReference``) even though
    both resolve to an :class:`EntryPoint` in the capability profile:
    only entry points with ``direction == "output"`` qualify as output
    surfaces.
    """

    kind: Literal["output_surface"]
    entry_point_id: str = Field(pattern=r"^ep:v1:[0-9a-f]{32}$")


class AgentInternalResourceReference(ContractModel):
    """Canonical reference to agent-internal state.

    Agent-internal state is data assembled or transformed within the
    agent's own working context — neither an external entry point, tool,
    integration, nor trust boundary.  It is the intrinsic singleton working
    state of the profiled agent, so it requires no adapter inventory identity.
    Candidate-v2 resolves exactly this typed singleton rather than laundering
    it through an unrelated tool or integration binding.
    """

    kind: Literal["agent_internal"]


CanonicalResourceReference: TypeAlias = Annotated[
    EntryPointResourceReference
    | ToolResourceReference
    | IntegrationResourceReference
    | TrustBoundaryResourceReference
    | OutputSurfaceResourceReference
    | AgentInternalResourceReference,
    Field(discriminator="kind"),
]


class ResourceBinding(ContractModel):
    slot_id: Identifier
    resource_ref: CanonicalResourceReference


class StepOmission(ContractModel):
    step_id: Identifier
    reason: Literal["condition_false"]


class ProjectionSnapshot(ContractModel):
    """Local structural/pure semantic parse; use qualification for external facts."""

    schema_version: Literal["1"]
    source_chain: CanonicalAttackChain
    selected_step_ids: tuple[Identifier, ...] = Field(min_length=1)
    condition_results: tuple[ConditionEvaluationResult, ...]
    omissions: tuple[StepOmission, ...]
    bindings: tuple[ResourceBinding, ...]
    catalog_pin: Digest
    pattern_pin: Digest
    capability_fact_snapshot_digest: Digest
    projection_digest: Digest
    source_influence_paths: tuple[SourceInfluencePath, ...] = ()

    @model_validator(mode="after")
    def semantics(self) -> ProjectionSnapshot:
        source_ids = _step_ids(self.source_chain)
        selected = list(self.selected_step_ids)
        omitted = _omitted_step_ids(self.omissions)
        _check_projection_partition(selected, omitted, source_ids)
        _check_condition_results_unique(self.condition_results)
        _check_bindings_unique(self.bindings)
        slots = _slots_by_id(self.source_chain)
        _check_binding_coverage(slots, self.bindings)
        _check_binding_kinds(slots, self.bindings)
        bindings_by_slot = _binding_refs_by_slot(self.bindings)
        _check_distinct_bindings(slots, bindings_by_slot)
        _check_ingress_binding(self.bindings, self.source_chain.initial_ingress_slot_id)
        results = _condition_results_map(self.condition_results)
        conditional_ids = _conditional_step_ids(self.source_chain)
        _check_condition_result_coverage(results, conditional_ids)
        _check_no_unknown_results(results)
        conditional_steps = _conditional_steps_map(self.source_chain)
        _check_recorded_results(self.condition_results, conditional_steps)
        _check_selected_matches_results(self.source_chain, selected, results)
        _check_omissions_match_results(omitted, results)
        _check_terminal_selected(self.source_chain, selected)
        _check_projection_digest(self)
        return self


def _check_partition_ids_unique(selected: list[str], omitted: list[str]) -> None:
    """Selected and omitted ids must each be duplicate-free."""
    if len(set(selected)) != len(selected) or len(set(omitted)) != len(omitted):
        raise ValueError("selected and omitted step ids must be unique")


def _check_partition_exact(
    selected: list[str], omitted: list[str], source_ids: list[str]
) -> None:
    """Selected and omitted must exactly partition the source steps."""
    if set(selected) & set(omitted) or set(selected) | set(omitted) != set(source_ids):
        raise ValueError(
            "selected and omitted steps must exactly partition source steps"
        )


def _check_selected_order(selected: list[str], source_ids: list[str]) -> None:
    """Selected steps must retain the source chain order."""
    if selected != [step_id for step_id in source_ids if step_id in set(selected)]:
        raise ValueError("selected steps must retain source chain order")


def _step_ids(chain: CanonicalAttackChain) -> list[str]:
    """Step ids in source order."""
    return [s.step_id for s in chain.steps]


def _omitted_step_ids(omissions: tuple[StepOmission, ...]) -> list[str]:
    """Omitted step ids."""
    return [o.step_id for o in omissions]


def _condition_results_map(
    results: tuple[ConditionEvaluationResult, ...],
) -> dict[str, str]:
    """Condition results indexed by step id."""
    return {r.condition_step_id: r.result for r in results}


def _conditional_step_ids(chain: CanonicalAttackChain) -> set[str]:
    """Ids of conditional steps."""
    return {s.step_id for s in chain.steps if s.requirement == "conditional"}


def _conditional_steps_map(
    chain: CanonicalAttackChain,
) -> dict[str, CanonicalChainStep]:
    """Conditional steps indexed by step id."""
    return {
        step.step_id: step for step in chain.steps if step.requirement == "conditional"
    }


def _binding_refs_by_slot(
    bindings: tuple[ResourceBinding, ...],
) -> dict[str, CanonicalResourceReference]:
    """Binding resource references indexed by slot id."""
    return {binding.slot_id: binding.resource_ref for binding in bindings}


def _check_projection_partition(
    selected: list[str], omitted: list[str], source_ids: list[str]
) -> None:
    """Selected and omitted ids are unique and exactly partition the steps."""
    _check_partition_ids_unique(selected, omitted)
    _check_partition_exact(selected, omitted, source_ids)
    _check_selected_order(selected, source_ids)


def _check_condition_results_unique(
    results: tuple[ConditionEvaluationResult, ...],
) -> None:
    """Condition result step ids must be unique."""
    if len({r.condition_step_id for r in results}) != len(results):
        raise ValueError("condition result step ids must be unique")


def _check_bindings_unique(bindings: tuple[ResourceBinding, ...]) -> None:
    """Slot bindings must be unique."""
    if len({b.slot_id for b in bindings}) != len(bindings):
        raise ValueError("slot bindings must be unique")


def _check_binding_coverage(
    slots: dict[str, ResourceSlot], bindings: tuple[ResourceBinding, ...]
) -> None:
    """Bindings must exactly cover all source resource slots."""
    if set(slots) != {binding.slot_id for binding in bindings}:
        raise ValueError("bindings must exactly cover all source resource slots")


def _check_binding_kinds(
    slots: dict[str, ResourceSlot], bindings: tuple[ResourceBinding, ...]
) -> None:
    """Binding resource kinds must match their slots."""
    for binding in bindings:
        slot = slots.get(binding.slot_id)
        if slot is None:
            raise ValueError("binding references an absent resource slot")
        if binding.resource_ref.kind != slot.kind:
            raise ValueError("binding resource kind must match its slot")


def _check_distinct_bindings(
    slots: dict[str, ResourceSlot],
    bindings_by_slot: dict[str, CanonicalResourceReference],
) -> None:
    """Distinct-slot constraints require distinct bound identities."""
    for slot in slots.values():
        for distinct_slot_id in slot.distinct_from_slot_ids:
            if bindings_by_slot[slot.slot_id] == bindings_by_slot[distinct_slot_id]:
                raise ValueError(
                    f"bindings for slots {slot.slot_id} and {distinct_slot_id} "
                    "must have distinct identities"
                )


def _ingress_bindings(
    bindings: tuple[ResourceBinding, ...], initial_ingress_slot_id: str
) -> list[ResourceBinding]:
    """Bindings on the initial ingress slot."""
    return [b for b in bindings if b.slot_id == initial_ingress_slot_id]


def _check_ingress_binding(
    bindings: tuple[ResourceBinding, ...], initial_ingress_slot_id: str
) -> None:
    """The ingress binding must be an entry-point canonical reference."""
    ingress = _ingress_bindings(bindings, initial_ingress_slot_id)
    if len(ingress) != 1 or not isinstance(
        ingress[0].resource_ref, EntryPointResourceReference
    ):
        raise ValueError("ingress binding must be an entry-point canonical reference")


def _check_condition_result_coverage(
    results: dict[str, str], conditional_ids: set[str]
) -> None:
    """Condition results must exactly cover conditional source steps."""
    if set(results) != conditional_ids:
        raise ValueError(
            "condition results must exactly cover conditional source steps"
        )


def _check_no_unknown_results(results: dict[str, str]) -> None:
    """Projection condition results cannot be unknown."""
    if any(result == "unknown" for result in results.values()):
        raise ValueError("projection condition results cannot be unknown")


def _check_recorded_results(
    condition_results: tuple[ConditionEvaluationResult, ...],
    conditional_steps: dict[str, CanonicalChainStep],
) -> None:
    """Recorded results must match the evidence evaluation."""
    for result in condition_results:
        condition = conditional_steps[result.condition_step_id].condition
        if condition is None:  # pragma: no cover - guaranteed by step validation
            raise ValueError("conditional source step requires a condition")
        evaluated = evaluate_condition(condition, result.evidence)
        if evaluated != result.result:
            raise ValueError("recorded condition result does not match evidence")


def _check_selected_matches_results(
    chain: CanonicalAttackChain,
    selected: list[str],
    results: dict[str, str],
) -> None:
    """Selected steps follow requirements and condition results."""
    expected_selected = [
        s.step_id
        for s in chain.steps
        if s.requirement == "required" or results[s.step_id] == "true"
    ]
    if selected != expected_selected:
        raise ValueError("selected steps do not match source requirements and results")


def _check_omissions_match_results(omitted: list[str], results: dict[str, str]) -> None:
    """Omissions must exactly identify false conditional steps."""
    expected_omitted = {
        step_id for step_id, result in results.items() if result == "false"
    }
    if set(omitted) != expected_omitted:
        raise ValueError("omissions must exactly identify false conditional steps")


def _check_terminal_selected(chain: CanonicalAttackChain, selected: list[str]) -> None:
    """The source terminal final step must be selected."""
    if chain.steps[-1].step_id not in selected:
        raise ValueError("source terminal final step must be selected")


def _check_projection_digest(snapshot: ProjectionSnapshot) -> None:
    """The signed projection digest must match the current content."""
    if snapshot.projection_digest != compute_projection_digest(snapshot):
        raise ValueError("projection_digest does not match projection semantics")


_UNORDERED_FIELDS = {
    "allowed_entry_point_controllability",
    "allowed_entry_point_directions",
    "allowed_entry_point_ingress_zones",
    "allowed_entry_point_types",
    "allowed_integration_types",
    "allowed_resource_ids",
    "allowed_trust_boundary_from_zones",
    "allowed_trust_boundary_to_zones",
    "consumed",
    "produced",
    "preconditions",
    "observable_postconditions",
    "references",
    "mappings",
    "ids",
    "resource_slots",
    "values",
    "evidence",
    "condition_results",
    "distinct_from_slot_ids",
    "omissions",
    "bindings",
    "requirements",
    "contributing_step_ids",
    "operands",
    "min_zones",
    "resource_links",
    "observable_outcome_links",
}


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T21:59:01Z","module_hash":"91b71a0b117aa7cdf9517dbd26ab637458ff687a7804c1d315c8426421c92e68","source_sha256":"3a2fa8e3205c766552367cc9d95045c7e2039fe44c4ffae01acba7c990934351","functions":[{"id":"func/ProjectionSnapshot.semantics","name":"semantics","line":112,"end_line":135,"hash":"5f25945f4fe9ff0f6765e7cc4f9302b991b50be33208a37802495a3162ccdf02"},{"id":"func/_check_partition_ids_unique","name":"_check_partition_ids_unique","line":138,"end_line":141,"hash":"e8243ac16722f7c857cf726de602741cac1cf6bbd350354918be5bcdc52af93a"},{"id":"func/_check_partition_exact","name":"_check_partition_exact","line":144,"end_line":151,"hash":"802305c6df528726667283f83e8e5f3935de8a7ac174b246f83b88eaad86c726"},{"id":"func/_check_selected_order","name":"_check_selected_order","line":154,"end_line":157,"hash":"42bc64b315a864bf6088720a54fdf7f5fa2a2917ef3528f39b74cc30a62cab4a"},{"id":"func/_step_ids","name":"_step_ids","line":160,"end_line":162,"hash":"bc479f7c66e435196535367f027ae0cbaf9b6595196d5f1ce07f02a9eed752a9"},{"id":"func/_omitted_step_ids","name":"_omitted_step_ids","line":165,"end_line":167,"hash":"96fac325f25c4c193868738d6cb4611d73d2ff48636fca6f77e3931751e7c24e"},{"id":"func/_condition_results_map","name":"_condition_results_map","line":170,"end_line":174,"hash":"2cbe1cd8ca94980f1375efca7f072b25a5aa36e708b974eb91a5f6e3241bd2cd"},{"id":"func/_conditional_step_ids","name":"_conditional_step_ids","line":177,"end_line":179,"hash":"ae91f706d2ee1fde87349aa82166698c1692c58b6c08851d89349eb7d9139d0e"},{"id":"func/_conditional_steps_map","name":"_conditional_steps_map","line":182,"end_line":188,"hash":"d9100ab8a50d9128b646718215590ff418414ef752c072588d27a46be55b0fa4"},{"id":"func/_binding_refs_by_slot","name":"_binding_refs_by_slot","line":191,"end_line":195,"hash":"07752dbb8132cafdd93aa3a0d546a5d1e80ec0bfc3f0be2687fd109e2276ebd3"},{"id":"func/_check_projection_partition","name":"_check_projection_partition","line":198,"end_line":204,"hash":"61d0f0d80f68332c5e536ea78ac5e281b40c3c89e62ef88c694c6465b3f1d872"},{"id":"func/_check_condition_results_unique","name":"_check_condition_results_unique","line":207,"end_line":212,"hash":"91cc69b52fd3f84abb0721c4b7e26dee600ee57e26ac2b1fc72dc57b77a9de4b"},{"id":"func/_check_bindings_unique","name":"_check_bindings_unique","line":215,"end_line":218,"hash":"f26a73eabaa79f4ccd1a58119978a558392d8831a9a7aa0d0e4c4c6fb68a22d4"},{"id":"func/_check_binding_coverage","name":"_check_binding_coverage","line":221,"end_line":226,"hash":"d32d411c62fef8fbf35a177f9dad20dda4cd52402fceb67c3210fdc66d808a2d"},{"id":"func/_check_binding_kinds","name":"_check_binding_kinds","line":229,"end_line":238,"hash":"a888f5bab83150501d3ce0c5655faba70449249be99fda1adf694a600d53c3bd"},{"id":"func/_check_distinct_bindings","name":"_check_distinct_bindings","line":241,"end_line":252,"hash":"3ffc0d07884a90f896ee6988e3f12ce872d1f904c50cdf0709d58ba631dbc641"},{"id":"func/_ingress_bindings","name":"_ingress_bindings","line":255,"end_line":259,"hash":"92bf6d27556b7f0bc345616d5ae9d17b79cb0a11512ff1ca7a3630a6e6aaae46"},{"id":"func/_check_ingress_binding","name":"_check_ingress_binding","line":262,"end_line":270,"hash":"3c8a5ac64aaafb807b18c087b6032275514f8e21a2600cefddf6dc3adc1ba68f"},{"id":"func/_check_condition_result_coverage","name":"_check_condition_result_coverage","line":273,"end_line":280,"hash":"2f685b9033007a8b8630cd07761c38d7384ab117dffe1ec1f75e96e816cfbf9a"},{"id":"func/_check_no_unknown_results","name":"_check_no_unknown_results","line":283,"end_line":286,"hash":"1af4f80b750e30319d49be44078d2b7e995cde94b9044f517930dc09bd8820ef"},{"id":"func/_check_recorded_results","name":"_check_recorded_results","line":289,"end_line":300,"hash":"840c12a77b2df2411f66be61db63a953f4bf2e8cede4225d4cded6dfdef38b39"},{"id":"func/_check_selected_matches_results","name":"_check_selected_matches_results","line":303,"end_line":315,"hash":"888093d545eb504fc460b5b60157b0e16875da32bc6e7882c83890acec4331ca"},{"id":"func/_check_omissions_match_results","name":"_check_omissions_match_results","line":318,"end_line":324,"hash":"8fe88eb85166881d4817526d4af167c0f50ba985f435d897a6ce6adefee127dc"},{"id":"func/_check_terminal_selected","name":"_check_terminal_selected","line":327,"end_line":330,"hash":"d9b6f2f11e9cba3f0d164eaec4f4a80b82d06ec64a09937c399f77b2e22137ef"},{"id":"func/_check_projection_digest","name":"_check_projection_digest","line":333,"end_line":336,"hash":"8b97c6cd6a29c875e16a4f9bcef4e29ed7dfbdfd483252da2211fe45e079e86c"}]}
# mutate4py-manifest-end
