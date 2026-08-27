"""Canonical attack-chain and attack-pattern models."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, StrictBool, StrictInt, model_validator

from .attack_pattern_contracts import (
    ChainMappingDecision,
    Condition,
    ContractModel,
    Digest,
    ExactMapping,
    Identifier,
    InputReference,
    MappingDecision,
    NotApplicableMapping,
    NistClassification,
    ObservableOutcomeLink,
    ObservablePostcondition,
    OutputReference,
    PrerequisiteCapabilities,
    StepPrecondition,
    StepProvenance,
    StepResourceLink,
    TaxonomyContext,
    _check_condition,
)
from .attack_pattern_digests import compute_chain_semantic_digest


class CanonicalChainStep(ContractModel):
    step_id: Identifier
    requirement: Literal["required", "conditional"]
    condition: Condition | None = None
    executor_role: Literal["attacker", "system", "operator"]
    boundary_position: Literal["outside", "crossing", "inside"]
    action_kind: Literal[
        "prepare", "deliver", "invoke", "transform", "persist", "observe", "impact"
    ]
    consumed: tuple[InputReference, ...]
    produced: tuple[OutputReference, ...] = Field(min_length=1)
    preconditions: tuple[StepPrecondition, ...]
    observable_postconditions: tuple[ObservablePostcondition, ...] = Field(min_length=1)
    resource_links: tuple[StepResourceLink, ...] = ()
    observable_outcome_links: tuple[ObservableOutcomeLink, ...] = ()
    order: StrictInt = Field(gt=0)
    attacker_controlled: StrictBool
    provenance: StepProvenance
    mappings: tuple[MappingDecision, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def semantics(self) -> CanonicalChainStep:
        _validate_step_semantics(self)
        return self


def _validate_step_semantics(step: CanonicalChainStep) -> None:
    """Run each canonical step invariant in a stable, explicit order."""
    for validator in (
        _check_step_condition_agreement,
        _check_step_collections_unique,
        _check_outcome_link_duplicates,
        _check_outcome_link_targets,
        _check_outside_step_outcome_links,
        _check_security_outcome_links,
        _check_conditional_activation_links,
        _check_step_taxonomy_scope,
        _check_step_executor_agreement,
        _check_attacker_mappings,
        _check_system_mappings,
    ):
        validator(step)


def _check_step_condition_agreement(step: CanonicalChainStep) -> None:
    """Conditional steps require a condition; required steps forbid it."""
    if (step.requirement == "conditional") != (step.condition is not None):
        raise ValueError(
            "conditional steps require a condition; required steps forbid it"
        )
    if step.condition is not None:
        _check_condition(step.condition)


def _check_step_collections_unique(step: CanonicalChainStep) -> None:
    """Each step collection is duplicate-free on its identity attribute."""
    for collection, label, attribute in (
        (step.consumed, "consumed references", "ref_id"),
        (step.produced, "produced references", "ref_id"),
        (step.preconditions, "preconditions", "condition_id"),
        (
            step.observable_postconditions,
            "observable postconditions",
            "postcondition_id",
        ),
        (step.resource_links, "resource links", "slot_id"),
    ):
        ids = [getattr(item, attribute) for item in collection]
        if len(ids) != len(set(ids)):
            raise ValueError(f"duplicate ids in {label}")


def _check_outcome_link_duplicates(step: CanonicalChainStep) -> None:
    """One outcome link per postcondition: requirement IDs must not collide."""
    outcome_pc_ids = [link.postcondition_id for link in step.observable_outcome_links]
    if len(outcome_pc_ids) != len(set(outcome_pc_ids)):
        raise ValueError(
            "duplicate observable outcome links for the same postcondition"
        )


def _check_outcome_link_targets(step: CanonicalChainStep) -> None:
    """Outcome links reference declared postconditions only."""
    postcondition_ids = {pc.postcondition_id for pc in step.observable_postconditions}
    for link in step.observable_outcome_links:
        if link.postcondition_id not in postcondition_ids:
            raise ValueError(
                f"observable outcome link references absent postcondition "
                f"{link.postcondition_id}"
            )


def _check_outside_step_outcome_links(step: CanonicalChainStep) -> None:
    """Outside steps are not system-observable: no outcome links allowed."""
    if step.boundary_position == "outside" and step.observable_outcome_links:
        raise ValueError(
            f"step {step.step_id} at boundary_position 'outside' must not "
            "have observable outcome links; outside-step postconditions "
            "are not system-observable"
        )


def _check_security_outcome_links(step: CanonicalChainStep) -> None:
    """Every security-relevant postcondition has exactly one outcome link."""
    if step.boundary_position != "outside":
        linked_pc_ids = {
            link.postcondition_id for link in step.observable_outcome_links
        }
        for pc in step.observable_postconditions:
            if pc.security_relevant and pc.postcondition_id not in linked_pc_ids:
                raise ValueError(
                    f"step {step.step_id} security-relevant postcondition "
                    f"{pc.postcondition_id} lacks an observable outcome link"
                )


def _check_conditional_activation_links(step: CanonicalChainStep) -> None:
    """Conditional steps must not carry deterministic activation links."""
    if step.requirement == "conditional":
        for link in step.resource_links:
            if link.role in ("ingress", "source_influence"):
                raise ValueError(
                    f"step {step.step_id} is conditional and must not "
                    f"carry an activation link (role={link.role}); "
                    "activation must be on a required step"
                )


def _check_step_taxonomy_scope(step: CanonicalChainStep) -> None:
    """Step mapping decisions cover distinct taxonomies."""
    taxonomies = [mapping.taxonomy for mapping in step.mappings]
    if len(set(taxonomies)) != len(taxonomies):
        raise ValueError("duplicate taxonomy decisions in step scope")


def _check_step_executor_agreement(step: CanonicalChainStep) -> None:
    """Executor role must agree with attacker control."""
    if (step.executor_role == "attacker") != step.attacker_controlled:
        raise ValueError("executor role must agree with attacker control")


def _check_attacker_mappings(step: CanonicalChainStep) -> None:
    """Attacker mappings must be exact or rationalized unmapped."""
    if step.attacker_controlled:
        if any(isinstance(m, NotApplicableMapping) for m in step.mappings):
            raise ValueError("attacker mappings must be exact or rationalized unmapped")


def _check_system_mappings(step: CanonicalChainStep) -> None:
    """Non-attacker mappings must all be not_applicable."""
    if not step.attacker_controlled:
        if any(not isinstance(m, NotApplicableMapping) for m in step.mappings):
            raise ValueError("non-attacker mappings must all be not_applicable")


class ResourceSlot(ContractModel):
    slot_id: Identifier
    kind: Literal[
        "entry_point",
        "tool",
        "integration",
        "trust_boundary",
        "output_surface",
        "agent_internal",
    ]
    purpose: Literal["initial_ingress", "intermediate", "target", "supporting"]
    allowed_integration_types: tuple[
        Literal[
            "api", "database", "message_queue", "file_system", "web_service", "other"
        ],
        ...,
    ] = ()
    allowed_entry_point_types: tuple[
        Literal[
            "user_input",
            "external_content",
            "configuration_load",
            "system_event",
            "inter_agent_message",
            "other",
        ],
        ...,
    ] = ()
    allowed_entry_point_directions: tuple[
        Literal["input", "output", "bidirectional"], ...
    ] = ()
    allowed_entry_point_controllability: tuple[
        Literal["direct", "indirect", "system"], ...
    ] = ()
    allowed_entry_point_ingress_zones: tuple[
        Literal["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        ...,
    ] = ()
    allowed_trust_boundary_from_zones: tuple[
        Literal["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        ...,
    ] = ()
    allowed_trust_boundary_to_zones: tuple[
        Literal["input", "reasoning", "tool_execution", "memory", "inter_agent"],
        ...,
    ] = ()
    allowed_resource_ids: tuple[Identifier, ...] = ()
    distinct_from_slot_ids: tuple[Identifier, ...] = ()

    @model_validator(mode="after")
    def typed_constraints_match_kind(self) -> ResourceSlot:
        _check_slot_constraint_kinds(self)
        _check_slot_constraint_lists_unique(self)
        _check_slot_distinct_refs(self)
        return self


def _check_slot_constraint_kinds(slot: ResourceSlot) -> None:
    """Typed constraint families require a matching slot kind."""
    groups = {
        "integration": slot.allowed_integration_types,
        "entry_point": (
            slot.allowed_entry_point_types
            + slot.allowed_entry_point_directions
            + slot.allowed_entry_point_controllability
            + slot.allowed_entry_point_ingress_zones
        ),
        "trust_boundary": (
            slot.allowed_trust_boundary_from_zones
            + slot.allowed_trust_boundary_to_zones
        ),
    }
    for constrained_kind, values in groups.items():
        if values and slot.kind != constrained_kind:
            raise ValueError(
                f"{constrained_kind} constraints require a {constrained_kind} slot"
            )


def _check_slot_constraint_lists_unique(slot: ResourceSlot) -> None:
    """Each constraint list must be duplicate-free."""
    constraint_groups = (
        slot.allowed_integration_types,
        slot.allowed_entry_point_types,
        slot.allowed_entry_point_directions,
        slot.allowed_entry_point_controllability,
        slot.allowed_entry_point_ingress_zones,
        slot.allowed_trust_boundary_from_zones,
        slot.allowed_trust_boundary_to_zones,
        slot.allowed_resource_ids,
    )
    if any(len(values) != len(set(values)) for values in constraint_groups):
        raise ValueError("each resource-slot constraint list must be unique")


def _check_slot_distinct_refs(slot: ResourceSlot) -> None:
    """Distinct references must be unique and never self-referential."""
    if len(slot.distinct_from_slot_ids) != len(set(slot.distinct_from_slot_ids)):
        raise ValueError("distinct resource-slot references must be unique")
    if slot.slot_id in slot.distinct_from_slot_ids:
        raise ValueError("resource slot cannot be distinct from itself")


class CanonicalAttackChain(ContractModel):
    schema_version: Literal["v1"]
    pattern_id: Identifier
    chain_id: Identifier
    semantic_revision: StrictInt = Field(gt=0)
    semantic_digest: Digest
    taxonomy_context: TaxonomyContext
    mappings: tuple[ChainMappingDecision, ...] = Field(min_length=1)
    steps: tuple[CanonicalChainStep, ...] = Field(min_length=1)
    earliest_attacker_controlled_step_id: Identifier
    resource_slots: tuple[ResourceSlot, ...] = Field(min_length=1)
    initial_ingress_slot_id: Identifier

    @model_validator(mode="after")
    def semantics(self) -> CanonicalAttackChain:
        _check_chain_taxonomy_scope(self)
        _check_step_ids_and_order(self)
        _check_earliest_attacker_step(self)
        _check_nonfinal_terminal_outcomes(self)
        _check_final_terminal_outcome(self)
        _check_attacker_exact_mapping(self)
        _check_slot_ids_unique(self)
        _check_initial_ingress_slot(self)
        _check_distinct_slot_references(self)
        _check_step_resource_links(self)
        _check_observable_outcome_links(self)
        _check_activation_mechanisms(self)
        _check_chain_digest(self)
        return self


def _chain_taxonomies(chain: CanonicalAttackChain) -> list[str]:
    """Taxonomies declared at chain scope."""
    return [mapping.taxonomy for mapping in chain.mappings]


def _chain_has_exact_mapping(chain: CanonicalAttackChain) -> bool:
    """True when a chain-scope mapping is exact."""
    return any(isinstance(mapping, ExactMapping) for mapping in chain.mappings)


def _chain_all_mappings(
    chain: CanonicalAttackChain,
) -> list[MappingDecision | ChainMappingDecision]:
    """Every mapping decision at chain and step scope."""
    return [
        mapping
        for scope in (chain.mappings, *(step.mappings for step in chain.steps))
        for mapping in scope
    ]


def _check_chain_laaf_pin(chain: CanonicalAttackChain) -> None:
    """LAAF decisions require an explicit LAAF taxonomy pin."""
    if chain.taxonomy_context.laaf is None:
        if any(mapping.taxonomy == "LAAF" for mapping in _chain_all_mappings(chain)):
            raise ValueError(
                "LAAF mapping decisions require an explicit LAAF taxonomy pin"
            )


def _check_chain_taxonomy_scope(chain: CanonicalAttackChain) -> None:
    """Chain mapping scope: unique taxonomies, an exact mapping, LAAF pin."""
    taxonomies = _chain_taxonomies(chain)
    if len(taxonomies) != len(set(taxonomies)):
        raise ValueError("duplicate taxonomy decisions in chain scope")
    if not _chain_has_exact_mapping(chain):
        raise ValueError("chain requires an exact ATLAS or LAAF mapping")
    _check_chain_laaf_pin(chain)


def _check_step_ids_and_order(chain: CanonicalAttackChain) -> None:
    """Step ids are unique and ordered 1..N."""
    if len({s.step_id for s in chain.steps}) != len(chain.steps):
        raise ValueError("step ids must be unique")
    if [s.order for s in chain.steps] != list(range(1, len(chain.steps) + 1)):
        raise ValueError("steps must be in total order 1..N")


def _check_earliest_attacker_step(chain: CanonicalAttackChain) -> None:
    """The first step is attacker-controlled and is the earliest one."""
    if not chain.steps[0].attacker_controlled or (
        chain.earliest_attacker_controlled_step_id != chain.steps[0].step_id
    ):
        raise ValueError("earliest attacker-controlled step is incorrect")


def _check_nonfinal_terminal_outcomes(chain: CanonicalAttackChain) -> None:
    """Terminal security outcomes are only valid on the final step."""
    for step in chain.steps[:-1]:
        if any(
            out.security_relevant and out.terminal
            for out in step.observable_postconditions
        ):
            raise ValueError(
                "terminal security outcomes are only valid on the final step"
            )


def _check_final_terminal_outcome(chain: CanonicalAttackChain) -> None:
    """The final step requires a security-relevant terminal outcome."""
    if not any(
        out.security_relevant and out.terminal
        for out in chain.steps[-1].observable_postconditions
    ):
        raise ValueError(
            "final step requires an observable security-relevant terminal outcome"
        )


def _attacker_steps(chain: CanonicalAttackChain) -> list[CanonicalChainStep]:
    """The attacker-controlled steps of a chain."""
    return [s for s in chain.steps if s.attacker_controlled]


def _step_has_exact_mapping(step: CanonicalChainStep) -> bool:
    """True when a step carries an exact taxonomy mapping."""
    return any(isinstance(m, ExactMapping) for m in step.mappings)


def _check_attacker_exact_mapping(chain: CanonicalAttackChain) -> None:
    """An attacker-controlled step requires an exact taxonomy mapping."""
    attacker = _attacker_steps(chain)
    if not any(_step_has_exact_mapping(s) for s in attacker):
        raise ValueError(
            "an attacker-controlled step requires an exact taxonomy mapping"
        )


def _check_slot_ids_unique(chain: CanonicalAttackChain) -> None:
    """Resource slot ids must be unique."""
    if len({slot.slot_id for slot in chain.resource_slots}) != len(
        chain.resource_slots
    ):
        raise ValueError("resource slot ids must be unique")


def _initial_ingress_slots(chain: CanonicalAttackChain) -> list[ResourceSlot]:
    """Slots declared with the initial-ingress purpose."""
    return [slot for slot in chain.resource_slots if slot.purpose == "initial_ingress"]


def _check_initial_ingress_slot(chain: CanonicalAttackChain) -> None:
    """Exactly one initial-ingress slot, matching the declared id."""
    ingress = _initial_ingress_slots(chain)
    if len(ingress) != 1 or ingress[0].slot_id != chain.initial_ingress_slot_id:
        raise ValueError("exactly one referenced initial ingress slot is required")
    if ingress[0].kind != "entry_point":
        raise ValueError("initial ingress slot must be an entry_point")


def _slots_by_id(chain: CanonicalAttackChain) -> dict[str, ResourceSlot]:
    """Resource slots indexed by slot id."""
    return {slot.slot_id: slot for slot in chain.resource_slots}


def _slot_ids(chain: CanonicalAttackChain) -> set[str]:
    """The declared resource slot ids."""
    return {slot.slot_id for slot in chain.resource_slots}


def _check_distinct_slot_references(chain: CanonicalAttackChain) -> None:
    """Distinct slot references exist and share the referencing kind."""
    slots_by_id = _slots_by_id(chain)
    for slot in chain.resource_slots:
        for distinct_slot_id in slot.distinct_from_slot_ids:
            distinct_slot = slots_by_id.get(distinct_slot_id)
            if distinct_slot is None:
                raise ValueError(
                    f"resource slot {slot.slot_id} references absent distinct slot "
                    f"{distinct_slot_id}"
                )
            if distinct_slot.kind != slot.kind:
                raise ValueError(
                    "distinct resource-slot constraints require matching kinds"
                )


def _check_step_resource_links(chain: CanonicalAttackChain) -> None:
    """Every step resource link resolves and matches its role contract."""
    slot_ids = _slot_ids(chain)
    slots_by_id = _slots_by_id(chain)
    for step in chain.steps:
        for link in step.resource_links:
            slot = _link_slot_or_raise(step, link, slot_ids, slots_by_id)
            _check_link_role(chain, step, link, slot, slots_by_id, slot_ids)


def _link_slot_or_raise(
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot_ids: set[str],
    slots_by_id: dict[str, ResourceSlot],
) -> ResourceSlot:
    """The declared slot for a resource link, or a dangling-link error."""
    if link.slot_id not in slot_ids:
        raise ValueError(
            f"step {step.step_id} resource link references absent slot {link.slot_id}"
        )
    return slots_by_id[link.slot_id]


def _check_link_role(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot: ResourceSlot,
    slots_by_id: dict[str, ResourceSlot],
    slot_ids: set[str],
) -> None:
    """Dispatch a resource link to its role-specific contract."""
    if link.role == "ingress":
        _check_ingress_link(chain, step, link, slot)
    elif link.role == "tool_fixture":
        _check_tool_fixture_link(step, link, slot)
    elif link.role == "source_influence":
        _check_source_influence_link(chain, step, link, slots_by_id, slot_ids)


def _check_ingress_link(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot: ResourceSlot,
) -> None:
    """Ingress links reference the initial ingress on a crossing step."""
    if link.slot_id != chain.initial_ingress_slot_id:
        raise ValueError(
            f"step {step.step_id} ingress link must reference the initial ingress slot"
        )
    if step.boundary_position == "outside":
        raise ValueError(
            f"step {step.step_id} ingress link requires a "
            "crossing or inside boundary position"
        )
    if slot.kind != "entry_point":
        raise ValueError(
            f"step {step.step_id} ingress link must reference an entry_point slot"
        )


def _check_tool_fixture_link(
    step: CanonicalChainStep, link: StepResourceLink, slot: ResourceSlot
) -> None:
    """Tool-fixture links reference a tool slot."""
    if slot.kind != "tool":
        raise ValueError(
            f"step {step.step_id} tool_fixture link must reference a tool slot"
        )


def _check_source_influence_link(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slots_by_id: dict[str, ResourceSlot],
    slot_ids: set[str],
) -> None:
    """Source-influence links satisfy role, boundary, and target contracts."""
    _check_source_influence_role(step, link, slots_by_id[link.slot_id])
    _check_source_influence_boundary(step, link, slot_ids, slots_by_id)
    _check_source_influence_target(chain, step, link, slot_ids, slots_by_id)


def _check_source_influence_role(
    step: CanonicalChainStep, link: StepResourceLink, slot: ResourceSlot
) -> None:
    """Source-influence slots are entry points or integrations, on a crossing step."""
    if slot.kind not in ("entry_point", "integration"):
        raise ValueError(
            f"step {step.step_id} source_influence link must "
            "reference an entry_point or integration slot"
        )
    if step.boundary_position == "outside":
        raise ValueError(
            f"step {step.step_id} source_influence link requires "
            "a crossing or inside boundary position"
        )


def _check_source_influence_boundary(
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot_ids: set[str],
    slots_by_id: dict[str, ResourceSlot],
) -> None:
    """The trust boundary exists and is a trust_boundary slot."""
    tb = link.trust_boundary_slot_id
    if tb is None or tb not in slot_ids:
        raise ValueError(
            f"step {step.step_id} source_influence link "
            "references an absent trust_boundary slot"
        )
    if slots_by_id[tb].kind != "trust_boundary":
        raise ValueError(
            f"step {step.step_id} source_influence link "
            "trust_boundary_slot_id must reference a "
            "trust_boundary slot"
        )


def _check_source_influence_target(
    chain: CanonicalAttackChain,
    step: CanonicalChainStep,
    link: StepResourceLink,
    slot_ids: set[str],
    slots_by_id: dict[str, ResourceSlot],
) -> None:
    """The target ingress is the initial ingress entry point."""
    tg = link.target_ingress_slot_id
    if tg not in slot_ids:
        raise ValueError(
            f"step {step.step_id} source_influence link "
            f"references an absent target_ingress slot {tg}"
        )
    if tg != chain.initial_ingress_slot_id:
        raise ValueError(
            f"step {step.step_id} source_influence link "
            "target_ingress_slot_id must reference the "
            "initial ingress slot"
        )
    if slots_by_id[tg].kind != "entry_point":
        raise ValueError(
            f"step {step.step_id} source_influence link "
            "target_ingress_slot_id must reference an "
            "entry_point slot"
        )


def _outcome_slot_kind(link: ObservableOutcomeLink) -> str:
    """The slot kind required by an observation kind."""
    return {
        "model_context": "entry_point",
        "tool_invocation": "tool",
        "persistent_state": "integration",
        "rendered_output": "output_surface",
        "endpoint_receipt": "integration",
        "agent_state": "agent_internal",
    }[link.observation]


def _check_observable_outcome_links(chain: CanonicalAttackChain) -> None:
    """Outcome links resolve to slots of the observation-appropriate kind."""
    slots_by_id = _slots_by_id(chain)
    for step in chain.steps:
        for link in step.observable_outcome_links:
            if link.binding_slot_id not in slots_by_id:
                raise ValueError(
                    f"step {step.step_id} observable outcome link "
                    f"references absent slot {link.binding_slot_id}"
                )
            expected_kind = _outcome_slot_kind(link)
            if slots_by_id[link.binding_slot_id].kind != expected_kind:
                raise ValueError(
                    f"step {step.step_id} observable outcome link "
                    f"observation {link.observation} requires a "
                    f"{expected_kind} slot, got {slots_by_id[link.binding_slot_id].kind}"
                )


def _is_ingress_activation(chain: CanonicalAttackChain, link: StepResourceLink) -> bool:
    """True for a direct ingress link on the initial ingress slot."""
    return link.role == "ingress" and link.slot_id == chain.initial_ingress_slot_id


def _is_source_activation(chain: CanonicalAttackChain, link: StepResourceLink) -> bool:
    """True for a source-influence link targeting the initial ingress."""
    return (
        link.role == "source_influence"
        and link.target_ingress_slot_id == chain.initial_ingress_slot_id
    )


def _ingress_activation_links(
    chain: CanonicalAttackChain,
) -> list[tuple[str, StepResourceLink]]:
    """Direct ingress activation links across the chain."""
    return [
        (step.step_id, link)
        for step in chain.steps
        for link in step.resource_links
        if _is_ingress_activation(chain, link)
    ]


def _source_activation_links(
    chain: CanonicalAttackChain,
) -> list[tuple[str, StepResourceLink]]:
    """Source-influence activation links across the chain."""
    return [
        (step.step_id, link)
        for step in chain.steps
        for link in step.resource_links
        if _is_source_activation(chain, link)
    ]


def _raise_too_many_ingress_links(
    ingress_links: list[tuple[str, StepResourceLink]],
) -> None:
    """At most one chain-wide direct-ingress activation link."""
    if len(ingress_links) > 1:
        step_ids = ", ".join(sid for sid, _ in ingress_links)
        raise ValueError(
            f"chain has {len(ingress_links)} direct-ingress activation "
            f"links (steps: {step_ids}); at most one chain-wide "
            "activation link is permitted"
        )


def _raise_too_many_source_links(
    source_influence_links: list[tuple[str, StepResourceLink]],
) -> None:
    """At most one chain-wide source-influence activation link."""
    if len(source_influence_links) > 1:
        step_ids = ", ".join(sid for sid, _ in source_influence_links)
        raise ValueError(
            f"chain has {len(source_influence_links)} source-influence "
            f"activation links (steps: {step_ids}); at most one "
            "chain-wide activation link is permitted"
        )


def _check_activation_mechanisms(chain: CanonicalAttackChain) -> None:
    """At most one activation mechanism; never both direct and influenced."""
    ingress_links = _ingress_activation_links(chain)
    source_influence_links = _source_activation_links(chain)
    _raise_too_many_ingress_links(ingress_links)
    _raise_too_many_source_links(source_influence_links)
    if ingress_links and source_influence_links:
        raise ValueError(
            "chain has both a direct ingress link and a source_influence "
            "link to the initial ingress; exactly one activation mechanism "
            "is permitted"
        )


def _check_chain_digest(chain: CanonicalAttackChain) -> None:
    """The signed semantic digest must match the current chain content."""
    if chain.semantic_digest != compute_chain_semantic_digest(chain):
        raise ValueError("semantic_digest does not match chain semantics")


class AttackPattern(ContractModel):
    """Structurally parsed pattern; taxonomy qualification is intentionally separate."""

    id: str
    threat_id: str
    name: str
    description: str
    nist_classification: NistClassification | None = None
    prerequisite_capabilities: PrerequisiteCapabilities
    canonical_chain: CanonicalAttackChain

    @model_validator(mode="after")
    def bind_chain(self) -> AttackPattern:
        if self.canonical_chain.pattern_id != self.id:
            raise ValueError("canonical chain pattern_id must match pattern id")
        return self


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T21:09:09Z","module_hash":"0b6a023d36e7f4ecfa64caf673073ccfc7ecdf10c5fdbe3e7b11bec60d9495f1","source_sha256":"95aef1bbfe2a347d63b19b84a21c209e83acf09e516753ab93a63b0730051b17","functions":[{"id":"func/CanonicalChainStep.semantics","name":"semantics","line":54,"end_line":56,"hash":"ec76883ffa7463fc9f5f591ba702508c18ff0e46e8370022ea42fb124e5a709c"},{"id":"func/_validate_step_semantics","name":"_validate_step_semantics","line":59,"end_line":74,"hash":"17e98266d26a0b4d30384c5e00f2c75e6fffe12f2b9c08e47e29dda1994281b7"},{"id":"func/_check_step_condition_agreement","name":"_check_step_condition_agreement","line":77,"end_line":84,"hash":"e0e1ebf54669583703f4afbbb2a120475ef7bfb72ddff1adb79885193e78cfc0"},{"id":"func/_check_step_collections_unique","name":"_check_step_collections_unique","line":87,"end_line":102,"hash":"548e0cc9454a5226852df5eaa3b5bd29dd47a0c5cab70b52e527e6f76a7ca043"},{"id":"func/_check_outcome_link_duplicates","name":"_check_outcome_link_duplicates","line":105,"end_line":111,"hash":"8b1dfa9dcd26a2f7036e6a1dcf822941ab2935838c0c7506a98f7ac317cf3a1d"},{"id":"func/_check_outcome_link_targets","name":"_check_outcome_link_targets","line":114,"end_line":122,"hash":"45deec1b9c07efe8ead1ad71a67e7c6ff45cfdac37dba51608edb880379e5fc3"},{"id":"func/_check_outside_step_outcome_links","name":"_check_outside_step_outcome_links","line":125,"end_line":132,"hash":"3a46ba79fcaec72be8a6d82b34c59aaea676d0fc73daec22304095f0b991ff77"},{"id":"func/_check_security_outcome_links","name":"_check_security_outcome_links","line":135,"end_line":146,"hash":"5903fc5d67dec1ab51ea0a29c430a7082ed62bb0df4b1c41e981031624297f52"},{"id":"func/_check_conditional_activation_links","name":"_check_conditional_activation_links","line":149,"end_line":158,"hash":"2842d03778761c8d76e2c9c8f98d08f699b73813d7b59cd574cf0e85740ebaba"},{"id":"func/_check_step_taxonomy_scope","name":"_check_step_taxonomy_scope","line":161,"end_line":165,"hash":"6fc10acd117b6499ff220bf93e9e26fb5ea09ed9c0e9a497bf0c132ca3e34866"},{"id":"func/_check_step_executor_agreement","name":"_check_step_executor_agreement","line":168,"end_line":171,"hash":"95c19a8fcb95089ae7d9cc7ed75254b992b95e6768ef124c675cec8b7d2aeed3"},{"id":"func/_check_attacker_mappings","name":"_check_attacker_mappings","line":174,"end_line":178,"hash":"8ea2b524f61eb3eb8bfc2638eecf7f5e2e94adced84fd09b112f29b35e846ae4"},{"id":"func/_check_system_mappings","name":"_check_system_mappings","line":181,"end_line":185,"hash":"b94026b691d9ca8ef119df0211edc2fd18fce42aee1836a9107086bb21d6439d"},{"id":"func/ResourceSlot.typed_constraints_match_kind","name":"typed_constraints_match_kind","line":238,"end_line":242,"hash":"cff67f17f4cab2996cf24be71eadf3440a9971c4ac680945bb6a9d5e39faa06b"},{"id":"func/_check_slot_constraint_kinds","name":"_check_slot_constraint_kinds","line":245,"end_line":264,"hash":"23d6627966ab62378e68af87df44b183ca6b13aa5a2ab9aa2f79704879b4d897"},{"id":"func/_check_slot_constraint_lists_unique","name":"_check_slot_constraint_lists_unique","line":267,"end_line":280,"hash":"dcdeb5c9997d7717ae576969b1c76f233810a41b67a05d6014554b099fad4c4f"},{"id":"func/_check_slot_distinct_refs","name":"_check_slot_distinct_refs","line":283,"end_line":288,"hash":"d6e342126126c518bae4e009b44f8a0849f202668765742707caaa50fc9ea09a"},{"id":"func/CanonicalAttackChain.semantics","name":"semantics","line":305,"end_line":319,"hash":"4bc51264aa16d65e3d37b9be3f1b3e7aa6bae8bda97ca8531bb7b47230f6d6f4"},{"id":"func/_chain_taxonomies","name":"_chain_taxonomies","line":322,"end_line":324,"hash":"7a33642d8799420c535ec769a3451b33346edcf40362c5d4206e7e6111dad680"},{"id":"func/_chain_has_exact_mapping","name":"_chain_has_exact_mapping","line":327,"end_line":329,"hash":"9d4350682026b304465685b82caef527715072071b5c785b52f1969fd4016252"},{"id":"func/_chain_all_mappings","name":"_chain_all_mappings","line":332,"end_line":340,"hash":"a1a24bda6f4f3a5d96f7c930829a9a64528ff1f2453baa2b3cd26044478779a4"},{"id":"func/_check_chain_laaf_pin","name":"_check_chain_laaf_pin","line":343,"end_line":349,"hash":"5c2fd7a8d5207362b4f641814711a2bb489f1f5757595476a5217948ce7880a8"},{"id":"func/_check_chain_taxonomy_scope","name":"_check_chain_taxonomy_scope","line":352,"end_line":359,"hash":"b499488dfb944cece72b5280c4abe9c48fc8d079a22ebe3e8dd4ea91f9f32474"},{"id":"func/_check_step_ids_and_order","name":"_check_step_ids_and_order","line":362,"end_line":367,"hash":"817da5a202d7556f3f8740aee8e4887868e058a04aa132e5853023a2f2707c6a"},{"id":"func/_check_earliest_attacker_step","name":"_check_earliest_attacker_step","line":370,"end_line":375,"hash":"37c8d24f98d33295b219daea249a0c21aeda7b03e4b685512d4fb612c91fe1c0"},{"id":"func/_check_nonfinal_terminal_outcomes","name":"_check_nonfinal_terminal_outcomes","line":378,"end_line":387,"hash":"f8a808d8e69fe5447ee769311e5258df5f4388181dd9b11ce7c64e0bf005ba54"},{"id":"func/_check_final_terminal_outcome","name":"_check_final_terminal_outcome","line":390,"end_line":398,"hash":"af569e138a1aa23dc9ee369ed84e489ee1b1bedda48ad299ae33722c92f22970"},{"id":"func/_attacker_steps","name":"_attacker_steps","line":401,"end_line":403,"hash":"99d3d31e7ada6584fdfc885ddd9e9ee12712844de55e79b56d9c259541cd114b"},{"id":"func/_step_has_exact_mapping","name":"_step_has_exact_mapping","line":406,"end_line":408,"hash":"f1e31c7109f94de88dd918aaa258b2badb59300e33d6cc84601af9f42f45a0c6"},{"id":"func/_check_attacker_exact_mapping","name":"_check_attacker_exact_mapping","line":411,"end_line":417,"hash":"dfbccaedc4fe4c0788f3addf3ba1e115394844faca90316976252932749e32d1"},{"id":"func/_check_slot_ids_unique","name":"_check_slot_ids_unique","line":420,"end_line":425,"hash":"277a0d7f760398233cd0f131f1ebefe6544c39ec9eabce7811226f865b8a609a"},{"id":"func/_initial_ingress_slots","name":"_initial_ingress_slots","line":428,"end_line":430,"hash":"807b08d729bb5d0f1e958237ea5bf12e4943d657ba696badc011b1ff861e5926"},{"id":"func/_check_initial_ingress_slot","name":"_check_initial_ingress_slot","line":433,"end_line":439,"hash":"b9e422eb86e63b0fb977ad313ac7e06d76c41d5467de84d8dd422bb4e1cef04e"},{"id":"func/_slots_by_id","name":"_slots_by_id","line":442,"end_line":444,"hash":"671dd4f0cc2118c63591ad6bfcb0a867f926b8e07770643cfb79a634e651c748"},{"id":"func/_slot_ids","name":"_slot_ids","line":447,"end_line":449,"hash":"5fb17171fa867486cb08ed389b256e2070e091579b273151bccdbdf40c50764b"},{"id":"func/_check_distinct_slot_references","name":"_check_distinct_slot_references","line":452,"end_line":466,"hash":"711835e82a6dab69e8c748e83be6111fc0211248d3cffa1506d5f17ed0143042"},{"id":"func/_check_step_resource_links","name":"_check_step_resource_links","line":469,"end_line":476,"hash":"f4035e38921c63102422f8cf08fe8eab351d46927dba9312377b6bc9d94081ce"},{"id":"func/_link_slot_or_raise","name":"_link_slot_or_raise","line":479,"end_line":490,"hash":"df056033020b79ac94f5fd0745b7f2937d566a28a54e37a9e27ac87ef9a8c218"},{"id":"func/_check_link_role","name":"_check_link_role","line":493,"end_line":507,"hash":"9146a7f24ab28901385b1fd1972b6aaaa2a1a4206b949137933b8373f8883f6f"},{"id":"func/_check_ingress_link","name":"_check_ingress_link","line":510,"end_line":529,"hash":"8d55671c07a90df396a04a2fae512d4775841fdf853706fcb0aea22e6b268800"},{"id":"func/_check_tool_fixture_link","name":"_check_tool_fixture_link","line":532,"end_line":539,"hash":"a28e6e5d7d56f5c0736fb0103431af87f877339e576cca2873802ddb587a8bbf"},{"id":"func/_check_source_influence_link","name":"_check_source_influence_link","line":542,"end_line":552,"hash":"86430d9a40cb7d3eab66148d9318ffc72d41153c7d02630dcb6bfa931c90fe2a"},{"id":"func/_check_source_influence_role","name":"_check_source_influence_role","line":555,"end_line":568,"hash":"769ee7ca6a8a9923bc41b1c9ee6bfc2841710b4f4a9d6c4bb3d0f8da7ff2cc2b"},{"id":"func/_check_source_influence_boundary","name":"_check_source_influence_boundary","line":571,"end_line":589,"hash":"437b40ea7c917861f1060d9bd6acf086a876ca26c6ba748ea76fc3370d6e6a93"},{"id":"func/_check_source_influence_target","name":"_check_source_influence_target","line":592,"end_line":617,"hash":"101246cd2e925e05413113311327ecc48d68978cd6c28d5e544b2287ea1abe28"},{"id":"func/_outcome_slot_kind","name":"_outcome_slot_kind","line":620,"end_line":629,"hash":"b730b8bb4e4f8b0e4232ee936864120586ac9dd764ec5f0d6e0d455b08c4d450"},{"id":"func/_check_observable_outcome_links","name":"_check_observable_outcome_links","line":632,"end_line":648,"hash":"4604e22e3c87801759839677e9d06bed8412ff94e3adfb65a0ea71e929d8b9c2"},{"id":"func/_is_ingress_activation","name":"_is_ingress_activation","line":651,"end_line":653,"hash":"7621608b6cc59cc926b46f1d7adc44de45ed512001616c687bd4b561e88e89d4"},{"id":"func/_is_source_activation","name":"_is_source_activation","line":656,"end_line":661,"hash":"2ec0f4547a471bf4dd74a2f7f58a3062c4021e60aaa11cb5140edfefed465845"},{"id":"func/_ingress_activation_links","name":"_ingress_activation_links","line":664,"end_line":673,"hash":"f6e4ef76e4d81d4f5a806e45a5d66d3b8b25709d472ac65756af07df7b617b0c"},{"id":"func/_source_activation_links","name":"_source_activation_links","line":676,"end_line":685,"hash":"a667c52c0ccc55b50a090a843c8bf31f8f9ec4db363c8cd5dfad4eeda9ec403a"},{"id":"func/_raise_too_many_ingress_links","name":"_raise_too_many_ingress_links","line":688,"end_line":698,"hash":"7e52be70781e6dd6224ad3b40f10ec82dcddd8d2abcf84bbcfc7fbd1d42e68fc"},{"id":"func/_raise_too_many_source_links","name":"_raise_too_many_source_links","line":701,"end_line":711,"hash":"e7f13645f1c27ed00dbbfd18101a68345933e15b21e56aafcae6f1871b8da1ae"},{"id":"func/_check_activation_mechanisms","name":"_check_activation_mechanisms","line":714,"end_line":725,"hash":"7d8822ae86a7d4ffdcd63b8f2a93a04aa48432b54548dcf731ee87de98edf158"},{"id":"func/_check_chain_digest","name":"_check_chain_digest","line":728,"end_line":731,"hash":"acff3e4e92a382bda0545b8cf19aa72800a0348327f9db806304b6473b3165ee"},{"id":"func/AttackPattern.bind_chain","name":"bind_chain","line":746,"end_line":749,"hash":"da6e703872c531a6a9b4ca3c08f7b88e355d8e3dfab36db754bbb764515d3459"}]}
# mutate4py-manifest-end
