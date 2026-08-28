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
