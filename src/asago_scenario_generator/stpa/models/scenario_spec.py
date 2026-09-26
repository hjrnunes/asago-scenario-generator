"""ScenarioSpec boundary schema (Section 4.5 of the STPA-Sec foundation spec).

SP3 internal, produced by Stage 5.

Cross-artifact validation against ControlStructure requires the
referencing model to have access to the referenced model. This is
handled by the ``validate_against`` method.
"""

from __future__ import annotations

from enum import Enum
from typing import TYPE_CHECKING, Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    field_validator,
    model_validator,
)

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactor,
    validate_factor_sources,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import CatalogMapping
from asago_scenario_generator.stpa.models.ica_enumeration import UCAType
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from asago_scenario_generator.stpa.models.semantic_conditions import (
    ActionValueCondition,
    SemanticCondition,
    StimulusTurn,
    normalize_semantic_proposition,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    SemanticExecutionContract,
)
from asago_scenario_generator.stpa.observation_contract import (
    ObservationAssessment,
    ObservationCriterion,
    SafeObservableOutcome,
)

if TYPE_CHECKING:
    from asago_scenario_generator.stpa.models.control_structure import ControlStructure


class DefenderBelief(BaseModel):
    """A defender belief referencing a process model part."""

    pm_id: str  # references ControlStructure PM
    content: str
    vulnerability: str  # LLM-added annotation


class DefenderDesire(BaseModel):
    """A defender desire grounded in a responsibility's governing constraint.

    ``resp_id`` remains the owner reference for compatibility with historical
    scenario records.  Corrected contextual scenarios also carry the exact
    ``constraint_id`` that gives the desire its normative meaning.
    """

    resp_id: str  # references ControlStructure RESP
    content: str
    constraint_id: str | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )


class DefenderIntention(BaseModel):
    """A defender intention referencing a control action."""

    ca_id: str  # references ControlStructure CA
    content: str


class DefenderBDI(BaseModel):
    """Defender Belief-Desire-Intention model."""

    beliefs: list[DefenderBelief]
    desires: list[DefenderDesire]
    intentions: list[DefenderIntention]


class AttackerBDI(BaseModel):
    """Attacker Belief-Desire-Intention model (free-form strings)."""

    beliefs: list[str]
    desires: list[str]
    intentions: list[str]


class AdversaryKind(str, Enum):
    """Phase 3.1 adversary kinds (spec-defined, closed)."""

    external_attacker = "external_attacker"
    malicious_customer = "malicious_customer"
    third_party_via_content = "third_party_via_content"
    none = "none"


class AdversaryReach(str, Enum):
    """How the adversary's stimulus reaches the target."""

    user_message = "user_message"
    conversation = "conversation"
    retrieved_content = "retrieved_content"


class Adversary(BaseModel):
    """Phase 3.1 adversary record: who attempts the unsafe behavior and why.

    The adversary is who and why, never how: no attack mechanism is
    required or permitted here.
    """

    model_config = ConfigDict(extra="forbid")

    kind: AdversaryKind
    gain: StrictStr = Field(min_length=1)
    reaches_target_via: AdversaryReach | None

    @field_validator("gain")
    @classmethod
    def _strip_gain(cls, value: str) -> str:
        stripped = value.strip()
        if not stripped:
            raise ValueError("gain must be a non-blank sentence")
        return stripped


class ThreatSource(BaseModel):
    """The source threat for a scenario."""

    ica_slot_id: str  # RESP-X:CA-Y:TYPE-Z or CL-X:CM-Y:TYPE-Z
    provenance: Literal["structural", "catalog_only"]
    ica_id: str | None = None


class ScenarioSpec(BaseModel):
    """A scenario specification produced by Stage 5."""

    scenario_id: str  # SCN-001, ...
    threat_source: ThreatSource
    target_controller: str  # resp_id
    target_control_action: str  # ca_id
    ica_type: UCAType
    defender_bdi: DefenderBDI
    attacker_bdi: AttackerBDI
    catalog_context: list[CatalogMapping] = Field(default_factory=list)
    loss_scenario: str  # carried from Stage 3
    # Stage 5 declared, evidence-backed causal factors in declared order.
    # Only factors the LLM explicitly declared with evidence are stored;
    # structural presence alone never invents a factor.  Empty is valid
    # and means "no declared factors".
    causal_factors: list[CausalFactor] = Field(default_factory=list)
    # Corrected Stage 5 output owns the semantic condition that makes the
    # selected UCA unsafe.  ``None`` remains accepted only for historical v1
    # ScenarioSpec values; contextual v2 preparation rejects it before Stage 6.
    unsafe_outcome_condition: SemanticCondition | None = None
    unsafe_outcome_semantic_proposition: StrictStr | None = None
    unsafe_outcome_hazard_refs: list[str] = Field(default_factory=list)
    unsafe_outcome_constraint_refs: list[str] = Field(default_factory=list)
    scenario_context: ScenarioGenerationContext | None = None
    # Corrected Stage 5 route selected from request-local handles.  A missing
    # value is retained for historical/non-contextual values but cannot be
    # published through the v2 execution projection seam.
    execution_contract: SemanticExecutionContract | None = None
    # Prepared user turns for a conversation_context delivery route.  The
    # producer copies them verbatim into the published stimulus requirement;
    # a missing value keeps the route free of turn content.
    stimulus_turns: tuple[StimulusTurn, ...] | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    # Phase 3.1 adversary record.  Optional only for historical/non-contextual
    # values; the corrected contextual Stage 5 wire requires it.
    adversary: Adversary | None = None
    # Stage 5's target-agnostic observation declaration.  The producer does
    # not assert that the outcome occurred; it records which runtime evidence
    # could establish the hypothesis and the deterministic disposition.
    observation_criteria: list[ObservationCriterion] = Field(default_factory=list)
    observation_assessment: ObservationAssessment | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    observation_contract_id: StrictStr | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    observation_contract_digest: StrictStr | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    safe_observable_outcome: SafeObservableOutcome | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    # Obligation-direction observation stamps (owner ruling Q30, 2026-09-10).
    # ``oracle_observes`` names what the compiled oracle measures (attempt,
    # total_omission, reply); ``oracle_basis`` records why the direction
    # check admitted the compile (reviewed interpretation, proxy, or an
    # explicitly UNVERIFIED default).  Both are omitted when absent, so
    # existing projection digests hold.
    oracle_observes: StrictStr | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    oracle_basis: StrictStr | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    # Structured omission evidence (authoring-side basis) for an accepted
    # tool_absent scenario.  The projection seam assembles the closed
    # ``omission_evidence`` carrier from it and the projection's own source
    # pins.  Omitted when absent so existing spec digests hold.  The type is
    # enforced by the validator below through a lazy import: a module-level
    # import of the omission-evidence module would close a real import cycle
    # (v3 -> v2 -> asago.models package init -> pipeline -> this module).
    omission_evidence_basis: Any | None = Field(
        default=None,
        exclude_if=lambda value: value is None,
    )
    # Exact prepared direct-prompt user text copied verbatim from the authored
    # stimulus before projection.  The v3 stimulus requirement delivers it
    # verbatim; a missing value keeps the route free of prepared content.
    # The 4,096 cap mirrors the v3 requirement model's
    # ``MAX_PREPARED_USER_TEXT_LENGTH`` (equality is pinned in the pipeline
    # tests); the constant itself is not imported here to keep this module's
    # import graph leaf-safe.
    prepared_user_text: StrictStr | None = Field(
        default=None,
        min_length=1,
        max_length=4096,
        exclude_if=lambda value: value is None,
    )

    @field_validator("omission_evidence_basis")
    @classmethod
    def _validate_omission_evidence_basis(cls, value: Any) -> Any:
        if value is None:
            return None
        from asago_scenario_generator.stpa.models.omission_evidence import (
            OmissionEvidenceBasis,
        )

        if isinstance(value, OmissionEvidenceBasis):
            return value
        return OmissionEvidenceBasis.model_validate(value)

    @property
    def is_functional_test(self) -> bool:
        """Phase 3.2: ``kind: none`` means nobody gains; a functional test."""
        return self.adversary is not None and self.adversary.kind is AdversaryKind.none

    @model_validator(mode="after")
    def preserve_scenario_context_authority(self) -> "ScenarioSpec":
        """Bind corrected scenarios to the exact immutable source context."""
        context = self.scenario_context
        if context is None:
            return self
        identity = context.scenario_identity
        expected = (
            identity.scenario_id,
            identity.ica_slot_id,
            identity.ica_id,
            context.target_control_path.controller.element_id,
            context.target_control_path.control_action.action_id,
            context.ica.uca_type,
            context.ica.loss_consequence,
        )
        actual = (
            self.scenario_id,
            self.threat_source.ica_slot_id,
            self.threat_source.ica_id,
            self.target_controller,
            self.target_control_action,
            self.ica_type,
            self.loss_scenario,
        )
        if actual != expected:
            raise ValueError("scenario fields do not match immutable scenario context")
        if not self.causal_factors:
            raise ValueError("successful contextual scenario requires causal_factors")
        expected_hazards = tuple(item.hazard_id for item in context.hazards)
        expected_constraints = tuple(item.constraint_id for item in context.constraints)
        if tuple(self.unsafe_outcome_hazard_refs) != expected_hazards:
            raise ValueError(
                "scenario unsafe_outcome_hazard_refs must equal scenario context"
            )
        if tuple(self.unsafe_outcome_constraint_refs) != expected_constraints:
            raise ValueError(
                "scenario unsafe_outcome_constraint_refs must equal scenario context"
            )
        observation_values = (
            bool(self.observation_criteria),
            self.observation_assessment is not None,
            self.observation_contract_id is not None,
            self.observation_contract_digest is not None,
        )
        if any(observation_values) and not all(observation_values):
            raise ValueError(
                "contextual observation metadata requires criteria, assessment, "
                "contract id, and contract digest"
            )
        if self.execution_contract is not None:
            action_kind = self.execution_contract.action_kind
            if action_kind is not None and action_kind.value == "model_output":
                normalize_semantic_proposition(
                    self.unsafe_outcome_semantic_proposition,
                    required=True,
                )
                if self.ica_type is UCAType.incorrect and not (
                    isinstance(self.unsafe_outcome_condition, ActionValueCondition)
                    and self.unsafe_outcome_condition.property == "semantic_proposition"
                    and self.unsafe_outcome_condition.operator == "equals"
                    and type(self.unsafe_outcome_condition.expected) is bool
                    and self.unsafe_outcome_condition.expected is True
                ):
                    raise ValueError(
                        "model_output INCORRECT scenarios require the fixed "
                        "semantic-proposition condition"
                    )
            elif self.unsafe_outcome_semantic_proposition is not None:
                normalize_semantic_proposition(
                    self.unsafe_outcome_semantic_proposition,
                    required=True,
                )
        return self

    def validate_against(self, control_structure: ControlStructure) -> None:
        """Validate scenario spec references against a ControlStructure.

        Checks:
        - Every DefenderBelief.pm_id references a valid PM.
        - Every DefenderDesire.resp_id references a valid RESP.
        - Contextual DefenderDesire.constraint_id references a selected SC.
        - Every DefenderIntention.ca_id references a valid CA.
        - target_controller references a valid RESP.
        - target_control_action references a valid CA belonging to
          target_controller.
        - Every causal-factor reference resolves to its PM/FB/CA
          namespace in the control structure.

        Args:
            control_structure: The control structure to validate against.

        Raises:
            ValueError: If any reference is invalid.
        """
        resp_ids, all_pm_ids, all_ca_ids, ca_to_resp = _build_lookup_maps(
            control_structure
        )

        if self.target_controller.startswith("CL-"):
            _validate_coordination_target(
                self.target_controller,
                self.target_control_action,
                control_structure,
            )
        else:
            _validate_target(
                self.target_controller,
                self.target_control_action,
                resp_ids,
                all_ca_ids,
                ca_to_resp,
            )
        constraint_ids = (
            {item.constraint_id for item in self.scenario_context.constraints}
            if self.scenario_context is not None
            else None
        )
        _validate_defender_bdi(
            self.defender_bdi,
            all_pm_ids,
            resp_ids,
            all_ca_ids,
            constraint_ids,
        )
        validate_factor_sources(control_structure, self.causal_factors)


def _build_lookup_maps(
    cs: ControlStructure,
) -> tuple[set[str], set[str], set[str], dict[str, str]]:
    """Build lookup maps from a control structure's responsibilities.

    Returns:
        A tuple of (resp_ids, all_pm_ids, all_ca_ids, ca_to_resp).
    """
    resp_ids: set[str] = set()
    all_pm_ids: set[str] = set()
    all_ca_ids: set[str] = set()
    ca_to_resp: dict[str, str] = {}

    for resp in cs.responsibilities:
        resp_ids.add(resp.resp_id)
        for pm in resp.process_model_parts:
            all_pm_ids.add(pm.pm_id)
        for ca in resp.control_actions:
            all_ca_ids.add(ca.ca_id)
            ca_to_resp[ca.ca_id] = resp.resp_id

    return resp_ids, all_pm_ids, all_ca_ids, ca_to_resp


def _validate_target(
    target_controller: str,
    target_control_action: str,
    resp_ids: set[str],
    all_ca_ids: set[str],
    ca_to_resp: dict[str, str],
) -> None:
    """Validate target_controller and target_control_action references."""
    if target_controller not in resp_ids:
        raise ValueError(
            f"target_controller '{target_controller}' is not a valid responsibility ID."
        )
    if target_control_action not in all_ca_ids:
        raise ValueError(
            f"target_control_action '{target_control_action}' is not a "
            f"valid control action ID."
        )
    if ca_to_resp.get(target_control_action) != target_controller:
        raise ValueError(
            f"target_control_action '{target_control_action}' does not "
            f"belong to target_controller '{target_controller}'."
        )


def _validate_coordination_target(
    link_id: str,
    mechanism_id: str,
    control_structure: ControlStructure,
) -> None:
    """Validate a CL/CM target without treating it as RESP/CA."""
    links = [
        item for item in control_structure.coordination_links if item.link_id == link_id
    ]
    if len(links) != 1:
        raise ValueError(
            f"target_controller '{link_id}' is not an exact coordination link ID."
        )
    expected = links[0].coordination_mechanism.cm_id
    if mechanism_id != expected:
        raise ValueError(
            f"target_control_action '{mechanism_id}' does not match coordination "
            f"mechanism '{expected}' for '{link_id}'."
        )


def _validate_defender_bdi(
    defender_bdi: DefenderBDI,
    all_pm_ids: set[str],
    resp_ids: set[str],
    all_ca_ids: set[str],
    constraint_ids: set[str] | None = None,
) -> None:
    """Validate defender BDI references against control structure lookups."""
    _validate_ref_items(defender_bdi.beliefs, "pm_id", all_pm_ids, "DefenderBelief")
    _validate_ref_items(defender_bdi.desires, "resp_id", resp_ids, "DefenderDesire")
    if constraint_ids is not None:
        for desire in defender_bdi.desires:
            if (
                desire.constraint_id is not None
                and desire.constraint_id not in constraint_ids
            ):
                raise ValueError(
                    "DefenderDesire references an unknown selected scenario "
                    f"constraint_id '{desire.constraint_id}'."
                )
    _validate_ref_items(
        defender_bdi.intentions, "ca_id", all_ca_ids, "DefenderIntention"
    )


def _validate_ref_items(
    items: list,
    attr_name: str,
    valid_ids: set[str],
    model_name: str,
) -> None:
    """Validate that each item's *attr_name* references a valid ID."""
    for item in items:
        ref_value = getattr(item, attr_name)
        if ref_value not in valid_ids:
            raise ValueError(
                f"{model_name} references non-existent {attr_name} '{ref_value}'."
            )
