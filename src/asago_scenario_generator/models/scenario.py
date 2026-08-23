"""Pydantic models for the Scenario Envelope.

The scenario envelope is the top-level document wrapping all four output layers
of a asago-scenario-generator scenario:

  1. Narrative       -- Zone-annotated attack prose (LLM Call 1)
  2. Attack tree     -- AND/OR YAML tree (LLM Call 2)
  3. Behavior spec   -- Tool-neutral test specifications (LLM Call 3)
  4. Faceting metadata -- Deterministic fields for querying/filtering

Plus priority signals and generation metadata.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.models.capability_profile import ConfidenceLevel
from asago_scenario_generator.models.complexity import (
    AttackComplexityAssessment,
    CapabilityLevel,
)
from asago_scenario_generator.models.projection_envelope import (
    ProjectionEnvelopeBlock,
)
from asago_scenario_generator.models.realization import ProjectedStepRealization
from asago_scenario_generator.models.source_influence_provenance import (
    SourceInfluenceProvenanceBlock,
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class TechniqueMaturity(str, Enum):
    """MITRE ATLAS technique maturity level."""

    feasible = "feasible"
    demonstrated = "demonstrated"
    realized = "realized"


class SeverityLevel(str, Enum):
    """Severity / impact / likelihood levels."""

    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class AttackComplexity(str, Enum):
    """Complexity of the attack path."""

    low = "low"
    medium = "medium"
    high = "high"


class LikelihoodLevel(str, Enum):
    """How feasible and motivated the attack is."""

    high = "high"
    medium = "medium"
    low = "low"


class ArchitectureMatch(str, Enum):
    """Whether the scenario matches explicit or inferred capabilities."""

    explicit = "explicit"
    inferred = "inferred"


class StructuralExposureSignal(str, Enum):
    """Structural exposure type for priority signals."""

    single_point_of_failure = "single_point_of_failure"
    convergence_point = "convergence_point"
    probabilistic_control = "probabilistic_control"
    defense_in_depth_claim = "defense_in_depth_claim"
    none = "none"


class CallName(str, Enum):
    """Which generation call produced a piece of the scenario."""

    actor_profile = "actor_profile"
    narrative = "narrative"
    attack_tree = "attack_tree"
    behavior_spec = "behavior_spec"


# ---------------------------------------------------------------------------
# ---------------------------------------------------------------------------#
# Narrative sub-models
# ---------------------------------------------------------------------------#


class NarrativeStep(BaseModel):
    """A single step in the attack narrative."""

    step_number: int = Field(description="Sequence number of this step.")
    zone: str = Field(description="Schneider zone where this step occurs.")
    action: str = Field(
        description="What the attacker does at this step (adversarial voice)."
    )
    effect: str = Field(
        description="What happens as a result -- system response or state change."
    )
    control_point: str | None = Field(
        default=None,
        description="Defensive control at this step, if one exists.",
    )
    projected_step_ids: tuple[str, ...] = Field(
        min_length=1,
        description=(
            "Canonical projected step IDs (from ProjectionEnvelopeBlock) "
            "that this narrative step realizes.  Controlled many-to-many: "
            "a narrative step may realize multiple projected steps (combine) "
            "and a projected step may be realized by multiple narrative "
            "steps (split).  Required (non-empty) on every narrative "
            "step in scenarios with a projection block; the LLM receives "
            "the IDs as opaque constraints."
        ),
    )
    # --- Per-projected-step canonical realization records (422o.4 blocker #3) ---
    # One record per projected_step_id, carrying action/executor/boundary,
    # concrete resources, consumed/produced refs/effects, outcome links,
    # and owned postconditions.  Prose action/effect explain but are not
    # the authority -- these typed records are the authority.
    realizations: tuple[ProjectedStepRealization, ...] = Field(
        default=(),
        description=(
            "Per-projected-step canonical realization records.  One record "
            "per projected_step_id.  Derived deterministically in "
            "post-processing from the projection context."
        ),
    )

    @model_validator(mode="after")
    def _validate_projected_step_ids(self) -> NarrativeStep:
        """Each projected step ID must match the canonical pattern."""
        for sid in self.projected_step_ids:
            if not sid or not sid[0].isalnum():
                raise ValueError(
                    f"projected_step_ids contains invalid ID '{sid}': "
                    f"must start with alphanumeric"
                )
        if len(set(self.projected_step_ids)) != len(self.projected_step_ids):
            raise ValueError(
                f"narrative step {self.step_number} has duplicate projected_step_ids"
            )
        # Realizations must cover exactly the projected_step_ids.
        # model_construct may not set realizations; skip check if absent.
        if self.realizations:
            realization_ids_list = [r.projected_step_id for r in self.realizations]
            projected_ids = set(self.projected_step_ids)
            if len(set(realization_ids_list)) != len(realization_ids_list):
                raise ValueError(
                    f"narrative step {self.step_number} has duplicate "
                    f"realization records (same projected_step_id appears "
                    f"more than once)"
                )
            if len(realization_ids_list) != len(projected_ids):
                raise ValueError(
                    f"narrative step {self.step_number} has "
                    f"{len(realization_ids_list)} realization records but "
                    f"{len(projected_ids)} projected_step_ids — exactly one "
                    f"record per projected_step_id is required"
                )
            realization_ids = set(realization_ids_list)
            if realization_ids != projected_ids:
                raise ValueError(
                    f"narrative step {self.step_number} realization IDs "
                    f"{realization_ids} do not match projected_step_ids "
                    f"{projected_ids}"
                )
        return self


class NarrativeAccessRealization(BaseModel):
    """Typed narrative access realization reference (cmps.6).

    Links the narrative to the actor's structured access provenance without
    relying on prose keyword matching.  The fields must exactly agree with
    ``ActorAccessProvenance`` — this is a cross-artifact invariant, not a
    keyword check.
    """

    model_config = ConfigDict(extra="forbid")

    # Conservative static maxima: the narrative response schema embeds this
    # record, and every generated probe field must declare a finite length.
    _NAME_MAX_LENGTH = 200

    initial_entry_point_id: str = Field(
        max_length=_NAME_MAX_LENGTH,
        description=(
            "Canonical entry-point name of the initial ingress "
            "this narrative realizes.  Must match actor access provenance."
        ),
    )
    influence_source: str | None = Field(
        default=None,
        max_length=_NAME_MAX_LENGTH,
        description=(
            "Canonical entry-point name of the upstream influence source, "
            "if indirect.  Must match actor access provenance."
        ),
    )
    influence_source_kind: (
        Annotated[Literal["entry_point", "integration"], Field(max_length=20)] | None
    ) = Field(
        default=None,
        description="Typed kind of the canonical upstream influence source.",
    )
    influence_source_id: str | None = Field(
        default=None,
        max_length=_NAME_MAX_LENGTH,
        description="Canonical upstream influence source ID, if indirect.",
    )
    trust_boundary_id: str | None = Field(
        default=None,
        max_length=_NAME_MAX_LENGTH,
        description=(
            "Canonical trust boundary name of the boundary crossed, "
            "if indirect.  Must match actor access provenance."
        ),
    )
    responsible_step_number: int = Field(
        description=(
            "Step number in the narrative where the actor realizes the "
            "initial access described by the provenance block."
        ),
        ge=1,
    )


class NarrativeLayer(BaseModel):
    """Layer 1: Schneider-style attack narrative with structured steps."""

    title: str = Field(description="Human-readable scenario title.")
    summary: str = Field(
        description="One-paragraph executive summary in adversarial voice."
    )
    entry_point: str = Field(
        description="Entry point from the capability profile (e.g. 'user prompts (zone 1)').",
    )
    zone_sequence: list[str] = Field(
        description="Ordered attack propagation path through Schneider zones.",
        min_length=1,
    )
    steps: list[NarrativeStep] = Field(
        description="Ordered sequence of attack steps.",
        min_length=1,
    )
    access_realization: NarrativeAccessRealization | None = Field(
        default=None,
        description=(
            "Typed narrative access realization reference (cmps.6). "
            "Validated against actor access provenance — no keyword matching."
        ),
    )


# ---------------------------------------------------------------------------
# Actor profile sub-models
# ---------------------------------------------------------------------------

ActorType = Literal[
    "cybercriminal",  # External, financially motivated (data theft, fraud, ransomware)
    "nation-state",  # State-sponsored, well-resourced, strategic objectives
    "malicious-insider",  # Privileged user acting deliberately (poisons data, abuses admin access)
    "negligent-insider",  # Legitimate user, unintentional harm (pastes secrets, misconfigures)
    "competitor",  # Rival organization (IP theft, output sabotage, reverse-engineering)
    "hacktivist",  # Ideologically motivated (disruption, exposure, defacement)
    "supply-chain-actor",  # Compromised upstream dependency (plugin, data source, tool, model provider)
    "adversarial-user",  # End-user deliberately weaponizing the AI (jailbreaking, prompt injection)
    "automated-agent",  # Another AI/bot attacking programmatically (agent-to-agent, automated injection)
]

ACTOR_TYPES: list[str] = list(ActorType.__args__)  # type: ignore[attr-defined]
"""All valid actor type values as a plain list (for diversity tracking)."""


class ActorAccessProvenance(BaseModel):
    """Typed evidence linking an actor to the scenario's canonical initial ingress.

    Replaces blanket direct/indirect actor allowlists and keyword insider
    checks with structured access provenance grounded in the canonical
    entry-point identity (cmps.6).

    Two distinct concepts are modelled:

    - ``ingress_mode`` — the channel controllability of the pinned entry
      point, derived from its canonical ``effective_controllability``.
      This is **never** LLM-inferred; it is authoritative.
    - ``access_class`` — the actor's relationship to the system
      (``public``, ``authenticated``, ``privileged``, ``supply_chain``).
      This is LLM-generated and validated against the ingress mode and
      actor type.

    Evidence fields:

    - ``indirect`` ingress requires ``influence_source`` (a canonical
      ``entry_point_id`` resolvable in the profile), ``influence_mechanism``,
      and ``trust_boundary_id`` (a canonical ``tb:v1:…`` referencing a
      ``TrustBoundary`` declared in the profile).  The boundary's
      ``to_zone`` must match the pinned entry point's
      ``effective_ingress_zone``, and the influence source must not be
      the same as the initial ingress (no self-relation unless explicitly
      modeled).
    - Insider actors using ``direct`` ingress require
      ``material_insider_advantage`` regardless of ``access_class`` —
      enum choice is not evidence.
    """

    model_config = ConfigDict(extra="forbid")

    initial_entry_point_id: str = Field(
        description=(
            "Canonical entry-point ID inherited from the initial "
            "ingress.  The scenario must inherit exactly one."
        ),
    )
    ingress_mode: Literal["direct", "indirect"] = Field(
        description=(
            "Channel controllability of the pinned entry point, derived "
            "from its canonical effective controllability: 'direct' (actor "
            "types input directly) or 'indirect' (actor influences an "
            "upstream data source).  Never LLM-inferred."
        ),
    )
    access_class: Literal["public", "authenticated", "privileged", "supply_chain"] = (
        Field(
            description=(
                "Actor access class describing the actor's relationship to "
                "the system: 'public' (no auth), 'authenticated' (registered "
                "user), 'privileged' (elevated/internal access), "
                "'supply_chain' (upstream supply-chain position)."
            ),
        )
    )
    influence_source: str | None = Field(
        default=None,
        description=(
            "Canonical entry-point ID of the upstream data source "
            "the actor influences (required for indirect ingress mode). "
            "Must resolve in the capability profile."
        ),
    )
    influence_source_kind: (
        Annotated[Literal["entry_point", "integration"], Field(max_length=20)] | None
    ) = Field(
        default=None,
        description="Typed kind of the canonical upstream influence source.",
    )
    influence_source_id: str | None = Field(
        default=None,
        description="Canonical upstream influence source ID, if indirect.",
    )
    influence_mechanism: str | None = Field(
        default=None,
        description=(
            "How the actor exerts influence — e.g. poisoning, injection, "
            "staging (required for indirect ingress mode)."
        ),
    )
    trust_boundary_id: str | None = Field(
        default=None,
        description=(
            "Canonical trust boundary ID referencing a "
            "TrustBoundary declared in the capability profile (required "
            "for indirect ingress mode).  The boundary's to_zone must "
            "match the pinned entry point's effective_ingress_zone."
        ),
    )
    material_insider_advantage: str | None = Field(
        default=None,
        description=(
            "Structured material insider advantage beyond public access "
            "(required for insider actors using public/authenticated "
            "access with direct ingress)."
        ),
    )


class ActorProfile(BaseModel):
    """Threat actor profile grounding the scenario narrative."""

    actor_type: ActorType = Field(
        description="Category of threat actor (e.g. cybercriminal, nation-state).",
    )
    capability_level: CapabilityLevel = Field(
        frozen=True,
        description=(
            "Skill and sophistication level of the actor. Frozen at "
            "construction (cmps.7): immutable after Call 0, so attack "
            "complexity is assessed separately and never relabels the "
            "actor. Post-construction assignment raises ValidationError."
        ),
    )
    beliefs: list[str] = Field(
        description="Deployment-time, black-box observations about the target system.",
    )
    desires: list[str] = Field(
        description="Concrete goals — what success looks like for this actor.",
    )
    intentions: list[str] = Field(
        description="Committed attack approach — techniques and sequence.",
    )
    resources: list[str] = Field(
        description="What the actor has access to (e.g. 'open-source tools', 'insider credentials').",
    )
    access: ActorAccessProvenance | None = Field(
        default=None,
        description=(
            "Typed access provenance linking the actor to the scenario's "
            "canonical initial ingress (cmps.6)."
        ),
    )
    goal_category: str | None = Field(
        default=None,
        description="Attack goal sub-category ID from the attack goals taxonomy.",
    )
    goal_category_name: str | None = Field(
        default=None,
        description="Human-readable attack goal name from the attack goals taxonomy.",
    )
    goal_category_parent: str | None = Field(
        default=None,
        description="Top-level attack goal category (availability, integrity, privacy, abuse).",
    )


# ---------------------------------------------------------------------------
# Faceting sub-models
# ---------------------------------------------------------------------------


class RiskCardRef(BaseModel):
    """Provenance linking back to the input risk card."""

    risk_id: str = Field(
        description="Risk taxonomy ID (e.g. 'atlas-prompt-injection')."
    )
    risk_name: str = Field(description="Human-readable risk name from the risk card.")
    risk_description: str = Field(description="Risk description from the risk card.")
    taxonomy: Literal["ibm-risk-atlas"] = Field(
        description="Source taxonomy identifier."
    )
    confidence: float = Field(
        description="Cross-encoder confidence score from the risk card (0.0 - 1.0).",
        ge=0.0,
        le=1.0,
    )
    grounding_confidence: ConfidenceLevel = Field(
        description="Grounding confidence level: high, medium, or low.",
    )
    threat: str | None = None
    threat_source: str | None = None
    vulnerability: str | None = None
    consequence: str | None = None
    impact: str | None = None


class TaxonomyChain(BaseModel):
    """The full three-hop taxonomy chain that seeded this scenario."""

    owasp_llm_ids: list[str] = Field(
        description="OWASP LLM Top 10 entry IDs (e.g. ['LLM06', 'LLM03']).",
        min_length=1,
    )
    agentic_threat_ids: list[str] = Field(
        description="OWASP Agentic Threat IDs (e.g. ['T2']).",
        min_length=1,
    )
    owasp_asi_ids: list[str] = Field(
        default_factory=list,
        description="OWASP ASI Top 10 entry IDs (e.g. ['ASI02', 'ASI06']).",
    )
    atlas_technique_ids: list[str] | None = Field(
        default=None,
        description="MITRE ATLAS technique IDs (e.g. ['AML.T0051']). May be empty.",
    )
    scenario_seed: str = Field(
        description="The attack pattern that seeded this scenario (e.g. 'AP-T7-01').",
    )


class TechniqueScopeEvidence(BaseModel):
    """Explicitly separated ATLAS identity scopes used by admission.

    Scenario classifications describe why the scenario was selected. Projected
    step mappings are exact catalog annotations carried by canonical tree
    leaves. Narrative references may be grounded in either scope.
    """

    scenario_classification_ids: list[str] = Field(default_factory=list)
    projected_step_mapping_ids: list[str] = Field(default_factory=list)
    narrative_reference_ids: list[str] = Field(default_factory=list)
    legacy_derived: bool = Field(
        default=False,
        description=(
            "True when a reader derived the scopes from a legacy envelope that "
            "did not publish explicit technique-scope evidence."
        ),
    )

    @model_validator(mode="after")
    def _ids_are_stably_unique(self) -> TechniqueScopeEvidence:
        for field_name in (
            "scenario_classification_ids",
            "projected_step_mapping_ids",
            "narrative_reference_ids",
        ):
            values = getattr(self, field_name)
            if len(values) != len(set(values)):
                raise ValueError(f"{field_name} must be unique in published order")
        return self


class CapabilityProfileRef(BaseModel):
    """References to the capability profile that scoped this scenario."""

    zones_traversed: list[str] = Field(
        description="Ordered attack propagation path through Schneider zones.",
        min_length=1,
    )
    architecture_match: ArchitectureMatch = Field(
        description="Whether the scenario targets explicit or inferred capabilities.",
    )
    entry_point: str = Field(
        description="Which entry point the attack uses from the capability profile.",
    )


class FacetingMetadata(BaseModel):
    """Layer 4: Structured metadata enabling queries across the scenario collection."""

    risk_card: RiskCardRef = Field(
        description="Provenance linking to the input risk card."
    )
    taxonomy_chain: TaxonomyChain = Field(description="Full three-hop taxonomy chain.")
    capability_profile: CapabilityProfileRef = Field(
        description="References to the capability profile that scoped this scenario.",
    )
    maestro_layers: list[Annotated[int, Field(ge=1, le=7)]] = Field(
        description="MAESTRO architectural layers targeted (1-7).",
        min_length=1,
    )


# ---------------------------------------------------------------------------
# Priority sub-models
# ---------------------------------------------------------------------------


class PrioritySignals(BaseModel):
    """Individual priority signals preserved as facets."""

    technique_maturity: TechniqueMaturity = Field(
        description="MITRE ATLAS maturity level.",
    )
    risk_impact: SeverityLevel = Field(
        description="Severity of consequence if the attack succeeds.",
    )
    risk_likelihood: LikelihoodLevel = Field(
        description="How feasible and motivated the attack is: high, medium, or low.",
    )
    attack_complexity: AttackComplexity = Field(
        description="Complexity of the attack path.",
    )
    architecture_match: ArchitectureMatch = Field(
        description="Whether the scenario targets explicit or inferred capabilities.",
    )
    structural_exposure: StructuralExposureSignal = Field(
        description="Structural exposure type from Schneider's node selection criteria.",
    )


class Priority(BaseModel):
    """Priority signals for human navigation of the scenario collection."""

    composite: float = Field(
        description="Composite priority score for default sort order (0.0 - 1.0).",
        ge=0.0,
        le=1.0,
    )
    signals: PrioritySignals = Field(description="Individual priority signals.")


# ---------------------------------------------------------------------------
# Generation metadata sub-models
# ---------------------------------------------------------------------------


class CallMetadata(BaseModel):
    """Metadata for a single LLM generation call."""

    call: CallName = Field(description="Which generation call this is.")
    prompt_tokens: int = Field(description="Number of prompt tokens used.")
    completion_tokens: int = Field(description="Number of completion tokens generated.")
    duration_ms: int = Field(
        description="Wall-clock duration of the LLM call in milliseconds."
    )


class GenerationMetadata(BaseModel):
    """Metadata about the generation process."""

    model: str = Field(description="LLM model used for generation.")
    call_metadata: list[CallMetadata] = Field(
        description="Per-call metadata for each LLM call that produced this scenario.",
    )
    notes: list[str] | None = Field(
        default=None,
        description="Generation-time notes and warnings.",
    )


# ---------------------------------------------------------------------------
# Validation sub-models (rwv2)
# ---------------------------------------------------------------------------


class PhantomViolationRecord(BaseModel):
    """A single phantom capability violation persisted on the envelope."""

    step_number: int = Field(description="Narrative step number (0 for behavior_spec).")
    field: str = Field(
        description="Which field triggered the match (action/effect/behavior_spec)."
    )
    category: str = Field(description="Violation category (e.g. privilege_escalation).")
    matched_text: str = Field(description="Substring that triggered the match.")
    reason: str = Field(description="Why this is phantom given the profile.")


class PhantomValidation(BaseModel):
    """Phantom capability validation results."""

    valid: bool = Field(
        default=True, description="True if no phantom capabilities detected."
    )
    violations: list[PhantomViolationRecord] = Field(
        default_factory=list,
        description="List of phantom capability violations found.",
    )


class StructuralValidation(BaseModel):
    """Structural (JSON Schema) validation results."""

    valid: bool = Field(
        default=True, description="True if the envelope passes JSON Schema validation."
    )
    violations: list[str] = Field(
        default_factory=list,
        description="List of JSON Schema validation error messages.",
    )


class SemanticViolation(BaseModel):
    """A single semantic validation violation."""

    rule: str = Field(
        description="Rule identifier (e.g. technique_exists, zone_in_profile)."
    )
    message: str = Field(description="Human-readable description of the violation.")
    severity: Literal["major", "moderate", "minor"] = Field(
        default="major",
        description="Severity of the violation.",
    )


class CorpusClaimCategory(str, Enum):
    """Inventory category for closed-world corpus claim applicability."""

    entry_points = "entry_points"
    tool_inventory = "tool_inventory"


class CorpusClaimStatus(str, Enum):
    """Whether closed-world corpus claims are applicable for a category."""

    applicable = "applicable"
    not_applicable = "not_applicable"


class CorpusClaimApplicability(BaseModel):
    """Typed, category-specific closed-world corpus claim applicability record.

    Closed-world omission/phantom claims (e.g. "no omitted tools") are
    ``not_applicable`` until the relevant inventory category is
    operator-confirmed complete.  When the category *is* complete, claims
    are ``applicable`` and unknown emitted IDs still fail independently
    via phantom validation (cmps.9 review correction 2).

    Status-appropriate payloads are enforced (cmps.9 third review
    correction 1):

    - ``applicable``: requires at least one nonblank evidence item;
      ``reason`` must be ``None``.
    - ``not_applicable``: requires a nonblank ``reason``; ``evidence``
      must be empty.
    """

    model_config = ConfigDict(extra="forbid")

    category: CorpusClaimCategory = Field(
        description="Inventory category this record applies to."
    )
    status: CorpusClaimStatus = Field(
        description=(
            "``applicable`` when the category inventory is "
            "operator-confirmed complete; ``not_applicable`` when it is "
            "inferred_partial."
        ),
    )
    reason: str | None = Field(
        default=None,
        description=(
            "Human-readable reason for the status, e.g. why claims are "
            "not_applicable for a partial inventory."
        ),
    )
    evidence: list[str] = Field(
        default_factory=list,
        description=(
            "Evidence sources supporting the status. For "
            "``applicable`` records this carries the operator-confirmed "
            "evidence; for ``not_applicable`` it is empty."
        ),
    )

    @model_validator(mode="after")
    def _validate_status_payload(self) -> CorpusClaimApplicability:
        if self.status == CorpusClaimStatus.applicable:
            if self.reason is not None:
                raise ValueError(
                    f"applicable corpus claim for category "
                    f"'{self.category.value}' must not carry a reason."
                )
            if not self.evidence:
                raise ValueError(
                    f"applicable corpus claim for category "
                    f"'{self.category.value}' requires at least one "
                    f"nonblank evidence item."
                )
            blank_evidence = [e for e in self.evidence if not e.strip()]
            if blank_evidence:
                raise ValueError(
                    f"applicable corpus claim for category "
                    f"'{self.category.value}' has blank/whitespace-only "
                    f"evidence item(s): {blank_evidence}. Every evidence "
                    f"item must be nonblank."
                )
        elif self.status == CorpusClaimStatus.not_applicable:
            if self.reason is None or not self.reason.strip():
                raise ValueError(
                    f"not_applicable corpus claim for category "
                    f"'{self.category.value}' requires a nonblank reason."
                )
            if self.evidence:
                raise ValueError(
                    f"not_applicable corpus claim for category "
                    f"'{self.category.value}' must not carry evidence."
                )
        return self


class SemanticValidation(BaseModel):
    """Semantic (Python logic) validation results."""

    valid: bool = Field(
        default=True, description="True if no semantic violations detected."
    )
    violations: list[SemanticViolation] = Field(
        default_factory=list,
        description="List of semantic validation violations found.",
    )
    corpus_claim_applicability: list[CorpusClaimApplicability] = Field(
        default_factory=lambda: [
            CorpusClaimApplicability(
                category=CorpusClaimCategory.entry_points,
                status=CorpusClaimStatus.not_applicable,
                reason="Inferred partial inventory.",
            ),
            CorpusClaimApplicability(
                category=CorpusClaimCategory.tool_inventory,
                status=CorpusClaimStatus.not_applicable,
                reason="Inferred partial inventory.",
            ),
        ],
        min_length=2,
        max_length=2,
        description=(
            "Typed, category-specific closed-world corpus claim "
            "applicability records. Partial inventory categories are "
            "structurally ``not_applicable``; operator-confirmed-complete "
            "categories are ``applicable``. This is independent of "
            "phantom.valid — unknown emitted IDs still fail regardless. "
            "Exactly one entry_points and one tool_inventory record "
            "are required (cmps.9 third review correction 1)."
        ),
    )

    @model_validator(mode="after")
    def _validate_corpus_claim_completeness(self) -> SemanticValidation:
        """Require exactly one ``entry_points`` and one ``tool_inventory``
        record — no empty, missing, or duplicate categories (cmps.9 third
        review correction 1).
        """
        categories = [r.category for r in self.corpus_claim_applicability]
        cat_counts: dict[str, int] = {}
        for c in categories:
            cat_counts[c.value] = cat_counts.get(c.value, 0) + 1
        required = {
            CorpusClaimCategory.entry_points.value,
            CorpusClaimCategory.tool_inventory.value,
        }
        missing = required - set(cat_counts)
        if missing:
            raise ValueError(
                f"corpus_claim_applicability is missing required "
                f"category record(s): {sorted(missing)}. Exactly one "
                f"entry_points and one tool_inventory record are required."
            )
        duplicates = {c: n for c, n in cat_counts.items() if n > 1}
        if duplicates:
            raise ValueError(
                f"corpus_claim_applicability has duplicate category "
                f"record(s): {duplicates}. Exactly one entry_points and "
                f"one tool_inventory record are required."
            )
        extra = set(cat_counts) - required
        if extra:
            raise ValueError(
                f"corpus_claim_applicability has unexpected category "
                f"record(s): {sorted(extra)}. Only entry_points and "
                f"tool_inventory are valid categories."
            )
        return self


class ValidationBlock(BaseModel):
    """Unified validation block aggregating all validation passes."""

    phantom: PhantomValidation = Field(default_factory=PhantomValidation)
    structural: StructuralValidation = Field(default_factory=StructuralValidation)
    semantic: SemanticValidation = Field(default_factory=SemanticValidation)
    parsimony_unprunable: str | None = Field(
        default=None,
        description="Set when parsimony pruning could not bring the tree within budget.",
    )


# ---------------------------------------------------------------------------#
# Structured behavior spec (asago-scenario-generator-422o.4)
# ---------------------------------------------------------------------------#


class BehaviorAction(BaseModel):
    """A structured behavior spec action tied to projected steps.

    Each behavior action carries the canonical projected step IDs it
    realizes (controlled many-to-many) and the tree leaf it was derived
    from, enabling deterministic traceability without Gherkin parsing.

    422o.4 blocker #4: Carries canonical action/executor/boundary
    metadata so the validator can reconcile per-step semantics at the
    behavior boundary, not just at the tree boundary.
    """

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(
        description=(
            "Stable behavior action identifier, deterministically derived "
            "from the tree leaf ID (e.g. 'ba-<leaf_id>')."
        ),
        min_length=1,
    )
    projected_step_ids: tuple[str, ...] = Field(
        description=(
            "Canonical projected step IDs this behavior action realizes. "
            "Controlled many-to-many: one action may realize multiple "
            "projected steps (combine)."
        ),
        min_length=1,
    )
    source_leaf_id: str = Field(
        description="Attack tree leaf node ID this behavior action was derived from.",
        pattern=r"^n\d+(\.\d+){0,4}$",
    )
    gherkin_keyword: Literal["Given", "When", "Then"] = Field(
        description="Gherkin keyword for this action step.",
    )
    text: str = Field(
        description="Gherkin step text for this action.",
        min_length=1,
    )
    # --- Per-projected-step canonical realization records (422o.4 blocker #3) ---
    realizations: tuple[ProjectedStepRealization, ...] = Field(
        min_length=1,
        description=(
            "Per-projected-step canonical realization records.  One record "
            "per projected_step_id.  The validator compares each record "
            "against the embedded canonical step at the behavior boundary."
        ),
    )

    @model_validator(mode="after")
    def _validate_projected_step_ids(self) -> BehaviorAction:
        for sid in self.projected_step_ids:
            if not sid or not sid[0].isalnum():
                raise ValueError(f"projected_step_ids contains invalid ID '{sid}'")
        if len(set(self.projected_step_ids)) != len(self.projected_step_ids):
            raise ValueError(
                f"behavior action '{self.action_id}' has duplicate projected_step_ids"
            )
        if self.realizations:
            realization_ids_list = [r.projected_step_id for r in self.realizations]
            projected_ids = set(self.projected_step_ids)
            if len(set(realization_ids_list)) != len(realization_ids_list):
                raise ValueError(
                    f"behavior action '{self.action_id}' has duplicate "
                    f"realization records (same projected_step_id appears "
                    f"more than once)"
                )
            if len(realization_ids_list) != len(projected_ids):
                raise ValueError(
                    f"behavior action '{self.action_id}' has "
                    f"{len(realization_ids_list)} realization records but "
                    f"{len(projected_ids)} projected_step_ids — exactly one "
                    f"record per projected_step_id is required"
                )
            realization_ids = set(realization_ids_list)
            if realization_ids != projected_ids:
                raise ValueError(
                    f"behavior action '{self.action_id}' realization IDs "
                    f"{realization_ids} do not match projected_step_ids "
                    f"{projected_ids}"
                )
        return self


class BehaviorAssertion(BaseModel):
    """A structured behavior assertion tied to projected postconditions.

    Assertions map to projected observable postconditions, not to setup
    steps.  Each assertion carries the canonical postcondition IDs and
    source step IDs it verifies.
    """

    model_config = ConfigDict(extra="forbid")

    assertion_id: str = Field(
        description=(
            "Stable assertion identifier, deterministically derived "
            "from the source step and postcondition (e.g. 'assert-<step>-<pc>')."
        ),
        min_length=1,
    )
    source_step_ids: tuple[str, ...] = Field(
        description=(
            "Projected step IDs that own the postconditions this assertion verifies."
        ),
        min_length=1,
    )
    projected_postcondition_ids: tuple[str, ...] = Field(
        description="Observable postcondition IDs this assertion verifies.",
        min_length=1,
    )
    gherkin_keyword: Literal["Then"] = Field(
        default="Then",
        description="Gherkin keyword for this assertion (always 'Then').",
    )
    text: str = Field(
        description="Gherkin step text for this assertion.",
        min_length=1,
    )

    @model_validator(mode="after")
    def _unique_ids(self) -> BehaviorAssertion:
        if len(set(self.source_step_ids)) != len(self.source_step_ids):
            raise ValueError(
                f"source_step_ids must be unique within assertion '{self.assertion_id}'"
            )
        if len(set(self.projected_postcondition_ids)) != len(
            self.projected_postcondition_ids
        ):
            raise ValueError(
                f"projected_postcondition_ids must be unique within "
                f"assertion '{self.assertion_id}'"
            )
        return self


class BehaviorScenario(BaseModel):
    """Provider-authored grouping of canonical behavior steps.

    ``step_ids`` contains behavior action and assertion IDs in the exact order
    chosen by the semantic draft.  The IDs themselves remain compiler-owned.
    """

    model_config = ConfigDict(extra="forbid")

    scenario_id: str = Field(min_length=1)
    title: str = Field(min_length=1, max_length=160)
    step_ids: tuple[str, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _step_ids_are_unique(self) -> BehaviorScenario:
        if len(set(self.step_ids)) != len(self.step_ids):
            raise ValueError(
                f"behavior scenario '{self.scenario_id}' has duplicate step IDs"
            )
        return self


class BehaviorSpec(BaseModel):
    """Structured behavior specification with projection traceability.

    Carries structured actions and assertions with canonical projected
    step/postcondition references, plus the rendered Gherkin text.
    Validation can cross-check the structured elements against the
    rendered Gherkin and the projection block without parsing Gherkin.
    """

    model_config = ConfigDict(extra="forbid")

    actions: tuple[BehaviorAction, ...] = Field(
        description="Structured behavior actions tied to projected steps.",
    )
    assertions: tuple[BehaviorAssertion, ...] = Field(
        description="Structured behavior assertions tied to projected postconditions.",
    )
    scenarios: tuple[BehaviorScenario, ...] = Field(
        default=(),
        description=(
            "Optional provider-authored scenario grouping. Empty preserves the "
            "legacy single-scenario rendering contract."
        ),
    )
    gherkin_text: str = Field(
        description="Rendered Gherkin feature text.",
        min_length=1,
    )

    @model_validator(mode="after")
    def _validate_scenario_grouping(self) -> BehaviorSpec:
        if not self.scenarios:
            return self
        action_ids = tuple(item.action_id for item in self.actions)
        assertion_ids = tuple(item.assertion_id for item in self.assertions)
        known = set(action_ids) | set(assertion_ids)
        grouped = tuple(
            step_id for scenario in self.scenarios for step_id in scenario.step_ids
        )
        unknown = set(grouped) - known
        if unknown:
            raise ValueError(
                f"behavior scenarios reference unknown step IDs: {sorted(unknown)}"
            )
        if len(set(grouped)) != len(grouped):
            raise ValueError("behavior scenarios must place every step ID exactly once")
        missing = known - set(grouped)
        if missing:
            raise ValueError(
                f"behavior scenarios omit canonical step IDs: {sorted(missing)}"
            )
        grouped_actions = tuple(step_id for step_id in grouped if step_id in action_ids)
        if grouped_actions != action_ids:
            raise ValueError(
                "behavior scenario grouping must preserve canonical action order"
            )
        return self


# ---------------------------------------------------------------------------
# Top-level model
# ---------------------------------------------------------------------------


class ScenarioEnvelope(BaseModel):
    """Top-level scenario document wrapping all four output layers.

    Layers:
      1. narrative      -- Zone-annotated attack prose
      2. attack_tree    -- AND/OR decomposition with taxonomy refs
      3. behavior_spec  -- Tool-neutral test specifications (opaque, stored as dict or str)
      4. faceting       -- Deterministic metadata for querying/filtering
    """

    # --- Identity ---

    scenario_id: str = Field(
        description=(
            "Collision-safe, run-specific identifier: "
            "scenario:<version>:<256-bit hex digest of run_id|candidate_id|attempt>."
        ),
    )
    candidate_id: str = Field(
        description=(
            "Stable canonical candidate identity (cand:v2:<128-bit hex>) "
            "that produced this scenario.  Separated from the run-specific "
            "scenario_id so the same candidate across runs yields distinct "
            "scenario IDs."
        ),
    )

    @field_validator("candidate_id")
    @classmethod
    def _validate_candidate_id_format(cls, v: str) -> str:
        """Validate that candidate_id follows cand:v2:<32-char lowercase hex> format."""
        if not v or not v.startswith("cand:v2:"):
            raise ValueError("candidate_id must follow 'cand:v2:<32-char hex>' format")
        hex_part = v[len("cand:v2:") :]
        if len(hex_part) != 32:
            raise ValueError(
                f"candidate_id hex part must be 32 chars, got {len(hex_part)}"
            )
        if hex_part != hex_part.lower():
            raise ValueError("candidate_id hex part must be lowercase")
        try:
            int(hex_part, 16)
        except ValueError:
            raise ValueError("candidate_id hex part must be valid hex") from None
        return v

    @field_validator("scenario_id")
    @classmethod
    def _validate_scenario_id_format(cls, v: str) -> str:
        """Validate that scenario_id follows scenario:v2:<64-char lowercase hex> format."""
        if not v or not v.startswith("scenario:v2:"):
            raise ValueError(
                "scenario_id must follow 'scenario:v2:<64-char hex>' format"
            )
        hex_part = v[len("scenario:v2:") :]
        if len(hex_part) != 64:
            raise ValueError(
                f"scenario_id hex part must be 64 chars, got {len(hex_part)}"
            )
        if hex_part != hex_part.lower():
            raise ValueError("scenario_id hex part must be lowercase")
        try:
            int(hex_part, 16)
        except ValueError:
            raise ValueError("scenario_id hex part must be valid hex") from None
        return v

    version: int = Field(
        default=3,
        description="Monotonically increasing version number.",
    )
    generated_at: datetime = Field(
        description="ISO 8601 timestamp of scenario generation.",
    )
    generator_version: str = Field(
        description="Version of the asago-scenario-generator pipeline that produced this scenario.",
    )

    # --- Scenario Seed Metadata ---

    scenario_seed_metadata: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Rich metadata from the scenario seed: seed_id, threat_id, "
            "threat_name, attack_pattern_name, attack_pattern_description."
        ),
    )

    legitimate_task: str | None = Field(
        default=None,
        description=(
            "One-line description of the agent's legitimate task — "
            "the honest job the system performs when not under attack."
        ),
    )

    # --- Actor Profile ---

    actor_profile: ActorProfile | None = Field(
        default=None,
        description="Threat actor profile grounding the scenario narrative.",
    )

    # --- Canonical Initial Ingress (cmps.6) ---

    initial_entry_point_id: str = Field(
        description=(
            "Canonical entry_point_id (ep:v1:…) inherited from the attack "
            "tree's initial_ingress action(s).  A scenario must inherit "
            "exactly one — only direct/indirect input or bidirectional entry "
            "points are eligible; system/output channels are downstream "
            "resources only."
        ),
        pattern=r"^ep:v1:[0-9a-f]{32}$",
    )

    # --- Attack Complexity Assessment (cmps.7) ---

    attack_complexity_assessment: AttackComplexityAssessment | None = Field(
        default=None,
        description=(
            "Closed, versioned deterministic attack-complexity assessment: "
            "candidate lower bound, final required capability level, rule "
            "version, typed reasons, and evidence — persisted separately "
            "from the immutable actor_profile.capability_level. Absent "
            "until the candidate-v2 seam is activated by cmps.5."
        ),
    )

    # --- Canonical Projection (asago-scenario-generator-422o.4) ---

    projection: ProjectionEnvelopeBlock = Field(
        description=(
            "Deeply immutable, standalone canonical projection snapshot "
            "with execution requirements and artifact realization mappings. "
            "Every generated scenario must embed exactly one projection "
            "block.  Generated content realizes but never selects, alters, "
            "omits, reorders, or fabricates projection semantics."
        ),
    )

    technique_scope_evidence: TechniqueScopeEvidence | None = Field(
        default=None,
        description=(
            "Explicit scenario-classification, projected-step-mapping, and "
            "narrative-reference ATLAS scopes. Older envelopes may omit this "
            "field and are read using legacy-derived evidence."
        ),
    )

    # --- Layer 1: Narrative ---

    narrative: NarrativeLayer = Field(
        description="Schneider-style attack narrative with structured steps.",
    )

    # --- Layer 2: Attack Tree ---

    attack_tree: AttackTree = Field(
        description="AND/OR decomposition with zone annotations and taxonomy references.",
    )

    # --- Layer 3: Behavior Specification ---

    behavior_spec: BehaviorSpec = Field(
        description=(
            "Structured behavior specification with projection-traceable "
            "actions and assertions.  Every action carries a canonical "
            "projected step ID; every assertion maps to projected "
            "observable postconditions.  Pre-alpha: no raw string/dict "
            "loophole on the authoritative envelope (422o.4)."
        ),
    )

    # --- Layer 4: Faceting Metadata ---

    faceting: FacetingMetadata = Field(
        description="Structured metadata for querying across the scenario collection.",
    )

    # --- Priority ---

    priority: Priority = Field(
        description="Priority signals for human navigation.",
    )

    # --- Candidate Filter Results ---

    candidate_filter: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Candidate filter results: pinned_entry_point, pinned_technique_ids, "
            "pinned_technique_names, rejection_rationales."
        ),
    )

    # --- Validation ---

    validation: ValidationBlock | None = Field(
        default=None,
        description="Unified validation results (phantom, structural, semantic).",
    )
    validation_passed: bool | None = Field(
        default=None,
        description="True only if all three validation sub-blocks are valid. None if validation has not run.",
    )

    # --- Source-Influence Provenance (Wave 2: slice 5) ---

    source_influence_provenance: SourceInfluenceProvenanceBlock | None = Field(
        default=None,
        description=(
            "Typed source-influence provenance block linking projected "
            "attack-tree leaves and narrative steps to the declared threat "
            "sources, mitigations, and capability constraints in taxonomy "
            "scenario envelopes, with deterministic qualification metrics "
            "and pass/fail status.  Absent until source-influence "
            "provenance is declared for the scenario."
        ),
    )

    # --- Generation Metadata ---

    generation: GenerationMetadata = Field(
        description="Metadata about the generation process.",
    )

    @model_validator(mode="after")
    def _sync_validation_passed(self) -> ScenarioEnvelope:
        """Keep validation_passed in sync with the validation block."""
        if self.validation is not None and self.validation_passed is None:
            self.validation_passed = (
                self.validation.phantom.valid
                and self.validation.structural.valid
                and self.validation.semantic.valid
            )
        return self
