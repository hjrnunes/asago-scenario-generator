"""Projection persistence and artifact traceability models for ScenarioEnvelope.

This module defines the deeply immutable, standalone canonical projection
block persisted on :class:`ScenarioEnvelope` (bead ``asago-scenario-generator-422o.4``).

The projection block embeds the full :class:`ProjectionSnapshot` —
catalog/chain/taxonomy/mapping pins and digests, ordered selected typed
steps, condition evaluations/omissions, and concrete canonical resource
bindings — plus the derived execution requirements, projected taxonomy
mappings, canonical ingress identity, and **artifact realization
mappings** that trace every generated narrative/tree/behavior element
back to projected steps and observable postconditions.

Design invariants:

- **Deeply immutable**: the block uses ``frozen=True``/``extra="forbid"``.
  The embedded :class:`ProjectionSnapshot` is already content-addressed
  (digest-verified).  Nested mutation is detected by digest mismatch.
- **Standalone**: the block is self-contained — no taxonomy checkout is
  required to validate it.  When authoritative source inputs (the
  original :class:`AttackPattern` and :class:`CapabilityFactSnapshot`)
  are available, the projection and execution requirements can be
  recomputed and compared to detect drift.
- **Adapter-neutral**: the block carries execution requirements, not
  adapter payloads.  Generated content realizes but never selects,
  alters, omits, reorders, or fabricates projection semantics.
"""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from asago_scenario_generator.models.attack_pattern_contracts import (
    ExecutionRequirement,
)
from asago_scenario_generator.models.attack_pattern_projection import (
    EntryPointResourceReference,
    ProjectionSnapshot,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    Digest,
    ProjectedMapping,
    ProjectionModel,
    compute_derivation_context_digest,
    compute_execution_requirements_digest,
)

# ---------------------------------------------------------------------------#
# Artifact realization mappings
# ---------------------------------------------------------------------------#


class ArtifactStage(str, Enum):
    """Generated artifact stage that realizes projected steps."""

    narrative = "narrative"
    attack_tree = "attack_tree"
    behavior = "behavior"


class ArtifactRealizationMapping(ProjectionModel):
    """Map one generated artifact element to one or more projected steps.

    Controlled many-to-many realization (contract §5): one artifact element
    may realize multiple projected steps (combine), and one projected step
    may be realized by multiple artifact elements (split).  The total order
    of projected steps must be preserved across element ordering within the
    same artifact stage.
    """

    artifact_stage: ArtifactStage
    element_id: str = Field(
        min_length=1,
        description=(
            "Generated artifact element identifier: narrative step number "
            "as a string, attack-tree leaf node id, or behavior step "
            "reference."
        ),
    )
    projected_step_ids: tuple[str, ...] = Field(
        min_length=1,
        description=(
            "One or more projected step IDs from the projection's "
            "selected_step_ids.  Must be unique within this mapping."
        ),
    )

    @model_validator(mode="after")
    def _unique_steps(self) -> ArtifactRealizationMapping:
        if len(set(self.projected_step_ids)) != len(self.projected_step_ids):
            raise ValueError(
                f"projected_step_ids must be unique within a realization "
                f"mapping for element '{self.element_id}'"
            )
        return self


class AssertionRealizationMapping(ProjectionModel):
    """Map a generated behavior assertion to projected observable postconditions.

    Assertions map to projected observable postconditions (contract §4), not
    mechanically to setup steps.  Each assertion traces to one or more
    postconditions owned by one or more selected projected steps.
    """

    element_id: str = Field(
        min_length=1,
        description="Generated behavior assertion element identifier.",
    )
    source_step_ids: tuple[str, ...] = Field(
        min_length=1,
        description=(
            "Projected step IDs that own the postconditions this assertion "
            "verifies.  Must be unique within this mapping."
        ),
    )
    projected_postcondition_ids: tuple[str, ...] = Field(
        min_length=1,
        description=(
            "Observable postcondition IDs from the projected steps.  Must "
            "be unique within this mapping and resolvable in the source "
            "steps."
        ),
    )

    @model_validator(mode="after")
    def _unique_ids(self) -> AssertionRealizationMapping:
        if len(set(self.source_step_ids)) != len(self.source_step_ids):
            raise ValueError(
                f"source_step_ids must be unique within assertion mapping "
                f"'{self.element_id}'"
            )
        if len(set(self.projected_postcondition_ids)) != len(
            self.projected_postcondition_ids
        ):
            raise ValueError(
                f"projected_postcondition_ids must be unique within "
                f"assertion mapping '{self.element_id}'"
            )
        return self


# ---------------------------------------------------------------------------#
# Typed traceability violations (contract §8)
# ---------------------------------------------------------------------------#


class ProjectionTraceabilityStage(str, Enum):
    """Earliest responsible generated stage for a traceability violation."""

    actor_profile = "actor_profile"
    narrative = "narrative"
    attack_tree = "attack_tree"
    behavior_spec = "behavior_spec"


class ProjectionTraceabilityViolationCode(str, Enum):
    """Typed violation codes for projection traceability failures."""

    omitted_projected_step = "omitted_projected_step"
    reordered_projected_step = "reordered_projected_step"
    duplicated_projected_step = "duplicated_projected_step"
    unprojected_security_action = "unprojected_security_action"
    incomplete_coverage = "incomplete_coverage"
    incorrect_resource_binding = "incorrect_resource_binding"
    incorrect_ingress_binding = "incorrect_ingress_binding"
    forged_opaque_id = "forged_opaque_id"
    postcondition_assertion_mismatch = "postcondition_assertion_mismatch"
    or_tree_prohibited = "or_tree_prohibited"
    projection_drift = "projection_drift"
    nested_mutation = "nested_mutation"
    ingress_identity_mismatch = "ingress_identity_mismatch"
    requirement_drift = "requirement_drift"
    invalid_technique_mapping = "invalid_technique_mapping"
    authoritative_pattern_pin_mismatch = "authoritative_pattern_pin_mismatch"
    authoritative_catalog_pin_mismatch = "authoritative_catalog_pin_mismatch"


class ProjectionTraceabilityViolation(BaseModel):
    """A single typed traceability violation attributed to a generated stage."""

    model_config = ConfigDict(extra="forbid")

    code: ProjectionTraceabilityViolationCode
    stage: ProjectionTraceabilityStage
    detail: str = Field(min_length=1)
    element_id: str | None = None
    projected_step_id: str | None = None


class ProjectionTraceabilityResult(BaseModel):
    """Aggregated traceability validation result for cmps.5 consumption."""

    model_config = ConfigDict(extra="forbid")

    valid: bool = Field(default=True)
    violations: list[ProjectionTraceabilityViolation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _sync_valid(self) -> ProjectionTraceabilityResult:
        if self.violations:
            self.valid = False
        elif self.valid:
            # If no violations but valid was explicitly False, keep it.
            pass
        return self


# ---------------------------------------------------------------------------#
# Projection envelope block (contract §1)
# ---------------------------------------------------------------------------#


class ProjectionEnvelopeBlock(ProjectionModel):
    """Deeply immutable, standalone canonical projection persisted on the envelope.

    Carries the full immutable projection snapshot, derived execution
    requirements, projected taxonomy mappings, canonical ingress identity,
    and artifact realization mappings.  Every generated artifact receives
    the same fixed projection constraints; generated content realizes but
    never chooses or mutates the projection.
    """

    schema_version: Literal["3"] = "3"

    # --- Immutable projection snapshot (contract §1) ---
    projection: ProjectionSnapshot
    canonical_ingress: EntryPointResourceReference
    ingress_controllability: Literal["direct", "indirect"]
    projected_mappings: tuple[ProjectedMapping, ...]

    # --- Authoritative capability evidence (422o.4 blocker #3) ---
    # Full immutable CapabilityFactSnapshot embedded so that controllability
    # can be *derived* from evidence during standalone validation, not trusted
    # as an independent persisted input.  The snapshot digest must match
    # projection.capability_fact_snapshot_digest.
    capability_snapshot: CapabilityFactSnapshot

    # --- Execution requirements (contract §1, §3) ---
    execution_requirements: tuple[ExecutionRequirement, ...]
    requirement_derivation_version: Literal["1"] = "1"
    execution_requirements_digest: Digest
    derivation_context_digest: Digest = Field(
        description=(
            "Content-addressed digest binding the projection_digest, "
            "pattern_id, and ingress_controllability into the immutable "
            "derivation context.  Prevents flipping controllability and "
            "re-signing arbitrary requirements."
        ),
    )

    # --- Artifact realization mappings (contract §1, §4, §5) ---
    narrative_realizations: tuple[ArtifactRealizationMapping, ...] = ()
    tree_realizations: tuple[ArtifactRealizationMapping, ...] = ()
    behavior_realizations: tuple[ArtifactRealizationMapping, ...] = ()
    assertion_realizations: tuple[AssertionRealizationMapping, ...] = ()

    @model_validator(mode="after")
    def _ingress_matches_projection(self) -> ProjectionEnvelopeBlock:
        chain = self.projection.source_chain
        ingress_binding = _ingress_binding(
            self.projection, chain.initial_ingress_slot_id
        )
        if not _is_entry_point_binding(ingress_binding):
            raise TypeError("ingress binding must be an entry-point reference")
        if not _matches_canonical_ingress(ingress_binding, self.canonical_ingress):
            raise ValueError(
                "canonical_ingress does not match the projection's ingress binding"
            )
        return self

    @model_validator(mode="after")
    def _execution_requirements_digest_matches(self) -> ProjectionEnvelopeBlock:
        """Reject tampered execution requirements (nested mutation defense)."""
        expected = compute_execution_requirements_digest(self.execution_requirements)
        if expected != self.execution_requirements_digest:
            raise ValueError(
                "execution_requirements_digest does not match the persisted "
                "execution requirements; requirements were mutated after derivation"
            )
        return self

    @model_validator(mode="after")
    def _derivation_context_digest_matches(self) -> ProjectionEnvelopeBlock:
        """Bind ingress_controllability into the derivation context.

        A caller must not be able to flip controllability and re-sign
        arbitrary requirements.  The derivation context digest binds
        projection_digest + pattern_id + ingress_controllability.
        """
        expected = compute_derivation_context_digest(
            self.projection.projection_digest,
            self.projection.source_chain.pattern_id,
            self.ingress_controllability,
        )
        if expected != self.derivation_context_digest:
            raise ValueError(
                "derivation_context_digest does not match; ingress "
                "controllability was flipped or derivation context was mutated"
            )
        return self

    @model_validator(mode="after")
    def _capability_snapshot_digest_matches(self) -> ProjectionEnvelopeBlock:
        """Verify embedded capability snapshot digest against projection pin.

        The snapshot's ``snapshot_digest`` must equal the projection's
        ``capability_fact_snapshot_digest``.  This binds the evidence to
        the projection so a caller cannot substitute a different snapshot
        and re-derive arbitrary controllability.
        """
        if self.capability_snapshot.snapshot_digest != (
            self.projection.capability_fact_snapshot_digest
        ):
            raise ValueError(
                "capability_snapshot.snapshot_digest does not match "
                "projection.capability_fact_snapshot_digest; the embedded "
                "evidence does not belong to this projection"
            )
        return self

    @model_validator(mode="after")
    def _ingress_controllability_matches_evidence(self) -> ProjectionEnvelopeBlock:
        """Derive controllability from embedded evidence and require equality.

        The ``ingress_controllability`` field is NOT an independent trusted
        input — it must equal the effective controllability resolved from
        the embedded capability snapshot for the canonical ingress entry
        point.  A caller who flips controllability and re-signs the
        derivation context digest will fail here because the snapshot
        evidence produces the original controllability.
        """
        ep = self.capability_snapshot.profile.resolve_entry_point(
            self.canonical_ingress.entry_point_id
        )
        if ep is None:
            raise ValueError(
                "canonical_ingress entry_point_id is absent from the "
                "embedded capability snapshot profile"
            )
        if ep.effective_controllability != self.ingress_controllability:
            raise ValueError(
                f"ingress_controllability '{self.ingress_controllability}' "
                f"does not match the controllability '{ep.effective_controllability}' "
                f"derived from the embedded capability snapshot evidence"
            )
        return self

    @property
    def selected_step_ids(self) -> tuple[str, ...]:
        """Convenience accessor for the projected selected step IDs."""
        return self.projection.selected_step_ids

    @property
    def projected_step_order(self) -> dict[str, int]:
        """Map each selected step ID to its 0-based ordinal in projection order."""
        return {
            step_id: index
            for index, step_id in enumerate(self.projection.selected_step_ids)
        }

    def postconditions_for_step(self, step_id: str) -> tuple[str, ...]:
        """Return observable postcondition IDs owned by a projected step."""
        chain = self.projection.source_chain
        step = next((s for s in chain.steps if s.step_id == step_id), None)
        if step is None:
            return ()
        return tuple(pc.postcondition_id for pc in step.observable_postconditions)

    def security_relevant_postconditions(self) -> dict[str, list[str]]:
        """Map step_id → list of security-relevant postcondition IDs."""
        result: dict[str, list[str]] = {}
        chain = self.projection.source_chain
        selected = set(self.projection.selected_step_ids)
        for step in chain.steps:
            if step.step_id not in selected:
                continue
            for pc in step.observable_postconditions:
                if pc.security_relevant:
                    result.setdefault(step.step_id, []).append(pc.postcondition_id)
        return result


def _ingress_binding(projection: ProjectionSnapshot, slot_id: str) -> Any:
    """The projection binding for the initial ingress slot.

    Raises ``StopIteration`` when no binding matches — the projection
    snapshot contract requires the initial ingress slot to be bound.
    """
    return next(b for b in projection.bindings if b.slot_id == slot_id)


def _is_entry_point_binding(binding: Any) -> bool:
    """Whether a binding references a typed entry-point resource."""
    return isinstance(binding.resource_ref, EntryPointResourceReference)


def _matches_canonical_ingress(binding: Any, canonical_ingress: Any) -> bool:
    """Whether the binding resource equals the canonical ingress reference."""
    return binding.resource_ref == canonical_ingress


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T15:33:02Z","module_hash":"2db51e9bf1b09eed3dc9086bb60e33857a8f4c25ea1e1b165a20e13eb065f215","source_sha256":"1842267ebde53aa5c451dc71fde23b4c6a15b9f6e9e3ed1cd4e92f44099e0738","functions":[{"id":"func/ArtifactRealizationMapping._unique_steps","name":"_unique_steps","line":93,"end_line":99,"hash":"307ed111aa5f377a56b72b27a1e62b6b328f6f91bc80c53893e70d1081277370"},{"id":"func/AssertionRealizationMapping._unique_ids","name":"_unique_ids","line":131,"end_line":144,"hash":"0be3b394fbe1c334f1de8dfed6b8fa5cac0782c2005710d004fb59fbb0560fec"},{"id":"func/ProjectionTraceabilityResult._sync_valid","name":"_sync_valid","line":204,"end_line":210,"hash":"ecee26ec7023dadcc7da0de89269988fd49d68ef6c1eb94c3d4fb00a2c579387"},{"id":"func/ProjectionEnvelopeBlock._ingress_matches_projection","name":"_ingress_matches_projection","line":263,"end_line":274,"hash":"13f8873728b1b6f18e0a1f188a2f72e4a0889d235fb48b24cebb5338bbf83192"},{"id":"func/ProjectionEnvelopeBlock._execution_requirements_digest_matches","name":"_execution_requirements_digest_matches","line":277,"end_line":285,"hash":"8177040b5d3f3e77348c1c98e334d82c21b5f9f82714e0e7ebd890ea630a3884"},{"id":"func/ProjectionEnvelopeBlock._derivation_context_digest_matches","name":"_derivation_context_digest_matches","line":288,"end_line":305,"hash":"70019e51f78b157f5aafb62980d5ca8f6a503949b5d791a370f69e441c495f63"},{"id":"func/ProjectionEnvelopeBlock._capability_snapshot_digest_matches","name":"_capability_snapshot_digest_matches","line":308,"end_line":324,"hash":"66b73ffc3bf6fe6933ef94c60cc6514ac25e9937249dc52eeae28a155765983d"},{"id":"func/ProjectionEnvelopeBlock._ingress_controllability_matches_evidence","name":"_ingress_controllability_matches_evidence","line":327,"end_line":351,"hash":"bf7f2abebdaefa1f9b4dbd9f59ac69e7ab073113eba70ef72363b0b8584b4642"},{"id":"func/ProjectionEnvelopeBlock.selected_step_ids","name":"selected_step_ids","line":354,"end_line":356,"hash":"08b2c7af8c21891c3bac03e27469ca48d11602efd757f5a309c5b87a1208d4f9"},{"id":"func/ProjectionEnvelopeBlock.projected_step_order","name":"projected_step_order","line":359,"end_line":364,"hash":"a876bad4982017d8a4204376b8d2f6715a52a92f171fca58d22f48efd31d189c"},{"id":"func/ProjectionEnvelopeBlock.postconditions_for_step","name":"postconditions_for_step","line":366,"end_line":372,"hash":"fbf9d566b36616a6c254493390a455cb4c5681c52803fcb7d7cd0ab7d930b3a8"},{"id":"func/ProjectionEnvelopeBlock.security_relevant_postconditions","name":"security_relevant_postconditions","line":374,"end_line":385,"hash":"28f85cc7e1fcc2be468dff8ab3b09c8d415d1944656c3233d2df9b2cb2807df1"},{"id":"func/_ingress_binding","name":"_ingress_binding","line":388,"end_line":394,"hash":"96193babd92d81d84109cd5fb180d779e8d05f1aea7a7132c6252200d97bc4fc"},{"id":"func/_is_entry_point_binding","name":"_is_entry_point_binding","line":397,"end_line":399,"hash":"ba4978e32282913e28e70e41273e0622954280ae029cc7c80f0dbdf0599434c8"},{"id":"func/_matches_canonical_ingress","name":"_matches_canonical_ingress","line":402,"end_line":404,"hash":"fa80066267684e9fc4e08f32b28fced043c982824a6e5af541095272490ddf96"}]}
# mutate4py-manifest-end
