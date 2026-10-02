"""Coverage-aware planning over authoritative candidate-v2 records.

Replaces the legacy post-validation raw-seed remediation generator with
coverage-aware selection that operates exclusively on fully qualified
ProjectedCandidate records via typed :class:`QualifiedCandidate` wrappers.

Key concepts
------------
* **Coverage universe** – canonical profile entry points with direction
  ``input`` or ``bidirectional`` and controllability ``direct`` or
  ``indirect``.  Output-only / system-controlled entries are excluded with
  typed reasons.  Completeness is derived from the profile, never from
  free-form input.
* **Qualified candidate** – a typed planned candidate carrying a complete
  :class:`ProjectedCandidate` plus accepted filter verdict/rationale, merged
  origins, rule-removal provenance, and an explicit deterministic rank with
  candidate-ID tie-break.
* **Fallback queue** – a deterministic ranked list of at most three
  :class:`QualifiedCandidate` choices per target.  The first choice is
  selected for generation; remaining choices are surfaced as
  ``fallback_available`` in the persisted coverage plan for downstream retry
  logic (cmps.5).
* **Stage ledger** – records actual stage events (rules, filter, projection,
  selection, generation, admission, quarantine) per target/candidate.  The
  furthest actual event determines gap attribution — never backward inference.
* **Quality gap** – a typed, stage-attributed reason emitted when no
  compatible candidate survives for a target.  Coverage is never fabricated.
* **Coverage plan** – a versioned, persisted artifact with per-target ordered
  choices, primary selected/attempted state, and ``fallback_available``
  excluding every selected/attempted candidate.

This module owns queue construction, selection, and surfacing the next
choice.  It does **not** implement cmps.5's retry / admission / quarantine
state machine.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    FilteredSeed,
    RejectionRecord,
)

# Re-export these helpers for compatibility with existing planner consumers.
from asago_scenario_generator.pipeline.projection_contracts import ProjectedCandidate

# ---------------------------------------------------------------------------
# Qualified candidate — typed planned candidate over ProjectedCandidate
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AcceptedFilterRecord:
    """Typed accepted-filter evidence for one filter-stage candidate.

    When multiple accepted filter records converge on the same projected
    ``candidate_id``, all are preserved and merged canonically — no
    first-wins loss of provenance.
    """

    filter_candidate_id: str
    rationale: str
    origins: tuple[CandidateOrigin, ...] = ()
    rejection_rationales: tuple[RejectionRecord, ...] = ()
    pinned_entry_point: str = ""
    pinned_technique_ids: tuple[str, ...] = ()
    pinned_technique_names: tuple[str, ...] = ()
    seed: FilteredSeed | None = None

    def to_dict(self) -> dict:
        result = {
            "filter_candidate_id": self.filter_candidate_id,
            "rationale": self.rationale,
            "origins": [o.model_dump(mode="json") for o in self.origins],
            "rejection_rationales": [
                r.model_dump(mode="json") for r in self.rejection_rationales
            ],
            "pinned_entry_point": self.pinned_entry_point,
            "pinned_technique_ids": list(self.pinned_technique_ids),
            "pinned_technique_names": list(self.pinned_technique_names),
        }
        if self.seed is not None:
            result["seed"] = self.seed.model_dump(mode="json")
        return result

    @classmethod
    def from_dict(cls, data: dict) -> AcceptedFilterRecord:
        """Reconstruct an AcceptedFilterRecord from a serialized dict.

        The embedded ``seed`` (FilteredSeed) is model_validated so the
        complete generation seed survives round-trip deserialization.
        """
        seed_data = data.get("seed")
        seed = FilteredSeed.model_validate(seed_data) if seed_data else None
        return cls(
            filter_candidate_id=data["filter_candidate_id"],
            rationale=data["rationale"],
            origins=tuple(
                CandidateOrigin.model_validate(o) for o in data.get("origins", [])
            ),
            rejection_rationales=tuple(
                RejectionRecord.model_validate(r)
                for r in data.get("rejection_rationales", [])
            ),
            pinned_entry_point=data.get("pinned_entry_point", ""),
            pinned_technique_ids=tuple(data.get("pinned_technique_ids", [])),
            pinned_technique_names=tuple(data.get("pinned_technique_names", [])),
            seed=seed,
        )

    @classmethod
    def from_seed(cls, fseed: FilteredSeed) -> AcceptedFilterRecord:
        """Build from a FilteredSeed, preserving all provenance."""
        return cls(
            filter_candidate_id=fseed.candidate_id,
            rationale=fseed.accepted_rationale,
            origins=tuple(fseed.origins),
            rejection_rationales=tuple(fseed.rejection_rationales),
            pinned_entry_point=fseed.pinned_entry_point,
            pinned_technique_ids=tuple(fseed.pinned_technique_ids),
            pinned_technique_names=tuple(fseed.pinned_technique_names),
            seed=fseed,
        )


@dataclass(frozen=True)
class QualifiedCandidate:
    """A typed planned candidate carrying complete ProjectedCandidate plus
    a deterministic tuple of accepted filter records.

    Replaces the legacy ``(FilteredSeed, ProjectedCandidate)`` tuple.  The
    complete :class:`ProjectedCandidate` is the authoritative candidate-v2
    record.  When multiple accepted filter records converge on one projected
    candidate, all are preserved as a canonically sorted tuple — no
    first-wins loss of provenance.  An explicit deterministic rank with
    candidate-ID tie-break replaces the legacy pinned-technique-count ranking.
    """

    projected: ProjectedCandidate
    accepted_filters: tuple[AcceptedFilterRecord, ...]
    rank: int = 0

    @property
    def entry_point_id(self) -> str:
        """Canonical ingress entry point ID from the projected candidate."""
        return self.projected.canonical_ingress.entry_point_id

    @property
    def candidate_id(self) -> str:
        """Authoritative candidate-v2 ID from the projected candidate."""
        return self.projected.candidate_id

    @property
    def pattern_id(self) -> str:
        """Attack pattern ID from the projected candidate."""
        return self.projected.pattern_id

    @property
    def _sorted_filters(self) -> tuple[AcceptedFilterRecord, ...]:
        """Accepted filter records sorted by filter_candidate_id (canonical)."""
        return tuple(sorted(self.accepted_filters, key=lambda r: r.filter_candidate_id))

    @property
    def generation_seed(self) -> FilteredSeed:
        """Deterministically chosen FilteredSeed for ordinary generation.

        The seed with the lowest ``filter_candidate_id`` is chosen so that
        generation behaviour is deterministic and encounter-independent.
        """
        for record in self._sorted_filters:
            if record.seed is not None:
                return record.seed
        raise ValueError(
            "QualifiedCandidate has no seed-bearing accepted filter record"
        )

    @property
    def filtered_seed(self) -> FilteredSeed:
        """Backward-compatible alias for :attr:`generation_seed`."""
        return self.generation_seed

    @property
    def filter_candidate_id(self) -> str:
        """Filter-stage candidate ID (provenance only, not authoritative)."""
        if not self._sorted_filters:
            return ""
        return self._sorted_filters[0].filter_candidate_id

    @property
    def accepted_rationale(self) -> str:
        """First rationale (deterministically sorted) for backward compat."""
        if not self._sorted_filters:
            return ""
        return self._sorted_filters[0].rationale

    @property
    def merged_origins(self) -> list[CandidateOrigin]:
        """Merged origins from all accepted filter records, deduplicated."""
        return _merge_deduped(self._sorted_filters, lambda record: record.origins)

    @property
    def origins(self) -> list[CandidateOrigin]:
        """Backward-compatible alias for :attr:`merged_origins`."""
        return self.merged_origins

    @property
    def merged_rejection_rationales(self) -> list[RejectionRecord]:
        """Merged rule-removal provenance from all accepted filter records."""
        return _merge_deduped(
            self._sorted_filters, lambda record: record.rejection_rationales
        )

    @property
    def rejection_rationales(self) -> list[RejectionRecord]:
        """Backward-compatible alias for :attr:`merged_rejection_rationales`."""
        return self.merged_rejection_rationales

    def to_plan_ref(self) -> dict:
        """Serialize to a content-addressed plan reference.

        Persists the complete validated ``ProjectedCandidate`` JSON (not
        a thin ref) plus the merged filter provenance tuple, so that a
        persisted fallback choice can be deserialized and reconstructed
        into an exact ``ProjectedCandidate`` usable by ordinary generation.
        """
        return {
            "candidate_id": self.candidate_id,
            "filter_candidate_id": self.filter_candidate_id,
            "pattern_id": self.pattern_id,
            "entry_point_id": self.entry_point_id,
            "rank": self.rank,
            "projected_candidate": self.projected.model_dump(mode="json"),
            "accepted_filters": [r.to_dict() for r in self._sorted_filters],
            "accepted_rationale": self.accepted_rationale,
            "origins": [o.model_dump(mode="json") for o in self.merged_origins],
            "rejection_rationales": [
                r.model_dump(mode="json") for r in self.merged_rejection_rationales
            ],
            **_first_filter_summary(self._sorted_filters),
        }


def _merge_deduped(
    records: Sequence[AcceptedFilterRecord],
    items_of: Any,
) -> list[Any]:
    """Merge items from accepted filter records, deduplicating by JSON identity.

    Order follows the canonically sorted filter records and preserves first
    occurrence per item — no first-wins loss of provenance.
    """
    seen: list[str] = []
    merged: list[Any] = []
    for record in records:
        for item in items_of(record):
            key = item.model_dump_json()
            if key not in seen:
                seen.append(key)
                merged.append(item)
    return merged


def _first_filter_summary(records: Sequence[AcceptedFilterRecord]) -> dict:
    """Pinned-technique summary of the first (canonically sorted) filter record."""
    if not records:
        return {
            "pinned_entry_point": "",
            "pinned_technique_ids": [],
            "pinned_technique_names": [],
        }
    first = records[0]
    return {
        "pinned_entry_point": first.pinned_entry_point,
        "pinned_technique_ids": list(first.pinned_technique_ids),
        "pinned_technique_names": list(first.pinned_technique_names),
    }


# ---------------------------------------------------------------------------
# Stage ledger — actual stage events per target/candidate
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Fallback queue construction
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Coverage-aware selection
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Versioned coverage plan
# ---------------------------------------------------------------------------


def deserialize_plan_ref(ref: dict) -> ProjectedCandidate:
    """Reconstruct an exact ``ProjectedCandidate`` from a persisted plan ref.

    The plan ref carries the complete validated ``ProjectedCandidate`` JSON
    (not a thin ref), so this round-trips through ``model_validate`` to
    produce a fully validated instance usable by ordinary generation.

    Args:
        ref: A serialized plan reference from :meth:`QualifiedCandidate.to_plan_ref`.

    Returns:
        A validated :class:`ProjectedCandidate` identical to the original.

    Raises:
        ValueError: If the ref does not contain a valid projected candidate.
    """
    pc_data = ref.get("projected_candidate")
    if pc_data is None:
        raise ValueError("plan ref missing 'projected_candidate' — cannot reconstruct")
    return ProjectedCandidate.model_validate(pc_data)


@dataclass(frozen=True)
class DeserializedPlanRef:
    """Typed result of deserializing a persisted plan reference.

    Carries the fully validated :class:`ProjectedCandidate`, the
    deterministically ordered accepted filter records, and the
    :class:`FilteredSeed` usable by ordinary generation.  The outer
    candidate/pattern/entry-point IDs are verified against the embedded
    data during deserialization — tampering is rejected.
    """

    projected: ProjectedCandidate
    accepted_filters: tuple[AcceptedFilterRecord, ...]
    rank: int

    @property
    def candidate_id(self) -> str:
        return self.projected.candidate_id

    @property
    def pattern_id(self) -> str:
        return self.projected.pattern_id

    @property
    def entry_point_id(self) -> str:
        return self.projected.canonical_ingress.entry_point_id

    @property
    def generation_seed(self) -> FilteredSeed:
        """Deterministic FilteredSeed for ordinary generation.

        The seed with the lowest ``filter_candidate_id`` is chosen —
        identical to :attr:`QualifiedCandidate.generation_seed`.
        """
        for record in self.accepted_filters:
            if record.seed is not None:
                return record.seed
        raise ValueError(
            "deserialized plan ref has no seed-bearing accepted filter record"
        )


def _verify_outer_identity(ref: dict, pc: ProjectedCandidate) -> None:
    """Verify the outer IDs agree with the embedded projected candidate."""
    outer_candidate_id = ref.get("candidate_id", "")
    if outer_candidate_id != pc.candidate_id:
        raise ValueError(
            f"plan ref outer candidate_id '{outer_candidate_id}' disagrees "
            f"with embedded projected candidate_id '{pc.candidate_id}'"
        )
    outer_pattern_id = ref.get("pattern_id", "")
    if outer_pattern_id != pc.pattern_id:
        raise ValueError(
            f"plan ref outer pattern_id '{outer_pattern_id}' disagrees "
            f"with embedded projected pattern_id '{pc.pattern_id}'"
        )
    outer_entry_point_id = ref.get("entry_point_id", "")
    if outer_entry_point_id != pc.canonical_ingress.entry_point_id:
        raise ValueError(
            f"plan ref outer entry_point_id '{outer_entry_point_id}' disagrees "
            f"with embedded projected ingress entry_point_id "
            f"'{pc.canonical_ingress.entry_point_id}'"
        )


def _deserialize_filter_records(
    raw_filters: Sequence[dict],
) -> list[AcceptedFilterRecord]:
    """Deserialize accepted filter records, enforcing seed presence and fidelity.

    The serialized summary fields are not independent evidence — they must
    exactly be the canonical projection of the embedded seed.
    """
    if not raw_filters:
        raise ValueError("plan ref has no accepted filter records")

    records: list[AcceptedFilterRecord] = []
    for raw in raw_filters:
        record = AcceptedFilterRecord.from_dict(raw)
        if record.seed is None:
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' is missing seed"
            )
        if record != AcceptedFilterRecord.from_seed(record.seed):
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' does not "
                "match its embedded FilteredSeed"
            )
        records.append(record)
    return records


def _verify_canonical_filter_ids(records: Sequence[AcceptedFilterRecord]) -> None:
    """Reject duplicate and noncanonically ordered filter_candidate_ids."""
    filter_ids = [r.filter_candidate_id for r in records]
    if len(set(filter_ids)) != len(filter_ids):
        dupes = sorted(cid for cid, count in Counter(filter_ids).items() if count > 1)
        raise ValueError(f"plan ref has duplicate filter_candidate_ids: {dupes}")

    expected_order = sorted(filter_ids)
    if filter_ids != expected_order:
        raise ValueError(
            f"plan ref accepted_filters are not in canonical order "
            f"(sorted by filter_candidate_id): got {filter_ids}, "
            f"expected {expected_order}"
        )


def _verify_seed_ingress_agreement(
    records: Sequence[AcceptedFilterRecord], pc: ProjectedCandidate
) -> None:
    """Verify each seed's entry_point_id matches the projected ingress."""
    for record in records:
        if record.seed is not None and (
            record.seed.entry_point_id != pc.canonical_ingress.entry_point_id
        ):
            raise ValueError(
                f"accepted filter record '{record.filter_candidate_id}' "
                f"seed entry_point_id '{record.seed.entry_point_id}' "
                f"disagrees with projected ingress "
                f"'{pc.canonical_ingress.entry_point_id}'"
            )


def _verify_outer_summaries(
    ref: dict, records: Sequence[AcceptedFilterRecord], pc: ProjectedCandidate
) -> None:
    """Validate duplicated outer summaries rather than trusting them.

    This keeps existing plan consumers compatible without creating a second,
    mutable source of filter provenance.
    """
    canonical_qc = QualifiedCandidate(
        projected=pc, accepted_filters=tuple(records), rank=0
    )
    expected_outer = {
        "filter_candidate_id": canonical_qc.filter_candidate_id,
        "accepted_rationale": canonical_qc.accepted_rationale,
        "origins": [o.model_dump(mode="json") for o in canonical_qc.merged_origins],
        "rejection_rationales": [
            r.model_dump(mode="json") for r in canonical_qc.merged_rejection_rationales
        ],
        "pinned_entry_point": canonical_qc.generation_seed.pinned_entry_point,
        "pinned_technique_ids": list(canonical_qc.generation_seed.pinned_technique_ids),
        "pinned_technique_names": list(
            canonical_qc.generation_seed.pinned_technique_names
        ),
    }
    for field_name, expected in expected_outer.items():
        if ref.get(field_name) != expected:
            raise ValueError(
                f"plan ref outer {field_name} does not match accepted filter records"
            )


def deserialize_qualified_candidate(ref: dict) -> DeserializedPlanRef:
    """Deserialize a persisted plan ref into a typed, verified contract.

    Reconstructs the complete :class:`ProjectedCandidate` and the
    deterministically ordered accepted filter records (each carrying its
    complete :class:`FilteredSeed`).  The following integrity checks are
    enforced:

    * The outer ``candidate_id``, ``pattern_id``, and ``entry_point_id``
      must agree with the embedded ``ProjectedCandidate`` data.
    * Accepted filter records must be in canonical (sorted by
      ``filter_candidate_id``) order with no duplicates.
    * Every accepted filter record's embedded seed must have an
      ``entry_point_id`` matching the projected candidate's ingress.

    Args:
        ref: A serialized plan reference from
            :meth:`QualifiedCandidate.to_plan_ref`.

    Returns:
        A :class:`DeserializedPlanRef` with the validated projected
        candidate, ordered filter records, and deterministic generation
        seed.

    Raises:
        ValueError: If any integrity check fails or embedded data is
            invalid.
    """
    # Validate the projected candidate through model_validate.
    pc = deserialize_plan_ref(ref)

    _verify_outer_identity(ref, pc)
    records = _deserialize_filter_records(ref.get("accepted_filters", []))
    _verify_canonical_filter_ids(records)
    _verify_seed_ingress_agreement(records, pc)

    rank = ref.get("rank", 0)
    _verify_outer_summaries(ref, records, pc)

    return DeserializedPlanRef(
        projected=pc,
        accepted_filters=tuple(records),
        rank=rank,
    )


def _find_trusted_record(
    trusted_catalog: Sequence[dict[str, Any]], pattern_id: str
) -> dict[str, Any] | None:
    """Locate the matching record in the COMPLETE trusted catalog by pattern ID."""
    return next(
        (record for record in trusted_catalog if record.get("id") == pattern_id),
        None,
    )


def _expected_authoritative_pin(
    trusted_catalog: Sequence[dict[str, Any]],
    taxonomy_resolver: Any,
    expected_catalog_pin: str | None,
) -> str:
    """Resolve the authoritative catalog pin, computing it when not supplied."""
    if expected_catalog_pin is None:
        from asago_scenario_generator.pipeline.projection_qualification import (
            compute_authoritative_catalog_pin,
        )

        return compute_authoritative_catalog_pin(trusted_catalog, taxonomy_resolver)
    return expected_catalog_pin


def revalidate_qualified_candidate(
    ref: dict,
    taxonomy_resolver: Any,
    snapshot: Any,
    trusted_catalog: Sequence[dict[str, Any]],
    *,
    expected_catalog_pin: str | None = None,
) -> DeserializedPlanRef:
    """Deserialize AND authoritatively revalidate a plan ref.

    Combines :func:`deserialize_qualified_candidate` with authoritative
    requalification of the embedded :class:`ProjectedCandidate` against a
    trusted catalog and :class:`CapabilityFactSnapshot`.  The self-contained
    JSON is never trusted alone — the candidate is re-derived from the
    trusted catalog and compared to the deserialized projection.

    Args:
        ref: A serialized plan reference.
        taxonomy_resolver: Trusted taxonomy resolver for attack pattern
            validation.
        snapshot: Trusted :class:`CapabilityFactSnapshot` for projection
            requalification.

    Returns:
        A :class:`DeserializedPlanRef` if both deserialization and
        authoritative revalidation succeed.

    Raises:
        ValueError: If deserialization fails or the authoritative
            requalification drifts from the embedded projection.
    """
    from asago_scenario_generator.pipeline.projection import (
        validate_projected_candidate,
    )

    deserialized = deserialize_qualified_candidate(ref)

    # Use the direct validation contract.  Do not bounded-reproject: an
    # exact binding variant can validly sit beyond any chosen projection
    # budget.
    trusted_pattern_id = deserialized.pattern_id
    trusted_record = _find_trusted_record(trusted_catalog, trusted_pattern_id)
    if trusted_record is None:
        raise ValueError(
            f"authoritative drift: pattern '{trusted_pattern_id}' not found "
            f"in trusted catalog"
        )

    pin = _expected_authoritative_pin(
        trusted_catalog, taxonomy_resolver, expected_catalog_pin
    )
    validated = validate_projected_candidate(
        deserialized.projected.model_dump(mode="json"),
        snapshot,
        trusted_record,
        taxonomy_resolver,
        expected_catalog_pin=pin,
    )
    if validated != deserialized.projected:
        raise ValueError(
            "authoritative validation did not preserve persisted candidate"
        )

    return deserialized


# ---------------------------------------------------------------------------
# Typed quality gaps — from actual stage ledger evidence
# ---------------------------------------------------------------------------
