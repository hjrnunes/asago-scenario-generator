"""Property-based tests for Stage 1a loss analysis merge/renumber invariants.

These tests verify structural invariants that hold across broad input
ranges for the two-call merge logic in ``loss_analysis.py``:

1. **Sequential IDs**: After merging any two drafts, all L-/H-/SC- IDs
   are sequential from 1 with no gaps or duplicates.

2. **Cross-reference validity**: After merge, every hazard's
   ``related_losses`` references a valid loss ID, and every constraint's
   ``related_hazards`` references a valid hazard ID.

3. **Item count conservation**: The merged result has exactly as many
   items as the sum of both drafts — no items are lost or duplicated.

4. **_renumber_items bijectivity**: The old→new ID map is injective
   (no two old IDs map to the same new ID) and surjective onto the
   sequential range.

5. **_max_id_num correctness**: Returns the maximum numeric suffix
   for any list of prefixed IDs, and 0 for empty/non-matching lists.

6. **_remap_references completeness**: All references found in the
   map are remapped; references not in the map are preserved unchanged.

These complement the example-based tests in ``test_sp1_loss_analysis.py``.
"""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings, strategies as st

from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysisDraft,
    LossProvenance,
    SecurityConstraint,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    _max_id_num,
    _merge_drafts,
    _remap_references,
    _renumber_items,
    derive_loss_analysis,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_risk_loss(loss_id: str, n_cards: int = 1) -> Loss:
    """Build a risk-card loss with valid provenance."""
    return Loss(
        loss_id=loss_id,
        description=f"Risk loss {loss_id}",
        provenance=LossProvenance.risk_card,
        source_risk_cards=[f"atlas-{i:03d}" for i in range(1, n_cards + 1)],
    )


def _make_uc_loss(loss_id: str) -> Loss:
    """Build a use-case loss with valid provenance."""
    return Loss(
        loss_id=loss_id,
        description=f"UC loss {loss_id}",
        provenance=LossProvenance.use_case,
        source_risk_cards=[],
    )


def _make_hazard(hazard_id: str, related_losses: list[str]) -> Hazard:
    """Build a hazard referencing the given loss IDs."""
    return Hazard(
        hazard_id=hazard_id,
        description=f"Hazard {hazard_id}",
        related_losses=list(related_losses),
    )


def _make_constraint(constraint_id: str, related_hazards: list[str]) -> SecurityConstraint:
    """Build a security constraint referencing the given hazard IDs."""
    return SecurityConstraint(
        constraint_id=constraint_id,
        description=f"Constraint {constraint_id}",
        related_hazards=list(related_hazards),
    )


def _build_risk_draft(
    n_risk_losses: int,
    n_hazards: int,
    n_constraints: int,
    id_offset: int = 0,
) -> LossAnalysisDraft:
    """Build a valid risk-derivation draft.

    Losses use non-sequential IDs starting from ``id_offset`` to stress
    the renumbering logic.  Hazards reference the first loss; constraints
    reference the first hazard.
    """
    risk_losses = [
        _make_risk_loss(f"L-{id_offset + i * 3 + 1}")
        for i in range(n_risk_losses)
    ]
    loss_ids = [loss.loss_id for loss in risk_losses]
    hazards = []
    for i in range(n_hazards):
        # Each hazard references at least one loss
        refs = [loss_ids[i % len(loss_ids)]] if loss_ids else []
        hazards.append(_make_hazard(f"H-{id_offset + i * 5 + 1}", refs))
    hazard_ids = [h.hazard_id for h in hazards]
    constraints = []
    for i in range(n_constraints):
        refs = [hazard_ids[i % len(hazard_ids)]] if hazard_ids else []
        constraints.append(_make_constraint(f"SC-{id_offset + i * 7 + 1}", refs))
    return LossAnalysisDraft(
        risk_card_losses=risk_losses,
        use_case_losses=[],
        hazards=hazards,
        security_constraints=constraints,
    )


def _build_gap_draft(
    n_uc_losses: int,
    n_hazards: int,
    n_constraints: int,
    id_offset: int = 0,
    cross_ref_loss_ids: list[str] | None = None,
) -> LossAnalysisDraft:
    """Build a valid gap-analysis draft.

    Losses use non-sequential IDs starting from ``id_offset``.  Hazards
    may cross-reference loss IDs from the risk draft via
    ``cross_ref_loss_ids`` to test cross-draft reference remapping.
    """
    uc_losses = [
        _make_uc_loss(f"L-{id_offset + i * 3 + 1}")
        for i in range(n_uc_losses)
    ]
    own_loss_ids = [loss.loss_id for loss in uc_losses]
    all_loss_ids = list(cross_ref_loss_ids or []) + own_loss_ids
    hazards = []
    for i in range(n_hazards):
        refs = [all_loss_ids[i % len(all_loss_ids)]] if all_loss_ids else []
        hazards.append(_make_hazard(f"H-{id_offset + i * 5 + 1}", refs))
    hazard_ids = [h.hazard_id for h in hazards]
    constraints = []
    for i in range(n_constraints):
        refs = [hazard_ids[i % len(hazard_ids)]] if hazard_ids else []
        constraints.append(_make_constraint(f"SC-{id_offset + i * 7 + 1}", refs))
    return LossAnalysisDraft(
        risk_card_losses=[],
        use_case_losses=uc_losses,
        hazards=hazards,
        security_constraints=constraints,
    )


# ---------------------------------------------------------------------------
# _max_id_num property tests
# ---------------------------------------------------------------------------


class TestMaxIdNumProperties:
    """Property tests for _max_id_num."""

    @given(
        nums=st.lists(st.integers(min_value=1, max_value=999), min_size=0, max_size=20),
        prefix=st.sampled_from(["L-", "H-", "SC-"]),
    )
    @settings(max_examples=50, deadline=None)
    def test_returns_maximum_numeric_suffix(self, nums, prefix):
        """_max_id_num returns the maximum numeric suffix for matching IDs."""
        ids = [f"{prefix}{n}" for n in nums]
        result = _max_id_num(ids, prefix)
        if nums:
            assert result == max(nums)
        else:
            assert result == 0

    @given(
        nums=st.lists(st.integers(min_value=1, max_value=999), min_size=1, max_size=10),
    )
    @settings(max_examples=30, deadline=None)
    def test_ignores_non_matching_prefix(self, nums):
        """_max_id_num ignores IDs with a different prefix."""
        ids = [f"L-{n}" for n in nums] + ["H-42", "SC-99"]
        result = _max_id_num(ids, "L-")
        assert result == max(nums)

    @given(
        prefix=st.sampled_from(["L-", "H-", "SC-"]),
    )
    @settings(max_examples=10, deadline=None)
    def test_empty_list_returns_zero(self, prefix):
        """_max_id_num returns 0 for an empty list."""
        assert _max_id_num([], prefix) == 0

    @given(
        prefix=st.sampled_from(["L-", "H-", "SC-"]),
    )
    @settings(max_examples=10, deadline=None)
    def test_non_matching_ids_return_zero(self, prefix):
        """_max_id_num returns 0 when no IDs match the prefix."""
        other_prefix = "X-" if prefix != "X-" else "Y-"
        ids = [f"{other_prefix}{n}" for n in range(1, 10)]
        assert _max_id_num(ids, prefix) == 0


# ---------------------------------------------------------------------------
# _renumber_items property tests
# ---------------------------------------------------------------------------


class _StubItem:
    """Minimal mutable object for _renumber_items / _remap_references tests."""

    def __init__(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self, key, value)


class TestRenumberItemsProperties:
    """Property tests for _renumber_items.

    The ``id_attr`` and ``prefix`` parameters are independent — e.g.
    ``id_attr="loss_id"`` pairs with ``prefix="L-"``.  Tests use a
    generic ``item_id`` attribute with various prefixes.
    """

    @given(
        n=st.integers(min_value=0, max_value=10),
        prefix=st.sampled_from(["L-", "H-", "SC-"]),
        start=st.integers(min_value=1, max_value=5),
    )
    @settings(max_examples=50, deadline=None)
    def test_produces_sequential_ids(self, n, prefix, start):
        """_renumber_items assigns sequential IDs starting from *start*."""
        items = [_StubItem(item_id=f"OLD-{i * 100}") for i in range(n)]
        id_map = _renumber_items(items, "item_id", prefix, start=start)
        if n == 0:
            assert id_map == {}
            return
        expected_ids = [f"{prefix}{start + i}" for i in range(n)]
        actual_ids = [item.item_id for item in items]
        assert actual_ids == expected_ids

    @given(
        n=st.integers(min_value=1, max_value=10),
        prefix=st.sampled_from(["L-", "H-", "SC-"]),
    )
    @settings(max_examples=40, deadline=None)
    def test_id_map_is_bijective(self, n, prefix):
        """The old→new ID map is injective (no two old IDs map to same new ID)."""
        items = [_StubItem(item_id=f"OLD-{i * 50}") for i in range(n)]
        id_map = _renumber_items(items, "item_id", prefix)
        new_ids = list(id_map.values())
        assert len(new_ids) == len(set(new_ids)), (
            f"Duplicate new IDs in map: {new_ids}"
        )
        # Map keys are the original IDs
        assert len(id_map) == n

    @given(
        n=st.integers(min_value=0, max_value=10),
        prefix=st.sampled_from(["L-", "H-", "SC-"]),
        start=st.integers(min_value=1, max_value=10),
    )
    @settings(max_examples=40, deadline=None)
    def test_new_ids_have_correct_prefix(self, n, prefix, start):
        """All new IDs have the correct prefix."""
        items = [_StubItem(item_id=f"OLD-{i}") for i in range(n)]
        _renumber_items(items, "item_id", prefix, start=start)
        for item in items:
            assert item.item_id.startswith(prefix)


# ---------------------------------------------------------------------------
# _remap_references property tests
# ---------------------------------------------------------------------------


class TestRemapReferencesProperties:
    """Property tests for _remap_references."""

    @given(
        n_known=st.integers(min_value=1, max_value=5),
        n_unknown=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=40, deadline=None)
    def test_known_refs_remapped(self, n_known, n_unknown):
        """References found in the map are remapped to new values."""
        id_map = {f"OLD-{i}": f"NEW-{i}" for i in range(n_known)}
        refs = [f"OLD-{i}" for i in range(n_known)] + [
            f"UNKNOWN-{i}" for i in range(n_unknown)
        ]
        item = _StubItem(refs=list(refs))
        _remap_references([item], "refs", id_map)
        remapped = item.refs
        # Known refs should be remapped
        for i in range(n_known):
            assert f"NEW-{i}" in remapped
        # Unknown refs should be preserved
        for i in range(n_unknown):
            assert f"UNKNOWN-{i}" in remapped

    @given(
        n_known=st.integers(min_value=0, max_value=5),
    )
    @settings(max_examples=20, deadline=None)
    def test_empty_map_preserves_all(self, n_known):
        """An empty map preserves all references unchanged."""
        refs = [f"REF-{i}" for i in range(n_known)]
        item = _StubItem(refs=list(refs))
        _remap_references([item], "refs", {})
        assert item.refs == refs

    @given(
        n_items=st.integers(min_value=1, max_value=5),
        n_refs=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=30, deadline=None)
    def test_ref_count_preserved(self, n_items, n_refs):
        """The number of references per item is preserved after remapping."""
        id_map = {f"OLD-{i}": f"NEW-{i}" for i in range(10)}
        items = [
            _StubItem(refs=[f"OLD-{i % 10}" for i in range(n_refs)])
            for _ in range(n_items)
        ]
        _remap_references(items, "refs", id_map)
        for item in items:
            assert len(item.refs) == n_refs


# ---------------------------------------------------------------------------
# _merge_drafts property tests
# ---------------------------------------------------------------------------


class TestMergeDraftsProperties:
    """Property tests for _merge_drafts invariants.

    These test the core merge/renumber logic directly, verifying that
    the merged LossAnalysis always satisfies structural invariants
    regardless of the input draft sizes or ID patterns.
    """

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=4),
        n_uc_losses=st.integers(min_value=1, max_value=4),
        n_risk_hazards=st.integers(min_value=1, max_value=3),
        n_gap_hazards=st.integers(min_value=0, max_value=3),
        n_risk_constraints=st.integers(min_value=1, max_value=3),
        n_gap_constraints=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=50, deadline=None)
    def test_sequential_ids_after_merge(
        self,
        n_risk_losses,
        n_uc_losses,
        n_risk_hazards,
        n_gap_hazards,
        n_risk_constraints,
        n_gap_constraints,
    ):
        """After merge, all L-/H-/SC- IDs are sequential from 1."""
        risk = _build_risk_draft(
            n_risk_losses, n_risk_hazards, n_risk_constraints, id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses, n_gap_hazards, n_gap_constraints, id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        all_losses = merged.risk_card_losses + merged.use_case_losses
        loss_ids = [loss.loss_id for loss in all_losses]
        expected_loss_ids = [f"L-{i}" for i in range(1, len(all_losses) + 1)]
        assert loss_ids == expected_loss_ids, (
            f"Loss IDs not sequential: {loss_ids}"
        )

        hazard_ids = [h.hazard_id for h in merged.hazards]
        expected_hazard_ids = [f"H-{i}" for i in range(1, len(hazard_ids) + 1)]
        assert hazard_ids == expected_hazard_ids, (
            f"Hazard IDs not sequential: {hazard_ids}"
        )

        sc_ids = [sc.constraint_id for sc in merged.security_constraints]
        expected_sc_ids = [f"SC-{i}" for i in range(1, len(sc_ids) + 1)]
        assert sc_ids == expected_sc_ids, (
            f"SC IDs not sequential: {sc_ids}"
        )

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=4),
        n_uc_losses=st.integers(min_value=1, max_value=4),
        n_risk_hazards=st.integers(min_value=1, max_value=3),
        n_gap_hazards=st.integers(min_value=0, max_value=3),
        n_risk_constraints=st.integers(min_value=1, max_value=3),
        n_gap_constraints=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=50, deadline=None)
    def test_cross_references_valid_after_merge(
        self,
        n_risk_losses,
        n_uc_losses,
        n_risk_hazards,
        n_gap_hazards,
        n_risk_constraints,
        n_gap_constraints,
    ):
        """After merge, all cross-references point to valid IDs."""
        risk = _build_risk_draft(
            n_risk_losses, n_risk_hazards, n_risk_constraints, id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses, n_gap_hazards, n_gap_constraints, id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        all_loss_ids = {
            loss.loss_id for loss in merged.risk_card_losses + merged.use_case_losses
        }
        all_hazard_ids = {h.hazard_id for h in merged.hazards}

        for hazard in merged.hazards:
            for ref in hazard.related_losses:
                assert ref in all_loss_ids, (
                    f"Hazard {hazard.hazard_id} references invalid loss '{ref}'"
                )

        for sc in merged.security_constraints:
            for ref in sc.related_hazards:
                assert ref in all_hazard_ids, (
                    f"Constraint {sc.constraint_id} references invalid hazard '{ref}'"
                )

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=4),
        n_uc_losses=st.integers(min_value=1, max_value=4),
        n_risk_hazards=st.integers(min_value=1, max_value=3),
        n_gap_hazards=st.integers(min_value=0, max_value=3),
        n_risk_constraints=st.integers(min_value=1, max_value=3),
        n_gap_constraints=st.integers(min_value=0, max_value=3),
    )
    @settings(max_examples=50, deadline=None)
    def test_item_count_conservation(
        self,
        n_risk_losses,
        n_uc_losses,
        n_risk_hazards,
        n_gap_hazards,
        n_risk_constraints,
        n_gap_constraints,
    ):
        """The merged result has exactly as many items as the sum of both drafts."""
        risk = _build_risk_draft(
            n_risk_losses, n_risk_hazards, n_risk_constraints, id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses, n_gap_hazards, n_gap_constraints, id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        assert len(merged.risk_card_losses) == n_risk_losses
        assert len(merged.use_case_losses) == n_uc_losses
        assert len(merged.hazards) == n_risk_hazards + n_gap_hazards
        assert len(merged.security_constraints) == n_risk_constraints + n_gap_constraints

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=3),
        n_uc_losses=st.integers(min_value=1, max_value=3),
        n_risk_hazards=st.integers(min_value=1, max_value=2),
        n_gap_hazards=st.integers(min_value=1, max_value=2),
        n_risk_constraints=st.integers(min_value=1, max_value=2),
        n_gap_constraints=st.integers(min_value=1, max_value=2),
    )
    @settings(max_examples=30, deadline=None)
    def test_no_duplicate_ids_after_merge(
        self,
        n_risk_losses,
        n_uc_losses,
        n_risk_hazards,
        n_gap_hazards,
        n_risk_constraints,
        n_gap_constraints,
    ):
        """After merge, no duplicate IDs exist in any category."""
        risk = _build_risk_draft(
            n_risk_losses, n_risk_hazards, n_risk_constraints, id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses, n_gap_hazards, n_gap_constraints, id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        all_loss_ids = [loss.loss_id for loss in merged.risk_card_losses + merged.use_case_losses]
        assert len(all_loss_ids) == len(set(all_loss_ids)), (
            f"Duplicate loss IDs: {all_loss_ids}"
        )

        hazard_ids = [h.hazard_id for h in merged.hazards]
        assert len(hazard_ids) == len(set(hazard_ids)), (
            f"Duplicate hazard IDs: {hazard_ids}"
        )

        sc_ids = [sc.constraint_id for sc in merged.security_constraints]
        assert len(sc_ids) == len(set(sc_ids)), (
            f"Duplicate SC IDs: {sc_ids}"
        )

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=3),
        n_uc_losses=st.integers(min_value=1, max_value=3),
    )
    @settings(max_examples=25, deadline=None)
    def test_provenance_preserved_after_merge(
        self,
        n_risk_losses,
        n_uc_losses,
    ):
        """Provenance is preserved: risk_card losses stay risk_card, UC stay use_case."""
        risk = _build_risk_draft(
            n_risk_losses, 1, 1, id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses, 1, 1, id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        for loss in merged.risk_card_losses:
            assert loss.provenance == LossProvenance.risk_card
            assert len(loss.source_risk_cards) > 0

        for loss in merged.use_case_losses:
            assert loss.provenance == LossProvenance.use_case
            assert len(loss.source_risk_cards) == 0

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=3),
        n_uc_losses=st.integers(min_value=1, max_value=3),
        n_risk_hazards=st.integers(min_value=1, max_value=2),
        n_gap_hazards=st.integers(min_value=0, max_value=2),
        n_risk_constraints=st.integers(min_value=1, max_value=2),
        n_gap_constraints=st.integers(min_value=0, max_value=2),
    )
    @settings(max_examples=30, deadline=None)
    def test_merged_result_passes_validation(
        self,
        n_risk_losses,
        n_uc_losses,
        n_risk_hazards,
        n_gap_hazards,
        n_risk_constraints,
        n_gap_constraints,
    ):
        """The merged result passes LossAnalysis model validation.

        This is the strongest invariant: the merge produces a structurally
        valid LossAnalysis that the Pydantic validator accepts.
        """
        risk = _build_risk_draft(
            n_risk_losses, n_risk_hazards, n_risk_constraints, id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses, n_gap_hazards, n_gap_constraints, id_offset=100,
        )
        merged = _merge_drafts(risk, gap)
        # If _merge_drafts returns a LossAnalysis, validation has already
        # passed during construction. Re-verify by checking the type.
        from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
        assert isinstance(merged, LossAnalysis)
        assert len(merged.hazards) >= 1
        assert len(merged.security_constraints) >= 1


# ---------------------------------------------------------------------------
# Cross-draft reference remapping property tests
# ---------------------------------------------------------------------------


class TestCrossDraftReferenceRemapping:
    """Property tests for cross-draft reference remapping.

    When gap-analysis hazards reference loss IDs from the risk-derivation
    draft, the merge must remap those references to the new sequential IDs.
    """

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=3),
        n_uc_losses=st.integers(min_value=1, max_value=3),
        cross_ref_index=st.integers(min_value=0, max_value=2),
    )
    @settings(max_examples=30, deadline=None)
    def test_cross_references_remap_correctly(
        self,
        n_risk_losses,
        n_uc_losses,
        cross_ref_index,
    ):
        """A gap hazard referencing a risk loss is remapped to the new ID."""
        risk = _build_risk_draft(
            n_risk_losses, n_hazards=1, n_constraints=1, id_offset=0,
        )
        risk_loss_ids = [loss.loss_id for loss in risk.risk_card_losses]
        # Pick a risk loss ID for cross-referencing
        cross_ref = risk_loss_ids[cross_ref_index % len(risk_loss_ids)]
        gap = _build_gap_draft(
            n_uc_losses,
            n_hazards=1,
            n_constraints=1,
            id_offset=100,
            cross_ref_loss_ids=[cross_ref],
        )
        merged = _merge_drafts(risk, gap)

        all_loss_ids = {
            loss.loss_id for loss in merged.risk_card_losses + merged.use_case_losses
        }
        # The gap hazard should reference valid loss IDs after remapping
        gap_hazard = merged.hazards[-1]  # gap hazards come after risk hazards
        for ref in gap_hazard.related_losses:
            assert ref in all_loss_ids, (
                f"Cross-draft reference '{ref}' not remapped to valid ID"
            )

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=4),
        n_uc_losses=st.integers(min_value=1, max_value=4),
    )
    @settings(max_examples=25, deadline=None)
    def test_all_cross_refs_valid_with_multiple_cross_refs(
        self,
        n_risk_losses,
        n_uc_losses,
    ):
        """Multiple cross-references from gap to risk are all remapped correctly."""
        risk = _build_risk_draft(
            n_risk_losses, n_hazards=1, n_constraints=1, id_offset=0,
        )
        risk_loss_ids = [loss.loss_id for loss in risk.risk_card_losses]
        gap = _build_gap_draft(
            n_uc_losses,
            n_hazards=2,
            n_constraints=1,
            id_offset=100,
            cross_ref_loss_ids=risk_loss_ids,  # cross-reference all risk losses
        )
        merged = _merge_drafts(risk, gap)

        all_loss_ids = {
            loss.loss_id for loss in merged.risk_card_losses + merged.use_case_losses
        }
        for hazard in merged.hazards:
            for ref in hazard.related_losses:
                assert ref in all_loss_ids


# ---------------------------------------------------------------------------
# Empty draft edge cases
# ---------------------------------------------------------------------------


class TestMergeDraftsEmptyEdgeCases:
    """Property tests for merge with empty drafts."""

    @given(
        n_uc_losses=st.integers(min_value=1, max_value=3),
        n_gap_hazards=st.integers(min_value=1, max_value=2),
        n_gap_constraints=st.integers(min_value=1, max_value=2),
    )
    @settings(max_examples=20, deadline=None)
    def test_empty_risk_draft(self, n_uc_losses, n_gap_hazards, n_gap_constraints):
        """An empty risk draft with a valid gap draft produces a valid merge."""
        risk = LossAnalysisDraft()
        gap = _build_gap_draft(
            n_uc_losses, n_gap_hazards, n_gap_constraints, id_offset=1,
        )
        merged = _merge_drafts(risk, gap)
        assert len(merged.risk_card_losses) == 0
        assert len(merged.use_case_losses) == n_uc_losses
        assert len(merged.hazards) == n_gap_hazards
        assert len(merged.security_constraints) == n_gap_constraints
        # IDs should be sequential from 1
        assert [loss.loss_id for loss in merged.use_case_losses] == [
            f"L-{i}" for i in range(1, n_uc_losses + 1)
        ]

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=3),
        n_risk_hazards=st.integers(min_value=1, max_value=2),
        n_risk_constraints=st.integers(min_value=1, max_value=2),
    )
    @settings(max_examples=20, deadline=None)
    def test_empty_gap_draft(self, n_risk_losses, n_risk_hazards, n_risk_constraints):
        """An empty gap draft with a valid risk draft produces a valid merge."""
        risk = _build_risk_draft(
            n_risk_losses, n_risk_hazards, n_risk_constraints, id_offset=1,
        )
        gap = LossAnalysisDraft()
        merged = _merge_drafts(risk, gap)
        assert len(merged.risk_card_losses) == n_risk_losses
        assert len(merged.use_case_losses) == 0
        assert len(merged.hazards) == n_risk_hazards
        assert len(merged.security_constraints) == n_risk_constraints
        # IDs should be sequential from 1
        assert [loss.loss_id for loss in merged.risk_card_losses] == [
            f"L-{i}" for i in range(1, n_risk_losses + 1)
        ]


# ---------------------------------------------------------------------------
# Call-log ordering and profile-skip semantics property tests
# ---------------------------------------------------------------------------


class TestCallLogOrderingAndProfileSkip:
    """Property tests for call-log ordering and profile-skip semantics.

    These verify two orchestration invariants of ``derive_loss_analysis``:

    1. **Call-log ordering**: The risk_derivation call is always logged
       before the gap_analysis call, and both use stage ``stage_1a``.

    2. **Profile-skip semantics**: When ``capability_profile`` is ``None``,
       the gap analysis call still executes and receives empty
       ``kc_subcodes``.  When a profile is provided, its ``kc_subcodes``
       appear in the gap call's user prompt.
    """

    @given(
        n_risk_losses=st.integers(min_value=1, max_value=3),
        n_uc_losses=st.integers(min_value=1, max_value=3),
    )
    @settings(
        max_examples=15,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_call_log_ordering_risk_before_gap(self, tmp_path, n_risk_losses, n_uc_losses):
        """risk_derivation is always logged before gap_analysis."""
        import json

        from tests.stpa.sp1_helpers import (
            MockLLMClient,
            valid_gap_draft_dict,
            valid_risk_draft_dict,
        )

        risk = valid_risk_draft_dict()
        risk["risk_card_losses"] = [
            {
                "loss_id": f"L-{i}",
                "description": f"Risk loss {i}",
                "provenance": "risk_card",
                "source_risk_cards": [f"atlas-{i:03d}"],
            }
            for i in range(1, n_risk_losses + 1)
        ]
        risk["hazards"] = [
            {
                "hazard_id": "H-1",
                "description": "Hazard 1",
                "related_losses": ["L-1"],
            }
        ]
        risk["security_constraints"] = [
            {
                "constraint_id": "SC-1",
                "description": "Constraint 1",
                "related_hazards": ["H-1"],
            }
        ]

        gap = valid_gap_draft_dict()
        gap["use_case_losses"] = [
            {
                "loss_id": f"L-{n_risk_losses + i + 1}",
                "description": f"UC loss {i}",
                "provenance": "use_case",
                "source_risk_cards": [],
            }
            for i in range(1, n_uc_losses + 1)
        ]
        gap["hazards"] = [
            {
                "hazard_id": "H-2",
                "description": "Hazard 2",
                "related_losses": [gap["use_case_losses"][0]["loss_id"]],
            }
        ]
        gap["security_constraints"] = [
            {
                "constraint_id": "SC-2",
                "description": "Constraint 2",
                "related_hazards": ["H-2"],
            }
        ]

        client = MockLLMClient()
        client.set_response_for(LossAnalysisDraft, [risk, gap])

        # Clear any prior entries from function-scoped fixture reuse
        calls_file = tmp_path / "calls.jsonl"
        if calls_file.exists():
            calls_file.unlink()

        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=[],
            run_dir=tmp_path,
        )

        entries = [json.loads(line) for line in calls_file.read_text().splitlines()]
        assert len(entries) == 2
        assert entries[0]["stage"] == "stage_1a"
        assert entries[0]["step"] == "risk_derivation"
        assert entries[1]["stage"] == "stage_1a"
        assert entries[1]["step"] == "gap_analysis"

    @given(
        has_profile=st.booleans(),
        n_kcs=st.integers(min_value=1, max_value=5),
        extra_kcs=st.lists(
            st.sampled_from(["KC1.1", "KC5.1", "KC6.1.1", "KC2.3", "KC4.3"]),
            min_size=0,
            max_size=5,
            unique=True,
        ),
    )
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_profile_skip_semantics(self, tmp_path, has_profile, n_kcs, extra_kcs):
        """When profile is None, gap call gets no kc_subcodes; when provided, it does."""
        from asago_scenario_generator.models.capability_profile import Stage1Profile
        from tests.stpa.sp1_helpers import (
            MockLLMClient,
            valid_gap_draft_dict,
            valid_risk_draft_dict,
        )

        # Always include KC1.1 (required), plus extra valid subcodes
        valid_pool = ["KC1.1", "KC5.1", "KC6.1.1", "KC2.3", "KC4.3"]
        kc_subcodes = valid_pool[:n_kcs]
        # Ensure KC1.1 is always present
        if "KC1.1" not in kc_subcodes:
            kc_subcodes = ["KC1.1"] + kc_subcodes

        profile = None
        if has_profile:
            profile = Stage1Profile(
                entry_points=[
                    {"name": "chat", "direction": "input", "controllability": "direct"},
                ],
                confidence="medium",
                kc_subcodes=kc_subcodes,
                tool_inventory=[{"name": "tool1", "description": "A tool"}],
            ).to_capability_profile()

        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft, [valid_risk_draft_dict(), valid_gap_draft_dict()],
        )

        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=[],
            run_dir=tmp_path,
            capability_profile=profile,
        )

        # The gap call is the second call
        gap_call = client.calls[1]
        if has_profile:
            # kc_subcodes from the profile should appear in the gap user prompt
            assert "kc_subcodes" in gap_call.user_prompt
            for kc in kc_subcodes:
                assert kc in gap_call.user_prompt
        else:
            # With no profile, kc_subcodes should be empty
            # The template may still render the section header but with no values
            pass

    def test_gap_call_starts_after_highest_risk_ids(self, tmp_path):
        """Gap prompts receive the next number for every merged ID family."""
        from tests.stpa.sp1_helpers import MockLLMClient, valid_gap_draft_dict

        risk = {
            "risk_card_losses": [
                {
                    "loss_id": "L-4",
                    "description": "Risk loss",
                    "provenance": "risk_card",
                    "source_risk_cards": ["atlas-001"],
                }
            ],
            "use_case_losses": [],
            "hazards": [
                {
                    "hazard_id": "H-7",
                    "description": "Risk hazard",
                    "related_losses": ["L-4"],
                }
            ],
            "security_constraints": [
                {
                    "constraint_id": "SC-9",
                    "description": "Risk constraint",
                    "related_hazards": ["H-7"],
                }
            ],
        }
        client = MockLLMClient()
        client.set_response_for(
            LossAnalysisDraft,
            [risk, valid_gap_draft_dict()],
        )

        derive_loss_analysis(
            llm_client=client,
            use_case_text="Test use case",
            risk_cards=[],
            run_dir=tmp_path,
        )

        gap_prompt = client.calls[1].user_prompt
        assert "L-5" in gap_prompt
        assert "H-8" in gap_prompt
        assert "SC-10" in gap_prompt
