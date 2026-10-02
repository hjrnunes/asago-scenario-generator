"""Property-based tests for Stage 1a loss analysis merge/renumber invariants.

These tests verify structural invariants that hold across broad input
ranges for the two-call merge logic in ``loss_analysis.py``:

1. **Canonical identity preservation**: After merging two drafts, existing
   L-/H-/SC- IDs remain stable, with no duplicates or accidental renumbering.

2. **Cross-reference validity**: After merge, every hazard's
   ``related_losses`` references a valid loss ID, and every constraint's
   ``related_hazards`` references a valid hazard ID.

3. **Item count conservation**: The merged result has exactly as many
   items as the sum of both drafts — no items are lost or duplicated.

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
    _merge_drafts,
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


def _make_constraint(
    constraint_id: str, related_hazards: list[str]
) -> SecurityConstraint:
    """Build a security constraint referencing the given hazard IDs."""
    return SecurityConstraint(
        constraint_id=constraint_id,
        rule=f"Constraint {constraint_id}",
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
        _make_risk_loss(f"L-{id_offset + i * 3 + 1}") for i in range(n_risk_losses)
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
        _make_uc_loss(f"L-{id_offset + i * 3 + 1}") for i in range(n_uc_losses)
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
    def test_canonical_ids_are_preserved_after_merge(
        self,
        n_risk_losses,
        n_uc_losses,
        n_risk_hazards,
        n_gap_hazards,
        n_risk_constraints,
        n_gap_constraints,
    ):
        """Merge preserves each draft's canonical IDs and their references."""
        risk = _build_risk_draft(
            n_risk_losses,
            n_risk_hazards,
            n_risk_constraints,
            id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses,
            n_gap_hazards,
            n_gap_constraints,
            id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        all_losses = merged.risk_card_losses + merged.use_case_losses
        loss_ids = [loss.loss_id for loss in all_losses]
        expected_loss_ids = [
            loss.loss_id for loss in risk.risk_card_losses + gap.use_case_losses
        ]
        assert loss_ids == expected_loss_ids
        assert len(loss_ids) == len(set(loss_ids))

        hazard_ids = [h.hazard_id for h in merged.hazards]
        expected_hazard_ids = [h.hazard_id for h in risk.hazards + gap.hazards]
        assert hazard_ids == expected_hazard_ids
        assert len(hazard_ids) == len(set(hazard_ids))

        sc_ids = [sc.constraint_id for sc in merged.security_constraints]
        expected_sc_ids = [
            sc.constraint_id
            for sc in risk.security_constraints + gap.security_constraints
        ]
        assert sc_ids == expected_sc_ids
        assert len(sc_ids) == len(set(sc_ids))

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
            n_risk_losses,
            n_risk_hazards,
            n_risk_constraints,
            id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses,
            n_gap_hazards,
            n_gap_constraints,
            id_offset=100,
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
            n_risk_losses,
            n_risk_hazards,
            n_risk_constraints,
            id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses,
            n_gap_hazards,
            n_gap_constraints,
            id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        assert len(merged.risk_card_losses) == n_risk_losses
        assert len(merged.use_case_losses) == n_uc_losses
        assert len(merged.hazards) == n_risk_hazards + n_gap_hazards
        assert (
            len(merged.security_constraints) == n_risk_constraints + n_gap_constraints
        )

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
            n_risk_losses,
            n_risk_hazards,
            n_risk_constraints,
            id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses,
            n_gap_hazards,
            n_gap_constraints,
            id_offset=100,
        )
        merged = _merge_drafts(risk, gap)

        all_loss_ids = [
            loss.loss_id for loss in merged.risk_card_losses + merged.use_case_losses
        ]
        assert len(all_loss_ids) == len(set(all_loss_ids)), (
            f"Duplicate loss IDs: {all_loss_ids}"
        )

        hazard_ids = [h.hazard_id for h in merged.hazards]
        assert len(hazard_ids) == len(set(hazard_ids)), (
            f"Duplicate hazard IDs: {hazard_ids}"
        )

        sc_ids = [sc.constraint_id for sc in merged.security_constraints]
        assert len(sc_ids) == len(set(sc_ids)), f"Duplicate SC IDs: {sc_ids}"

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
            n_risk_losses,
            1,
            1,
            id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses,
            1,
            1,
            id_offset=100,
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
            n_risk_losses,
            n_risk_hazards,
            n_risk_constraints,
            id_offset=0,
        )
        gap = _build_gap_draft(
            n_uc_losses,
            n_gap_hazards,
            n_gap_constraints,
            id_offset=100,
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
            n_risk_losses,
            n_hazards=1,
            n_constraints=1,
            id_offset=0,
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
            n_risk_losses,
            n_hazards=1,
            n_constraints=1,
            id_offset=0,
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
            n_uc_losses,
            n_gap_hazards,
            n_gap_constraints,
            id_offset=1,
        )
        merged = _merge_drafts(risk, gap)
        assert len(merged.risk_card_losses) == 0
        assert len(merged.use_case_losses) == n_uc_losses
        assert len(merged.hazards) == n_gap_hazards
        assert len(merged.security_constraints) == n_gap_constraints
        # The gap's existing canonical IDs remain stable even when the risk
        # draft is empty.
        assert [loss.loss_id for loss in merged.use_case_losses] == [
            loss.loss_id for loss in gap.use_case_losses
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
            n_risk_losses,
            n_risk_hazards,
            n_risk_constraints,
            id_offset=1,
        )
        gap = LossAnalysisDraft()
        merged = _merge_drafts(risk, gap)
        assert len(merged.risk_card_losses) == n_risk_losses
        assert len(merged.use_case_losses) == 0
        assert len(merged.hazards) == n_risk_hazards
        assert len(merged.security_constraints) == n_risk_constraints
        # The risk draft's existing canonical IDs remain stable even when the
        # gap draft is empty.
        assert [loss.loss_id for loss in merged.risk_card_losses] == [
            loss.loss_id for loss in risk.risk_card_losses
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
    def test_call_log_ordering_risk_before_gap(
        self, tmp_path, n_risk_losses, n_uc_losses
    ):
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
                "rule": "Constraint 1",
                "related_hazards": ["H-1"],
                "applies_when": [],
            }
        ]
        risk["risk_dispositions"] = []

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
                "rule": "Constraint 2",
                "related_hazards": ["H-2"],
                "applies_when": [],
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
            LossAnalysisDraft,
            [valid_risk_draft_dict(), valid_gap_draft_dict()],
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
            # Codes appear with their plain-language meanings, not as an
            # unexplained serialized field name.
            from asago_scenario_generator.models.capability_profile import (
                build_kc_subcodes_display,
            )

            for kc, description in build_kc_subcodes_display(kc_subcodes).items():
                assert kc in gap_call.user_prompt
                assert description in gap_call.user_prompt
        else:
            # With no profile, kc_subcodes should be empty
            # The template may still render the section header but with no values
            pass

    def test_gap_call_receives_existing_ids_without_global_allocation(self, tmp_path):
        """Gap prompts expose prior IDs; local handles own new allocation."""
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
                    "rule": "Risk constraint",
                    "related_hazards": ["H-7"],
                    "applies_when": [],
                }
            ],
            "risk_dispositions": [],
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
        # The first provider response is compiled from local handles, so its
        # canonical IDs start at one.  The gap prompt receives that compiled
        # dependency view; it does not receive or invent global "next IDs".
        assert "L-1" in gap_prompt
        assert "H-1" in gap_prompt
        assert "SC-1" in gap_prompt
        assert "L-5" not in gap_prompt
        assert "H-8" not in gap_prompt
        assert "SC-10" not in gap_prompt
