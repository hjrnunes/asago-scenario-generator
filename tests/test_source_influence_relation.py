"""Unit contract for source-influence relation preflight."""

from __future__ import annotations

from copy import deepcopy

from hypothesis import given, settings, strategies as st
import pytest
from asago_scenario_generator.models.attack_pattern import (
    AttackPattern,
    ProjectionSnapshot,
    compute_chain_semantic_digest,
    compute_projection_digest,
)
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.capability_profile import TrustBoundary
from asago_scenario_generator.models.scenario import (
    NarrativeAccessRealization,
    NarrativeLayer,
    NarrativeStep,
)
from asago_scenario_generator.pipeline.generate.actor import (
    Call0Response,
    build_actor_access_provenance,
    validate_actor_access_provenance,
)
from asago_scenario_generator.pipeline.generate.assembly import (
    _build_projection_context,
)
from asago_scenario_generator.pipeline.generate.narrative import (
    _apply_projection_access_realization,
)
from asago_scenario_generator.pipeline.generate.narrative_access import (
    validate_narrative_access_realization,
)
from asago_scenario_generator.pipeline.generate.names import (
    humanize_projection_context,
)
from asago_scenario_generator.pipeline.projection import (
    ProjectionBudget,
    _candidate_v2_id,
    capture_capability_snapshot,
    project_authoritative_candidates,
    validate_projected_candidate,
)
from asago_scenario_generator.pipeline.projection_realizations import (
    _step_links_initial_ingress,
)
from tests.test_projected_candidates import TaxonomyResolver, _pattern, _profile


def _source_pattern(*, declared_source_kind: str | None = None) -> dict:
    raw = deepcopy(_pattern(conditional=False))
    raw["canonical_chain"]["resource_slots"][0][
        "allowed_entry_point_controllability"
    ] = ["indirect"]
    raw["canonical_chain"]["steps"][0]["resource_links"] = []
    link = {
        "slot_id": "source",
        "role": "source_influence",
        "trust_boundary_slot_id": "boundary",
        "target_ingress_slot_id": "ingress",
    }
    if declared_source_kind is not None:
        link["source_identity_kind"] = declared_source_kind
    raw["canonical_chain"]["steps"][1]["resource_links"] = [link]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    return raw


def _project_source_pattern(
    raw: dict,
    profile: CapabilityProfile | None = None,
):
    if profile is None:
        profile = _profile()
        profile = profile.model_copy(
            update={
                "entry_points": [
                    profile.entry_points[0],
                    profile.entry_points[1].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                ]
            }
        )
    snapshot = capture_capability_snapshot(profile)
    resolver = TaxonomyResolver(
        AttackPattern.model_validate(raw).canonical_chain.taxonomy_context
    )
    return project_authoritative_candidates(
        [raw],
        resolver,
        snapshot,
        budget=ProjectionBudget(max_candidates=32),
    )


def test_valid_relation_exposes_one_canonical_source_boundary_target_path() -> None:
    result = _project_source_pattern(
        _source_pattern(declared_source_kind="integration")
    )

    candidate = next(
        item for item in result.candidates if item.ingress_controllability == "indirect"
    )
    context = _build_projection_context(candidate)

    paths = context["source_influence_paths"]
    assert len(paths) == 1
    path = paths[0]
    assert path["source_identity_kind"] == "integration"
    assert path["source_id"].startswith("int:v1:")
    assert path["boundary_id"].startswith("tb:v1:")
    assert path["target_ingress_id"] == candidate.canonical_ingress.entry_point_id
    assert path["boundary_zones"] == "input->reasoning"


def test_source_influence_link_is_an_initial_ingress_activation() -> None:
    pattern = AttackPattern.model_validate(
        _source_pattern(declared_source_kind="integration")
    )
    activation_step = next(
        step
        for step in pattern.canonical_chain.steps
        if any(link.role == "source_influence" for link in step.resource_links)
    )

    assert _step_links_initial_ingress(
        activation_step, pattern.canonical_chain.initial_ingress_slot_id
    )


def test_implicit_ingress_zone_mismatch_is_typed_before_generation() -> None:
    profile = _profile()

    result = _project_source_pattern(
        _source_pattern(declared_source_kind="integration"), profile
    )

    assert result.candidates == ()
    issue = next(
        item
        for item in result.infeasibilities
        if item.code == "source_influence_relation_infeasible"
    )
    assert issue.expected_target_zone == "input"
    assert issue.actual_boundary_zones == "input->reasoning"


def test_humanized_relation_uses_typed_integration_name() -> None:
    base = _profile()
    profile = base.model_copy(
        update={
            "entry_points": [
                base.entry_points[0],
                base.entry_points[1].model_copy(update={"ingress_zone": "reasoning"}),
            ]
        }
    )
    result = _project_source_pattern(
        _source_pattern(declared_source_kind="integration"), profile
    )
    candidate = next(
        item for item in result.candidates if item.ingress_controllability == "indirect"
    )
    context = _build_projection_context(candidate)

    humanized = humanize_projection_context(context, profile)

    assert humanized is not None
    path = humanized["source_influence_paths"][0]
    assert path["source_name"] == profile.external_integrations[0].name


def test_source_kind_mismatch_is_typed_and_never_substituted() -> None:
    result = _project_source_pattern(
        _source_pattern(declared_source_kind="entry_point")
    )

    assert result.candidates == ()
    issues = [
        issue
        for issue in result.infeasibilities
        if issue.code == "source_influence_relation_infeasible"
    ]
    assert issues
    issue = issues[0]
    assert issue.expected_source_kind == "entry_point"
    assert issue.actual_binding_kind == "integration"
    assert issue.source_id.startswith("int:v1:")


def test_boundary_zone_mismatch_is_typed_before_generation() -> None:
    base = _profile()
    profile = base.model_copy(
        update={
            "entry_points": [
                base.entry_points[0],
                base.entry_points[1].model_copy(update={"ingress_zone": "input"}),
            ],
            "trust_boundaries": [
                TrustBoundary(
                    name="input-to-tools",
                    from_zone="input",
                    to_zone="tool_execution",
                    confidence="explicit",
                )
            ],
        }
    )
    result = _project_source_pattern(
        _source_pattern(declared_source_kind="integration"), profile
    )

    assert result.candidates == ()
    issues = [
        issue
        for issue in result.infeasibilities
        if issue.code == "source_influence_relation_infeasible"
    ]
    assert issues
    assert issues[0].expected_target_zone == "input"
    assert issues[0].actual_boundary_zones == "input->tool_execution"
    assert "ingress_zone" in issues[0].guidance


def test_actor_and_narrative_share_projected_typed_integration_provenance() -> None:
    base = _profile()
    profile = base.model_copy(
        update={
            "entry_points": [
                base.entry_points[0],
                base.entry_points[1].model_copy(update={"ingress_zone": "reasoning"}),
            ]
        }
    )
    result = _project_source_pattern(
        _source_pattern(declared_source_kind="integration"), profile
    )
    candidate = next(
        item for item in result.candidates if item.ingress_controllability == "indirect"
    )
    context = _build_projection_context(candidate)
    response = Call0Response(
        actor_type="supply-chain-actor",
        capability_level="intermediate",
        beliefs=["The source is consumed by the agent."],
        desires=["Influence the agent context."],
        intentions=["Poison the upstream source."],
        resources=["A source account"],
        access_class="supply_chain",
        influence_source=None,
        influence_mechanism="poisoning",
        trust_boundary_id=None,
    )
    actor_access = build_actor_access_provenance(
        entry_point_id=candidate.canonical_ingress.entry_point_id,
        ep_controllability=candidate.ingress_controllability,
        actor_type="supply-chain-actor",
        resp=response,
        profile=profile,
        projection_context=context,
    )
    assert actor_access.influence_source_kind == "integration"
    assert (
        actor_access.influence_source_id
        == context["source_influence_paths"][0]["source_id"]
    )
    assert not validate_actor_access_provenance(
        type(
            "Actor", (), {"actor_type": "supply-chain-actor", "access": actor_access}
        )(),
        profile,
    )

    narrative = NarrativeLayer(
        title="Projected",
        summary="Projected",
        entry_point="model output",
        zone_sequence=["input", "reasoning"],
        steps=[
            NarrativeStep(
                step_number=1,
                zone="input",
                action="Influence source",
                effect="Content is ingested",
                projected_step_ids=("step.1",),
            )
        ],
        access_realization=NarrativeAccessRealization(
            initial_entry_point_id="model-selected",
            influence_source="model-selected",
            trust_boundary_id="model-selected",
            responsible_step_number=1,
        ),
    )
    _apply_projection_access_realization(narrative, context)
    assert narrative.access_realization is not None
    assert (
        narrative.access_realization.influence_source_id
        == actor_access.influence_source_id
    )
    assert narrative.access_realization.influence_source_kind == "integration"
    assert not validate_narrative_access_realization(
        narrative,
        type("Actor", (), {"access": actor_access})(),
    )


def test_unreviewed_explicit_boundary_binding_is_quarantined_typed() -> None:
    raw = _source_pattern(declared_source_kind="integration")
    raw["canonical_chain"]["resource_slots"][-1]["allowed_resource_ids"] = [
        "tb:v1:" + "6" * 32
    ]
    raw["canonical_chain"]["semantic_digest"] = compute_chain_semantic_digest(
        raw["canonical_chain"]
    )
    result = _project_source_pattern(raw)

    assert result.candidates == ()
    issue = next(
        item
        for item in result.infeasibilities
        if item.code == "source_influence_relation_infeasible"
    )
    assert issue.boundary_id == "tb:v1:" + "6" * 32
    assert issue.actual_boundary_zones == "unreviewed"
    assert issue.guidance is not None


def test_serialized_candidate_revalidates_derived_relation() -> None:
    base = _profile()
    profile = base.model_copy(
        update={
            "entry_points": [
                base.entry_points[0],
                base.entry_points[1].model_copy(update={"ingress_zone": "reasoning"}),
            ]
        }
    )
    raw = _source_pattern(declared_source_kind="integration")
    result = _project_source_pattern(raw, profile)
    candidate = next(
        item for item in result.candidates if item.ingress_controllability == "indirect"
    )
    forged = candidate.model_dump(mode="json")
    forged_projection = forged["projection"]
    forged_projection["source_influence_paths"][0]["boundary_zones"] = (
        "input->tool_execution"
    )
    forged_projection["projection_digest"] = compute_projection_digest(
        forged_projection
    )
    projection = ProjectionSnapshot.model_validate(forged_projection)
    forged["candidate_id"] = _candidate_v2_id(candidate.pattern_id, projection)

    snapshot = capture_capability_snapshot(profile)
    resolver = TaxonomyResolver(
        AttackPattern.model_validate(raw).canonical_chain.taxonomy_context
    )
    with pytest.raises(ValueError, match="source-influence paths"):
        validate_projected_candidate(
            forged,
            snapshot,
            raw,
            resolver,
            expected_catalog_pin=candidate.projection.catalog_pin,
        )


@given(
    field=st.sampled_from(
        (
            "source_id",
            "boundary_id",
            "target_ingress_id",
            "expected_target_zone",
            "boundary_zones",
        )
    ),
    value=st.text(min_size=1, max_size=40).map(lambda item: f"forged:{item}"),
)
@settings(max_examples=12, deadline=None)
def test_relation_validation_rejects_arbitrary_path_mutations(
    field: str, value: str
) -> None:
    """Self-consistent serialized paths still require authoritative re-derivation."""
    base = _profile()
    profile = base.model_copy(
        update={
            "entry_points": [
                base.entry_points[0],
                base.entry_points[1].model_copy(update={"ingress_zone": "reasoning"}),
            ]
        }
    )
    raw = _source_pattern(declared_source_kind="integration")
    candidate = next(
        item
        for item in _project_source_pattern(raw, profile).candidates
        if item.ingress_controllability == "indirect"
    )
    forged = candidate.model_dump(mode="json")
    forged["projection"]["source_influence_paths"][0][field] = value
    forged["projection"]["projection_digest"] = compute_projection_digest(
        forged["projection"]
    )
    projection = ProjectionSnapshot.model_validate(forged["projection"])
    forged["candidate_id"] = _candidate_v2_id(candidate.pattern_id, projection)

    with pytest.raises(ValueError, match="source-influence paths"):
        validate_projected_candidate(
            forged,
            capture_capability_snapshot(profile),
            raw,
            TaxonomyResolver(
                AttackPattern.model_validate(raw).canonical_chain.taxonomy_context
            ),
            expected_catalog_pin=candidate.projection.catalog_pin,
        )


class TestSourceInfluenceRelationHelpers:
    """Branch-level coverage for _source_influence_relation sub-helpers."""

    @staticmethod
    def _raw_pattern(*, declared_source_kind: str | None = None) -> dict:
        return _source_pattern(declared_source_kind=declared_source_kind)

    @staticmethod
    def _chain(*, declared_source_kind: str | None = None):
        raw = _source_pattern(declared_source_kind=declared_source_kind)
        return AttackPattern.model_validate(raw).canonical_chain

    @staticmethod
    def _snapshot(profile: CapabilityProfile | None = None):
        if profile is None:
            profile = _profile()
            profile = profile.model_copy(
                update={
                    "entry_points": [
                        profile.entry_points[0],
                        profile.entry_points[1].model_copy(
                            update={"ingress_zone": "reasoning"}
                        ),
                    ]
                }
            )
        return capture_capability_snapshot(profile)

    @staticmethod
    def _refs(snapshot):
        from asago_scenario_generator.pipeline.projection import (
            _references_for_kind,
        )

        return (
            _references_for_kind(
                "entry_point",
                snapshot,
                initial_ingress=False,
                attacker_influence_required=False,
            ),
            _references_for_kind(
                "integration",
                snapshot,
                initial_ingress=False,
                attacker_influence_required=False,
            ),
            _references_for_kind(
                "trust_boundary",
                snapshot,
                initial_ingress=False,
                attacker_influence_required=False,
            ),
        )

    def test_source_influence_links_filters_selected_and_role(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_influence_links,
        )

        chain = self._chain(declared_source_kind="integration")
        links = _source_influence_links(chain, {"step.2"})
        assert len(links) == 1
        assert links[0].role == "source_influence"
        assert _source_influence_links(chain, {"step.1"}) == ()
        assert _source_influence_links(chain, {"step.1", "step.2"}) == links

    def test_source_influence_expected_kind_declared(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_influence_expected_kind,
        )

        chain = self._chain(declared_source_kind="integration")
        link = next(
            link
            for step in chain.steps
            for link in step.resource_links
            if link.role == "source_influence"
        )
        assert _source_influence_expected_kind(chain, link) == "integration"

    def test_source_influence_expected_kind_from_slot(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_influence_expected_kind,
        )

        chain = self._chain(declared_source_kind=None)
        link = next(
            link
            for step in chain.steps
            for link in step.resource_links
            if link.role == "source_influence"
        )
        assert _source_influence_expected_kind(chain, link) == "integration"

    def test_source_relation_boundary_present_and_absent(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_relation_boundary,
        )
                

        snapshot = self._snapshot()
        eps, _ints, tbs = self._refs(snapshot)
        boundary = _source_relation_boundary(snapshot, tbs[0])
        assert boundary is not None
        assert boundary.name == "user-to-agent"
        assert _source_relation_boundary(snapshot, eps[0]) is None

    def test_source_identity_kind_detail(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_identity_kind_detail,
        )

        assert (
            _source_identity_kind_detail("integration", "entry_point")
            == "source identity kind does not match the concrete binding"
        )
        assert _source_identity_kind_detail("integration", "integration") is None

    def test_source_binding_kind_detail(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_binding_kind_detail,
        )
        from asago_scenario_generator.models.attack_pattern import (
            ToolResourceReference,
        )

        snapshot = self._snapshot()
        eps, _ints, _tbs = self._refs(snapshot)
        tool = ToolResourceReference(kind="tool", tool_id="tool:v1:" + "0" * 32)
        assert _source_binding_kind_detail(tool) == (
            "source binding is not an entry point or integration"
        )
        assert _source_binding_kind_detail(eps[0]) is None

    def test_source_entry_point_detail_non_entry(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_entry_point_detail,
        )

        snapshot = self._snapshot()
        _eps, ints, _tbs = self._refs(snapshot)
        ingress = snapshot.profile.resolve_entry_point(
            snapshot.profile.entry_points[1].entry_point_id
        )
        assert _source_entry_point_detail(ints[0], ingress, snapshot) is None

    def test_source_entry_point_detail_not_attacker_influenceable(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_entry_point_detail,
        )

        base = _profile()
        output = base.entry_points[0].model_copy(update={"direction": "output"})
        profile = base.model_copy(
            update={
                "entry_points": [output, base.entry_points[1]],
                "zones_active": ["input", "reasoning", "tool_execution"],
            }
        )
        snapshot = self._snapshot(profile)
        eps, _ints, _tbs = self._refs(snapshot)
        # The output-only entry point is not attacker-accessible.
        ingress = snapshot.profile.resolve_entry_point(
            profile.entry_points[1].entry_point_id
        )
        output_ref = next(
            ref for ref in eps if ref.entry_point_id == output.entry_point_id
        )
        assert (
            _source_entry_point_detail(output_ref, ingress, snapshot)
            == "entry-point source is not attacker-influenceable"
        )

    def test_source_entry_point_detail_distinctness(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_entry_point_detail,
        )

        profile = _profile()
        profile = profile.model_copy(
            update={
                "entry_points": [
                    profile.entry_points[0],
                    profile.entry_points[1].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                ]
            }
        )
        snapshot = self._snapshot(profile)
        eps, _ints, _tbs = self._refs(snapshot)
        # Both chat and RAG docs are attacker-accessible; the same reference
        # used as both source and target ingress violates distinctness.
        ingress = snapshot.profile.resolve_entry_point(
            profile.entry_points[1].entry_point_id
        )
        indirect = next(
            ref
            for ref in eps
            if ref.entry_point_id == profile.entry_points[1].entry_point_id
        )
        assert (
            _source_entry_point_detail(indirect, ingress, snapshot)
            == "source entry point must be distinct from target ingress"
        )

    def test_source_entry_point_detail_ok(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_entry_point_detail,
        )

        profile = _profile()
        profile = profile.model_copy(
            update={
                "entry_points": [
                    profile.entry_points[0].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                    profile.entry_points[1].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                ]
            }
        )
        snapshot = self._snapshot(profile)
        eps, _ints, _tbs = self._refs(snapshot)
        chat = next(
            ref
            for ref in eps
            if ref.entry_point_id == profile.entry_points[0].entry_point_id
        )
        ingress = snapshot.profile.resolve_entry_point(
            profile.entry_points[1].entry_point_id
        )
        # chat is a distinct, attacker-accessible source from the target.
        assert _source_entry_point_detail(chat, ingress, snapshot) is None

    def test_source_boundary_detail_cascade(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_boundary_detail,
        )

        snapshot = self._snapshot()
        _eps, _ints, tbs = self._refs(snapshot)
        boundary = snapshot.profile.resolve_trust_boundary(tbs[0].trust_boundary_id)
        assert (
            _source_boundary_detail(None, "input", "t1", "i1")
            == "source-influence boundary is absent from reviewed declarations"
        )
        # The fixture boundary spans input->reasoning.
        assert _source_boundary_detail(boundary, "reasoning", "i1", "i1") is None
        hypothesized_profile = _profile().model_copy(
            update={
                "trust_boundaries": [
                    TrustBoundary(
                        name="user-to-agent",
                        from_zone="input",
                        to_zone="reasoning",
                        confidence="hypothesized",
                    )
                ]
            }
        )
        hypothesized_snapshot = capture_capability_snapshot(hypothesized_profile)
        hypothesized = hypothesized_snapshot.profile.resolve_trust_boundary(
            tbs[0].trust_boundary_id
        )
        assert (
            _source_boundary_detail(hypothesized, "reasoning", "t1", "i1")
            == "source-influence boundary is not a reviewed declaration"
        )
        wrong_zone = boundary.model_copy(update={"to_zone": "tool_execution"})
        assert (
            _source_boundary_detail(wrong_zone, "reasoning", "t1", "i1")
            == "trust-boundary destination zone does not match target ingress"
        )
        assert (
            _source_boundary_detail(boundary, "reasoning", "wrong", "i1")
            == "source-influence target is not the canonical ingress binding"
        )

    def test_source_relation_issue_detail_boundary_wins(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_relation_issue_detail,
        )

        profile = _profile()
        snapshot = self._snapshot(profile)
        eps, ints, tbs = self._refs(snapshot)
        # Kind mismatch AND absent boundary: the boundary cascade wins.
        detail = _source_relation_issue_detail(
            ints[0],
            "integration",
            "entry_point",
            eps[0],
            snapshot,
            None,
            "target-1",
            "ingress-1",
        )
        assert (
            detail == "source-influence boundary is absent from reviewed declarations"
        )

    def test_source_relation_issue_detail_kind_wins_without_boundary_detail(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_relation_issue_detail,
        )

        profile = _profile()
        profile = profile.model_copy(
            update={
                "entry_points": [
                    profile.entry_points[0],
                    profile.entry_points[1].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                ]
            }
        )
        snapshot = self._snapshot(profile)
        eps, ints, tbs = self._refs(snapshot)
        boundary = snapshot.profile.resolve_trust_boundary(tbs[0].trust_boundary_id)
        detail = _source_relation_issue_detail(
            ints[0],
            "integration",
            "entry_point",
            eps[0],
            snapshot,
            boundary,
            eps[0].entry_point_id,
            eps[0].entry_point_id,
        )
        assert detail == "source identity kind does not match the concrete binding"

    def test_source_relation_issue_detail_none(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_relation_issue_detail,
        )

        profile = _profile()
        profile = profile.model_copy(
            update={
                "entry_points": [
                    profile.entry_points[0],
                    profile.entry_points[1].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                ]
            }
        )
        snapshot = self._snapshot(profile)
        eps, ints, tbs = self._refs(snapshot)
        boundary = snapshot.profile.resolve_trust_boundary(tbs[0].trust_boundary_id)
        indirect = next(
            ref
            for ref in eps
            if ref.entry_point_id == profile.entry_points[1].entry_point_id
        )
        chat = next(
            ref
            for ref in eps
            if ref.entry_point_id == profile.entry_points[0].entry_point_id
        )
        assert (
            _source_relation_issue_detail(
                chat,
                "entry_point",
                "entry_point",
                indirect,
                snapshot,
                boundary,
                indirect.entry_point_id,
                indirect.entry_point_id,
            )
            is None
        )

    def test_source_relation_resolution_ok(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_relation_resolution,
        )

        profile = _profile()
        profile = profile.model_copy(
            update={
                "entry_points": [
                    profile.entry_points[0],
                    profile.entry_points[1].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                ]
            }
        )
        snapshot = self._snapshot(profile)
        eps, ints, tbs = self._refs(snapshot)
        chain = self._chain(declared_source_kind="integration")
        link = next(
            link
            for step in chain.steps
            for link in step.resource_links
            if link.role == "source_influence"
        )
        ingress = snapshot.profile.resolve_entry_point(
            profile.entry_points[1].entry_point_id
        )
        indirect = next(
            ref
            for ref in eps
            if ref.entry_point_id == profile.entry_points[1].entry_point_id
        )
        bindings = {
            "ingress": indirect,
            link.slot_id: ints[0],
            str(link.trust_boundary_slot_id): tbs[0],
        }
        paths, issue = _source_relation_resolution(
            "AP-T1-01",
            ingress,
            indirect,
            link,
            chain,
            bindings,
            snapshot,
        )
        assert issue is None
        assert len(paths) == 1
        assert paths[0].source_identity_kind == "integration"
        assert paths[0].target_ingress_id == indirect.entry_point_id

    def test_source_relation_resolution_issue(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_relation_resolution,
        )

        profile = _profile()
        snapshot = self._snapshot(profile)
        eps, ints, tbs = self._refs(snapshot)
        chain = self._chain(declared_source_kind="entry_point")
        link = next(
            link
            for step in chain.steps
            for link in step.resource_links
            if link.role == "source_influence"
        )
        ingress = snapshot.profile.resolve_entry_point(
            profile.entry_points[1].entry_point_id
        )
        bindings = {
            "ingress": eps[1],
            link.slot_id: ints[0],
            str(link.trust_boundary_slot_id): tbs[0],
        }
        paths, issue = _source_relation_resolution(
            "AP-T1-01",
            ingress,
            eps[1],
            link,
            chain,
            bindings,
            snapshot,
        )
        assert paths == ()
        assert issue is not None
        assert issue.expected_source_kind == "entry_point"
        assert issue.actual_binding_kind == "integration"

    def test_source_ingress_relation_guard_direct(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_ingress_relation_guard,
        )

        profile = _profile()
        snapshot = self._snapshot(profile)
        eps, _ints, _tbs = self._refs(snapshot)
        ingress = snapshot.profile.resolve_entry_point(
            profile.entry_points[0].entry_point_id
        )
        assert _source_ingress_relation_guard(
            "AP-T1-01", ingress, eps[0], ("some", "link")
        ) == ((), None)

    def test_source_ingress_relation_guard_missing_and_multi(self):
        from asago_scenario_generator.pipeline.projection import (
            _source_ingress_relation_guard,
        )

        profile = _profile()
        profile = profile.model_copy(
            update={
                "entry_points": [
                    profile.entry_points[0],
                    profile.entry_points[1].model_copy(
                        update={"ingress_zone": "reasoning"}
                    ),
                ]
            }
        )
        snapshot = self._snapshot(profile)
        eps, _ints, _tbs = self._refs(snapshot)
        indirect = next(
            ref
            for ref in eps
            if ref.entry_point_id == profile.entry_points[1].entry_point_id
        )
        ingress = snapshot.profile.resolve_entry_point(
            profile.entry_points[1].entry_point_id
        )
        paths, issue = _source_ingress_relation_guard("AP-T1-01", ingress, indirect, ())
        assert paths == ()
        assert issue is not None
        assert issue.target_ingress_id == indirect.entry_point_id
        paths, issue = _source_ingress_relation_guard(
            "AP-T1-01", ingress, indirect, ("l1", "l2")
        )
        assert paths == ()
        assert issue is not None
        assert "exactly one" in issue.detail
