"""Focused public tests for Phase 4 Task 2a graph composition."""

from __future__ import annotations

import pytest

import asago_scenario_generator.models.hybrid_scenario_projection as projection_models
from asago_scenario_generator.models.hybrid_scenario_projection import (
    ArtifactProjectionSourcePin,
    ArtifactPin,
    BridgeLink,
    CausalEdge,
    CausalNode,
    CausalProjection,
    HybridProjectionResolution,
    HybridProjectionUnit,
    HybridScenarioProjection,
    HybridScenarioProjectionSet,
    ProjectionDiagnostic,
    ProjectionExclusion,
    ProjectionTraceReference,
    StpaEndpoint,
)
import asago_scenario_generator.pipeline.hybrid_scenario_projection as projection_pipeline
from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    build_hybrid_scenario_projection_set,
)
from tests.test_hybrid_scenario_projection import _task1_authority_fixture


def test_builder_returns_one_canonical_projection_and_trace() -> None:
    inputs, relation, _candidate = _task1_authority_fixture()

    result = build_hybrid_scenario_projection_set(inputs)

    assert isinstance(result, HybridScenarioProjectionSet)
    assert result.schema_version == "hybrid-scenario-projection-set-v1"
    assert result.evidence_class == "normative_bookkeeping_fixture"
    assert len(result.projections) == 1
    projection = result.projections[0]
    assert projection.relation_id == relation.relation_id
    assert projection.obligation_id == relation.obligation_id
    assert projection.selected_candidate_id == relation.selected_candidate_id
    assert projection.ica_slot_id == relation.ica_slot_id
    assert projection.ica_id == relation.ica_id
    assert projection.exec_candidate_id == relation.exec_candidate_id
    assert projection.bridge_links[0].bridge_kind == "perturbs_control_action"
    assert {trace.source_kind for trace in projection.risk_trace} == {
        "phase1_obligation",
        "phase1_candidate",
        "phase2_relation",
        "stpa_loss",
        "stpa_hazard",
        "stpa_constraint",
        "stpa_slot",
        "stpa_ica",
        "stpa_exec",
        "bridge_evidence",
    }
    assert projection.source_pins
    assert set(projection.source_pins).issubset(set(result.source_pins))
    assert set(projection.model_dump(mode="python")) == {
        "schema_version",
        "projection_id",
        "relation_id",
        "obligation_id",
        "risk_id",
        "attack_pattern_id",
        "selected_candidate_id",
        "ica_slot_id",
        "ica_id",
        "exec_candidate_id",
        "relation_kind",
        "evidence_class",
        "causal_projection",
        "mechanism_projection",
        "bridge_links",
        "confirmed_review",
        "risk_trace",
        "source_pins",
        "semantic_digest",
    }
    result.assert_integrity()


@pytest.mark.parametrize(
    ("bridge_kind", "target_kind", "target_id"),
    (
        ("perturbs_control_action", "control_action", "CA-1-1"),
        ("enables_unsafe_action", "uca", "RESP-1:CA-1-1:WRONG_TIMING"),
        (
            "enables_unsafe_action",
            "ica",
            "RESP-1:CA-1-1:WRONG_TIMING:1",
        ),
        ("realizes_unsafe_outcome", "hazard", "H-1"),
        ("realizes_unsafe_outcome", "loss", "L-1"),
    ),
)
def test_builder_accepts_each_available_fixed_bridge_endpoint(
    bridge_kind: str, target_kind: str, target_id: str
) -> None:
    inputs, _relation, _candidate = _task1_authority_fixture()
    base = inputs.bridge_links[0]
    bridge = BridgeLink.model_validate(
        {
            **base.model_dump(mode="python"),
            "bridge_id": "",
            "semantic_digest": None,
            "bridge_kind": bridge_kind,
            "stpa_endpoint": StpaEndpoint(kind=target_kind, record_id=target_id),
        }
    )

    result = build_hybrid_scenario_projection_set(
        inputs.model_copy(update={"bridge_links": (bridge,)})
    )

    assert len(result.projections) == 1
    assert result.exclusions == ()


def test_reordered_input_authorities_have_identical_output_bytes() -> None:
    inputs, _relation, _candidate = _task1_authority_fixture()

    baseline = build_hybrid_scenario_projection_set(inputs)
    reordered = inputs.model_copy(
        update={
            "requested_relation_ids": tuple(reversed(inputs.requested_relation_ids)),
            "confirmed_reviews": tuple(reversed(inputs.confirmed_reviews)),
            "bridge_links": tuple(reversed(inputs.bridge_links)),
        }
    )

    assert (
        baseline.model_dump_json()
        == build_hybrid_scenario_projection_set(reordered).model_dump_json()
    )
    assert (
        baseline.semantic_digest
        == build_hybrid_scenario_projection_set(reordered).semantic_digest
    )


def test_empty_projection_set_retains_explicit_exclusion() -> None:
    inputs, _relation, _candidate = _task1_authority_fixture()

    result = build_hybrid_scenario_projection_set(
        inputs.model_copy(
            update={"requested_relation_ids": ("correlation:v1:" + "f" * 64,)}
        )
    )

    assert result.projections == ()
    assert len(result.exclusions) == 1
    assert result.exclusions[0].reason == "relation_not_accepted"
    result.assert_integrity()


def test_builder_requires_the_closed_typed_input() -> None:
    with pytest.raises(TypeError, match="HybridProjectionInputs"):
        build_hybrid_scenario_projection_set({})


def test_duplicate_bridge_semantics_are_retained_as_an_exclusion() -> None:
    inputs, _relation, _candidate = _task1_authority_fixture()
    bridge = inputs.bridge_links[0]
    duplicate = BridgeLink.model_validate(
        {
            **bridge.model_dump(mode="python"),
            "bridge_id": "",
            "semantic_digest": None,
            "evidence": (
                {
                    **bridge.evidence[0].model_dump(mode="python"),
                    "evidence_id": "",
                    "semantic_digest": None,
                    "rationale": "same endpoint, second semantic edge",
                },
            ),
        }
    )

    result = build_hybrid_scenario_projection_set(
        inputs.model_copy(update={"bridge_links": (bridge, duplicate)})
    )

    assert result.projections == ()
    assert [item.reason for item in result.exclusions] == ["bridge_duplicate"]


def test_composition_rejects_a_resolved_unit_without_any_bridge(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A unit reaching composition without a bridge remains excluded."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    resolution = projection_pipeline.resolve_hybrid_projection_units(inputs)
    unit = resolution.units[0]
    bridge_free = HybridProjectionUnit.model_validate(
        {
            **unit.model_dump(mode="python"),
            "bridge_links": (),
            "unit_id": "",
            "semantic_digest": None,
        }
    )
    bridge_free_resolution = HybridProjectionResolution(
        assessment_digest=resolution.assessment_digest,
        evidence_class=resolution.evidence_class,
        source_pins=resolution.source_pins,
        units=(bridge_free,),
    )
    monkeypatch.setattr(
        projection_pipeline,
        "resolve_hybrid_projection_units",
        lambda _inputs: bridge_free_resolution,
    )

    result = build_hybrid_scenario_projection_set(inputs)

    assert result.projections == ()
    assert [item.reason for item in result.exclusions] == ["bridge_missing"]


def test_composition_rejects_an_endpoint_with_only_a_matching_kind(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bridge target must match both its namespace kind and exact ID."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    original = projection_pipeline._resolved_bridge_endpoints

    def wrong_id(*args: object, **kwargs: object) -> tuple[object, object]:
        source, target = original(*args, **kwargs)
        return source, (target[0], target[1], target[2] + "-missing")

    monkeypatch.setattr(projection_pipeline, "_resolved_bridge_endpoints", wrong_id)

    result = build_hybrid_scenario_projection_set(inputs)

    assert result.projections == ()
    assert [item.reason for item in result.exclusions] == ["bridge_invalid_endpoint"]


def test_composition_rejects_a_cycle_in_the_union_graph(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cycle introduced at composition remains a typed exclusion."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    original = projection_pipeline._taxonomy_graph

    def cyclic_graph(mechanism: object) -> tuple[object, tuple[object, ...]]:
        nodes, edges = original(mechanism)
        step = nodes[("mechanism_step", "step.1")]
        return nodes, (*edges, (step, step, "synthetic"))

    monkeypatch.setattr(projection_pipeline, "_taxonomy_graph", cyclic_graph)

    result = build_hybrid_scenario_projection_set(inputs)

    assert result.projections == ()
    assert [item.reason for item in result.exclusions] == ["ordering_cycle"]


def test_wrong_fixed_endpoint_is_retained_as_a_typed_exclusion() -> None:
    inputs, _relation, _candidate = _task1_authority_fixture()
    bridge = BridgeLink.model_validate(
        {
            **inputs.bridge_links[0].model_dump(mode="python"),
            "bridge_id": "",
            "semantic_digest": None,
            "stpa_endpoint": StpaEndpoint(kind="hazard", record_id="H-1"),
        }
    )

    result = build_hybrid_scenario_projection_set(
        inputs.model_copy(update={"bridge_links": (bridge,)})
    )

    assert result.projections == ()
    assert result.exclusions[0].reason == "bridge_invalid_endpoint"


def test_control_action_endpoint_does_not_alias_coordination_mechanism(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public builder rejects a control-action-to-CM namespace shortcut."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    resolution = projection_pipeline.resolve_hybrid_projection_units(inputs)
    unit = resolution.units[0]
    causal_payload = unit.causal_projection.model_dump(mode="python")
    node_replacements = {
        "RESP-1": ("CL-1", "coordination_link"),
        "CA-1-1": ("CM-1", "coordination_mechanism"),
    }
    causal_payload["controller_id"] = "CL-1"
    causal_payload["control_action_id"] = "CM-1"
    causal_payload["causal_projection_id"] = ""
    causal_payload["semantic_digest"] = None
    causal_payload["nodes"] = tuple(
        {
            **node,
            "node_id": node_replacements.get(
                node["node_id"], (node["node_id"], node["kind"])
            )[0],
            "kind": node_replacements.get(
                node["node_id"], (node["node_id"], node["kind"])
            )[1],
        }
        for node in causal_payload["nodes"]
    )
    causal_payload["edges"] = tuple(
        {
            **edge,
            "from_node_id": node_replacements.get(
                edge["from_node_id"], (edge["from_node_id"], "")
            )[0],
            "to_node_id": node_replacements.get(
                edge["to_node_id"], (edge["to_node_id"], "")
            )[0],
        }
        for edge in causal_payload["edges"]
    )
    causal = CausalProjection.model_validate(causal_payload)
    bridge = unit.bridge_links[0].model_copy(
        update={
            "stpa_endpoint": StpaEndpoint(kind="control_action", record_id="CM-1"),
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    changed_payload = unit.model_dump(mode="python")
    changed_payload.update(
        {
            "causal_projection": causal,
            "bridge_links": (bridge,),
            "unit_id": "",
            "semantic_digest": None,
        }
    )
    changed = HybridProjectionUnit.model_validate(changed_payload)
    replacement = HybridProjectionResolution(
        assessment_digest=resolution.assessment_digest,
        evidence_class=resolution.evidence_class,
        source_pins=resolution.source_pins,
        units=(changed,),
    )
    monkeypatch.setattr(
        projection_pipeline,
        "resolve_hybrid_projection_units",
        lambda _inputs: replacement,
    )

    result = build_hybrid_scenario_projection_set(inputs)

    assert result.projections == ()
    assert result.exclusions[0].reason == "bridge_invalid_endpoint"


def test_projection_trace_pin_must_be_in_set_pin_closure() -> None:
    """Every unlabelled trace artifact must match a labelled set pin."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(inputs)
    projection = baseline.projections[0]
    unlisted = ArtifactPin(
        artifact_id="trace-only",
        schema_version="trace-only-v1",
        semantic_digest="e" * 64,
    )
    changed = projection.model_copy(
        update={
            "projection_id": "",
            "semantic_digest": None,
            "risk_trace": (
                *projection.risk_trace,
                ProjectionTraceReference(
                    source_kind="phase1_obligation",
                    record_id=projection.obligation_id,
                    artifact_pin=unlisted,
                ),
            ),
        }
    )

    with pytest.raises(ValueError, match="trace artifact pin"):
        HybridScenarioProjectionSet(
            assessment_digest=baseline.assessment_digest,
            source_pins=baseline.source_pins,
            projections=(changed,),
            evidence_class=baseline.evidence_class,
        )


def test_set_integrity_rechecks_tampered_exclusion_identity() -> None:
    """An exclusion copied with changed content cannot pass set integrity."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(
        inputs.model_copy(
            update={"requested_relation_ids": ("correlation:v1:" + "f" * 64,)}
        )
    )
    changed = baseline.exclusions[0].model_copy(update={"reason": "bridge_missing"})
    tampered = baseline.model_copy(update={"exclusions": (changed,)})

    with pytest.raises(ValueError, match="exclusion ID"):
        tampered.assert_integrity()


def test_exclusion_integrity_rejects_short_identity_even_when_relation_matches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The public integrity check rejects a truncated identity independently."""
    baseline = ProjectionExclusion(
        relation_id="correlation:v1:" + "a" * 64,
        unit_identity=(
            "correlation:v1:" + "a" * 64,
            "obligation:v1:" + "b" * 64,
            "candidate:v2:" + "c" * 64,
            "RESP-1:CA-1-1:WRONG_TIMING:1",
            "EXEC:RESP-1:CA-1-1:WRONG_TIMING",
        ),
        reason="bridge_missing",
    )
    malformed = baseline.model_copy(update={"unit_identity": (baseline.relation_id,)})
    monkeypatch.setattr(
        projection_models,
        "_derive_id",
        lambda *_args, **_kwargs: malformed.exclusion_id,
    )

    with pytest.raises(ValueError, match="exclusion unit identity"):
        malformed.assert_integrity()


def test_projection_id_uses_the_independent_identity_domain() -> None:
    """Projection IDs use the versioned identity domain, not semantic hashing."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    result = build_hybrid_scenario_projection_set(inputs)

    assert result.projections[0].projection_id == (
        "projection:v1:2ddba081ba60536ef323669b3dc5b82c30b5c292f73f50c7fcbb905d515c3a45"
    )


def test_set_source_pins_reject_extra_unreferenced_pin() -> None:
    """The set pin collection is an exact closure, not a permissive superset."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(inputs)
    extra = ArtifactProjectionSourcePin.from_artifact_pin(
        ArtifactPin(
            artifact_id="unreferenced",
            schema_version="unreferenced-v1",
            semantic_digest="f" * 64,
        ),
        role="unreferenced",
    )
    tampered = baseline.model_copy(
        update={"source_pins": (*baseline.source_pins, extra)}
    )

    with pytest.raises(ValueError, match="exact source-pin closure"):
        tampered.assert_integrity()


def test_projection_source_pins_reject_role_and_source_digest_conflicts() -> None:
    """The public projection model rejects both pin conflict forms."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(inputs)
    pin = baseline.source_pins[0]
    assert isinstance(pin, ArtifactProjectionSourcePin)

    role_conflict = pin.model_copy(
        update={
            "pin": pin.pin.model_copy(update={"semantic_digest": "0" * 64}),
        }
    )
    with pytest.raises(ValueError, match="identity has conflicting digests"):
        HybridScenarioProjection.model_validate(
            {
                **baseline.projections[0].model_dump(mode="python"),
                "source_pins": (pin, role_conflict),
                "projection_id": "",
                "semantic_digest": None,
            }
        )

    source_conflict = pin.model_copy(
        update={
            "role": "source-conflict",
            "pin": pin.pin.model_copy(update={"semantic_digest": "1" * 64}),
        }
    )
    with pytest.raises(ValueError, match="source identity has conflicting digests"):
        HybridScenarioProjection.model_validate(
            {
                **baseline.projections[0].model_dump(mode="python"),
                "source_pins": (pin, source_conflict),
                "projection_id": "",
                "semantic_digest": None,
            }
        )


def test_nested_bridge_evidence_pin_must_match_set_pin_closure() -> None:
    """Bridge evidence pins are covered even when the projection pin list omits them."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(inputs)
    projection = baseline.projections[0]
    evidence = (
        projection.bridge_links[0]
        .evidence[0]
        .model_copy(
            update={
                "artifact_pin": ArtifactPin(
                    artifact_id="bridge-only",
                    schema_version="bridge-only-v1",
                    semantic_digest="f" * 64,
                ),
                "evidence_id": "",
                "semantic_digest": None,
            }
        )
    )
    bridge = projection.bridge_links[0].model_copy(
        update={"evidence": (evidence,), "bridge_id": "", "semantic_digest": None}
    )
    changed = projection.model_copy(
        update={
            "projection_id": "",
            "semantic_digest": None,
            "bridge_links": (bridge,),
        }
    )

    with pytest.raises(ValueError, match="bridge evidence artifact pin"):
        HybridScenarioProjectionSet(
            assessment_digest=baseline.assessment_digest,
            source_pins=baseline.source_pins,
            projections=(changed,),
            evidence_class=baseline.evidence_class,
        )


def test_set_integrity_rejects_duplicate_exclusion_and_diagnostic_ids() -> None:
    """Set integrity checks every relation-local collection for duplicate IDs."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(
        inputs.model_copy(
            update={"requested_relation_ids": ("correlation:v1:" + "f" * 64,)}
        )
    )
    duplicate_exclusions = baseline.model_copy(
        update={"exclusions": (baseline.exclusions[0], baseline.exclusions[0])}
    )
    with pytest.raises(ValueError, match="exclusion IDs"):
        duplicate_exclusions.assert_integrity()

    diagnostic = ProjectionDiagnostic(kind="bridge_unreviewed")
    duplicate_diagnostics = baseline.model_copy(
        update={"diagnostics": (diagnostic, diagnostic)}
    )
    with pytest.raises(ValueError, match="diagnostic IDs"):
        duplicate_diagnostics.assert_integrity()


def test_public_builder_rejects_unknown_bridge_kind_from_fixed_table(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A bridge kind absent from the fixed table is a local exclusion."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    monkeypatch.delitem(
        projection_pipeline._COMPOSITION_BRIDGE_KINDS,
        "perturbs_control_action",
    )

    result = build_hybrid_scenario_projection_set(inputs)

    assert result.projections == ()
    assert result.exclusions[0].reason == "bridge_invalid_endpoint"


def test_projection_exclusion_and_diagnostic_integrity_recompute_ids() -> None:
    """Relation-local records reject changed content after construction."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(
        inputs.model_copy(
            update={"requested_relation_ids": ("correlation:v1:" + "f" * 64,)}
        )
    )
    changed_exclusion = baseline.exclusions[0].model_copy(
        update={"reason": "bridge_missing"}
    )
    with pytest.raises(ValueError, match="exclusion ID"):
        changed_exclusion.assert_integrity()

    diagnostic = ProjectionDiagnostic(kind="bridge_unreviewed")
    changed_diagnostic = diagnostic.model_copy(
        update={"kind": "bridge_not_authoritative"}
    )
    with pytest.raises(ValueError, match="diagnostic ID"):
        changed_diagnostic.assert_integrity()


def test_set_integrity_rejects_a_relation_in_both_projection_and_exclusion() -> None:
    """One relation cannot be emitted and excluded in the same set."""
    inputs, relation, _candidate = _task1_authority_fixture()
    baseline = build_hybrid_scenario_projection_set(inputs)
    projection = baseline.projections[0]
    exclusion = ProjectionExclusion(
        relation_id=relation.relation_id,
        unit_identity=(
            relation.relation_id,
            projection.obligation_id,
            projection.selected_candidate_id,
            projection.ica_id,
            projection.exec_candidate_id,
        ),
        reason="bridge_missing",
        source_pins=projection.source_pins,
    )
    tampered = baseline.model_copy(update={"exclusions": (exclusion,)})

    with pytest.raises(ValueError, match="projection and exclusion"):
        tampered.assert_integrity()


def test_public_set_integrity_rechecks_each_nested_authority_digest() -> None:
    """Every public authority leaf rejects content tampering after assembly."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    result = build_hybrid_scenario_projection_set(inputs)
    result.assert_integrity()
    unit = projection_pipeline.resolve_hybrid_projection_units(inputs).units[0]
    authorities = (
        inputs.capability_facts,
        result.projections[0].mechanism_projection,
        result.projections[0].causal_projection,
        result.projections[0].confirmed_review,
        unit,
    )

    for authority in authorities:
        authority.assert_integrity()
        tampered = authority.model_copy(update={"semantic_digest": "0" * 64})
        with pytest.raises(ValueError, match="digest"):
            tampered.assert_integrity()


def _composition_variant(
    monkeypatch: pytest.MonkeyPatch,
    *,
    bridge_kind: str,
    target_kind: str,
    target_id: str,
    inserted_kind: str,
    inserted_id: str,
    inserted_ordinal: int,
    inserted_edge: tuple[str, str, str] | None = None,
) -> object:
    """Prepare a public-builder fixture with one extra ordered STPA node."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    resolution = projection_pipeline.resolve_hybrid_projection_units(inputs)
    unit = resolution.units[0]
    payload = unit.causal_projection.model_dump(mode="python")
    payload["causal_projection_id"] = ""
    payload["semantic_digest"] = None
    payload["nodes"] = tuple(
        {
            **node,
            "ordinal": node["ordinal"] + (node["ordinal"] >= inserted_ordinal),
        }
        for node in payload["nodes"]
    ) + (
        CausalNode(
            node_id=inserted_id,
            kind=inserted_kind,
            ordinal=inserted_ordinal,
        ),
    )
    if inserted_edge is not None:
        edge_id, source_id, target_id_for_edge = inserted_edge
        payload["edges"] = (
            *payload["edges"],
            CausalEdge(
                edge_id=edge_id,
                from_node_id=source_id,
                to_node_id=target_id_for_edge,
                kind="causal",
            ),
        )
    causal = projection_pipeline.CausalProjection.model_validate(payload)
    bridge = unit.bridge_links[0].model_copy(
        update={
            "bridge_kind": bridge_kind,
            "stpa_endpoint": StpaEndpoint(kind=target_kind, record_id=target_id),
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    unit_payload = unit.model_dump(mode="python")
    unit_payload.update(
        {
            "causal_projection": causal,
            "bridge_links": (bridge,),
            "unit_id": "",
            "semantic_digest": None,
        }
    )
    changed = HybridProjectionUnit.model_validate(unit_payload)
    replacement = HybridProjectionResolution(
        assessment_digest=resolution.assessment_digest,
        evidence_class=resolution.evidence_class,
        source_pins=resolution.source_pins,
        units=(changed,),
    )
    monkeypatch.setattr(
        projection_pipeline,
        "resolve_hybrid_projection_units",
        lambda _inputs: replacement,
    )
    return inputs


def test_builder_accepts_process_model_bridge_in_authority_order(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A process-model bridge is valid when its target precedes the UCA path."""
    inputs = _composition_variant(
        monkeypatch,
        bridge_kind="corrupts_process_model",
        target_kind="process_model",
        target_id="PM-1-1",
        inserted_kind="process_model",
        inserted_id="PM-1-1",
        inserted_ordinal=3,
        inserted_edge=("edge-pm", "PM-1-1", "RESP-1:CA-1-1:WRONG_TIMING"),
    )

    result = build_hybrid_scenario_projection_set(inputs)

    assert len(result.projections) == 1
    assert result.exclusions == ()


def test_builder_accepts_feedback_bridge_before_control_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A feedback bridge is valid when feedback precedes control descendants."""
    inputs = _composition_variant(
        monkeypatch,
        bridge_kind="delays_feedback",
        target_kind="feedback",
        target_id="FB-1-1",
        inserted_kind="feedback",
        inserted_id="FB-1-1",
        inserted_ordinal=3,
        inserted_edge=("edge-feedback", "FB-1-1", "RESP-1:CA-1-1:WRONG_TIMING"),
    )

    result = build_hybrid_scenario_projection_set(inputs)

    assert len(result.projections) == 1
    assert result.exclusions == ()


def test_builder_rejects_feedback_after_uca_as_ordering_exclusion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A late feedback factor cannot be bridged back into the authority path."""
    inputs = _composition_variant(
        monkeypatch,
        bridge_kind="delays_feedback",
        target_kind="feedback",
        target_id="FB-1-1",
        inserted_kind="feedback",
        inserted_id="FB-1-1",
        inserted_ordinal=6,
    )

    result = build_hybrid_scenario_projection_set(inputs)

    assert result.projections == ()
    assert result.exclusions[0].reason == "ordering_violation"


def test_builder_rejects_dangling_fixed_table_target() -> None:
    """A bridge to an absent endpoint remains a typed exclusion."""
    inputs, _relation, _candidate = _task1_authority_fixture()
    base = inputs.bridge_links[0]
    bridge = BridgeLink.model_validate(
        {
            **base.model_dump(mode="python"),
            "bridge_kind": "delays_feedback",
            "stpa_endpoint": StpaEndpoint(kind="feedback", record_id="FB-missing"),
            "bridge_id": "",
            "semantic_digest": None,
        }
    )

    result = build_hybrid_scenario_projection_set(
        inputs.model_copy(update={"bridge_links": (bridge,)})
    )

    assert result.projections == ()
    assert result.exclusions[0].reason == "bridge_invalid_endpoint"
