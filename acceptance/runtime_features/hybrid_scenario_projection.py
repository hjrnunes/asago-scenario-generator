"""Offline acceptance handlers for the complete Phase 4 projection set."""

from __future__ import annotations

import re
import socket
import tempfile
from copy import deepcopy
from pathlib import Path
from typing import Any, Callable
from unittest.mock import patch

import yaml

from runtime_shared import World

from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
    build_hybrid_scenario_projection_set,
    candidate_materialization_set_from_artifacts,
)
from asago_scenario_generator.pipeline.hybrid_scenario_projection_persistence import (
    read_hybrid_scenario_projection_set,
    write_hybrid_scenario_projection_set,
)


FEATURE_ID = "hybrid_scenario_projection"


def _state(world: World) -> dict[str, Any]:
    """Return isolated state for one complete-projection scenario."""
    state = getattr(world, "hybrid_scenario_projection_state", None)
    if state is None:
        state = {
            "inputs": None,
            "relation": None,
            "candidate": None,
            "result": None,
            "round_trip": None,
            "error": None,
            "network_calls": 0,
            "provider_calls": 0,
        }
        world.hybrid_scenario_projection_state = state
    return state


def _fixture() -> tuple[Any, Any, Any]:
    """Build the complete typed fixture through the established public seam."""
    from tests.test_hybrid_scenario_projection import _task1_authority_fixture

    return _task1_authority_fixture()


def _run_guarded(state: dict[str, Any], operation: Callable[[], Any]) -> Any:
    """Run one operation while making provider and network activity fail closed."""
    state["network_calls"] = 0
    state["provider_calls"] = 0

    def blocked_socket(*_args: Any, **_kwargs: Any) -> None:
        state["network_calls"] += 1
        raise AssertionError("Phase 4 acceptance attempted network activity")

    def blocked_provider(*_args: Any, **_kwargs: Any) -> None:
        state["provider_calls"] += 1
        raise AssertionError("Phase 4 acceptance attempted provider activity")

    from asago_scenario_generator.llm.client import LLMClient as TaxonomyLLMClient
    from asago_scenario_generator.stpa.infra.llm import LLMClient as StpaLLMClient

    with (
        patch.object(socket, "socket", side_effect=blocked_socket),
        patch.object(socket, "create_connection", side_effect=blocked_socket),
        patch.object(TaxonomyLLMClient, "__init__", side_effect=blocked_provider),
        patch.object(StpaLLMClient, "__init__", side_effect=blocked_provider),
    ):
        return operation()


def _execute(world: World, operation: Callable[[], Any]) -> tuple[bool, str]:
    """Execute a public operation and retain expected negative outcomes."""
    state = _state(world)
    state["result"] = None
    state["round_trip"] = None
    state["error"] = None
    try:
        state["result"] = _run_guarded(state, operation)
    except Exception as exc:  # noqa: BLE001 - acceptance checks expected failures
        state["error"] = str(exc)
    return True, ""


def _given_fixture(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Prepare one complete exact authority graph."""
    state = _state(world)
    state["inputs"], state["relation"], state["candidate"] = _fixture()
    return True, ""


def _given_guard(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Reset the observable offline guard counters."""
    state = _state(world)
    state["network_calls"] = 0
    state["provider_calls"] = 0
    return True, ""


def _build(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Build one complete set through the public composition seam."""
    state = _state(world)
    return _execute(
        world, lambda: build_hybrid_scenario_projection_set(state["inputs"])
    )


def _ordered_bridge_resolution(
    inputs: Any,
    *,
    bridge_kind: str,
    target_kind: str,
    target_id: str,
    inserted_kind: str,
    inserted_id: str,
    inserted_ordinal: int,
) -> Any:
    """Create a typed authority variation with a real STPA endpoint node."""
    from asago_scenario_generator.models.hybrid_scenario_projection import (
        CausalEdge,
        CausalNode,
        HybridProjectionResolution,
        HybridProjectionUnit,
    )
    import asago_scenario_generator.pipeline.hybrid_scenario_projection as projection_pipeline

    baseline = projection_pipeline.resolve_hybrid_projection_units(inputs)
    unit = baseline.units[0]
    causal_payload = unit.causal_projection.model_dump(mode="python")
    causal_payload["causal_projection_id"] = ""
    causal_payload["semantic_digest"] = None
    causal_payload["nodes"] = tuple(
        {
            **node,
            "ordinal": node["ordinal"] + (node["ordinal"] >= inserted_ordinal),
        }
        for node in causal_payload["nodes"]
    ) + (
        CausalNode(
            node_id=inserted_id,
            kind=inserted_kind,
            ordinal=inserted_ordinal,
        ),
    )
    causal_payload["edges"] = (
        *causal_payload["edges"],
        CausalEdge(
            edge_id=f"edge-{inserted_kind}",
            from_node_id=inserted_id,
            to_node_id=unit.causal_projection.uca_slot_id,
            kind="causal",
        ),
    )
    causal = type(unit.causal_projection).model_validate(causal_payload)

    bridge_payload = unit.bridge_links[0].model_dump(mode="python")
    bridge_payload.update(
        {
            "bridge_kind": bridge_kind,
            "stpa_endpoint": {
                "kind": target_kind,
                "record_id": target_id,
                "namespace": "stpa",
            },
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    bridge = type(unit.bridge_links[0]).model_validate(bridge_payload)
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
    return HybridProjectionResolution(
        assessment_digest=baseline.assessment_digest,
        evidence_class=baseline.evidence_class,
        source_pins=baseline.source_pins,
        units=(changed,),
        exclusions=baseline.exclusions,
        diagnostics=baseline.diagnostics,
    )


def _dual_ica_resolution(inputs: Any) -> Any:
    """Build a real two-ICA authority variation sharing one EXEC identity."""
    from asago_scenario_generator.models.correspondence import compute_relation_id
    from asago_scenario_generator.models.hybrid_scenario_projection import (
        HybridProjectionResolution,
        HybridProjectionUnit,
    )
    import asago_scenario_generator.pipeline.hybrid_scenario_projection as projection_pipeline

    baseline = projection_pipeline.resolve_hybrid_projection_units(inputs)
    first = baseline.units[0]
    relation = inputs.correspondence.accepted_relations[0]
    second_ica_id = f"{relation.ica_slot_id}:2"
    second_relation_payload = relation.model_dump(mode="python")
    second_relation_payload.update(
        {
            "ica_id": second_ica_id,
            "relation_id": compute_relation_id(
                obligation_id=relation.obligation_id,
                ica_slot_id=relation.ica_slot_id,
                ica_id=second_ica_id,
                exec_candidate_id=relation.exec_candidate_id,
                relation_kind=relation.relation_kind,
                resource_link_ids=relation.resource_link_ids,
            ),
        }
    )
    second_relation = type(relation).model_validate(second_relation_payload)

    causal_payload = first.causal_projection.model_dump(mode="python")
    old_ica_id = first.causal_projection.ica_id
    causal_payload.update(
        {
            "ica_id": second_ica_id,
            "causal_projection_id": "",
            "semantic_digest": None,
            "nodes": tuple(
                {
                    **node,
                    "node_id": (
                        second_ica_id
                        if node["node_id"] == old_ica_id
                        else node["node_id"]
                    ),
                }
                for node in causal_payload["nodes"]
            ),
            "edges": tuple(
                {
                    **edge,
                    "from_node_id": (
                        second_ica_id
                        if edge["from_node_id"] == old_ica_id
                        else edge["from_node_id"]
                    ),
                    "to_node_id": (
                        second_ica_id
                        if edge["to_node_id"] == old_ica_id
                        else edge["to_node_id"]
                    ),
                }
                for edge in causal_payload["edges"]
            ),
        }
    )
    causal = type(first.causal_projection).model_validate(causal_payload)

    review_payload = first.confirmed_review.model_dump(mode="python")
    review_payload.update(
        {"relation_id": second_relation.relation_id, "semantic_digest": None}
    )
    review = type(first.confirmed_review).model_validate(review_payload)

    bridge_payload = first.bridge_links[0].model_dump(mode="python")
    bridge_payload.update(
        {
            "relation_id": second_relation.relation_id,
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    bridge = type(first.bridge_links[0]).model_validate(bridge_payload)

    unit_payload = first.model_dump(mode="python")
    unit_payload.update(
        {
            "relation_id": second_relation.relation_id,
            "ica_id": second_ica_id,
            "causal_projection": causal,
            "confirmed_review": review,
            "bridge_links": (bridge,),
            "unit_id": "",
            "semantic_digest": None,
        }
    )
    second = HybridProjectionUnit.model_validate(unit_payload)
    return HybridProjectionResolution(
        assessment_digest=baseline.assessment_digest,
        evidence_class=baseline.evidence_class,
        source_pins=baseline.source_pins,
        units=(first, second),
        exclusions=baseline.exclusions,
        diagnostics=baseline.diagnostics,
    )


def _dual_ica(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Compose two distinct ICA relations that share one EXEC candidate."""
    state = _state(world)
    import asago_scenario_generator.pipeline.hybrid_scenario_projection as projection_pipeline

    def operation() -> Any:
        resolution = _dual_ica_resolution(state["inputs"])
        with patch.object(
            projection_pipeline,
            "resolve_hybrid_projection_units",
            return_value=resolution,
        ):
            return build_hybrid_scenario_projection_set(state["inputs"])

    return _execute(world, operation)


def _dual_ica_result(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Check that relation and ICA identities remain distinct while EXEC matches."""
    result = _state(world)["result"]
    if result is None or len(result.projections) != 2:
        return False, "two projections are required"
    projections = result.projections
    relations = {item.relation_id for item in projections}
    icas = {item.ica_id for item in projections}
    execs = {item.exec_candidate_id for item in projections}
    return (
        len(relations) == 2 and len(icas) == 2 and len(execs) == 1,
        f"expected two relation/ICA IDs and one EXEC, got {relations}/{icas}/{execs}",
    )


def _exclusion_value(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Validate one exclusion reason through the closed public model."""
    match = re.fullmatch(r'the exclusion reason "([^"]+)" is inspected', text)
    if match is None:
        return False, f"unexpected exclusion inventory step: {text}"
    reason = match.group(1)
    from typing import get_args

    from asago_scenario_generator.models.hybrid_scenario_projection import (
        ExclusionReason,
        ProjectionExclusion,
    )

    relation = _state(world)["relation"]
    if reason not in get_args(ExclusionReason):
        return False, f"unknown closed exclusion reason: {reason}"
    try:
        value = ProjectionExclusion(
            relation_id=relation.relation_id,
            unit_identity=(
                relation.relation_id,
                relation.obligation_id,
                relation.selected_candidate_id,
                relation.ica_id,
                relation.exec_candidate_id,
            ),
            reason=reason,
        )
    except Exception as exc:  # noqa: BLE001 - acceptance reports contract errors
        return False, f"closed exclusion model rejected {reason}: {exc}"
    _state(world)["exclusion_reason"] = value.reason
    return True, ""


def _exclusion_value_result(
    world: World, text: str, _examples: dict
) -> tuple[bool, str]:
    """Check the reason accepted by the typed exclusion model."""
    match = re.fullmatch(
        r"the exclusion reason is accepted by the closed contract", text
    )
    if match is None:
        return False, f"unexpected exclusion result: {text}"
    reason = _state(world).get("exclusion_reason")
    return reason is not None, f"closed exclusion reason was not retained: {reason!r}"


def _exclusion_inventory(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Require the runtime model's closed vocabulary to be complete and exact."""
    from typing import get_args

    from asago_scenario_generator.models.hybrid_scenario_projection import (
        ExclusionReason,
    )

    expected = (
        "relation_not_accepted",
        "relation_not_coverage",
        "relation_unresolved",
        "relation_contradictory",
        "challenge_outcome_not_correspondence",
        "obligation_not_applicable",
        "candidate_materialization_missing",
        "candidate_not_projectable",
        "candidate_binding_mismatch",
        "stpa_identity_missing",
        "stpa_identity_mismatch",
        "resource_link_mismatch",
        "bridge_missing",
        "bridge_unreviewed",
        "bridge_not_authoritative",
        "bridge_invalid_endpoint",
        "bridge_duplicate",
        "ordering_cycle",
        "ordering_violation",
    )
    actual = tuple(
        reason
        for reason in get_args(ExclusionReason)
        if reason != "related_but_not_coverage"
    )
    return actual == expected, f"expected {expected}, got {actual}"


def _exclusion_inventory_result(
    world: World, text: str, _examples: dict
) -> tuple[bool, str]:
    """Check the exact closed exclusion vocabulary assertion."""
    if text != "the closed exclusion vocabulary matches the contract exactly":
        return False, f"unexpected exclusion inventory result: {text}"
    return _exclusion_inventory(world, "", {})


def _nonprojectable_candidate(inputs: Any) -> Any:
    """Return the fixture's concrete retained non-projectable candidate."""
    return next(
        candidate
        for obligation in inputs.obligation_plan.obligations
        for candidate in obligation.candidate_records
        if candidate.projection_disposition != "projectable"
    )


def _mixed_projection_set(inputs: Any) -> Any:
    """Build a valid set containing one projection and one disjoint exclusion."""
    from asago_scenario_generator.models.hybrid_scenario_projection import (
        HybridScenarioProjectionSet,
        ProjectionExclusion,
    )

    baseline = build_hybrid_scenario_projection_set(inputs)
    projection = baseline.projections[0]
    candidate = _nonprojectable_candidate(inputs)
    relation_id = "correlation:v1:" + "9" * 64
    exclusion = ProjectionExclusion(
        relation_id=relation_id,
        unit_identity=(
            relation_id,
            projection.obligation_id,
            candidate.candidate_id,
            projection.ica_id,
            projection.exec_candidate_id,
        ),
        reason="candidate_not_projectable",
        source_pins=projection.source_pins,
    )
    return HybridScenarioProjectionSet(
        assessment_digest=baseline.assessment_digest,
        source_pins=baseline.source_pins,
        projections=baseline.projections,
        exclusions=(exclusion,),
        diagnostics=baseline.diagnostics,
        evidence_class=baseline.evidence_class,
    )


def _related_resource_set(inputs: Any) -> tuple[Any, bytes, bytes]:
    """Build the real Phase 2 association-only relation and project it."""
    from asago_scenario_generator.models.correspondence import (
        AdjudicationSet,
        CorrespondenceAdjudication,
    )
    from asago_scenario_generator.pipeline.correspondence import (
        reconcile_correspondence,
    )
    from asago_scenario_generator.pipeline.hybrid_coverage import (
        assess_hybrid_coverage,
    )
    from asago_scenario_generator.pipeline.hybrid_scenario_projection import (
        build_hybrid_correspondence_attestation,
    )
    from tests.test_hybrid_coverage_assessment import (
        _proposal_set,
        _stpa_input,
        _taxonomy_input,
    )

    proposal_set, candidate = _proposal_set(
        inputs.obligation_plan,
        inputs.resource_map_validation,
        relation_kind="related_but_not_coverage",
    )
    proposal = proposal_set.proposals[0]
    reconciliation = reconcile_correspondence(
        inputs.resource_map_validation,
        proposal_set,
        AdjudicationSet(
            decisions=(
                CorrespondenceAdjudication(
                    proposal_id=proposal.proposal_id,
                    status="confirmed",
                    reason="shared-resource relation only",
                    adjudicated_by="operator-1",
                ),
            )
        ),
    )
    assessment = assess_hybrid_coverage(
        inputs.obligation_plan,
        inputs.resource_map_validation,
        reconciliation,
        _taxonomy_input(inputs.obligation_plan, candidate),
        _stpa_input(),
    )
    assessment_before = assessment.to_yaml()
    attestation = build_hybrid_correspondence_attestation(
        proposal_set, reconciliation, assessment
    )
    relation = attestation.accepted_relations[0]
    related_inputs = inputs.model_copy(
        update={
            "phase2_assessment": assessment,
            "correspondence": attestation,
            "confirmed_reviews": (),
            "bridge_links": (),
            "requested_relation_ids": (relation.relation_id,),
        }
    )
    result = build_hybrid_scenario_projection_set(related_inputs)
    return result, assessment_before, assessment.to_yaml()


def _invalid_document(value: Any, case: str, inputs: Any) -> str:
    """Create one deliberately invalid serialized projection artifact."""
    payload = deepcopy(value.model_dump(mode="json"))
    projection = payload["projections"][0]
    if case == "substituted_candidate":
        projection["selected_candidate_id"] = _nonprojectable_candidate(
            inputs
        ).candidate_id
    elif case == "cross_candidate_binding":
        bindings = projection["mechanism_projection"]["projection"]["bindings"]
        bindings[0]["resource_id"] = "tool:v1:" + "f" * 32
    elif case == "full_source_pin_tamper":
        for record in (payload, *payload["projections"]):
            for pin in record["source_pins"]:
                pin["pin"][
                    "semantic_digest" if pin["kind"] == "artifact" else "digest"
                ] = "f" * 64
    else:  # pragma: no cover - guarded by acceptance tables
        raise ValueError(f"unknown invalid corpus case {case}")
    return yaml.safe_dump(payload, sort_keys=False, allow_unicode=True)


def _mixed_build(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Build the valid mixed set through the public contracts."""
    state = _state(world)
    return _execute(world, lambda: _mixed_projection_set(state["inputs"]))


def _mixed_accounting(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Require complete, disjoint relation accounting for a mixed set."""
    result = _state(world)["result"]
    if result is None:
        return False, f"mixed set failed: {_state(world)['error']}"
    projected = {item.relation_id for item in result.projections}
    excluded = {item.relation_id for item in result.exclusions}
    complete = len(projected | excluded) == 2
    return (
        len(projected) == 1
        and len(excluded) == 1
        and projected.isdisjoint(excluded)
        and complete,
        f"mixed identity accounting failed: {projected}/{excluded}",
    )


def _mixed_round_trip(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Publish and reload the valid mixed set through public persistence."""
    result = _state(world)["result"]
    if result is None:
        return False, "mixed set is unavailable"
    with tempfile.TemporaryDirectory(prefix="asago-phase4-mixed-") as directory:
        path = write_hybrid_scenario_projection_set(Path(directory), result)
        loaded = read_hybrid_scenario_projection_set(path)
    return (
        loaded == result and loaded.to_yaml() == result.to_yaml(),
        "mixed reload changed bytes",
    )


def _corpus_case(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Exercise one adversarial case through public readers/builders."""
    match = re.fullmatch(r'projection corpus case "([^"]+)" is evaluated', text)
    if match is None:
        return False, f"unexpected corpus step: {text}"
    case = match.group(1)
    state = _state(world)
    inputs = state["inputs"]
    phase2_before = inputs.phase2_assessment.to_yaml()
    try:
        if case in {
            "substituted_candidate",
            "cross_candidate_binding",
            "full_source_pin_tamper",
        }:
            baseline = build_hybrid_scenario_projection_set(inputs)
            document = _invalid_document(baseline, case, inputs)
            from asago_scenario_generator.models.hybrid_scenario_projection import (
                HybridScenarioProjectionSet,
            )

            HybridScenarioProjectionSet.from_yaml(document)
            outcome = "accepted_invalid"
        elif case == "nonprojectable_candidate":
            mixed = _mixed_projection_set(inputs)
            outcome = next(item.reason for item in mixed.exclusions)
        elif case == "related_resource_relation":
            related, related_before, related_after = _related_resource_set(inputs)
            outcome = next(item.reason for item in related.exclusions)
            phase2_before = related_before
            state["corpus_phase2_after"] = related_after
        else:
            return False, f"unknown corpus case {case}"
    except Exception:  # expected for deliberately corrupt serialized inputs
        outcome = "fatal"
    state["corpus_outcome"] = outcome
    state["corpus_phase2_before"] = phase2_before
    state.setdefault("corpus_phase2_after", inputs.phase2_assessment.to_yaml())
    return True, ""


def _corpus_outcome(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check one exact adversarial-corpus outcome."""
    match = re.fullmatch(r'the corpus outcome is "([^"]+)"', text)
    if match is None:
        return False, f"unexpected corpus result: {text}"
    actual = _state(world).get("corpus_outcome")
    return actual == match.group(1), f"expected {match.group(1)!r}, got {actual!r}"


def _phase2_unchanged_after_corpus(
    world: World, _text: str, _examples: dict
) -> tuple[bool, str]:
    """Require byte-identical Phase 2 matrices after every adversarial case."""
    state = _state(world)
    return (
        state.get("corpus_phase2_before") == state.get("corpus_phase2_after"),
        "the Phase 2 assessment changed during projection evaluation",
    )


def emit_qa_corpus(output_dir: Path) -> None:
    """Emit valid and corrupt corpus artifacts for an independent subprocess."""
    output_dir.mkdir(parents=True, exist_ok=True)
    inputs, _relation, _candidate = _fixture()
    base_before = inputs.phase2_assessment.to_yaml()
    baseline = build_hybrid_scenario_projection_set(inputs)
    mixed = _mixed_projection_set(inputs)
    related, related_before, related_after = _related_resource_set(inputs)
    write_hybrid_scenario_projection_set(output_dir / "mixed", mixed)
    write_hybrid_scenario_projection_set(output_dir / "related", related)
    for case in (
        "substituted_candidate",
        "cross_candidate_binding",
        "full_source_pin_tamper",
    ):
        (output_dir / f"{case}.yaml").write_text(
            _invalid_document(baseline, case, inputs), encoding="utf-8"
        )
    (output_dir / "phase2-base-before.yaml").write_text(base_before, encoding="utf-8")
    (output_dir / "phase2-base-after.yaml").write_text(
        inputs.phase2_assessment.to_yaml(), encoding="utf-8"
    )
    (output_dir / "phase2-related-before.yaml").write_text(
        related_before, encoding="utf-8"
    )
    (output_dir / "phase2-related-after.yaml").write_text(
        related_after, encoding="utf-8"
    )


def _phase3_history(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Supply a valid Phase 3 history and retain its non-promotion result."""
    state = _state(world)

    def operation() -> Any:
        from asago_scenario_generator.models.challenge_ledger import (
            ChallengeLedgerDiagnostics,
            StpaChallengeLedger,
        )
        from asago_scenario_generator.models.closed_loop_stpa import ClosedLoopStpaRun
        from asago_scenario_generator.models.hybrid_coverage import ArtifactPin

        inputs = state["inputs"]
        assessment_pin = ArtifactPin(
            artifact_id="hybrid-coverage-assessment",
            schema_version=inputs.phase2_assessment.schema_version,
            semantic_digest=inputs.phase2_assessment.semantic_digest,
        )
        plan_pin = ArtifactPin(
            artifact_id="taxonomy-obligation-plan",
            schema_version=inputs.obligation_plan.schema_version,
            semantic_digest=inputs.obligation_plan.semantic_digest,
        )
        ledger = StpaChallengeLedger(
            assessment_pin=assessment_pin,
            source_pins=(assessment_pin, plan_pin, inputs.capability_facts.source_pin),
            challenge_budget=0,
            records=(),
            diagnostics=ChallengeLedgerDiagnostics(
                eligible_targets=0,
                selected_targets=0,
                not_selected_budget=0,
            ),
        )
        history = ClosedLoopStpaRun(ledger=ledger, analysis_opt_in=False)
        baseline = build_hybrid_scenario_projection_set(inputs)
        with_history = build_hybrid_scenario_projection_set(
            inputs.model_copy(update={"closed_loop_run": history})
        )
        return baseline, with_history, history

    return _execute(world, operation)


def _phase3_unchanged(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check that Phase 3 history cannot alter projection/exclusion content."""
    if (
        text
        != "projections and exclusions remain unchanged and no relation is promoted"
    ):
        return False, f"unexpected Phase 3 result: {text}"
    value = _state(world)["result"]
    if not isinstance(value, tuple) or len(value) != 3:
        return False, "Phase 3 history result is unavailable"
    baseline, with_history, _history = value

    def projection_identity(item: Any) -> tuple[str, ...]:
        return (
            item.relation_id,
            item.obligation_id,
            item.selected_candidate_id,
            item.ica_slot_id,
            item.ica_id,
            item.exec_candidate_id,
        )

    baseline_projection_ids = tuple(
        projection_identity(item) for item in baseline.projections
    )
    history_projection_ids = tuple(
        projection_identity(item) for item in with_history.projections
    )

    def exclusion_identity(item: Any) -> tuple[Any, ...]:
        return (item.relation_id, item.unit_identity, item.reason)

    baseline_exclusion_ids = tuple(
        exclusion_identity(item) for item in baseline.exclusions
    )
    history_exclusion_ids = tuple(
        exclusion_identity(item) for item in with_history.exclusions
    )
    return (
        baseline_projection_ids == history_projection_ids
        and baseline_exclusion_ids == history_exclusion_ids
        and tuple(item.relation_id for item in with_history.projections)
        == tuple(item.relation_id for item in baseline.projections),
        "Phase 3 history changed projection or exclusion identities",
    )


def _phase3_changes(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check exact Phase 3 change counters remain zero."""
    match = re.fullmatch(
        r"Phase 3 history records (\d+) correspondence and (\d+) coverage changes",
        text,
    )
    if match is None:
        return False, f"unexpected Phase 3 counter step: {text}"
    value = _state(world)["result"]
    history = value[2] if isinstance(value, tuple) and len(value) == 3 else None
    if history is None:
        return False, "Phase 3 history is unavailable"
    expected = (int(match.group(1)), int(match.group(2)))
    actual = (history.correspondence_changes, history.coverage_changes)
    return actual == expected, f"expected {expected}, got {actual}"


def _compatibility_gate(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Run the existing ordinary compatibility helpers without duplicating them."""
    from runtime_features.taxonomy_obligation_planner import (
        _run_stpa_compatibility,
        _run_taxonomy_compatibility,
    )

    try:
        observations = (
            _run_taxonomy_compatibility(),
            _run_stpa_compatibility(),
        )
    except Exception as exc:  # noqa: BLE001 - preserve existing gate diagnostics
        _state(world)["compatibility"] = False
        _state(world)["compatibility_error"] = str(exc)
        return True, ""
    _state(world)["compatibility"] = all(
        observation["exit_match"] for observation in observations
    )
    _state(world)["compatibility_error"] = ""
    return True, ""


def _compatibility_result(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check compatibility remains covered by the existing gate."""
    expected = 'the existing gate covers the "generate" and "stpa-run" commands without Phase 4 flags'
    if text != expected:
        return False, f"unexpected compatibility result: {text}"
    state = _state(world)
    return bool(state.get("compatibility")), (
        "ordinary compatibility gate is incomplete: "
        + str(state.get("compatibility_error", "no details"))
    )


def _count(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check projection and exclusion counts."""
    match = re.fullmatch(
        r"the projection set has (\d+) projection and (\d+) exclusions", text
    )
    if match is None:
        return False, f"unexpected count step: {text}"
    result = _state(world)["result"]
    if result is None:
        return False, f"projection set was not built: {_state(world)['error']}"
    expected = (int(match.group(1)), int(match.group(2)))
    actual = (len(result.projections), len(result.exclusions))
    return actual == expected, f"expected {expected}, got {actual}"


def _identity(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Require the five exact relation/unit identities to survive composition."""
    state = _state(world)
    result = state["result"]
    relation = state["relation"]
    if result is None or relation is None or len(result.projections) != 1:
        return False, "one exact projection is required"
    projection = result.projections[0]
    actual = (
        projection.relation_id,
        projection.obligation_id,
        projection.selected_candidate_id,
        projection.ica_id,
        projection.exec_candidate_id,
    )
    expected = (
        relation.relation_id,
        relation.obligation_id,
        relation.selected_candidate_id,
        relation.ica_id,
        relation.exec_candidate_id,
    )
    return actual == expected, f"expected {expected}, got {actual}"


def _closed_and_evidence(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Check closed output fields and independent review/mechanism evidence."""
    result = _state(world)["result"]
    if result is None or len(result.projections) != 1:
        return False, "one projection is required"
    projection = result.projections[0]
    forbidden = {
        "score",
        "coverage_rate",
        "readiness",
        "readiness_verdict",
        "admission_status",
        "execution_result",
        "scenario_id",
    }
    payload = result.model_dump(mode="python")
    nested_payload = projection.model_dump(mode="python")
    if forbidden & (set(payload) | set(nested_payload)):
        return False, "projection output contains a forbidden execution/readiness field"
    review = projection.confirmed_review
    bridge_pins = {
        evidence.artifact_pin
        for bridge in projection.bridge_links
        for evidence in bridge.evidence
    }
    independent = review.mechanism_evidence.artifact_pin != review.review_artifact_pin
    independent = independent and not bridge_pins.intersection(
        {review.review_artifact_pin, review.mechanism_evidence.artifact_pin}
    )
    return independent, "review and mechanism evidence are not independent"


def _bridge_variant(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Build with one endpoint-table bridge variant."""
    match = re.fullmatch(
        r'the projection is built with bridge "([^"]+)" to "([^"]+)"', text
    )
    if match is None:
        return False, f"unexpected bridge step: {text}"
    bridge_kind, target_kind = match.groups()
    state = _state(world)
    base = state["inputs"].bridge_links[0]
    target_ids = {
        "control_action": "CA-1-1",
        "uca": "RESP-1:CA-1-1:WRONG_TIMING",
        "ica": "RESP-1:CA-1-1:WRONG_TIMING:1",
        "hazard": "H-1",
        "loss": "L-1",
        "process_model": "PM-1-1",
        "feedback": "FB-1-1",
    }
    if target_kind in {"process_model", "feedback"}:
        resolution = _ordered_bridge_resolution(
            state["inputs"],
            bridge_kind=bridge_kind,
            target_kind=target_kind,
            target_id=target_ids[target_kind],
            inserted_kind=target_kind,
            inserted_id=target_ids[target_kind],
            inserted_ordinal=3,
        )
        import asago_scenario_generator.pipeline.hybrid_scenario_projection as projection_pipeline

        def operation() -> Any:
            with patch.object(
                projection_pipeline,
                "resolve_hybrid_projection_units",
                return_value=resolution,
            ):
                return build_hybrid_scenario_projection_set(state["inputs"])

        return _execute(world, operation)
    bridge_payload = base.model_dump(mode="python")
    bridge_payload.update(
        {
            "bridge_kind": bridge_kind,
            "stpa_endpoint": {
                "kind": target_kind,
                "record_id": target_ids[target_kind],
                "namespace": "stpa",
            },
            "bridge_id": "",
            "semantic_digest": None,
        }
    )
    bridge = type(base).model_validate(bridge_payload)
    return _execute(
        world,
        lambda: build_hybrid_scenario_projection_set(
            state["inputs"].model_copy(update={"bridge_links": (bridge,)})
        ),
    )


def _bridge_outcome(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check the expected result for one endpoint-table example."""
    match = re.fullmatch(r'the bridge outcome is "([^"]+)" with (\d+) projection', text)
    if match is None:
        return False, f"unexpected bridge outcome: {text}"
    outcome, count = match.groups()
    state = _state(world)
    result = state["result"]
    expected_count = int(count)
    actual_count = len(result.projections) if result is not None else 0
    actual_outcome = "projection" if actual_count else "exclusion"
    return (
        actual_outcome == outcome and actual_count == expected_count,
        f"expected {outcome}/{expected_count}, got {actual_outcome}/{actual_count}; {state['error']}",
    )


def _omission(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Create one relation-local omission without changing source authority."""
    match = re.fullmatch(r'the projection request uses omission "([^"]+)"', text)
    if match is None:
        return False, f"unexpected omission step: {text}"
    omission = match.group(1)
    state = _state(world)
    inputs = state["inputs"]

    if omission == "missing_relation":
        altered = inputs.model_copy(
            update={"requested_relation_ids": ("correlation:v1:" + "f" * 64,)}
        )
    elif omission == "missing_review":
        altered = inputs.model_copy(update={"confirmed_reviews": ()})
    elif omission == "missing_materialization":
        from tests.helpers.projection_factory import get_test_snapshot

        empty = candidate_materialization_set_from_artifacts(
            inputs.obligation_plan, (), get_test_snapshot()
        )
        altered = inputs.model_copy(
            update={"candidate_materializations": empty, "bridge_links": ()}
        )
    elif omission == "missing_bridge":
        altered = inputs.model_copy(update={"bridge_links": ()})
    elif omission == "unreviewed_bridge":
        bridge = inputs.bridge_links[0]
        evidence_payload = bridge.evidence[0].model_dump(mode="python")
        evidence_payload.update(
            {
                "evidence_kind": "exact_taxonomy_record",
                "evidence_id": "",
                "semantic_digest": None,
            }
        )
        bridge_payload = bridge.model_dump(mode="python")
        bridge_payload.update(
            {"evidence": (evidence_payload,), "bridge_id": "", "semantic_digest": None}
        )
        altered_bridge = type(bridge).model_validate(bridge_payload)
        altered = inputs.model_copy(update={"bridge_links": (altered_bridge,)})
    elif omission == "unknown_bridge_evidence":
        bridge = inputs.bridge_links[0]
        evidence_payload = bridge.evidence[0].model_dump(mode="python")
        evidence_payload.update(
            {
                "record_id": "unknown-bridge-record",
                "evidence_id": "",
                "semantic_digest": None,
            }
        )
        bridge_payload = bridge.model_dump(mode="python")
        bridge_payload.update(
            {"evidence": (evidence_payload,), "bridge_id": "", "semantic_digest": None}
        )
        altered_bridge = type(bridge).model_validate(bridge_payload)
        altered = inputs.model_copy(update={"bridge_links": (altered_bridge,)})
    elif omission == "wrong_endpoint":
        bridge = inputs.bridge_links[0]
        bridge_payload = bridge.model_dump(mode="python")
        bridge_payload.update(
            {
                "stpa_endpoint": {
                    "kind": "hazard",
                    "record_id": "H-1",
                    "namespace": "stpa",
                },
                "bridge_id": "",
                "semantic_digest": None,
            }
        )
        altered_bridge = type(bridge).model_validate(bridge_payload)
        altered = inputs.model_copy(update={"bridge_links": (altered_bridge,)})
    elif omission == "missing_bridge_endpoint":
        bridge = inputs.bridge_links[0]
        bridge_payload = bridge.model_dump(mode="python")
        bridge_payload.update(
            {
                "bridge_kind": "delays_feedback",
                "stpa_endpoint": {
                    "kind": "feedback",
                    "record_id": "FB-missing",
                    "namespace": "stpa",
                },
                "bridge_id": "",
                "semantic_digest": None,
            }
        )
        altered_bridge = type(bridge).model_validate(bridge_payload)
        altered = inputs.model_copy(update={"bridge_links": (altered_bridge,)})
    else:
        return False, f"unknown acceptance omission {omission}"
    return _execute(world, lambda: build_hybrid_scenario_projection_set(altered))


def _omission_reason(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check the exact typed exclusion reason."""
    match = re.fullmatch(r'the omission is retained as "([^"]+)"', text)
    if match is None:
        return False, f"unexpected omission reason: {text}"
    result = _state(world)["result"]
    actual = result.exclusions[0].reason if result and result.exclusions else None
    return actual == match.group(1), f"expected {match.group(1)!r}, got {actual!r}"


def _round_trip(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Publish and reload the exact canonical artifact."""
    state = _state(world)

    def operation() -> Any:
        result = build_hybrid_scenario_projection_set(state["inputs"])
        with tempfile.TemporaryDirectory(
            prefix="asago-phase4-acceptance-"
        ) as directory:
            path = write_hybrid_scenario_projection_set(Path(directory), result)
            loaded = read_hybrid_scenario_projection_set(path)
            return result.to_yaml() == loaded.to_yaml() and loaded == result

    return _execute(world, operation)


def _committed_round_trip(
    world: World, _text: str, _examples: dict
) -> tuple[bool, str]:
    """Load the committed artifact, then publish and reload it atomically."""
    fixture_path = (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "fixtures"
        / "hybrid-scenario-projection-set.yaml"
    )

    def operation() -> Any:
        source_bytes = fixture_path.read_bytes()
        source = read_hybrid_scenario_projection_set(fixture_path)
        with tempfile.TemporaryDirectory(
            prefix="asago-phase4-acceptance-"
        ) as directory:
            target = write_hybrid_scenario_projection_set(Path(directory), source)
            reloaded = read_hybrid_scenario_projection_set(target)
            return {
                "source": source,
                "target": target,
                "source_bytes": source_bytes,
                "target_bytes": target.read_bytes(),
                "reloaded": reloaded,
            }

    return _execute(world, operation)


def _committed_round_trip_result(
    world: World, text: str, _examples: dict
) -> tuple[bool, str]:
    """Require exact filename, bytes, digest, and bookkeeping evidence label."""
    match = re.fullmatch(
        r'the committed artifact round-trip has filename "([^"]+)" and evidence class "([^"]+)"',
        text,
    )
    if match is None:
        return False, f"unexpected committed round-trip step: {text}"
    expected_name, expected_class = match.groups()
    round_trip = _state(world)["result"]
    if not isinstance(round_trip, dict):
        return False, f"committed round-trip failed: {_state(world)['error']}"
    source = round_trip["source"]
    reloaded = round_trip["reloaded"]
    actual = (
        round_trip["target"].name,
        reloaded.evidence_class,
        round_trip["source_bytes"] == round_trip["target_bytes"],
        source.semantic_digest == reloaded.semantic_digest,
        source == reloaded,
    )
    expected = (expected_name, expected_class, True, True, True)
    return actual == expected, f"expected {expected}, got {actual}"


def _round_trip_result(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check canonical artifact filename, class, and round-trip result."""
    match = re.fullmatch(
        r'the persisted artifact is "([^"]+)" and evidence class is "([^"]+)"', text
    )
    if match is None:
        return False, f"unexpected round-trip result: {text}"
    name, evidence_class = match.groups()
    result = _state(world)["result"]
    if result is not True:
        return False, f"round trip failed: {_state(world)['error']}"
    state = _state(world)
    if state["inputs"] is None:
        return False, "fixture was not prepared"
    built = build_hybrid_scenario_projection_set(state["inputs"])
    return (
        name == "hybrid-scenario-projection-set.yaml"
        and built.evidence_class == evidence_class
        and evidence_class == "normative_bookkeeping_fixture",
        "artifact name/class did not match the normative contract",
    )


def _reordered(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Build reordered authorities and retain the baseline for comparison."""
    state = _state(world)
    baseline = build_hybrid_scenario_projection_set(state["inputs"])
    reordered = state["inputs"].model_copy(
        update={
            "requested_relation_ids": tuple(
                reversed(state["inputs"].requested_relation_ids)
            ),
            "confirmed_reviews": tuple(reversed(state["inputs"].confirmed_reviews)),
            "bridge_links": tuple(reversed(state["inputs"].bridge_links)),
        }
    )
    result = _run_guarded(
        state, lambda: build_hybrid_scenario_projection_set(reordered)
    )
    state["result"] = (baseline, result)
    return True, ""


def _same_canonical(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Check canonical bytes and semantic digest are order independent."""
    pair = _state(world)["result"]
    if not isinstance(pair, tuple) or len(pair) != 2:
        return False, "reordered results are unavailable"
    first, second = pair
    return (
        first.to_yaml() == second.to_yaml()
        and first.semantic_digest == second.semantic_digest,
        "reordered inputs changed canonical output",
    )


def _tampered_plan(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Attempt to use a tampered top-level plan digest."""
    state = _state(world)
    altered_plan = state["inputs"].obligation_plan.model_copy(
        update={"semantic_digest": "f" * 64}
    )
    altered = state["inputs"].model_copy(update={"obligation_plan": altered_plan})
    return _execute(world, lambda: build_hybrid_scenario_projection_set(altered))


def _error(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check the exact fatal diagnostic fragment."""
    match = re.fullmatch(r'the projection operation fails with "([^"]+)"', text)
    if match is None:
        return False, f"unexpected error step: {text}"
    actual = _state(world)["error"] or ""
    return match.group(1) in actual, f"expected {match.group(1)!r} in {actual!r}"


def _offline(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check that the guarded run performed no external calls."""
    match = re.fullmatch(
        r"the offline guard records (\d+) network calls and (\d+) provider calls", text
    )
    if match is None:
        return False, f"unexpected guard step: {text}"
    expected = (int(match.group(1)), int(match.group(2)))
    state = _state(world)
    actual = (state["network_calls"], state["provider_calls"])
    return actual == expected, f"expected {expected}, got {actual}"


def _normative(world: World, _text: str, _examples: dict) -> tuple[bool, str]:
    """Load the committed fixture and retain it for the next assertion."""
    path = (
        Path(__file__).resolve().parents[2]
        / "tests"
        / "fixtures"
        / "hybrid-scenario-projection-set.yaml"
    )
    state = _state(world)
    try:
        state["result"] = read_hybrid_scenario_projection_set(path.resolve())
    except Exception as exc:  # noqa: BLE001 - expected acceptance diagnostic
        state["error"] = str(exc)
    return True, ""


def _normative_result(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Ensure the fixture is bookkeeping evidence, never semantic truth."""
    match = re.fullmatch(
        r'the fixture is labelled "([^"]+)" and semantic claims are "([^"]+)"', text
    )
    if match is None:
        return False, f"unexpected normative step: {text}"
    label, claims = match.groups()
    result = _state(world)["result"]
    actual_claims = (
        "not_allowed"
        if result and result.evidence_class == "normative_bookkeeping_fixture"
        else "allowed"
    )
    return (
        label == "normative_bookkeeping_fixture" and claims == actual_claims,
        "normative fixture was treated as semantic evidence",
    )


def _malformed_graph(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Exercise the public closed causal graph parser's failure paths."""
    match = re.fullmatch(r'the causal graph contains a "([^"]+)" failure', text)
    if match is None:
        return False, f"unexpected graph step: {text}"
    failure = match.group(1)
    state = _state(world)
    causal = state["inputs"].stpa_projection_authority.projections[0]
    payload = causal.model_dump(mode="python")
    if failure == "duplicate":
        payload["edges"] = (*payload["edges"], payload["edges"][0])
    elif failure in {"cycle", "dangling", "order"}:
        edge = dict(payload["edges"][0])
        edge["edge_id"] = "edge-bad"
        if failure == "cycle":
            edge.update(
                {
                    "from_node_id": payload["nodes"][-1]["node_id"],
                    "to_node_id": payload["nodes"][0]["node_id"],
                }
            )
        elif failure == "dangling":
            edge.update(
                {
                    "from_node_id": "missing-node",
                    "to_node_id": payload["nodes"][0]["node_id"],
                }
            )
        else:
            edge.update(
                {
                    "from_node_id": payload["nodes"][1]["node_id"],
                    "to_node_id": payload["nodes"][0]["node_id"],
                }
            )
        payload["edges"] = (*payload["edges"], edge)
    else:
        return False, f"unknown graph failure {failure}"
    try:
        from asago_scenario_generator.models.hybrid_scenario_projection import (
            CausalProjection,
        )

        CausalProjection.model_validate(payload)
    except Exception as exc:  # noqa: BLE001 - expected parser failure
        state["error"] = str(exc)
    else:
        state["error"] = "graph unexpectedly accepted"
    return True, ""


def _graph_error(world: World, text: str, _examples: dict) -> tuple[bool, str]:
    """Check a malformed graph failure was rejected."""
    match = re.fullmatch(r'the graph parser reports "([^"]+)"', text)
    if match is None:
        return False, f"unexpected graph error: {text}"
    actual = _state(world)["error"] or ""
    return match.group(1) in actual, f"expected {match.group(1)!r} in {actual!r}"


def register(api: object) -> None:
    """Register complete-projection acceptance handlers."""
    registrations = (
        (
            r"^a complete typed hybrid projection authority fixture is available$",
            _given_fixture,
        ),
        (
            r"^the complete projection path has an offline provider and network guard$",
            _given_guard,
        ),
        (r"^the complete projection set is built$", _build),
        (r"^the projection set has \d+ projection and \d+ exclusions$", _count),
        (r"^the projection retains the exact five-part relation identity$", _identity),
        (
            r"^two accepted ICA identities sharing one EXEC are composed$",
            _dual_ica,
        ),
        (
            r"^the result contains two distinct relation and ICA identities sharing one EXEC$",
            _dual_ica_result,
        ),
        (
            r"^the projection has closed fields and independent review evidence$",
            _closed_and_evidence,
        ),
        (r'^the projection is built with bridge "[^"]+" to "[^"]+"$', _bridge_variant),
        (r'^the bridge outcome is "[^"]+" with \d+ projection$', _bridge_outcome),
        (r'^the projection request uses omission "[^"]+"$', _omission),
        (r'^the omission is retained as "[^"]+"$', _omission_reason),
        (
            r'^the exclusion reason "[^"]+" is inspected$',
            _exclusion_value,
        ),
        (
            r"^the exclusion reason is accepted by the closed contract$",
            _exclusion_value_result,
        ),
        (
            r"^the closed exclusion reason inventory is inspected$",
            _exclusion_inventory,
        ),
        (
            r"^the closed exclusion vocabulary matches the contract exactly$",
            _exclusion_inventory_result,
        ),
        (
            r"^a mixed projection and exclusion set is built through public contracts$",
            _mixed_build,
        ),
        (
            r"^one projection and one distinct exclusion account for two relation identities$",
            _mixed_accounting,
        ),
        (
            r"^the mixed set survives canonical publication and reload$",
            _mixed_round_trip,
        ),
        (r'^projection corpus case "[^"]+" is evaluated$', _corpus_case),
        (r'^the corpus outcome is "[^"]+"$', _corpus_outcome),
        (
            r"^the Phase 2 matrices remain byte-identical$",
            _phase2_unchanged_after_corpus,
        ),
        (
            r"^a Phase 3 challenge history is supplied$",
            _phase3_history,
        ),
        (
            r"^projections and exclusions remain unchanged and no relation is promoted$",
            _phase3_unchanged,
        ),
        (
            r"^Phase 3 history records \d+ correspondence and \d+ coverage changes$",
            _phase3_changes,
        ),
        (
            r"^the existing ordinary workflow compatibility gate is inspected$",
            _compatibility_gate,
        ),
        (
            r'^the existing gate covers the "generate" and "stpa-run" commands without Phase 4 flags$',
            _compatibility_result,
        ),
        (r"^the projection set is published and reloaded atomically$", _round_trip),
        (
            r"^the committed projection artifact is loaded and published atomically$",
            _committed_round_trip,
        ),
        (
            r'^the committed artifact round-trip has filename "[^"]+" and evidence class "[^"]+"$',
            _committed_round_trip_result,
        ),
        (
            r'^the persisted artifact is "[^"]+" and evidence class is "[^"]+"$',
            _round_trip_result,
        ),
        (r"^reordered projection authorities are built$", _reordered),
        (
            r"^the reordered projection set has identical canonical bytes and digest$",
            _same_canonical,
        ),
        (r"^the projection request uses a tampered source plan$", _tampered_plan),
        (r'^the projection operation fails with "[^"]+"$', _error),
        (
            r"^the offline guard records \d+ network calls and \d+ provider calls$",
            _offline,
        ),
        (r"^the committed normative projection fixture is loaded$", _normative),
        (
            r'^the fixture is labelled "[^"]+" and semantic claims are "[^"]+"$',
            _normative_result,
        ),
        (r'^the causal graph contains a "[^"]+" failure$', _malformed_graph),
        (r'^the graph parser reports "[^"]+"$', _graph_error),
    )
    for pattern, handler in registrations:
        api.register(pattern, handler)


__all__ = ["FEATURE_ID", "emit_qa_corpus", "register"]
