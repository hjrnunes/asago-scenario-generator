"""Obligation-aware STPA synthesis seams.

The package exposes distinct production stage functions so the composition
root can enforce ordering: initial consideration, one bounded revision,
complete recheck, and final ICA filling.  ``analyze_obligations`` remains a
convenience for direct callers and tests; production orchestration should use
the four named functions.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    NeutralObligationBrief,
    ObligationRoute,
)
from asago_scenario_generator.stpa.obligation_aware.analysis import (
    ObligationAwareAnalysisResult,
    analyze_obligations,
    run_obligation_aware_analysis,
    run_structural_consideration,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import *  # noqa: F403
from asago_scenario_generator.stpa.obligation_aware.contracts import AnalysisControls
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
    adapter_from_synthesis_inputs,
    make_obligation_aware_adapter,
)
from asago_scenario_generator.stpa.obligation_aware.revision import (
    RevisionCompilation,
    RevisionRunResult,
    compile_revision_draft,
    revise_structure_once,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    RoutingRunResult,
    build_neutral_brief,
    build_neutral_briefs,
    create_obligation_batches,
    route_obligations,
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SlotFillRunResult,
    build_synthesis_slot_requests,
    fill_synthesis_slots,
    final_slot_universe,
)


def _provider(kwargs: Mapping[str, Any], *, stage: str) -> Any:
    """Resolve an explicitly supplied adapter or the configured provider."""
    for key in ("adapter", "analysis_adapter", "obligation_aware_adapter"):
        value = kwargs.get(key)
        if value is not None:
            return value
    client = kwargs.get("llm_client")
    controls = kwargs.get("controls")
    inputs = kwargs.get("inputs")
    output_dir = kwargs.get("output_dir")
    if output_dir is None and inputs is not None:
        output_dir = getattr(inputs, "output_dir", Path("output/synthesis"))
    if inputs is not None:
        shared = getattr(inputs, "obligation_adapter", None)
        if shared is not None:
            return shared
    if client is not None:
        if controls is None:
            from asago_scenario_generator.stpa.infra.llm import effective_temperature

            controls = AnalysisControls(
                model_profile=getattr(inputs, "sp2_profile", None)
                or getattr(inputs, "profile", None)
                or "caller-supplied",
                model_name=getattr(client, "model", "caller-supplied"),
                deadline_seconds=300.0,
                temperature=effective_temperature(
                    client,
                    getattr(inputs, "temperature", None),
                ),
                max_batch_size=kwargs.get("max_batch_size") or 8,
            )
        return ObligationAwareLLMAdapter(
            client,
            run_dir=Path(output_dir),
            controls=controls,
            stage_prefix=f"synthesis_obligation_aware_{stage}",
        )
    if inputs is None:
        raise TypeError(
            "an obligation-aware adapter, llm_client, or synthesis inputs are required"
        )
    return adapter_from_synthesis_inputs(
        inputs=inputs,
        output_dir=Path(output_dir),
        controls=controls,
    )


def _briefs(kwargs: Mapping[str, Any]) -> tuple[NeutralObligationBrief, ...]:
    """Resolve exact neutral briefs from direct values or the Phase 1 graph."""
    values = kwargs.get("briefs", kwargs.get("neutral_briefs"))
    if values is not None:
        result = tuple(values)
        if any(not isinstance(item, NeutralObligationBrief) for item in result):
            raise TypeError("briefs must contain NeutralObligationBrief values")
        return tuple(sorted(result, key=lambda item: item.obligation_id))
    plan = kwargs.get("plan", kwargs.get("obligation_plan"))
    catalog = kwargs.get("attack_pattern_catalog", kwargs.get("patterns"))
    if plan is None or catalog is None:
        raise TypeError(
            "briefs or an exact plan and attack-pattern catalog are required"
        )
    return build_neutral_briefs(plan, catalog)


def consider_obligations(adapter: Any | None = None, **kwargs: Any) -> RoutingRunResult:
    """Run only the initial complete structural-routing pass."""
    if adapter is not None:
        kwargs["adapter"] = adapter
    briefs = _briefs(kwargs)
    controls = kwargs.get("controls")
    max_batch_size = kwargs.get("max_batch_size")
    if max_batch_size is None and controls is not None:
        max_batch_size = controls.max_batch_size
    adapter = _provider(kwargs, stage="routing")
    return route_obligations(
        adapter,
        briefs=briefs,
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        slots=kwargs.get("slots"),
        controls=controls,
        max_batch_size=max_batch_size,
        purpose="initial",
    )


def _gap_concepts(values: Sequence[Any]) -> tuple[MissingStructuralConcept, ...]:
    """Normalize route-shaped or concept-shaped upstream gaps."""
    concepts: list[MissingStructuralConcept] = []
    for value in values:
        if isinstance(value, MissingStructuralConcept):
            concepts.append(value)
            continue
        if isinstance(value, ObligationRoute):
            concepts.extend(value.missing_concepts)
            continue
        nested = getattr(value, "missing_concepts", None)
        if nested is not None:
            concepts.extend(nested)
            continue
        raise TypeError(
            "gaps must contain MissingStructuralConcept or ObligationRoute values"
        )
    unique = {concept.gap_id: concept for concept in concepts}
    return tuple(unique[key] for key in sorted(unique))


def revise_structure(adapter: Any | None = None, **kwargs: Any) -> RevisionRunResult:
    """Run exactly one additive revision attempt for all upstream gaps."""
    if adapter is not None:
        kwargs["adapter"] = adapter
    values = kwargs.get("gaps", kwargs.get("upstream_gaps", ()))
    gaps = _gap_concepts(tuple(values))
    trigger_ids = tuple(
        sorted(
            {
                value.obligation_id
                for value in values
                if isinstance(value, MissingStructuralConcept)
                and value.obligation_id is not None
            }
            | {
                route.obligation_id
                for route in values
                if isinstance(route, ObligationRoute)
                and route.disposition == "upstream_gap"
            }
        )
    )
    plan = kwargs.get("plan", kwargs.get("obligation_plan"))
    # A clean pass has no provider-capable revision stage to construct.
    adapter = None if not gaps else _provider(kwargs, stage="revision")
    return revise_structure_once(
        adapter,
        gaps=gaps,
        trigger_obligation_ids=trigger_ids,
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        controls=kwargs.get("controls"),
        plan_digest=None if plan is None else getattr(plan, "semantic_digest", None),
    )


def recheck_obligations(adapter: Any | None = None, **kwargs: Any) -> RoutingRunResult:
    """Run one complete routing pass against the final revised structure."""
    if adapter is not None:
        kwargs["adapter"] = adapter
    briefs = _briefs(kwargs)
    controls = kwargs.get("controls")
    max_batch_size = kwargs.get("max_batch_size")
    if max_batch_size is None and controls is not None:
        max_batch_size = controls.max_batch_size
    adapter = _provider(kwargs, stage="recheck")
    return route_obligations(
        adapter,
        briefs=briefs,
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        slots=kwargs.get("slots"),
        controls=controls,
        max_batch_size=max_batch_size,
        purpose="recheck",
    )


def fill_obligation_aware_icas(
    adapter: Any | None = None, **kwargs: Any
) -> SlotFillRunResult:
    """Fill the final ordinary and coordination slots with routed briefs only."""
    if adapter is not None:
        kwargs["adapter"] = adapter
    briefs = _briefs(kwargs)
    routes = kwargs.get("routes", kwargs.get("final_routes", ()))
    adapter = _provider(kwargs, stage="icas")
    return fill_synthesis_slots(
        adapter,
        briefs=briefs,
        routes=tuple(routes),
        loss_analysis=kwargs["loss_analysis"],
        control_structure=kwargs["control_structure"],
        controls=kwargs.get("controls"),
    )


# Friendly aliases for direct callers and the existing composition-root
# discovery spellings.
build_neutral_obligation_briefs = build_neutral_briefs
consider = consider_obligations
run_consideration = consider_obligations
run_revision = revise_structure
bounded_revision = revise_structure
recheck = recheck_obligations
run_recheck = recheck_obligations
fill_icas = fill_obligation_aware_icas
run_ica_analysis = fill_obligation_aware_icas


__all__ = [
    "ObligationAwareAnalysisResult",
    "ObligationAwareLLMAdapter",
    "RevisionCompilation",
    "RevisionRunResult",
    "RoutingRunResult",
    "SlotFillRunResult",
    "adapter_from_synthesis_inputs",
    "analyze_obligations",
    "build_neutral_brief",
    "build_neutral_briefs",
    "build_neutral_obligation_briefs",
    "build_synthesis_slot_requests",
    "compile_revision_draft",
    "consider",
    "consider_obligations",
    "create_obligation_batches",
    "fill_icas",
    "fill_obligation_aware_icas",
    "fill_synthesis_slots",
    "final_slot_universe",
    "make_obligation_aware_adapter",
    "recheck",
    "recheck_obligations",
    "revise_structure",
    "revise_structure_once",
    "run_ica_analysis",
    "run_obligation_aware_analysis",
    "run_recheck",
    "run_revision",
    "run_structural_consideration",
]
