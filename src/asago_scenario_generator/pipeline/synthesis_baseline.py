"""Synthesis stages up to the ordinary SP1 baseline.

The shared capability profile and snapshot, the closed Phase 1 input graph
and its identity checks, the obligation plan, the neutral briefs, and the
baseline run.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.models.obligation_plan import TaxonomyObligationPlan
from asago_scenario_generator.pipeline.obligation_contracts import (
    RiskCardInput,
    TaxonomyObligationInputs,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    CapabilityFactSnapshot,
    capture_capability_snapshot,
)
from asago_scenario_generator.pipeline.synthesis_types import (
    StageRun,
    SynthesisAdapters,
    SynthesisInputs,
    _systemic_inputs,
)
from asago_scenario_generator.pipeline.synthesis_values import (
    _digest_value,
    _dump,
    _semantic_digest,
)


def _baseline_diagnostics(baseline: Any) -> list[str]:
    """Carry nonfatal baseline findings past later stage-manifest replacement."""
    categories = (
        "stage_warnings",
        "heuristic_errors",
        "heuristic_warnings",
        "solution_neutrality_warnings",
        "post_revision_warnings",
    )
    return [
        f"Baseline {category}: {warning}"
        for category in categories
        for warning in getattr(baseline, category)
    ]


def _baseline_failure_message(baseline: Any) -> str:
    errors = baseline.stage_errors
    if errors:
        return "baseline STPA failed: " + "; ".join(str(error) for error in errors)
    return "baseline STPA adapter must return loss_analysis and control_structure"


def _prepare_capability_profile(
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Resolve the one shared profile through the preparation adapter."""
    if adapters.prepare_capability is None:
        raise ValueError("synthesis requires a capability preparation adapter")
    profile = adapters.prepare_capability(
        model_runtime=adapters.model_runtime,
        inputs=_systemic_inputs(inputs),
        output_dir=inputs.output_dir,
    )
    if profile is None:
        raise ValueError("capability preparation adapter returned no profile")
    if not isinstance(profile, CapabilityProfile):
        raise TypeError(
            "capability preparation adapter must return a CapabilityProfile, "
            f"not {type(profile).__name__}"
        )
    return StageRun(profile, calls=("capability",))


def _prepare_snapshot(
    inputs: SynthesisInputs, profile: CapabilityProfile
) -> CapabilityFactSnapshot:
    """Capture one capability/fact snapshot before planning."""
    return capture_capability_snapshot(
        profile, _evaluated_facts(inputs.qualification_facts)
    )


def _prepare_taxonomy_inputs(
    inputs: SynthesisInputs,
    profile: CapabilityProfile,
    snapshot: CapabilityFactSnapshot,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Obtain a complete typed Phase 1 graph through one adapter."""
    if adapters.build_taxonomy_inputs is None:
        raise ValueError("synthesis requires a taxonomy-input preparation adapter")
    value = adapters.build_taxonomy_inputs(
        inputs=_systemic_inputs(inputs),
        capability_profile=profile,
        capability_snapshot=snapshot,
        risk_cards=inputs.risk_cards,
        qualification_facts=inputs.qualification_facts,
        output_dir=inputs.output_dir,
    )
    if value is None:
        raise ValueError("taxonomy input adapter returned no value")
    if not isinstance(value, TaxonomyObligationInputs):
        raise TypeError(
            "taxonomy input adapter must return TaxonomyObligationInputs, "
            f"not {type(value).__name__}"
        )
    _assert_taxonomy_input_identity(value, inputs, profile, snapshot)
    return StageRun(value, calls=("taxonomy_inputs",))


def _assert_taxonomy_input_identity(
    taxonomy_inputs: TaxonomyObligationInputs,
    inputs: SynthesisInputs,
    profile: CapabilityProfile,
    snapshot: CapabilityFactSnapshot,
) -> None:
    """Reject a Phase 1 graph that silently forks shared run identity.

    The typed contract carries a capability/fact snapshot, reviewed risk
    cards, and qualification facts.  All three are checked before the planner
    is entered.
    """
    taxonomy_snapshot = taxonomy_inputs.capability_snapshot
    if taxonomy_snapshot.snapshot_digest != snapshot.snapshot_digest:
        raise ValueError(
            "taxonomy inputs capability snapshot does not match prepared snapshot"
        )
    if taxonomy_snapshot.profile != profile:
        raise ValueError(
            "taxonomy inputs capability profile does not match prepared profile"
        )

    if _risk_ids(taxonomy_inputs.risk_cards) != _risk_ids(inputs.risk_cards):
        raise ValueError(
            "taxonomy inputs reviewed risk IDs do not match synthesis inputs"
        )
    if _risk_digest(taxonomy_inputs.risk_cards) != _risk_digest(inputs.risk_cards):
        raise ValueError(
            "taxonomy inputs reviewed risk content does not match synthesis inputs"
        )

    if _semantic_digest(taxonomy_inputs.qualification_facts) != _semantic_digest(
        inputs.qualification_facts
    ):
        raise ValueError(
            "taxonomy inputs qualification facts do not match synthesis inputs"
        )


def _risk_ids(cards: tuple[RiskCardInput, ...]) -> tuple[str, ...]:
    """Return reviewed risk identities in deterministic order."""
    return tuple(sorted(card.risk_id for card in cards))


def _risk_digest(cards: tuple[RiskCardInput, ...]) -> str:
    """Digest the complete reviewed-risk tuple, not just IDs."""
    return _digest_value(tuple(sorted(cards, key=lambda card: card.risk_id)))


def _run_plan(
    taxonomy_inputs: Any,
    inputs: SynthesisInputs,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Run Phase 1 before any baseline STPA adapter work."""
    if adapters.plan_obligations is None:
        raise ValueError("synthesis has no Phase 1 planning adapter")
    plan = adapters.plan_obligations(
        taxonomy_inputs=taxonomy_inputs,
        inputs=_systemic_inputs(inputs),
        output_dir=inputs.output_dir,
    )
    if plan is None:
        raise ValueError("Phase 1 planner returned no obligation plan")
    if not isinstance(plan, TaxonomyObligationPlan):
        raise TypeError(
            "Phase 1 planner must return a TaxonomyObligationPlan, "
            f"not {type(plan).__name__}"
        )
    plan.assert_integrity()
    return StageRun(plan, calls=("plan",))


def _build_briefs(
    plan: Any,
    inputs: SynthesisInputs,
    snapshot: Any,
    taxonomy_inputs: Any,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Build exact neutral briefs for applicable obligations."""
    if adapters.build_briefs is None:
        raise ValueError("synthesis has no neutral obligation brief adapter")
    result = adapters.build_briefs(
        plan=plan,
        inputs=_systemic_inputs(inputs),
        capability_snapshot=snapshot,
        taxonomy_inputs=taxonomy_inputs,
    )
    if result is None:
        raise ValueError("neutral obligation brief adapter returned no briefs")
    return StageRun(tuple(result), calls=("briefs",))


def _run_baseline(
    inputs: SynthesisInputs,
    profile: Any,
    snapshot: Any,
    taxonomy_inputs: Any,
    plan: Any,
    prepared_profile_path: Path,
    adapters: SynthesisAdapters,
) -> StageRun:
    """Run ordinary SP1 over the shared profile and reviewed risks."""
    if adapters.baseline is None:
        raise ValueError("synthesis has no baseline STPA adapter")
    baseline_inputs = _systemic_inputs(inputs)
    result = adapters.baseline(
        model_runtime=adapters.model_runtime,
        inputs=baseline_inputs,
        use_case=inputs.use_case,
        risk_cards=inputs.risk_cards,
        capability_profile=profile,
        capability_snapshot=snapshot,
        capability_profile_path=prepared_profile_path,
        taxonomy_inputs=taxonomy_inputs,
        plan=plan,
        output_dir=inputs.output_dir,
        max_workers=inputs.max_workers,
        # SP1 receives the observed target as evidence for Stage 1a and
        # Stage 2.  Adapters without these parameters simply filter them out.
        execution_target_profile=inputs.execution_target_profile,
        target_observations=inputs.target_observations,
    )
    return StageRun(result, calls=("baseline",))


def _fact_items(value: Any) -> tuple[Any, ...]:
    """Extract explicit fact records from typed or serialized input."""
    if value is None:
        return ()
    if isinstance(value, CapabilityFactSnapshot):
        return tuple(value.facts)
    raw = _dump(value)
    if isinstance(raw, Mapping):
        raw = raw.get("facts", ())
    if isinstance(raw, Mapping):
        raw = tuple(raw.values())
    return tuple(raw) if isinstance(raw, (list, tuple)) else ()


def _coerce_evaluated_fact(item: Any) -> Any | None:
    """Convert one profile fact mapping to conservative evidence."""
    if not isinstance(item, Mapping):
        return None
    from asago_scenario_generator.models.attack_pattern_contracts import (
        EvaluatedFactEvidence,
    )

    status = item.get("status", "unknown")
    if status == "contradictory":
        status = "unknown"
    try:
        return EvaluatedFactEvidence.model_validate(
            {"fact": item["fact"], "status": status, "value": item.get("value")}
        )
    except Exception:
        # The typed Phase 1 adapter reports malformed evidence.  The
        # profile-only path remains conservative instead of raising.
        return None


def _evaluated_facts(value: Any) -> tuple[Any, ...]:
    """Adapt explicit qualification values to snapshot evidence models."""
    return tuple(
        fact
        for item in _fact_items(value)
        if (fact := _coerce_evaluated_fact(item)) is not None
    )
