"""Correction feedback for rejected Stage 5 drafts."""

from __future__ import annotations

from collections.abc import Sequence
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)
from ..target_observations import TargetObservationSnapshot
from .wire import (
    _CausalSourceChoice,
)


def _normal_validation_retry_feedback(
    context: ScenarioGenerationContext,
    choices: Sequence[_CausalSourceChoice],
    *,
    target_observations: TargetObservationSnapshot | None = None,
) -> str:
    """Describe normal-path field repairs without execution-design codes."""
    observation_refs = (
        [item.observation_ref for item in target_observations.observations]
        if target_observations is not None
        else []
    )
    supplied_records = (
        ", ".join(observation_refs) if observation_refs else "none are supplied"
    )
    return (
        " Correct only the fields identified by the validation error; preserve "
        "the intended unsafe proposition and exact supplied references. "
        "Never copy a sample value or invent a threshold to satisfy the schema.\n"
        "Stable repair codes:\n"
        "- missing_unsafe_proposition: return one nonblank bounded "
        "semantic_proposition sentence describing exactly what makes the "
        "outcome unsafe.\n"
        "- missing_temporal_branch_field: use the explained reference_handle "
        "and fields of that temporal branch; use event ordering for before/after "
        "relationships, not an invented quantitative delay.\n"
        "- incomplete_evidence_status_branch: include evidence_status and only "
        "its supported references or explicit bounded-assumption text.\n"
        "- observation_command_attempt_operation_missing: an observable "
        "command_attempt criterion or safe outcome must name one exact "
        "operation_name from the supplied inventory; if no exact operation "
        "applies, reassess it as analytical_only.\n"
        "- observation_operation_not_in_inventory: replace operation_name with "
        "one exact supplied inventory name, or reassess the entry as "
        "analytical_only; do not rename an operation or invent one.\n"
        "- discriminating_condition_missing: return the condition that "
        "separates unsafe from safe behavior for this executable scenario; "
        "keep observation_criteria and safe_observable_outcome unchanged.\n"
        "- discriminating_condition_check_failed: fix only the listed "
        "comparisons, paths, or references using supplied operation, argument, "
        "and absolute fact names; compare values of the same kind and take "
        "record facts from the selected record or a record one link from it; "
        "select a listed record that the unsafe call "
        "acts on and that meets the comparisons, and set record_selection to "
        "unavailable only if no listed record does. Keep observation_criteria "
        "and safe_observable_outcome unchanged. Never invent a record or "
        "value.\n"
        "- safe_outcome_record_ref_not_supplied: safe_observable_outcome."
        "record_refs lists only top-level supplied observation_ref values "
        f"({supplied_records}); put record and field paths in fact_refs.\n"
        "- safe_outcome_observability_mismatch: set "
        "safe_observable_outcome.observable=true with the claim_level and "
        "evidence of a supported observation criterion when the scenario is "
        "executable, and observable=false with no claim or references when "
        "it is analytical_only.\n"
        "- intention_handle_undeclared: every attacker_bdi intention cites at "
        "least one source_handle that has a declared causal_factors entry; "
        "declare the factor or cite a declared handle.\n"
        "- copied_opaque_identity_mismatch: copy one supplied handle exactly.\n"
        "- mechanism_source_mismatch: choose a mechanism listed in the "
        "selected source's compatible_mechanisms, or use none.\n"
        f"Available causal handles are "
        f"{', '.join(choice.handle for choice in choices)}.\n"
        "Return one complete corrected provider response."
    )
