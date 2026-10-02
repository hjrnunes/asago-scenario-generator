"""Obligation-aware STPA synthesis seams.

The composition root runs the named stages (initial routing, one bounded
revision, complete recheck, and final ICA filling) through the stage modules
directly.  ``analyze_obligations`` remains a convenience for direct callers
and tests.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.obligation_aware.analysis import (
    ObligationAwareAnalysisResult,
    analyze_obligations,
    run_structural_consideration,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import *  # noqa: F403
from asago_scenario_generator.stpa.obligation_aware.provider import (
    ObligationAwareLLMAdapter,
    adapter_from_synthesis_inputs,
)
from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
    apply_ica_hazard_verification_correction,
    build_ica_hazard_verification_request,
    filter_ica_considerations,
    verify_final_ica_batch,
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
)
from asago_scenario_generator.stpa.obligation_aware.slot_filling import (
    SlotFillRunResult,
    build_synthesis_slot_requests,
    fill_synthesis_slots,
    final_slot_universe,
)


# Friendly alias for direct callers and the composition-root discovery spelling.
build_neutral_obligation_briefs = build_neutral_briefs


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
    "create_obligation_batches",
    "fill_synthesis_slots",
    "final_slot_universe",
    "apply_ica_hazard_verification_correction",
    "build_ica_hazard_verification_request",
    "filter_ica_considerations",
    "revise_structure_once",
    "run_structural_consideration",
    "verify_final_ica_batch",
]
