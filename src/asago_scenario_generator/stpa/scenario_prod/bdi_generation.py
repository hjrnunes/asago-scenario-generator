"""Stage 5 — Dual-BDI scenario specification.

Deterministic defender BDI pre-population from the control structure,
combined LLM call for the causal story + attacker BDI,
and deterministic assembly of the ScenarioSpec.

The implementation lives in the ``stage5`` package; this module is its
public surface.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.causal_factor import CausalEvidenceStatus

from .stage5.generate import (
    FUNCTIONAL_TEST_GAIN as FUNCTIONAL_TEST_GAIN,
    assemble_scenario_spec,
    build_context_bdi_prompts,
    generate_bdi_for_context,
    generate_scenario_id,
    is_bdi_length_retry_exhausted as is_bdi_length_retry_exhausted,
    parse_ica_slot_id,
    populate_defender_bdi,
)
from .stage5.wire import (
    AnalyticalOnlyRouteSelection,
    BDIGenerationResult,
    CausalFactorDeclaration,
    StimulusCategory,
    UnsafeOutcomeDeclaration,
)

__all__ = [
    "AnalyticalOnlyRouteSelection",
    "BDIGenerationResult",
    "CausalEvidenceStatus",
    "CausalFactorDeclaration",
    "StimulusCategory",
    "UnsafeOutcomeDeclaration",
    "populate_defender_bdi",
    "generate_bdi_for_context",
    "build_context_bdi_prompts",
    "assemble_scenario_spec",
    "generate_scenario_id",
    "parse_ica_slot_id",
]
