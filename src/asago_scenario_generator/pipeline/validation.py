"""Compatibility façade for scenario validation passes.

Implementations are grouped by responsibility, while this module retains the
historical import surface used by callers and tests, including private helper
imports resolved through ``__getattr__``.
"""

from __future__ import annotations

from typing import Any

from . import (
    validation_common,
    validation_goal,
    validation_insider,
    validation_parsimony,
    validation_phantom,
    validation_provenance,
    validation_semantic,
    validation_semantic_actions,
    validation_semantic_scope,
    validation_structure,
)
from .validation_insider import (
    InsiderAccessResult,
    InsiderAccessViolation,
    validate_insider_access_floor,
)
from .validation_parsimony import ParsimonyResult, PrunedNode, enforce_parsimony
from .validation_phantom import (
    PhantomViolation,
    ValidationResult,
    validate_phantom_capabilities,
)
from .validation_provenance import (
    BlankLeafResult,
    BlankLeafViolation,
    LeafTechniqueResult,
    LeafTechniqueViolation,
    check_leaf_technique_provenance,
    validate_blank_leaves,
)
from .validation_semantic import (
    check_corpus_claims_applicability,
    check_scenario_semantics,
    validate_scenario_semantics,
    validate_semantic,
)
from .validation_structure import validate_scenario_structure
from .validation_goal import (
    GateLogicResult,
    GateLogicViolation,
    check_goal_narrative_alignment,
    check_seed_mechanism_fidelity,
    validate_gate_logic_consistency,
)

_COMPATIBILITY_MODULES = (
    validation_common,
    validation_phantom,
    validation_insider,
    validation_structure,
    validation_semantic,
    validation_semantic_scope,
    validation_semantic_actions,
    validation_provenance,
    validation_parsimony,
    validation_goal,
)


def __getattr__(name: str) -> Any:
    """Resolve historical helper names from responsibility modules."""
    for module in _COMPATIBILITY_MODULES:
        try:
            return getattr(module, name)
        except AttributeError:
            continue
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = (
    "BlankLeafResult",
    "BlankLeafViolation",
    "GateLogicResult",
    "GateLogicViolation",
    "InsiderAccessResult",
    "InsiderAccessViolation",
    "LeafTechniqueResult",
    "LeafTechniqueViolation",
    "ParsimonyResult",
    "PhantomViolation",
    "PrunedNode",
    "ValidationResult",
    "check_corpus_claims_applicability",
    "check_goal_narrative_alignment",
    "check_leaf_technique_provenance",
    "check_scenario_semantics",
    "check_seed_mechanism_fidelity",
    "enforce_parsimony",
    "validate_blank_leaves",
    "validate_gate_logic_consistency",
    "validate_insider_access_floor",
    "validate_phantom_capabilities",
    "validate_scenario_structure",
    "validate_scenario_semantics",
    "validate_semantic",
)
