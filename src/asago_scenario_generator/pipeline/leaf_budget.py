"""Deterministic leaf-budget policy shared by scenario validators.

The budget is a structural validation rule, independent of any scenario
authoring or provider workflow.  Keeping it in this inward leaf prevents
validation and lifecycle code from depending on the retired generation
package.
"""

from __future__ import annotations


def compute_leaf_budget(technique_count: int) -> int:
    """Compute the canonical parsimony leaf budget for an attack tree.

    The formula is ``2 * technique_count + 2`` for a non-empty technique set,
    with a minimum budget of five when no techniques are present.
    """
    return 2 * technique_count + 2 if technique_count > 0 else 5
