"""Keep literal provenance distinct from the model's interpretation of a rule.

Exact quotation checks establish source presence, not that a comparison faithfully
interprets a policy. The interpretation remains an explicit model-authored claim.
"""

from asago_scenario_generator.stpa.models.semantic_conditions import (
    SemanticBindingPlaceholder,
)


def scope_temporal_placeholder(
    value: object,
    scope: str,
    field_name: str,
) -> object:
    """Scope one temporal placeholder without changing its typed metadata."""
    if not isinstance(value, SemanticBindingPlaceholder):
        return value
    binding_ref = value.binding_ref
    # Stage 5 uses exact occurrence
    # namespaces (``factor-1`` … ``factor-N`` and ``outcome``).  Only the
    # matching field namespace is idempotent; a provider may have copied an
    # outcome reference into a factor, and that occurrence must still be
    # independently bindable.
    expected_prefix = f"SEM-{scope}-{field_name}-"
    if binding_ref.startswith(expected_prefix):
        return value
    base = binding_ref.removeprefix("SEM-")
    return value.model_copy(update={"binding_ref": f"SEM-{scope}-{field_name}-{base}"})
