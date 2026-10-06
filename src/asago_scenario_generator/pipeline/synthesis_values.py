"""Value helpers shared by the synthesis stages, manifest, and persistence.

They serialize stage values for digests and read the final ICA result, which
is either the slot-fill result or a bare target-projected enumeration.
"""

from __future__ import annotations

from typing import Any, Mapping

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration


_MANIFEST_VALUE_DOMAIN = "asago-scenario-generator:stpa-synthesis-value:v1"


def _declared_capability_labels(profile: Any) -> tuple[str, ...]:
    """Return exact declared operation labels without interpreting prose."""
    labels = {
        str(item.name)
        for collection_name in ("tool_inventory", "external_integrations")
        for item in tuple(getattr(profile, collection_name, None) or ())
        if getattr(item, "name", None)
    }
    return tuple(sorted(labels))


def _dump(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, Mapping):
        return {str(key): _dump(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_dump(item) for item in value]
    return _dump_object(value)


def _dump_object(value: Any) -> Any:
    model_dump = getattr(value, "model_dump", None)
    if callable(model_dump):
        try:
            return _dump(model_dump(mode="json"))
        except TypeError:
            return _dump(model_dump())
    if hasattr(value, "__dict__"):
        return {
            key: _dump(item)
            for key, item in vars(value).items()
            if not key.startswith("_") and not callable(item)
        }
    return str(value)


def _digest_value(value: Any) -> str:
    return compute_framed_digest(_MANIFEST_VALUE_DOMAIN, _dump(value))


def _semantic_digest(value: Any) -> str | None:
    if value is None:
        return None
    declared = getattr(value, "semantic_digest", None)
    if isinstance(declared, str) and declared:
        return declared
    return _digest_value(value)


# The final ICAs are the slot-fill result, or, when a target realization
# has an effective view, the bare ICAEnumeration projected from it, which
# carries no obligation/slot evidence and no verification batch.


def _ordinary_icas(value: Any) -> Any:
    """Return the ordinary ICA enumeration of the final ICAs."""
    if isinstance(value, ICAEnumeration):
        return value
    return value.ica_enumeration


def _ica_verification(value: Any) -> Any | None:
    """Return the final ICAs' hazard verification batch, if any."""
    if isinstance(value, ICAEnumeration):
        return None
    return value.ica_hazard_verification


def _ica_considerations(value: Any) -> tuple[Any, ...]:
    """Expose exact obligation/slot evidence from the final ICA result."""
    if isinstance(value, ICAEnumeration):
        return ()
    values = tuple(value.considerations)
    verification = value.ica_hazard_verification
    if verification is None or not values:
        return values
    from asago_scenario_generator.stpa.obligation_aware.ica_verification import (
        filter_ica_considerations,
    )

    return filter_ica_considerations(
        values,
        verification,
        enumeration=value.ica_enumeration,
    )
