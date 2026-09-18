"""Runtime prerequisite checks that do not depend on consumer authoring code."""

from __future__ import annotations

from typing import Any


class PrerequisiteMismatchError(ValueError):
    """Raised when current captured state cannot establish a frozen prerequisite."""


def verify_live_dispatch_prerequisites(
    plan: Any, before: dict[str, Any]
) -> dict[str, Any]:
    """Re-check exact plan dependencies against one current state capture."""

    dependencies = getattr(plan, "prerequisite_dependencies", ()) or ()
    if not dependencies:
        return {"verified": True, "checked": []}
    from capture_runtime_context import author_context

    try:
        context = author_context(before)
    except ValueError as exc:
        raise PrerequisiteMismatchError(f"no state observation: {exc}") from exc
    checked: list[dict[str, Any]] = []
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise PrerequisiteMismatchError(
                "prerequisite-runtime-mismatch: malformed dependency"
            )
        if dependency.get("check") != "record_field":
            raise PrerequisiteMismatchError(
                f"prerequisite-runtime-mismatch: unsupported check {dependency.get('check')!r}"
            )
        record_id = dependency.get("record_id")
        field = dependency.get("field")
        expected = dependency.get("expected")
        state = context.get("state", {})
        actual = (
            state.get("orders", {}).get(record_id, {}).get(field)
            if isinstance(state, dict)
            else None
        )
        if actual != expected:
            raise PrerequisiteMismatchError(
                f"prerequisite-runtime-mismatch: {dependency.get('name', field)} "
                f"expected {expected!r}, observed {actual!r}"
            )
        checked.append(dependency)
    return {"verified": True, "checked": checked}


__all__ = ["PrerequisiteMismatchError", "verify_live_dispatch_prerequisites"]
