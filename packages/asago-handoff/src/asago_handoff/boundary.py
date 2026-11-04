"""The ownership walker: no key or string may name an artifact-design field."""

from __future__ import annotations

from typing import Any

from .contract import Contract, packaged_contract
from .violation import Violation


def iter_boundary_strings(value: Any, path: str = "") -> list[tuple[str, str]]:
    """List ``(path, text)`` for every mapping key and string scalar.

    A mapping contributes each key, then the values under it; a sequence numbers
    its items; a string is a leaf. The paths match the producer's walker, so a
    violation names the same place either repository reports.
    """

    found: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, item in value.items():
            found.append((f"{path}.{key}", str(key)))
            found.extend(iter_boundary_strings(item, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found.extend(iter_boundary_strings(item, f"{path}[{index}]"))
    elif isinstance(value, str):
        found.append((path, value))
    return found


def ownership_violations(
    payload: Any, contract: Contract | None = None
) -> list[Violation]:
    """Report each artifact-design field a key or string names, once, in first-seen order.

    The producer's rule: a key whose leaf is a forbidden key is
    ``artifact_design_field:<leaf>``; a string matching an ownership pattern is
    ``prose_hiding:<slug>``. The first place a code appears names its path.
    """

    contract = contract or packaged_contract()
    found: dict[str, Violation] = {}
    for path, text in iter_boundary_strings(payload):
        leaf = path.rsplit(".", 1)[-1].lower()
        where = path.lstrip(".")
        if leaf in contract.forbidden_keys:
            code = f"artifact_design_field:{leaf}"
            found.setdefault(
                code, Violation(code, where, "is an artifact-design field")
            )
        for slug, pattern in contract.forbidden_patterns:
            if pattern.search(text):
                code = f"prose_hiding:{slug}"
                found.setdefault(
                    code, Violation(code, where, f"matches the {slug} pattern")
                )
    return list(found.values())


__all__ = ["iter_boundary_strings", "ownership_violations"]
