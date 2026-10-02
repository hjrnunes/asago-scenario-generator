"""Stage 3 — N/A quality gate (deterministic, no LLM calls).

N/A justifications must reference a specific structural property
(discrete, continuous, stateless, etc.).
"""

from __future__ import annotations


__all__ = [
    "STRUCTURAL_KEYWORDS",
    "check_structural_keywords",
]

# Keywords that indicate a structural property reference.
STRUCTURAL_KEYWORDS: frozenset[str] = frozenset(
    {
        "discrete",
        "continuous",
        "stateless",
        "stateful",
        "atomic",
        "one-shot",
        "instantaneous",
        "no duration",
        "single",
        "point-in-time",
    }
)


def check_structural_keywords(na_justification: str | None) -> bool:
    """Check whether an N/A justification cites a structural property.

    Scans the justification text for structural keywords (discrete,
    continuous, stateless, stateful, atomic, one-shot, instantaneous,
    no duration, single, point-in-time).

    Args:
        na_justification: The N/A justification text, or ``None``.

    Returns:
        ``True`` if at least one structural keyword is found,
        ``False`` otherwise.
    """
    if not na_justification:
        return False
    text = na_justification.lower()
    return any(kw in text for kw in STRUCTURAL_KEYWORDS)
