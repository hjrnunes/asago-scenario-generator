"""Stage 3 — N/A quality gates (deterministic, no LLM calls).

Two mechanisms:
1. **Structural keyword check** — N/A justifications must reference a
   specific structural property (discrete, continuous, stateless, etc.).
2. **Ratio monitoring** — responsibilities with more than 75% N/A slots
   are flagged for review.
"""

from __future__ import annotations

from asago_scenario_generator.stpa.models.ica_enumeration import ICASlot

__all__ = [
    "STRUCTURAL_KEYWORDS",
    "check_structural_keywords",
    "check_na_ratio",
    "check_all_na_quality",
    "NAQualityResult",
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


class NAQualityResult:
    """Result of N/A quality checks on a set of slots.

    Attributes:
        flagged_slots: Slot IDs that failed the structural keyword check.
        ratio_flags: Flag messages from ratio monitoring.
    """

    def __init__(
        self,
        flagged_slots: list[str] | None = None,
        ratio_flags: list[str] | None = None,
    ) -> None:
        self.flagged_slots = flagged_slots or []
        self.ratio_flags = ratio_flags or []


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


def check_na_ratio(slots: list[ICASlot], threshold: float = 0.75) -> list[str]:
    """Flag responsibilities with excessive N/A ratios.

    Only responsibility slots (where ``slot.responsibility`` is not
    ``None``) are counted. Coordination link slots are excluded.

    A responsibility is flagged when its N/A ratio **exceeds** the
    threshold (strictly greater than, not greater-than-or-equal).

    Args:
        slots: All ICA slots (responsibility + coordination link).
        threshold: N/A ratio threshold (default 0.75).

    Returns:
        A list of flag messages, one per flagged responsibility.
    """
    by_resp = _group_slots_by_responsibility(slots)

    flags: list[str] = []
    for resp_id, resp_slots in by_resp.items():
        na_count = sum(1 for s in resp_slots if s.is_na)
        ratio = na_count / len(resp_slots)
        if ratio > threshold:
            flags.append(
                f"{resp_id}: {na_count}/{len(resp_slots)} slots N/A "
                f"({ratio:.0%}) — exceeds {threshold:.0%} threshold"
            )
    return flags


def _group_slots_by_responsibility(
    slots: list[ICASlot],
) -> dict[str, list[ICASlot]]:
    """Group responsibility slots by their responsibility ID.

    Coordination link slots (where ``responsibility`` is ``None``) are
    excluded from the result.
    """
    by_resp: dict[str, list[ICASlot]] = {}
    for slot in slots:
        if slot.responsibility:
            by_resp.setdefault(slot.responsibility, []).append(slot)
    return by_resp


def check_all_na_quality(
    slots: list[ICASlot], threshold: float = 0.75
) -> NAQualityResult:
    """Run both structural keyword check and ratio monitoring.

    Args:
        slots: All ICA slots to check.
        threshold: N/A ratio threshold.

    Returns:
        An :class:`NAQualityResult` with flagged slots and ratio flags.
    """
    flagged_slots: list[str] = []
    for slot in slots:
        if slot.is_na and not check_structural_keywords(slot.na_justification):
            flagged_slots.append(slot.slot_id)

    ratio_flags = check_na_ratio(slots, threshold)

    return NAQualityResult(
        flagged_slots=flagged_slots,
        ratio_flags=ratio_flags,
    )
