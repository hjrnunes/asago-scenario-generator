"""Diversity helpers for entry points, narrative patterns, and structural patterns."""

from __future__ import annotations

import math
import re
from collections import Counter

from asago_scenario_generator.models.scenario import NarrativeLayer

from asago_scenario_generator.pipeline.generate.constants import (
    _ENTRY_POINT_ZONE_KEYWORDS,
    _PATTERN_STOP_WORDS,
    _PHASE_KEYWORDS,
)


def _entry_point_zone_keyword_matches(ep_lower: str) -> set[str]:
    """Zones implied by an entry-point name, defaulting to ``input``."""
    ep_zones: set[str] = set()
    for keyword, zones in _ENTRY_POINT_ZONE_KEYWORDS.items():
        if keyword in ep_lower:
            ep_zones.update(zones)
    if not ep_zones:
        ep_zones = {"input"}
    return ep_zones


def _zone_overlap_score(ep_zones: set[str], target_zones: set[str]) -> float:
    """Jaccard overlap of entry-point zones with the threat's zone sequence."""
    overlap = len(ep_zones & target_zones)
    total = len(ep_zones | target_zones)
    return overlap / total if total > 0 else 0.0


def compute_entry_point_affinity(
    entry_points: list[str],
    zone_sequence: list[str],
) -> dict[str, float]:
    """Score each entry point by how well it feeds into the threat's zone sequence.

    Returns a dict mapping each entry point to a score in [0, 1].
    Higher scores mean the entry point naturally feeds into the zones
    the attack traverses.
    """
    if not entry_points:
        return {}

    target_zones = set(zone_sequence)
    return {
        ep: _zone_overlap_score(
            _entry_point_zone_keyword_matches(ep.lower()), target_zones
        )
        for ep in entry_points
    }


def assign_entry_point(
    entry_points: list[str],
    zone_sequence: list[str],
    usage_counts: Counter[str],
    total_seeds: int,
) -> str | None:
    """Pick a preferred entry point for a seed, balancing affinity and diversity.

    Returns the suggested entry point string, or None if no entry points
    are available.

    Strategy:
    - Compute affinity scores for each entry point.
    - Penalise entry points that have been used more than their fair share
      (ceil(total_seeds / num_entry_points)).
    - Return the entry point with the highest adjusted score.
    """
    if not entry_points:
        return None
    if len(entry_points) == 1:
        return entry_points[0]

    fair_share = math.ceil(total_seeds / len(entry_points))
    affinity = compute_entry_point_affinity(entry_points, zone_sequence)

    best_ep = None
    best_score = -1.0

    for ep in entry_points:
        base = affinity.get(ep, 0.0)
        count = usage_counts.get(ep, 0)
        # Penalise over-used entry points: subtract 0.3 for each use beyond
        # fair share, floored at 0.
        penalty = max(0, count - fair_share) * 0.3
        adjusted = max(0.0, base - penalty)
        if adjusted > best_score:
            best_score = adjusted
            best_ep = ep

    return best_ep


def get_overused_entry_points(
    entry_points: list[str],
    usage_counts: Counter[str],
    total_seeds: int,
) -> list[str]:
    """Return entry points that have been used more than their fair share.

    Fair share = ceil(total_seeds / num_entry_points).
    """
    if len(entry_points) <= 1:
        return []
    fair_share = math.ceil(total_seeds / len(entry_points))
    return [ep for ep in entry_points if usage_counts.get(ep, 0) > fair_share]


def extract_narrative_keywords(
    narrative: NarrativeLayer,
    max_keywords: int = 3,
    attack_pattern_name: str | None = None,
) -> list[str]:
    """Extract short keyword phrases summarizing the attack pattern from a narrative.

    When *attack_pattern_name* is provided, keywords are preferentially extracted
    from it (the attack pattern name is the actual distinguishing signal between
    seeds). Falls back to narrative text when the attack pattern name yields
    fewer than *max_keywords* after stop-word filtering.

    Uses the narrative title/summary to
    identify the dominant attack archetype. Returns up to *max_keywords*
    descriptive words, lowercased and deduplicated.

    This is intentionally a simple heuristic — keyword matching, not a
    classifier. Good enough to nudge the LLM away from repeated templates.
    """

    def _tokenize(text: str) -> list[str]:
        tokens = re.split(r"[^a-z]+", text.lower())
        return [t for t in tokens if t and len(t) > 2 and t not in _PATTERN_STOP_WORDS]

    # Try attack_pattern_name first — it's the best discriminative signal.
    if attack_pattern_name:
        pattern_tokens = _tokenize(attack_pattern_name)
        if len(pattern_tokens) >= max_keywords:
            counts = Counter(pattern_tokens)
            return [word for word, _ in counts.most_common(max_keywords)]

    text_parts: list[str] = []

    # Prepend attack_pattern_name tokens (if any) so they get counted.
    if attack_pattern_name:
        text_parts.append(attack_pattern_name)

    text_parts.extend([narrative.title, narrative.summary])

    combined = " ".join(text_parts).lower()

    # Tokenize: split on non-alpha and filter stop words / short tokens.
    tokens = _tokenize(combined)

    # Count and pick the most common meaningful tokens.
    counts = Counter(tokens)
    return [word for word, _ in counts.most_common(max_keywords)]


def get_overused_patterns(
    pattern_counts: Counter[str],
    threshold: int = 2,
) -> list[str]:
    """Return attack pattern keywords used more than *threshold* times.

    Returns up to 5 most-used patterns (enough to steer without overwhelming
    the prompt).
    """
    overused = [kw for kw, count in pattern_counts.most_common() if count > threshold]
    return overused[:5]


def _phase_for_action_text(action_lower: str) -> str:
    """Map action text to the first matching canonical phase label."""
    for phase, keywords in _PHASE_KEYWORDS.items():
        if any(kw in action_lower for kw in keywords):
            return phase
    return "other"


def _append_distinct_phase(phases: list[str], matched_phase: str) -> None:
    """Append a phase, collapsing consecutive duplicates."""
    if not phases or phases[-1] != matched_phase:
        phases.append(matched_phase)


def extract_structural_pattern(narrative: NarrativeLayer) -> str:
    """Extract the structural attack phase sequence from a narrative.

    Maps each narrative step's action text to a canonical phase label
    (e.g., "inject", "poison", "persist", "bypass") and returns them
    joined with arrows: "inject->hallucinate->persist->bypass".

    Steps that don't match any phase keyword are labeled "other".
    Consecutive duplicate phases are collapsed (e.g., inject->inject
    becomes just inject).

    This captures the *shape* of the attack, not surface keywords.
    Two scenarios with different titles but the same structural pattern
    ("poison->hallucinate->persist->bypass") are flagged as convergent.
    """
    phases: list[str] = []
    for step in narrative.steps:
        matched_phase = _phase_for_action_text(step.action.lower())
        _append_distinct_phase(phases, matched_phase)

    return "->".join(phases)


def get_overused_structural_patterns(
    structural_counts: Counter[str],
    threshold: int = 2,
) -> list[str]:
    """Return structural attack patterns used more than *threshold* times.

    Returns up to 3 most-used structural patterns. These are phase sequences
    like "inject->hallucinate->persist->bypass".
    """
    overused = [
        pattern
        for pattern, count in structural_counts.most_common()
        if count > threshold and pattern != "other"
    ]
    return overused[:3]


def _format_structural_exclusions(patterns: list[str]) -> str:
    """Format overused structural patterns into a prompt-ready exclusion block.

    Translates phase-arrow patterns into natural language descriptions
    that the LLM can understand and avoid.
    """
    if not patterns:
        return ""

    _PHASE_DESCRIPTIONS: dict[str, str] = {
        "poison": "poisoning/corrupting data",
        "inject": "injecting malicious content",
        "probe": "reconnaissance/probing",
        "hallucinate": "causing hallucination/confabulation",
        "exfiltrate": "exfiltrating/stealing data",
        "persist": "persisting in memory/state",
        "escalate": "privilege escalation/lateral movement",
        "bypass": "bypassing human review/controls",
        "deny": "denial of service/degradation",
        "manipulate": "manipulating/tampering with data",
        "other": "general attack action",
    }

    lines = []
    for pattern in patterns:
        phases = pattern.split("->")
        described = [_PHASE_DESCRIPTIONS.get(p, p) for p in phases]
        lines.append(f"  - {' then '.join(described)} ({pattern})")

    return (
        "\n## Structural Attack Pattern Diversity\n"
        "The following attack STRUCTURES have already been used too many times "
        "in this batch. Do NOT follow these same phase sequences — use a "
        "fundamentally different attack approach:\n" + "\n".join(lines) + "\n"
        "Instead, try attack shapes like:\n"
        "  - Direct exploitation without persistence\n"
        "  - Reconnaissance before targeted strike\n"
        "  - Denial of service or resource exhaustion\n"
        "  - Privilege escalation through trust boundary confusion\n"
        "  - Data exfiltration via side channels\n"
        "Vary the structural attack approach — do not repeat the same "
        "sequence of attack phases.\n"
    )
