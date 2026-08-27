"""Batch diversity metrics for scenario evaluation.

Measures how well a batch of scenarios covers the threat landscape:
- Entry point entropy (Shannon entropy, normalized)
- Zone coverage (fraction of 5 Schneider zones used)
- Actor type entropy
- Capability level distribution evenness
- Pairwise title uniqueness
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Any

from asago_scenario_generator.models.capability_profile import (
    ZONE_NAMES,
    CapabilityProfile,
    _canonical_entry_point_name,
)


def _entropy_value(counts: Counter, n: int) -> float:
    """Raw Shannon entropy over counter values."""
    entropy = 0.0
    for count in counts.values():
        p = count / n
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def _normalized_entropy(entropy: float, n_categories: int) -> float:
    """Entropy normalized by log2(n_categories)."""
    max_entropy = math.log2(n_categories)
    if max_entropy > 0:
        return entropy / max_entropy
    return entropy


def _shannon_entropy(values: list[str], normalize: bool = True) -> float:
    """Compute Shannon entropy of a discrete distribution.

    Args:
        values: List of category values.
        normalize: If True, normalize by log2(n_categories) to get [0, 1].

    Returns:
        Entropy value. Returns 0.0 for empty or single-value lists.
    """
    if not values:
        return 0.0

    counts = Counter(values)
    n = len(values)
    n_categories = len(counts)

    if n_categories <= 1:
        return 0.0

    entropy = _entropy_value(counts, n)

    if normalize:
        return _normalized_entropy(entropy, n_categories)
    return entropy


def _jaccard_tokens(a: str, b: str, stopwords: set[str] | None = None) -> float:
    """Jaccard similarity of token sets from two strings.

    Args:
        a: First string.
        b: Second string.
        stopwords: Optional set of tokens to exclude before comparison.
    """
    tokens_a = set(a.lower().split())
    tokens_b = set(b.lower().split())
    if stopwords:
        tokens_a -= stopwords
        tokens_b -= stopwords
    if not tokens_a and not tokens_b:
        return 1.0
    union = tokens_a | tokens_b
    if not union:
        return 1.0
    return len(tokens_a & tokens_b) / len(union)


def _extract_domain_stopwords(titles: list[str], threshold: float = 0.5) -> set[str]:
    """Extract domain stopwords — words appearing in more than *threshold* of titles.

    These are common domain vocabulary (e.g. "Policy", "Agent", "Attack") that
    inflate Jaccard similarity without indicating genuine duplication.
    """
    if not titles:
        return set()

    word_counts: Counter[str] = Counter()
    for title in titles:
        unique_words = set(title.lower().split())
        word_counts.update(unique_words)

    n = len(titles)
    return {word for word, count in word_counts.items() if count / n > threshold}


def _entry_point_id_lookup(
    profile: CapabilityProfile | None,
) -> dict[str, set[str]]:
    """Normalized display name to canonical ingress ID set, when a profile is given."""
    if profile is None:
        return {}
    # Only attacker-accessible EPs are in the coverage universe
    # (cmps.9 third review correction 2).
    from asago_scenario_generator.models.capability_profile import (
        _canonical_entry_point_name,
        is_attacker_accessible_ingress,
    )

    active_zones = set(profile.zones_active) if profile.zones_active else set()
    ep_name_to_ids: dict[str, set[str]] = {}
    for ep in profile.entry_points:
        if not is_attacker_accessible_ingress(ep, active_zones):
            continue
        key = _canonical_entry_point_name(ep.name)
        ep_name_to_ids.setdefault(key, set()).add(ep.entry_point_id)
    return ep_name_to_ids


def _unique_match_id(matched_ids: set[str] | None) -> str | None:
    """The single canonical id behind a name match, or None when ambiguous."""
    if matched_ids and len(matched_ids) == 1:
        return next(iter(matched_ids))
    return None


def _name_fallback(ep: str, profile: CapabilityProfile | None) -> str | None:
    """Identity for an unresolved display name, without inflating coverage."""
    if profile is None:
        # No profile — fall back to canonical name as identity.
        return _canonical_entry_point_name(ep)
    # Ambiguous or unknown with profile — do not inflate coverage.
    return None


def _scenario_entry_point_identity(
    scenario: dict[str, Any],
    ep_name_to_ids: dict[str, set[str]],
    profile: CapabilityProfile | None,
) -> str | None:
    """Canonical entry-point identity for one scenario, or None."""
    cf = scenario.get("candidate_filter") or {}
    ep_id = cf.get("entry_point_id")
    if ep_id:
        return ep_id
    ep = scenario.get("narrative", {}).get("entry_point", "")
    if not ep:
        return None

    # Resolve display name to canonical ID(s) when possible.
    # Unique match: credit the single ID.
    # Ambiguous match (multiple IDs): unresolved — credit none.
    # Unknown name without profile: use canonical name as identity.
    matched_ids = ep_name_to_ids.get(_canonical_entry_point_name(ep))
    unique_id = _unique_match_id(matched_ids)
    if unique_id is not None:
        return unique_id
    return _name_fallback(ep, profile)


def _expected_entry_point_ids(profile: CapabilityProfile) -> set[str]:
    """Attacker-accessible canonical ingress entry-point IDs from the profile."""
    from asago_scenario_generator.models.capability_profile import (
        is_attacker_accessible_ingress,
    )

    active_zones = set(profile.zones_active) if profile.zones_active else set()
    return {
        ep.entry_point_id
        for ep in profile.entry_points
        if is_attacker_accessible_ingress(ep, active_zones)
    }


def _entry_point_coverage_ratio(
    used_ids: set[str],
    entry_point_list: list[str],
    expected_entry_points: int,
    profile: CapabilityProfile | None,
) -> float:
    """Raw entry-point coverage ratio in [0, 1]."""
    if profile is not None:
        # Exact canonical set arithmetic — only attacker-accessible EPs
        # (cmps.9 third review correction 2).  Only count IDs that are in
        # the expected set — unknown IDs must not inflate coverage.
        expected_ids = _expected_entry_point_ids(profile)
        if expected_ids:
            return len(used_ids & expected_ids) / len(expected_ids)
        return 0.0
    if expected_entry_points > 0:
        return len(set(entry_point_list)) / expected_entry_points
    return 0.0


def entry_point_entropy(
    scenarios: list[dict[str, Any]],
    expected_entry_points: int | None = None,
    profile: CapabilityProfile | None = None,
) -> float | dict[str, Any]:
    """Shannon entropy of entry points across scenarios (normalized).

    Extracts entry point identity from each scenario.  Prefers the
    canonical ``entry_point_id`` from ``candidate_filter`` provenance;
    falls back to ``narrative.entry_point`` resolved against the profile
    for scenarios without provenance.

    When *expected_entry_points* is given as an integer count and
    *profile* is provided, coverage is computed as exact canonical set
    arithmetic: ``len(used_ids & expected_ids) / len(expected_ids)``
    where ``expected_ids`` are the canonical ingress entry-point IDs
    from the profile.  Unknown IDs do not inflate coverage.

    When *profile* is not provided, falls back to the integer-count
    approach (clamped to [0, 1]).

    Args:
        scenarios: List of scenario dicts.
        expected_entry_points: If provided, also compute entry_point_coverage.
        profile: If provided, use canonical profile entry-point IDs for
            exact set-based coverage.

    Returns:
        float (entropy) when expected_entry_points is None, otherwise a dict
        with 'entropy' and 'entry_point_coverage'.
    """
    ep_name_to_ids = _entry_point_id_lookup(profile)
    used_ids: set[str] = set()
    entry_point_list: list[str] = []
    for s in scenarios:
        identity = _scenario_entry_point_identity(s, ep_name_to_ids, profile)
        if identity is not None:
            used_ids.add(identity)
            entry_point_list.append(identity)

    entropy = round(_shannon_entropy(entry_point_list), 4)

    if expected_entry_points is None:
        return entropy

    raw_coverage = _entry_point_coverage_ratio(
        used_ids, entry_point_list, expected_entry_points, profile
    )
    coverage = round(min(1.0, max(0.0, raw_coverage)), 4)
    result: dict[str, Any] = {
        "entropy": entropy,
        "entry_point_coverage": coverage,
    }
    if profile is not None:
        expected_ids = _expected_entry_point_ids(profile)
        covered_ids = used_ids & expected_ids
        result["covered_entry_point_count"] = len(covered_ids)
        result["expected_entry_point_count"] = len(expected_ids)
        result["covered_entry_point_ids"] = sorted(covered_ids)
        result["expected_entry_point_ids"] = sorted(expected_ids)
    return result


def _out_of_scope_violation(
    scenario: dict[str, Any], active_zones: set[str]
) -> dict[str, Any] | None:
    """Out-of-scope zone violation record for one scenario, or None."""
    zones = {str(z) for z in scenario.get("narrative", {}).get("zone_sequence", [])}
    out_of_scope = zones - active_zones
    if not out_of_scope:
        return None
    return {
        "scenario_id": scenario.get("scenario_id", "unknown"),
        "out_of_scope_zones": sorted(out_of_scope),
    }


def _zone_coverage_violations(
    scenarios: list[dict[str, Any]], active_zones: set[str]
) -> list[dict[str, Any]]:
    """Out-of-scope violation records across scenarios."""
    violations: list[dict[str, Any]] = []
    for scenario in scenarios:
        violation = _out_of_scope_violation(scenario, active_zones)
        if violation is not None:
            violations.append(violation)
    return violations


def zone_coverage(
    scenarios: list[dict[str, Any]],
    active_zones: set[str] | None = None,
) -> float | dict[str, Any]:
    """Fraction of zones represented across all scenarios.

    Args:
        scenarios: List of scenario dicts.
        active_zones: If provided, compute coverage as fraction of *active*
            zones used (not all 5) and flag scenarios referencing zones
            outside the active set. Returns a dict instead of a bare float.

    Returns:
        float (raw coverage vs 5 zones) when active_zones is None, otherwise
        a dict with 'raw_coverage', 'active_zone_coverage', and
        'out_of_scope_zone_violations'.
    """
    all_zones: set[str] = set()
    for s in scenarios:
        zones = s.get("narrative", {}).get("zone_sequence", [])
        all_zones.update(str(z) for z in zones)

    valid_zone_names = set(ZONE_NAMES)
    raw_coverage = round(len(all_zones & valid_zone_names) / len(ZONE_NAMES), 4)

    if active_zones is None:
        return raw_coverage

    # Contextualized coverage against active zones
    covered_active = all_zones & active_zones
    active_coverage = (
        round(len(covered_active) / len(active_zones), 4) if active_zones else 0.0
    )

    return {
        "raw_coverage": raw_coverage,
        "active_zone_coverage": active_coverage,
        "out_of_scope_zone_violations": _zone_coverage_violations(
            scenarios, active_zones
        ),
    }


def goal_category_entropy(scenarios: list[dict[str, Any]]) -> float:
    """Shannon entropy of goal categories across scenarios (normalized)."""
    goal_categories = []
    for s in scenarios:
        ap = s.get("actor_profile")
        if ap and isinstance(ap, dict):
            gc = ap.get("goal_category", "")
            if gc:
                goal_categories.append(gc)
    return round(_shannon_entropy(goal_categories), 4)


def actor_type_entropy(scenarios: list[dict[str, Any]]) -> float:
    """Shannon entropy of actor types across scenarios (normalized)."""
    actor_types = []
    for s in scenarios:
        ap = s.get("actor_profile")
        if ap and isinstance(ap, dict):
            at = ap.get("actor_type", "")
            if at:
                actor_types.append(at)
    return round(_shannon_entropy(actor_types), 4)


def capability_level_evenness(scenarios: list[dict[str, Any]]) -> float:
    """Evenness of capability level distribution (normalized Shannon entropy).

    Capability levels: novice, intermediate, advanced, expert.
    """
    levels = []
    for s in scenarios:
        ap = s.get("actor_profile")
        if ap and isinstance(ap, dict):
            cl = ap.get("capability_level", "")
            if cl:
                levels.append(cl)
    return round(_shannon_entropy(levels), 4)


def title_uniqueness(scenarios: list[dict[str, Any]], top_k: int = 5) -> float:
    """Pairwise title uniqueness: 1 - mean of top-k Jaccard similarities.

    Before computing Jaccard, extracts "domain stopwords" — words appearing in
    more than 50% of titles — and excludes them.  This prevents common domain
    vocabulary (e.g. "Policy", "Agent", "Manipulation") from penalizing batches
    whose titles are genuinely diverse.

    Uses the mean of the top-k most similar pairs rather than a single max,
    so that one duplicate pair penalizes the score but does not drive it to 0.0
    on its own.  When fewer than *top_k* pairs exist, all pairs are averaged.

    Returns 1.0 if all titles are completely distinct, lower if duplicates exist.
    Returns 1.0 for 0 or 1 scenarios.
    """
    titles = []
    for s in scenarios:
        title = s.get("narrative", {}).get("title", "")
        if title:
            titles.append(title)

    if len(titles) <= 1:
        return 1.0

    domain_stopwords = _extract_domain_stopwords(titles)

    similarities: list[float] = []
    for i in range(len(titles)):
        for j in range(i + 1, len(titles)):
            sim = _jaccard_tokens(titles[i], titles[j], stopwords=domain_stopwords)
            similarities.append(sim)

    # Take the top-k highest similarities and average them.
    similarities.sort(reverse=True)
    k = min(top_k, len(similarities))
    mean_top_k = sum(similarities[:k]) / k

    return round(1.0 - mean_top_k, 4)


def score_diversity(
    scenarios: list[dict[str, Any]],
    *,
    expected_entry_points: int | None = None,
    active_zones: set[str] | None = None,
    profile: CapabilityProfile | None = None,
) -> dict[str, Any]:
    """Compute all batch diversity metrics.

    Args:
        scenarios: List of scenario dicts (parsed YAML).
        expected_entry_points: Number of entry points from the capability
            profile. When provided, entry_point_entropy includes a
            coverage ratio alongside the raw entropy.
        active_zones: Set of active Schneider zones from the capability
            profile. When provided, zone_coverage includes contextualized
            coverage and out-of-scope violation detection.
        profile: When provided, entry_point_entropy uses exact canonical
            set arithmetic against the profile's ingress entry-point IDs
            and returns numerator/denominator evidence.

    Returns:
        Dict with entry_point_entropy, zone_coverage, actor_type_entropy,
        capability_level_evenness, and title_uniqueness.  When context
        parameters are supplied the entropy/coverage values are dicts with
        both raw and contextualized metrics.
    """
    return {
        "entry_point_entropy": entry_point_entropy(
            scenarios,
            expected_entry_points=expected_entry_points,
            profile=profile,
        ),
        "zone_coverage": zone_coverage(scenarios, active_zones=active_zones),
        "actor_type_entropy": actor_type_entropy(scenarios),
        "goal_category_entropy": goal_category_entropy(scenarios),
        "capability_level_evenness": capability_level_evenness(scenarios),
        "title_uniqueness": title_uniqueness(scenarios),
    }
