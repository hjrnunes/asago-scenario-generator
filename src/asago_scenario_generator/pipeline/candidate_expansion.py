"""Candidate expansion and canonicalization implementations."""

from __future__ import annotations

import logging
from collections import defaultdict
from itertools import combinations
from typing import Any

from asago_scenario_generator.data.atlas import (
    ATLAS_TECHNIQUE_DESCRIPTIONS,
    ATLAS_TECHNIQUE_NAMES,
)
from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    is_attacker_accessible_ingress,
)
from asago_scenario_generator.pipeline.candidate_models import (
    CandidateOrigin,
    CandidateTriple,
    StageRecord,
    _canonicalize_and_dedup_origins,
    _non_provenance_conflicts,
    compute_candidate_id,
)
from asago_scenario_generator.pipeline.seeds import ScenarioSeed

logger = logging.getLogger("asago_scenario_generator.pipeline.candidates")

# ---------------------------------------------------------------------------
# Candidate expansion: cross-product seeds x entry_points x techniques
# ---------------------------------------------------------------------------


def expand_candidates(
    seeds: list[ScenarioSeed],
    profile: CapabilityProfile,
    max_techniques: int = 1,
    stage_records: list[StageRecord] | None = None,
) -> list[CandidateTriple]:
    """Cross-product each seed with all entry points and ATLAS technique combos.

    For every ScenarioSeed, produces one CandidateTriple per
    (entry_point, technique_combo) combination, carrying full context
    needed by the downstream LLM filter stage.

    When ``max_techniques=1`` (the default), behaviour is equivalent to the
    original per-technique expansion.  With ``max_techniques=2``, both
    single-technique and two-technique combos are generated (C(N,1)+C(N,2)
    per seed x entry_point).

    Args:
        seeds: Output of ``expand_seeds()`` (Stage 3).
        profile: Capability profile with ``entry_points`` list.
        max_techniques: Maximum number of techniques in a combo (default 1).
        stage_records: Optional list to append a :class:`StageRecord`
            capturing pre-dedup/post-dedup counts.  When provided, the
            caller receives typed records for funnel accounting.

    Returns:
        Flat list of deduplicated CandidateTriple, one per unique
        canonical identity.
    """
    if not profile.entry_points:
        logger.warning("Profile has no entry points — returning empty candidate list")
        return []

    eligible_seeds = _capability_eligible_seeds(seeds, profile)
    _log_seed_eligibility(eligible_seeds, seeds)

    ingress_points = _attacker_ingress_points(profile)
    if not ingress_points:
        logger.warning(
            "Profile has %d entry points but none are input/bidirectional — "
            "returning empty candidate list",
            len(profile.entry_points),
        )
        return []

    candidates: list[CandidateTriple] = []
    for seed in eligible_seeds:
        candidates.extend(_expand_one_seed(seed, ingress_points, max_techniques))

    _log_expansion_summary(eligible_seeds, ingress_points, max_techniques, candidates)

    _check_candidate_collisions(candidates)

    # Canonicalize and deduplicate immediately after expansion.
    raw_count = len(candidates)
    candidates = canonicalize_and_dedup(candidates, stage="expansion")
    _expansion_stage_record(stage_records, raw_count, candidates)
    return candidates


def _seed_capability_supported(
    seed: ScenarioSeed, cap: str, profile: CapabilityProfile
) -> bool:
    """Whether one required capability is supported; warns when not."""
    if not _capability_available(cap, profile):
        logger.warning(
            "Skipping seed %s: requires %s but profile does not support it",
            seed.seed_id,
            cap,
        )
        return False
    return True


def _capability_available(cap: str, profile: CapabilityProfile) -> bool:
    """Profile support for one named capability (unknown caps pass)."""
    if cap == "multi_agent":
        return profile.multi_agent
    if cap == "persistent_memory":
        return profile.has_persistent_memory
    if cap == "tool_execution":
        return "tool_execution" in profile.zones_active
    return True


def _capability_eligible_seeds(
    seeds: list[ScenarioSeed], profile: CapabilityProfile
) -> list[ScenarioSeed]:
    """Pre-filter: reject seeds whose required_capabilities are not met."""
    eligible_seeds: list[ScenarioSeed] = []
    for seed in seeds:
        if seed.required_capabilities:
            skip = False
            for cap in seed.required_capabilities:
                if not _seed_capability_supported(seed, cap, profile):
                    skip = True
                    break
            if skip:
                continue
        eligible_seeds.append(seed)
    return eligible_seeds


def _log_seed_eligibility(
    eligible_seeds: list[ScenarioSeed], seeds: list[ScenarioSeed]
) -> None:
    """Log the capability-filter outcome when any seed was rejected."""
    if len(eligible_seeds) < len(seeds):
        logger.info(
            "Seed capability filter: %d/%d seeds eligible (rejected %d)",
            len(eligible_seeds),
            len(seeds),
            len(seeds) - len(eligible_seeds),
        )


def _attacker_ingress_points(
    profile: CapabilityProfile,
) -> list[Any]:
    """Attacker-accessible ingress entry points (cmps.9 correction 2).

    Excludes output-only, system-controlled, and entries whose canonical
    ingress zone is inactive.
    """
    active_zones = set(profile.zones_active) if profile.zones_active else set()
    ingress_points = [
        ep
        for ep in profile.entry_points
        if is_attacker_accessible_ingress(ep, active_zones)
    ]
    excluded_count = len(profile.entry_points) - len(ingress_points)
    if excluded_count > 0:
        logger.info(
            "Entry point filter: %d/%d entry points are attacker-accessible "
            "(%d excluded: output-only or system-controlled)",
            len(ingress_points),
            len(profile.entry_points),
            excluded_count,
        )
    return ingress_points


def _seed_technique_pool(seed: ScenarioSeed) -> tuple[str, ...] | None:
    """ATLAS technique IDs, falling back to LAAF IDs; None when empty."""
    pool = seed.atlas_technique_ids or seed.laaf_technique_ids
    if not pool:
        logger.warning(
            "Seed %s has no technique IDs (ATLAS or LAAF) — skipping",
            seed.seed_id,
        )
        return None
    return pool


def _candidate_triple_for(
    seed: ScenarioSeed,
    entry_point: Any,
    ep_id: str,
    tech_combo: tuple[str, ...],
) -> CandidateTriple:
    """One (seed, entry point, technique combo) candidate."""
    return CandidateTriple(
        seed_id=seed.seed_id,
        threat_id=seed.threat_id,
        threat_name=seed.threat_name,
        attack_pattern_name=seed.attack_pattern_name,
        attack_pattern_description=seed.attack_pattern_description,
        entry_point=entry_point.name,
        controllability=entry_point.controllability,
        direction=entry_point.direction,
        ingress_zone=entry_point.ingress_zone,
        entry_point_id=ep_id,
        candidate_id=compute_candidate_id(
            seed.seed_id,
            ep_id,
            tech_combo,
        ),
        atlas_technique_ids=tech_combo,
        atlas_technique_names=tuple(
            ATLAS_TECHNIQUE_NAMES.get(t, t) for t in tech_combo
        ),
        atlas_technique_descriptions=tuple(
            ATLAS_TECHNIQUE_DESCRIPTIONS.get(t, "") for t in tech_combo
        ),
        risk_card_ref=seed.risk_card_ref,
        owasp_llm_ids=seed.owasp_llm_ids,
        origins=(
            CandidateOrigin(
                source_candidate_id=compute_candidate_id(
                    seed.seed_id,
                    ep_id,
                    tech_combo,
                ),
                original_technique_ids=tech_combo,
                transform_stage="expansion",
            ),
        ),
    )


def _expand_one_seed(
    seed: ScenarioSeed,
    ingress_points: list[Any],
    max_techniques: int,
) -> list[CandidateTriple]:
    """Cross-product one seed with all ingress points and technique combos."""
    technique_pool = _seed_technique_pool(seed)
    if technique_pool is None:
        return []

    candidates: list[CandidateTriple] = []
    for entry_point in ingress_points:
        ep_id = entry_point.entry_point_id
        for combo_size in range(1, max_techniques + 1):
            for tech_combo in combinations(technique_pool, combo_size):
                candidates.append(
                    _candidate_triple_for(seed, entry_point, ep_id, tech_combo)
                )
    return candidates


def _average_technique_count(eligible_seeds: list[ScenarioSeed]) -> float:
    """Mean technique-pool size over seeds that have any technique IDs."""
    tech_counts = [
        len(s.atlas_technique_ids or s.laaf_technique_ids)
        for s in eligible_seeds
        if s.atlas_technique_ids or s.laaf_technique_ids
    ]
    return sum(tech_counts) / len(tech_counts) if tech_counts else 0.0


def _log_expansion_summary(
    eligible_seeds: list[ScenarioSeed],
    ingress_points: list[Any],
    max_techniques: int,
    candidates: list[CandidateTriple],
) -> None:
    """Log the expansion outcome when any seed was processed."""
    if not eligible_seeds:
        return
    avg_techniques = _average_technique_count(eligible_seeds)
    logger.info(
        "%d seeds x %d ingress entry points x avg %.1f techniques "
        "(max_techniques=%d) = %d candidates",
        len(eligible_seeds),
        len(ingress_points),
        avg_techniques,
        max_techniques,
        len(candidates),
    )


def _expansion_stage_record(
    stage_records: list[StageRecord] | None,
    raw_count: int,
    candidates: list[CandidateTriple],
) -> None:
    """Record the expansion stage counts when a ledger is supplied."""
    if stage_records is not None:
        stage_records.append(
            StageRecord(
                stage="expansion",
                input_count=raw_count,
                output_count=len(candidates),
                collapsed_count=raw_count - len(candidates),
            )
        )


def _check_candidate_collisions(candidates: list[CandidateTriple]) -> None:
    """Reject candidates with same candidate_id but different identity inputs.

    Two candidates are *semantic duplicates* when they share the same
    ``candidate_id`` and the same ``(seed_id, entry_point_id, sorted
    unique technique IDs)`` — this is expected from duplicate expansion
    and is silently deduplicated elsewhere.

    Two candidates *collide* when they share the same ``candidate_id``
    but have different identity inputs (a hash collision or forged ID).
    This is rejected because the filter protocol cannot distinguish them.

    Args:
        candidates: List of candidates to check.

    Raises:
        ValueError: If two candidates with different identity inputs
            produce the same ``candidate_id``.
    """
    seen: dict[str, tuple[str, str, tuple[str, ...]]] = {}
    for c in candidates:
        identity = (
            c.seed_id,
            c.entry_point_id,
            tuple(sorted(set(c.atlas_technique_ids))),
        )
        if c.candidate_id in seen:
            existing = seen[c.candidate_id]
            if existing != identity:
                raise ValueError(
                    f"Candidate collision: candidate_id '{c.candidate_id}' "
                    f"maps to different identity inputs "
                    f"({identity} vs {existing}). "
                    f"Remove or disambiguate one of them."
                )
            # Semantic duplicate — not an error here, just a debug log.
            logger.debug(
                "Semantic duplicate candidate_id '%s' in expansion",
                c.candidate_id,
            )
        else:
            seen[c.candidate_id] = identity


def _canonicalize_techniques(
    ids: tuple[str, ...],
    names: tuple[str, ...],
    descriptions: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Sort technique IDs and align names/descriptions deterministically.

    Detects duplicate technique IDs with conflicting names/descriptions
    (fatal), deduplicates duplicate IDs with identical metadata, and
    sorts by ID so equivalent inputs serialize identically regardless
    of input ordering.

    Raises:
        ValueError: If the same technique ID appears with conflicting
            name or description metadata.
    """
    if not ids:
        return (), (), ()

    padded_names, padded_descs = _padded_metadata(ids, names, descriptions)
    id_to_name, id_to_desc = _technique_metadata_map(ids, padded_names, padded_descs)
    return _aligned_metadata(id_to_name, id_to_desc)


def _padded_metadata(
    ids: tuple[str, ...],
    names: tuple[str, ...],
    descriptions: tuple[str, ...],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Pad names/descriptions to match ids length (defensive)."""
    padded_names = tuple(names) + ("",) * max(0, len(ids) - len(names))
    padded_descs = tuple(descriptions) + ("",) * max(0, len(ids) - len(descriptions))
    return padded_names, padded_descs


def _technique_metadata_map(
    ids: tuple[str, ...],
    names: tuple[str, ...],
    descriptions: tuple[str, ...],
) -> tuple[dict[str, str], dict[str, str]]:
    """Build per-ID metadata, detecting conflicting values for one ID."""
    id_to_name: dict[str, str] = {}
    id_to_desc: dict[str, str] = {}
    for tid, name, desc in zip(ids, names, descriptions, strict=False):
        if tid in id_to_name:
            if id_to_name[tid] != name:
                raise ValueError(
                    f"Conflicting technique name for ID '{tid}': "
                    f"{id_to_name[tid]!r} vs {name!r}"
                )
            if id_to_desc[tid] != desc:
                raise ValueError(
                    f"Conflicting technique description for ID '{tid}': "
                    f"{id_to_desc[tid]!r} vs {desc!r}"
                )
        else:
            id_to_name[tid] = name
            id_to_desc[tid] = desc
    return id_to_name, id_to_desc


def _aligned_metadata(
    id_to_name: dict[str, str], id_to_desc: dict[str, str]
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Sort by ID and align names/descriptions to that order."""
    sorted_ids = tuple(sorted(id_to_name))
    sorted_names = tuple(id_to_name[tid] for tid in sorted_ids)
    sorted_descs = tuple(id_to_desc[tid] for tid in sorted_ids)
    return sorted_ids, sorted_names, sorted_descs


def _check_converged_technique_metadata(
    group: list[CandidateTriple],
) -> None:
    """Compare canonical technique ID/name/description mappings across
    every converged candidate and reject conflicts."""
    ref_map: dict[str, tuple[str, str]] | None = None
    for c in group:
        c_map = _candidate_technique_map(c)
        if ref_map is None:
            ref_map = c_map
            continue
        _technique_map_conflicts(ref_map, c_map)


def _candidate_technique_map(
    c: CandidateTriple,
) -> dict[str, tuple[str, str]]:
    """Per-ID (name, description) metadata of one candidate."""
    c_map: dict[str, tuple[str, str]] = {}
    for tid, name, desc in zip(
        c.atlas_technique_ids,
        c.atlas_technique_names,
        c.atlas_technique_descriptions,
        strict=False,
    ):
        c_map[tid] = (name, desc)
    return c_map


def _technique_map_conflicts(
    ref_map: dict[str, tuple[str, str]],
    c_map: dict[str, tuple[str, str]],
) -> None:
    """Reject differing ID sets or per-ID metadata across converged maps."""
    # Compare keys (technique IDs) — must be the same set.
    if set(ref_map) != set(c_map):
        raise ValueError(
            f"Conflicting technique ID sets for converged candidate: "
            f"{sorted(ref_map)} vs {sorted(c_map)}"
        )
    # Compare per-ID metadata.
    for tid in ref_map:
        if ref_map[tid] != c_map[tid]:
            raise ValueError(
                f"Conflicting technique metadata for ID '{tid}': "
                f"{ref_map[tid]!r} vs {c_map[tid]!r}"
            )


def canonicalize_and_dedup(
    candidates: list[CandidateTriple],
    stage: str,
) -> list[CandidateTriple]:
    """Canonicalize by ``(seed_id, entry_point_id, sorted unique technique IDs)``
    and deduplicate immediately.

    When multiple candidates converge to the same canonical identity
    (e.g. after rule-based technique pruning), produces **one** final
    candidate carrying **all** source origins.  Never first-wins
    provenance — every source candidate's origin is preserved.

    Args:
        candidates: List of candidates after an identity-changing transform.
        stage: Transform stage name for origin records
            (``"expansion"``, ``"rule_pruning"``, or ``"capping"``).

    Returns:
        Deduplicated list of candidates with merged origins.

    Raises:
        ValueError: If two candidates with the same canonical identity
            but different ``candidate_id`` values are found (a hash
            collision or forged ID — should be impossible given
            ``compute_candidate_id`` is deterministic).
    """
    if not candidates:
        return []

    groups: dict[tuple[str, str, tuple[str, ...]], list[CandidateTriple]] = defaultdict(
        list
    )
    for c in candidates:
        groups[_canonical_group_key(c)].append(c)

    result: list[CandidateTriple] = []
    collapsed_count = 0
    for key, group in groups.items():
        if len(group) == 1:
            result.append(_singleton_candidate(group[0]))
            continue

        # Multiple candidates converged — merge origins.
        collapsed_count += len(group) - 1
        result.append(_converged_candidate(group))

    if collapsed_count:
        logger.info(
            "Canonicalize (%s): %d candidates -> %d unique identities (%d collapsed)",
            stage,
            len(candidates),
            len(result),
            collapsed_count,
        )

    return result


def _canonical_group_key(
    c: CandidateTriple,
) -> tuple[str, str, tuple[str, ...]]:
    """Canonical dedup identity of one candidate."""
    return (
        c.seed_id,
        c.entry_point_id,
        tuple(sorted(set(c.atlas_technique_ids))),
    )


def _singleton_candidate(c: CandidateTriple) -> CandidateTriple:
    """Canonicalize a non-collapsed candidate deterministically.

    Canonicalize technique IDs/names/descriptions and origins so
    reversed technique/decision order serializes identically.
    """
    c_ids, c_names, c_descs = _canonicalize_techniques(
        c.atlas_technique_ids,
        c.atlas_technique_names,
        c.atlas_technique_descriptions,
    )
    canonical_origins = _canonicalize_and_dedup_origins(list(c.origins))
    needs_rebuild = c_ids != c.atlas_technique_ids
    if canonical_origins != list(c.origins):
        needs_rebuild = True
    if needs_rebuild:
        c = CandidateTriple.model_validate(
            c.model_dump(mode="python")
            | {
                "atlas_technique_ids": c_ids,
                "atlas_technique_names": c_names,
                "atlas_technique_descriptions": c_descs,
                "origins": tuple(canonical_origins),
            }
        )
    return c


def _converged_candidate(group: list[CandidateTriple]) -> CandidateTriple:
    """Merge one collapsed group: origins plus conflict-free metadata."""
    # Compare technique metadata across all converged candidates
    # before choosing a template.
    _check_converged_technique_metadata(group)
    all_origins: list[CandidateOrigin] = []
    for c in group:
        all_origins.extend(c.origins)
    unique_origins = _canonicalize_and_dedup_origins(all_origins)

    template = group[0]
    _non_provenance_conflicts(template, group[1:], _CONVERGED_NON_PROV_FIELDS)
    merged = CandidateTriple.model_validate(
        template.model_dump(mode="python")
        | {
            "origins": tuple(unique_origins),
        }
    )
    # Canonicalize technique IDs/names/descriptions: sort by ID and
    # align names/descriptions so equivalent inputs serialize identically.
    c_ids, c_names, c_descs = _canonicalize_techniques(
        merged.atlas_technique_ids,
        merged.atlas_technique_names,
        merged.atlas_technique_descriptions,
    )
    if c_ids != merged.atlas_technique_ids:
        merged = CandidateTriple.model_validate(
            merged.model_dump(mode="python")
            | {
                "atlas_technique_ids": c_ids,
                "atlas_technique_names": c_names,
                "atlas_technique_descriptions": c_descs,
            }
        )
    return merged


_CONVERGED_NON_PROV_FIELDS = (
    "seed_id",
    "threat_id",
    "threat_name",
    "attack_pattern_name",
    "attack_pattern_description",
    "entry_point",
    "entry_point_id",
    "direction",
    "risk_card_ref",
    "owasp_llm_ids",
    "controllability",
)


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-26T18:18:24Z","module_hash":"fa969819599608b220e968c3318242ed79d20cf774866e33e40548b3b5ce9099","source_sha256":"6a27c4ac818a3b63925cf52313ca9e23eb8f1b4f2ec1e102f0110f1fd1054cab","functions":[{"id":"func/expand_candidates","name":"expand_candidates","line":35,"end_line":92,"hash":"ca2d890e0a04aadb876ac9a1ed3a2c14e895bcc494eacfd63b37aa035ee46f90"},{"id":"func/_seed_capability_supported","name":"_seed_capability_supported","line":95,"end_line":106,"hash":"15ac1ea908b68a8ca00b3df7cea83b1bf06aa177066352221fcad698340a4043"},{"id":"func/_capability_available","name":"_capability_available","line":109,"end_line":117,"hash":"a36db224403ea91abc0b163d77d6a1aaea3aca8809f5e5f22c2e6447c92d4d4b"},{"id":"func/_capability_eligible_seeds","name":"_capability_eligible_seeds","line":120,"end_line":135,"hash":"868bcaf28c02a86fceb5faaeb3d55c0bc6c2869394b8259d8603df21f4348420"},{"id":"func/_log_seed_eligibility","name":"_log_seed_eligibility","line":138,"end_line":148,"hash":"62b007631f1c7418677a108a4cf82b007e9822637cdb13245ed1baf601ada3e6"},{"id":"func/_attacker_ingress_points","name":"_attacker_ingress_points","line":151,"end_line":174,"hash":"33d2cd6ca867d48fece84b8a92d3fb2c92fd92ae431b4dad85f436f9ffadd2f6"},{"id":"func/_seed_technique_pool","name":"_seed_technique_pool","line":177,"end_line":186,"hash":"2c41d6a92d018c3bd64399bd0566fdadc52fff27180656bd8668ab1b1d90f118"},{"id":"func/_candidate_triple_for","name":"_candidate_triple_for","line":189,"end_line":232,"hash":"cd2ee904a58aa4c1f3522cd0539c24bb30c9e94ef5369757e83ddd0e04a75479"},{"id":"func/_expand_one_seed","name":"_expand_one_seed","line":235,"end_line":253,"hash":"95484f1af2adaedd67396103d9a05ef8df1008e4094afca566db380c3c9627f5"},{"id":"func/_average_technique_count","name":"_average_technique_count","line":256,"end_line":263,"hash":"d1dc236b5800d2a4419ed5e58bc9298d62b86b5d9329d114eec787b67561214e"},{"id":"func/_log_expansion_summary","name":"_log_expansion_summary","line":266,"end_line":284,"hash":"e25a5b151ab5abfa140efbfb5a6357a36d8aa4317c008c26406413d722453892"},{"id":"func/_expansion_stage_record","name":"_expansion_stage_record","line":287,"end_line":301,"hash":"e4fe8212514452cf8d282f638961e758bd8335450824725d156b75830a2e25f6"},{"id":"func/_check_candidate_collisions","name":"_check_candidate_collisions","line":304,"end_line":345,"hash":"4ea2caa7528dbe1182bb5f64e055131cb3f4e3240153ded0f98b386828dffb68"},{"id":"func/_canonicalize_techniques","name":"_canonicalize_techniques","line":348,"end_line":369,"hash":"d6e4a4a19ef3494063a08af4872b4b429704e30f74f14558004a57fcb0d4061f"},{"id":"func/_padded_metadata","name":"_padded_metadata","line":372,"end_line":380,"hash":"cff190c8ba7899f2f42faf310ffb8aa0851a8183e79d03cb5acda2cfc20906c2"},{"id":"func/_technique_metadata_map","name":"_technique_metadata_map","line":383,"end_line":406,"hash":"30662c61280cb146e0d5fa5dedbe47b7d3c6572eb039e0a752a7e62e365f2b06"},{"id":"func/_aligned_metadata","name":"_aligned_metadata","line":409,"end_line":416,"hash":"8a2ffa61cf93dd653b0509065e5d084130338e56f74dfea1f515242c033a1fb1"},{"id":"func/_check_converged_technique_metadata","name":"_check_converged_technique_metadata","line":419,"end_line":430,"hash":"8f46edf3b1f492a537a56961398c153555f80ff03e38ee4f85b2856f4c339086"},{"id":"func/_candidate_technique_map","name":"_candidate_technique_map","line":433,"end_line":445,"hash":"67d9bab48fa9a7b4894f7a61570b286351382687b90a2d308a361c8c7e0a7ccc"},{"id":"func/_technique_map_conflicts","name":"_technique_map_conflicts","line":448,"end_line":465,"hash":"d1cf0953a8abf04aba03688377411e178bca52b95120cbc4348e2023d88a6dfe"},{"id":"func/canonicalize_and_dedup","name":"canonicalize_and_dedup","line":468,"end_line":523,"hash":"bc324da6301bd061cfe9629d29c2980e832bbaebf64622c678533cd51209b1e7"},{"id":"func/_canonical_group_key","name":"_canonical_group_key","line":526,"end_line":534,"hash":"a37180f2dfc788b467561d15a3077eb510f352f9a4a071aa15e17a3d97a6266c"},{"id":"func/_singleton_candidate","name":"_singleton_candidate","line":537,"end_line":562,"hash":"5a095f75f03081953851a2517c4fc9cd009a3882fc6d26cec0746d742a453c50"},{"id":"func/_converged_candidate","name":"_converged_candidate","line":565,"end_line":599,"hash":"ee0011dc414337c84302277896ea9f3dc08cccedae64195891022760b7287d0a"}]}
# mutate4py-manifest-end
