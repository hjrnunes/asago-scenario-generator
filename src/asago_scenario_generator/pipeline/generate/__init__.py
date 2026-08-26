"""Stage 4: Scenario Generation.

Four sequential LLM calls per scenario seed produce a complete multi-layered
ScenarioEnvelope:

  Call 0  Actor Profile   -- threat actor type, motivation, capability, resources
  Call 1  Narrative       -- zone-annotated attack prose (grounded in actor)
  Call 2  Attack Tree     -- AND/OR YAML tree
  Call 3  Behavior Spec   -- Gherkin with native keywords

This package was split from a monolithic ``generate.py`` for maintainability.
All previously importable names are re-exported here so existing call sites
(``from asago_scenario_generator.pipeline.generate import X``) continue to work
unchanged.
"""

from __future__ import annotations

# External dependencies used in patches
from asago_scenario_generator.llm.client import LLMClient

# actor
from asago_scenario_generator.pipeline.generate.actor import (
    ActorAccessViolation,
    Call0Response,
    _call_actor_profile,
    _enforce_capability_floor,
    _max_capability_level,
    _normalize_actor_type,
    _normalize_capability_level,
    _validate_actor_type,
    build_actor_access_provenance,
    build_call0_context,
    compute_compatible_actor_types,
    compute_minimum_capability_level,
    validate_actor_access_provenance,
)

# assembly
from asago_scenario_generator.pipeline.generate.assembly import (
    GenerationError,
    ScenarioForgeIntegrityError,
    _assemble_envelope,
    _call_log_entry,
    _call_log_entry_error,
    _call_metadata,
    compute_artifact_hash,
    compute_scenario_id,
    generate_run_id,
    generate_scenario,
    replace_scenario_outputs,
    write_call_log,
    write_scenario_outputs,
)

# ---------------------------------------------------------------------------
# Re-exports — every name that was importable from the old generate.py
# ---------------------------------------------------------------------------
# constants
from asago_scenario_generator.pipeline.generate.constants import (
    _ACTOR_GOAL_INCOMPATIBLE,
    _ADVERSARIAL_ONLY_THREATS,
    _ASSERTIONS_MARKER,
    _CAPABILITY_ORDER,
    _CONSISTENCY_MAX_RETRIES,
    _ENTRY_POINT_ZONE_KEYWORDS,
    _GENERATOR_VERSION,
    _OWASP_LLM_NAMES,
    _PATTERN_STOP_WORDS,
    _PHASE_KEYWORDS,
    _THREAT_GOAL_EXCLUSIONS,
    _ZONE_TO_DEFAULT_MAESTRO,
    ALL_ACTOR_TYPES,
    CHAIN_TECHNIQUE_PAIRS,
    THREAT_VIOLATION_CATEGORY,
    compute_leaf_budget,
)

# diversity
from asago_scenario_generator.pipeline.generate.diversity import (
    _format_structural_exclusions,
    assign_entry_point,
    compute_entry_point_affinity,
    extract_narrative_keywords,
    extract_structural_pattern,
    get_overused_entry_points,
    get_overused_patterns,
    get_overused_structural_patterns,
)

# gherkin
from asago_scenario_generator.pipeline.generate.gherkin import (
    MAX_OR_PATHS,
    _build_gherkin_template,
    _call_behavior_spec,
    _collect_leaf_nodes_dfs,
    _enumerate_paths,
    build_call3_context,
)

# goals
from asago_scenario_generator.pipeline.generate.goals import (
    _build_attack_goal_context_block,
    _fair_share_pick,
    compute_compatible_goal_ids,
    filter_sub_goals_by_zones,
    get_all_sub_goals,
    select_attack_goal,
)

# narrative
from asago_scenario_generator.pipeline.generate.narrative import (
    Call1Response,
    Call1Step,
    _call_narrative,
    _is_latin_or_common,
    _map_call1_to_narrative,
    _sanitize_narrative,
    _sanitize_non_latin,
    build_call1_context,
    build_call1_response_model,
)
from asago_scenario_generator.pipeline.generate.narrative_semantics import (
    _derive_zone_sequence,
)

# ontology
from asago_scenario_generator.pipeline.generate.ontology import (
    _build_ontology_context,
    _build_technique_context_block,
    _format_taxonomy_ids,
    _lookup_entry_point_controllability,
    _lookup_entry_point_direction,
    build_kc_definitions_block,
)

# priority
from asago_scenario_generator.pipeline.generate.priority import (
    _compute_priority,
    _continuous_technique_maturity_score,
    _continuous_tree_complexity_score,
    _continuous_zone_score,
    _extract_maestro_layers_from_tree,
    _extract_structural_exposures_from_tree,
    _heuristic_attack_complexity,
    _heuristic_risk_impact,
    _heuristic_risk_likelihood,
    _heuristic_technique_maturity,
    _tree_depth,
    _tree_node_count,
)

# tree
from asago_scenario_generator.pipeline.generate.tree import (
    _build_tree_skeleton,
    _call_attack_tree,
    _call_attack_tree_once,
    _collect_threat_ids_from_tree,
    _format_skeleton_yaml,
    _validate_mandatory_leaves,
    _warn_dominant_threat_id_crossref,
    build_call2_context,
)

# tree_transport
from asago_scenario_generator.pipeline.generate.tree_transport import (
    _parse_attack_tree_yaml,
    _sanitize_yaml_colons,
    normalize_attack_tree_transport,
)

# tree_validation
from asago_scenario_generator.pipeline.generate.tree_validation import (
    _check_consistency,
    _check_non_actionable_leaves,
    _count_leaves,
    _strip_non_skeleton_techniques,
    _strip_non_skeleton_techniques_node,
    _validate_technique_zone_compatibility,
    _validate_technique_zone_node,
    _validate_tree_against_projection,
)

# step_ids
from asago_scenario_generator.pipeline.generate.step_ids import (
    normalize_projected_step_ids,
)

# zones
from asago_scenario_generator.pipeline.generate.zones import (
    _collect_zones_from_tree,
    _enforce_zones_attack_tree,
    _enforce_zones_narrative,
    active_narrative_zones,
    enforce_narrative_projection_zones,
    projected_boundary_by_id,
    validate_attack_tree_zones,
)

from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl,
    RetryDirective,
    StageAttemptFailure,
    StageCallEvidence,
)
from asago_scenario_generator.pipeline.generate.stages import (
    ActorStageResult,
    BehaviorStageResult,
    GenerationRequest,
    NarrativeStageResult,
    PreparedGeneration,
    TreeStageResult,
    assemble_final_envelope,
    generate_actor_stage,
    generate_behavior_stage,
    generate_narrative_stage,
    generate_tree_stage,
    prepare_generation,
)

__all__ = [
    # constants
    "ALL_ACTOR_TYPES",
    "CHAIN_TECHNIQUE_PAIRS",
    # gherkin
    "MAX_OR_PATHS",
    "THREAT_VIOLATION_CATEGORY",
    "_ACTOR_GOAL_INCOMPATIBLE",
    "_ADVERSARIAL_ONLY_THREATS",
    "_ASSERTIONS_MARKER",
    "_CAPABILITY_ORDER",
    "_CONSISTENCY_MAX_RETRIES",
    "_ENTRY_POINT_ZONE_KEYWORDS",
    "_GENERATOR_VERSION",
    "_OWASP_LLM_NAMES",
    "_PATTERN_STOP_WORDS",
    "_PHASE_KEYWORDS",
    "_THREAT_GOAL_EXCLUSIONS",
    "_ZONE_TO_DEFAULT_MAESTRO",
    "ActorAccessViolation",
    "ActorStageResult",
    "BehaviorStageResult",
    "CausalRetryControl",
    "GenerationRequest",
    "NarrativeStageResult",
    "PreparedGeneration",
    "RetryDirective",
    "StageAttemptFailure",
    "StageCallEvidence",
    "TreeStageResult",
    "active_narrative_zones",
    "enforce_narrative_projection_zones",
    "projected_boundary_by_id",
    # actor
    "Call0Response",
    # narrative
    "Call1Response",
    "Call1Step",
    # assembly
    "GenerationError",
    # External dependencies
    "LLMClient",
    "ScenarioForgeIntegrityError",
    "_assemble_envelope",
    # goals
    "_build_attack_goal_context_block",
    "_build_gherkin_template",
    # ontology
    "_build_ontology_context",
    "_build_technique_context_block",
    # tree
    "_build_tree_skeleton",
    "_call_actor_profile",
    "_call_attack_tree",
    "_call_attack_tree_once",
    "_call_behavior_spec",
    "_call_log_entry",
    "_call_log_entry_error",
    "_call_metadata",
    "_call_narrative",
    "_check_consistency",
    "_check_non_actionable_leaves",
    "_collect_leaf_nodes_dfs",
    "_collect_threat_ids_from_tree",
    # zones
    "_collect_zones_from_tree",
    # priority
    "_compute_priority",
    "_continuous_technique_maturity_score",
    "_continuous_tree_complexity_score",
    "_continuous_zone_score",
    "_count_leaves",
    "_derive_zone_sequence",
    "_enforce_capability_floor",
    "_enforce_zones_attack_tree",
    "_enforce_zones_narrative",
    "_enumerate_paths",
    "_extract_maestro_layers_from_tree",
    "_extract_structural_exposures_from_tree",
    "_fair_share_pick",
    "_format_skeleton_yaml",
    # diversity
    "_format_structural_exclusions",
    "_format_taxonomy_ids",
    "_heuristic_attack_complexity",
    "_heuristic_risk_impact",
    "_heuristic_risk_likelihood",
    "_heuristic_technique_maturity",
    "_is_latin_or_common",
    "_lookup_entry_point_controllability",
    "_lookup_entry_point_direction",
    "_map_call1_to_narrative",
    "_max_capability_level",
    "_normalize_actor_type",
    "_normalize_capability_level",
    "_parse_attack_tree_yaml",
    "normalize_attack_tree_transport",
    "normalize_projected_step_ids",
    "_sanitize_narrative",
    "_sanitize_non_latin",
    "_sanitize_yaml_colons",
    "_strip_non_skeleton_techniques",
    "_strip_non_skeleton_techniques_node",
    "_tree_depth",
    "_tree_node_count",
    "_validate_actor_type",
    "_validate_mandatory_leaves",
    "_validate_technique_zone_compatibility",
    "_validate_technique_zone_node",
    "_validate_tree_against_projection",
    "_warn_dominant_threat_id_crossref",
    "assemble_final_envelope",
    "assign_entry_point",
    "build_actor_access_provenance",
    "build_call0_context",
    "build_call1_context",
    "build_call1_response_model",
    "build_call2_context",
    "build_call3_context",
    "build_kc_definitions_block",
    "compute_artifact_hash",
    "compute_compatible_actor_types",
    "compute_compatible_goal_ids",
    "compute_entry_point_affinity",
    "compute_leaf_budget",
    "compute_minimum_capability_level",
    "compute_scenario_id",
    "extract_narrative_keywords",
    "extract_structural_pattern",
    "filter_sub_goals_by_zones",
    "generate_run_id",
    "generate_actor_stage",
    "generate_behavior_stage",
    "generate_narrative_stage",
    "generate_scenario",
    "generate_tree_stage",
    "prepare_generation",
    "get_all_sub_goals",
    "get_overused_entry_points",
    "get_overused_patterns",
    "get_overused_structural_patterns",
    "replace_scenario_outputs",
    "select_attack_goal",
    "validate_actor_access_provenance",
    "validate_attack_tree_zones",
    "write_call_log",
    "write_scenario_outputs",
]
