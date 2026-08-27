"""Taxonomy grounding metrics for scenario evaluation.

Validates that threat_ids in attack tree nodes reference valid entries
in the bundled OWASP Agentic Threats data.  Also measures cross-lens
technique agreement between attack tree and behavior spec.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from asago_scenario_generator.data.paths import DATA_ROOT

# Regex for technique IDs: ATLAS like [AML.T0054] or LAAF like [S1], [M2]
_TECHNIQUE_RE = re.compile(r"\[(?:AML\.T\d{4}(?:\.\d{3})?|[SML]\d+)\]")


# Default path to bundled OWASP agentic threats data
_DEFAULT_THREATS_PATH = (
    DATA_ROOT
    / "taxonomies"
    / "owasp-agentic-threats"
    / "owasp-agentic-threats-v1.1.yaml"
)


def _load_valid_threat_ids(threats_path: Path | None = None) -> set[str]:
    """Load the set of valid threat IDs from the OWASP agentic threats file."""
    path = threats_path or _DEFAULT_THREATS_PATH
    if not path.exists():
        return set()
    with open(path) as f:
        data = yaml.safe_load(f)
    threats = data.get("threats", {})
    return set(threats.keys())


def _collect_tree_threat_ids(node: dict[str, Any]) -> list[str]:
    """Recursively collect all threat_id values from attack tree nodes."""
    ids: list[str] = []
    tid = node.get("threat_id")
    if tid:
        ids.append(tid)
    for child in node.get("children") or []:
        ids.extend(_collect_tree_threat_ids(child))
    return ids


def _collect_tree_technique_ids(node: dict[str, Any]) -> list[str]:
    """Recursively collect all technique_id values from attack tree nodes."""
    ids: list[str] = []
    tech_id = node.get("technique_id")
    if tech_id:
        ids.append(tech_id)
    for child in node.get("children") or []:
        ids.extend(_collect_tree_technique_ids(child))
    return ids


def _get_technique_scopes(
    scenario: dict[str, Any], tree_technique_ids: list[str]
) -> tuple[list[str], list[str], bool]:
    """Read explicit named scopes or derive them from a legacy envelope."""
    evidence = scenario.get("technique_scope_evidence")
    if isinstance(evidence, dict):
        return (
            list(dict.fromkeys(evidence.get("scenario_classification_ids") or [])),
            list(dict.fromkeys(evidence.get("projected_step_mapping_ids") or [])),
            bool(evidence.get("legacy_derived", False)),
        )
    chain = scenario.get("faceting", {}).get("taxonomy_chain", {})
    return (
        list(dict.fromkeys(chain.get("atlas_technique_ids") or [])),
        list(dict.fromkeys(tree_technique_ids)),
        True,
    )


def _threat_ref_details(
    scenario_id: str,
    threat_ids: list[str],
    valid_ids: set[str],
) -> tuple[int, int, list[dict[str, str]]]:
    """Valid/dangling counts and dangling details for one scenario."""
    total = 0
    valid = 0
    dangling: list[dict[str, str]] = []
    for tid in threat_ids:
        total += 1
        if tid in valid_ids:
            valid += 1
        else:
            dangling.append(
                {
                    "scenario_id": scenario_id,
                    "threat_id": tid,
                }
            )
    return total, valid, dangling


def _technique_grounding_details(
    scenario_id: str,
    technique_ids: list[str],
    exact_mappings: list[str],
) -> tuple[int, int, list[dict[str, str]]]:
    """Grounded/ungrounded counts and details for one scenario."""
    if not technique_ids:
        return 0, 0, []
    allowed = set(exact_mappings)
    total = 0
    grounded = 0
    ungrounded: list[dict[str, str]] = []
    for tech_id in technique_ids:
        total += 1
        if allowed and tech_id in allowed:
            grounded += 1
        elif not allowed:
            # No seed technique IDs -> any technique_id is ungrounded
            ungrounded.append(
                {
                    "scenario_id": scenario_id,
                    "technique_id": tech_id,
                    "reason": "no_projected_step_mapping_ids",
                }
            )
        else:
            ungrounded.append(
                {
                    "scenario_id": scenario_id,
                    "technique_id": tech_id,
                    "reason": "not_in_projected_step_mappings",
                }
            )
    return total, grounded, ungrounded


def score_grounding(
    scenarios: list[dict[str, Any]],
    threats_path: Path | None = None,
) -> dict[str, Any]:
    """Compute taxonomy grounding metrics across a batch of scenarios.

    Checks:
    - threat_id validity: fraction of threat_ids that map to known OWASP threats
    - dangling reference count: number of invalid threat_ids
    - technique_id grounding: fraction of technique_ids on tree nodes that
      occur in the exact projected-step mapping scope

    Args:
        scenarios: List of scenario dicts (parsed YAML).
        threats_path: Optional path to the OWASP agentic threats file.

    Returns:
        Dict with threat_id_validity (float 0-1), dangling_references (int),
        technique_id_grounding (float 0-1), ungrounded_technique_references (int),
        and details about any invalid references.
    """
    valid_ids = _load_valid_threat_ids(threats_path)

    total_refs = 0
    valid_refs = 0
    dangling: list[dict[str, str]] = []

    # Technique grounding tracking
    total_technique_refs = 0
    grounded_technique_refs = 0
    ungrounded_techniques: list[dict[str, str]] = []
    scenario_classifications: set[str] = set()
    projected_step_mappings: set[str] = set()
    legacy_scope_count = 0

    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id", "unknown")
        tree = scenario.get("attack_tree", {})
        root = tree.get("root", {})

        # --- threat_id validation ---
        threat_ids = _collect_tree_threat_ids(root)
        t_total, t_valid, t_dangling = _threat_ref_details(
            scenario_id, threat_ids, valid_ids
        )
        total_refs += t_total
        valid_refs += t_valid
        dangling.extend(t_dangling)

        # --- technique_id grounding ---
        technique_ids = _collect_tree_technique_ids(root)
        classifications, exact_mappings, legacy_derived = _get_technique_scopes(
            scenario, technique_ids
        )
        scenario_classifications.update(classifications)
        projected_step_mappings.update(exact_mappings)
        legacy_scope_count += int(legacy_derived)

        g_total, g_grounded, g_ungrounded = _technique_grounding_details(
            scenario_id, technique_ids, exact_mappings
        )
        total_technique_refs += g_total
        grounded_technique_refs += g_grounded
        ungrounded_techniques.extend(g_ungrounded)

    validity = valid_refs / total_refs if total_refs > 0 else 1.0
    technique_grounding = (
        grounded_technique_refs / total_technique_refs
        if total_technique_refs > 0
        else 1.0
    )

    result: dict[str, Any] = {
        "threat_id_validity": round(validity, 4),
        "dangling_references": len(dangling),
        "technique_id_grounding": round(technique_grounding, 4),
        "ungrounded_technique_references": len(ungrounded_techniques),
        "scenario_classifications": sorted(scenario_classifications),
        "projected_step_mappings": sorted(projected_step_mappings),
        "legacy_derived_technique_scope_count": legacy_scope_count,
    }
    if dangling:
        result["dangling_details"] = dangling
    if ungrounded_techniques:
        result["ungrounded_technique_details"] = ungrounded_techniques

    return result


# ---------------------------------------------------------------------------
# Cross-lens technique agreement
# ---------------------------------------------------------------------------


def _extract_technique_ids_from_text(text: str) -> set[str]:
    """Extract ATLAS technique IDs from annotated text.

    Looks for patterns like ``[AML.T0054]`` or ``[AML.T0051.000]`` and
    returns the IDs *without* surrounding brackets.
    """
    return {m.group()[1:-1] for m in _TECHNIQUE_RE.finditer(text)}


def _extract_narrative_technique_ids(scenario: dict[str, Any]) -> set[str]:
    """Extract technique IDs from narrative step action and effect text."""
    ids: set[str] = set()
    narrative = scenario.get("narrative", {})
    for step in narrative.get("steps", []):
        for field in ("action", "effect"):
            text = step.get(field, "")
            if text:
                ids |= _extract_technique_ids_from_text(text)
    return ids


def _extract_spec_technique_ids(
    scenario: dict[str, Any],
    gherkin_text: str | None = None,
) -> set[str]:
    """Extract technique IDs from the behavior spec (Gherkin text).

    Uses the ``behavior_spec`` field on the scenario dict first, falling
    back to the separately-loaded *gherkin_text* if provided.
    """
    text = ""
    bs = scenario.get("behavior_spec")
    if isinstance(bs, str):
        text = bs
    elif gherkin_text:
        text = gherkin_text
    if not text:
        return set()
    return _extract_technique_ids_from_text(text)


def _technique_agreement_detail(
    scenario: dict[str, Any],
    gherkin_text: str | None,
    tree_ids: set[str],
    classifications: list[str],
    projected_mappings: list[str],
    legacy_derived: bool,
) -> tuple[float, dict[str, Any]]:
    """Agreement ratio and detail record for one scenario."""
    narrative_ids = _extract_narrative_technique_ids(scenario)
    spec_ids = _extract_spec_technique_ids(scenario, gherkin_text)

    # Jaccard similarity of tree and spec sets only
    union = tree_ids | spec_ids
    if not union:
        # Vacuously agree when no techniques in either lens
        agreement = 1.0
    else:
        intersection = tree_ids & spec_ids
        agreement = len(intersection) / len(union)

    # Build detail record for imperfect agreement
    detail: dict[str, Any] = {
        "technique_agreement": round(agreement, 4),
        "scenario_classifications": classifications,
        "projected_step_mappings": projected_mappings,
        "narrative_references": sorted(narrative_ids),
        "tree_projected_step_mappings": sorted(tree_ids),
        "spec_projected_step_mappings": sorted(spec_ids),
        "legacy_derived": legacy_derived,
    }

    missing_from_tree = spec_ids - tree_ids
    missing_from_spec = tree_ids - spec_ids

    if missing_from_tree:
        detail["missing_from_tree"] = sorted(missing_from_tree)
    if missing_from_spec:
        detail["missing_from_spec"] = sorted(missing_from_spec)

    return agreement, detail


def score_technique_agreement(
    scenarios: list[dict[str, Any]],
    gherkin_files: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compute projected-step mapping agreement between attack tree and spec.

    For each scenario, collects the set of ATLAS technique IDs referenced in:
    1. **Attack tree** -- ``technique_id`` fields on tree nodes
    2. **Behavior spec** -- ``[AML.T0054]`` annotations in Gherkin text

    Agreement is the Jaccard similarity of the two sets (intersection over
    union).  A score of 1.0 means both lenses reference exactly the same
    techniques.

    Scenario classifications and narrative references are reported separately
    for context. They do not affect the score and are never treated as drift
    from exact projected-step mappings.

    Args:
        scenarios: List of scenario dicts (parsed YAML).
        gherkin_files: Optional dict mapping scenario stem to Gherkin text
            (used when the scenario dict lacks a ``behavior_spec`` field).

    Returns:
        Dict with ``mean_technique_agreement`` (float 0-1) and per-scenario
        details for any scenario with agreement < 1.0.
    """
    if gherkin_files is None:
        gherkin_files = {}

    per_scenario: dict[str, dict[str, Any]] = {}
    agreements: list[float] = []

    for scenario in scenarios:
        scenario_id = scenario.get("scenario_id", "unknown")

        tree_root = scenario.get("attack_tree", {}).get("root", {})
        tree_ids = set(_collect_tree_technique_ids(tree_root))

        gherkin_text = gherkin_files.get(scenario_id)
        classifications, projected_mappings, legacy_derived = _get_technique_scopes(
            scenario, list(tree_ids)
        )

        agreement, detail = _technique_agreement_detail(
            scenario,
            gherkin_text,
            tree_ids,
            classifications,
            projected_mappings,
            legacy_derived,
        )
        agreements.append(agreement)

        if agreement < 1.0:
            per_scenario[scenario_id] = detail

    mean_agreement = sum(agreements) / len(agreements) if agreements else 1.0

    result: dict[str, Any] = {
        "mean_technique_agreement": round(mean_agreement, 4),
    }
    if per_scenario:
        result["per_scenario"] = per_scenario

    return result
