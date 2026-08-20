"""Transport normalization for raw attack-tree LLM output.

Everything between the raw YAML/dict transport and the strict
``AttackTree`` model boundary: YAML fence/colon sanitization, projected
step-ID echo normalization for tree leaves, boundary-significant leaf
field cleanup (external preconditions and external impacts), and the
strict typed parse entry point.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import yaml

from asago_scenario_generator.models.attack_tree import AttackTree
from asago_scenario_generator.pipeline.generate.step_ids import (
    normalize_projected_step_ids,
)
from asago_scenario_generator.pipeline.generate.zones import projected_boundary_by_id
from asago_scenario_generator.pipeline.seeds import ScenarioSeed

logger = logging.getLogger(__name__)

_VALID_TECHNIQUE_ID_RE = re.compile(r"^(?:AML\.T\d{4}(?:\.\d{3})?|[SML]\d+)$")


def _sanitize_yaml_colons(raw_yaml: str) -> str:
    """Quote YAML values that contain unquoted colons.

    LLM-generated YAML often contains values like:
        description: Human-in-the-loop: Investigator/Supervisor approval
    which fails parsing because the second colon starts a new mapping.

    This function finds lines matching ``<indent><key>: <value>`` where
    ``<value>`` itself contains a ``:`` and is not already quoted, then wraps
    the value in double quotes (escaping any internal double quotes).

    Lines that are pure mapping keys (value is empty or only whitespace, i.e.
    the value starts on the next indented line) are left untouched.
    """
    # Pattern: optional leading whitespace, a YAML key (``- `` list prefix
    # allowed), then ``: ``, then a value that contains another ``:``.
    # We only act when the value is *not* already wrapped in quotes.
    _KEY_VALUE_RE = re.compile(
        r"^(?P<prefix>\s*(?:-\s+)?)(?P<key>[A-Za-z_][\w.]*):\s+(?P<value>.+)$"
    )

    sanitized_lines: list[str] = []
    for line in raw_yaml.split("\n"):
        m = _KEY_VALUE_RE.match(line)
        if m:
            value = m.group("value")
            # Only act if the value contains another colon AND is not already
            # quoted (single or double).
            if (
                ":" in value
                and not (value.startswith('"') and value.endswith('"'))
                and not (value.startswith("'") and value.endswith("'"))
            ):
                # Escape existing double quotes inside the value, then wrap.
                escaped = value.replace("\\", "\\\\").replace('"', '\\"')
                line = f'{m.group("prefix")}{m.group("key")}: "{escaped}"'
        sanitized_lines.append(line)
    return "\n".join(sanitized_lines)


def _resolve_projected_step_ids(
    result: dict[str, Any],
    canonical_by_id: dict[str, dict[str, Any]],
) -> None:
    """Validate and replace model-supplied realizations from projected IDs.

    Normalizes accepted transport echo shapes (exact strings, ``step_id``
    records, ``step.`` prefixes, ``step_id`` objects) to canonical IDs in
    their original order.  Raises a stable ValueError for unknown,
    ambiguous, or duplicate canonical identities — never TypeError.
    """
    projected_ids = result.get("projected_step_ids", ())
    if not projected_ids:
        return
    normalized = normalize_projected_step_ids(projected_ids, canonical_by_id)
    if isinstance(projected_ids, list):
        result["projected_step_ids"] = list(normalized)
    else:
        result["projected_step_ids"] = normalized
    # Model-supplied realization semantics are transport-only. Replace
    # them before strict validation, including omitted or duplicate
    # records.
    result["realizations"] = [canonical_by_id[sid] for sid in normalized]


def _projection_step_context(
    projection_context: dict[str, Any],
) -> tuple[dict[str, dict[str, Any]], dict[str, Any]]:
    """Index canonical realizations and boundary positions by step ID."""
    selected_steps = _selected_projection_steps(projection_context)
    canonical_by_id = {
        item["step_id"]: item["realization"]
        for item in selected_steps
        if isinstance(item.get("realization"), dict)
    }
    boundary_by_id = projected_boundary_by_id(selected_steps)
    return canonical_by_id, boundary_by_id


def _selected_projection_steps(
    projection_context: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return selected steps with usable string IDs."""
    return [
        item
        for item in projection_context.get("selected_steps", [])
        if isinstance(item, dict) and isinstance(item.get("step_id"), str)
    ]


def _normalize_external_precondition(
    node: dict[str, Any],
    boundary_by_id: dict[str, Any],
) -> None:
    """Clear boundary metadata and invalid mappings from an external leaf."""
    node["zone"] = None
    technique_id = node.get("technique_id")
    if technique_id is not None and not _VALID_TECHNIQUE_ID_RE.fullmatch(
        str(technique_id)
    ):
        node["technique_id"] = None

    projected_ids = tuple(node.get("projected_step_ids", ()))
    if projected_ids and not all(
        boundary_by_id.get(step_id) == "outside" for step_id in projected_ids
    ):
        node["projected_step_ids"] = ()
        node["realizations"] = ()


def _normalize_attack_tree_node(
    node: Any,
    canonical_by_id: dict[str, dict[str, Any]],
    boundary_by_id: dict[str, Any],
) -> Any:
    """Normalize one attack-tree node and recursively process its children."""
    if not isinstance(node, dict):
        return node
    result = dict(node)
    _resolve_projected_step_ids(result, canonical_by_id)
    _normalize_leaf_action(result, boundary_by_id)
    if isinstance(result.get("children"), list):
        result["children"] = [
            _normalize_attack_tree_node(child, canonical_by_id, boundary_by_id)
            for child in result["children"]
        ]
    return result


def _normalize_leaf_action(
    node: dict[str, Any], boundary_by_id: dict[str, Any]
) -> None:
    """Clear boundary-significant leaf fields before strict parsing.

    External preconditions are outside the assessed boundary: their zone is
    always cleared and only outside-boundary leaves may retain a projected
    step mapping.  External impacts also occur outside the assessed AI
    boundary, so their transport zone is cleared — the mapped projected
    step IDs are preserved, and strict projection validation fails closed
    on a non-outside mapping (never silent removal/remap).
    """
    action = node.get("action")
    if not isinstance(action, dict):
        return
    kind = action.get("kind")
    if kind == "external_precondition":
        _normalize_external_precondition(node, boundary_by_id)
    elif kind == "impact" and action.get("boundary") == "external":
        node["zone"] = None


def normalize_attack_tree_transport(
    data: Any,
    projection_context: dict[str, Any] | None,
) -> Any:
    """Normalize relaxed transport fields before strict attack-tree parsing.

    Transport annotations are deliberately normalized before Pydantic sees
    them.  External preconditions are outside the assessed boundary, so their
    zone is always cleared and only outside-boundary leaves may retain a
    projected-step mapping.  The projected-step resolver remains the
    canonical authority for unknown IDs and runs before the boundary rule.
    """
    if projection_context is None or not isinstance(data, dict):
        return data
    normalized = dict(data)
    if isinstance(normalized.get("attack_tree"), dict):
        normalized["attack_tree"] = normalize_attack_tree_transport(
            normalized["attack_tree"], projection_context
        )
        return normalized

    canonical_by_id, boundary_by_id = _projection_step_context(projection_context)
    if isinstance(normalized.get("root"), dict):
        normalized["root"] = _normalize_attack_tree_node(
            normalized["root"], canonical_by_id, boundary_by_id
        )
    return normalized


def _parse_attack_tree_yaml(
    raw: str,
    seed: ScenarioSeed,
    projection_context: dict[str, Any] | None = None,
) -> AttackTree:
    """Parse YAML text into an AttackTree model.

    Strips markdown code fences if present, then validates through Pydantic.
    If the initial parse fails due to YAML syntax errors (commonly from
    unquoted colons in LLM-generated values), the raw text is sanitized
    and parsing is retried once.
    """
    cleaned = raw.strip()
    if cleaned.startswith("```"):
        lines = cleaned.split("\n")
        lines = lines[1:]  # drop opening fence
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        cleaned = "\n".join(lines)

    try:
        data = yaml.safe_load(cleaned)
    except yaml.YAMLError:
        logger.warning(
            "YAML parse failed for seed %s; attempting colon sanitization",
            seed.seed_id,
        )
        sanitized = _sanitize_yaml_colons(cleaned)
        try:
            data = yaml.safe_load(sanitized)
        except yaml.YAMLError as exc:
            raise yaml.YAMLError(
                f"Failed to parse attack tree YAML for seed {seed.seed_id} "
                f"even after colon sanitization: {exc}"
            ) from exc

    if isinstance(data, dict) and "attack_tree" in data:
        data = data["attack_tree"]

    # Strict typed normal generation: do NOT repair single-child AND/OR
    # gates before Pydantic validation.  Malformed gates must be rejected
    # by the model validator so the caller retries or rejects — no silent
    # structural mutation (cmps.9 review correction 3).
    # repair_attack_tree_dict is retained only for post-pruning repair in
    # validation.py (explicit parsimony boundary).

    data = normalize_attack_tree_transport(data, projection_context)
    return AttackTree.model_validate(data)
