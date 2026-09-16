"""Stage 7 — Validators (stage-local + end-to-end traceability).

Stage-local validators check BDI grounding, vulnerability completeness,
tree branch coverage, and Gherkin structure. End-to-end traceability
validation checks the full provenance chain:
provenance root → loss → hazard → constraint → responsibility → CA → ICA → scenario.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.enriched_threat_set import (
    EnrichedThreatSet,
    StructuralThreat,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.models.scenario_envelope import (
    GherkinSpec,
    ScenarioEnvelope,
)
from asago_scenario_generator.stpa.models.scenario_spec import ScenarioSpec

__all__ = [
    "ValidationResult",
    "TraceabilityError",
    "validate_bdi_grounding",
    "validate_vulnerability_completeness",
    "validate_active_access_grounding",
    "validate_tree_branch_coverage",
    "validate_tree_factor_evidence_coverage",
    "validate_gherkin_structure",
    "validate_gherkin_correspondence",
    "validate_loss_hazard_id_references",
    "validate_attack_tree_root_label",
    "validate_tree_id_references",
    "validate_traceability",
    "detect_orphan_elements",
    "detect_orphan_icas",
    "collect_valid_tree_ids",
    "count_branch_categories",
    "get_branch_categories",
    "BRANCH_CATEGORIES",
]

BRANCH_CATEGORIES = ["controller_side", "path_side", "coordination_gap"]

LEGAL_PROVENANCE_ROOTS = {"risk_card", "use_case", "critic_derived"}

# (regex pattern, label) for tree ID validation
_TREE_ID_SPECS: list[tuple[str, str]] = [
    (r"PM-\d+-\d+", "PM"),
    (r"FB-\d+-\d+", "FB"),
    (r"CA-\d+-\d+", "CA"),
    (r"RESP-\d+", "RESP"),
    (r"CL-\d+", "CL"),
    (r"CM-\d+", "CM"),
]

_ACTIVE_ACCESS_RE = re.compile(
    r"\b(?:attacker|adversary)\b[^.\n]{0,80}\b"
    r"(?:change(?:s|d|ing)?|cause(?:s|d|ing)?|force(?:s|d|ing)?|"
    r"use(?:s|d|ing)?|send(?:s|ing)?|sent|trigger(?:s|ed|ing)?)\b|"
    r"\b(?:inject(?:s|ed|ing)?|poison(?:s|ed|ing)?|"
    r"manipulat(?:e|es|ed|ing)|suppress(?:es|ed|ing)?|"
    r"intercept(?:s|ed|ing)?|spoof(?:s|ed|ing)?|"
    r"hijack(?:s|ed|ing)?|steal(?:s|ing)?|stolen|"
    r"flood(?:s|ed|ing)?)\b",
    re.IGNORECASE,
)


@dataclass
class ValidationResult:
    """Result of a validation check."""

    passed: bool
    errors: list[str] = field(default_factory=list)

    @classmethod
    def success(cls) -> ValidationResult:
        return cls(passed=True, errors=[])

    @classmethod
    def failure(cls, errors: list[str]) -> ValidationResult:
        return cls(passed=False, errors=errors)


@dataclass
class TraceabilityError:
    """A traceability validation error for a single scenario."""

    scenario_id: str
    broken_link: str
    expected: str
    actual: str


def validate_bdi_grounding(
    scenario_spec: ScenarioSpec,
    control_structure: ControlStructure,
) -> ValidationResult:
    """Validate that defender BDI references valid control structure IDs.

    Checks:
    - Every DefenderBelief.pm_id references a valid PM.
    - Every DefenderDesire.resp_id references a valid RESP.
    - Every DefenderIntention.ca_id references a valid CA.
    - target_controller references a valid RESP.
    - target_control_action references a valid CA belonging to target_controller.

    Args:
        scenario_spec: The scenario spec to validate.
        control_structure: The control structure to validate against.

    Returns:
        A :class:`ValidationResult`.
    """
    errors: list[str] = []
    try:
        scenario_spec.validate_against(control_structure)
    except ValueError as e:
        errors.append(str(e))
    return ValidationResult(passed=len(errors) == 0, errors=errors)


def validate_vulnerability_completeness(
    scenario_spec: ScenarioSpec,
) -> ValidationResult:
    """Validate that every defender belief has a non-empty vulnerability.

    Args:
        scenario_spec: The scenario spec to validate.

    Returns:
        A :class:`ValidationResult`.
    """
    errors: list[str] = []
    for belief in scenario_spec.defender_bdi.beliefs:
        if not belief.vulnerability or not belief.vulnerability.strip():
            errors.append(
                f"DefenderBelief {belief.pm_id} has an empty vulnerability annotation."
            )
    return ValidationResult(passed=len(errors) == 0, errors=errors)


def validate_active_access_grounding(
    scenario_spec: ScenarioSpec,
    *artifacts: str,
) -> ValidationResult:
    """Reject asserted attacker access without capability or labelled assumption.

    The immutable scenario context is the authority for reachability.  Active
    access language is acceptable only when that context carries a reachable
    capability, or when the scenario has an explicit bounded-assumption factor
    and the affected artifact labels the claim as an assumption.
    """
    if _context_permits_active_access(scenario_spec):
        return ValidationResult.success()
    errors = _unsupported_active_access_errors(scenario_spec, artifacts)
    return ValidationResult(passed=not errors, errors=errors)


def _context_permits_active_access(scenario_spec: ScenarioSpec) -> bool:
    """Return whether exact reachability evidence permits active prose."""
    context = scenario_spec.scenario_context
    return context is None or bool(context.reachable_capabilities)


def _unsupported_active_access_errors(
    scenario_spec: ScenarioSpec,
    artifacts: tuple[str, ...],
) -> list[str]:
    """Collect ungrounded active-access claims from rendered artifacts."""
    has_bounded_assumption = any(
        factor.evidence_status == "bounded_assumption"
        for factor in scenario_spec.causal_factors
    )
    errors: list[str] = []
    for index, artifact in enumerate(artifacts, start=1):
        claims = _active_access_claims(artifact)
        if not claims or _is_labelled_assumption(artifact, has_bounded_assumption):
            continue
        errors.append(
            "Scenario artifact "
            f"{index} asserts unsupported active access: {', '.join(claims)}."
        )
    return errors


def _active_access_claims(artifact: str) -> list[str]:
    """Return canonical matched active-access phrases from one artifact."""
    return sorted({match.group(0) for match in _ACTIVE_ACCESS_RE.finditer(artifact)})


def _is_labelled_assumption(artifact: str, has_bounded_assumption: bool) -> bool:
    """Return whether an active claim is visibly bounded by supplied evidence."""
    return has_bounded_assumption and "assum" in artifact.lower()


def count_branch_categories(attack_tree: dict) -> int:
    """Count how many of the 3 branch categories are used in the tree."""
    return len(get_branch_categories(attack_tree))


def get_branch_categories(attack_tree: dict) -> set[str]:
    """Get the set of branch categories used in the tree."""
    branches = attack_tree.get("branches", [])
    categories: set[str] = set()
    for branch in branches:
        cat = branch.get("category", "")
        if cat in BRANCH_CATEGORIES:
            categories.add(cat)
    return categories


def validate_tree_branch_coverage(attack_tree: dict) -> ValidationResult:
    """Validate that the attack tree uses at least one supported category.

    Args:
        attack_tree: The attack tree dict (YAML-serializable).

    Returns:
        A :class:`ValidationResult`.
    """
    count = count_branch_categories(attack_tree)
    if count < 1:
        return ValidationResult.failure(
            ["Attack tree uses no supported branch category; need at least 1."]
        )
    return ValidationResult.success()


def validate_tree_factor_evidence_coverage(
    attack_tree: dict,
    scenario_spec: ScenarioSpec,
) -> ValidationResult:
    """Require an attack tree to cover declared factors with exact evidence.

    Branch-category counts are a presentation property, not evidence that a
    tree explains a scenario.  For a contextual Stage 5 result, the factor
    selected by the execution route must occur by its exact structural source
    ID (or by its complete normalized evidence phrase), and structural
    references outside the selected path are rejected.  Additional declared
    factors may remain provenance-only. Empty-factor legacy fixtures are kept
    valid for compatibility with the historical diagnostic adapter.

    The check is deliberately structural: it never treats an adversarial verb
    as proof of access and never imports taxonomy mechanism text into the
    allowed evidence set.
    """
    factors = _selected_tree_factors(scenario_spec)
    if not factors:
        return ValidationResult.success()

    tree_text = _flatten_tree_to_text(attack_tree)
    normalized_tree = _normalize_evidence_text(tree_text)
    errors: list[str] = []
    for factor in factors:
        source_id = factor.source_id
        if source_id in tree_text:
            continue
        evidence = _normalize_evidence_text(factor.description)
        if evidence and evidence in normalized_tree:
            continue
        errors.append(
            f"Attack tree does not cover declared causal factor {source_id} "
            "with its declared evidence."
        )

    allowed_refs = _allowed_tree_evidence_refs(scenario_spec)
    for reference in _structural_tree_references(tree_text):
        if reference in allowed_refs:
            continue
        errors.append(
            f"Attack tree references unsupported causal bridge {reference}; "
            "only selected-path and declared-factor evidence is allowed."
        )
    return ValidationResult(passed=not errors, errors=errors)


def _selected_tree_factors(scenario_spec: ScenarioSpec) -> tuple[object, ...]:
    """Return the route-selected factor, leaving provenance-only factors out."""
    factors = tuple(scenario_spec.causal_factors)
    contract = scenario_spec.execution_contract
    factor_id = getattr(getattr(contract, "delivery", None), "factor_id", None)
    if isinstance(factor_id, str) and factor_id.startswith("CF-"):
        try:
            index = int(factor_id[3:]) - 1
        except ValueError:
            index = -1
        if 0 <= index < len(factors):
            return (factors[index],)
    return factors[:1]


def _normalize_evidence_text(value: str) -> str:
    """Normalize prose enough for exact phrase evidence matching."""
    return " ".join(re.findall(r"[a-z0-9]+", value.lower().replace("-", " ")))


def _structural_tree_references(tree_text: str) -> set[str]:
    """Return all closed structural IDs mentioned by one tree."""
    return {
        match.group(0)
        for pattern, _label in _TREE_ID_SPECS
        for match in re.finditer(pattern, tree_text)
    }


def _allowed_tree_evidence_refs(scenario_spec: ScenarioSpec) -> set[str]:
    """Return exact references the selected scenario tree may explain."""
    allowed = {factor.source_id for factor in scenario_spec.causal_factors}
    allowed.add(scenario_spec.target_control_action)
    context = scenario_spec.scenario_context
    if context is None:
        return allowed
    path = context.target_control_path
    allowed.update(item.element_id for item in path.process_model_parts)
    allowed.update(item.element_id for item in path.feedback)
    allowed.update(item.action_id for item in path.related_control_actions)
    allowed.add(path.control_action.action_id)
    allowed.add(path.controller.element_id)
    if path.responsibility is not None:
        allowed.add(path.responsibility.element_id)
    if path.coordination_path is not None:
        coordination = path.coordination_path
        allowed.update(
            {
                coordination.link_id,
                coordination.source.element_id,
                coordination.target.element_id,
                coordination.shared_process_model.element_id,
                coordination.coordination_mechanism.element_id,
            }
        )
    return allowed


def validate_gherkin_structure(gherkin: GherkinSpec | str) -> ValidationResult:
    """Validate that Gherkin has should/but structure and PM references.

    Accepts either a structured :class:`GherkinSpec` or a raw Gherkin
    string (for backward compatibility).

    When given a :class:`GherkinSpec`, validates the structured fields:
    - ``given`` is non-empty, readable, and references process model states (PM-*).
    - ``when`` is non-empty and names a triggering event.
    - ``then_expected`` is non-empty and contains a "should" step.
    - ``then_actual`` is non-empty and contains a "but" step distinct from the
      expected safe behavior.

    When given a ``str``, validates the text for:
    - Contains a `Then ... should ...` line.
    - Contains a `But` line.
    - Given steps reference process model states (PM-* IDs or descriptions).

    Args:
        gherkin: The Gherkin spec (structured or raw text) to validate.

    Returns:
        A :class:`ValidationResult`.
    """
    if isinstance(gherkin, GherkinSpec):
        return _validate_gherkin_spec(gherkin)
    return _validate_gherkin_text(gherkin)


_PM_ID_RE = re.compile(r"PM-\d+-\d+")


def _validate_gherkin_spec(spec: GherkinSpec) -> ValidationResult:
    """Validate a structured :class:`GherkinSpec`."""
    errors: list[str] = []
    errors.extend(_check_step_collection("given", spec.given, "Given"))
    errors.extend(_check_step_collection("when", spec.when, "When"))
    errors.extend(_check_then_expected(spec.then_expected))
    errors.extend(_check_then_actual(spec.then_actual))
    errors.extend(_check_given_pm_refs(spec.given))
    errors.extend(_check_expected_actual_separation(spec))
    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _check_step_collection(
    field_name: str, steps: list[str], keyword: str
) -> list[str]:
    """Require readable non-empty Given/When step collections."""
    if not steps:
        return [f"Gherkin {field_name} steps are empty; add a domain {field_name}."]
    errors: list[str] = []
    for step in steps:
        if not isinstance(step, str) or not step.strip():
            errors.append(f"Gherkin {field_name} contains a blank step.")
            continue
        if not re.match(rf"^(?:{keyword}|And)\s+\S", step.strip(), re.IGNORECASE):
            errors.append(
                f"Gherkin {field_name} step must start with '{keyword}' or 'And'."
            )
    return errors


def _check_then_expected(steps: list[str]) -> list[str]:
    """Validate that then_expected has a 'should' clause."""
    if not steps:
        return [
            "Gherkin missing a 'Then ... should ...' step (then_expected is empty)."
        ]
    if not any(re.search(r"\bshould\b", step, re.IGNORECASE) for step in steps):
        return ["Gherkin then_expected missing a 'should' clause."]
    if any(step.strip().lower().startswith("but") for step in steps):
        return ["Gherkin expected steps must not contain a 'But' unsafe alternative."]
    invalid = [
        step
        for step in steps
        if not re.match(r"^(?:Then|And)\s+\S", step.strip(), re.IGNORECASE)
    ]
    if invalid:
        return ["Gherkin expected steps must start with 'Then' or 'And'."]
    return []


def _check_then_actual(steps: list[str]) -> list[str]:
    """Validate that then_actual has a 'But' clause."""
    if not steps:
        return ["Gherkin missing a 'But' step (then_actual is empty)."]
    if not any(step.lower().startswith("but") for step in steps):
        return ["Gherkin then_actual missing a 'But' clause."]
    invalid = [
        step
        for index, step in enumerate(steps)
        if not re.match(
            r"^(?:But|And)\s+\S" if index else r"^But\s+\S",
            step.strip(),
            re.IGNORECASE,
        )
    ]
    if invalid:
        return ["Gherkin unsafe steps must start with 'But' or 'And'."]
    return []


def _check_expected_actual_separation(spec: GherkinSpec) -> list[str]:
    """Reject one outcome being represented as both expected and unsafe."""
    expected = {
        _normalize_gherkin_step(re.sub(r"^Then\s+", "", step, flags=re.IGNORECASE))
        for step in spec.then_expected
    }
    actual = {
        _normalize_gherkin_step(re.sub(r"^But\s+", "", step, flags=re.IGNORECASE))
        for step in spec.then_actual
    }
    overlap = sorted(expected & actual)
    if overlap:
        return [
            "Gherkin expected and unsafe steps represent simultaneous outcomes: "
            + ", ".join(overlap)
        ]
    return []


def _normalize_gherkin_step(step: str) -> str:
    """Normalize a step for correspondence and contradiction comparisons."""
    return " ".join(step.lower().split())


def _check_given_pm_refs(steps: list[str]) -> list[str]:
    """Validate that given steps reference process model states (PM-*)."""
    if not steps or not any(_PM_ID_RE.search(step) for step in steps):
        return ["Gherkin Given steps do not reference a process model state (PM-*)."]
    return []


def _validate_gherkin_text(gherkin_text: str) -> ValidationResult:
    """Validate raw Gherkin text for should/but structure and PM references."""
    errors: list[str] = []
    text_lower = gherkin_text.lower()

    has_then_should = bool(re.search(r"then.*should", text_lower))
    if not has_then_should:
        errors.append("Gherkin missing a 'Then ... should ...' line.")

    has_but = bool(re.search(r"^\s*but\s", gherkin_text, re.IGNORECASE | re.MULTILINE))
    if not has_but:
        errors.append("Gherkin missing a 'But' line.")

    has_pm_ref = bool(re.search(r"PM-\d+-\d+", gherkin_text))
    if not has_pm_ref:
        errors.append(
            "Gherkin Given steps do not reference a process model state (PM-*)."
        )

    if re.search(r"^\s*feature\s*:", gherkin_text, re.IGNORECASE | re.MULTILINE):
        errors.extend(_check_native_feature_syntax(gherkin_text))

    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _check_native_feature_syntax(gherkin_text: str) -> list[str]:
    """Validate the small native feature subset emitted by the producer."""
    lines = [line.strip() for line in gherkin_text.splitlines() if line.strip()]
    feature_lines = [line for line in lines if line.lower().startswith("feature:")]
    scenario_lines = [line for line in lines if line.lower().startswith("scenario:")]
    errors: list[str] = []
    if len(feature_lines) != 1:
        errors.append("Native Gherkin must contain exactly one 'Feature:' line.")
    if len(scenario_lines) != 1:
        errors.append("Native Gherkin must contain exactly one 'Scenario:' line.")
    for line in lines:
        if line.lower().startswith(("feature:", "scenario:")):
            if line.split(":", 1)[1].strip() == "":
                errors.append("Native Gherkin headings must have non-empty names.")
            continue
        if not re.match(r"^(?:Given|When|Then|And|But)\s+\S", line, re.IGNORECASE):
            errors.append(
                "Native Gherkin contains a non-step line outside its headings: "
                f"{line!r}."
            )
    return errors


def validate_gherkin_correspondence(
    structured: GherkinSpec,
    native_feature: str,
) -> ValidationResult:
    """Verify native ``.feature`` text is the exact structured rendering.

    The producer has one authoritative structured representation.  Native
    output is a transport rendering, so accepting step drift would publish two
    different scenario meanings.
    """
    errors = _check_native_feature_syntax(native_feature)
    expected = _normalized_feature_lines(structured.to_feature_text())
    actual = _normalized_feature_lines(native_feature)
    if expected != actual:
        errors.append(
            "Native Gherkin does not correspond to the structured Gherkin steps."
        )
    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _normalized_feature_lines(text: str) -> list[str]:
    """Normalize indentation and blank lines without changing step content."""
    return [
        " ".join(line.strip().split()) for line in text.splitlines() if line.strip()
    ]


# Regex patterns for Loss and Hazard ID extraction
_LOSS_ID_RE = re.compile(r"L-\d+")
_HAZARD_ID_RE = re.compile(r"H-\d+")


def validate_loss_hazard_id_references(
    gherkin: GherkinSpec | str,
    loss_analysis: LossAnalysis,
) -> ValidationResult:
    """Check that all L-* and H-* references in Gherkin are valid.

    Extracts all L-\\* and H-\\* patterns from the Gherkin text (using
    ``gherkin_raw`` for :class:`GherkinSpec` input, or the text directly
    for ``str`` input) and checks each against the valid IDs from the
    loss analysis.

    Args:
        gherkin: The Gherkin spec (structured or raw text) to check.
        loss_analysis: The loss analysis with valid Loss and Hazard IDs.

    Returns:
        A :class:`ValidationResult` with errors for hallucinated IDs.
    """
    if isinstance(gherkin, GherkinSpec):
        text = gherkin.to_feature_text()
    else:
        text = gherkin

    valid_loss_ids = {
        loss.loss_id
        for loss in loss_analysis.risk_card_losses + loss_analysis.use_case_losses
    }
    valid_hazard_ids = {hazard.hazard_id for hazard in loss_analysis.hazards}

    errors: list[str] = []
    errors.extend(_find_hallucinated_ids(text, _LOSS_ID_RE, valid_loss_ids, "Loss"))
    errors.extend(
        _find_hallucinated_ids(text, _HAZARD_ID_RE, valid_hazard_ids, "Hazard")
    )

    return ValidationResult(passed=len(errors) == 0, errors=errors)


def _find_hallucinated_ids(
    text: str,
    id_regex: re.Pattern,
    valid_ids: set[str],
    label: str,
) -> list[str]:
    """Find IDs in *text* matching *id_regex* that are not in *valid_ids*."""
    errors: list[str] = []
    for match in id_regex.finditer(text):
        id_val = match.group()
        if id_val not in valid_ids:
            errors.append(f"Gherkin references hallucinated {label} ID '{id_val}'.")
    return errors


def validate_attack_tree_root_label(
    attack_tree: dict,
    ica_type: str,
    ca_id: str,
) -> ValidationResult:
    """Check that attack tree root matches the expected format.

    Expected root label: ``f"Induce ICA {ica_type} on {ca_id}"``.

    The check is case-insensitive on "Induce ICA" but exact on the
    ICA type enum value and the CA ID.

    Args:
        attack_tree: The attack tree dict with a ``root`` key.
        ica_type: The expected UCAType value (e.g. ``NOT_PROVIDED``).
        ca_id: The expected control action ID (e.g. ``CA-1-1``).

    Returns:
        A :class:`ValidationResult`.
    """
    root = _extract_root(attack_tree)
    expected = f"Induce ICA {ica_type} on {ca_id}"

    if not root or not root.strip():
        return ValidationResult.failure(
            [f"Attack tree root is empty; expected '{expected}'."]
        )

    # Case-insensitive on "Induce ICA", exact on type and CA
    root_lower = root.lower().strip()
    prefix = "induce ica "
    if not root_lower.startswith(prefix):
        return ValidationResult.failure(
            [
                f"Attack tree root '{root}' does not start with 'Induce ICA'; "
                f"expected '{expected}'."
            ]
        )

    remainder = root.strip()[len("Induce ICA ") :]
    expected_suffix = f"{ica_type} on {ca_id}"
    if remainder != expected_suffix:
        return ValidationResult.failure(
            [
                f"Attack tree root '{root}' does not match expected '{expected}' "
                f"(ICA type or CA ID mismatch)."
            ]
        )

    return ValidationResult.success()


def _extract_root(attack_tree: dict | object) -> str:
    """Safely extract the root label from *attack_tree*."""
    if isinstance(attack_tree, dict):
        return attack_tree.get("root", "")
    return ""


def validate_tree_id_references(
    attack_tree: dict,
    control_structure: ControlStructure,
) -> ValidationResult:
    """Validate that attack tree branch references to IDs are valid.

    Checks that any PM-*, FB-*, CA-*, RESP-* IDs mentioned in the tree
    exist in the control structure.

    Args:
        attack_tree: The attack tree dict.
        control_structure: The control structure.

    Returns:
        A :class:`ValidationResult`.
    """
    valid_ids = collect_valid_tree_ids(control_structure)
    tree_text = _flatten_tree_to_text(attack_tree)

    errors: list[str] = []
    for pattern, label in _TREE_ID_SPECS:
        errors.extend(_find_invalid_ids(tree_text, pattern, valid_ids[label], label))

    return ValidationResult(passed=len(errors) == 0, errors=errors)


def collect_valid_tree_ids(cs: ControlStructure) -> dict[str, set[str]]:
    """Collect all valid structural IDs from the control structure."""
    return {
        "PM": _flatten_nested_ids(cs.responsibilities, "process_model_parts", "pm_id"),
        "FB": _flatten_nested_ids(cs.responsibilities, "feedback_channels", "fb_id"),
        "CA": _flatten_nested_ids(cs.responsibilities, "control_actions", "ca_id"),
        "RESP": {r.resp_id for r in cs.responsibilities},
        "CL": {item.link_id for item in cs.coordination_links},
        "CM": {item.coordination_mechanism.cm_id for item in cs.coordination_links},
    }


def _flatten_nested_ids(
    responsibilities: list[Responsibility],
    attr: str,
    id_attr: str,
) -> set[str]:
    """Flatten a nested collection of IDs from responsibilities.

    Each responsibility has a list attribute (e.g. ``process_model_parts``);
    this collects ``id_attr`` from every item across all responsibilities.
    """
    return {
        getattr(item, id_attr) for r in responsibilities for item in getattr(r, attr)
    }


def _find_invalid_ids(
    tree_text: str,
    pattern: str,
    valid_ids: set[str],
    label: str,
) -> list[str]:
    """Find IDs matching *pattern* in *tree_text* that are not in *valid_ids*."""
    errors: list[str] = []
    for match in re.finditer(pattern, tree_text):
        id_val = match.group()
        if id_val not in valid_ids:
            errors.append(f"Attack tree references non-existent {label} '{id_val}'.")
    return errors


def _flatten_tree_to_text(attack_tree: dict) -> str:
    """Flatten an attack tree dict to a single text string for ID scanning."""
    return json.dumps(attack_tree, default=str)


def validate_traceability(
    scenarios: list[ScenarioEnvelope],
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> list[TraceabilityError]:
    """Validate end-to-end provenance chains for all scenarios.

    For each scenario, traces the chain:
    provenance root → loss → hazard → constraint → responsibility → CA → ICA → scenario

    Args:
        scenarios: List of scenario envelopes.
        enriched_threat_set: The enriched threat set.
        control_structure: The control structure.
        loss_analysis: The loss analysis.

    Returns:
        A list of :class:`TraceabilityError` for broken links.
    """
    lookups = _build_traceability_lookups(
        enriched_threat_set, control_structure, loss_analysis
    )

    errors: list[TraceabilityError] = []
    for scenario in scenarios:
        errors.extend(_validate_single_scenario_traceability(scenario, lookups))
    return errors


@dataclass
class _TraceabilityLookups:
    """Pre-computed lookup sets for traceability validation."""

    hazard_ids: set[str]
    constraint_ids: set[str]
    resp_ids: set[str]
    all_ca_ids: set[str]
    coordination_link_ids: set[str]
    coordination_mechanism_ids: set[str]
    coordination_mechanism_by_link: dict[str, str]
    threat_by_ica_id: dict[str, StructuralThreat]


def _build_traceability_lookups(
    enriched_threat_set: EnrichedThreatSet,
    control_structure: ControlStructure,
    loss_analysis: LossAnalysis,
) -> _TraceabilityLookups:
    """Build lookup maps for traceability validation."""
    cs_ids = collect_valid_tree_ids(control_structure)
    return _TraceabilityLookups(
        hazard_ids={h.hazard_id for h in loss_analysis.hazards},
        constraint_ids={sc.constraint_id for sc in loss_analysis.security_constraints},
        resp_ids=cs_ids["RESP"],
        all_ca_ids=cs_ids["CA"],
        coordination_link_ids=cs_ids["CL"],
        coordination_mechanism_ids=cs_ids["CM"],
        coordination_mechanism_by_link={
            item.link_id: item.coordination_mechanism.cm_id
            for item in control_structure.coordination_links
        },
        threat_by_ica_id={
            t.ica_id: t for t in enriched_threat_set.structural_threats if t.ica_id
        },
    )


def _validate_single_scenario_traceability(
    scenario: ScenarioEnvelope,
    lookups: _TraceabilityLookups,
) -> list[TraceabilityError]:
    """Validate the provenance chain for a single scenario."""
    spec = scenario.scenario_spec
    sid = scenario.scenario_id
    errors: list[TraceabilityError] = []

    errors.extend(_check_scenario_links(sid, spec, lookups))

    threat = lookups.threat_by_ica_id.get(spec.threat_source.ica_id)
    if threat is None:
        errors.append(
            TraceabilityError(
                scenario_id=sid,
                broken_link="ica",
                expected=f"valid ica_id from {sorted(lookups.threat_by_ica_id.keys())}",
                actual=spec.threat_source.ica_id or "None",
            )
        )
        return errors

    errors.extend(_check_hazard_and_constraint_links(sid, threat, lookups))
    return errors


def _check_scenario_links(
    sid: str,
    spec: ScenarioSpec,
    lookups: _TraceabilityLookups,
) -> list[TraceabilityError]:
    """Check provenance root, responsibility, and CA links for a scenario."""
    errors: list[TraceabilityError] = []

    provenance = spec.threat_source.provenance
    if provenance not in LEGAL_PROVENANCE_ROOTS and provenance != "structural":
        errors.append(
            TraceabilityError(
                scenario_id=sid,
                broken_link="provenance_root",
                expected=str(LEGAL_PROVENANCE_ROOTS | {"structural"}),
                actual=provenance,
            )
        )

    if spec.target_controller.startswith("CL-"):
        if spec.target_controller not in lookups.coordination_link_ids:
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="coordination_link",
                    expected=(
                        f"valid CL ID from {sorted(lookups.coordination_link_ids)}"
                    ),
                    actual=spec.target_controller,
                )
            )
        if spec.target_control_action not in lookups.coordination_mechanism_ids:
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="coordination_mechanism",
                    expected=(
                        f"valid CM ID from {sorted(lookups.coordination_mechanism_ids)}"
                    ),
                    actual=spec.target_control_action,
                )
            )
        elif (
            lookups.coordination_mechanism_by_link.get(spec.target_controller)
            != spec.target_control_action
        ):
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="coordination_mechanism",
                    expected=(
                        "mechanism paired with "
                        f"{spec.target_controller}: "
                        f"{lookups.coordination_mechanism_by_link.get(spec.target_controller)}"
                    ),
                    actual=spec.target_control_action,
                )
            )
    else:
        if spec.target_controller not in lookups.resp_ids:
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="responsibility",
                    expected=f"valid RESP ID from {sorted(lookups.resp_ids)}",
                    actual=spec.target_controller,
                )
            )

        if spec.target_control_action not in lookups.all_ca_ids:
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="control_action",
                    expected=f"valid CA ID from {sorted(lookups.all_ca_ids)}",
                    actual=spec.target_control_action,
                )
            )

    return errors


def _check_hazard_and_constraint_links(
    sid: str,
    threat: StructuralThreat,
    lookups: _TraceabilityLookups,
) -> list[TraceabilityError]:
    """Check hazard and constraint links for a scenario's threat."""
    errors: list[TraceabilityError] = []

    for hz_id in threat.related_hazards:
        if hz_id not in lookups.hazard_ids:
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="hazard",
                    expected=f"valid hazard ID from {sorted(lookups.hazard_ids)}",
                    actual=hz_id,
                )
            )

    for cs_id in threat.related_constraints:
        if cs_id not in lookups.constraint_ids and not cs_id.startswith("RC-"):
            errors.append(
                TraceabilityError(
                    scenario_id=sid,
                    broken_link="constraint",
                    expected=f"valid constraint ID from {sorted(lookups.constraint_ids)}",
                    actual=cs_id,
                )
            )

    return errors


def detect_orphan_elements(
    control_structure: ControlStructure,
    enriched_threat_set: EnrichedThreatSet,
) -> list[str]:
    """Detect control structure elements not referenced by any ICA.

    An element is orphaned if no structural threat references it.

    Args:
        control_structure: The control structure.
        enriched_threat_set: The enriched threat set.

    Returns:
        A list of orphan element IDs.
    """
    referenced = _collect_referenced_ids(enriched_threat_set.structural_threats)
    return _find_orphan_elements(control_structure, referenced)


def _collect_referenced_ids(
    threats: list[StructuralThreat],
) -> tuple[set[str], set[str], set[str]]:
    """Collect PM, CA, and RESP IDs referenced by any threat.

    Returns:
        A tuple of (referenced_pms, referenced_cas, referenced_resps).
    """
    referenced_pms: set[str] = set()
    referenced_cas: set[str] = set()
    referenced_resps: set[str] = set()

    for threat in threats:
        slot_parts = threat.ica_slot_id.split(":")
        if len(slot_parts) >= 2:
            referenced_resps.add(slot_parts[0])
            referenced_cas.add(slot_parts[1])

        for pm_match in re.finditer(
            r"PM-\d+-\d+", threat.ica_text + " " + threat.hazardous_context
        ):
            referenced_pms.add(pm_match.group())

    return referenced_pms, referenced_cas, referenced_resps


def _find_orphan_elements(
    control_structure: ControlStructure,
    referenced: tuple[set[str], set[str], set[str]],
) -> list[str]:
    """Find control structure elements not in the referenced set."""
    referenced_pms, referenced_cas, referenced_resps = referenced
    orphans: list[str] = []
    for resp in control_structure.responsibilities:
        orphans.extend(
            _find_orphans_in_resp(
                resp, referenced_pms, referenced_cas, referenced_resps
            )
        )
    return orphans


def _find_orphans_in_resp(
    resp: Responsibility,
    ref_pms: set[str],
    ref_cas: set[str],
    ref_resps: set[str],
) -> list[str]:
    """Find orphaned elements within a single responsibility."""
    orphans: list[str] = []
    if resp.resp_id not in ref_resps:
        orphans.append(resp.resp_id)
    orphans.extend(
        pm.pm_id for pm in resp.process_model_parts if pm.pm_id not in ref_pms
    )
    orphans.extend(ca.ca_id for ca in resp.control_actions if ca.ca_id not in ref_cas)
    return orphans


def detect_orphan_icas(
    enriched_threat_set: EnrichedThreatSet,
    scenarios: list[ScenarioEnvelope],
) -> list[str]:
    """Detect ICAs not concretized into scenarios.

    Args:
        enriched_threat_set: The enriched threat set.
        scenarios: The produced scenario envelopes.

    Returns:
        A list of orphan ICA IDs.
    """
    scenario_ica_ids = {
        s.scenario_spec.threat_source.ica_id
        for s in scenarios
        if s.scenario_spec.threat_source.ica_id
    }
    orphans: list[str] = []
    for threat in enriched_threat_set.structural_threats:
        if threat.ica_id and threat.ica_id not in scenario_ica_ids:
            orphans.append(threat.ica_id)
    return orphans
