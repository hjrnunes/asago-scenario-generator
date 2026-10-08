"""Stage 7 — Validators (stage-local + end-to-end traceability).

Stage-local validators check BDI grounding, vulnerability completeness,
tree branch and factor-evidence coverage, and Gherkin correspondence.
End-to-end traceability validation checks the full provenance chain:
provenance root → loss → hazard → constraint → responsibility → CA → ICA → scenario.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

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
    "validate_tree_factor_evidence_coverage",
    "validate_loss_hazard_id_references",
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


@dataclass
class ValidationResult:
    """Result of a validation check."""

    passed: bool
    errors: list[str] = field(default_factory=list)

    @classmethod
    def success(cls) -> ValidationResult:
        return cls(passed=True, errors=[])


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


def validate_tree_factor_evidence_coverage(
    attack_tree: dict,
    scenario_spec: ScenarioSpec,
) -> ValidationResult:
    """Require an attack tree to cover declared factors with exact evidence.

    Branch-category counts are a presentation property, not evidence that a
    tree explains a scenario.  For a contextual Stage 5 result, the first
    declared factor must occur by its exact structural source ID (or by its
    complete normalized evidence phrase), and structural
    references outside the selected path are rejected unless they are exact
    sources for grounded defender BDI evidence. Additional declared factors
    may remain provenance-only.

    The check is deliberately structural: it never treats an adversarial verb
    as proof of access and never imports taxonomy mechanism text into the
    allowed evidence set.
    """
    factors = _selected_tree_factors(scenario_spec)
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
    """Return the first declared factor, leaving provenance-only factors out."""
    return tuple(scenario_spec.causal_factors[:1])


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
    allowed.update(_defender_tree_evidence_refs(scenario_spec))
    context = scenario_spec.scenario_context
    if context is None:
        return allowed
    allowed.update(_context_tree_evidence_refs(context))
    return allowed


def _defender_tree_evidence_refs(scenario_spec: ScenarioSpec) -> set[str]:
    """Collect exact source IDs from grounded defender BDI."""
    defender = scenario_spec.defender_bdi
    return {
        *[item.pm_id for item in defender.beliefs],
        *[item.resp_id for item in defender.desires],
        *[
            item.constraint_id
            for item in defender.desires
            if item.constraint_id is not None
        ],
        *[item.ca_id for item in defender.intentions],
    }


def _context_tree_evidence_refs(context: Any) -> set[str]:
    """Collect exact source IDs from the selected control path."""
    path = context.target_control_path
    allowed = {
        *(item.element_id for item in path.process_model_parts),
        *(item.element_id for item in path.feedback),
        *(item.action_id for item in path.related_control_actions),
        path.control_action.action_id,
        path.controller.element_id,
    }
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
