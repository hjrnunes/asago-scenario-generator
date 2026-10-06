"""Completeness critic and revision for Stage 2.

The critic is a single LLM call with three probes:
  1. Generic checklist (input validation, authorization, etc.)
  2. Taxonomy-derived probes (conditioned on CapabilityProfile KC sub-codes)
  3. Adversarial probe (3 most obvious attack paths)

Revision is a single LLM call (not a loop) if the critic finds unjustified gaps.
The revision uses a RevisionDelta schema — only new and modified elements —
which is merged programmatically into the existing ControlStructure.
"""

from __future__ import annotations

import copy
import logging
import re
from collections.abc import Mapping
from enum import Enum
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationInfo, field_validator

from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.stpa.infra.llm import DEFAULT_TEMPERATURE, LLMClient
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CorrectionPolicy,
    call_with_policy,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ControlStructure,
    ControlledProcess,
    CoordinationLink,
    FeedbackSourceKind,
    Responsibility,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.target_evidence import (
    TargetEvidence,
)
from asago_scenario_generator.stpa.system_model.heuristics import run_heuristics
from asago_scenario_generator.stpa.system_model.id_normalization import (
    validate_normalized_control_structure,
)

STAGE = "stage_2"
STEP_CRITIC = "critic"
STEP_REVISION = "revision"
REVISION_MAX_COMPLETION_TOKENS = 8192
_REVISION_VALIDATION_FEEDBACK = (
    "\n\nThe prior response was not a valid RevisionDelta. Return exactly one "
    "JSON object with the five top-level delta fields shown in the schema "
    "example. Do not restate the existing control structure; use canonical "
    "RESP/PM/CA/FB/RC/CP/CL/CM IDs and keep every reference resolvable."
)
_CRITIC_VALIDATION_FEEDBACK = (
    "\n\nThe prior critic response was inconsistent: every checklist or taxonomy "
    "result marked absent_unjustified must be represented by at least one "
    "explicit gap. Add a gap whose description states the missing concept, "
    "whose related_attack_path states the supplied evidence (or that evidence "
    "is not established), and whose suggested_remedy states what should be "
    "added. Keep unrelated probe results unchanged."
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Internal models
# ---------------------------------------------------------------------------


class CriticGap(BaseModel):
    """A gap identified by the completeness critic."""

    gap_type: Literal["missing_responsibility", "missing_feedback", "missing_pm_part"]
    description: str
    related_attack_path: str
    suggested_remedy: str


class CriticFindings(BaseModel):
    """Findings from the completeness critic."""

    model_config = ConfigDict(
        extra="forbid",
        # Internal callers may still construct empty findings on a recorded
        # provider failure. The generation contract must request every section.
        json_schema_extra={
            "required": ["gaps", "checklist_results", "taxonomy_probe_results"]
        },
    )
    gaps: list[CriticGap] = []
    checklist_results: dict[
        str,
        Literal["present", "absent_justified", "absent_unjustified"],
    ] = Field(default_factory=dict)
    taxonomy_probe_results: dict[
        str,
        Literal["present", "absent_justified", "absent_unjustified"],
    ] = Field(default_factory=dict)

    @field_validator("checklist_results", "taxonomy_probe_results")
    @classmethod
    def validate_result_names(cls, value: dict[str, str], info: ValidationInfo):
        """Bound maps locally; deployed guided decoding lacks property limits."""
        limit = 7 if info.field_name == "checklist_results" else 5
        if len(value) > limit:
            raise ValueError(f"{info.field_name} may contain at most {limit} probes")
        for name in value:
            if not name.strip() or len(name) > 100:
                raise ValueError("critic probe names must contain 1–100 characters")
        return value


def _validate_critic_findings_consistency(findings: CriticFindings) -> None:
    """Require an actionable gap for each unjustified critic result."""
    unjustified = _critic_unjustified_result_names(findings)
    if unjustified and not findings.gaps:
        names = ", ".join(unjustified)
        raise ValueError(
            "critic absent_unjustified result(s) require at least one explicit "
            f"gap stating the missing concept and evidence: {names}"
        )
    for index, gap in enumerate(findings.gaps):
        _validate_critic_gap_fields(gap, index)


def _critic_unjustified_result_names(findings: CriticFindings) -> tuple[str, ...]:
    """Return checklist and taxonomy results marked absent without justification."""
    return tuple(
        name
        for results in (
            findings.checklist_results,
            findings.taxonomy_probe_results,
        )
        for name, status in results.items()
        if status == "absent_unjustified"
    )


def _validate_critic_gap_fields(gap: CriticGap, index: int) -> None:
    """Require each explicit gap to retain concept, evidence, and remedy text."""
    for field_name, label in (
        ("description", "the missing concept"),
        ("related_attack_path", "evidence"),
        ("suggested_remedy", "a remedy"),
    ):
        if not getattr(gap, field_name).strip():
            raise ValueError(f"critic gap {index} must state {label}")


class RevisionDelta(BaseModel):
    """Delta schema for the revision LLM call.

    Instead of restating the entire ControlStructure, the LLM returns
    only the new and modified elements. These are merged programmatically
    into the existing ControlStructure.
    """

    # A revision response is a closed wire object.  In particular, accepting
    # an entire ``ControlStructure`` here would make a malformed or stale
    # model response look like a successful delta and could silently replace
    # data that the critic asked us to preserve.
    model_config = ConfigDict(extra="forbid")

    new_responsibilities: list[Responsibility] = Field(default_factory=list)
    new_controlled_processes: list[ControlledProcess] = Field(default_factory=list)
    new_coordination_links: list[CoordinationLink] = Field(default_factory=list)
    modified_responsibilities: list[Responsibility] = Field(default_factory=list)
    dismissed_gaps: list[str] = Field(default_factory=list)


def _validate_revision_delta_carrier(value: Any) -> None:
    """Validate the revision wire shape before tolerant model construction.

    The revision call intentionally keeps malformed *identifiers* tolerant:
    ``id_normalization`` can map a source identifier to the element's final
    structural position.  That tolerance must not extend to the object graph
    itself, though.  In particular, tolerant construction turns an omitted
    ``coordination_mechanism`` into ``None`` and would otherwise let merge code
    fail while dereferencing it.  This validator therefore checks the nested
    carrier shape and scalar/container types while leaving the actual ID
    formats and cross-references to the existing normalization pass.

    Top-level fields remain backward-compatible and may be omitted (they have
    empty-list defaults), but any field that is supplied must be a list.
    """
    if not isinstance(value, Mapping):
        raise ValueError("RevisionDelta response must be a JSON object")
    expected = set(RevisionDelta.model_fields)
    unknown = set(value) - expected
    if unknown:
        raise ValueError(
            "RevisionDelta contains unknown top-level fields: "
            + ", ".join(sorted(unknown))
        )
    for field_name in expected:
        field_value = value.get(field_name, [])
        if not isinstance(field_value, list):
            raise ValueError(f"RevisionDelta {field_name} must be a list")

    _validate_revision_delta_collections(value)
    _validate_revision_dismissed_gaps(value.get("dismissed_gaps", []))


def _validate_revision_delta_collections(value: Mapping[str, Any]) -> None:
    """Validate the four nested object collections in a revision delta."""
    for field_name, validator in (
        ("new_responsibilities", _validate_revision_responsibility),
        ("modified_responsibilities", _validate_revision_responsibility),
        ("new_controlled_processes", _validate_revision_controlled_process),
        ("new_coordination_links", _validate_revision_coordination_link),
    ):
        _validate_revision_objects(value.get(field_name, []), validator, field_name)


def _valid_revision_gap(value: Any) -> bool:
    """Return whether a dismissed-gap source string carries content."""
    return isinstance(value, str) and bool(value.strip())


def _validate_revision_dismissed_gaps(values: list[Any]) -> None:
    """Require each dismissed gap to retain a meaningful source string."""
    for index, gap in enumerate(values):
        if not _valid_revision_gap(gap):
            raise ValueError(
                "RevisionDelta dismissed_gaps[{}] must be a non-empty string".format(
                    index
                )
            )


def _validate_revision_objects(
    values: list[Any],
    validator: Any,
    field_name: str,
) -> None:
    """Apply one nested carrier validator with a stable field path."""
    for index, item in enumerate(values):
        try:
            validator(item)
        except ValueError as exc:
            raise ValueError(f"{field_name}[{index}]: {exc}") from exc


def _require_revision_mapping(
    value: Any,
    *,
    path: str,
    fields: set[str],
) -> Mapping[str, Any]:
    """Require an object with exactly the fields known by its Pydantic type."""
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} must be an object")
    unknown = set(value) - fields
    if unknown:
        raise ValueError(
            f"{path} contains unknown field(s): " + ", ".join(sorted(unknown))
        )
    return value


def _require_revision_text(
    value: Any,
    *,
    path: str,
    non_empty: bool = True,
) -> None:
    """Require a string, optionally enforcing the model's minimum length."""
    if not isinstance(value, str):
        raise ValueError(f"{path} must be a string")
    if non_empty and not value.strip():
        raise ValueError(f"{path} must be a non-empty string")


def _require_revision_id(value: Any, *, path: str) -> None:
    """Require a repairable source identifier without imposing its format."""
    # Source IDs such as ``new-controller`` are deliberately accepted here;
    # the high-level normalization policy rewrites them deterministically.
    _require_revision_text(value, path=path)


def _require_revision_list(
    value: Any,
    *,
    path: str,
    item_validator: Any | None = None,
) -> None:
    """Require a JSON array and validate each item when requested."""
    if not isinstance(value, list):
        raise ValueError(f"{path} must be a list")
    if item_validator is not None:
        for index, item in enumerate(value):
            try:
                item_validator(item)
            except ValueError as exc:
                raise ValueError(f"{path}[{index}]: {exc}") from exc


def _validate_revision_element_ref(value: Any, *, path: str) -> None:
    """Validate the complete shape of a responsibility/process reference."""
    ref = _require_revision_mapping(value, path=path, fields={"type", "id"})
    _require_revision_text(ref.get("type"), path=f"{path}.type")
    _require_revision_id(ref.get("id"), path=f"{path}.id")


def _validate_revision_responsibility_constraint(value: Any, *, path: str) -> None:
    """Validate one nested responsibility constraint."""
    item = _require_revision_mapping(
        value,
        path=path,
        fields={"rc_id", "description"},
    )
    _require_revision_id(item.get("rc_id"), path=f"{path}.rc_id")
    _require_revision_text(item.get("description"), path=f"{path}.description")


def _validate_revision_process_model_part(value: Any, *, path: str) -> None:
    """Validate one nested process-model part."""
    item = _require_revision_mapping(
        value,
        path=path,
        fields={"pm_id", "description", "feedback_source", "values", "evidence_refs"},
    )
    for name in ("values", "evidence_refs"):
        _require_revision_list(
            item.get(name, []),
            path=f"{path}.{name}",
            item_validator=lambda nested, name=name: _require_revision_text(
                nested, path=f"{path}.{name}[]"
            ),
        )
    _require_revision_id(item.get("pm_id"), path=f"{path}.pm_id")
    _require_revision_text(item.get("description"), path=f"{path}.description")
    if "feedback_source" in item and item["feedback_source"] is not None:
        _validate_revision_element_ref(
            item["feedback_source"], path=f"{path}.feedback_source"
        )


def _validate_optional_revision_ref(
    item: Mapping[str, Any],
    *,
    field_name: str,
    path: str,
) -> None:
    """Validate an optional typed element reference when it is present."""
    value = item.get(field_name)
    if value is not None:
        _validate_revision_element_ref(value, path=f"{path}.{field_name}")


def _validate_revision_enum_fields(
    item: Mapping[str, Any],
    *,
    path: str,
) -> None:
    """Validate optional effect/temporality display metadata values."""
    for name in ("effect_kind", "temporality"):
        value = item.get(name)
        if value is not None and not isinstance(value, (str, Enum)):
            raise ValueError(f"{path}.{name} must be a string")


def _validate_revision_control_action(value: Any, *, path: str) -> None:
    """Validate one nested control action and its optional typed metadata."""
    item = _require_revision_mapping(
        value,
        path=path,
        fields={
            "ca_id",
            "description",
            "target",
            "effect_kind",
            "temporality",
            "operation",
            "process_model_refs",
        },
    )
    _require_revision_id(item.get("ca_id"), path=f"{path}.ca_id")
    if item.get("operation") is not None:
        _require_revision_text(item["operation"], path=f"{path}.operation")
    _require_revision_list(
        item.get("process_model_refs", []),
        path=f"{path}.process_model_refs",
        item_validator=lambda nested: _require_revision_id(
            nested, path=f"{path}.process_model_refs[]"
        ),
    )
    _require_revision_text(item.get("description"), path=f"{path}.description")
    _validate_optional_revision_ref(item, field_name="target", path=path)
    _validate_revision_enum_fields(item, path=path)


def _validate_revision_feedback_channel(value: Any, *, path: str) -> None:
    """Validate one nested feedback channel."""
    item = _require_revision_mapping(
        value,
        path=path,
        fields={"fb_id", "description", "updates", "source", "source_kind"},
    )
    _require_revision_id(item.get("fb_id"), path=f"{path}.fb_id")
    source_kind = item.get("source_kind")
    if source_kind is not None and source_kind not in {
        kind.value for kind in FeedbackSourceKind
    }:
        raise ValueError(
            f"{path}.source_kind must be one of: "
            + ", ".join(kind.value for kind in FeedbackSourceKind)
        )
    _require_revision_text(item.get("description"), path=f"{path}.description")
    _require_revision_id(item.get("updates"), path=f"{path}.updates")
    if "source" in item and item["source"] is not None:
        _validate_revision_element_ref(item["source"], path=f"{path}.source")


def _validate_revision_responsibility(value: Any) -> None:
    """Validate a complete responsibility object before tolerant decoding."""
    item = _require_revision_mapping(
        value,
        path="responsibility",
        fields={
            "resp_id",
            "description",
            "responsibility_constraints",
            "security_constraint_refs",
            "process_model_parts",
            "control_actions",
            "feedback_channels",
        },
    )
    _require_revision_id(item.get("resp_id"), path="responsibility.resp_id")
    _require_revision_text(item.get("description"), path="responsibility.description")
    _require_revision_list(
        item.get("responsibility_constraints", []),
        path="responsibility.responsibility_constraints",
        item_validator=lambda nested: _validate_revision_responsibility_constraint(
            nested, path="responsibility.responsibility_constraints[]"
        ),
    )
    _require_revision_list(
        item.get("security_constraint_refs", []),
        path="responsibility.security_constraint_refs",
        item_validator=lambda nested: _require_revision_id(
            nested, path="responsibility.security_constraint_refs[]"
        ),
    )
    _require_revision_list(
        item.get("process_model_parts", []),
        path="responsibility.process_model_parts",
        item_validator=lambda nested: _validate_revision_process_model_part(
            nested, path="responsibility.process_model_parts[]"
        ),
    )
    _require_revision_list(
        item.get("control_actions", []),
        path="responsibility.control_actions",
        item_validator=lambda nested: _validate_revision_control_action(
            nested, path="responsibility.control_actions[]"
        ),
    )
    _require_revision_list(
        item.get("feedback_channels", []),
        path="responsibility.feedback_channels",
        item_validator=lambda nested: _validate_revision_feedback_channel(
            nested, path="responsibility.feedback_channels[]"
        ),
    )


def _validate_revision_controlled_process(value: Any) -> None:
    """Validate a complete controlled-process object."""
    item = _require_revision_mapping(
        value,
        path="controlled_process",
        fields={"cp_id", "description"},
    )
    _require_revision_id(item.get("cp_id"), path="controlled_process.cp_id")
    _require_revision_text(
        item.get("description"), path="controlled_process.description"
    )


def _validate_revision_coordination_mechanism(value: Any, *, path: str) -> None:
    """Validate the required nested coordination mechanism object."""
    item = _require_revision_mapping(
        value,
        path=path,
        fields={"cm_id", "description", "payload"},
    )
    _require_revision_id(item.get("cm_id"), path=f"{path}.cm_id")
    _require_revision_text(item.get("description"), path=f"{path}.description")
    _require_revision_text(item.get("payload"), path=f"{path}.payload", non_empty=False)


def _validate_revision_coordination_link(value: Any) -> None:
    """Validate a complete link, including endpoints and its mechanism."""
    item = _require_revision_mapping(
        value,
        path="coordination_link",
        fields={
            "link_id",
            "source",
            "target",
            "shared_pm",
            "coordination_mechanism",
            "description",
        },
    )
    _require_revision_id(item.get("link_id"), path="coordination_link.link_id")
    for endpoint in ("source", "target", "shared_pm"):
        _require_revision_id(item.get(endpoint), path=f"coordination_link.{endpoint}")
    if "coordination_mechanism" not in item:
        raise ValueError("coordination_link.coordination_mechanism is required")
    _validate_revision_coordination_mechanism(
        item["coordination_mechanism"],
        path="coordination_link.coordination_mechanism",
    )
    _require_revision_text(
        item.get("description"), path="coordination_link.description"
    )


# ---------------------------------------------------------------------------
# Completeness critic
# ---------------------------------------------------------------------------


def run_completeness_critic(
    *,
    llm_client: LLMClient,
    control_structure: ControlStructure,
    capability_profile: CapabilityProfile,
    use_case_text: str,
    run_dir: Path,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    loss_analysis: LossAnalysis | None = None,
    call3_warnings: list[str] | None = None,
    target_evidence: TargetEvidence | None = None,
    sent: list[int] | None = None,
) -> CriticFindings:
    """Run the completeness critic on the control structure.

    Makes a single LLM call with three probes. Logs the call and returns
    the CriticFindings.

    Args:
        llm_client: LLM client for making the completion call.
        control_structure: The derived control structure to critique.
        capability_profile: The capability profile for taxonomy probes.
        use_case_text: Free-text use-case description.
        run_dir: Directory for call logging.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).
        loss_analysis: Optional loss analysis used for hazard-trace context.
        call3_warnings: Optional warnings from the preceding Gherkin call.
        sent: Optional tally; receives the number of requests sent.

    Returns:
        CriticFindings model with gaps, checklist results, and taxonomy probe results.
        Returns empty CriticFindings if the LLM call fails.
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    taxonomy_probes = _build_taxonomy_probes(capability_profile)

    system_prompt = loader.render_prompt(
        "critic_system.j2",
        taxonomy_probes=taxonomy_probes,
    )
    user_prompt = loader.render_prompt(
        "critic_user.j2",
        use_case_text=use_case_text,
        control_structure=control_structure,
        capability_profile=capability_profile,
        zone_display_names=ZONE_DISPLAY_NAMES,
        kc_subcodes_display=build_kc_subcodes_display(capability_profile.kc_subcodes),
        taxonomy_probes=taxonomy_probes,
        loss_analysis=loss_analysis,
        call3_warnings=call3_warnings,
        target_evidence=target_evidence,
    )

    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=CriticFindings,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_CRITIC,
        policy=CorrectionPolicy(
            validation_retries=1,
            feedback=_CRITIC_VALIDATION_FEEDBACK,
            include_schema=False,
        ),
        temperature=temperature,
        result_validator=_validate_critic_findings_consistency,
    )
    if sent is not None:
        sent.append(outcome.calls)
    if outcome.error is not None:
        return CriticFindings()

    return outcome.value  # type: ignore[return-value]


def has_unjustified_gaps(findings: CriticFindings) -> bool:
    """Return whether findings contain an explicit actionable structural gap.

    Checklist and taxonomy probe statuses remain diagnostic context. They do
    not authorize a revision unless the critic also represents the missing
    concept and evidence in a typed ``CriticGap``.

    Args:
        findings: The critic findings to check.

    Returns:
        True if revision should be triggered, False otherwise.
    """
    return bool(findings.gaps)


def count_findings(findings: CriticFindings) -> int:
    """Count the findings the revision is asked to address.

    Only explicit structural gaps are actionable revision findings. The
    checklist and taxonomy maps are retained as diagnostic context and are
    intentionally excluded from this count.
    """
    return len(findings.gaps)


# ---------------------------------------------------------------------------
# Critic ID sanitization
# ---------------------------------------------------------------------------

# Conforming ID patterns (valid format per the model schema):
# RESP-N, PM-X-Y, CA-X-Y, FB-X-Y, CP-N, CL-N, RC-X-Y
_CONFORMING_PATTERNS = [
    re.compile(r"^RESP-\d+$"),
    re.compile(r"^PM-\d+-\d+$"),
    re.compile(r"^CA-\d+-\d+$"),
    re.compile(r"^FB-\d+-\d+$"),
    re.compile(r"^CP-\d+$"),
    re.compile(r"^CL-\d+$"),
    re.compile(r"^RC-\d+-\d+$"),
]

# Any ID-like token (for detection): RESP-*, PM-*, CA-*, FB-*, CP-*, CL-*, RC-*
_ID_LIKE_PATTERN = re.compile(r"\b(?:RESP|PM|CA|FB|CP|CL|RC)-\d+(?:-\d+)?\b")

# Generic descriptions for non-conforming ID prefixes, used as replacements
# in suggested_remedy strings so the revision model never sees invalid IDs.
_ID_REPLACEMENTS: dict[str, str] = {
    "PM": "a new PM part",
    "RESP": "a new responsibility",
    "CA": "a new control action",
    "FB": "a new feedback channel",
    "CP": "a new controlled process",
    "CL": "a new coordination link",
    "RC": "a new responsibility constraint",
}


def _is_conforming_id(token: str) -> bool:
    """Check whether an ID-like token matches a valid format and is non-zero."""
    return any(p.match(token) for p in _CONFORMING_PATTERNS)


def _replace_non_conforming_ids(remedy: str) -> str:
    """Replace non-conforming ID tokens in a suggested_remedy string.

    Replaces any ID-like token (RESP-*, PM-*, CA-*, FB-*, CP-*, CL-*, RC-*)
    that does not match the expected format with a generic description.
    For example, ``PM-0`` (single-part, missing the X-Y suffix) is replaced
    with ``a new PM part``. Conforming IDs like ``PM-1-2`` are preserved.
    """

    def _replacer(match: re.Match) -> str:
        token = match.group()
        if _is_conforming_id(token):
            return token
        # Non-conforming: determine replacement
        prefix = token.split("-")[0]
        return _ID_REPLACEMENTS.get(prefix, "a new element")

    return _ID_LIKE_PATTERN.sub(_replacer, remedy)


def sanitize_critic_ids(findings: CriticFindings) -> CriticFindings:
    """Sanitize non-conforming IDs in critic suggested_remedy strings.

    The completeness critic's ``suggested_remedy`` field is free-text and
    may contain non-conforming IDs (e.g., ``PM-0``, ``RESP-0``, or
    IDs that don't match the standard format). These are passed verbatim
    into the revision user prompt, causing the revision LLM to use invalid
    IDs and trigger Pydantic ValidationError on the RevisionDelta output.

    This function replaces non-conforming IDs with generic descriptions
    (e.g., ``PM-0`` → ``a new PM part``) so the revision model receives
    only valid or descriptive text.

    Args:
        findings: The CriticFindings from the completeness critic.

    Returns:
        A new CriticFindings with sanitized suggested_remedy strings.
        ``checklist_results`` and ``taxonomy_probe_results`` are preserved
        unchanged.
    """
    sanitized_gaps = []
    for gap in findings.gaps:
        sanitized_remedy = _replace_non_conforming_ids(gap.suggested_remedy)
        sanitized_gaps.append(
            CriticGap(
                gap_type=gap.gap_type,
                description=gap.description,
                related_attack_path=gap.related_attack_path,
                suggested_remedy=sanitized_remedy,
            )
        )
    return CriticFindings(
        gaps=sanitized_gaps,
        checklist_results=findings.checklist_results,
        taxonomy_probe_results=findings.taxonomy_probe_results,
    )


# ---------------------------------------------------------------------------
# Revision
# ---------------------------------------------------------------------------


def _revision_failure_warnings(error_msg: str) -> list[str]:
    """Describe a failed revision while distinguishing validation degradation."""
    warnings = [f"Revision failed: {error_msg}"]
    if "ValidationError" in error_msg:
        warnings.append(
            "Revision degraded: the validated delta was rejected; the "
            "pre-revision control structure and critic findings were retained."
        )
    return warnings


def _finish_revision(
    control_structure: ControlStructure,
    revision_delta: RevisionDelta,
    *,
    critic_findings: CriticFindings,
    loss_analysis: LossAnalysis | None,
) -> tuple[ControlStructure, list[str]]:
    """Merge a validated delta and retain post-revision diagnostics."""
    revision_warnings = [
        f"Revision dismissed finding: {justification}"
        for justification in revision_delta.dismissed_gaps
    ]
    revision_warnings.extend(
        _all_dismissed_no_change_warning(critic_findings, revision_delta)
    )
    if (
        critic_findings.gaps
        and not _delta_has_changes(revision_delta)
        and len(revision_delta.dismissed_gaps) < len(critic_findings.gaps)
    ):
        revision_warnings.append(
            "Revision made no structural changes for explicit critic gaps; the "
            "baseline control structure was retained and those gaps remain "
            "unresolved."
        )

    # Merge the delta into the existing ControlStructure
    try:
        revised_cs, merge_warnings = _merge_revision_delta(
            control_structure, revision_delta
        )
    except Exception as exc:
        warning = f"Revision delta merge degraded: {type(exc).__name__}: {exc}"
        return control_structure, [warning]

    # Warnings are accumulated in chronological order: dismissal → merge →
    # strip → heuristics, so consumers see the earliest root-cause first.
    revision_warnings.extend(merge_warnings)

    # Strip empty responsibilities as a safety net
    revised_cs, strip_warnings = strip_empty_responsibilities(revised_cs)
    revision_warnings.extend(strip_warnings)

    # Re-run structural heuristics after revision
    post_revision = run_heuristics(revised_cs, loss_analysis)
    revision_warnings.extend(post_revision.errors)
    revision_warnings.extend(post_revision.warnings)

    return revised_cs, revision_warnings


def run_revision(
    *,
    llm_client: LLMClient,
    control_structure: ControlStructure,
    critic_findings: CriticFindings,
    use_case_text: str,
    run_dir: Path,
    loss_analysis: LossAnalysis | None = None,
    template_loader: TemplateLoader | None = None,
    temperature: float = DEFAULT_TEMPERATURE,
    target_evidence: TargetEvidence | None = None,
    sent: list[int] | None = None,
) -> tuple[ControlStructure, list[str]]:
    """Run a single revision attempt on the control structure.

    Requests a :class:`RevisionDelta` from the LLM (only new/modified
    elements) and merges it programmatically into the existing
    ControlStructure. After the merge, ``strip_empty_responsibilities``
    runs as a safety net, and structural heuristics are re-run.

    This is NOT a loop — one revision attempt maximum. After revision,
    structural heuristics are re-run. If structural errors remain, they
    are returned as warnings (the pipeline proceeds).

    Args:
        llm_client: LLM client for making the completion call.
        control_structure: The current control structure to revise.
        critic_findings: The gaps identified by the critic.
        use_case_text: Free-text use-case description.
        run_dir: Directory for call logging.
        loss_analysis: Optional loss analysis for heuristic hazard tracing.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).
        sent: Optional tally; receives the number of requests sent.

    Returns:
        A tuple of (revised ControlStructure, post-revision heuristic warnings).
        On LLM failure, returns (pre-revision ControlStructure, [warning]).
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    next_ids = _compute_next_ids(control_structure)

    system_prompt = loader.render_prompt(
        "revision_system.j2",
        control_structure=control_structure,
        **next_ids,
    )
    user_prompt = loader.render_prompt(
        "revision_user.j2",
        use_case_text=use_case_text,
        control_structure=control_structure,
        critic_findings=critic_findings,
        target_evidence=target_evidence,
    )

    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=RevisionDelta,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_REVISION,
        policy=CorrectionPolicy(
            validation_retries=1,
            feedback=_REVISION_VALIDATION_FEEDBACK,
            include_schema=False,
        ),
        temperature=temperature,
        max_completion_tokens=REVISION_MAX_COMPLETION_TOKENS,
        # Keep the wire envelope closed, then preserve malformed source IDs
        # until the complete stitched structure can normalize references.
        allow_unvalidated=True,
        raw_result_validator=_validate_revision_delta_carrier,
    )
    if sent is not None:
        sent.append(outcome.calls)
    revision_delta, error_msg = outcome.value, outcome.error
    if error_msg is not None:
        return control_structure, _revision_failure_warnings(error_msg)
    if revision_delta is None:
        return control_structure, ["Revision failed: unexpected None response"]
    return _finish_revision(
        control_structure,
        revision_delta,
        critic_findings=critic_findings,
        loss_analysis=loss_analysis,
    )


def _delta_has_changes(delta: RevisionDelta) -> bool:
    """Check whether a revision delta carries any additions or modifications."""
    return bool(
        delta.new_responsibilities
        or delta.new_controlled_processes
        or delta.new_coordination_links
        or delta.modified_responsibilities
    )


def _all_dismissed_no_change_warning(
    critic_findings: CriticFindings,
    revision_delta: RevisionDelta,
) -> list[str]:
    """Build the warning for a revision that dismissed everything.

    Returns a single-element list with the warning string when there was
    at least one finding, the delta dismisses every finding, and the delta
    adds or modifies nothing — the revision accomplished no structural
    work. Returns an empty list otherwise.
    """
    finding_count = count_findings(critic_findings)
    if finding_count == 0:
        return []
    if len(revision_delta.dismissed_gaps) < finding_count:
        return []
    if _delta_has_changes(revision_delta):
        return []
    return [
        f"Revision dismissed all findings ({finding_count}) and made no "
        "changes: the control structure is unchanged. Review each dismissal "
        "justification above to confirm the findings were false positives."
    ]


def _compute_next_ids(
    cs: ControlStructure,
) -> dict[str, int]:
    """Compute next-available ID numbers from an existing ControlStructure.

    Returns a dict of template variables for the revision system prompt:
    ``next_resp_num``, ``next_cl_num``, ``next_cp_num``, and ``next_cm_num``.
    """
    return {
        "next_resp_num": _next_num_from(cs.responsibilities, lambda r: r.resp_id),
        "next_cl_num": _next_num_from(cs.coordination_links, lambda cl: cl.link_id),
        "next_cp_num": _next_num_from(cs.controlled_processes, lambda cp: cp.cp_id),
        "next_cm_num": _next_num_from(
            cs.coordination_links,
            lambda cl: cl.coordination_mechanism.cm_id,
        ),
    }


def _next_num_from(items: list, id_getter: Any) -> int:
    """Return the next-available number from a list of items.

    Extracts numeric suffixes from each item's ID via *id_getter* and
    returns ``max(found) + 1``, or 1 when the list is empty.
    """
    nums = [_extract_num(id_getter(item)) for item in items]
    valid_nums = [n for n in nums if n is not None]
    return max(valid_nums, default=0) + 1


def _extract_num(id_str: str) -> int | None:
    """Extract the numeric suffix from an ID like 'RESP-3' or 'CL-1'.

    For multi-part IDs like 'PM-1-2', returns the first number (1).
    """
    match = re.search(r"\d+", id_str)
    return int(match.group()) if match else None


def _add_new_items(
    existing: list,
    new_items: list,
    existing_ids: set,
    id_getter: Any,
) -> list:
    """Append new_items to a deep-copied existing list, skipping duplicate IDs.

    Mutates *existing_ids* by adding each newly inserted item's ID.
    """
    merged = [copy.deepcopy(item) for item in existing]
    for new_item in new_items:
        item_id = id_getter(new_item)
        if item_id not in existing_ids:
            merged.append(copy.deepcopy(new_item))
            existing_ids.add(item_id)
        else:
            logger.warning("Skipping duplicate item %s from revision delta", item_id)
    return merged


def _replace_modified_resps(
    resps: list[Responsibility],
    modified: list[Responsibility],
) -> list[Responsibility]:
    """Replace responsibilities whose resp_id appears in *modified*.

    Responsibilities not in the modified set are deep-copied as-is.  The
    ``resp_id`` is the pre-normalization stitch key, so every modified
    responsibility must name an existing responsibility exactly.  A
    non-canonical or otherwise unknown key cannot be matched safely.
    """
    existing_ids = {resp.resp_id for resp in resps}
    modified_map = {r.resp_id: r for r in modified}
    unknown_ids = set(modified_map) - existing_ids
    if unknown_ids:
        unknown = ", ".join(sorted(unknown_ids))
        raise ValueError(
            "Modified responsibility resp_id must match an existing "
            f"canonical responsibility ID; unknown ID(s): {unknown}."
        )
    return [_revised_responsibility(r, modified_map.get(r.resp_id, r)) for r in resps]


def _revised_responsibility(
    original: Responsibility, replacement: Responsibility
) -> Responsibility:
    """A completeness revision cannot revoke already established ownership links."""
    revised = copy.deepcopy(replacement)
    revised.security_constraint_refs = sorted(
        set(original.security_constraint_refs)
        | set(replacement.security_constraint_refs)
    )
    _carry_forward_context(original, revised)
    return revised


def _carry_forward_context(original: Responsibility, revised: Responsibility) -> None:
    """Keep context fields a restated element omits.

    A revision restates a whole responsibility; the model may drop the
    optional context fields (PM values and evidence, CA operation and PM
    refs, FB source kind) of an element it did not mean to change.
    """
    _carry_forward_process_model_context(original, revised)
    _carry_forward_action_context(original, revised)
    old_fbs = {fb.fb_id: fb for fb in original.feedback_channels}
    for fb in revised.feedback_channels:
        old = old_fbs.get(fb.fb_id)
        if old is not None and fb.source_kind is None:
            fb.source_kind = old.source_kind


def _carry_forward_process_model_context(
    original: Responsibility, revised: Responsibility
) -> None:
    """Keep the values and evidence refs a restated PM part omits."""
    old_pms = {pm.pm_id: pm for pm in original.process_model_parts}
    for pm in revised.process_model_parts:
        old = old_pms.get(pm.pm_id)
        if old is None:
            continue
        if not pm.values:
            pm.values = list(old.values)
        if not pm.evidence_refs:
            pm.evidence_refs = list(old.evidence_refs)


def _carry_forward_action_context(
    original: Responsibility, revised: Responsibility
) -> None:
    """Keep the operation and surviving PM refs a restated action omits."""
    revised_pm_ids = {pm.pm_id for pm in revised.process_model_parts}
    old_cas = {ca.ca_id: ca for ca in original.control_actions}
    for ca in revised.control_actions:
        old = old_cas.get(ca.ca_id)
        if old is None:
            continue
        if ca.operation is None:
            ca.operation = old.operation
        if not ca.process_model_refs:
            ca.process_model_refs = [
                ref for ref in old.process_model_refs if ref in revised_pm_ids
            ]


def _next_free_cm_id(used_cm_ids: set[str]) -> str:
    """Return the next ``CM-N`` not already in *used_cm_ids*."""
    nums = [n for n in (_extract_num(cm_id) for cm_id in used_cm_ids) if n is not None]
    return f"CM-{max(nums, default=0) + 1}"


def _renumber_colliding_cm_ids(
    existing_links: list[CoordinationLink],
    merged_links: list[CoordinationLink],
) -> tuple[list[CoordinationLink], list[str]]:
    """Renumber cm_id collisions in newly added coordination links.

    Existing links (identified by ``link_id`` membership) keep their
    cm_ids.  New links whose cm_id collides with any already-used cm_id
    are renumbered to the next free ``CM-N``.

    Identifying new links by ``link_id`` rather than by list position
    avoids an implicit ordering contract with ``_add_new_items``.

    Returns the merged list (with renumbered cm_ids) and renumber warnings.
    Each warning mentions both the colliding cm_id and the link_id.
    """
    warnings: list[str] = []
    existing_link_ids = {cl.link_id for cl in existing_links}
    used_cm_ids = {cl.coordination_mechanism.cm_id for cl in existing_links}

    for cl in merged_links:
        if cl.link_id in existing_link_ids:
            continue
        cm_id = cl.coordination_mechanism.cm_id
        if cm_id in used_cm_ids:
            new_cm_id = _next_free_cm_id(used_cm_ids)
            cl.coordination_mechanism = cl.coordination_mechanism.model_copy(
                update={"cm_id": new_cm_id}
            )
            used_cm_ids.add(new_cm_id)
            warnings.append(
                f"Renumber cm_id: collision on {cm_id} from link {cl.link_id}, "
                f"renumbered to {new_cm_id}."
            )
        else:
            used_cm_ids.add(cm_id)

    return merged_links, warnings


def _stitch_revision_delta(
    cs: ControlStructure,
    delta: RevisionDelta,
) -> tuple[ControlStructure, list[str]]:
    """Stitch a revision delta onto the current structure by source ID.

    This is list surgery only.  Matching uses the pre-normalization
    source IDs so a modification can name an existing element even when
    that source ID is later rewritten.  Published IDs are assigned later
    from the stitched list positions.

    - Replaces ``modified_responsibilities`` by source ``resp_id`` while
      retaining their established governing security-constraint links.
    - Appends new responsibilities, processes, and links whose source
      IDs are not already present.
    - Records ``cm_id`` collisions among newly added links so the
      operator can see the LLM chose a colliding mechanism ID.  Those
      IDs are not the published IDs; the subsequent normalization pass
      assigns ``CM-N`` from final list position.

    The returned structure is unvalidated: the revision delta is decoded
    tolerantly, so malformed source IDs must survive until the
    high-level normalizer sees the complete stitched lists.
    """
    existing_resp_ids = {r.resp_id for r in cs.responsibilities}
    existing_cp_ids = {cp.cp_id for cp in cs.controlled_processes}
    existing_cl_ids = {cl.link_id for cl in cs.coordination_links}

    merged_resps = _replace_modified_resps(
        cs.responsibilities, delta.modified_responsibilities
    )
    merged_resps = _add_new_items(
        merged_resps,
        delta.new_responsibilities,
        existing_resp_ids,
        lambda r: r.resp_id,
    )

    merged_cps = _add_new_items(
        cs.controlled_processes,
        delta.new_controlled_processes,
        existing_cp_ids,
        lambda cp: cp.cp_id,
    )

    merged_cls = _add_new_items(
        cs.coordination_links,
        delta.new_coordination_links,
        existing_cl_ids,
        lambda cl: cl.link_id,
    )

    merged_cls, cm_warnings = _renumber_colliding_cm_ids(
        cs.coordination_links, merged_cls
    )
    return (
        ControlStructure.model_construct(
            responsibilities=merged_resps,
            controlled_processes=merged_cps,
            coordination_links=merged_cls,
        ),
        cm_warnings,
    )


def _merge_revision_delta(
    cs: ControlStructure,
    delta: RevisionDelta,
) -> tuple[ControlStructure, list[str]]:
    """Merge a RevisionDelta into an existing ControlStructure.

    Stitch by source ID first, then hand the complete structure to the
    high-level ID policy.  Published IDs come from final list position;
    resolvable references are rewritten; unresolved references fail
    validation and degrade the revision.

    Returns a tuple of (merged ControlStructure, stitch warnings).
    """
    stitched, stitch_warnings = _stitch_revision_delta(cs, delta)
    return validate_normalized_control_structure(stitched), stitch_warnings


# ---------------------------------------------------------------------------
# Post-revision strip empty responsibilities
# ---------------------------------------------------------------------------


def _is_responsibility_empty(resp: Responsibility) -> bool:
    """Check if a responsibility has no PM parts, CAs, or FB channels."""
    return not any(
        [resp.process_model_parts, resp.control_actions, resp.feedback_channels]
    )


def strip_empty_responsibilities(
    control_structure: ControlStructure,
) -> tuple[ControlStructure, list[str]]:
    """Strip responsibilities with no PM parts, CAs, or FB channels.

    After revision, the LLM may produce skeleton responsibilities that
    have a description but no process model parts, no control actions,
    and no feedback channels. These would produce downstream heuristic
    errors (every responsibility must have >=1 PM, CA, and FB). This
    function detects and removes them.

    A responsibility is considered empty when **all three** of
    ``process_model_parts``, ``control_actions``, and
    ``feedback_channels`` are empty. ``responsibility_constraints`` alone
    do not prevent stripping.

    Args:
        control_structure: The (possibly revised) control structure.

    Returns:
        A tuple of (stripped ControlStructure, list of warning strings).
        Each warning includes the resp_id and description of the
        stripped responsibility.
    """
    kept: list[Responsibility] = []
    warnings: list[str] = []

    for resp in control_structure.responsibilities:
        if _is_responsibility_empty(resp):
            warnings.append(
                f"Stripped empty responsibility {resp.resp_id} "
                f"({resp.description}) after revision: no PM parts, "
                f"control actions, or feedback channels."
            )
        else:
            kept.append(resp)

    if len(kept) == len(control_structure.responsibilities):
        return control_structure, warnings

    stripped_cs = control_structure.model_copy(
        update={"responsibilities": kept},
    )
    return stripped_cs, warnings


# ---------------------------------------------------------------------------
# Taxonomy probe builder
# ---------------------------------------------------------------------------

# Each entry: (predicate, probe text).  Predicates are kept as small
# standalone functions so the builder itself stays a simple loop.
_PROBE_TEXT_RAG = (
    "RAG retrieval integrity: Is there a responsibility governing "
    "retrieval content validation and source integrity?"
)
_PROBE_TEXT_TOOL = (
    "Tool parameter validation: Is there a responsibility governing "
    "parameter validation for tool invocations?"
)
_PROBE_TEXT_MEMORY = (
    "Memory integrity: Is there a responsibility governing "
    "persistent memory integrity and access control?"
)
_PROBE_TEXT_MULTI_AGENT = (
    "Multi-agent coordination: Are there coordination responsibilities "
    "for inter-agent communication?"
)
_PROBE_TEXT_HITL = (
    "Human-in-the-loop escalation: Is there a responsibility for "
    "escalation to human review when needed?"
)


def _needs_rag_probe(profile: CapabilityProfile) -> bool:
    """True when the profile includes RAG capabilities."""
    kc_set = set(profile.kc_subcodes)
    if "KC6.3.3" in kc_set:
        return True
    return any("rag" in ep.name.lower() for ep in profile.entry_points)


def _needs_tool_probe(profile: CapabilityProfile) -> bool:
    """True when the profile includes tool-invocation capabilities."""
    kc_set = set(profile.kc_subcodes)
    return any(kc.startswith("KC5.") or kc.startswith("KC6.") for kc in kc_set)


def _build_taxonomy_probes(profile: CapabilityProfile) -> list[str]:
    """Build taxonomy-derived probes based on the capability profile.

    Each probe is gated by a small predicate so this function stays a
    simple loop instead of a chain of independent ``if`` blocks.

    Args:
        profile: The capability profile.

    Returns:
        A list of probe descriptions.
    """
    gated_probes: list[tuple[Any, str]] = [
        (_needs_rag_probe, _PROBE_TEXT_RAG),
        (_needs_tool_probe, _PROBE_TEXT_TOOL),
        (lambda p: p.has_persistent_memory, _PROBE_TEXT_MEMORY),
        (lambda p: p.multi_agent, _PROBE_TEXT_MULTI_AGENT),
        (lambda p: p.hitl, _PROBE_TEXT_HITL),
    ]
    return [text for predicate, text in gated_probes if predicate(profile)]
