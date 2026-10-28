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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    ValidationInfo,
    field_validator,
)

from asago_scenario_generator.models.capability_profile import (
    ZONE_DISPLAY_NAMES,
    CapabilityProfile,
    build_kc_subcodes_display,
)
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE,
    LLMClient,
    LLMResult,
)
from asago_scenario_generator.stpa.infra.llm_helpers import (
    CallOutcome,
    CorrectionPolicy,
    call_with_policy,
    decode_content,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.models.control_structure import (
    ASSEMBLY_DEFERRED,
    ControlStructure,
    NonBlankStr,
    ControlledProcess,
    CoordinationLink,
    FeedbackSourceKind,
    FeedbackUpdateAuthority,
    ReferenceType,
    Responsibility,
    check_structural_heuristics,
)
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.feedback_authority import (
    FeedbackAuthorityError,
    feedback_authority_defect,
    validate_all_feedback_authority_assessments,
)
from asago_scenario_generator.stpa.system_model.target_evidence import (
    TargetEvidence,
)
from asago_scenario_generator.stpa.system_model.undecodable_reply import (
    decode_aware_feedback,
)
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


# Revision IDs keep any non-empty source text: ``id_normalization`` maps each
# one to the element's final structural position after the merge.
_Text = NonBlankStr


class _RevisionWire(BaseModel):
    """A closed object of the revision wire: unknown fields are errors."""

    model_config = ConfigDict(extra="forbid")


class _RevisionRef(_RevisionWire):
    # ``type`` stays text so the assembled structure, not the carrier,
    # rejects an unknown reference type.
    type: _Text
    id: _Text


class _RevisionConstraint(_RevisionWire):
    rc_id: _Text
    description: _Text


class _RevisionProcessModelPart(_RevisionWire):
    pm_id: _Text
    description: _Text
    feedback_source: _RevisionRef | None = None
    values: list[_Text] = []
    evidence_refs: list[_Text] = []


class _RevisionControlAction(_RevisionWire):
    ca_id: _Text
    description: _Text
    target: _RevisionRef | None = None
    effect_kind: StrictStr | None = None
    temporality: StrictStr | None = None
    operation: _Text | None = None
    process_model_refs: list[_Text] = []


class _RevisionFeedbackChannel(_RevisionWire):
    fb_id: _Text
    description: _Text
    updates: _Text
    source: _RevisionRef | None = None
    source_kind: FeedbackSourceKind | None = None
    authority_for_update: FeedbackUpdateAuthority | None = None


class _RevisionResponsibility(_RevisionWire):
    resp_id: _Text
    description: _Text
    responsibility_constraints: list[_RevisionConstraint] = []
    security_constraint_refs: list[_Text] = []
    process_model_parts: list[_RevisionProcessModelPart] = []
    control_actions: list[_RevisionControlAction] = []
    feedback_channels: list[_RevisionFeedbackChannel] = []


class _RevisionControlledProcess(_RevisionWire):
    cp_id: _Text
    description: _Text


class _RevisionMechanism(_RevisionWire):
    cm_id: _Text
    description: _Text
    payload: StrictStr


class _RevisionLink(_RevisionWire):
    link_id: _Text
    source: _Text
    target: _Text
    shared_pm: _Text
    coordination_mechanism: _RevisionMechanism
    description: _Text


# The revision response as the model must write it, and the schema the request
# sends.  It narrows ``RevisionDelta`` to the wire objects the way
# ``_ControlElementProviderSet`` narrows Call 2b, so a reply the schema allows is
# a reply the wire models accept.  Every object is closed and every collection
# that is present must be a list; an omitted collection is empty.  IDs,
# reference types, and action kinds stay as written for normalization and
# assembly to settle.  A docstring here would reach the model as the schema
# description.
class _RevisionDeltaProviderSet(RevisionDelta):
    new_responsibilities: list[_RevisionResponsibility] = []
    new_controlled_processes: list[_RevisionControlledProcess] = []
    new_coordination_links: list[_RevisionLink] = []
    modified_responsibilities: list[_RevisionResponsibility] = []
    dismissed_gaps: list[_Text] = []


def _validate_revision_wire(
    value: Any,
    *,
    target_evidence: TargetEvidence | None = None,
) -> None:
    """Reject a revision response whose carrier breaks the wire models.

    The authority checks name every failing channel, so the one correction
    request can ask for all of them.
    """
    wire = _RevisionDeltaProviderSet.model_validate(value)
    validate_all_feedback_authority_assessments(
        (
            channel
            for responsibility in (
                *wire.new_responsibilities,
                *wire.modified_responsibilities,
            )
            for channel in responsibility.feedback_channels
        ),
        target_evidence=target_evidence,
        require_domain_scope=True,
    )


@dataclass(frozen=True)
class _SalvagedRevision:
    """A revision reply without its unsupported authority bases.

    ``dropped_authority`` holds the ``(resp_id, fb_id)`` of each restated
    channel whose assessment was dropped, as the reply wrote them.
    """

    delta: RevisionDelta
    warnings: list[str]
    dropped_authority: frozenset[tuple[str, str]]


def _revision_without_unsupported_authority(
    outcome: CallOutcome[RevisionDelta],
    *,
    target_evidence: TargetEvidence | None,
) -> _SalvagedRevision | None:
    """Return the last revision reply without its unsupported authority bases.

    It applies only when the reply fails nothing but the authority basis
    checks; any other failure returns ``None`` so the revision is discarded as
    before.  No request is sent.  A dropped assessment leaves the channel's
    authority unknown: unlike an omitted one, the merge does not keep the
    channel's earlier assessment for it.  Each drop adds a warning naming the
    channel and the reason.
    """
    if outcome.result is None or not isinstance(
        outcome.failure, FeedbackAuthorityError
    ):
        return None
    try:
        value = copy.deepcopy(decode_content(outcome.result))
        wire = _RevisionDeltaProviderSet.model_validate(value)
    except Exception:
        return None
    reasons: list[tuple[str, str]] = []
    dropped: set[tuple[str, str]] = set()
    for key in ("new_responsibilities", "modified_responsibilities"):
        for resp_index, responsibility in enumerate(getattr(wire, key)):
            for fb_index, channel in enumerate(responsibility.feedback_channels):
                reason = feedback_authority_defect(
                    channel, target_evidence=target_evidence, require_domain_scope=True
                )
                if reason is None:
                    continue
                del value[key][resp_index]["feedback_channels"][fb_index][
                    "authority_for_update"
                ]
                reasons.append((channel.fb_id, reason))
                if key == "modified_responsibilities":
                    dropped.add((responsibility.resp_id, channel.fb_id))
    if not reasons:
        return None
    try:
        _validate_revision_wire(value, target_evidence=target_evidence)
        delta = _revision_delta_from_wire(value)
    except Exception:
        return None
    return _SalvagedRevision(
        delta=delta,
        warnings=[
            f"Revision dropped the authority_for_update of feedback channel "
            f"{fb_id}: {reason}"
            for fb_id, reason in reasons
        ],
        dropped_authority=frozenset(dropped),
    )


def _revision_delta_from_wire(value: Any) -> RevisionDelta:
    """Build the delta from a carrier that passed the wire models."""
    return RevisionDelta.model_validate(value, context=ASSEMBLY_DEFERRED)


def _parse_revision_result(
    result: LLMResult, cleanup_transformations: list[dict[str, Any]]
) -> RevisionDelta:
    """Parse a revision response that ``_validate_revision_wire`` accepted."""
    return _revision_delta_from_wire(
        decode_content(result, cleanup_transformations=cleanup_transformations)
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
) -> CriticFindings:
    """Run the completeness critic on the control structure.

    Makes a single LLM call with three probes. Logs the call and returns
    the CriticFindings.  A reply that fails validation or does not decode
    earns one correction request.

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
            feedback=decode_aware_feedback(
                loader,
                reply_name="critic findings",
                feedback=_CRITIC_VALIDATION_FEEDBACK,
            ),
            include_schema=False,
            correct_undecodable=True,
        ),
        temperature=temperature,
        result_validator=_validate_critic_findings_consistency,
    )
    if outcome.error is not None:
        return CriticFindings()

    return outcome.value  # type: ignore[return-value]


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
    sanitized_gaps = [
        gap.model_copy(
            update={
                "suggested_remedy": _replace_non_conforming_ids(gap.suggested_remedy)
            }
        )
        for gap in findings.gaps
    ]
    return findings.model_copy(update={"gaps": sanitized_gaps})


# ---------------------------------------------------------------------------
# Revision
# ---------------------------------------------------------------------------


# A revision whose reply is not applied leaves one warning with one of these
# prefixes; ``discarded_revision_reason`` reads it back for the stage record.
_REVISION_FAILED = "Revision failed: "
_REVISION_MERGE_DEGRADED = "Revision delta merge degraded: "


def discarded_revision_reason(warnings: list[str]) -> str | None:
    """Return the warning that says why ``run_revision`` kept the baseline.

    ``None`` means the reply was applied, whether or not it changed anything.
    """
    return next(
        (
            warning
            for warning in warnings
            if warning.startswith((_REVISION_FAILED, _REVISION_MERGE_DEGRADED))
        ),
        None,
    )


def _revision_failure_warnings(error_msg: str) -> list[str]:
    """Describe a failed revision while distinguishing validation degradation."""
    warnings = [f"{_REVISION_FAILED}{error_msg}"]
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
    dropped_authority: frozenset[tuple[str, str]] = frozenset(),
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
    # A delta that adds and restates nothing is not merged: merging
    # re-normalizes the structure, and that copy would read as revised.
    if not _delta_has_changes(revision_delta):
        post_revision = check_structural_heuristics(control_structure, loss_analysis)
        revision_warnings.extend(post_revision.errors)
        revision_warnings.extend(post_revision.warnings)
        return control_structure, revision_warnings

    # Merge the delta into the existing ControlStructure
    try:
        revised_cs, merge_warnings = _merge_revision_delta(
            control_structure, revision_delta, dropped_authority=dropped_authority
        )
    except Exception as exc:
        warning = f"{_REVISION_MERGE_DEGRADED}{type(exc).__name__}: {exc}"
        return control_structure, [warning]

    # Warnings are accumulated in chronological order: dismissal → merge →
    # strip → heuristics, so consumers see the earliest root-cause first.
    revision_warnings.extend(merge_warnings)

    # Strip empty responsibilities as a safety net
    revised_cs, strip_warnings = strip_empty_responsibilities(revised_cs)
    revision_warnings.extend(strip_warnings)

    # Re-run structural heuristics after revision
    post_revision = check_structural_heuristics(revised_cs, loss_analysis)
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
) -> tuple[ControlStructure, list[str]]:
    """Run a single revision attempt on the control structure.

    Requests a :class:`RevisionDelta` from the LLM (only new/modified
    elements) and merges it programmatically into the existing
    ControlStructure. After the merge, ``strip_empty_responsibilities``
    runs as a safety net, and structural heuristics are re-run.

    This is NOT a loop — one revision attempt maximum. After revision,
    structural heuristics are re-run. If structural errors remain, they
    are returned as warnings (the pipeline proceeds).

    A reply whose authority bases fail the checks earns the one correction,
    which shows the rejected delta and names every failing channel with its
    reason.  An undecodable reply earns the same one correction.  Bases that
    still fail
    after it are dropped, so those channels' authority is unknown.

    Args:
        llm_client: LLM client for making the completion call.
        control_structure: The current control structure to revise.
        critic_findings: The gaps identified by the critic.
        use_case_text: Free-text use-case description.
        run_dir: Directory for call logging.
        loss_analysis: Optional loss analysis for heuristic hazard tracing.
        template_loader: Optional template loader (defaults to SP1 prompts dir).
        temperature: LLM temperature (default 0.4).

    Returns:
        A tuple of (revised ControlStructure, post-revision heuristic warnings).
        On LLM failure, returns (pre-revision ControlStructure, [warning]).
    """
    loader = template_loader or TemplateLoader(PROMPTS_DIR)

    next_ids = _compute_next_ids(control_structure)

    system_prompt = loader.render_prompt(
        "revision_system.j2",
        control_structure=control_structure,
        use_case_text=use_case_text,
        **next_ids,
    )
    user_prompt = loader.render_prompt(
        "revision_user.j2",
        use_case_text=use_case_text,
        control_structure=control_structure,
        critic_findings=critic_findings,
        target_evidence=target_evidence,
    )

    def authority_note(error: Exception) -> str:
        if not isinstance(error, FeedbackAuthorityError):
            return ""
        return loader.render_prompt("revision_authority_correction.j2").rstrip()

    outcome = call_with_policy(
        llm_client=llm_client,
        system_prompt=system_prompt,
        user_prompt=user_prompt,
        response_format=_RevisionDeltaProviderSet,
        run_dir=run_dir,
        stage=STAGE,
        step=STEP_REVISION,
        policy=CorrectionPolicy(
            validation_retries=1,
            feedback=decode_aware_feedback(
                loader,
                reply_name="revision delta",
                feedback=_REVISION_VALIDATION_FEEDBACK,
            ),
            include_schema=False,
            include_response=True,
            error_note=authority_note,
            correct_undecodable=True,
        ),
        temperature=temperature,
        max_completion_tokens=REVISION_MAX_COMPLETION_TOKENS,
        raw_result_validator=lambda value: _validate_revision_wire(
            value, target_evidence=target_evidence
        ),
        response_parser=_parse_revision_result,
    )
    revision_delta, error_msg = outcome.value, outcome.error
    authority_warnings: list[str] = []
    dropped_authority: frozenset[tuple[str, str]] = frozenset()
    if error_msg is not None:
        salvaged = _revision_without_unsupported_authority(
            outcome, target_evidence=target_evidence
        )
        if salvaged is None:
            return control_structure, _revision_failure_warnings(error_msg)
        revision_delta = salvaged.delta
        authority_warnings = salvaged.warnings
        dropped_authority = salvaged.dropped_authority
    if revision_delta is None:
        return control_structure, [f"{_REVISION_FAILED}unexpected None response"]
    revised, revision_warnings = _finish_revision(
        control_structure,
        revision_delta,
        critic_findings=critic_findings,
        loss_analysis=loss_analysis,
        dropped_authority=dropped_authority,
    )
    return revised, [*authority_warnings, *revision_warnings]


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
    finding_count = len(critic_findings.gaps)
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
    dropped_authority: frozenset[tuple[str, str]] = frozenset(),
) -> list[Responsibility]:
    """Replace responsibilities whose resp_id appears in *modified*.

    Responsibilities not in the modified set are deep-copied as-is.  The
    ``resp_id`` is the pre-normalization stitch key, so every modified
    responsibility must name an existing responsibility exactly.  A
    non-canonical or otherwise unknown key cannot be matched safely.
    *dropped_authority* names the ``(resp_id, fb_id)`` of each restated
    channel whose assessment was dropped.
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
    return [
        _revised_responsibility(
            r,
            modified_map.get(r.resp_id, r),
            dropped_authority=frozenset(
                fb_id for resp_id, fb_id in dropped_authority if resp_id == r.resp_id
            ),
        )
        for r in resps
    ]


def _revised_responsibility(
    original: Responsibility,
    replacement: Responsibility,
    *,
    dropped_authority: frozenset[str] = frozenset(),
) -> Responsibility:
    """A completeness revision cannot revoke already established ownership links."""
    revised = copy.deepcopy(replacement)
    revised.security_constraint_refs = sorted(
        set(original.security_constraint_refs)
        | set(replacement.security_constraint_refs)
    )
    _carry_forward_context(original, revised, dropped_authority=dropped_authority)
    return revised


def _carry_forward_context(
    original: Responsibility,
    revised: Responsibility,
    *,
    dropped_authority: frozenset[str] = frozenset(),
) -> None:
    """Keep context fields a restated element omits.

    A revision restates a whole responsibility; the model may drop the
    optional context fields (PM values and evidence, CA target, effect,
    temporality, operation and PM refs, FB source, source kind and authority)
    of an element it did not mean to change.  An authority assessment is about
    the variable a channel updates, so it is kept only while the channel still
    updates that variable.  A channel in *dropped_authority* stated an
    assessment that was dropped as unsupported; it did not omit one, so its
    authority stays unknown.
    """
    _carry_forward_process_model_context(original, revised)
    _carry_forward_action_context(original, revised)
    old_fbs = {fb.fb_id: fb for fb in original.feedback_channels}
    for fb in revised.feedback_channels:
        old = old_fbs.get(fb.fb_id)
        if old is None:
            continue
        if fb.source is None:
            fb.source = old.source
        if fb.source_kind is None:
            fb.source_kind = old.source_kind
        if (
            fb.authority_for_update is None
            and fb.updates == old.updates
            and fb.fb_id not in dropped_authority
        ):
            fb.authority_for_update = old.authority_for_update


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
    """Keep the typed fields, operation and surviving PM refs a restated action omits.

    The effect is kept only while the action keeps its target: an effect
    fixed for one target does not carry to another.
    """
    revised_pm_ids = {pm.pm_id for pm in revised.process_model_parts}
    old_cas = {ca.ca_id: ca for ca in original.control_actions}
    for ca in revised.control_actions:
        old = old_cas.get(ca.ca_id)
        if old is None:
            continue
        if ca.target is None:
            ca.target = old.target
        if ca.effect_kind is None and ca.target == old.target:
            ca.effect_kind = old.effect_kind
        if ca.temporality is None:
            ca.temporality = old.temporality
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
    dropped_authority: frozenset[tuple[str, str]] = frozenset(),
) -> tuple[ControlStructure, list[str]]:
    """Stitch a revision delta onto the current structure by source ID.

    This is list surgery only.  Matching uses the pre-normalization
    source IDs so a modification can name an existing element even when
    that source ID is later rewritten.  Published IDs are assigned later
    from the stitched list positions.

    - Replaces ``modified_responsibilities`` by source ``resp_id`` while
      retaining their established governing security-constraint links;
      *dropped_authority* names the restated channels whose assessment was
      dropped, which keep no earlier assessment.
    - Appends new responsibilities, processes, and links whose source
      IDs are not already present.
    - Records ``cm_id`` collisions among newly added links so the
      operator can see the LLM chose a colliding mechanism ID.  Those
      IDs are not the published IDs; the subsequent normalization pass
      assigns ``CM-N`` from final list position.

    The returned structure is unvalidated: the revision delta keeps its IDs
    as written (``ASSEMBLY_DEFERRED``), so malformed source IDs must survive
    until the high-level normalizer sees the complete stitched lists.
    """
    existing_resp_ids = {r.resp_id for r in cs.responsibilities}
    existing_cp_ids = {cp.cp_id for cp in cs.controlled_processes}
    existing_cl_ids = {cl.link_id for cl in cs.coordination_links}

    merged_resps = _replace_modified_resps(
        cs.responsibilities, delta.modified_responsibilities, dropped_authority
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
    *,
    dropped_authority: frozenset[tuple[str, str]] = frozenset(),
) -> tuple[ControlStructure, list[str]]:
    """Merge a RevisionDelta into an existing ControlStructure.

    Stitch by source ID first, then hand the complete structure to the
    high-level ID policy.  Published IDs come from final list position;
    resolvable references are rewritten; unresolved references fail
    validation and degrade the revision.

    Returns a tuple of (merged ControlStructure, repair and stitch warnings).
    """
    delta, label_warnings = _restore_descriptions_with_pasted_labels(cs, delta)
    delta, kind_warnings = _move_source_kinds_out_of_source_refs(delta)
    stitched, stitch_warnings = _stitch_revision_delta(cs, delta, dropped_authority)
    return (
        validate_normalized_control_structure(stitched),
        label_warnings + kind_warnings + stitch_warnings,
    )


# The labels a revision prompt has shown for an element's typed fields, mapped
# to the field: the parenthetical labels of earlier prompts and the JSON field
# names of the current one.
_ACTION_LABELS = {
    "target": "target",
    "effect": "effect_kind",
    "effect_kind": "effect_kind",
    "temporality": "temporality",
    "operation": "operation",
    "process-model refs": "process_model_refs",
    "process_model_refs": "process_model_refs",
}
_PROCESS_MODEL_LABELS = {
    "source": "feedback_source",
    "feedback_source": "feedback_source",
    "values": "values",
    "evidence": "evidence_refs",
    "evidence_refs": "evidence_refs",
}
_FEEDBACK_LABELS = {
    "updates": "updates",
    "source": "source",
    "source kind": "source_kind",
    "source_kind": "source_kind",
    "authority for update": "authority_for_update.status",
    "authority_for_update.status": "authority_for_update.status",
    "authority basis": "authority_for_update.basis",
    "authority_for_update.basis": "authority_for_update.basis",
}
# One ``label: value`` item of a group.  Earlier prompts listed a channel's
# fields as comma-separated items of one group.
_LABEL_ITEM = re.compile(r"^([a-z_.\- ]+):\s*(.*)$", re.DOTALL)


def _plain_description(text: str) -> str:
    """Collapse whitespace and drop trailing punctuation for comparison."""
    return " ".join(text.split()).rstrip(" .,;:")


def _parenthesised_groups(text: str) -> list[str] | None:
    """Split *text* into the contents of its balanced parenthesised groups.

    Returns ``None`` unless *text* is only such groups separated by
    whitespace.  A group may itself contain balanced parentheses.
    """
    groups: list[str] = []
    index = 0
    while index < len(text):
        if text[index].isspace():
            index += 1
            continue
        if text[index] != "(":
            return None
        depth = 0
        for end in range(index, len(text)):
            depth += {"(": 1, ")": -1}.get(text[end], 0)
            if depth == 0:
                break
        else:
            return None
        groups.append(text[index + 1 : end])
        index = end + 1
    return groups


def _rendered_field(element: Any, field: str) -> str | None:
    """Render one typed field of *element* the way the revision prompt shows it."""
    owner, _, name = field.rpartition(".")
    if owner:
        element = getattr(element, owner, None)
    value = getattr(element, name or field, None) if element is not None else None
    if value is None or value == []:
        return None
    if isinstance(value, list):
        return ("; " if field == "values" else ", ").join(map(str, value))
    if hasattr(value, "id") and hasattr(value, "type"):
        return f"{getattr(value.type, 'value', value.type)} {value.id}"
    return " ".join(str(getattr(value, "value", value)).split())


def _is_pasted_field(
    label: str,
    value: str,
    labels: dict[str, str],
    elements: tuple[Any, ...],
    pm_ids: set[str],
) -> bool:
    """Whether ``label: value`` shows a typed field of one of *elements*.

    A process-model ref list is pasted when every ref names a PM part of the
    responsibility: a reply may paste the refs it meant to set.  Every other
    value must be the field's value on the original or restated element.
    """
    field = labels.get(label)
    if field is None:
        return False
    value = " ".join(value.split())
    if field == "process_model_refs":
        refs = [ref.strip() for ref in value.split(",")]
        return all(ref in pm_ids for ref in refs)
    return any(_rendered_field(element, field) == value for element in elements)


def _label_items(group: str, labels: dict[str, str]) -> list[str]:
    """Split a group at each comma that a known label follows.

    Only a comma outside nested parentheses separates items, so a value may
    itself contain ``, label:``.
    """
    marker = "|".join(re.escape(label) for label in sorted(labels, key=len)[::-1])
    next_label = re.compile(rf",\s*(?:{marker}):")
    items: list[str] = []
    depth = start = 0
    for index, char in enumerate(group):
        depth += {"(": 1, ")": -1}.get(char, 0)
        if char == "," and depth == 0 and next_label.match(group, index):
            items.append(group[start:index])
            start = index + 1
    items.append(group[start:])
    return [item.strip() for item in items]


def _is_pasted_group(
    group: str,
    labels: dict[str, str],
    elements: tuple[Any, ...],
    pm_ids: set[str],
) -> bool:
    """Whether a parenthesised group lists only typed fields of *elements*."""
    for item in _label_items(group.strip(), labels):
        match = _LABEL_ITEM.match(item)
        if match is None or not _is_pasted_field(
            match.group(1), match.group(2), labels, elements, pm_ids
        ):
            return False
    return True


def _only_appends_typed_fields(
    original: Any,
    restated: Any,
    labels: dict[str, str],
    pm_ids: set[str],
) -> bool:
    """Whether *restated*'s description is *original*'s plus pasted typed fields.

    Only the text appended to the original description is read.  It must be
    one or more balanced parenthesised groups, each listing typed fields whose
    values are the element's own.
    """
    before = _plain_description(original.description)
    after = _plain_description(restated.description)
    if not after.startswith(before) or after == before:
        return False
    suffix = after[len(before) :].lstrip(".,;:")
    groups = _parenthesised_groups(suffix)
    if not groups:
        return False
    return all(
        _is_pasted_group(group, labels, (original, restated), pm_ids)
        for group in groups
    )


def _restore_descriptions_with_pasted_labels(
    cs: ControlStructure,
    delta: RevisionDelta,
) -> tuple[RevisionDelta, list[str]]:
    """Keep an element's description when a restatement only appends labels.

    A reply may restate an existing PM part, control action, or feedback
    channel with its typed fields pasted after the description, such as
    ``(target: controlled_process CP-1) (effect: model_output)``.  When the
    restated description is the original followed only by groups that show
    the element's own typed field values, the original is kept; any other
    change to the description is a revision and stays.
    """
    delta = delta.model_copy(deep=True)
    warnings: list[str] = []
    originals = {resp.resp_id: resp for resp in cs.responsibilities}
    for resp in delta.modified_responsibilities:
        original = originals.get(resp.resp_id)
        if original is None:
            continue
        pm_ids = {
            pm.pm_id for owner in (original, resp) for pm in owner.process_model_parts
        }
        for kind, labels, restated, existing in (
            (
                "process model part",
                _PROCESS_MODEL_LABELS,
                {pm.pm_id: pm for pm in resp.process_model_parts},
                {pm.pm_id: pm for pm in original.process_model_parts},
            ),
            (
                "control action",
                _ACTION_LABELS,
                {ca.ca_id: ca for ca in resp.control_actions},
                {ca.ca_id: ca for ca in original.control_actions},
            ),
            (
                "feedback channel",
                _FEEDBACK_LABELS,
                {fb.fb_id: fb for fb in resp.feedback_channels},
                {fb.fb_id: fb for fb in original.feedback_channels},
            ),
        ):
            for element_id, element in restated.items():
                old = existing.get(element_id)
                if old is None or not _only_appends_typed_fields(
                    old, element, labels, pm_ids
                ):
                    continue
                warnings.append(
                    f"Revision {kind} {element_id} of {resp.resp_id} restated its "
                    "description with typed-field labels appended; the original "
                    "description is kept."
                )
                element.description = old.description
    return delta, warnings


_SOURCE_KINDS = {kind.value: kind for kind in FeedbackSourceKind}


def _move_source_kinds_out_of_source_refs(
    delta: RevisionDelta,
) -> tuple[RevisionDelta, list[str]]:
    """Read a source kind given as a feedback source's reference type.

    A source reference names a responsibility or controlled process.  A reply
    may instead write the channel's source kind (``session_context``,
    ``operation_result``, ...) as the reference ``type``; the two vocabularies
    are disjoint, so that reference names no element.  Its kind becomes the
    channel's ``source_kind`` and the reference is dropped, so a restated
    channel keeps its earlier source.  A kind that contradicts the channel's
    own ``source_kind`` is left for validation to reject.
    """
    delta = delta.model_copy(deep=True)
    warnings: list[str] = []
    for resp in (*delta.new_responsibilities, *delta.modified_responsibilities):
        for fb in resp.feedback_channels:
            if fb.source is None or isinstance(fb.source.type, ReferenceType):
                continue
            kind = _SOURCE_KINDS.get(fb.source.type)
            if kind is None or fb.source_kind not in (None, kind):
                continue
            warnings.append(
                f"Revision feedback channel {fb.fb_id} of {resp.resp_id} gave the "
                f"source kind '{kind.value}' as its source type; it is kept as "
                "the channel's source_kind and the source reference "
                f"'{fb.source.id}', which names no responsibility or controlled "
                "process, is dropped."
            )
            fb.source_kind = kind
            fb.source = None
    return delta, warnings


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
