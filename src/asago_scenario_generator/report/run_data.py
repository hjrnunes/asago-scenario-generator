"""Read one generate output directory into typed values for the report.

The report is the producer's view of its own work, so it reads the producer's
sidecars. Sidecars with a producer model load through that model. The
manifest, the call log, the obligation plan and the testability summary are
large or loosely shaped files, so the report declares only the fields it
reads, and ignores the rest. An absent optional sidecar is ``None``; an
invalid one raises, so the report never renders a guess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
)

from asago_scenario_generator.models.mechanism_suggestion_accounting import (
    MECHANISM_SUGGESTION_ACCOUNTING_FILENAME,
    MechanismSuggestionAccounting,
)
from asago_scenario_generator.models.obligation_accounting import ObligationAccounting
from asago_scenario_generator.models.slot_hazard_offer import SlotHazardOfferReport
from asago_scenario_generator.models.target_realization import TargetRealizationResult
from asago_scenario_generator.stpa.infra.call_log import call_entries, jsonl_lines
from asago_scenario_generator.stpa.infra.provider_record import RECORD_FILENAME
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.scenario_prod.handoff import (
    ScenarioHandoff,
)
from asago_scenario_generator.stpa.system_model.risk_actionability import (
    RiskActionabilityRecord,
)

MANIFEST = "synthesis-manifest.yaml"
CALLS = "calls.jsonl"
POLICY = "policy-coverage.json"

_M = TypeVar("_M", bound=BaseModel)


class _Read(BaseModel):
    """A read model: it names the fields the report uses and ignores the rest."""

    model_config = ConfigDict(extra="ignore")


class ProviderRequest(_Read):
    """The ``provider-calls.jsonl`` record of one request a call sent."""

    sequence: int
    request_sha256: str


class CallRecord(_Read):
    """One request of ``calls.jsonl``; ``n`` is its 1-based entry number.

    ``response_content`` is the reply text.  A call log written before calls
    named their provider records holds it; for a newer log the report reads
    a successful call's reply from the record of its last request.  The old
    log stored a reply the client had parsed against its response model as
    that model's JSON dump; ``response_parsed`` marks such a reply, whose raw
    text a reader must normalize as the model did.  ``finish_reason`` is why
    a failed call's last reply stopped, read from its provider record.
    """

    n: int = 0
    stage: str
    step: str
    slot_id: str | None = None
    scenario_id: str | None = None
    attempt_id: str | None = None
    attempt_number: int = 1
    success: bool
    failure_class: str | None = None
    error: str | None = None
    terminal_error_codes: list[str] = Field(default_factory=list)
    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    duration_ms: int = 0
    retry_of: str | None = None
    provider_requests: list[ProviderRequest] = Field(default_factory=list)
    response_parsed: bool = False
    response_content: str | None = None
    finish_reason: str | None = None

    @property
    def tokens(self) -> int:
        return (self.prompt_tokens or 0) + (self.completion_tokens or 0)


class CandidateOutcome(_Read):
    scenario_id: str
    ica_slot_id: str | None = None
    ica_id: str | None = None
    status: str
    reason_code: str | None = None
    diagnostics: list[str] = Field(default_factory=list)


class VerificationRecord(_Read):
    """The verifier's judgement of one finding (ICA)."""

    ica_id: str
    slot_id: str
    disposition: str
    final_verdict: dict[str, Any] | None = None
    request: dict[str, Any] | None = None
    corrected_request: dict[str, Any] | None = None
    correction: Any = None


class VerificationDiagnostic(_Read):
    """One diagnostic of the verification batch, such as a slot/hazard flag."""

    code: str
    detail: str
    refs: list[str] = Field(default_factory=list)


class _Verification(_Read):
    records: list[VerificationRecord] = Field(default_factory=list)
    diagnostics: list[VerificationDiagnostic] = Field(default_factory=list)


class _IcaEvidence(_Read):
    ica_hazard_verification: _Verification = Field(default_factory=_Verification)


class _ProviderEvidence(_Read):
    ica: _IcaEvidence = Field(default_factory=_IcaEvidence)


class Manifest(_Read):
    schema_version: str
    run_id: str
    created_at: str
    run_status: str
    run_status_reason: str | None = None
    scenario_counts: dict[str, int | None] = Field(default_factory=dict)
    candidate_outcomes: list[CandidateOutcome] = Field(default_factory=list)
    stage_warnings: list[str] = Field(default_factory=list)
    stage_errors: list[Any] = Field(default_factory=list)
    context_tables: dict[str, Any] | None = None
    model_controls: dict[str, Any] = Field(default_factory=dict)
    total_prompt_tokens: int | None = None
    obligation_resolution_funnel: dict[str, Any] | None = None
    obligation_scope_summary: dict[str, Any] | None = None
    obligation_stop_reason_counts: dict[str, int] = Field(default_factory=dict)
    revision: dict[str, Any] | None = None
    source_artifacts: dict[str, dict[str, Any]] = Field(default_factory=dict)
    provider_evidence: _ProviderEvidence = Field(default_factory=_ProviderEvidence)

    @field_validator("candidate_outcomes", mode="before")
    @classmethod
    def _unreported(cls, value: Any) -> Any:
        return [] if value is None else value

    @property
    def verifications(self) -> list[VerificationRecord]:
        return self.provider_evidence.ica.ica_hazard_verification.records


class _PlanRisk(_Read):
    risk_id: str
    risk_name: str = ""


class PlanObligation(_Read):
    obligation_id: str
    risk_ref: _PlanRisk
    attack_pattern_id: str | None = None


class _Plan(_Read):
    obligations: list[PlanObligation] = Field(default_factory=list)


class _DedupKey(_Read):
    uca_id: str | None = None
    claim_level: str | None = None
    constraint_ids: list[str] = Field(default_factory=list)


class TestabilityRow(_Read):
    __test__ = False

    scenario_id: str
    status: str
    duplicate_of: str | None = None
    key: _DedupKey = Field(default_factory=_DedupKey)


class NotApplicableRow(_Read):
    """A candidate code routed before Stage 5: kept and counted, never written."""

    scenario_id: str
    ica_slot_id: str | None = None
    ica_id: str | None = None
    reason_code: str
    reason: str = ""


class _Testability(_Read):
    scenarios: list[TestabilityRow] = Field(default_factory=list)
    not_applicable: list[NotApplicableRow] = Field(default_factory=list)


class _Batching(_Read):
    planned_batch_sizes: list[int] = Field(default_factory=list)


class CoverageReview(_Read):
    status: str
    failure_reason: str | None = None
    batching: _Batching = Field(default_factory=_Batching)


@dataclass(frozen=True)
class RunData:
    """Everything the generate report reads, loaded once."""

    output_dir: Path
    manifest: Manifest
    calls: tuple[CallRecord, ...]
    loss: LossAnalysis | None
    actionability: RiskActionabilityRecord | None
    structure: ControlStructure | None
    offers: SlotHazardOfferReport | None
    accounting: ObligationAccounting | None
    mechanisms: MechanismSuggestionAccounting | None
    plan: tuple[PlanObligation, ...] | None
    realization: TargetRealizationResult | None
    testability: dict[str, TestabilityRow] | None
    coverage_review: CoverageReview | None
    scenarios: dict[str, ScenarioHandoff]
    features: dict[str, str]
    policy: dict[str, Any] | None
    unreadable: dict[str, str] = field(default_factory=dict)
    # The candidates the testability record lists as not applicable.
    not_applicable: tuple[NotApplicableRow, ...] = ()

    def has(self, name: str) -> bool:
        """Tell whether *name* is a file of the output directory."""
        return (self.output_dir / name).exists()


def _reason(error: Exception) -> str:
    return " ".join(str(error).split())[:300]


def _read_yaml(
    output: Path, name: str, model: type[_M], unreadable: dict[str, str]
) -> _M | None:
    """Load a sidecar through its model; one that does not load is named, not guessed at."""
    path = output / name
    if not path.exists():
        return None
    try:
        return model.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))
    except (ValidationError, yaml.YAMLError) as error:
        unreadable[name] = _reason(error)
        return None


def _read_policy(output: Path, unreadable: dict[str, str]) -> dict[str, Any] | None:
    path = output / POLICY
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        unreadable[POLICY] = _reason(error)
        return None


def _read_calls(output: Path) -> tuple[CallRecord, ...]:
    path = output / CALLS
    if not path.exists():
        return ()
    entries = call_entries(path.read_text(encoding="utf-8"))
    calls = [
        CallRecord.model_validate(entry).model_copy(update={"n": n})
        for n, entry in enumerate(entries, 1)
    ]
    return tuple(_with_replies(output, calls))


def _reply_key(call: CallRecord) -> tuple[int, str] | None:
    """The provider record holding *call*'s last reply, when the log names it."""
    if call.success and call.response_content is not None:
        return None
    if not call.provider_requests:
        return None
    last = call.provider_requests[-1]
    return last.sequence, last.request_sha256


def _with_replies(output: Path, calls: list[CallRecord]) -> list[CallRecord]:
    """Fill each call's reply evidence from the provider record it names.

    A successful call gets its reply text; a failed call gets the reason its
    last reply stopped.
    """
    wanted = {key for call in calls if (key := _reply_key(call)) is not None}
    if not wanted:
        return calls
    replies = _provider_replies(output / RECORD_FILENAME, wanted)
    return [
        call.model_copy(update=_reply_fields(call, replies.get(key, (None, None))))
        if (key := _reply_key(call)) is not None
        else call
        for call in calls
    ]


def _reply_fields(
    call: CallRecord, reply: tuple[str | None, str | None]
) -> dict[str, Any]:
    content, finish_reason = reply
    if call.success:
        return {"response_content": content}
    return {"finish_reason": finish_reason}


def _provider_replies(
    path: Path, wanted: set[tuple[int, str]]
) -> dict[tuple[int, str], tuple[str | None, str | None]]:
    """Read the message content and finish reason of the *wanted* provider records."""
    if not path.exists():
        return {}
    replies: dict[tuple[int, str], tuple[str | None, str | None]] = {}
    for line in jsonl_lines(path.read_text(encoding="utf-8")):
        record = json.loads(line)
        key = (record.get("sequence"), record.get("request_sha256"))
        if key in wanted:
            response = record.get("response") or {}
            replies[key] = (_message_content(record), response.get("finish_reason"))
    return replies


def _message_content(record: dict[str, Any]) -> str | None:
    body = (record.get("response") or {}).get("body") or {}
    choices = body.get("choices") or []
    message = choices[0].get("message") if choices else None
    content = message.get("content") if isinstance(message, dict) else None
    return content if isinstance(content, str) else None


def _read_scenarios(output: Path) -> dict[str, ScenarioHandoff]:
    folder = output / "scenarios"
    paths = sorted(folder.glob("SCN-*.yaml")) if folder.is_dir() else []
    documents = {
        path.stem: yaml.safe_load(path.read_text(encoding="utf-8")) for path in paths
    }
    return {
        stem: ScenarioHandoff.model_validate(document)
        for stem, document in documents.items()
    }


def _read_features(output: Path) -> dict[str, str]:
    folder = output / "scenarios"
    paths = sorted(folder.glob("SCN-*.feature")) if folder.is_dir() else []
    return {path.stem: path.read_text(encoding="utf-8") for path in paths}


def load_run(output_dir: Path | str) -> RunData:
    """Load the sidecars of one generate run from *output_dir*."""
    output = Path(output_dir)
    unreadable: dict[str, str] = {}
    manifest = _read_yaml(output, MANIFEST, Manifest, unreadable)
    if manifest is None:
        if MANIFEST in unreadable:
            raise ValueError(f"{MANIFEST}: {unreadable[MANIFEST]}")
        raise FileNotFoundError(output / MANIFEST)
    plan = _read_yaml(output, "taxonomy-obligation-plan.yaml", _Plan, unreadable)
    testability = _read_yaml(output, "testability.yaml", _Testability, unreadable)
    return RunData(
        output_dir=output,
        manifest=manifest,
        calls=_read_calls(output),
        loss=_read_yaml(output, "loss-analysis.yaml", LossAnalysis, unreadable),
        actionability=_read_yaml(
            output, "risk-actionability.yaml", RiskActionabilityRecord, unreadable
        ),
        structure=_read_yaml(
            output, "control-structure.yaml", ControlStructure, unreadable
        ),
        offers=_read_yaml(
            output, "slot-hazard-offers.yaml", SlotHazardOfferReport, unreadable
        ),
        accounting=_read_yaml(
            output, "obligation-accounting.yaml", ObligationAccounting, unreadable
        ),
        mechanisms=_read_yaml(
            output,
            MECHANISM_SUGGESTION_ACCOUNTING_FILENAME,
            MechanismSuggestionAccounting,
            unreadable,
        ),
        plan=None if plan is None else tuple(plan.obligations),
        realization=_read_yaml(
            output, "target-realization.yaml", TargetRealizationResult, unreadable
        ),
        testability=(
            None
            if testability is None
            else {row.scenario_id: row for row in testability.scenarios}
        ),
        coverage_review=_read_yaml(
            output,
            "loss-analysis-risk-coverage-review.yaml",
            CoverageReview,
            unreadable,
        ),
        scenarios=_read_scenarios(output),
        features=_read_features(output),
        policy=_read_policy(output, unreadable),
        unreadable=unreadable,
        not_applicable=(
            () if testability is None else tuple(testability.not_applicable)
        ),
    )
