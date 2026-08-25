"""Conversion of runtime evidence into durable persistence records."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import JsonValue

from asago_scenario_generator.pipeline.finalization_admission import (
    PostbehaviorAdmissionReport,
)
from asago_scenario_generator.pipeline.generation_contracts import (
    CausalRetryControl,
    StageAttemptFailure,
    StageCallEvidence,
)
from .persistence_common import _json_value
from .persistence_journal import AdmittedArtifactPublication, AdmittedTerminalPayload
from .persistence_models import (
    CallMetadataRecord,
    GateResultRecord,
    LLMResultRecord,
    PromptRecord,
    StageAttemptFailureRecord,
    StageCallEvidenceRecord,
    ViolationRecord,
)


def make_admitted_terminal_payload(
    report: PostbehaviorAdmissionReport,
    publication: AdmittedArtifactPublication,
) -> AdmittedTerminalPayload:
    """Phase 5 seam joining concrete admission gates to publication bytes."""

    if type(report) is not PostbehaviorAdmissionReport:
        raise TypeError("admission persistence requires PostbehaviorAdmissionReport")
    return AdmittedTerminalPayload(report=report, publication=publication)


def _llm_result(value: Any) -> LLMResultRecord:
    return LLMResultRecord(
        content=_json_value(value.content),
        prompt_tokens=value.prompt_tokens,
        completion_tokens=value.completion_tokens,
        duration_ms=value.duration_ms,
        system_prompt=value.system_prompt,
        user_prompt=value.user_prompt,
        request_controls=_json_value(getattr(value, "request_controls", {})),
    )


def _pipeline_log_response(value: Any) -> Any:
    """Convert one LLM result content to the historical log representation."""
    content = value.content
    if content is None:
        return None
    if hasattr(content, "model_dump"):
        return content.model_dump(mode="json")
    return content if isinstance(content, str) else str(content)


def _call_evidence(value: StageCallEvidence) -> StageCallEvidenceRecord:
    return StageCallEvidenceRecord(
        call_name=value.call_name.value,
        result=_llm_result(value.result),
        metadata=CallMetadataRecord(
            call=value.metadata.call.value,
            prompt_tokens=value.metadata.prompt_tokens,
            completion_tokens=value.metadata.completion_tokens,
            duration_ms=value.metadata.duration_ms,
        ),
        semantic_evidence=(
            _json_value(value.semantic_evidence.as_dict())
            if value.semantic_evidence is not None
            else None
        ),
    )


def _prompt_record(value: Any) -> PromptRecord | None:
    if value.system_prompt is None and value.user_prompt is None:
        return None
    return PromptRecord(
        system_prompt=value.system_prompt,
        user_prompt=value.user_prompt,
    )


def _semantic_json(value: Any) -> JsonValue | None:
    return _json_value(value.as_dict()) if value is not None else None


def _attempt_failure(value: StageAttemptFailure) -> StageAttemptFailureRecord:
    prompt = _prompt_record(value)
    return StageAttemptFailureRecord(
        call_name=value.call_name.value,
        exception_type=value.exception_type,
        detail=value.detail,
        phase=value.phase,
        invoked=value.invoked,
        code=value.code,
        retryable=value.retryable,
        semantic_evidence=_semantic_json(value.semantic_evidence),
        finish_reason=value.finish_reason,
        prompt_tokens=value.prompt_tokens,
        completion_tokens=value.completion_tokens,
        total_tokens=value.total_tokens,
        usage_details=_json_value(value.usage_details or {}),
        response_id=value.response_id,
        model=value.model,
        partial_character_count=value.partial_character_count,
        partial_sha256=value.partial_sha256,
        partial_preview_prefix=value.partial_preview_prefix,
        partial_preview_suffix=value.partial_preview_suffix,
        elapsed_ms=value.elapsed_ms,
        request_controls=_json_value(value.request_controls),
        prompt=prompt,
        result=_llm_result(value.result) if value.result is not None else None,
        raw_response=(
            _json_value(value.raw_response) if value.raw_response is not None else None
        ),
    )


def _retry_control(value: CausalRetryControl | None) -> JsonValue | None:
    if value is None:
        return None
    return {
        "control_id": value.control_id,
        "field": value.field,
        "initial_value": value.initial_value,
        "retry_value": value.retry_value,
    }


def _violation_record(value: Any) -> ViolationRecord:
    owner = getattr(value, "owner", None)
    code = getattr(value, "code", "invalid")
    if isinstance(code, Enum):
        serialized_code = code.value
    elif isinstance(code, str):
        serialized_code = code
    else:
        raise TypeError("violation code must be a string or enum")
    return ViolationRecord(
        code=serialized_code,
        detail=value.detail,
        owner=owner,
        retryable=getattr(value, "retryable", owner is not None),
    )


def _gate_report_records(
    report: PostbehaviorAdmissionReport,
) -> list[GateResultRecord]:
    if type(report) is not PostbehaviorAdmissionReport:
        raise TypeError("admission persistence requires PostbehaviorAdmissionReport")
    return [
        GateResultRecord(
            gate=gate.evidence_id,
            passed=gate.passed,
            applicable=gate.applicable,
            violations=[_violation_record(v) for v in gate.violations],
            diagnostics=[_violation_record(d) for d in gate.diagnostics],
        )
        for gate in report.gate_results
    ]
