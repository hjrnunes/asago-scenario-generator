"""Deterministic checks for model-authored feedback-authority assessments."""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Protocol

from asago_scenario_generator.stpa.models.control_structure import (
    FeedbackAuthorityStatus,
    FeedbackSourceKind,
    FeedbackUpdateAuthority,
)
from asago_scenario_generator.stpa.system_model.target_evidence import TargetEvidence


_EVIDENCE_REF_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?:operation|argument|session|state|policy):"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.:-]*[A-Za-z0-9])?"
)
_USE_CASE_CITATION_RE = re.compile(r"\buse[ -]case\b", re.IGNORECASE)
_WORD_RE = re.compile(r"[a-z0-9]+")

_GENERIC_RESTATEMENT_WORDS = frozenset(
    {
        "a",
        "an",
        "are",
        "as",
        "comes",
        "current",
        "data",
        "earlier",
        "from",
        "information",
        "is",
        "kind",
        "of",
        "only",
        "provided",
        "reported",
        "source",
        "supplied",
        "the",
        "trusted",
        "untrusted",
        "unverified",
        "value",
        "was",
        "were",
    }
)
_SOURCE_KIND_WORDS = {
    FeedbackSourceKind.operation_result: frozenset(
        {"operation", "output", "response", "result", "results", "tool"}
    ),
    FeedbackSourceKind.session_context: frozenset(
        {"context", "field", "runtime", "session"}
    ),
    FeedbackSourceKind.user_message: frozenset(
        {"input", "message", "request", "requester", "text", "user"}
    ),
    FeedbackSourceKind.conversation_history: frozenset(
        {"conversation", "history", "prior", "turn", "turns"}
    ),
    FeedbackSourceKind.retrieved_content: frozenset(
        {"content", "document", "documents", "retrieved", "text"}
    ),
    FeedbackSourceKind.other: frozenset({"other"}),
}
_SCOPE_FILLER_WORDS = frozenset(
    {
        "and",
        "authoritative",
        "basis",
        "cited",
        "cites",
        "conditional",
        "evidence",
        "for",
        "non",
        "or",
        "per",
        "ref",
        "reference",
        "references",
        "says",
        "source",
        "status",
        "the",
        "unknown",
    }
)


class _AuthorityChannel(Protocol):
    """The authority-bearing fields shared by Call 2b and revision wires."""

    fb_id: str
    source_kind: FeedbackSourceKind | None
    authority_for_update: FeedbackUpdateAuthority | None


def validate_feedback_authority_assessments(
    channels: Iterable[_AuthorityChannel],
    *,
    target_evidence: TargetEvidence | None,
    require_domain_scope: bool,
) -> None:
    """Validate authority bases against evidence offered in the request.

    Semantic authority remains the model's judgment. This check enforces only
    what code can know exactly: citations exist in the request, and a basis is
    more than an evidence handle or a spelling-out of ``source_kind``.
    """
    offered_refs = (
        target_evidence.refs() if target_evidence is not None else frozenset()
    )
    for channel in channels:
        assessment = channel.authority_for_update
        if assessment is None or assessment.basis is None:
            continue
        basis = assessment.basis
        cited_refs = tuple(dict.fromkeys(_EVIDENCE_REF_RE.findall(basis)))
        unknown_refs = tuple(ref for ref in cited_refs if ref not in offered_refs)
        if unknown_refs:
            raise ValueError(
                f"feedback channel {channel.fb_id} authority basis cites "
                "target-evidence ref(s) not offered in this request: "
                + ", ".join(unknown_refs)
            )
        cites_use_case = _USE_CASE_CITATION_RE.search(basis) is not None
        if _only_restates_source_kind(
            basis,
            source_kind=channel.source_kind,
            cited_refs=cited_refs,
            cites_use_case=cites_use_case,
        ):
            kind = channel.source_kind.value if channel.source_kind else "unspecified"
            raise ValueError(
                f"feedback channel {channel.fb_id} authority basis only restates "
                f"source kind {kind!r}; state why that source may or may not "
                "establish this value and cite supplied evidence"
            )
        if (
            assessment.status is not FeedbackAuthorityStatus.unknown
            and not cites_use_case
            and not cited_refs
        ):
            raise ValueError(
                f"feedback channel {channel.fb_id} settled authority basis must "
                "cite the supplied use case or an exact target-evidence ref"
            )
        if require_domain_scope and not _states_domain_scope(basis, cited_refs):
            raise ValueError(
                f"feedback channel {channel.fb_id} authority basis must state "
                "its scope in domain words, not only evidence refs"
            )


def _only_restates_source_kind(
    basis: str,
    *,
    source_kind: FeedbackSourceKind | None,
    cited_refs: tuple[str, ...],
    cites_use_case: bool,
) -> bool:
    """Return whether *basis* says only what kind of source the channel has."""
    if source_kind is None or cited_refs or cites_use_case:
        return False
    words = frozenset(_WORD_RE.findall(basis.casefold()))
    kind_words = _SOURCE_KIND_WORDS.get(source_kind, frozenset())
    return bool(words & kind_words) and words <= _GENERIC_RESTATEMENT_WORDS | kind_words


def _states_domain_scope(basis: str, cited_refs: tuple[str, ...]) -> bool:
    """Return whether a basis contains meaning beyond citations and labels."""
    prose = basis
    for ref in cited_refs:
        prose = prose.replace(ref, " ")
    prose = _USE_CASE_CITATION_RE.sub(" ", prose)
    words = set(_WORD_RE.findall(prose.casefold()))
    return bool(words - _SCOPE_FILLER_WORDS)


__all__ = ["validate_feedback_authority_assessments"]
