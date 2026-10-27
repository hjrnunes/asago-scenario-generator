"""Deterministic checks for model-authored feedback-authority assessments."""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from typing import Protocol

from asago_scenario_generator.stpa.infra.llm_helpers import ExactFeedbackError
from asago_scenario_generator.stpa.models.control_structure import (
    FeedbackAuthorityStatus,
    FeedbackSourceKind,
    FeedbackUpdateAuthority,
)
from asago_scenario_generator.stpa.system_model.target_evidence import TargetEvidence


# A ref is ``kind:name``.  The kind is one of five fixed words, so a basis
# that opens a sentence with ``State:`` still cites a state record; the name
# is the target's own identifier and must match exactly.
_EVIDENCE_REF_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?i:operation|argument|session|state|policy):"
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

    Raises:
        ValueError: For the first channel whose basis fails.  The class stays
            ``ValueError`` because correction prompts name it.
    """
    offered_refs = _offered_refs(target_evidence)
    for channel in channels:
        reason = _basis_defect(
            channel,
            offered_refs=offered_refs,
            require_domain_scope=require_domain_scope,
        )
        if reason is not None:
            raise ValueError(reason)


class FeedbackAuthorityError(ExactFeedbackError):
    """Every channel whose authority basis fails the checks, in reply order.

    ``defects`` holds ``(fb_id, reason)`` for each failing channel.  The
    message lists every reason on a line of its own, so the one correction
    request names each failing channel.  It is not shortened, however long
    the list.
    """

    max_chars = None

    def __init__(self, defects: Sequence[tuple[str, str]]) -> None:
        self.defects = tuple(defects)
        count = len(self.defects)
        heading = (
            "1 feedback channel authority basis fails the checks:"
            if count == 1
            else f"{count} feedback channel authority bases fail the checks:"
        )
        super().__init__(
            "\n".join([heading, *(f"- {reason}" for _, reason in self.defects)])
        )


def validate_all_feedback_authority_assessments(
    channels: Iterable[_AuthorityChannel],
    *,
    target_evidence: TargetEvidence | None,
    require_domain_scope: bool,
) -> None:
    """Check bases as :func:`validate_feedback_authority_assessments` does.

    Unlike that function, it does not stop at the first failing channel.

    Raises:
        FeedbackAuthorityError: Naming each channel whose basis fails, in the
            order of *channels*.
    """
    offered_refs = _offered_refs(target_evidence)
    defects = [
        (channel.fb_id, reason)
        for channel in channels
        if (
            reason := _basis_defect(
                channel,
                offered_refs=offered_refs,
                require_domain_scope=require_domain_scope,
            )
        )
        is not None
    ]
    if defects:
        raise FeedbackAuthorityError(defects)


def feedback_authority_defect(
    channel: _AuthorityChannel,
    *,
    target_evidence: TargetEvidence | None,
    require_domain_scope: bool,
) -> str | None:
    """Return why *channel*'s authority basis fails the checks, or ``None``.

    The reason is the message :func:`validate_feedback_authority_assessments`
    raises for that channel.
    """
    return _basis_defect(
        channel,
        offered_refs=_offered_refs(target_evidence),
        require_domain_scope=require_domain_scope,
    )


def _offered_refs(target_evidence: TargetEvidence | None) -> frozenset[str]:
    return target_evidence.refs() if target_evidence is not None else frozenset()


def _basis_defect(
    channel: _AuthorityChannel,
    *,
    offered_refs: frozenset[str],
    require_domain_scope: bool,
) -> str | None:
    """Return why *channel*'s authority basis fails, or ``None`` if it passes."""
    assessment = channel.authority_for_update
    if assessment is None or assessment.basis is None:
        return None
    basis = assessment.basis
    cited_refs = _cited_refs(basis)
    unknown_refs = tuple(ref for ref in cited_refs if ref not in offered_refs)
    if unknown_refs:
        return (
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
        return (
            f"feedback channel {channel.fb_id} authority basis only restates "
            f"source kind {kind!r}; state why that source may or may not "
            "establish this value and cite supplied evidence"
        )
    if (
        assessment.status is not FeedbackAuthorityStatus.unknown
        and not cites_use_case
        and not cited_refs
    ):
        return (
            f"feedback channel {channel.fb_id} settled authority basis must "
            "cite the supplied use case or an exact target-evidence ref"
        )
    if require_domain_scope and not _states_domain_scope(basis):
        return (
            f"feedback channel {channel.fb_id} authority basis must state "
            "its scope in domain words, not only evidence refs"
        )
    return None


def _cited_refs(basis: str) -> tuple[str, ...]:
    """Return the evidence refs *basis* cites, each with its kind in lower case."""
    refs = (
        f"{kind.lower()}:{name}"
        for kind, _, name in (
            match.partition(":") for match in _EVIDENCE_REF_RE.findall(basis)
        )
    )
    return tuple(dict.fromkeys(refs))


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


def _states_domain_scope(basis: str) -> bool:
    """Return whether a basis contains meaning beyond citations and labels."""
    prose = _USE_CASE_CITATION_RE.sub(" ", _EVIDENCE_REF_RE.sub(" ", basis))
    words = set(_WORD_RE.findall(prose.casefold()))
    return bool(words - _SCOPE_FILLER_WORDS)


__all__ = [
    "FeedbackAuthorityError",
    "feedback_authority_defect",
    "validate_all_feedback_authority_assessments",
    "validate_feedback_authority_assessments",
]
