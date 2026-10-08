"""Helpers shared by the stages that call a model adapter."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from asago_scenario_generator.models.canonical import compute_framed_digest
from asago_scenario_generator.models.obligation_consideration import (
    ConsiderationCallEvidence,
)


def call_with_feedback(
    method: Callable[..., Any], request: Any, feedback: str | None
) -> Any:
    """Call one adapter stage, passing a bounded schema correction if any."""
    if feedback is None:
        return method(request)
    return method(request, correction_feedback=feedback)


def response_digest(response: Any | None, domain: str) -> str | None:
    """Return the response's own digest, else its framed digest in *domain*."""
    if response is None:
        return None
    return getattr(response, "response_digest", None) or compute_framed_digest(
        domain, response.model_dump(mode="json")
    )


def call_evidence(
    call_id: str,
    attempts: int,
    outcome: str,
    *,
    request_digest: str | None = None,
    controls: Any | None = None,
    response: Any | None = None,
    digest_domain: str | None = None,
) -> ConsiderationCallEvidence:
    """Record one model call; *digest_domain* is required with a *response*."""
    return ConsiderationCallEvidence(
        call_id=call_id,
        request_digest=request_digest,
        response_digest=(
            None if response is None else response_digest(response, str(digest_domain))
        ),
        model_profile=None if controls is None else controls.model_profile,
        model_name=None if controls is None else controls.model_name,
        attempt_count=attempts,
        outcome=outcome,
    )
