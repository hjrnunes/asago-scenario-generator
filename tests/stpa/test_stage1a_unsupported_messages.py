"""The exact text of every Stage 1a "targeted repair unsupported" stop.

Each stop reaches ``stage.json`` and the repair record verbatim, so these
tests pin the message, the recorded scope and reason, and the chained
cause, with the routing inputs replaced by fakes.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.system_model import loss_analysis as la
from asago_scenario_generator.stpa.system_model.loss_analysis_repair import (
    UnsupportedRepair,
)

ERROR = "first error"
FEEDBACK = "Validation feedback: fix it."


def _call(failure_class: str | None) -> SimpleNamespace:
    recorded: list[tuple[str, str]] = []
    return SimpleNamespace(
        step="gap_analysis",
        failure_class=failure_class,
        validation_feedback=FEEDBACK,
        first_wire_error=object(),
        first_parse_failed=False,
        response_format=la._Stage1aGapProviderDraft,
        authoritative_draft=None,
        accounting_cards=(),
        require_risk_accounting=False,
        repair_record=None,
        recorded=recorded,
        record_unsupported=lambda scope, reason: recorded.append((scope, reason)),
    )


def _raised(action) -> StageError:
    with pytest.raises(StageError) as caught:
        action()
    return caught.value


@pytest.mark.parametrize(
    ("failure_class", "shown"), [(None, "unknown"), ("draft_semantics", None)]
)
def test_unsupported_repair_plan(monkeypatch, failure_class, shown) -> None:
    call = _call(failure_class)
    monkeypatch.setattr(la, "_reject_unsupported_wire_error", lambda *a: None)
    monkeypatch.setattr(
        la, "_require_repair_input", lambda *a: (object(), la._Stage1aGapRepairDraft)
    )
    monkeypatch.setattr(la, "_check_repair_graph", lambda *a: None)
    monkeypatch.setattr(
        la,
        "build_repair_plan",
        lambda **kw: UnsupportedRepair(reason="out of scope", scope="SC-1"),
    )

    error = _raised(lambda: la._repair_stage1a_failure(call, None, ERROR))

    assert str(error) == (
        "stage_1a/gap_analysis: targeted repair unsupported (out of scope); "
        f"no repair call was made; {shown or failure_class} failure class; "
        f"first attempt failed: {ERROR}. {FEEDBACK}"
    )
    assert call.recorded == [("SC-1", "out of scope")]


@pytest.mark.parametrize(
    ("failure_class", "shown"), [(None, "wire_schema"), ("draft_semantics", None)]
)
def test_unsupported_wire_error(monkeypatch, failure_class, shown) -> None:
    call = _call(failure_class)
    reason = "hazards container is not a list"
    monkeypatch.setattr(
        la,
        "classify_wire_validation_errors",
        lambda exc: SimpleNamespace(unsupported_reason=reason),
    )

    error = _raised(lambda: la._reject_unsupported_wire_error(call, ERROR))

    assert str(error) == (
        f"stage_1a/gap_analysis: targeted repair unsupported ({reason}); "
        f"{shown or failure_class} failure class; no repair call was made; "
        f"first attempt failed: {ERROR}. {FEEDBACK}"
    )
    assert call.recorded == [("hazards", reason)]


@pytest.mark.parametrize(
    ("failure_class", "shown"), [(None, "unknown"), ("draft_semantics", None)]
)
def test_missing_repair_input(monkeypatch, failure_class, shown) -> None:
    call = _call(failure_class)
    monkeypatch.setattr(
        la, "_prepare_current_provider_repair_input", lambda *a, **kw: None
    )
    monkeypatch.setattr(la, "_missing_repair_input_reason", lambda *a: "no wire")

    error = _raised(lambda: la._require_repair_input(call, None, ERROR))

    assert str(error) == (
        "stage_1a/gap_analysis: targeted repair unsupported (no wire); "
        f"{shown or failure_class} failure class; no repair call was made; "
        f"first attempt failed: {ERROR}. {FEEDBACK}"
    )
    assert call.recorded == [("response", "no wire")]


@pytest.mark.parametrize(
    ("failure_class", "shown"),
    [(None, "draft_references"), ("draft_semantics", None)],
)
def test_graph_outside_repair_scope(failure_class, shown) -> None:
    call = _call(failure_class)
    cause = ValueError("H-9 is unknown")

    error = _raised(lambda: la._stop_outside_graph_scope(call, cause, ERROR))

    reason = "graph validation is outside the approved repair scope: H-9 is unknown"
    assert str(error) == (
        f"stage_1a/gap_analysis: targeted repair unsupported ({reason}); "
        f"no repair call was made; {shown or failure_class} failure class; "
        f"first attempt failed: {ERROR}. {FEEDBACK}"
    )
    assert call.recorded == [("response", reason)]
    assert error.__cause__ is cause


@pytest.fixture
def cleanup(monkeypatch) -> list[ValueError]:
    """Record the failed cleanup instead of writing it."""
    failed: list[ValueError] = []
    monkeypatch.setattr(
        la, "_record_failed_cleanup", lambda call, outcome, exc: failed.append(exc)
    )
    return failed


def test_cleanup_failing_provider_revalidation(monkeypatch, cleanup) -> None:
    cause = ValueError("bad row")

    def fail(*args, **kwargs):
        raise cause

    monkeypatch.setattr(la, "revalidate_provider_object", fail)

    error = _raised(
        lambda: la._apply_deterministic_cleanup(
            _call(None), SimpleNamespace(draft=None), None, ERROR
        )
    )

    assert str(error) == (
        "stage_1a/gap_analysis: targeted repair unsupported (deterministic "
        "cleanup failed re-validation of the original provider schema: bad "
        f"row); no repair call was made; first attempt failed: {ERROR}"
    )
    assert cleanup == [cause]
    assert error.__cause__ is cause


@pytest.mark.parametrize(
    ("failure_class", "shown"), [(None, "draft"), ("draft_references", None)]
)
def test_cleanup_leaving_a_draft_failure(
    monkeypatch, cleanup, failure_class, shown
) -> None:
    cause = la._DraftReferenceValidationError("H-9 is unknown", feedback="Fix H-9.")

    def fail(call, cleaned):
        raise cause

    monkeypatch.setattr(la, "revalidate_provider_object", lambda *a, **kw: None)
    monkeypatch.setattr(la, "_validate_cleaned_draft", fail)

    error = _raised(
        lambda: la._apply_deterministic_cleanup(
            _call(failure_class), SimpleNamespace(draft=None), None, ERROR
        )
    )

    assert str(error) == (
        "stage_1a/gap_analysis: targeted repair unsupported (deterministic "
        f"cleanup left a {shown or failure_class} failure: H-9 is unknown); "
        f"no repair call was made; first attempt failed: {ERROR}. Fix H-9."
    )
    assert cleanup == [cause]
    assert error.__cause__ is cause


def test_cleanup_producing_a_conflicting_duplicate(monkeypatch, cleanup) -> None:
    cause = ValueError("conflicting duplicate hazard ID 'H-1'")

    def fail(call, cleaned):
        raise cause

    monkeypatch.setattr(la, "revalidate_provider_object", lambda *a, **kw: None)
    monkeypatch.setattr(la, "_validate_cleaned_draft", fail)

    error = _raised(
        lambda: la._apply_deterministic_cleanup(
            _call(None), SimpleNamespace(draft=None), None, ERROR
        )
    )

    assert str(error) == (
        "stage_1a/gap_analysis: targeted repair unsupported (deterministic "
        "cleanup produced a conflicting duplicate: conflicting duplicate "
        "hazard ID 'H-1'); no repair call was made; first attempt failed: "
        f"{ERROR}"
    )
    assert cleanup == [cause]
    assert error.__cause__ is cause
