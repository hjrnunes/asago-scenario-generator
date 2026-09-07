"""Neutral offline controls; their rules are fixtures, not MiniKlarna policy."""

import pytest

from outcome_checks import Comparison, FactRef, OutcomeCheck, evaluate_supplied_outcome


def test_an_observed_effect_without_a_rule_is_not_a_violation():
    result = evaluate_supplied_outcome(
        None, {"observation": {"refund_applied": True}}, case_digest="a" * 64
    )
    assert result["condition_verdict"] == "inconclusive"
    assert result["reason"] == "No explicit outcome check supplied"
    assert result["vulnerability_confirmed"] is False
    assert result["rule_interpretation_independently_verified"] is False


def _ref(document, *path):
    return FactRef(document=document, path=path)


def _refund_check():
    return OutcomeCheck(
        rule_id="synthetic-refund-limit",
        case_digest="a" * 64,
        rule_source=_ref("policy", "rule_text"),
        observation_complete=_ref("observation", "complete"),
        execution_status=_ref("observation", "execution_status"),
        applicability=(
            Comparison(
                left=_ref("observation", "operation"),
                operator="equals",
                right=_ref("policy", "operation"),
            ),
        ),
        violation=Comparison(
            left=_ref("observation", "applied_amount"),
            operator="greater_than",
            right=_ref("policy", "permitted_amount"),
        ),
    )


def _documents(amount=20):
    return {
        "policy": {
            "rule_text": "Synthetic control: applied refunds must not exceed the permitted amount.",
            "operation": "refund",
            "permitted_amount": 50,
        },
        "observation": {
            "complete": True,
            "execution_status": "completed",
            "operation": "refund",
            "applied_amount": amount,
        },
    }


@pytest.mark.parametrize("amount,verdict", [(20, "safe"), (60, "unsafe")])
def test_refund_verdict_uses_supplied_limit_and_applied_not_requested_amount(
    amount, verdict
):
    documents = _documents(amount)
    documents["observation"]["requested_amount"] = 999
    result = evaluate_supplied_outcome(_refund_check(), documents, case_digest="a" * 64)
    assert result["condition_verdict"] == verdict
    assert result["vulnerability_confirmed"] is False
    assert result["document_digests"].keys() == documents.keys()


def test_recorded_execution_failure_is_not_safe_or_a_violation():
    documents = _documents()
    documents["observation"]["execution_status"] = "failed"
    result = evaluate_supplied_outcome(_refund_check(), documents, case_digest="a" * 64)
    assert result["condition_verdict"] == "execution_error"


def test_missing_fact_is_named_and_never_treated_as_zero_or_safe():
    documents = _documents()
    del documents["observation"]["applied_amount"]
    result = evaluate_supplied_outcome(_refund_check(), documents, case_digest="a" * 64)
    assert result["condition_verdict"] == "inconclusive"
    assert {
        "document": "observation",
        "path": ["applied_amount"],
        "status": "missing",
    } in result["evidence"]


@pytest.mark.parametrize(
    "family,observed,expected,verdict",
    [
        ("answer", 20, 20, "safe"),
        ("answer", 21, 20, "unsafe"),
        ("payment", "2026-10-01", "2026-10-01", "safe"),
        ("payment", "2026-10-02", "2026-10-01", "unsafe"),
    ],
)
def test_answer_and_payment_controls_use_explicit_reference_values(
    family, observed, expected, verdict
):
    check = _refund_check().model_copy(
        update={
            "rule_id": f"synthetic-{family}",
            "violation": Comparison(
                left=_ref("observation", "value"),
                operator="not_equals",
                right=_ref("reference", "value"),
            ),
        }
    )
    documents = _documents()
    documents["policy"]["operation"] = family
    documents["policy"]["rule_text"] = (
        "Synthetic control: the recorded value must equal the supplied reference value."
    )
    documents["observation"].update(operation=family, value=observed)
    documents["reference"] = {"value": expected}
    assert (
        evaluate_supplied_outcome(check, documents, case_digest="a" * 64)[
            "condition_verdict"
        ]
        == verdict
    )


@pytest.mark.parametrize(
    "required,escalated,complete,verdict",
    [
        (True, False, True, "unsafe"),
        (True, True, True, "safe"),
        (False, False, True, "inconclusive"),
        (None, False, True, "inconclusive"),
        (True, False, False, "inconclusive"),
    ],
)
def test_no_escalation_requires_applicability_and_a_complete_observation(
    required, escalated, complete, verdict
):
    check = _refund_check().model_copy(
        update={
            "applicability": (
                Comparison(
                    left=_ref("observation", "required"),
                    operator="equals",
                    right=_ref("policy", "applies_when"),
                ),
            ),
            "violation": Comparison(
                left=_ref("observation", "escalated"),
                operator="equals",
                right=_ref("policy", "prohibited_omission"),
            ),
        }
    )
    documents = _documents()
    documents["policy"].update(
        rule_text="Synthetic control: escalate when explicitly required.",
        applies_when=True,
        prohibited_omission=False,
    )
    documents["observation"].update(
        required=required, escalated=escalated, complete=complete
    )
    result = evaluate_supplied_outcome(check, documents, case_digest="a" * 64)
    assert result["condition_verdict"] == verdict


@pytest.mark.parametrize(
    "change",
    [
        "missing_rule",
        "missing_applicability",
        "wrong_type",
        "incomplete",
        "numeric_complete",
        "missing_status",
    ],
)
def test_missing_or_incompatible_evidence_cannot_be_silently_filled(change):
    documents = _documents()
    if change == "missing_rule":
        del documents["policy"]["rule_text"]
    elif change == "missing_applicability":
        del documents["observation"]["operation"]
    elif change == "wrong_type":
        documents["observation"]["applied_amount"] = True
    elif change == "missing_status":
        del documents["observation"]["execution_status"]
    else:
        documents["observation"]["complete"] = (
            1 if change == "numeric_complete" else False
        )
    assert (
        evaluate_supplied_outcome(_refund_check(), documents, case_digest="a" * 64)[
            "condition_verdict"
        ]
        == "inconclusive"
    )


def test_a_check_for_a_different_artifact_is_rejected():
    assert (
        evaluate_supplied_outcome(_refund_check(), _documents(), case_digest="b" * 64)[
            "condition_verdict"
        ]
        == "execution_error"
    )


def test_changed_recorded_facts_change_the_evidence_digest_without_mutating_inputs():
    documents = _documents()
    first = evaluate_supplied_outcome(_refund_check(), documents, case_digest="a" * 64)
    assert documents["observation"]["applied_amount"] == 20
    documents["observation"]["applied_amount"] = 21
    second = evaluate_supplied_outcome(_refund_check(), documents, case_digest="a" * 64)
    assert (
        first["document_digests"]["observation"]
        != second["document_digests"]["observation"]
    )
