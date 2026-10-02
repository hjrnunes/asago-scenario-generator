"""Owner ruling Q30 (2026-09-10): obligation entries and direction derivation.

Offline coverage for the option-iii contract frozen as v3
(``build/qualification/replay-round64/c2_option3_v3_freeze.yaml``):

- ``Obligation`` parsing and kind-exclusive channel validators;
- constraint-level direction derivation, reviewer stamps, and the proposed
  restamp deterministic code applies to derived graphs.
"""

from __future__ import annotations

from datetime import date

import pytest

from pydantic import ValidationError

from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    Obligation,
    SecurityConstraint,
    stamp_proposed_direction,
)


# The default test candidate's rule; spans below quote it verbatim.
RULE = (
    "The assistant must process a refund only for an eligible order "
    "owned by the authenticated customer."
)


def _forbidden(**overrides) -> Obligation:
    fields = {
        "obligation_id": "O1",
        "kind": "forbidden",
        "behavior": "process a refund for an ineligible order",
        "rule_span": "process a refund only for an eligible order",
        "violated_via": "tool_call",
    }
    fields.update(overrides)
    return Obligation(**fields)


def _required(**overrides) -> Obligation:
    fields = {
        "obligation_id": "O1",
        "kind": "required",
        "behavior": "process an eligible refund",
        "rule_span": "process a refund only for an eligible order",
        "realized_by": "tool_call",
    }
    fields.update(overrides)
    return Obligation(**fields)


def _constraint(**overrides) -> SecurityConstraint:
    fields = {
        "constraint_id": "SC-1",
        "rule": RULE,
        "related_hazards": ["H-1"],
    }
    fields.update(overrides)
    return SecurityConstraint(**fields)


# Obligation model: parsing and kind-exclusive channel validators


def test_required_entry_defaults_realized_by_unknown():
    assert _required(realized_by=None).realized_by == "unknown"


def test_forbidden_entry_defaults_violated_via_unknown():
    assert _forbidden(violated_via=None).violated_via == "unknown"


def test_required_entry_rejects_violated_via():
    with pytest.raises(ValidationError, match="violated_via"):
        _required(violated_via="tool_call")


def test_required_entry_rejects_the_observation_role_fields():
    with pytest.raises(ValidationError, match="observation_role/source_outcome"):
        _required(observation_role="source")


def test_forbidden_entry_rejects_realized_by_and_completion():
    with pytest.raises(ValidationError, match="realized_by"):
        _forbidden(realized_by="tool_call")
    with pytest.raises(ValidationError, match="completion"):
        _forbidden(completion="the refund exists")


def test_proxy_entry_requires_a_named_source_outcome():
    with pytest.raises(ValidationError, match="source_outcome"):
        _forbidden(observation_role="proxy")
    entry = _forbidden(observation_role="proxy", source_outcome="ledger debit")
    assert entry.observation_role == "proxy"


def test_source_outcome_requires_the_proxy_role():
    with pytest.raises(ValidationError, match="observation_role: proxy"):
        _forbidden(source_outcome="ledger debit")


def test_obligation_id_must_be_a_positive_ordinal():
    for bad in ("O0", "O01", "o1", "X1"):
        with pytest.raises(ValidationError):
            _forbidden(obligation_id=bad)
    assert _forbidden(obligation_id="O12").obligation_id == "O12"


def test_rule_span_must_quote_the_rule_case_insensitively():
    entry = _forbidden(rule_span="PROCESS A REFUND ONLY FOR AN ELIGIBLE ORDER")
    assert _constraint(obligations=[entry]).obligations
    with pytest.raises(ValidationError, match="rule_span"):
        _constraint(obligations=[_forbidden(rule_span="not in the rule")])


def test_duplicate_obligation_ids_reject():
    with pytest.raises(ValidationError, match="duplicate obligation ids"):
        _constraint(obligations=[_forbidden(), _required()])


def test_reviewed_authority_requires_reviewer_stamps():
    with pytest.raises(ValidationError, match="reviewed_by"):
        _constraint(obligations=[_forbidden()], direction_authority="reviewed")


def test_reviewer_stamps_require_reviewed_authority():
    with pytest.raises(ValidationError, match="reviewer stamps"):
        _constraint(
            obligations=[_forbidden()],
            reviewed_by="owner",
            reviewed_on=date(2026, 9, 10),
        )


def test_failure_direction_is_computed_from_the_entries():
    assert _constraint().failure_direction == "unresolved"
    assert _constraint(obligations=[_forbidden()]).failure_direction == "forbidden"
    assert _constraint(obligations=[_required()]).failure_direction == "required"
    assert (
        _constraint(
            obligations=[_forbidden(), _required(obligation_id="O2")]
        ).failure_direction
        == "mixed"
    )
    constraint = _constraint(obligations=[_forbidden()])
    assert constraint.effective_direction_authority == "proposed"
    assert constraint.obligation_by_id("O1") is constraint.obligations[0]
    assert constraint.obligation_by_id("O9") is None


def test_stamp_proposed_direction_restamps_and_clears_review_marks():
    """A derived or revision-merged graph can never keep a wire-carried
    reviewed stamp; deterministic code restamps it proposed."""
    analysis = LossAnalysis(
        risk_card_losses=[
            Loss(
                loss_id="L-1",
                description="Unauthorized refund execution",
                provenance=LossProvenance.risk_card,
                source_risk_cards=["atlas-001"],
            )
        ],
        use_case_losses=[],
        hazards=[Hazard(hazard_id="H-1", description="h", related_losses=["L-1"])],
        security_constraints=[
            SecurityConstraint.model_construct(
                constraint_id="SC-1",
                rule=RULE,
                related_hazards=["H-1"],
                applies_when=[],
                description=RULE,
                obligations=[_forbidden()],
                direction_authority="reviewed",
                reviewed_by="owner",
                reviewed_on=date(2026, 9, 10),
            ),
            _constraint(constraint_id="SC-2"),
        ],
    )
    stamp_proposed_direction(analysis)
    first, second = analysis.security_constraints
    assert first.direction_authority == "proposed"
    assert first.reviewed_by is None
    assert first.reviewed_on is None
    # An entryless constraint stays unstamped.
    assert second.direction_authority is None


# Effect-layer channels (state/result): representable so the exclusion is explicit


def test_realized_by_rejects_effect_layer_channels():
    with pytest.raises(ValidationError):
        _required(realized_by="state")
    with pytest.raises(ValidationError):
        _required(realized_by="provider_request")
