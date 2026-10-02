"""The request-local causal factor draft checks its evidence claims."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.stpa.models.causal_factor import CausalEvidenceStatus
from asago_scenario_generator.stpa.scenario_prod.bdi_generation import (
    _ContextCausalFactorDraft,
)

_EVIDENCE = "The controller trusts a stale release-gate reading."
_ASSUMPTION = "The gate reading can lag behind the gate state."


def _draft(**fields) -> _ContextCausalFactorDraft:
    return _ContextCausalFactorDraft(
        source_handle="cause_1", evidence=fields.pop("evidence", _EVIDENCE), **fields
    )


@pytest.mark.parametrize(
    "fields",
    [
        pytest.param({}, id="structural-failure"),
        pytest.param(
            {
                "evidence_status": CausalEvidenceStatus.reachable_capability,
                "capability_refs": ("CAP-1",),
                "access_refs": ("ACC-1",),
            },
            id="reachable-capability",
        ),
        pytest.param(
            {
                "evidence_status": CausalEvidenceStatus.bounded_assumption,
                "bounded_assumption": _ASSUMPTION,
            },
            id="bounded-assumption",
        ),
        pytest.param(
            {"bounded_assumption": _ASSUMPTION},
            id="assumption-with-default-status",
        ),
    ],
)
def test_consistent_evidence_is_accepted(fields: dict) -> None:
    draft = _draft(**fields)

    assert draft.model_dump(include=set(fields)) == fields


def test_evidence_that_repeats_a_status_label_is_rejected() -> None:
    with pytest.raises(ValidationError, match="must explain the causal condition"):
        _draft(evidence=CausalEvidenceStatus.bounded_assumption.value)


@pytest.mark.parametrize(
    ("fields", "message"),
    [
        pytest.param(
            {"evidence_status": CausalEvidenceStatus.reachable_capability},
            "reachable_capability causal factor requires capability_refs",
            id="capability-without-refs",
        ),
        pytest.param(
            {"evidence_status": CausalEvidenceStatus.bounded_assumption},
            "bounded_assumption evidence requires bounded_assumption text",
            id="assumption-status-without-text",
        ),
        pytest.param(
            {"capability_refs": ("CAP-1",), "access_refs": ("ACC-1",)},
            "capability_refs and access_refs require reachable_capability",
            id="refs-with-structural-status",
        ),
        pytest.param(
            {"bounded_assumption": _ASSUMPTION, "capability_refs": ("CAP-1",)},
            "capability_refs and access_refs require reachable_capability",
            id="assumption-and-refs-with-default-status",
        ),
    ],
)
def test_contradictory_evidence_is_rejected(fields: dict, message: str) -> None:
    with pytest.raises(ValidationError, match=message):
        _draft(**fields)
