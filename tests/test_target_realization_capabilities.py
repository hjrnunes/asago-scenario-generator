"""Declared-versus-observed capability rows from target realization."""

from __future__ import annotations

from asago_scenario_generator.models.target_realization import (
    CapabilityExposureDisposition as Disposition,
    SystemicStpaBaseline,
)
from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)
from asago_scenario_generator.stpa.models.control_structure import (
    ControlAction,
    ControlActionEffectKind,
    ControlStructure,
    Responsibility,
)
from asago_scenario_generator.stpa.models.ica_enumeration import ICAEnumeration
from asago_scenario_generator.stpa.models.loss_analysis import (
    Hazard,
    Loss,
    LossAnalysis,
    LossProvenance,
    SecurityConstraint,
)
from tests.helpers.target_realization import _Interpreter, _profile, _realize

# Interpreter evidence, the compiler-owned verified-pair reference, and the
# verifier evidence, deduplicated and sorted.
_SCHEDULE_EVIDENCE = (
    "inventory:mcp:payments/schedule_payment",
    "target-realization:verified-pair:CA-1-1:"
    "mcp:target:mini:schedule_payment/schedule_payment",
    "verification:test",
)


def _declaring_baseline(*declared: str) -> SystemicStpaBaseline:
    """Build the shared one-action payment baseline with declared capabilities."""
    loss_analysis = LossAnalysis(
        risk_card_losses=[],
        use_case_losses=[
            Loss(
                loss_id="L-1",
                description="payment loss",
                provenance=LossProvenance.use_case,
            )
        ],
        hazards=[
            Hazard(hazard_id="H-1", description="bad payment", related_losses=["L-1"])
        ],
        security_constraints=[
            SecurityConstraint(
                constraint_id="SC-1",
                rule="payments are authorized",
                related_hazards=["H-1"],
            )
        ],
    )
    control_structure = ControlStructure(
        responsibilities=[
            Responsibility(
                resp_id="RESP-1",
                description="payment controller",
                security_constraint_refs=["SC-1"],
                control_actions=[
                    ControlAction(
                        ca_id="CA-1-1",
                        description="Controller schedules a payment",
                        effect_kind=ControlActionEffectKind.state_change,
                    )
                ],
            )
        ],
    )
    return SystemicStpaBaseline.from_stpa(
        loss_analysis=loss_analysis,
        control_structure=control_structure,
        ica_enumeration=ICAEnumeration(slots=[]),
        baseline_id="baseline:capabilities",
        declared_capabilities=declared,
    )


def _partial_profile() -> ExecutionTargetProfile:
    payload = _profile().model_dump(mode="json", exclude={"semantic_digest"})
    payload["inventory_completeness"] = "observed_partial"
    return ExecutionTargetProfile.model_validate(payload)


class _UnverifiedInterpreter(_Interpreter):
    def __call__(self, *, action, operations):
        response = super().__call__(action=action, operations=operations)
        response["verifier"] = {
            "status": "rejected",
            "detail": "The pair could not be checked.",
            "evidence_refs": ("verification:test",),
        }
        return response


def _rows(baseline, profile, interpreter) -> dict[str, tuple]:
    result = _realize(baseline, profile, lambda: interpreter)
    return {
        row.capability: (row.declared, row.observed, row.disposition, row.evidence_refs)
        for row in result.capability_reconciliation
    }


def test_complete_inventory_classifies_each_capability_with_verified_evidence():
    rows = _rows(
        _declaring_baseline("schedule_payment", "refund_payment"),
        _profile(),
        _Interpreter(),
    )

    assert rows == {
        "get_payment": (False, True, Disposition.not_comparable, ()),
        "refund_payment": (True, False, Disposition.declared_not_observed, ()),
        "schedule_payment": (
            True,
            True,
            Disposition.confirmed_exposure,
            _SCHEDULE_EVIDENCE,
        ),
    }


def test_partial_inventory_keeps_an_unobserved_declaration_not_comparable():
    rows = _rows(
        _declaring_baseline("schedule_payment", "refund_payment"),
        _partial_profile(),
        _Interpreter(),
    )

    assert rows["refund_payment"] == (True, False, Disposition.not_comparable, ())
    assert rows["schedule_payment"][2] is Disposition.confirmed_exposure


def test_unverified_selection_neither_confirms_nor_contributes_evidence():
    rows = _rows(
        _declaring_baseline("schedule_payment"),
        _profile(),
        _UnverifiedInterpreter(),
    )

    assert rows["schedule_payment"] == (True, True, Disposition.not_comparable, ())


def test_no_declared_capabilities_produces_no_rows():
    assert _rows(_declaring_baseline(), _profile(), _Interpreter()) == {}
