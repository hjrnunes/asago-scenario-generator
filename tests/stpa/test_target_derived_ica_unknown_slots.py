"""A target-derived ICA finding that names an unknown slot does not end the unit.

The finder maps a ``slot_id`` written as an exact request slot plus a
``:<digits>`` ICA suffix back to that slot, with a warning, and drops a
finding naming any other unknown slot with a diagnostic.  Compilation keeps a
backstop: a finding whose slot the realization does not hold becomes a
per-finding diagnostic, and the other findings continue.  The fixture is the
trimmed L1 klarna-r2 draft (requests 308 and 309 of the b8-glm batch), in
which every finding's ``slot_id`` carries the ``:1`` suffix.
"""

from __future__ import annotations

import json
from pathlib import Path

from asago_scenario_generator.models.target_realization import (
    TargetDerivedICAFinding,
    TargetDerivedICAProviderResponse,
    TargetDerivedICARequest,
)
from asago_scenario_generator.pipeline.target_realization import (
    realize_target_derived_icas,
)
from tests.helpers.target_realization import _baseline, _target_extended_result

_FIXTURE = json.loads(
    (
        Path(__file__).resolve().parents[1]
        / "fixtures"
        / "unit_loss"
        / "l1-klarna-r2-target-derived-icas.json"
    ).read_text(encoding="utf-8")
)


class _ResponseFinder:
    """A finder that returns one fixed provider response."""

    def __init__(self, response: TargetDerivedICAProviderResponse) -> None:
        self._response = response

    def __call__(self, request: TargetDerivedICARequest):
        del request
        return self._response


def _verified(slot_id: str, ica_id: str) -> TargetDerivedICAFinding:
    recorded = _FIXTURE["draft"]["findings"][0]
    return TargetDerivedICAFinding(
        slot_id=slot_id,
        ica_id=ica_id,
        ica_text=recorded["ica_text"],
        hazardous_context=recorded["hazardous_context"],
        loss_scenario=recorded["loss_scenario"],
        related_hazards=("H-1",),
        verification={"status": "verified", "detail": "verified"},
    )


class TestCompilationBackstop:
    """Compilation drops an unknown-slot finding instead of raising."""

    def test_unknown_slot_becomes_a_diagnostic_and_the_rest_continue(self) -> None:
        known = "RESP-1:CA-1-2:INCORRECT"
        unknown = f"{known}:1"
        response = TargetDerivedICAProviderResponse(
            findings=(
                _verified(unknown, f"{unknown}:1"),
                _verified(known, f"{known}:1"),
            )
        )

        enhanced = realize_target_derived_icas(
            _baseline(), _target_extended_result(), _ResponseFinder(response)
        )

        assert [f.ica_id for f in enhanced.target_derived_ica_findings] == [
            f"{known}:1"
        ]
        assert (
            f"target-derived ICA finding {unknown}:1 is unresolved: "
            f"unknown slot {unknown}"
        ) in enhanced.diagnostics
