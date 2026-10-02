"""Obligation routes are canonical, content-identified, and disposition-complete."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    ObligationRoute,
    ObligationSemanticAssessment,
)

_OBLIGATION = "ob:v1:" + "1" * 64


def _concept(description: str = "No feedback reports the gate state.") -> dict:
    return MissingStructuralConcept(
        concept_type="feedback_channel",
        description=description,
        evidence_refs=("brief:gate",),
        obligation_id=_OBLIGATION,
    ).model_dump(mode="json")


_COMPLETE = {
    "targeted": {
        "slot_ids": ("RESP-1:CA-1:TYPE-NOT_PROVIDED",),
        "hazard_ids": ("H-1",),
        "constraint_ids": ("SC-1",),
    },
    "proposed_not_applicable": {"rationale": "The system has no release gate."},
    "upstream_gap": {
        "rationale": "The gate feedback is not modelled.",
        "missing_concepts": (_concept(),),
    },
    "unresolved": {"rationale": "The evidence does not decide the placement."},
}


def _route(disposition: str, **fields) -> ObligationRoute:
    values = {
        "obligation_id": _OBLIGATION,
        "disposition": disposition,
        "evidence": ("brief evidence",),
        **_COMPLETE[disposition],
        **fields,
    }
    return ObligationRoute.model_validate(
        {name: value for name, value in values.items() if value is not None}
    )


@pytest.mark.parametrize("disposition", sorted(_COMPLETE))
def test_complete_route_is_accepted_and_identified(disposition: str) -> None:
    route = _route(disposition)

    assert route.route_id is not None
    assert route.route_id.startswith("route:v1:")
    assert ObligationRoute.model_validate(route.model_dump(mode="json")) == route


def test_set_like_fields_are_sorted_and_concepts_ordered_by_gap_id() -> None:
    concepts = (_concept("Second concept."), _concept("First concept."))
    route = _route(
        "upstream_gap",
        controller_ids=("CTRL-2", "CTRL-1"),
        evidence=("z evidence", "a evidence"),
        missing_concepts=concepts,
    )

    assert route.controller_ids == ("CTRL-1", "CTRL-2")
    assert route.evidence == ("a evidence", "z evidence")
    assert [item.gap_id for item in route.missing_concepts] == sorted(
        item["gap_id"] for item in concepts
    )


def test_route_id_ignores_field_order() -> None:
    first = _route("targeted", hazard_ids=("H-2", "H-1"))
    second = _route("targeted", hazard_ids=("H-1", "H-2"))

    assert first.route_id == second.route_id


def test_semantic_assessment_changes_the_route_id() -> None:
    assessment = ObligationSemanticAssessment(
        mechanism_assessment="plausible_in_system",
        risk_alignment="supported",
        mapping_strength="direct_curated_pair",
        mechanism_rationale="The gate mechanism exists.",
        risk_alignment_rationale="The risk names the gate.",
    )

    plain = _route("targeted")
    assessed = _route("targeted", semantic_assessment=assessment.model_dump())

    assert assessed.route_id != plain.route_id


def test_stale_route_id_is_rejected() -> None:
    with pytest.raises(ValidationError, match="route_id does not match route content"):
        _route("targeted", route_id="route:v1:" + "0" * 64)


def test_duplicate_missing_concepts_are_rejected() -> None:
    with pytest.raises(
        ValidationError, match="missing structural concepts must be unique"
    ):
        _route("upstream_gap", missing_concepts=(_concept(), _concept()))


def test_route_without_evidence_is_rejected() -> None:
    with pytest.raises(ValidationError, match="obligation routes require evidence"):
        _route("unresolved", evidence=())


@pytest.mark.parametrize(
    ("disposition", "fields", "message"),
    [
        pytest.param(
            "targeted",
            {"slot_ids": ()},
            "targeted routes require at least one slot",
            id="targeted-without-slot",
        ),
        pytest.param(
            "targeted",
            {"hazard_ids": ()},
            "targeted routes require hazard and constraint references",
            id="targeted-without-hazard",
        ),
        pytest.param(
            "targeted",
            {"constraint_ids": ()},
            "targeted routes require hazard and constraint references",
            id="targeted-without-constraint",
        ),
        pytest.param(
            "targeted",
            {"missing_concepts": (_concept(),)},
            "targeted routes cannot retain missing structural concepts",
            id="targeted-with-gap",
        ),
        pytest.param(
            "proposed_not_applicable",
            {"rationale": None},
            "proposed non-applicable routes require a rationale",
            id="not-applicable-without-rationale",
        ),
        pytest.param(
            "proposed_not_applicable",
            {"missing_concepts": (_concept(),)},
            "non-applicable routes cannot retain upstream gaps",
            id="not-applicable-with-gap",
        ),
        pytest.param(
            "upstream_gap",
            {"missing_concepts": ()},
            "upstream-gap routes require missing structural concepts",
            id="gap-without-concept",
        ),
        pytest.param(
            "upstream_gap",
            {"rationale": None},
            "upstream-gap routes require a rationale",
            id="gap-without-rationale",
        ),
        pytest.param(
            "unresolved",
            {"rationale": None},
            "unresolved routes require a rationale",
            id="unresolved-without-rationale",
        ),
    ],
)
def test_incomplete_disposition_is_rejected(
    disposition: str, fields: dict, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        _route(disposition, **fields)
