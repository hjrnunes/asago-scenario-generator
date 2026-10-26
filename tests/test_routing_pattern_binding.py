"""Each routing route is bound to its own obligation's attack pattern.

A batch shows several obligation questions at once.  A route must echo the
``attack_pattern_id`` of its own question, and its free text must not name a
pattern ID that belongs only to another question of the batch.  A route that
breaks either rule fails record validation through the existing path: the
batch is asked again within ``validation_retries`` and the record is then
retained as unresolved beside its valid siblings.
"""

from __future__ import annotations

from typing import Any

import pytest
import yaml
from pydantic import ValidationError

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    ROUTING_RECORD_VALIDATION_FAILED,
    ObligationRoute,
)
from asago_scenario_generator.stpa.obligation_aware.contracts import (
    StructuralRoutingResponse,
)
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_structural_routing_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.provider import (
    _routing_provider_payload_type,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    AttackPatternBindingError,
    _names_pattern_id,
    _validate_pattern_binding,
    build_neutral_briefs,
    route_obligations,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.known_mechanism import linked_brief
from tests.helpers.obligation_aware import (
    _control_structure,
    _controls,
    _loss_analysis,
    route_assessment,
)
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern

_OWN = "AP-T10-01"
_OTHER = "AP-T15-01"


def _brief(pattern_id: str, digit: str):
    """A brief for bundled pattern *pattern_id* with its own obligation ID."""
    pattern = AttackPattern.model_validate(get_test_raw_pattern())
    base = build_neutral_briefs(make_plan(), (pattern,))[0]
    unchecked = linked_brief(base, pattern_id).model_copy(
        update={"obligation_id": "ob:v1:" + digit * 64}
    )
    return unchecked.model_copy(
        update={"semantic_digest": unchecked.compute_semantic_digest()}
    )


def _route(brief, *, rationale: str, echo: str | None = None) -> ObligationRoute:
    """A not-applicable route for *brief* that echoes *echo* (its own by default)."""
    return ObligationRoute(
        obligation_id=brief.obligation_id,
        attack_pattern_id=echo or brief.attack_pattern_id,
        disposition="proposed_not_applicable",
        semantic_assessment=route_assessment(brief, mechanism="absent_from_system"),
        rationale=rationale,
        evidence=("The supplied structure has no such surface.",),
    )


class _Adapter:
    """Answer every routing request with the same fixed routes."""

    def __init__(self, routes: tuple[ObligationRoute, ...]) -> None:
        self.routes = routes
        self.feedback: list[str | None] = []

    def route(self, request, *, correction_feedback=None):
        self.feedback.append(correction_feedback)
        return StructuralRoutingResponse(
            adapter_kind="fake",
            request_digest=request.semantic_digest,
            routes=self.routes,
        )


def _run(adapter: _Adapter, briefs) -> Any:
    structure = _control_structure()
    return route_obligations(
        adapter,
        briefs=briefs,
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
        controls=_controls(),
    )


def _route_for(result, brief) -> ObligationRoute:
    return next(r for r in result.routes if r.obligation_id == brief.obligation_id)


def test_a_route_echoing_another_pattern_is_refused_and_its_sibling_kept() -> None:
    own, other = _brief(_OWN, "a"), _brief(_OTHER, "b")
    adapter = _Adapter(
        (
            _route(own, rationale="No decision interface exists.", echo=_OTHER),
            _route(other, rationale="No content is substituted."),
        )
    )

    result = _run(adapter, (own, other))

    refused = _route_for(result, own)
    assert refused.disposition == "unresolved"
    (diagnostic,) = refused.diagnostics
    assert diagnostic.code == ROUTING_RECORD_VALIDATION_FAILED
    assert diagnostic.detail == (
        f"AttackPatternBindingError: route {own.obligation_id} echoes "
        "attack_pattern_id "
        f"{_OTHER}, but its obligation's own attack pattern is {_OWN}"
    )
    # Its absent-mechanism judgement was about another pattern: not retained.
    assert refused.semantic_assessment is None
    assert _route_for(result, other).disposition == "proposed_not_applicable"
    # The existing bounded retry, and no further request.
    assert len(adapter.feedback) == _controls().validation_retries + 1
    assert "Repair code attack_pattern_crossover" in str(adapter.feedback[-1])


def test_a_rationale_naming_another_batch_pattern_is_refused() -> None:
    own, other = _brief(_OWN, "a"), _brief(_OTHER, "b")
    adapter = _Adapter(
        (
            _route(
                own,
                rationale=f"No content substitution path exists for {_OTHER}.",
            ),
            _route(other, rationale="No content is substituted."),
        )
    )

    result = _run(adapter, (own, other))

    refused = _route_for(result, own)
    assert refused.disposition == "unresolved"
    assert refused.semantic_assessment is None
    assert refused.diagnostics[0].detail == (
        f"AttackPatternBindingError: route {own.obligation_id} for attack "
        f"pattern {_OWN} "
        f"names another batch obligation's attack pattern: {_OTHER} in rationale"
    )
    assert _route_for(result, other).disposition == "proposed_not_applicable"
    assert len(adapter.feedback) == _controls().validation_retries + 1


def test_every_free_text_field_is_checked() -> None:
    own, other = _brief(_OWN, "a"), _brief(_OTHER, "b")
    route = _route(own, rationale="No decision interface exists.").model_copy(
        update={
            "evidence": (f"{_OTHER} needs a content channel.",),
            "semantic_assessment": route_assessment(
                own, mechanism="absent_from_system"
            ).model_copy(update={"risk_alignment_rationale": f"As in {_OTHER}."}),
        }
    )

    with pytest.raises(AttackPatternBindingError) as caught:
        _validate_pattern_binding(route, own, (own, other))

    assert str(caught.value) == (
        f"route {own.obligation_id} for attack pattern {_OWN} names another "
        f"batch obligation's attack pattern: {_OTHER} in evidence; "
        f"{_OTHER} in risk_alignment_rationale"
    )


def test_a_rationale_naming_its_own_pattern_is_accepted() -> None:
    own, other = _brief(_OWN, "a"), _brief(_OTHER, "b")
    adapter = _Adapter(
        (
            _route(own, rationale=f"{_OWN} needs a decision interface; none exists."),
            _route(other, rationale=f"{_OTHER} needs content substitution."),
        )
    )

    result = _run(adapter, (own, other))

    assert [r.disposition for r in result.routes] == ["proposed_not_applicable"] * 2
    assert len(adapter.feedback) == 1
    assert result.diagnostics == ()


def test_a_shared_pattern_is_not_foreign() -> None:
    first, second = _brief(_OWN, "a"), _brief(_OWN, "b")
    route = _route(first, rationale=f"{_OWN} needs a decision interface.")

    _validate_pattern_binding(route, first, (first, second))


@pytest.mark.parametrize(
    "text",
    [
        "AP-T1-01 needs free text.",
        "See AP-T1-01.",
        "Unlike XAP-T1-0, this path is absent.",
        "AP-T1-0-1 is not a pattern of this batch.",
        "ap-t1-0 is lower case.",
    ],
)
def test_a_pattern_id_never_matches_inside_a_longer_token(text: str) -> None:
    assert not _names_pattern_id(text, "AP-T1-0")


@pytest.mark.parametrize(
    "text",
    ["AP-T1-0 needs free text.", "As in AP-T1-0.", "(AP-T1-0)", "'AP-T1-0's path"],
)
def test_a_pattern_id_matches_as_a_whole_token(text: str) -> None:
    assert _names_pattern_id(text, "AP-T1-0")


def test_a_longer_own_pattern_id_is_not_a_prefix_match() -> None:
    own = _brief(_OWN, "a").model_copy(update={"attack_pattern_id": "AP-T1-01"})
    other = _brief(_OTHER, "b").model_copy(update={"attack_pattern_id": "AP-T1-0"})
    route = _route(own, rationale="AP-T1-01 needs free text; none is accepted.")

    _validate_pattern_binding(route, own, (own, other))


def test_pattern_names_are_not_matched() -> None:
    own, other = _brief(_OWN, "a"), _brief(_OTHER, "b")
    route = _route(own, rationale=f"Not {other.attack_pattern_name}.")

    _validate_pattern_binding(route, own, (own, other))


def test_a_single_item_batch_is_unaffected() -> None:
    own = _brief(_OWN, "a")
    adapter = _Adapter(
        (_route(own, rationale=f"Unlike {_OTHER}, {_OWN} needs a decision UI."),)
    )

    result = _run(adapter, (own,))

    assert result.routes[0].disposition == "proposed_not_applicable"
    assert result.routes[0].attack_pattern_id == _OWN
    assert len(adapter.feedback) == 1


def test_a_route_without_an_echo_keeps_its_identity() -> None:
    own = _brief(_OWN, "a")
    route = _route(own, rationale="No decision interface exists.")
    plain = route.model_copy(update={"attack_pattern_id": None})
    unechoed = ObligationRoute.model_validate(
        plain.model_dump(mode="python", exclude={"route_id"})
    )

    assert "attack_pattern_id" not in unechoed.model_dump(mode="json")
    assert unechoed.route_id != route.route_id
    _validate_pattern_binding(unechoed, own, (own, _brief(_OTHER, "b")))


def _question_rows(user: str) -> list[dict[str, Any]]:
    block = user.split("Compact obligation questions:\n", 1)[1]
    block = block.split("Every obligation_handle is an opaque reference", 1)[0]
    return yaml.safe_load(block)


def test_each_question_states_its_own_pattern_id_and_name() -> None:
    first, second = _brief(_OWN, "a"), _brief(_OTHER, "b")
    structure = _control_structure()

    system, user = build_structural_routing_prompts(
        briefs=(second, first),
        loss_analysis=_loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    )

    by_handle = {item.obligation_id: item for item in (first, second)}
    rows = _question_rows(user)
    assert len(rows) == 2
    for row in rows:
        brief = by_handle[row["obligation_handle"]]
        assert row["attack_pattern_id"] == brief.attack_pattern_id
        assert row["attack_pattern_name"] == brief.attack_pattern_name
        assert "known_concern_ref" not in row
    assert "`attack_pattern_id` binds the route to its own question" in system


def test_the_provider_schema_requires_an_echo_from_the_batch() -> None:
    obligation_id = "ob:v1:" + "a" * 64
    wire = _routing_provider_payload_type(
        1, obligation_ids=(obligation_id,), attack_pattern_ids=(_OTHER, _OWN)
    )
    route = {
        "obligation_id": obligation_id,
        "disposition": "unresolved",
        "semantic_assessment": {
            "mechanism_assessment": "insufficient_evidence",
            "risk_alignment": "insufficient_evidence",
            "mechanism_rationale": "Not supplied.",
            "risk_alignment_rationale": "Not supplied.",
        },
        "rationale": "Not supplied.",
        "evidence": ["Supplied structure"],
    }

    with pytest.raises(ValidationError, match="attack_pattern_id"):
        wire.model_validate({"routes": [route]})
    with pytest.raises(ValidationError, match="attack_pattern_id"):
        wire.model_validate({"routes": [{**route, "attack_pattern_id": "AP-T1-01"}]})
    parsed = wire.model_validate({"routes": [{**route, "attack_pattern_id": _OWN}]})
    assert parsed.routes[0].attack_pattern_id == _OWN
    schema = wire.model_json_schema()
    assert "copied unchanged: the pattern this route judges" in str(schema)
