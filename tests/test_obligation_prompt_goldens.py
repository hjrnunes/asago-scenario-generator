"""Byte-level goldens for the obligation-aware prompts that carry instruction prose.

Each case renders the complete system and user messages of one prompt builder
from fixed inputs and compares them byte for byte with the files under
``tests/golden/obligation_prompts/``. The cases cover each branch that changes
instruction text: the four mapping-strength readings, the empty hazard-constraint
ledger, a concern that links known mechanisms, both revision context paths, the
governance and pattern ICA questions, every routing retry repair, and the
mechanism verifier with and without known mechanisms.

To rewrite the goldens after an intended prompt change, call ``write_goldens()``
from a Python shell at the repository root.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import pytest

from asago_scenario_generator.models.attack_pattern_chain import AttackPattern
from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    ObligationRoute,
)
from asago_scenario_generator.data.loaders import load_attack_patterns
from asago_scenario_generator.stpa.obligation_aware.prompts import (
    build_mechanism_verification_prompts,
    build_structural_revision_prompts,
    build_structural_routing_prompts,
    build_synthesis_slot_prompts,
)
from asago_scenario_generator.stpa.obligation_aware.routing import (
    _routing_validation_feedback,
    build_neutral_briefs,
)
from asago_scenario_generator.stpa.threat_enum.slot_creation import create_slots
from tests.helpers.governance import _pattern_route, _setup
from tests.helpers.known_mechanism import linked_brief
from tests.helpers.obligation_aware import _control_structure, _loss_analysis
from tests.helpers.obligation_factory import make_plan
from tests.helpers.projection_factory import get_test_raw_pattern

GOLDEN_DIR = Path(__file__).parent / "golden" / "obligation_prompts"

Messages = dict[str, str]


def _pattern() -> AttackPattern:
    return AttackPattern.model_validate(get_test_raw_pattern())


def _brief(*, first_relation: str | None = None):
    pattern = _pattern()
    if first_relation is None:
        return build_neutral_briefs(make_plan(), (pattern,))[0]
    plan = make_plan(
        mappings=[
            {
                "source_id": "risk-a",
                "target_id": "CATEGORY-1",
                "relation": first_relation,
            },
            {
                "source_id": "CATEGORY-1",
                "target_id": pattern.id,
                "relation": "attacks_via",
            },
        ]
    )
    return build_neutral_briefs(plan, (pattern,))[0]


def _linked_brief(pattern_id: str):
    return linked_brief(_brief(), pattern_id)


def _routing(brief, *, loss_analysis=None) -> Messages:
    structure = _control_structure()
    system, user = build_structural_routing_prompts(
        briefs=(brief,),
        loss_analysis=loss_analysis or _loss_analysis(),
        control_structure=structure,
        slots=create_slots(structure),
    )
    return {"system": system, "user": user}


_PATH = [
    {"id": "RESP-1", "description": "Answer customer requests."},
    {"id": "CA-1-1", "description": "Compose the reply to the customer."},
    {"id": "H-1", "description": "A reply discloses another customer's records."},
]


def _verifier_item(handle: str, pattern_id: str, refs: tuple[str, ...]) -> dict:
    record = load_attack_patterns()[pattern_id]
    item = {
        "item_handle": handle,
        "distinctive_mechanism": {
            "name": record["name"],
            "description": record["description"],
        },
        "selected_structural_path": [dict(row) for row in _PATH],
    }
    return {**item, "known_mechanism_refs": list(refs)} if refs else item


def _verification(*items: dict) -> Messages:
    system, user = build_mechanism_verification_prompts(items)
    return {"system": system, "user": user}


def _governance_route(brief, slot) -> ObligationRoute:
    return ObligationRoute(
        obligation_id=brief.obligation_id,
        disposition="targeted",
        slot_ids=(slot.slot_id,),
        hazard_ids=("H-1",),
        constraint_ids=("SC-1",),
        rationale="the action changes the risky state",
        evidence=("CA-1-1: the action changes the risky state",),
    )


def _slots(briefs, routes, *, structure, loss_analysis) -> Messages:
    slots = create_slots(structure)
    system, user = build_synthesis_slot_prompts(
        target_id="RESP-1",
        slots=[item for item in slots if item.responsibility == "RESP-1"],
        routed_briefs=briefs,
        routed_routes=routes,
        loss_analysis=loss_analysis,
        control_structure=structure,
    )
    return {"system": system, "user": user}


def _pattern_slots(*, routed: bool) -> Messages:
    structure = _control_structure()
    brief = _brief()
    route = _pattern_route(brief, create_slots(structure)[0])
    return _slots(
        (brief,) if routed else (),
        (route,) if routed else (),
        structure=structure,
        loss_analysis=_loss_analysis(),
    )


def _governance_slots(*, with_pattern: bool) -> Messages:
    briefs, _selection, loss_analysis, structure = _setup("risk-b")
    slot = create_slots(structure)[0]
    routed_briefs = (briefs[0],)
    routes = (_governance_route(briefs[0], slot),)
    if with_pattern:
        other = _brief()
        routed_briefs += (other,)
        routes += (_pattern_route(other, slot),)
    return _slots(
        routed_briefs, routes, structure=structure, loss_analysis=loss_analysis
    )


def _revision(*gaps: MissingStructuralConcept) -> Messages:
    system, user = build_structural_revision_prompts(
        gaps=gaps,
        loss_analysis=_loss_analysis(),
        control_structure=_control_structure(),
    )
    return {"system": system, "user": user}


def _gap(concept_type: str, description: str, ref: str) -> MissingStructuralConcept:
    return MissingStructuralConcept(
        concept_type=concept_type, description=description, evidence_refs=(ref,)
    )


def _feedback(error: BaseException) -> Messages:
    return {"text": _routing_validation_feedback(error)}


def _empty_ledger_analysis():
    return _loss_analysis().model_copy(update={"security_constraints": ()})


CASES: dict[str, Callable[[], Messages]] = {
    "routing-direct-curated-pair": lambda: _routing(_brief()),
    "routing-exact-then-category": lambda: _routing(
        _brief(first_relation="skos:exactMatch")
    ),
    "routing-broad-category": lambda: _routing(
        _brief(first_relation="skos:broadMatch")
    ),
    "routing-related-category": lambda: _routing(
        _brief(first_relation="skos:relatedMatch")
    ),
    "routing-empty-ledger": lambda: _routing(
        _brief(), loss_analysis=_empty_ledger_analysis()
    ),
    "routing-known-mechanism": lambda: _routing(_linked_brief("AP-T6-03")),
    "mechanism-verification": lambda: _verification(
        _verifier_item("R1", "AP-T1-01", ())
    ),
    "mechanism-verification-known-mechanism": lambda: _verification(
        _verifier_item("R1", "AP-T6-08", ("user_claim",)),
        _verifier_item("R2", "AP-T6-03", ("retrieved_instructions",)),
    ),
    "revision-responsibility-gap": lambda: _revision(
        _gap("responsibility", "A reviewing responsibility is needed.", "review-gap")
    ),
    "revision-hazard-gap": lambda: _revision(
        _gap("hazard", "A hazard is not explicit in the baseline.", "H-1")
    ),
    "revision-two-gaps": lambda: _revision(
        _gap("responsibility", "A reviewing responsibility is needed.", "RESP-1"),
        _gap("constraint", "A governing constraint is missing.", "SC-1"),
    ),
    "slots-pattern": lambda: _pattern_slots(routed=True),
    "slots-empty": lambda: _pattern_slots(routed=False),
    "slots-governance": lambda: _governance_slots(with_pattern=False),
    "slots-governance-and-pattern": lambda: _governance_slots(with_pattern=True),
    "feedback-opaque-identity": lambda: _feedback(
        ValueError("opaque obligation identity mismatch: ob:v1:0")
    ),
    "feedback-attack-pattern": lambda: _feedback(
        ValueError(
            "route ob:v1:0 for attack pattern AP-T10-01 names another batch "
            "obligation's attack pattern: AP-T15-01 in rationale"
        )
    ),
    "feedback-rationale": lambda: _feedback(ValueError("rationale is required")),
    "feedback-disposition": lambda: _feedback(ValueError("disposition is missing")),
    "feedback-default": lambda: _feedback(
        ValueError("constraint SC-9 does not govern\nselected hazard(s) H-1")
    ),
    "feedback-truncated": lambda: _feedback(ValueError("x" * 1500)),
}


def _path(case: str, part: str) -> Path:
    return GOLDEN_DIR / f"{case}.{part}.txt"


def write_goldens() -> None:
    """Rewrite every golden file from the current prompt builders."""
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    for path in GOLDEN_DIR.glob("*.txt"):
        path.unlink()
    for case, build in CASES.items():
        for part, text in build().items():
            _path(case, part).write_bytes(text.encode("utf-8"))


@pytest.mark.parametrize("case", sorted(CASES))
def test_prompt_bytes_match_the_golden(case: str) -> None:
    for part, text in CASES[case]().items():
        assert text.encode("utf-8") == _path(case, part).read_bytes(), (
            f"{case} {part} differs from its golden file"
        )


def test_every_golden_file_belongs_to_a_case() -> None:
    expected = {
        _path(case, part).name for case, build in CASES.items() for part in build()
    }
    assert {path.name for path in GOLDEN_DIR.glob("*.txt")} == expected
