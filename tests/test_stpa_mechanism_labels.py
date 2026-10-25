"""The join's mechanism labels are mechanism library IDs that fit their entries."""

from __future__ import annotations

import json

from asago_scenario_generator.stpa.mechanism_library import (
    ControllerCrossing,
    MechanismId,
    bundled_mechanism_library,
)
from asago_scenario_generator.stpa.models.control_structure import (
    UNTRUSTED_FEEDBACK_SOURCES,
    FeedbackAuthorityStatus,
)
from asago_scenario_generator.stpa.obligation_aware.stpa_index import (
    ASSESSED_AUTHORITY,
    CROSS_CONTROLLER_MECHANISM,
    SOURCE_MECHANISMS,
    MechanismCandidate,
)

_KEPT_AUTHORITY = ASSESSED_AUTHORITY | {FeedbackAuthorityStatus.unknown}


def test_every_untrusted_source_kind_has_a_library_label() -> None:
    assert set(SOURCE_MECHANISMS) == UNTRUSTED_FEEDBACK_SOURCES
    for label in (*SOURCE_MECHANISMS.values(), CROSS_CONTROLLER_MECHANISM):
        assert isinstance(label, MechanismId)


def test_a_source_label_entry_starts_from_its_source_kind() -> None:
    library = bundled_mechanism_library()
    for kind, label in SOURCE_MECHANISMS.items():
        signature = library.entry(label).signature
        assert kind in signature.source_kinds, label
        assert signature.crossing is not ControllerCrossing.must_cross, label


def test_the_cross_controller_label_entry_crosses_from_any_untrusted_kind() -> None:
    signature = bundled_mechanism_library().entry(CROSS_CONTROLLER_MECHANISM).signature

    assert signature.crossing is ControllerCrossing.must_cross
    assert set(signature.source_kinds) == UNTRUSTED_FEEDBACK_SOURCES


def test_a_label_entry_applies_exactly_where_the_authority_filter_keeps() -> None:
    library = bundled_mechanism_library()
    for label in (*SOURCE_MECHANISMS.values(), CROSS_CONTROLLER_MECHANISM):
        assert set(library.entry(label).signature.authority) == _KEPT_AUTHORITY


def test_a_typed_label_keeps_the_candidate_equal_to_its_string_form() -> None:
    path = ("FB-1-1", "PM-1-1", "CA-1-1")
    typed = MechanismCandidate(MechanismId.user_claim, path)
    plain = MechanismCandidate("user_claim", path)  # type: ignore[arg-type]

    assert typed == plain and hash(typed) == hash(plain)
    assert json.dumps({typed.mechanism: typed.mechanism}) == (
        '{"user_claim": "user_claim"}'
    )
    assert f"{typed.mechanism}" == "user_claim"
