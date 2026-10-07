"""Stage 5 instructions for the condition language: order, not_called, values.

Each test pins text in the request the model receives (built by the real
prompt builder, or by the real correction flow), not in the template source.
"""

from __future__ import annotations

from .test_condition_family import _request


def _flat(text: str) -> str:
    return " ".join(text.split())


def _user() -> str:
    _, user = _request(None)
    return _flat(user)


# --- P1: the exact meaning of an order comparison ---------------------------


def test_order_comparison_states_the_one_sequence_it_holds_for() -> None:
    user = _user()
    for phrase in (
        "It holds only for a call of `operation` that no `requires_prior` "
        "call precedes.",
        "It cannot say that `operation` happens after `requires_prior` or "
        "that the two run in the opposite order; do not swap the names to "
        "approximate such a sequence.",
        "When the unsafe behavior has that form, state it with a comparison "
        "over supplied values that separates the unsafe call, or declare the "
        "scenario analytical-only.",
    ):
        assert phrase in user, phrase
