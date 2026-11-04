"""The producer's canonical encoder agrees with the shared core's producer encoding."""

from __future__ import annotations

import pytest

from asago_contracts_core import (
    CONSUMER_ENCODING,
    PRODUCER_ENCODING,
    canonical_json_bytes as core_bytes,
    framed_digest as core_framed_digest,
)
from asago_scenario_generator.models.canonical import (
    canonical_json_bytes,
    compute_framed_digest,
)

VALUES = [
    {"a": 1, "b": ["x", "e\u0301"]},
    {"nested": {"\u00e9": [None, True, 2.5]}},
    ["plain", "text"],
]


@pytest.mark.parametrize("value", VALUES)
def test_the_producer_encoder_matches_the_core(value: object) -> None:
    assert canonical_json_bytes(value) == core_bytes(value, encoding=PRODUCER_ENCODING)
    assert compute_framed_digest("d", value) == core_framed_digest(
        "d", value, encoding=PRODUCER_ENCODING
    )


def test_the_producer_encoder_rejects_nan_as_the_core_does() -> None:
    with pytest.raises(ValueError):
        canonical_json_bytes({"value": float("nan")})
    with pytest.raises(ValueError):
        core_bytes({"value": float("nan")}, encoding=PRODUCER_ENCODING)


def test_the_consumer_encoding_keeps_decomposed_text() -> None:
    value = {"label": "e\u0301"}

    assert core_bytes(value, encoding=CONSUMER_ENCODING) != core_bytes(
        value, encoding=PRODUCER_ENCODING
    )
