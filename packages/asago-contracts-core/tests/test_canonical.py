"""Pin the two persisted canonical-JSON encodings and their framed digests."""

from __future__ import annotations

import hashlib
import json

import pytest

from asago_contracts_core import (
    CONSUMER_ENCODING,
    PRODUCER_ENCODING,
    canonical_json,
    canonical_json_bytes,
    digest_record,
    encoding_for,
    framed_digest,
    normalize_unicode,
    sha256_hex,
)

DECOMPOSED = "e\u0301"
COMPOSED = "\u00e9"


def test_the_producer_encoding_normalizes_to_nfc() -> None:
    assert canonical_json({"label": DECOMPOSED}, encoding=PRODUCER_ENCODING) == (
        '{"label":"%s"}' % COMPOSED
    )


def test_the_consumer_encoding_leaves_text_as_written() -> None:
    assert canonical_json({"label": DECOMPOSED}, encoding=CONSUMER_ENCODING) == (
        '{"label":"%s"}' % DECOMPOSED
    )


def test_the_producer_encoding_rejects_non_finite_numbers() -> None:
    with pytest.raises(ValueError):
        canonical_json({"value": float("nan")}, encoding=PRODUCER_ENCODING)


def test_the_consumer_encoding_accepts_non_finite_numbers() -> None:
    assert canonical_json({"value": float("nan")}, encoding=CONSUMER_ENCODING) == (
        '{"value":NaN}'
    )


def test_the_producer_encoding_refuses_non_string_keys_and_nfc_collisions() -> None:
    with pytest.raises(TypeError, match="keys must be strings"):
        canonical_json({1: "a"}, encoding=PRODUCER_ENCODING)
    with pytest.raises(ValueError, match="collide after NFC normalization"):
        canonical_json({COMPOSED: 1, DECOMPOSED: 2}, encoding=PRODUCER_ENCODING)


def test_both_encodings_agree_when_text_is_already_nfc_and_finite() -> None:
    value = {"b": [1, 2.5, None, True], "a": COMPOSED}

    assert canonical_json_bytes(value, encoding=PRODUCER_ENCODING) == (
        canonical_json_bytes(value, encoding=CONSUMER_ENCODING)
    )
    assert canonical_json(value, encoding=PRODUCER_ENCODING) == (
        '{"a":"%s","b":[1,2.5,null,true]}' % COMPOSED
    )


def test_the_frame_is_utf8_domain_nul_and_canonical_json() -> None:
    value = {"a": 1}
    payload = (
        f"scenario-handoff-v1\0{canonical_json(value, encoding=PRODUCER_ENCODING)}"
    )

    assert (
        framed_digest("scenario-handoff-v1", value)
        == hashlib.sha256(payload.encode("utf-8")).hexdigest()
    )


def test_the_producer_and_consumer_frames_differ_on_unnormalized_text() -> None:
    value = {"label": DECOMPOSED}

    assert framed_digest("d", value, encoding=PRODUCER_ENCODING) != framed_digest(
        "d", value, encoding=CONSUMER_ENCODING
    )


def test_a_digest_record_names_the_encoding_that_produced_it() -> None:
    record = digest_record("d", {"a": 1}, encoding=CONSUMER_ENCODING)

    assert record == {
        "encoding": "canonical-json-v1",
        "domain": "d",
        "sha256": framed_digest("d", {"a": 1}, encoding=CONSUMER_ENCODING),
    }
    assert digest_record("d", {"a": 1})["encoding"] == "canonical-json-nfc-v1"


def test_encoding_for_names_all_four_policies() -> None:
    assert encoding_for(nfc=True, allow_nan=False) is PRODUCER_ENCODING
    assert encoding_for(nfc=False, allow_nan=True) is CONSUMER_ENCODING
    assert encoding_for(nfc=True, allow_nan=True).name == (
        "canonical-json-nfc-allow-nan-v1"
    )
    assert encoding_for(nfc=False, allow_nan=False).name == "canonical-json-no-nan-v1"


def test_normalize_unicode_walks_mappings_and_lists() -> None:
    assert normalize_unicode({DECOMPOSED: [DECOMPOSED]}) == {COMPOSED: [COMPOSED]}
    with pytest.raises(TypeError):
        normalize_unicode({1: "a"})


def test_sha256_hex_hashes_raw_bytes_only() -> None:
    assert sha256_hex(b"abc") == hashlib.sha256(b"abc").hexdigest()
    with pytest.raises(TypeError):
        sha256_hex("abc")  # type: ignore[arg-type]


def test_the_producer_encoding_matches_a_literal_json_dump() -> None:
    value = {"z": 1, "a": ["x", DECOMPOSED]}

    assert canonical_json(value, encoding=PRODUCER_ENCODING) == json.dumps(
        {"z": 1, "a": ["x", COMPOSED]},
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
