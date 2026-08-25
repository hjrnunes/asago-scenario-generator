"""Property tests for the inward projection-contract leaf.

These properties pin digest, canonical-JSON, and slot-matching helpers
that live on ``pipeline.projection_contracts``.  They are offline and
deterministic; they never contact an LLM endpoint.
"""

from __future__ import annotations

import hashlib
import json
import unicodedata

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.models.attack_pattern import (
    EntryPointResourceReference,
    ToolResourceReference,
)
from asago_scenario_generator.pipeline.projection_contracts import (
    _digest,
    _normalize_unicode,
    _resource_id,
    _resource_id_allowed,
    _restriction_blocks,
    canonical_json_bytes,
    compute_derivation_context_digest,
    compute_execution_requirements_digest,
)

_MAX_EXAMPLES = 60
_HEX = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
_HEX32 = st.text(alphabet="0123456789abcdef", min_size=32, max_size=32)
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=16,
)
_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-10_000, max_value=10_000),
    st.text(max_size=24),
)
_JSON_VALUES = st.recursive(
    _JSON_SCALARS,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(
            st.text(
                alphabet="abcdefghijklmnopqrstuvwxyzéè",
                min_size=1,
                max_size=8,
            ),
            children,
            max_size=4,
        ),
    ),
    max_leaves=12,
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(value=_JSON_VALUES)
def test_canonical_json_bytes_is_deterministic_and_nfc(value: object) -> None:
    """Canonical encoding is stable and applies NFC to strings and keys."""
    first = canonical_json_bytes(value)
    second = canonical_json_bytes(value)
    assert first == second
    decoded = json.loads(first.decode("utf-8"))
    assert decoded == _normalize_unicode(value)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    left=st.text(max_size=12),
    right=st.text(max_size=12),
)
def test_nfc_key_collision_is_rejected(left: str, right: str) -> None:
    """Mapping keys that collide after NFC cannot be digested."""
    left_nfc = unicodedata.normalize("NFC", left)
    right_nfc = unicodedata.normalize("NFC", right)
    if not left or not right or left_nfc != right_nfc or left == right:
        return
    try:
        canonical_json_bytes({left: 1, right: 2})
    except ValueError as exc:
        assert "collide after NFC" in str(exc)
        return
    raise AssertionError("NFC-colliding mapping keys must fail closed")


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    payloads=st.lists(
        st.dictionaries(
            st.sampled_from(("kind", "requirement_id", "slot_id")),
            _IDS,
            min_size=1,
            max_size=3,
        ),
        max_size=5,
    )
)
def test_execution_requirements_digest_is_order_sensitive(
    payloads: list[dict[str, str]],
) -> None:
    """The digest is deterministic and changes when requirement order does."""
    first = compute_execution_requirements_digest(payloads)
    assert first == compute_execution_requirements_digest(payloads)
    assert len(first) == 64
    if len(set(json.dumps(item, sort_keys=True) for item in payloads)) < 2:
        return
    reversed_payloads = list(reversed(payloads))
    if reversed_payloads == payloads:
        return
    assert first != compute_execution_requirements_digest(reversed_payloads)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    projection_digest=_HEX,
    pattern_id=_IDS,
    controllability=st.sampled_from(("direct", "indirect")),
)
def test_derivation_context_digest_binds_identity_inputs(
    projection_digest: str,
    pattern_id: str,
    controllability: str,
) -> None:
    """The derivation digest is a domain-separated hash of its three inputs."""
    digest = compute_derivation_context_digest(
        projection_digest, pattern_id, controllability
    )
    expected = _digest(
        "asago-scenario-generator:derivation-context:v1",
        {
            "projection_digest": projection_digest,
            "pattern_id": pattern_id,
            "ingress_controllability": controllability,
        },
    )
    assert digest == expected
    assert digest == compute_derivation_context_digest(
        projection_digest, pattern_id, controllability
    )
    flipped = "indirect" if controllability == "direct" else "direct"
    assert digest != compute_derivation_context_digest(
        projection_digest, pattern_id, flipped
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    hex_id=_HEX32,
    allowed_hex=st.lists(_HEX32, max_size=6),
)
def test_resource_id_allow_list_is_empty_or_membership(
    hex_id: str, allowed_hex: list[str]
) -> None:
    """An empty allow-list admits every reference; a nonempty list is exact."""
    resource_id = f"tool:v1:{hex_id}"
    reference = ToolResourceReference(kind="tool", tool_id=resource_id)
    allowed_set = {f"tool:v1:{item}" for item in allowed_hex}
    assert _resource_id(reference) == resource_id
    if not allowed_set:
        assert _resource_id_allowed(reference, allowed_set)
        return
    assert _resource_id_allowed(reference, allowed_set) is (
        resource_id in allowed_set
    )


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    value=_IDS,
    allowed=st.lists(_IDS, max_size=6),
)
def test_restriction_blocks_empty_or_membership(
    value: str, allowed: list[str]
) -> None:
    """An empty restriction never blocks; a nonempty one is membership."""
    allowed_tuple = tuple(allowed)
    if not allowed_tuple:
        assert _restriction_blocks(value, allowed_tuple) is False
        return
    assert _restriction_blocks(value, allowed_tuple) is (value not in allowed_tuple)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(hex_id=_HEX32)
def test_entry_point_resource_id_is_the_canonical_identifier(
    hex_id: str,
) -> None:
    """Entry-point identity extraction is the declared entry_point_id."""
    entry_point_id = f"ep:v1:{hex_id}"
    reference = EntryPointResourceReference(
        kind="entry_point", entry_point_id=entry_point_id
    )
    assert _resource_id(reference) == entry_point_id


def test_digest_uses_domain_separator() -> None:
    """Domain-separated digests differ from a bare SHA-256 of the payload."""
    payload = {"pattern_id": "AP-T1-01"}
    digest = _digest("asago-scenario-generator:candidate:v2", payload)
    bare = hashlib.sha256(canonical_json_bytes(payload)).hexdigest()
    assert digest != bare
    assert len(digest) == 64
