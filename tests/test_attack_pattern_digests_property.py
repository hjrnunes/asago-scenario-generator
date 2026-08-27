"""Property tests for attack-pattern and catalog-lineage digest leaves."""

from __future__ import annotations

import json
import unicodedata

from hypothesis import assume, given, settings, strategies as st

from asago_scenario_generator.data.canonical import _nfc
from asago_scenario_generator.data.catalog_lineage_snapshot import (
    compute_source_catalog_digest,
)
from asago_scenario_generator.models.attack_pattern_contracts import (
    AllCondition,
    AuthoritativeFactReference,
    EqualityCondition,
    EvaluatedFactEvidence,
    NotCondition,
    evaluate_condition,
)
from asago_scenario_generator.models.attack_pattern_digests import (
    _canonical_json as digest_canonical_json,
    _normalize,
)

_MAX_EXAMPLES = 60
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
_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789-_",
    min_size=1,
    max_size=8,
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(value=_JSON_VALUES)
def test_digest_canonical_json_is_deterministic_and_nfc(value: object) -> None:
    """Digest encoding is stable and applies NFC to strings and keys."""
    first = digest_canonical_json(value)
    second = digest_canonical_json(value)
    assert first == second
    decoded = json.loads(first)
    assert decoded == _normalize(value)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(text=st.text(max_size=24))
def test_lineage_nfc_matches_canonical_helper(text: str) -> None:
    """Snapshot pinning uses the shared NFC helper."""
    assert _nfc(text) == unicodedata.normalize("NFC", text)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    pattern_id=_IDS,
    filename=_IDS,
    payload=st.dictionaries(
        st.text(
            alphabet="abcdefghijklmnopqrstuvwxyz",
            min_size=1,
            max_size=6,
        ),
        st.one_of(st.none(), st.booleans(), st.text(max_size=12)),
        max_size=4,
    ),
)
def test_source_catalog_digest_is_order_insensitive(
    pattern_id: str,
    filename: str,
    payload: dict[str, object],
) -> None:
    """Reordering object keys does not change the source-catalog pin."""
    record = {"id": pattern_id, **payload}
    reversed_record = dict(reversed(list(record.items())))
    first = compute_source_catalog_digest(
        {pattern_id: record},
        {pattern_id: filename},
        [filename],
    )
    second = compute_source_catalog_digest(
        {pattern_id: reversed_record},
        {pattern_id: filename},
        [filename],
    )
    assert first == second
    assert len(first) == 64
    int(first, 16)
    other = compute_source_catalog_digest(
        {pattern_id + "x": record},
        {pattern_id + "x": filename},
        [filename],
    )
    assert other != first


def _fact(fact_id: str) -> AuthoritativeFactReference:
    return AuthoritativeFactReference(
        namespace="profile",
        fact_id=fact_id,
        value_type="string",
        property_path=(),
    )


def _equality(fact_id: str, value: str) -> EqualityCondition:
    return EqualityCondition(
        op="equality",
        schema_version="1",
        fact=_fact(fact_id),
        value=value,
    )


def _evidence(
    fact_id: str,
    status: str,
    value: str | None,
) -> EvaluatedFactEvidence:
    return EvaluatedFactEvidence(
        fact=_fact(fact_id),
        status=status,  # type: ignore[arg-type]
        value=value,
    )


_STATUSES = st.sampled_from(("present", "absent", "unknown"))
_VALUES = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz",
    min_size=1,
    max_size=8,
)
_FACT_IDS = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz",
    min_size=1,
    max_size=8,
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    left_id=_FACT_IDS,
    right_id=_FACT_IDS,
    left_value=_VALUES,
    right_value=_VALUES,
    left_status=_STATUSES,
    right_status=_STATUSES,
)
def test_condition_evaluation_is_order_insensitive_and_double_negation_identity(
    left_id: str,
    right_id: str,
    left_value: str,
    right_value: str,
    left_status: str,
    right_status: str,
) -> None:
    """Evidence order does not change a conjunction; not-not preserves the verdict."""
    assume(left_id != right_id)
    left_ev_value = left_value if left_status == "present" else None
    right_ev_value = right_value if right_status == "present" else None
    left = _equality(left_id, left_value)
    right = _equality(right_id, right_value)
    conjunction = AllCondition(
        op="all",
        schema_version="1",
        operands=(left, right),
    )
    evidence = (
        _evidence(left_id, left_status, left_ev_value),
        _evidence(right_id, right_status, right_ev_value),
    )
    reversed_evidence = tuple(reversed(evidence))
    first = evaluate_condition(conjunction, evidence)
    second = evaluate_condition(conjunction, reversed_evidence)
    assert first == second
    negated = NotCondition(op="not", schema_version="1", operand=conjunction)
    double_negated = NotCondition(op="not", schema_version="1", operand=negated)
    assert evaluate_condition(double_negated, evidence) == first
