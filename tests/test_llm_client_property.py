"""Property tests for LLM telemetry conversion and Gherkin row classification.

These properties pin JSON-compatible telemetry conversion and deterministic
Gherkin keyword classification. They are offline and never contact an LLM
endpoint.
"""

from __future__ import annotations

import json
from types import SimpleNamespace

from hypothesis import given, settings, strategies as st

from asago_scenario_generator.llm.client import _plain_value
from asago_scenario_generator.stpa.report.template import (
    _GHERKIN_ROW_KEYWORDS,
    _gherkin_keyword_row,
    _gherkin_row_html,
)

_MAX_EXAMPLES = 60
_TEXT = st.text(
    alphabet="abcdefghijklmnopqrstuvwxyz0123456789 -._",
    min_size=0,
    max_size=24,
)
_JSON_SCALARS = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-1000, max_value=1000),
    st.floats(min_value=-1000, max_value=1000, allow_nan=False, allow_infinity=False),
    _TEXT,
)


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(value=_JSON_SCALARS)
def test_plain_value_leaves_json_scalars_unchanged(value: object) -> None:
    """JSON scalars remain themselves after telemetry conversion."""
    assert _plain_value(value) == value
    json.dumps(_plain_value(value))


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    items=st.lists(_JSON_SCALARS, max_size=5),
    mapping=st.dictionaries(
        st.integers(min_value=0, max_value=20),
        _JSON_SCALARS,
        max_size=4,
    ),
    public=_TEXT,
    private=_TEXT,
)
def test_plain_value_is_json_serializable_and_drops_private_attrs(
    items: list[object],
    mapping: dict[int, object],
    public: str,
    private: str,
) -> None:
    """Containers become JSON data; private object attributes stay hidden."""
    obj = SimpleNamespace(public=public, _private=private)
    converted = _plain_value({"items": items, "map": mapping, "obj": obj})
    json.dumps(converted, sort_keys=True)
    assert converted["items"] == items
    assert converted["map"] == {str(key): item for key, item in mapping.items()}
    assert converted["obj"] == {"public": public}
    assert "_private" not in converted["obj"]


@settings(max_examples=_MAX_EXAMPLES, deadline=None)
@given(
    keyword=st.sampled_from(tuple(kw for kw, _ in _GHERKIN_ROW_KEYWORDS)),
    rest=_TEXT,
)
def test_gherkin_keyword_rows_are_stable(keyword: str, rest: str) -> None:
    """A keyword line always classifies to the same keyword and remainder."""
    line = f"{keyword}{rest}"
    classified = _gherkin_keyword_row(line)
    assert classified is not None
    name, step_text, step_class = classified
    assert name == keyword.strip().rstrip(":")
    assert step_text == rest.strip()
    assert classified == _gherkin_keyword_row(line)
    html = _gherkin_row_html(line)
    assert html is not None
    assert name in html
