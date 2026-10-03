"""Property tests for policy-free unvalidated model construction.

These cover the decode-layer invariants:

- every required field is accessible after a missing-field decode
- declared defaults survive omitted optional fields
- already-well-formed mappings decode idempotently
- omitted required nested models become None and fail validation
"""

from __future__ import annotations

from hypothesis import given, settings, strategies as st
from pydantic import BaseModel, Field, ValidationError
import pytest

from asago_scenario_generator.stpa.infra.llm import LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import parse_llm_result_unvalidated
from asago_scenario_generator.stpa.infra.unvalidated_decode import (
    construct_model_unvalidated,
)


class _NestedModel(BaseModel):
    item_id: str
    label: str = "kept"


class _RequiredNested(BaseModel):
    nested: _NestedModel


class _KitchenSink(BaseModel):
    text: str
    count: int
    ratio: float
    enabled: bool
    labels: list[str]
    checkpoints: tuple[str, ...]
    tags: set[str]
    metadata: dict[str, int]
    note: str | None = None
    extras: list[str] = Field(default_factory=list)
    nested: _NestedModel | None = None


st_text = st.text(max_size=12)
st_labels = st.lists(st_text, max_size=4)
st_checkpoints = st.lists(st_text, max_size=4)
st_tags = st.lists(st_text, max_size=4)
st_metadata = st.dictionaries(
    st_text, st.integers(min_value=-20, max_value=20), max_size=4
)
st_optional_note = st.one_of(st.none(), st_text)
st_nested = st.fixed_dictionaries({"item_id": st_text, "label": st_text})


@st.composite
def st_kitchen_payload(draw) -> dict:
    payload = {
        "text": draw(st_text),
        "count": draw(st.integers(min_value=-50, max_value=50)),
        "ratio": draw(st.floats(allow_nan=False, allow_infinity=False, width=32)),
        "enabled": draw(st.booleans()),
        "labels": draw(st_labels),
        "checkpoints": tuple(draw(st_checkpoints)),
        "tags": set(draw(st_tags)),
        "metadata": draw(st_metadata),
    }
    if draw(st.booleans()):
        payload["note"] = draw(st_optional_note)
    if draw(st.booleans()):
        payload["extras"] = draw(st_labels)
    if draw(st.booleans()):
        payload["nested"] = draw(st.one_of(st.none(), st_nested))
    return payload


def _accessible_fields(model: BaseModel) -> dict[str, object]:
    return {name: getattr(model, name) for name in type(model).model_fields}


class TestRequiredFieldsAreAlwaysAccessible:
    """Missing required fields never raise AttributeError."""

    @given(st.lists(st.sampled_from(list(_KitchenSink.model_fields)), unique=True))
    @settings(max_examples=40, deadline=None)
    def test_omitted_required_fields_are_readable(self, omitted):
        payload = {
            "text": "ok",
            "count": 1,
            "ratio": 1.5,
            "enabled": True,
            "labels": ["a"],
            "checkpoints": ("b",),
            "tags": {"c"},
            "metadata": {"k": 1},
            "note": "keep",
            "extras": ["x"],
            "nested": {"item_id": "n", "label": "l"},
        }
        for name in omitted:
            payload.pop(name, None)

        decoded = construct_model_unvalidated(payload, _KitchenSink)
        values = _accessible_fields(decoded)

        for name, field in _KitchenSink.model_fields.items():
            assert name in values
            if name in omitted and field.is_required():
                annotation = field.annotation
                if annotation is str:
                    assert values[name] == ""
                elif annotation is int:
                    assert values[name] == 0
                elif annotation is float:
                    assert values[name] == 0.0
                elif annotation is bool:
                    assert values[name] is False
                elif annotation is list[str]:
                    assert values[name] == []
                elif annotation is tuple[str, ...]:
                    assert values[name] == ()
                elif annotation is set[str]:
                    assert values[name] == set()
                elif annotation is dict[str, int]:
                    assert values[name] == {}
            elif name not in omitted:
                expected = payload[name]
                if name == "nested" and isinstance(expected, dict):
                    assert values[name].item_id == expected["item_id"]
                    assert values[name].label == expected["label"]
                else:
                    assert values[name] == expected


class TestDeclaredDefaultsArePreserved:
    """Omitted optional fields keep the model's declared default."""

    @given(st_text, st.integers(min_value=-20, max_value=20))
    @settings(max_examples=30, deadline=None)
    def test_optional_defaults_survive(self, item_id, unused):
        del unused
        decoded = construct_model_unvalidated({"item_id": item_id}, _NestedModel)
        assert decoded.item_id == item_id
        assert decoded.label == "kept"

        kitchen = construct_model_unvalidated(
            {
                "text": item_id,
                "count": 1,
                "ratio": 0.5,
                "enabled": False,
                "labels": [],
                "checkpoints": (),
                "tags": set(),
                "metadata": {},
            },
            _KitchenSink,
        )
        assert kitchen.note is None
        assert kitchen.extras == []
        assert kitchen.nested is None


class TestWellFormedDecodeIsIdempotent:
    """A second unvalidated decode of dumped values is a no-op."""

    @given(st_kitchen_payload())
    @settings(max_examples=40, deadline=None)
    def test_second_decode_matches_first(self, payload):
        first = construct_model_unvalidated(payload, _KitchenSink)
        dumped = first.model_dump()
        second = construct_model_unvalidated(dumped, _KitchenSink)
        assert second.model_dump() == dumped

        result = LLMResult(
            content=dumped,
            prompt_tokens=0,
            completion_tokens=0,
            duration_ms=0,
        )
        via_adapter = parse_llm_result_unvalidated(result, _KitchenSink)
        assert via_adapter.model_dump() == dumped


class TestMissingNestedModelsFailValidation:
    """Required nested models stay None and fail later validation."""

    @given(st.dictionaries(st.sampled_from(["other", "extra"]), st_text, max_size=2))
    @settings(max_examples=20, deadline=None)
    def test_omitted_nested_model_is_none(self, extras):
        decoded = construct_model_unvalidated(extras, _RequiredNested)
        assert decoded.nested is None
        with pytest.raises(ValidationError, match="nested"):
            _RequiredNested.model_validate(decoded.model_dump())
