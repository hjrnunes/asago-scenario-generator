"""The producer's profile readers run the ``model-profile`` contract's cases.

``data/contracts/model-profile/model-profile-v1`` holds the field table, the
load cases and the request cases. The consumer and orch run the same files
against their own readers, so a field handled differently in one reader fails
there.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
import pytest
import yaml
from openai import RateLimitError
from pydantic import BaseModel

from asago_scenario_generator.model_profiles import (
    OPTIONAL_FIELDS,
    REQUIRED_FIELDS,
    ProfileFieldError,
)
from asago_scenario_generator.stpa.infra.llm import LLMClient
from asago_scenario_generator.stpa.pipeline.llm_config import (
    resolve_llm_client_from_profile,
)

READER = "producer"
KIT = (
    Path(__file__).resolve().parents[2]
    / "data/contracts/model-profile/model-profile-v1"
)


def _read(name: str) -> Any:
    return json.loads((KIT / name).read_text(encoding="utf-8"))


FIELDS: list[dict[str, Any]] = _read("fields.json")["fields"]
LOAD_CASES: list[dict[str, Any]] = _read("load-cases.json")["cases"]
_REQUESTS = _read("request-cases.json")
CALL_DEFAULTS: dict[str, Any] = _REQUESTS["call_defaults"]
REQUEST_CASES: list[dict[str, Any]] = _REQUESTS["cases"]
BASE = {
    "base_url": "https://models.example.test/v1",
    "model": "m-1",
    "api_key": "key-1",
}
# The producer client's attribute for each field it carries.
ATTRIBUTE = {"headers": "extra_headers"}


class Reply(BaseModel):
    answer: str = ""


class _Response:
    def __init__(self) -> None:
        message = type("M", (), {"content": '{"answer": "x"}'})()
        self.choices = [type("C", (), {"message": message, "finish_reason": "stop"})()]
        self.usage = type("U", (), {"prompt_tokens": 1, "completion_tokens": 1})()


@pytest.fixture(autouse=True)
def _no_producer_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    import os

    for name in list(os.environ):
        if name.startswith("ASAGO_SCENARIO_GENERATOR_"):
            monkeypatch.delenv(name)


def _default(row: dict[str, Any]) -> Any:
    return row["default"].get(READER, row["default"]["*"])


def expected_loaded(profile: dict[str, Any]) -> dict[str, Any]:
    out = {}
    for row in FIELDS:
        if READER in row["used_by"]:
            value = profile.get(row["name"])
            out[row["name"]] = _default(row) if value is None else value
    return out


def load(
    tmp_path: Path, profile: dict[str, Any], *, shape: str = "flat", name: str = "p"
):
    """Return ('loaded', client), ('rejected', error) or ('not_found', None)."""
    document = {"profiles": {"p": profile}} if shape == "nested" else {"p": profile}
    path = tmp_path / "profiles.yaml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    try:
        with patch("asago_scenario_generator.stpa.infra.llm.OpenAI"):
            client, _ = resolve_llm_client_from_profile(str(path), name)
    except KeyError:
        return "not_found", None
    except ProfileFieldError as error:
        return "rejected", error
    return "loaded", client


def loaded_view(client: LLMClient) -> dict[str, Any]:
    return {
        row["name"]: getattr(client, ATTRIBUTE.get(row["name"], row["name"]))
        for row in FIELDS
        if READER in row["used_by"]
    }


def _expect(case: dict[str, Any]) -> dict[str, Any]:
    return case["expect"].get(READER, case["expect"].get("*"))


def test_field_table_names_the_producer_allow_list() -> None:
    assert {row["name"] for row in FIELDS} == {*REQUIRED_FIELDS, *OPTIONAL_FIELDS}


@pytest.mark.parametrize("case", LOAD_CASES, ids=lambda case: case["id"])
def test_load_case(case: dict[str, Any], tmp_path: Path) -> None:
    outcome, result = load(
        tmp_path,
        case["profile"],
        shape=case.get("file_shape", "flat"),
        name=case.get("lookup_name", "p"),
    )
    expect = _expect(case)
    if "rejected" in expect:
        assert outcome == "rejected"
        assert result.field == expect["rejected"]
        for value in case["profile"].values():
            if isinstance(value, str) and len(value) > 3:
                assert value not in str(result)
    elif "not_found" in expect:
        assert outcome == "not_found"
    else:
        assert outcome == "loaded"
        assert loaded_view(result) == expected_loaded(case["profile"])


_VALID = [(row["name"], value) for row in FIELDS for value in row["valid"]]
_INVALID = [(row["name"], value) for row in FIELDS for value in row["invalid"]]
_REQUIRED = [row["name"] for row in FIELDS if READER in row["required_by"]]


@pytest.mark.parametrize("name,value", _VALID, ids=lambda item: str(item)[:30])
def test_valid_field_value_loads(name: str, value: Any, tmp_path: Path) -> None:
    profile = {**BASE, name: value}
    outcome, result = load(tmp_path, profile)
    assert outcome == "loaded"
    assert loaded_view(result) == expected_loaded(profile)


@pytest.mark.parametrize("name,value", _INVALID, ids=lambda item: str(item)[:30])
def test_invalid_field_value_is_rejected_by_name(
    name: str, value: Any, tmp_path: Path
) -> None:
    outcome, result = load(tmp_path, {**BASE, name: value})
    assert outcome == "rejected"
    assert result.field == name
    if isinstance(value, str) and len(value) > 3:
        assert value not in str(result)


@pytest.mark.parametrize("name", _REQUIRED)
def test_absent_required_field_is_rejected_by_name(name: str, tmp_path: Path) -> None:
    profile = {key: value for key, value in BASE.items() if key != name}
    outcome, result = load(tmp_path, profile)
    assert outcome == "rejected"
    assert result.field == name


@pytest.mark.parametrize(
    "name,value",
    [
        ("timeout", float("inf")),
        ("temperature", float("nan")),
        ("repetition_penalty", float("inf")),
    ],
    ids=lambda item: str(item),
)
def test_non_finite_number_is_rejected_by_name(
    name: str, value: float, tmp_path: Path
) -> None:
    """JSON cannot carry infinity or NaN, so the contract's value lists omit them."""
    outcome, result = load(tmp_path, {**BASE, name: value})
    assert outcome == "rejected"
    assert result.field == name


def normalized(kwargs: dict[str, Any]) -> dict[str, Any]:
    request = {key: value for key, value in kwargs.items() if key != "messages"}
    spec = request.get("response_format")
    if spec is not None:
        shown = {"type": spec["type"]}
        if spec["type"] == "json_schema":
            shown.update(
                name=spec["json_schema"]["name"], strict=spec["json_schema"]["strict"]
            )
        request["response_format"] = shown
    return request


def _rate_limit() -> RateLimitError:
    response = httpx.Response(
        429, request=httpx.Request("POST", "https://models.example.test")
    )
    return RateLimitError("rate limited", response=response, body=None)


def send(
    client: LLMClient, call: dict[str, Any]
) -> tuple[list[dict[str, Any]], str | None]:
    outcomes: list[Any] = [_rate_limit()] if call["first_error"] else []
    create = MagicMock(side_effect=[*outcomes, _Response(), _Response()])
    client._client = MagicMock()
    client._client.chat.completions.create = create
    error = None
    try:
        client.complete(
            call["system"],
            call["user"],
            response_format=Reply if call["structured"] else None,
            max_completion_tokens=call["max_completion_tokens"],
            temperature=call["temperature"],
        )
    except RateLimitError:
        error = "RateLimitError"
    return [normalized(item.kwargs) for item in create.call_args_list], error


@pytest.mark.parametrize("case", REQUEST_CASES, ids=lambda case: case["id"])
def test_request_case(case: dict[str, Any], tmp_path: Path) -> None:
    outcome, client = load(tmp_path, case["profile"])
    assert outcome == "loaded"
    requests, error = send(client, {**CALL_DEFAULTS, **case["call"]})
    expect = _expect(case)
    assert requests == expect["requests"]
    assert error == expect.get("error")
