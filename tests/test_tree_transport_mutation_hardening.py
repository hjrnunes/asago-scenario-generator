"""Focused adversarial coverage for attack-tree transport helpers."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from asago_scenario_generator.pipeline.generate import tree_transport


def test_quoted_yaml_value_requires_matching_delimiters() -> None:
    assert tree_transport._is_quoted_yaml_value('"value"') is True
    assert tree_transport._is_quoted_yaml_value("'value'") is True
    assert tree_transport._is_quoted_yaml_value("value") is False
    assert tree_transport._is_quoted_yaml_value('"value\'') is False


@pytest.mark.parametrize(
    ("kind", "boundary", "initial_zone", "expected_zone"),
    (
        ("impact", "external", "reasoning", None),
        ("impact", "internal", "reasoning", "reasoning"),
        ("ai_system_action", "external", "reasoning", "reasoning"),
    ),
)
def test_normalize_leaf_action_only_clears_external_impacts(
    kind: str,
    boundary: str,
    initial_zone: str,
    expected_zone: str | None,
) -> None:
    node = {
        "zone": initial_zone,
        "action": {"kind": kind, "boundary": boundary},
    }

    tree_transport._normalize_leaf_action(node, {})

    assert node["zone"] == expected_zone


def test_normalize_transport_requires_dict_data_and_context() -> None:
    data = ["not", "a", "mapping"]

    assert tree_transport.normalize_attack_tree_transport(data, {}) is data
    mapping = {"root": {"id": "root"}}
    assert (
        tree_transport.normalize_attack_tree_transport(mapping, None)
        == mapping
    )


def test_strip_yaml_fences_removes_opening_and_closing_fences() -> None:
    assert (
        tree_transport._strip_yaml_fences("```yaml\nroot: value\n```\n")
        == "root: value"
    )


def test_strip_yaml_fences_preserves_content_without_closing_fence() -> None:
    assert (
        tree_transport._strip_yaml_fences("```yaml\nroot: value\nchild: value")
        == "root: value\nchild: value"
    )


def test_parse_tree_extracts_optional_attack_tree_wrapper(monkeypatch) -> None:
    monkeypatch.setattr(
        tree_transport,
        "_load_tree_yaml",
        lambda _cleaned, _seed_id: {"attack_tree": {"root": {"id": "root"}}},
    )
    monkeypatch.setattr(
        tree_transport,
        "AttackTree",
        SimpleNamespace(model_validate=lambda data: data),
    )

    result = tree_transport._parse_attack_tree_yaml(
        "root: ignored",
        SimpleNamespace(seed_id="seed"),
    )

    assert result == {"root": {"id": "root"}}


def test_parse_tree_keeps_plain_mapping_without_wrapper(monkeypatch) -> None:
    plain = {"root": {"id": "root"}}
    monkeypatch.setattr(
        tree_transport,
        "_load_tree_yaml",
        lambda _cleaned, _seed_id: plain,
    )
    monkeypatch.setattr(
        tree_transport,
        "AttackTree",
        SimpleNamespace(model_validate=lambda data: data),
    )

    assert (
        tree_transport._parse_attack_tree_yaml(
            "root: ignored",
            SimpleNamespace(seed_id="seed"),
        )
        == plain
    )
