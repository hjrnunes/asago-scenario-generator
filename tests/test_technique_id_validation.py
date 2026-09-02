"""Tests for technique_id validation on AttackTreeNode.

Ensures both ATLAS (AML.T0054) and LAAF (S1, M2, L1) technique ID
formats are accepted, and invalid IDs are rejected.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from asago_scenario_generator.models.attack_tree import AiSystemAction, AttackTreeNode


def _make_leaf(technique_id: str | None = None) -> dict:
    """Build a minimal LEAF node dict with an optional technique_id."""
    node = {
        "id": "n1",
        "label": "Test node",
        "gate": "LEAF",
        "zone": "input",
        "action": AiSystemAction(),
    }
    if technique_id is not None:
        node["technique_id"] = technique_id
    return node


# ---- ATLAS format (AML.T + 4 digits, optional .3-digit sub) ----


class TestAtlasTechniqueIds:
    """ATLAS-format technique IDs should be accepted."""

    @pytest.mark.parametrize(
        "tid",
        [
            "AML.T0051",
            "AML.T0054",
            "AML.T0010",
            "AML.T9999",
            "AML.T0051.000",
            "AML.T0051.001",
            "AML.T0054.123",
        ],
    )
    def test_valid_atlas_ids(self, tid: str) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(technique_id=tid))
        assert node.technique_id == tid

    def test_none_is_valid(self) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(technique_id=None))
        assert node.technique_id is None


# ---- LAAF format ([SML] + digits) ----


class TestLaafTechniqueIds:
    """LAAF-format technique IDs should be accepted."""

    @pytest.mark.parametrize(
        "tid",
        [
            "S1",
            "S3",
            "M2",
            "M3",
            "M4",
            "L1",
            "S10",
            "M99",
            "L123",
        ],
    )
    def test_valid_laaf_ids(self, tid: str) -> None:
        node = AttackTreeNode.model_validate(_make_leaf(technique_id=tid))
        assert node.technique_id == tid


# ---- Invalid IDs that should be rejected ----


class TestInvalidTechniqueIds:
    """Invalid technique IDs should be rejected by the pattern."""

    @pytest.mark.parametrize(
        "tid",
        [
            "T0054",  # missing AML. prefix
            "AML.T054",  # only 3 digits
            "AML.T00541",  # 5 digits
            "AML.T0054.01",  # sub-technique with 2 digits
            "AML.T0054.0001",  # sub-technique with 4 digits
            "aml.t0054",  # lowercase
            "ATLAS.T0054",  # wrong prefix
            "X1",  # invalid LAAF prefix letter
            "A1",  # not S, M, or L
            "s1",  # lowercase LAAF
            "S",  # missing digit
            "M0a",  # non-digit suffix
            "",  # empty string
            "random",  # arbitrary string
        ],
    )
    def test_invalid_ids_rejected(self, tid: str) -> None:
        with pytest.raises(ValidationError):
            AttackTreeNode.model_validate(_make_leaf(technique_id=tid))
