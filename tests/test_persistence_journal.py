"""Validation of quarantine-bundle digests."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from asago_scenario_generator.pipeline.persistence_common import canonical_sha256
from asago_scenario_generator.pipeline.persistence_journal import QuarantineBundleV1

_ACTOR = {"name": "actor"}
_TREE = {"root": {"id": "n1"}}


def _bundle(**overrides: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": "1",
        "run_id": "run-1",
        "attempt_id": "attempt-1",
        "candidate_id": "cand-1",
        "target_entry_point_id": "ep-1",
        "actor": _ACTOR,
        "narrative": None,
        "tree": _TREE,
        "behavior": None,
        "artifact_sha256": {
            "actor": canonical_sha256(_ACTOR),
            "tree": canonical_sha256(_TREE),
        },
        "violations": [
            {"code": "x", "detail": "detail", "owner": None, "retryable": False}
        ],
    }
    payload.update(overrides)
    return payload


def test_bundle_accepts_digests_that_match_each_serialized_artifact() -> None:
    bundle = QuarantineBundleV1.model_validate(_bundle())
    assert bundle.actor == _ACTOR
    assert bundle.narrative is None


@pytest.mark.parametrize(
    "digest",
    ["abc", "A" * 64, "g" * 64, "a" * 65],
    ids=["short", "uppercase", "non-hex", "long"],
)
def test_bundle_rejects_noncanonical_digest_text(digest: str) -> None:
    payload = _bundle(artifact_sha256={"actor": digest, "tree": digest})
    with pytest.raises(ValidationError, match="must be canonical SHA-256"):
        QuarantineBundleV1.model_validate(payload)


def test_bundle_rejects_artifact_without_a_digest() -> None:
    payload = _bundle(artifact_sha256={"actor": canonical_sha256(_ACTOR)})
    with pytest.raises(
        ValidationError, match="each serialized quarantine artifact requires one digest"
    ):
        QuarantineBundleV1.model_validate(payload)


def test_bundle_rejects_digest_for_a_missing_artifact() -> None:
    payload = _bundle(
        artifact_sha256={
            "actor": canonical_sha256(_ACTOR),
            "tree": canonical_sha256(_TREE),
            "behavior": canonical_sha256({"x": 1}),
        }
    )
    with pytest.raises(
        ValidationError, match="each serialized quarantine artifact requires one digest"
    ):
        QuarantineBundleV1.model_validate(payload)


def test_bundle_rejects_digest_that_belongs_to_other_content() -> None:
    payload = _bundle(
        artifact_sha256={
            "actor": canonical_sha256(_TREE),
            "tree": canonical_sha256(_TREE),
        }
    )
    with pytest.raises(ValidationError, match="quarantine actor digest mismatch"):
        QuarantineBundleV1.model_validate(payload)
