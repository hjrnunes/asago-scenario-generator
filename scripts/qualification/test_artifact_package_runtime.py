from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re

import pytest

from artifact_package_runtime import (
    ArtifactPackageError,
    load_artifact_package,
    secret_metadata_paths,
    validate_artifact_package_contract,
)


PRODUCER_ROOT = Path(__file__).resolve().parents[2]
CONSUMER_ROOT = PRODUCER_ROOT.parent / "asago-artifact-generator"


G07_PACKAGE = (
    CONSUMER_ROOT / "runs" / "authoring" / "g07-fresh-20260918" / "G07-fresh-20260918"
)


def _write_package(
    root: Path,
    *,
    tamper: bool = False,
    authoring: dict | None = None,
) -> Path:
    members = {
        "plan.json": b'{"runtime_contract":{"setup_permissions":[]}}\n',
        "stimulus.json": b'{"user_text":"hello"}\n',
        "setup.json": b"[]\n",
        "bindings.json": b"[]\n",
        "prerequisites.json": b"[]\n",
        "detector.py": (
            b"def evaluate(evidence):\n"
            b"    return {'outcome': 'inconclusive', 'reason': 'missing', "
            b"'evidence_refs': [], 'claim_level': 'reply'}\n"
        ),
        "inputs.json": b'{"runtime_contract":{},"inventory":{}}\n',
    }
    records = [
        {
            "path": name,
            "media_type": "text/x-python"
            if name.endswith(".py")
            else "application/json",
            "length": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        }
        for name, content in sorted(members.items())
    ]
    manifest = {
        "schema_version": "artifact-package-v1",
        "package_id": "pkg-1",
        "scenario_id": "scenario-1",
        "input_kind": "reference-task",
        "source_digests": {"input": "a" * 64},
        "members": records,
        "authoring": authoring or {"attempts": 2, "max_retries": 0},
        "detector_interface": "evaluate(evidence: dict) -> dict",
        "runtime_capabilities": {},
        "creation_model": {"model": "configured-private-authoring"},
    }
    canonical = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["manifest_digest"] = hashlib.sha256(canonical).hexdigest()
    root.mkdir()
    for name, content in members.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    if tamper:
        (root / "detector.py").write_bytes(b"changed")
    return root


def test_producer_vendored_artifact_contract_matches_consumer_authority() -> None:
    validate_artifact_package_contract()
    producer = PRODUCER_ROOT / "contracts" / "artifact-package"
    consumer = CONSUMER_ROOT / "contracts" / "artifact-package"
    producer_files = sorted(
        path.relative_to(producer) for path in producer.rglob("*") if path.is_file()
    )
    consumer_files = sorted(
        path.relative_to(consumer) for path in consumer.rglob("*") if path.is_file()
    )
    assert producer_files == consumer_files
    assert [
        hashlib.sha256((producer / path).read_bytes()).hexdigest()
        for path in producer_files
    ] == [
        hashlib.sha256((consumer / path).read_bytes()).hexdigest()
        for path in consumer_files
    ]


def test_consumer_vendored_handoff_contract_matches_producer_authority() -> None:
    producer = PRODUCER_ROOT / "data" / "contracts" / "scenario-handoff"
    consumer = CONSUMER_ROOT / "contracts" / "scenario-handoff"
    producer_files = sorted(
        path.relative_to(producer) for path in producer.rglob("*") if path.is_file()
    )
    consumer_files = sorted(
        path.relative_to(consumer) for path in consumer.rglob("*") if path.is_file()
    )
    assert producer_files == consumer_files
    assert [
        hashlib.sha256((producer / path).read_bytes()).hexdigest()
        for path in producer_files
    ] == [
        hashlib.sha256((consumer / path).read_bytes()).hexdigest()
        for path in consumer_files
    ]


def test_loader_verifies_all_members_before_exposing_content(tmp_path: Path) -> None:
    package = load_artifact_package(_write_package(tmp_path / "package"))
    assert package.manifest.package_id == "pkg-1"
    assert package.members["detector.py"].startswith(b"def evaluate")

    with pytest.raises(ArtifactPackageError, match="digest mismatch"):
        load_artifact_package(_write_package(tmp_path / "tampered", tamper=True))


def test_exact_g07_package_loads_with_closed_provider_usage_metadata() -> None:
    package = load_artifact_package(G07_PACKAGE)

    assert package.manifest.manifest_digest == (
        "f46b2a1568acdf37a0f4736d715c69d065c51a33bb2d38ba2532ba6cdec3d1b2"
    )
    assert len(package.members) == 21
    assert package.manifest.raw["source_digests"] == {
        "benchmark": "9db76badc3690bfd1e5e5c480ae206195fdd47703e0dfc211380540c35d4f0bd",
        "input": "752adc33d01678664191d0ed6a3fc8d125c87c90b873a4a1e232617166a49b92",
    }


def test_closed_usage_policy_accepts_provider_usage_shapes(tmp_path: Path) -> None:
    allowed = [
        {
            "interface": "artifact-authoring-v1",
            "usage": [
                {
                    "availability": "available",
                    "value": {
                        "prompt_tokens": 4,
                        "completion_tokens": 3,
                        "total_tokens": 7,
                        "prompt_tokens_details": {
                            "cached_tokens": 1,
                            "nested": {"audio_tokens": 0},
                        },
                        "completion_tokens_details": {"reasoning_tokens": 2},
                    },
                }
            ],
        },
        {
            "usage": {
                "availability": "available",
                "value": {
                    "prompt_tokens": 1,
                    "completion_tokens": 2,
                    "total_tokens": 3,
                    "prompt_tokens_details": None,
                    "completion_tokens_details": {},
                },
            }
        },
        {
            "usage": [
                {
                    "availability": "unavailable",
                    "reason": "provider did not report usage",
                }
            ]
        },
        {
            "usage": {
                "availability": "unavailable",
                "reason": "not reported",
            }
        },
        {"interface": "artifact-authoring-v1", "max_retries": 0},
    ]

    for index, metadata in enumerate(allowed):
        package = load_artifact_package(
            _write_package(tmp_path / f"allowed-{index}", authoring=metadata)
        )
        assert package.manifest.authoring == metadata
        assert secret_metadata_paths({"authoring": metadata}) == []


@pytest.mark.parametrize(
    "metadata",
    [
        {"usage": [{"availability": "available", "value": {"prompt_tokens": "4"}}]},
        {"usage": [{"availability": "available", "value": {"prompt_tokens": -1}}]},
        {"usage": [{"availability": "available", "value": {"prompt_tokens": True}}]},
        {
            "usage": [
                {
                    "availability": "available",
                    "value": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                        "total_tokens_extra": 2,
                    },
                }
            ]
        },
        {
            "usage": [
                {
                    "availability": "available",
                    "value": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                        "prompt_tokens_details": {"api_key": 1},
                    },
                }
            ]
        },
        {
            "usage": [
                {
                    "availability": "available",
                    "value": {
                        "prompt_tokens": 1,
                        "completion_tokens": 1,
                        "total_tokens": 2,
                        "prompt_tokens_details": {"api_tokens": 1},
                    },
                }
            ]
        },
        {"usage": {}},
        {"usage": "not-a-list"},
        {"usage": [{"availability": "available", "value": 7}]},
        {"usage": [{"availability": "available", "value": {}}]},
        {"usage": [{"availability": "unavailable", "reason": ""}]},
        {"auth_token": "redacted"},
        {"auth": "redacted"},
        {"session_token": "redacted"},
        {"session": "redacted"},
        {"access_token": "redacted"},
        {"access": "redacted"},
        {"bearer_token": "redacted"},
        {"bearer": "redacted"},
        {"api_key": "redacted"},
        {"apikey": "redacted"},
        {"credential": "redacted"},
        {"password": "redacted"},
        {"authorization_header": "redacted"},
        {"endpoint": "redacted"},
        {"base_url": "redacted"},
        {"base-url": "redacted"},
        {"baseurl": "redacted"},
    ],
)
def test_closed_usage_policy_rejects_secret_or_malformed_shapes(
    tmp_path: Path, metadata: dict
) -> None:
    assert secret_metadata_paths({"authoring": metadata})
    with pytest.raises(ArtifactPackageError):
        load_artifact_package(_write_package(tmp_path / "rejected", authoring=metadata))


def test_closed_usage_policy_rejects_non_string_metadata_keys() -> None:
    assert secret_metadata_paths({"authoring": {"usage": {1: 1}}})


def test_frozen_runtime_sources_do_not_import_consumer_authoring() -> None:
    runtime_files = [
        "artifact_package_runtime.py",
        "runtime_bindings.py",
        "request_ledger.py",
        "evidence_adapter.py",
        "frozen_judge.py",
        "safe_lifecycle.py",
        "frozen_runtime.py",
        "detector_runtime_adapter.py",
        "garak_dispatch.py",
    ]
    forbidden = re.compile(r"asago_artifact_generator|(?:from|import)\s+\S*authoring")
    for name in runtime_files:
        source = (PRODUCER_ROOT / "scripts" / "qualification" / name).read_text()
        assert not forbidden.search(source), name
