"""Authoring-free loader for the consumer-owned artifact-package contract.

This module intentionally has no dependency on the consumer Python package.
The producer receives contract bytes and package bytes, verifies both, and
then exposes only the immutable members to downstream execution.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

PACKAGE_SCHEMA_VERSION = "artifact-package-v1"
DETECTOR_INTERFACE_VERSION = "evaluate(evidence: dict) -> dict"
CONTRACT_ROOT = Path(__file__).resolve().parents[2] / "contracts" / "artifact-package"
ALLOWED_MEMBER_NAMES = {
    "plan.json",
    "stimulus.json",
    "setup.json",
    "bindings.json",
    "prerequisites.json",
    "detector.py",
    "checks.json",
    "inputs.json",
    "source-hashes.json",
    "observations.json",
    "judge.json",
    "explanation.json",
    "examples.json",
}
INPUT_KINDS = frozenset(
    {"scenario-handoff-v1", "native-semantic-yaml", "reference-task"}
)


class ArtifactPackageError(ValueError):
    """Raised when a package or contract is unavailable or unverifiable."""


@dataclass(frozen=True)
class ArtifactPackageManifest:
    """The canonical package manifest without consumer model types."""

    raw: dict[str, Any]

    @property
    def package_id(self) -> str:
        return self.raw["package_id"]

    @property
    def scenario_id(self) -> str:
        return self.raw["scenario_id"]

    @property
    def manifest_digest(self) -> str:
        return self.raw["manifest_digest"]

    @property
    def runtime_capabilities(self) -> dict[str, Any]:
        return self.raw["runtime_capabilities"]

    @property
    def authoring(self) -> dict[str, Any]:
        return self.raw["authoring"]


@dataclass(frozen=True)
class ArtifactPackage:
    """Verified immutable package bytes."""

    root: Path
    manifest: ArtifactPackageManifest
    members: dict[str, bytes]

    @property
    def digest(self) -> str:
        return self.manifest.manifest_digest

    @property
    def detector_digest(self) -> str:
        try:
            return _sha256(self.members["detector.py"])
        except KeyError as exc:
            raise ArtifactPackageError("package is missing detector.py") from exc

    def json_member(self, name: str, *, default: Any = None) -> Any:
        """Decode one verified JSON member, preserving a useful missing default."""

        content = self.members.get(name)
        if content is None:
            return default
        try:
            return json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ArtifactPackageError(f"invalid JSON package member: {name}") from exc


def validate_artifact_package_contract() -> None:
    """Verify the vendored contract lock and every normative contract member."""

    lock_path = CONTRACT_ROOT / "CONTRACT.lock"
    try:
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ArtifactPackageError(
            f"cannot read artifact package contract lock: {exc}"
        ) from exc
    if (
        lock.get("authority") != "asago-artifact-generator"
        or lock.get("contract") != "artifact-package"
        or lock.get("digest_domain") != PACKAGE_SCHEMA_VERSION
    ):
        raise ArtifactPackageError("artifact package contract authority mismatch")
    files = lock.get("files")
    if not isinstance(files, dict) or not files:
        raise ArtifactPackageError("artifact package contract lock has no files")
    for relative, expected in files.items():
        path = _contained_path(CONTRACT_ROOT, relative)
        if not path.is_file() or _sha256(path.read_bytes()) != expected:
            raise ArtifactPackageError(
                f"artifact package contract digest mismatch: {relative}"
            )


def load_artifact_package(path: str | Path) -> ArtifactPackage:
    """Verify the manifest and every member before returning package content."""

    validate_artifact_package_contract()
    root = Path(path).expanduser().resolve()
    if not root.is_dir() or root.is_symlink():
        raise ArtifactPackageError(f"package directory is unavailable: {path}")
    try:
        manifest_data = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArtifactPackageError(f"invalid package manifest: {exc}") from exc
    _validate_manifest(manifest_data)
    expected: dict[str, bytes] = {}
    records = manifest_data["members"]
    for record in records:
        if not isinstance(record, dict):
            raise ArtifactPackageError("package member record must be an object")
        relative = _validate_member_path(record.get("path"))
        if relative in expected:
            raise ArtifactPackageError(f"duplicate package member: {relative}")
        member = _contained_path(root, relative)
        if not member.is_file() or member.is_symlink():
            raise ArtifactPackageError(f"missing package member: {relative}")
        content = member.read_bytes()
        if record.get("sha256") != _sha256(content):
            raise ArtifactPackageError(
                f"digest mismatch for package member: {relative}"
            )
        if record.get("length") != len(content):
            raise ArtifactPackageError(
                f"length mismatch for package member: {relative}"
            )
        if record.get("media_type") != _media_type(relative):
            raise ArtifactPackageError(
                f"media type mismatch for package member: {relative}"
            )
        expected[relative] = content

    actual = {
        item.relative_to(root).as_posix()
        for item in root.rglob("*")
        if item.is_file() and item.name != "manifest.json"
    }
    if actual != set(expected):
        raise ArtifactPackageError("package member set does not match manifest")
    if any(item.is_symlink() for item in root.rglob("*")):
        raise ArtifactPackageError("symlink is not allowed in package")
    return ArtifactPackage(root, ArtifactPackageManifest(manifest_data), expected)


def _validate_manifest(value: Any) -> None:
    if not isinstance(value, dict):
        raise ArtifactPackageError("package manifest must be an object")
    required = {
        "schema_version",
        "package_id",
        "scenario_id",
        "input_kind",
        "source_digests",
        "members",
        "authoring",
        "detector_interface",
        "runtime_capabilities",
        "creation_model",
        "manifest_digest",
    }
    unknown = set(value) - required - {"reference_task"}
    if unknown or required - set(value):
        raise ArtifactPackageError(
            f"package manifest fields invalid (missing={sorted(required - set(value))}, "
            f"unknown={sorted(unknown)})"
        )
    if value["schema_version"] != PACKAGE_SCHEMA_VERSION:
        raise ArtifactPackageError("unknown artifact package schema version")
    if value["detector_interface"] != DETECTOR_INTERFACE_VERSION:
        raise ArtifactPackageError("unknown detector interface version")
    if value["input_kind"] not in INPUT_KINDS:
        raise ArtifactPackageError("unsupported artifact package input kind")
    if not all(
        isinstance(value[name], str) and value[name]
        for name in ("package_id", "scenario_id")
    ):
        raise ArtifactPackageError("package identity fields must be nonblank strings")
    source_digests = value["source_digests"]
    if (
        not isinstance(source_digests, dict)
        or not source_digests
        or any(
            not isinstance(key, str)
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(char not in "0123456789abcdef" for char in digest)
            for key, digest in source_digests.items()
        )
    ):
        raise ArtifactPackageError(
            "manifest source_digests must contain SHA-256 strings"
        )
    expected_digest = _manifest_digest(value)
    if value["manifest_digest"] != expected_digest:
        raise ArtifactPackageError("manifest digest mismatch")
    if not isinstance(value["members"], list) or not value["members"]:
        raise ArtifactPackageError("manifest members must be a non-empty list")
    for name in ("authoring", "runtime_capabilities", "creation_model"):
        if not isinstance(value[name], dict):
            raise ArtifactPackageError(f"manifest {name} must be an object")
        if _contains_secret_key(value[name]):
            raise ArtifactPackageError(
                f"manifest {name} contains secret-bearing metadata"
            )


def _validate_member_path(value: Any) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise ArtifactPackageError(f"invalid package member path: {value!r}")
    path = PurePosixPath(value)
    if path.is_absolute() or any(part in {"", ".", ".."} for part in path.parts):
        raise ArtifactPackageError(f"package member path escapes package: {value!r}")
    normalized = path.as_posix()
    if normalized != value:
        raise ArtifactPackageError(f"non-canonical package member path: {value!r}")
    if normalized not in ALLOWED_MEMBER_NAMES and not normalized.startswith(
        "authoring/"
    ):
        raise ArtifactPackageError(f"unexpected package member path: {normalized}")
    return normalized


def _contained_path(root: Path, relative: str) -> Path:
    candidate = (root / relative).resolve()
    if candidate != root.resolve() and root.resolve() not in candidate.parents:
        raise ArtifactPackageError(f"path escapes package: {relative}")
    return candidate


def _manifest_digest(value: dict[str, Any]) -> str:
    unsigned = dict(value)
    unsigned.pop("manifest_digest", None)
    return _sha256(_canonical_json(unsigned))


def _media_type(path: str) -> str:
    if path.endswith(".py"):
        return "text/x-python"
    if path.endswith(".json"):
        return "application/json"
    if path.endswith((".yaml", ".yml")):
        return "application/yaml"
    return "application/octet-stream"


def _contains_secret_key(value: Any) -> bool:
    terms = (
        "api_key",
        "apikey",
        "authorization",
        "credential",
        "endpoint",
        "password",
        "secret",
        "token",
    )
    if isinstance(value, dict):
        return any(
            any(term in str(key).lower() for term in terms)
            or _contains_secret_key(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret_key(item) for item in value)
    return False


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


load_package = load_artifact_package
read_artifact_package = load_artifact_package

__all__ = [
    "ALLOWED_MEMBER_NAMES",
    "ArtifactPackage",
    "ArtifactPackageError",
    "ArtifactPackageManifest",
    "load_artifact_package",
    "load_package",
    "read_artifact_package",
    "validate_artifact_package_contract",
]
