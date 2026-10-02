"""Atomic publication of the verified execution target profile."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

from asago_scenario_generator.stpa.models.execution_classification import (
    ExecutionTargetProfile,
)

EXECUTION_TARGET_PROFILE_NAME = "execution-target-profile.json"


class TargetProfilePublicationError(ValueError):
    """Raised when the target profile cannot be published."""


def publish_execution_target_profile(
    destination: Path,
    profile: ExecutionTargetProfile,
) -> Path:
    """Publish one verified target profile as canonical JSON in *destination*.

    The run publishes the profile before any scenario work, and refuses to
    produce scenarios whose classifications would point at unavailable
    profile bytes.
    """
    if not isinstance(destination, Path):
        raise TargetProfilePublicationError("destination must be a pathlib.Path")
    if not isinstance(profile, ExecutionTargetProfile):
        raise TargetProfilePublicationError("profile must be an ExecutionTargetProfile")
    profile.assert_integrity()
    profile_path = destination.resolve() / EXECUTION_TARGET_PROFILE_NAME
    _atomic_write(profile_path, profile.canonical_json_bytes())
    return profile_path


def _atomic_write(path: Path, content: bytes) -> None:
    """Atomically replace one final path with durable bytes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temporary_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "EXECUTION_TARGET_PROFILE_NAME",
    "TargetProfilePublicationError",
    "publish_execution_target_profile",
]
