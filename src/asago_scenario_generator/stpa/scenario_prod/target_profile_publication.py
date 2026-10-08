"""Atomic publication of the verified execution target profile."""

from __future__ import annotations

from pathlib import Path

from asago_scenario_generator.manifest import atomic_write_bytes
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
    atomic_write_bytes(profile_path, profile.canonical_json_bytes())
    return profile_path


__all__ = [
    "EXECUTION_TARGET_PROFILE_NAME",
    "TargetProfilePublicationError",
    "publish_execution_target_profile",
]
