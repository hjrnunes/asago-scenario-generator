"""Completed-manifest inventory and scorecard validation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from asago_scenario_generator.manifest_errors import ManifestIntegrityError
from asago_scenario_generator.manifest_funnel import validate_attempt_equations
from asago_scenario_generator.manifest_models import (
    MANIFEST_V3,
    ArtifactEntry,
    ArtifactRole,
    AttemptDisposition,
    RunManifest,
    SINGLETON_ROLES,
    required_singleton_roles,
)
from asago_scenario_generator.manifest_resolver import ManifestInventoryResolver


def validate_completed_inventory(
    manifest: RunManifest,
    *,
    eval_enabled: bool,
    run_dir: Path | None = None,
) -> None:
    """Globally validate role cardinality, singleton requirements, funnel
    equations, attempt equations, and full inventory before atomically
    committing ``completed``.

    When *run_dir* is provided, also runs the full strict
    :class:`ManifestInventoryResolver` (including orphan checks) against
    the exact final manifest and run directory.

    Raises:
        ManifestIntegrityError: If any invariant is violated.
    """
    resolver = _strict_resolver_for_completed(manifest, run_dir)
    _check_completed_singleton_roles(manifest, eval_enabled)
    _check_completed_duplicate_singletons(manifest)
    _check_completed_scenario_pairing(manifest)
    _check_completed_attempt_equations(manifest)
    _check_completed_inventory_identity(manifest)
    if eval_enabled:
        _check_completed_scorecard_counts(manifest, resolver)
    if resolver is not None and manifest.manifest_version == MANIFEST_V3:
        validate_v3_resolver_policy(resolver)


def _strict_resolver_for_completed(
    manifest: RunManifest,
    run_dir: Path | None,
) -> ManifestInventoryResolver | None:
    """Run the full strict resolver validation when a run directory exists."""
    if run_dir is None:
        return None
    return ManifestInventoryResolver(run_dir, manifest, check_orphans=True)


def _check_completed_singleton_roles(
    manifest: RunManifest,
    eval_enabled: bool,
) -> None:
    """Reject a completed inventory missing any required singleton role."""
    required = required_singleton_roles(
        eval_enabled=eval_enabled, manifest_version=manifest.manifest_version
    )
    present_roles: set[ArtifactRole] = set()
    for entry in manifest.inventory:
        try:
            present_roles.add(entry.role)
        except (ValueError, TypeError):
            raise ManifestIntegrityError(
                f"Invalid artifact role in inventory: {entry.role!r}"
            ) from None
    missing = required - present_roles
    if missing:
        raise ManifestIntegrityError(
            f"Missing required singleton roles for completed status: "
            f"{sorted(r.value for r in missing)}"
        )


def _check_completed_duplicate_singletons(manifest: RunManifest) -> None:
    """Reject duplicate singleton roles in the completed inventory."""
    role_counts: dict[ArtifactRole, int] = {}
    for entry in manifest.inventory:
        try:
            role = entry.role
        except (ValueError, TypeError):
            raise ManifestIntegrityError(
                f"Invalid artifact role: {entry.role!r}"
            ) from None
        if role in SINGLETON_ROLES:
            role_counts[role] = role_counts.get(role, 0) + 1
            if role_counts[role] > 1:
                raise ManifestIntegrityError(
                    f"Duplicate singleton role {role.value}: "
                    f"{role_counts[role]} entries"
                )


def _unique_scenario_ids(
    manifest: RunManifest,
    role: ArtifactRole,
    label: str,
) -> set[str]:
    """Return scenario IDs for one role, rejecting duplicates within it."""
    ids: set[str] = set()
    for entry in manifest.inventory:
        if entry.role != role:
            continue
        if entry.scenario_id:
            if entry.scenario_id in ids:
                raise ManifestIntegrityError(
                    f"Duplicate scenario_id in {label} role: {entry.scenario_id}"
                )
            ids.add(entry.scenario_id)
    return ids


def _check_completed_scenario_pairing(manifest: RunManifest) -> None:
    """Require scenario YAML and feature ID sets to be identical (paired)."""
    yaml_scenario_ids = _unique_scenario_ids(
        manifest, ArtifactRole.SCENARIO_YAML, "YAML"
    )
    feature_scenario_ids = _unique_scenario_ids(
        manifest, ArtifactRole.SCENARIO_FEATURE, "feature"
    )
    if yaml_scenario_ids != feature_scenario_ids:
        yaml_only = yaml_scenario_ids - feature_scenario_ids
        feat_only = feature_scenario_ids - yaml_scenario_ids
        parts: list[str] = []
        if yaml_only:
            parts.append(f"YAML without feature: {sorted(yaml_only)}")
        if feat_only:
            parts.append(f"feature without YAML: {sorted(feat_only)}")
        raise ManifestIntegrityError(
            f"Scenario YAML/feature ID set mismatch: {'; '.join(parts)}"
        )


def _check_completed_attempt_equations(manifest: RunManifest) -> None:
    """Reconcile legacy attempt equations; manifest-v3 inventory is the
    sole attempt authority."""
    if manifest.manifest_version != MANIFEST_V3:
        validate_attempt_equations(manifest)


def _admitted_attempt_keys(manifest: RunManifest) -> set[tuple[str, str]]:
    """Return admitted attempt (scenario_id, candidate_id) keys."""
    return {
        (a.scenario_id, a.candidate_id)
        for a in manifest.attempts
        if a.disposition == AttemptDisposition.ADMITTED
    }


def _quarantined_attempt_keys(manifest: RunManifest) -> set[tuple[str, str]]:
    """Return quarantined attempt (scenario_id, candidate_id) keys."""
    return {
        (a.scenario_id, a.candidate_id)
        for a in manifest.attempts
        if a.disposition == AttemptDisposition.QUARANTINED
    }


def _yaml_inventory_keys(manifest: RunManifest) -> set[tuple[str, str]]:
    """Return YAML inventory (scenario_id, candidate_id) keys."""
    return {
        (entry.scenario_id, entry.candidate_id)
        for entry in manifest.inventory
        if entry.role == ArtifactRole.SCENARIO_YAML
        and entry.scenario_id
        and entry.candidate_id
    }


def _check_completed_inventory_identity(manifest: RunManifest) -> None:
    """Reconcile admitted/quarantined inventory identities with attempts."""
    if manifest.manifest_version == MANIFEST_V3:
        return
    admitted_attempt_keys = _admitted_attempt_keys(manifest)
    quarantined_attempt_keys = _quarantined_attempt_keys(manifest)
    yaml_inventory_keys = _yaml_inventory_keys(manifest)
    inventory_non_quarantined_keys = yaml_inventory_keys - quarantined_attempt_keys
    if inventory_non_quarantined_keys != admitted_attempt_keys:
        raise ManifestIntegrityError(
            f"Admitted scenario identity mismatch: "
            f"inventory(non-quarantined)={sorted(inventory_non_quarantined_keys)}, "
            f"attempts(admitted)={sorted(admitted_attempt_keys)}"
        )
    quarantined_in_inventory = yaml_inventory_keys & quarantined_attempt_keys
    if quarantined_in_inventory != quarantined_attempt_keys:
        raise ManifestIntegrityError(
            f"Quarantined scenario identity mismatch: "
            f"inventory(quarantined)={sorted(quarantined_in_inventory)}, "
            f"attempts(quarantined)={sorted(quarantined_attempt_keys)}"
        )


def _scenario_role_counts(manifest: RunManifest) -> tuple[int, int]:
    """Return YAML and feature role counts from the inventory."""
    yaml_count = sum(
        1 for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_YAML
    )
    feature_count = sum(
        1 for e in manifest.inventory if e.role == ArtifactRole.SCENARIO_FEATURE
    )
    return yaml_count, feature_count


def _v3_scorecard_counts(
    sc_data: dict,
    manifest: RunManifest,
) -> tuple[Any, Any]:
    """Return strict v1 scorecard counts, validating identity and
    qualification."""
    from asago_scenario_generator.eval.scorecard import ScorecardV1

    try:
        scorecard = ScorecardV1.model_validate(sc_data)
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Scorecard violates strict v1 schema: {exc}"
        ) from exc
    if scorecard.run_id != manifest.run_id:
        raise ManifestIntegrityError(
            f"Scorecard run_id={scorecard.run_id!r} does not match "
            f"manifest run_id={manifest.run_id!r}"
        )
    if (
        manifest.status.requires_complete_inventory
        and scorecard.qualification.status.value != "pass"
    ):
        raise ManifestIntegrityError(
            "completed manifest requires passing scorecard qualification"
        )
    return scorecard.scenario_count, scorecard.feature_file_count


def _v2_scorecard_counts(sc_data: dict) -> tuple[Any, Any]:
    """Return legacy v2 scorecard counts from the evaluation section."""
    eval_data = sc_data.get("evaluation")
    if not isinstance(eval_data, dict):
        raise ManifestIntegrityError("Scorecard 'evaluation' section is not a dict")
    return eval_data.get("scenario_count"), eval_data.get("feature_file_count")


def _check_scorecard_count_equality(
    sc_scenario_count: Any,
    sc_feature_count: Any,
    yaml_count: int,
    feature_count: int,
) -> None:
    """Require scorecard counts to match the unique typed inventory."""
    if sc_scenario_count is None:
        raise ManifestIntegrityError("Scorecard missing scenario_count")
    if sc_feature_count is None:
        raise ManifestIntegrityError("Scorecard missing feature_file_count")
    if sc_scenario_count != yaml_count:
        raise ManifestIntegrityError(
            f"Scorecard scenario_count={sc_scenario_count} "
            f"!= inventory YAML count={yaml_count}"
        )
    if sc_feature_count != feature_count:
        raise ManifestIntegrityError(
            f"Scorecard feature_file_count={sc_feature_count} "
            f"!= inventory feature count={feature_count}"
        )


def _check_completed_scorecard_entry(
    manifest: RunManifest,
    resolver: ManifestInventoryResolver,
    sc_entry: ArtifactEntry,
    yaml_count: int,
    feature_count: int,
) -> None:
    """Validate one scorecard entry against the manifest and inventory."""
    try:
        sc_data = resolver.read_yaml(sc_entry)
        if not isinstance(sc_data, dict):
            raise ManifestIntegrityError("Scorecard root is not a dict")
        if manifest.manifest_version == MANIFEST_V3:
            sc_scenario_count, sc_feature_count = _v3_scorecard_counts(
                sc_data, manifest
            )
        else:
            sc_scenario_count, sc_feature_count = _v2_scorecard_counts(sc_data)
        _check_scorecard_count_equality(
            sc_scenario_count, sc_feature_count, yaml_count, feature_count
        )
    except ManifestIntegrityError:
        raise
    except Exception as exc:
        raise ManifestIntegrityError(
            f"Failed to read scorecard for count validation: {exc}"
        ) from exc


def _scorecard_entry_verifiable(
    sc_entry: ArtifactEntry | None,
    resolver: ManifestInventoryResolver | None,
) -> bool:
    """True when a scorecard entry exists and a strict resolver is
    available."""
    return sc_entry is not None and resolver is not None


def _check_completed_scorecard_counts(
    manifest: RunManifest,
    resolver: ManifestInventoryResolver | None,
) -> None:
    """Require scorecard counts to validate against the unique typed
    inventory when eval is enabled and a resolver is available."""
    yaml_count, feature_count = _scenario_role_counts(manifest)
    if yaml_count != feature_count:
        raise ManifestIntegrityError(
            f"Scenario YAML/feature count mismatch: "
            f"yaml={yaml_count}, feature={feature_count}"
        )
    sc_entry = next(
        (e for e in manifest.inventory if e.role == ArtifactRole.EVAL_SCORECARD),
        None,
    )
    if _scorecard_entry_verifiable(sc_entry, resolver):
        _check_completed_scorecard_entry(
            manifest, resolver, sc_entry, yaml_count, feature_count
        )


# --------------------------------------------------------------------------- #
# v3 resolver-policy validation (post-resolver, depends on pipeline.persistence)
# --------------------------------------------------------------------------- #


def validate_v3_resolver_policy(resolver: ManifestInventoryResolver) -> None:
    """Run v3-only semantic-generation comparison against the finalization
    inventory.

    This is a separate post-resolver step so that the IO-near resolver
    class does not depend on ``pipeline.persistence`` for higher-level
    lifecycle authority checks.  Scorecard binding and v3 inventory
    integrity are validated during resolver construction.
    """
    from asago_scenario_generator.pipeline.persistence import (
        FinalizationInventoryV1,
        build_semantic_generation_summary,
    )

    if resolver.manifest.semantic_generation:
        finalization_entry = resolver.entry_by_role(ArtifactRole.FINALIZATION_INVENTORY)
        assert finalization_entry is not None
        authoritative_inventory = FinalizationInventoryV1.model_validate(
            resolver.read_json(finalization_entry)
        )
        expected_semantic_generation = build_semantic_generation_summary(
            authoritative_inventory
        )
        if resolver.manifest.semantic_generation != expected_semantic_generation:
            raise ManifestIntegrityError(
                "semantic_generation does not match finalization inventory"
            )
