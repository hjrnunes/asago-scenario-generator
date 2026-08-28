"""Resume orchestration helpers for the manifest-v3 pipeline runner.

Decomposed from ``pipeline.runner`` so the resume entry point stays a thin
public facade over self-contained, individually mutation-scoped helpers.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

from asago_scenario_generator.llm.client import LLMClient
from asago_scenario_generator.manifest import (
    MANIFEST_V3 as MANIFEST_VERSION,
)
from asago_scenario_generator.manifest import (
    ArtifactRole,
    ManifestIntegrityError,
    RunStatus,
    compute_bytes_sha256,
    compute_config_digest,
    load_manifest,
    validate_generation_run_id,
)
from asago_scenario_generator.models import ThreatSurface
from asago_scenario_generator.models.capability_profile import CapabilityProfile
from asago_scenario_generator.pipeline.coverage_planning import (
    GenerationMode,
    StageLedger,
)
from asago_scenario_generator.prompts import hash_prompt_templates

# runner-owned helpers are imported lazily inside the functions that use
# them: pipeline.runner re-exports this module at its bottom, so a
# module-level import here would make the import order of runner vs
# runner_resume order-dependent.

logger = logging.getLogger(__name__)


def _resolve_resume_directory(run_dir: Path) -> Path:
    """Resolve the run directory, requiring a real existing directory."""
    supplied = Path(run_dir).resolve()
    if not supplied.is_dir():
        raise ManifestIntegrityError("resume requires an existing run directory")
    return supplied


def _load_resumable_manifest(supplied: Path) -> Any:
    """Load the manifest and require a v3 STARTED status."""
    manifest = load_manifest(supplied, requested_version=MANIFEST_VERSION)
    if manifest.status is not RunStatus.STARTED:
        raise ManifestIntegrityError("only a v3 STARTED run can be resumed")
    return manifest


def _validate_resume_manifest_identity(supplied: Path, manifest: Any) -> None:
    """Require canonical run_id, matching directory name, and provenance."""
    try:
        validate_generation_run_id(manifest.run_id)
    except ValueError as exc:
        raise ManifestIntegrityError("resume manifest has noncanonical run_id") from exc
    if supplied.name != manifest.run_id:
        raise ManifestIntegrityError("manifest run_id does not match run directory")
    if manifest.provenance is None or manifest.provenance.run_id != manifest.run_id:
        raise ManifestIntegrityError("manifest provenance run_id mismatch")


def _load_resume_support_artifacts(
    supplied: Path,
    manifest: Any,
    support: Any,
) -> tuple[str, CapabilityProfile, ThreatSurface, Any]:
    """Read and validate the immutable resume support inventory."""
    from asago_scenario_generator.pipeline.persistence import (
        read_finalization_inventory,
        read_planning_checkpoint_bytes,
        recover_finalization_journal,
    )

    use_entry = support.entry_by_role(ArtifactRole.USE_CASE)
    profile_entry = support.entry_by_role(ArtifactRole.CAPABILITY_PROFILE)
    threat_entry = support.entry_by_role(ArtifactRole.THREAT_SURFACE)
    planning_entry = support.entry_by_role(ArtifactRole.PLANNING_CHECKPOINT)
    if not all((use_entry, profile_entry, threat_entry, planning_entry)):
        raise ManifestIntegrityError("started manifest support inventory is incomplete")
    use_case = support.read_text(use_entry)
    profile = CapabilityProfile.model_validate(support.read_yaml(profile_entry))
    threat_surface = ThreatSurface.model_validate(support.read_yaml(threat_entry))
    planning = read_planning_checkpoint_bytes(support.read_bytes(planning_entry))
    recover_finalization_journal(supplied, expected_run_id=manifest.run_id)
    inventory = read_finalization_inventory(supplied)
    if inventory.run_id != manifest.run_id:
        raise ManifestIntegrityError("finalization inventory run_id mismatch")
    return use_case, profile, threat_surface, planning


def _resume_command_options(
    provenance: Any,
) -> tuple[dict[str, Any], bool]:
    """Extract and validate the persisted command options."""
    options = provenance.command.options
    required_paths = {
        "risk_extraction_path",
        "sssom_path",
        "cross_taxonomy_path",
        "threats_path",
    }
    if not required_paths.issubset(options):
        raise ManifestIntegrityError("resume command provenance is incomplete")
    persisted_eval = options.get("eval")
    if not isinstance(persisted_eval, bool):
        raise ManifestIntegrityError("resume eval provenance must be boolean")
    _validate_resume_presentation_fallback(
        options.get("presentation_fallback", "allow")
    )
    _validate_resume_generation_mode(
        options.get("generation_mode", GenerationMode.COVERAGE.value)
    )
    return options, persisted_eval


def _validate_resume_presentation_fallback(value: Any) -> None:
    """Require a valid persisted presentation fallback mode."""
    if value not in {"allow", "forbid"}:
        raise ManifestIntegrityError(
            "resume presentation fallback provenance is invalid"
        )


def _validate_resume_generation_mode(value: Any) -> None:
    """Require a valid persisted generation mode."""
    try:
        GenerationMode(value)
    except ValueError as exc:
        raise ManifestIntegrityError(
            "resume generation mode provenance is invalid"
        ) from exc


def _validate_resume_provenance_inputs(manifest: Any, use_case: str) -> None:
    """Require config, prompt-template, and use-case provenance stability."""
    provenance = manifest.provenance
    if provenance.config_digest != compute_config_digest(provenance.command.options):
        raise ManifestIntegrityError("resume configuration provenance drift")
    if provenance.prompt_template_hashes != hash_prompt_templates():
        raise ManifestIntegrityError("resume prompt template provenance drift")
    if provenance.input_hashes.use_case_hash != compute_bytes_sha256(
        use_case.encode("utf-8")
    ):
        raise ManifestIntegrityError("resume use-case provenance drift")


def _validate_resume_eval_override(eval: bool | None, persisted_eval: bool) -> None:
    """Reject eval overrides that contradict the persisted run option."""
    if eval is not None and eval is not persisted_eval:
        raise ManifestIntegrityError("resume eval override conflicts with provenance")


def _resume_input_paths(options: dict[str, Any]) -> list[Path | None]:
    """Return the six canonical input paths from persisted options."""
    return [
        Path(options["risk_extraction_path"]),
        Path(options["sssom_path"]),
        Path(options["cross_taxonomy_path"]),
        Path(options["threats_path"]),
        Path(options["profile_path"]) if options.get("profile_path") else None,
        (
            Path(options["qualification_facts_path"])
            if options.get("qualification_facts_path")
            else None
        ),
    ]


def _validate_resume_input_hash_drift(
    current_hashes: Any, persisted_hashes: Any
) -> None:
    """Require every canonical input hash to match the persisted hashes."""
    for field in (
        "risk_extraction_hash",
        "sssom_hash",
        "cross_taxonomy_hash",
        "threats_hash",
        "source_profile_hash",
        "qualification_facts_hash",
        "attack_patterns_hash",
        "attack_patterns_sssom_hash",
        "attack_goals_taxonomy_hash",
        "threat_goal_affinity_hash",
        "attack_patterns_yaml_map",
        "attack_patterns_sssom_map",
    ):
        if getattr(current_hashes, field) != getattr(persisted_hashes, field):
            raise ManifestIntegrityError(f"resume input provenance drift: {field}")


def _validate_resume_facts_absent(planning: Any, persisted_hashes: Any) -> None:
    """Reject a missing facts path when any fact provenance claims exist."""
    if (
        planning.qualification_facts_source is not None
        or planning.qualification_facts_sha256 is not None
        or persisted_hashes.qualification_facts_hash is not None
    ):
        raise ManifestIntegrityError(
            "resume qualification facts provenance is inconsistent"
        )


def _parse_resume_facts(planning: Any, persisted_hashes: Any) -> tuple[Any, ...]:
    """Verify and parse persisted qualification facts when present."""
    source_bytes = planning.qualification_facts_source.encode("utf-8")
    if compute_bytes_sha256(source_bytes) != persisted_hashes.qualification_facts_hash:
        raise ManifestIntegrityError("resume qualification facts provenance drift")
    try:
        from asago_scenario_generator.pipeline.runner import (
            _parse_qualification_facts,
        )

        return _parse_qualification_facts(source_bytes).facts
    except ValueError as exc:
        raise ManifestIntegrityError(str(exc)) from exc


def _resume_qualification_facts(
    planning: Any,
    persisted_hashes: Any,
    options: dict[str, Any],
) -> tuple[Any, ...]:
    """Return parsed qualification facts consistent with persisted provenance."""
    facts_path = options.get("qualification_facts_path")
    if facts_path is None:
        _validate_resume_facts_absent(planning, persisted_hashes)
        return ()
    if planning.qualification_facts_source is None:
        raise ManifestIntegrityError(
            "resume planning checkpoint lacks qualification facts source"
        )
    return _parse_resume_facts(planning, persisted_hashes)


def _revalidate_resume_candidates(
    durable_plan: Any,
    taxonomy_resolver: Any,
    capability_snapshot: Any,
    trusted_catalog: list[dict[str, Any]],
) -> None:
    """Revalidate every durable plan choice against its qualified source."""
    from asago_scenario_generator.pipeline.coverage_planning import (
        revalidate_qualified_candidate,
    )

    try:
        for target in durable_plan.targets:
            for choice in target.ordered_choices:
                revalidate_qualified_candidate(
                    choice.model_dump(mode="json"),
                    taxonomy_resolver,
                    capability_snapshot,
                    trusted_catalog,
                )
    except Exception as exc:
        raise ManifestIntegrityError(
            f"resume durable candidate provenance drift: {exc}"
        ) from exc


def _setup_resume_logging(
    log_level: str,
    supplied: Path,
    structured: bool,
) -> None:
    """Configure run-local logging for the resumed run."""
    from asago_scenario_generator.log_config import setup_logging

    setup_logging(log_level=log_level, output_dir=supplied, structured=structured)


def _validate_resume_model_config(
    model: str | None,
    base_url: str | None,
    persisted_model: Any,
) -> None:
    """Require persisted model configuration and consistent overrides."""
    if persisted_model is None:
        raise ManifestIntegrityError(
            "resumable v3 run requires persisted model configuration"
        )
    _validate_resume_model_override(model, persisted_model)
    _validate_resume_endpoint_override(base_url, persisted_model)


def _validate_resume_model_override(model: str | None, persisted_model: Any) -> None:
    """Reject model overrides that contradict the persisted model."""
    if model is not None and model != persisted_model.model:
        raise ManifestIntegrityError("resume model override conflicts with provenance")


def _validate_resume_endpoint_override(
    base_url: str | None,
    persisted_model: Any,
) -> None:
    """Reject endpoint overrides that contradict the persisted model."""
    if base_url is not None and base_url != persisted_model.base_url:
        raise ManifestIntegrityError(
            "resume endpoint override conflicts with provenance"
        )


def _resolved_resume_base_url(base_url: str | None, persisted_model: Any) -> str | None:
    """Return the override base URL, or the persisted base URL."""
    return base_url or (persisted_model.base_url if persisted_model else None)


def _resolved_resume_model(model: str | None, persisted_model: Any) -> str | None:
    """Return the override model, or the persisted model."""
    return model or (persisted_model.model if persisted_model else None)


def _persisted_temperature(persisted_model: Any) -> float | None:
    """Return the persisted temperature, if any."""
    return persisted_model.temperature if persisted_model else None


def _persisted_max_completion_tokens(persisted_model: Any) -> int | None:
    """Return the persisted max completion tokens, if any."""
    return persisted_model.max_completion_tokens if persisted_model else None


def _resume_llm_client(
    base_url: str | None,
    api_key: str | None,
    model: str | None,
    persisted_model: Any,
) -> Any:
    """Build the resume LLM client from persisted model configuration."""
    return LLMClient(
        base_url=_resolved_resume_base_url(base_url, persisted_model),
        api_key=api_key,
        model=_resolved_resume_model(model, persisted_model),
        temperature=_persisted_temperature(persisted_model),
        max_completion_tokens=_persisted_max_completion_tokens(persisted_model),
    )


def persisted_presentation_fallback(options: dict[str, Any]) -> str:
    """Return the persisted presentation fallback mode."""
    return options.get("presentation_fallback", "allow")


def _resume_stage_ledger(planning: Any) -> Any:
    """Rebuild the stage ledger from persisted stage events."""
    from asago_scenario_generator.pipeline.coverage_planning import StageEvent

    return StageLedger(
        events=[
            StageEvent(**item.model_dump(mode="python"))
            for item in planning.stage_events
        ]
    )
