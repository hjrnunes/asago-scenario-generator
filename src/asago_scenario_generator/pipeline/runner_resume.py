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


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-24T10:23:12Z","module_hash":"c2a2ba4329f32aecd71465c02e3645d79748d3a2dab6d6ab88cfce7bf53fd685","source_sha256":"13ea28845f1493bbd0504ef0799a9783f15f2049ece3dbc137036a8fd243e0a4","functions":[{"id":"func/_resolve_resume_directory","name":"_resolve_resume_directory","line":42,"end_line":47,"hash":"e5e16faa5a47c7d4d3769851fb1c40af3e95f81b2fcf80d96f5d4d0d41359024"},{"id":"func/_load_resumable_manifest","name":"_load_resumable_manifest","line":50,"end_line":55,"hash":"370adc4d9c07f5af673676946db8e0c67eb0c9a8235e236bcbfe6bf382b1f45d"},{"id":"func/_validate_resume_manifest_identity","name":"_validate_resume_manifest_identity","line":58,"end_line":67,"hash":"cecf30712364cf28ab830e0b4e51e57e55223b6a069cd56ba09a6fa120de08da"},{"id":"func/_load_resume_support_artifacts","name":"_load_resume_support_artifacts","line":70,"end_line":96,"hash":"cbd73a7345f7ce1ef1d5193027a6fdd3a050f12a4650a5f295a6f00cc3c18f4c"},{"id":"func/_resume_command_options","name":"_resume_command_options","line":99,"end_line":121,"hash":"199158c434b86801aa69074b232918305418720b7b62f207abb1d50bf69d955f"},{"id":"func/_validate_resume_presentation_fallback","name":"_validate_resume_presentation_fallback","line":124,"end_line":129,"hash":"a89287219237416eec40a9bb51a07c75ed26ae90840b7e053cd494676b88ecf8"},{"id":"func/_validate_resume_generation_mode","name":"_validate_resume_generation_mode","line":132,"end_line":139,"hash":"34c284733769db2b688642c41904c6b7585a53450dcce5c02b77b67dbb5e2c4b"},{"id":"func/_validate_resume_provenance_inputs","name":"_validate_resume_provenance_inputs","line":142,"end_line":152,"hash":"96242315d85521c53b8757098f9420b6fdda41d91b7a235b67f97609bf4a8deb"},{"id":"func/_validate_resume_eval_override","name":"_validate_resume_eval_override","line":155,"end_line":158,"hash":"ccb227ec4bae20aa167ebcea535f3f0605e5ccf4ba15950c30e785da2097b1d2"},{"id":"func/_resume_input_paths","name":"_resume_input_paths","line":161,"end_line":174,"hash":"92b30ec2c0954993b57b86def6e9ab569f5cb29c89d2569109283197fb76afa1"},{"id":"func/_validate_resume_input_hash_drift","name":"_validate_resume_input_hash_drift","line":177,"end_line":196,"hash":"99201acc4ef58b2b322eb66c827ec8916e7391f1d5e54dd9708cbf063bd908e4"},{"id":"func/_validate_resume_facts_absent","name":"_validate_resume_facts_absent","line":199,"end_line":208,"hash":"6504ec1ab4d6036222973e5cba43eb91b8683c3a036ad89227197839d1158393"},{"id":"func/_parse_resume_facts","name":"_parse_resume_facts","line":211,"end_line":223,"hash":"0cb7ed64572a0983b2382fa49956d478fd31bec08a98f415693b346ff9efb827"},{"id":"func/_resume_qualification_facts","name":"_resume_qualification_facts","line":226,"end_line":240,"hash":"456e1df64c8005dd121b04df5da210ddd9c1bd72d55b27b3dc4a421877f5861b"},{"id":"func/_revalidate_resume_candidates","name":"_revalidate_resume_candidates","line":243,"end_line":266,"hash":"27baf6b64927473e9aac342b8bfec6d0ff6248fb4af6198526d9a3ad32a376cc"},{"id":"func/_setup_resume_logging","name":"_setup_resume_logging","line":269,"end_line":277,"hash":"280e9be704760559db109829400e7e089ec43c723e15c15541c857413db9583a"},{"id":"func/_validate_resume_model_config","name":"_validate_resume_model_config","line":280,"end_line":291,"hash":"dc3b9434339d0d4b91086d689c629f3b1d080c4dc5718006df392beb13084601"},{"id":"func/_validate_resume_model_override","name":"_validate_resume_model_override","line":294,"end_line":297,"hash":"032892de21781ddccadf518f74f06554053637b2ad62909e625f6eb7a273f6ed"},{"id":"func/_validate_resume_endpoint_override","name":"_validate_resume_endpoint_override","line":300,"end_line":308,"hash":"d7adedd0432b9a52b46a62f583d98e14e7c02b31f676581b02e98cd73429f4e0"},{"id":"func/_resolved_resume_base_url","name":"_resolved_resume_base_url","line":311,"end_line":313,"hash":"aefbb2ddf2c78e3ddb0712c9db3508ea55c5136e108e8cc07e1693513db20ef0"},{"id":"func/_resolved_resume_model","name":"_resolved_resume_model","line":316,"end_line":318,"hash":"6adf3b4bc25c4cc6dff2e60d8b21effccb1231bc21d59179eead989ad7e7ae7d"},{"id":"func/_persisted_temperature","name":"_persisted_temperature","line":321,"end_line":323,"hash":"d0980c7bf41ce806614156a76a1267e4a728b509939131cc1bc7aab127167143"},{"id":"func/_persisted_max_completion_tokens","name":"_persisted_max_completion_tokens","line":326,"end_line":328,"hash":"b33e18e56dca92644565a7292f1f211c47e7d90c815e2e750bb94d52fa024748"},{"id":"func/_resume_llm_client","name":"_resume_llm_client","line":331,"end_line":344,"hash":"4c693887cf46d044e6589ab956382de23505226aaad3be2893a18aacf641f383"},{"id":"func/persisted_presentation_fallback","name":"persisted_presentation_fallback","line":347,"end_line":349,"hash":"204cd28aca47246c4667a9dcbd7a5cae825a95b0c370ee2bbd821cb1e82079be"},{"id":"func/_resume_stage_ledger","name":"_resume_stage_ledger","line":352,"end_line":361,"hash":"1dece9d3ea40deeb4431d61f942bdf711775e7c5cd049336743f2d4911075102"}]}
# mutate4py-manifest-end
