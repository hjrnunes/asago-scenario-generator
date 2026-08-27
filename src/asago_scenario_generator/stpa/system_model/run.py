"""SP1 run orchestration — Stages 1a → 1b → 2.

Orchestrates the full SP1 pipeline:
  Stage 1a: Loss analysis derivation
  Stage 1b: Capability profile inference (or load with --profile)
  Stage 2: Control structure derivation (4 calls + heuristics + critic + revision)
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from asago_scenario_generator.models.capability_profile import (
    CapabilityProfile,
    inject_kc_subcodes_display,
)
from asago_scenario_generator.models.risk_card import RiskCard
from asago_scenario_generator.stpa.infra.llm import (
    DEFAULT_TEMPERATURE as LLM_DEFAULT_TEMPERATURE,
    LLMClient,
    effective_model_config,
    effective_temperature,
)
from asago_scenario_generator.stpa.infra.llm_helpers import StageError
from asago_scenario_generator.stpa.infra.manifest import STPARunManifest
from asago_scenario_generator.stpa.infra.parallel_llm import (  # noqa: F401 — imported for patchability
    parallel_safe_llm_calls,
)
from asago_scenario_generator.stpa.infra.templates import TemplateLoader
from asago_scenario_generator.stpa.infra.yaml_io import write_yaml
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.loss_analysis import LossAnalysis
from asago_scenario_generator.stpa.system_model._constants import PROMPTS_DIR
from asago_scenario_generator.stpa.system_model.control_structure import (
    STAGE_2_CALL_COUNT,
    derive_control_structure,
)
from asago_scenario_generator.stpa.system_model.critic import (
    CriticFindings,
    has_unjustified_gaps,
    run_completeness_critic,
    run_revision,
    sanitize_critic_ids,
    strip_empty_responsibilities,
)
from asago_scenario_generator.stpa.system_model.heuristics import (
    check_solution_neutrality,
    run_heuristics,
)
from asago_scenario_generator.stpa.system_model.loss_analysis import (
    derive_loss_analysis,
)
from asago_scenario_generator.stpa.system_model.profile import (
    derive_capability_profile,
    load_capability_profile,
)

DEFAULT_TEMPERATURE = LLM_DEFAULT_TEMPERATURE


@dataclass
class SP1RunResult:
    """Result of a full SP1 run.

    On partial failure, ``loss_analysis``, ``capability_profile``, and
    ``control_structure`` may be ``None`` and ``stage_errors`` lists
    the failures that occurred.
    """

    loss_analysis: LossAnalysis | None = None
    capability_profile: CapabilityProfile | None = None
    control_structure: ControlStructure | None = None
    critic_findings: CriticFindings | None = None
    heuristic_errors: list[str] = field(default_factory=list)
    heuristic_warnings: list[str] = field(default_factory=list)
    solution_neutrality_warnings: list[str] = field(default_factory=list)
    post_revision_warnings: list[str] = field(default_factory=list)
    revised: bool = False
    stage_errors: list[str] = field(default_factory=list)
    stage_warnings: list[str] = field(default_factory=list)


def run_sp1(
    *,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    profile_path: Path | None = None,
    temperature: float | None = None,
    profile_name: str | None = None,
    max_workers: int = 1,
) -> SP1RunResult:
    """Run the full SP1 pipeline: Stages 1b → 1a → 2.

    Pipeline ordering: Stage 1b (capability profile) runs first, then
    Stage 1a (loss analysis, two calls: risk_derivation + gap_analysis).
    Stage 1a-2 (gap analysis) receives the capability profile as input.
    Stage 2 runs after both 1a and 1b complete.

    Args:
        llm_client: LLM client for making completion calls.
        use_case_text: Free-text use-case description.
        risk_cards: List of RiskCard objects from risk extraction.
        run_dir: Directory for output artifacts.
        profile_path: Optional path to a pre-built capability-profile.yaml.
            When provided, Stage 1b LLM call is skipped.
        temperature: Explicit LLM temperature override. When omitted, use the
            resolved client temperature (default 0.4).
        profile_name: Optional model profile name for manifest recording.
        max_workers: Maximum parallel workers for LLM calls (default 1 =
            sequential, backwards compatible). SP1's sequential stages do
            not use parallel execution yet; this parameter is recorded in
            the manifest and available for future use.

    Returns:
        SP1RunResult with all artifacts and diagnostic info. On partial
        failure, returns a partial result with ``stage_errors`` populated
        and remaining artifacts as None.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    loader = TemplateLoader(PROMPTS_DIR)
    temperature = effective_temperature(llm_client, temperature)

    stage_errors: list[str] = []
    stage_warnings: list[str] = []

    # --- Stage 1b: Capability Profile (runs BEFORE Stage 1a) ---
    capability_profile = _try_derive_capability_profile(
        llm_client,
        use_case_text,
        run_dir,
        loader,
        temperature,
        profile_path,
        stage_errors,
    )

    # --- Stage 1a: Loss Analysis (two calls, receives capability profile) ---
    loss_analysis = _try_derive_loss_analysis(
        llm_client,
        use_case_text,
        risk_cards,
        run_dir,
        loader,
        temperature,
        stage_errors,
        capability_profile,
    )

    # --- Stage 2: Control Structure + heuristics + critic + revision ---
    stage2_result = _run_stage_2_block(
        llm_client,
        use_case_text,
        loss_analysis,
        capability_profile,
        run_dir,
        loader,
        temperature,
        stage_errors,
        stage_warnings,
    )

    # Write run manifest (always, even on partial failure)
    _profile_skipped = profile_path is not None
    _write_manifest(
        run_dir=run_dir,
        llm_client=llm_client,
        use_case_text=use_case_text,
        risk_cards=risk_cards,
        loader=loader,
        critic_findings=stage2_result.critic_findings,
        revised=stage2_result.revised,
        post_revision_warnings=stage2_result.post_revision_warnings,
        temperature=temperature,
        profile_skipped=_profile_skipped,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
        profile_name=profile_name,
        max_workers=max_workers,
    )

    return SP1RunResult(
        loss_analysis=loss_analysis,
        capability_profile=capability_profile,
        control_structure=stage2_result.control_structure,
        critic_findings=stage2_result.critic_findings,
        heuristic_errors=stage2_result.heuristic_errors,
        heuristic_warnings=stage2_result.heuristic_warnings,
        solution_neutrality_warnings=stage2_result.solution_neutrality_warnings,
        post_revision_warnings=stage2_result.post_revision_warnings,
        revised=stage2_result.revised,
        stage_errors=stage_errors,
        stage_warnings=stage_warnings,
    )


@dataclass
class _Stage2Result:
    """Internal result container for the Stage 2 block."""

    control_structure: ControlStructure | None = None
    critic_findings: CriticFindings | None = None
    heuristic_errors: list[str] = field(default_factory=list)
    heuristic_warnings: list[str] = field(default_factory=list)
    solution_neutrality_warnings: list[str] = field(default_factory=list)
    post_revision_warnings: list[str] = field(default_factory=list)
    revised: bool = False


def _try_derive_loss_analysis(
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    capability_profile: CapabilityProfile | None = None,
) -> LossAnalysis | None:
    """Run Stage 1a (two calls), recording errors on failure."""
    try:
        return derive_loss_analysis(
            llm_client=llm_client,
            use_case_text=use_case_text,
            risk_cards=risk_cards,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
            capability_profile=capability_profile,
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return None


def _try_derive_capability_profile(
    llm_client: LLMClient,
    use_case_text: str,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    profile_path: Path | None,
    stage_errors: list[str],
) -> CapabilityProfile | None:
    """Run Stage 1b (or load a pre-built profile), recording errors on failure."""
    if profile_path is not None:
        capability_profile = load_capability_profile(profile_path)
        write_yaml(
            capability_profile,
            run_dir / "capability-profile.yaml",
            post_process=inject_kc_subcodes_display,
        )
        return capability_profile
    try:
        return derive_capability_profile(
            llm_client=llm_client,
            use_case_text=use_case_text,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
        )
    except StageError as exc:
        stage_errors.append(str(exc))
        return None


def _run_stage_2_block(
    llm_client: LLMClient,
    use_case_text: str,
    loss_analysis: LossAnalysis | None,
    capability_profile: CapabilityProfile | None,
    run_dir: Path,
    loader: TemplateLoader,
    temperature: float,
    stage_errors: list[str],
    stage_warnings: list[str] | None = None,
) -> _Stage2Result:
    """Run Stage 2: control structure derivation, heuristics, critic, and revision.

    Returns an empty result when prerequisites are missing or derivation fails.
    """
    if loss_analysis is None or capability_profile is None:
        return _Stage2Result()

    stage_warnings = [] if stage_warnings is None else stage_warnings

    try:
        control_structure, merge_warnings = derive_control_structure(
            llm_client=llm_client,
            use_case_text=use_case_text,
            loss_analysis=loss_analysis,
            capability_profile=capability_profile,
            run_dir=run_dir,
            template_loader=loader,
            temperature=temperature,
        )
        stage_warnings.extend(merge_warnings)
    except StageError as exc:
        stage_errors.append(str(exc))
        return _Stage2Result()

    # Structural heuristics (always run after Call 3)
    heuristic_result = run_heuristics(control_structure, loss_analysis)
    solution_neutrality_warnings = check_solution_neutrality(control_structure)

    # Completeness critic (graceful — returns empty findings on failure)
    critic_findings = run_completeness_critic(
        llm_client=llm_client,
        control_structure=control_structure,
        capability_profile=capability_profile,
        use_case_text=use_case_text,
        run_dir=run_dir,
        template_loader=loader,
        temperature=temperature,
        loss_analysis=loss_analysis,
        call3_warnings=merge_warnings,
    )

    # Sanitize non-conforming IDs from critic remedies before revision
    critic_findings = sanitize_critic_ids(critic_findings)

    # Revision (single attempt if unjustified gaps; graceful on failure)
    post_revision_warnings: list[str] = []
    revised = False
    if has_unjustified_gaps(critic_findings):
        revised = True
        control_structure, post_revision_warnings = run_revision(
            llm_client=llm_client,
            control_structure=control_structure,
            critic_findings=critic_findings,
            use_case_text=use_case_text,
            run_dir=run_dir,
            loss_analysis=loss_analysis,
            template_loader=loader,
            temperature=temperature,
        )
        # Strip empty responsibilities that revision may have introduced
        control_structure, strip_warnings = strip_empty_responsibilities(
            control_structure
        )
        post_revision_warnings.extend(strip_warnings)
        write_yaml(control_structure, run_dir / "control-structure.yaml")

    return _Stage2Result(
        control_structure=control_structure,
        critic_findings=critic_findings,
        heuristic_errors=list(heuristic_result.errors),
        heuristic_warnings=list(heuristic_result.warnings),
        solution_neutrality_warnings=solution_neutrality_warnings,
        post_revision_warnings=post_revision_warnings,
        revised=revised,
    )


def _compute_input_hashes(
    use_case_text: str, risk_cards: list[RiskCard]
) -> dict[str, str]:
    """Compute SHA-256 hashes of input artifacts for the manifest."""
    hashes = {
        "use_case_text": hashlib.sha256(use_case_text.encode("utf-8")).hexdigest()
    }
    if risk_cards:
        risk_ids = ",".join(rc.risk_id for rc in risk_cards)
        hashes["risk_extraction"] = hashlib.sha256(risk_ids.encode("utf-8")).hexdigest()
    else:
        hashes["risk_extraction"] = hashlib.sha256(b"").hexdigest()
    return hashes


def _summarize_critic_findings(critic_findings: CriticFindings | None) -> list[str]:
    """Build a human-readable summary list from critic findings."""
    if critic_findings is None:
        return []
    return [f"{gap.gap_type}: {gap.description}" for gap in critic_findings.gaps]


def _write_manifest(
    *,
    run_dir: Path,
    llm_client: LLMClient,
    use_case_text: str,
    risk_cards: list[RiskCard],
    loader: TemplateLoader,
    critic_findings: CriticFindings | None,
    revised: bool = False,
    post_revision_warnings: list[str] | None = None,
    temperature: float,
    profile_skipped: bool,
    stage_errors: list[str] | None = None,
    stage_warnings: list[str] | None = None,
    profile_name: str | None = None,
    max_workers: int = 1,
) -> None:
    """Write the run manifest with stage summary, input hashes, and prompt hashes."""
    input_hashes = _compute_input_hashes(use_case_text, risk_cards)
    prompt_hashes = loader.hash_prompt_templates()
    critic_summary = _summarize_critic_findings(critic_findings)
    stage_1b_calls = 0 if profile_skipped else 1
    _stage_1a_call_count = 2
    _stage_2_call_count = STAGE_2_CALL_COUNT

    model_config_dict = effective_model_config(llm_client, temperature=temperature)
    model_config_dict["max_workers"] = max_workers
    if profile_name is not None:
        model_config_dict["profile"] = profile_name

    manifest = STPARunManifest(
        run_id=run_dir.name,
        run_dir=str(run_dir),
        created_at=datetime.now(timezone.utc).isoformat(),
        **{  # type: ignore[arg-type]
            "model_config": model_config_dict,
        },
        input_hashes=input_hashes,
        prompt_hashes=prompt_hashes,
        stage_summary={
            "stage_1a": {"call_count": _stage_1a_call_count},
            "stage_1b": {"call_count": stage_1b_calls},
            "stage_2": {"call_count": _stage_2_call_count},
        },
        critic_findings=critic_summary,
        revised=revised,
        post_revision_warnings=post_revision_warnings or [],
        stage_warnings=stage_warnings or [],
    )
    if stage_errors:
        manifest.stage_errors = stage_errors
    write_yaml(manifest, run_dir / "run-manifest.yaml")


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-13T19:48:27Z","module_hash":"5763124a1343cf5c8f78e35f44ae47b8d2c59f7e87a2b54c3f5fdbca639f20da","functions":[{"id":"func/run_sp1","name":"run_sp1","line":79,"end_line":168,"hash":"d424caecdd95117094deece88e91b9bbcf78aa74f58e3d1fee52c0aedb776d1d"},{"id":"func/_try_derive_loss_analysis","name":"_try_derive_loss_analysis","line":184,"end_line":207,"hash":"b1795ba3b9e34725aac83d6c52e299ce98641aa62de59de074c6709bb2fc2119"},{"id":"func/_try_derive_capability_profile","name":"_try_derive_capability_profile","line":210,"end_line":238,"hash":"cdeddcc8136f89427881ec908455e5a85949ae0aa19030b9b137a52923038840"},{"id":"func/_run_stage_2_block","name":"_run_stage_2_block","line":241,"end_line":323,"hash":"21a7f70f55bbfccef88c20e398955fcf1f858ea7aa1497fac1ac39a0bd03533a"},{"id":"func/_compute_input_hashes","name":"_compute_input_hashes","line":326,"end_line":334,"hash":"e6bdbd62d47427569dd6f476f0e301433f188035c685a7e38fa64960bd43b80c"},{"id":"func/_summarize_critic_findings","name":"_summarize_critic_findings","line":337,"end_line":341,"hash":"52f92e834950dffd8fbfbc258cbf55efcd8d6e9f51c7cfe4543c097d2d38b54d"},{"id":"func/_write_manifest","name":"_write_manifest","line":344,"end_line":397,"hash":"f717c04a63526fc8352afd95bf559a30ac330856291c910cf0c6cfb68364bcc1"}]}
# mutate4py-manifest-end
