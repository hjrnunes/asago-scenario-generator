"""Simplified STPA run manifest — no sentinel/finalization protocol.

The manifest is written once at the end of the run. No immutability
enforcement, no sentinel protocol, no finalization inventory. Crash
recovery is handled by the caller re-running.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class STPARunManifest(BaseModel):
    """Simplified run manifest for the STPA pipeline (Section 5 of spec)."""

    model_config = ConfigDict(protected_namespaces=())

    run_id: str
    run_dir: str
    created_at: str  # ISO 8601
    # NOTE: ``model_config`` is a Pydantic reserved attribute, so the field
    # is named ``model_settings`` with the alias ``model_config``.
    model_settings: dict = Field(
        alias="model_config",
        description="Model configuration: model name, base_url, temperature.",
    )
    input_hashes: dict = Field(
        description="Hashes of input artifacts (use-case text, risk extraction).",
    )
    prompt_hashes: dict = Field(
        description="Template filename → SHA-256 hash.",
    )
    stage_summary: dict = Field(
        description="Per-stage: call count, duration_ms, token usage.",
    )
    slot_count: int = 0
    na_count: int = 0
    fill_rate: float = 0.0  # non_na / total_slots
    scenario_count: int = 0
    critic_findings: list[str] = Field(
        default_factory=list,
        description="Gaps identified by the completeness critic.",
    )
    revised: bool = Field(
        default=False,
        description="Whether SP1 attempted a revision after critic findings.",
    )
    post_revision_warnings: list[str] = Field(
        default_factory=list,
        description="Warnings produced while applying and validating the revision.",
    )
    stage_errors: list[str] = Field(
        default_factory=list,
        description="Stage failures that occurred during the run (partial failure).",
    )
    stage_warnings: list[str] = Field(
        default_factory=list,
        description=(
            "Recoverable stage diagnostics that did not prevent validated artifacts."
        ),
    )
    eval_scorecard_path: str | None = None


# mutate4py-manifest-begin
# {"version":1,"tested_at":"2026-08-08T23:13:34Z","module_hash":"5ed1c01dc526997426ea91bb445bf9eb03cb6c8b33932c099c96beace4df8cf0","functions":[]}
# mutate4py-manifest-end
