"""Per-example state for the acceptance runtime.

The world is deliberately kept independent from registry and execution
lifecycle code.  Feature handlers may retain the compatibility import from
``runtime_shared``, while framework code can depend on this narrow module.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


class World:
    """Shared state for a single scenario execution.

    Field types stay generic so this module does not depend on production
    models, persistence shapes, or feature handlers.  Handlers that need
    those types import them from their own side of the boundary.
    """

    def __init__(self) -> None:
        self.loss_analysis: Any = None
        self.control_structure: Any = None
        self.ica_enumeration: Any = None
        self.enriched_threat_set: Any = None
        self.scenario_spec: Any = None  # ScenarioSpec
        self.validation_error: Exception | None = None
        self.validation_succeeded: bool = False
        self.heuristic_result = None
        # Infrastructure test state
        self.fixture_dir: Path | None = None
        self.fixture_filename: str | None = None
        self.fixture_model: Any = None
        self.env_overrides: dict[str, str | None] = {}
        self.llm_client: Any = None
        self.llm_result: Any = None
        self.call_log_entries: list[dict] = []
        self.call_log_path: Path | None = None
        self.yaml_model: Any = None
        self.yaml_path: Path | None = None
        self.yaml_read_back: Any = None
        self.template_dir: Path | None = None
        self.template_loader: Any = None
        self.template_rendered: str | None = None
        self.template_hashes: dict[str, str] | None = None
        self.manifest: Any = None
        # SP1 system model test state
        self.sp1_llm_content: Any = None
        self.sp1_component_name: str | None = None
        self.sp1_warnings: list[str] = []
        self.sp1_gap_type: str | None = None
        self.sp1_element_type: str | None = None
        self.sp1_entity: str | None = None
        self.sp1_ref_target: str | None = None
        self.sp1_error_fragment: str | None = None
        self.sp1_run_dir: Path | None = None
        self.sp1_mock_client: Any = None
        self.sp1_profile: Any = None  # CapabilityProfile
        self.sp1_profile_path: Path | None = None
        self.sp1_requirement_set: Any = None
        self.sp1_responsibility_set: Any = None
        self.sp1_control_element_set: Any = None
        self.sp1_connection_set: Any = None
        self.sp1_critic_findings: Any = None
        self.sp1_revised: bool = False
        self.sp1_revision_call_count: int = 0
        self.sp1_run_result: Any = None
        self.sp1_user_prompt: str | None = None
        self.sp1_use_case_text: str = "Test use case for SP1"
        self.sp1_risk_cards: list = []
        self.sp1_post_revision_warnings: list[str] = []
        self.sp1_temperature: float | None = None
        self.sp1_manifest: Any = None
        # Graceful degradation test state
        self.gd_stage_error: Exception | None = None
        self.gd_pre_revision_cs: Any = None
        self.gd_run_result: Any = None
        # Model profiles and calls HTML test state
        self.current_data_table: list[list[str]] | None = None
        self.profiles_path: Path | None = None
        self.profile_result: dict | None = None
        self.calls_jsonl_path: Path | None = None
        self.calls_html_path: Path | None = None
        self.calls_html_result: Path | None = None
        self.calls_html_content: str | None = None
        self.runner_llm_client: Any = None
        self.runner_profile_name: str | None = None
        # Parallel LLM test state
        self.parallel_mock_client: Any = None
        self.parallel_calls: list = []
        self.parallel_results: list = []
        self.parallel_run_dir: Path | None = None
        self.parallel_spec: Any = None
        self.parallel_max_workers: int = 4
        # SP1 batch3 sanitization and repair state
        self.sp1_sanitized_findings: Any = None
        self.sp1_sanitized_remedy: str | None = None
        self.sp1_original_remedy: str | None = None
        self.sp1_repair_warnings: list[str] = []
        self.sp1_revision_prompt: str | None = None
        self.sp1_sanitize_called: bool = False
        # SP1 bug fix test state (merge fallback sanitize, revision delta, calls HTML)
        self.san_merge_warnings: list[str] = []
        self.san_resp_set_dict: dict | None = None
        self.san_connection_set: Any = None
        self.san_merge_failure_triggered: bool = False
        self.rev_delta: Any = None
        self.rev_response_format: type | None = None
        self.rev_rendered_system: str | None = None
        self.rev_rendered_user: str | None = None
        self.fc_entry: dict | None = None
        self.fc_calls_path: Path | None = None
        self.fc_llm_result: Any = None
        # STPA report test state
        self.report_tmpdir: Path | None = None
        self.report_html_path: Path | None = None
        self.report_html_content: str | None = None
        # Nullable usage report test state
        self.nullable_pipeline_calls: list[dict[str, Any]] = []
        self.nullable_scenario_calls: dict[str, list[dict[str, Any]]] = {}
        self.nullable_scenarios: list[dict[str, Any]] = []
        self.nullable_report_error: str | None = None
        # Envelope enrichment test state
        self.envelope: Any = None
        self.capability_profile: Any = None
        self.system_context: Any = None
        self.consumer_hints: Any = None
        self.enrichment_attack_tree: dict | None = None
        self.enrichment_narrative: str | None = None
        self.enrichment_primary_zone: str | None = None
        # critic-revision-fix test state
        self.sp1_call3_warnings: list[str] | None = None
        self.sp1_next_ids: dict[str, int] | None = None
        self.sp1_run_py_source: str | None = None
        self.sp1_critic_run_fn: Any = None


__all__ = ["World"]
