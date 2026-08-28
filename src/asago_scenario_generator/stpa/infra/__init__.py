"""STPA infrastructure — clean copies of minimal pipeline utilities.

Zero coupling to the existing pipeline infrastructure modules.

Public API: import infrastructure utilities from here rather than from
individual sub-modules.
"""

from asago_scenario_generator.stpa.infra.call_log import (
    append_call_log,
    make_call_log_entry,
)
from asago_scenario_generator.stpa.infra.calls_html import render_calls_html
from asago_scenario_generator.stpa.infra.llm import LLMClient, LLMResult
from asago_scenario_generator.stpa.infra.llm_helpers import (
    log_llm_call,
    parse_llm_result,
    safe_llm_call_raw,
)
from asago_scenario_generator.stpa.infra.manifest import STPARunManifest
from asago_scenario_generator.stpa.infra.model_profiles import load_profile
from asago_scenario_generator.stpa.infra.parallel_llm import (
    LLMCallResult,
    LLMCallSpec,
    parallel_safe_llm_calls,
)
from asago_scenario_generator.stpa.infra.templates import (
    TemplateLoader,
    hash_prompt_templates,
)
from asago_scenario_generator.stpa.infra.yaml_io import read_yaml, write_yaml

__all__ = [
    # llm
    "LLMClient",
    "LLMResult",
    # llm_helpers
    "log_llm_call",
    "parse_llm_result",
    "safe_llm_call_raw",
    # call_log
    "append_call_log",
    "make_call_log_entry",
    # calls_html
    "render_calls_html",
    # model_profiles
    "load_profile",
    # yaml_io
    "read_yaml",
    "write_yaml",
    # templates
    "TemplateLoader",
    "hash_prompt_templates",
    # manifest
    "STPARunManifest",
    # parallel_llm
    "LLMCallSpec",
    "LLMCallResult",
    "parallel_safe_llm_calls",
]
