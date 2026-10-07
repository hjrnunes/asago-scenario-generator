"""Feature steps that assert nothing, all bound to one no-op handler."""

from __future__ import annotations

from generic_steps import noop
from registry import StepTable

FEATURE_ID = "noop_steps"

# (pattern, registered first, feature scope)
NOOP_STEPS: list[tuple[str, bool, str | None]] = [
    ("the STPA boundary schema module is importable", False, None),
    ("the STPA infra module is importable", False, None),
    ("the STPA run manifest module is imported", False, None),
    ("the SystemContext model is defined", False, None),
    ("the ConsumerHints model is defined", False, None),
    ("the ScenarioEnvelope model is defined", False, None),
    ("the computation involves no LLM calls", False, None),
    ("the scenario_prod enrichment module is importable", False, None),
    ("a use-case description and risk cards are available as input", False, None),
    ("a use-case description and risk cards are available$", False, None),
    ("a use-case description and loss analysis are available as input", False, None),
    ("a use-case description is available", False, None),
    ("a capability profile and use-case text are available", False, None),
    ("capability profile entry-point validation is available$", False, None),
    ("the entry point is validated$", False, None),
    ("the user prompt contains the current control structure", False, None),
    ("the user prompt contains the critic findings", False, None),
    ("the existing test suite is run", False, None),
    ("no new failures are introduced", False, None),
    ("the SP1 system model module is implemented", False, None),
    ("the STPA system model module$", False, None),
    ("SP1 assembles the responses with deterministic ID normalization$", False, None),
    ("every field not varied by the scenario is valid$", False, None),
    ("every control-structure field not varied by the scenario is valid$", False, None),
    ("source IDs are assigned canonical IDs by final list position$", False, None),
    ("an SP1 LLM response is decoded in tolerant mode$", False, None),
    ("the pipeline does not raise an exception", False, None),
    ("Stage \\S+ depends on the output of Stage", True, None),
    ("Stage 2 Call \\d+ depends on the output", True, None),
    ("the critic depends on the output", True, None),
    ("the revision depends on the output", True, None),
    ("the SP1 pipeline stage dependencies", True, None),
    ("the capability profile module is importable", False, None),
    ("the control structure module is importable", False, None),
    ("the SP2 slot creation module is importable", False, None),
    ("the SP2 N/A quality module is importable", False, None),
    ("the SP2 catalog enrichment module is importable", False, None),
    ("the SP2 coverage module is importable", False, None),
    ("no LLM calls are made", False, None),
    ("non-N/A ICAs have catalog mappings", False, None),
    ("the SP3 BDI generation module is importable", False, None),
    ("the SP3 validators module is importable", False, None),
    ("the SP3 eval metrics module is importable", False, None),
    ("the SP3 coverage module is importable", False, None),
    ("the SP3 run module is importable", False, None),
    ("the SP3 scenario production module", False, None),
    ("the SP3 prompt templates directory", False, None),
    ("a security constraint SC-1 related to hazard H-1", False, None),
    ("the call is labeled with stage stage_5", False, None),
    ("the call step is bdi_generation", False, None),
    ("no LLM calls are made", True, "sp3"),
    ("Stage 5 BDI generation is produced first", True, "sp3"),
    ("Stage 6 concretization is produced second", True, "sp3"),
    ("Stage 7 validation and eval is produced last", True, "sp3"),
    ("the scenario specs are validated against the control structure", False, None),
    ("the eval metrics consume the enriched threat set.*", False, None),
    ("the traceability validation consumes the loss analysis", False, None),
    ("the SP3 prompt assembly modules are importable", True, "sp3"),
    ("a use-case file and a risk-extraction file are available", False, None),
    ("an LLM endpoint is configured", False, None),
    ("the acceptance runtime module is importable", False, None),
]

step = StepTable()
for _pattern, _first, _feature in NOOP_STEPS:
    step.add(_pattern, noop, first=_first, feature=_feature)

register = step.register

__all__ = ["FEATURE_ID", "NOOP_STEPS", "register"]
