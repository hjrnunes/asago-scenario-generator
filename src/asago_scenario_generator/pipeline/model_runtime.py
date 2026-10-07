"""One model client per synthesis run.

``ModelRuntime`` resolves the configured LLM client once, on first use, and
hands the same client, its temperature, and the SP2 analysis controls to
every default stage. A run whose stages are all caller-supplied never
resolves a client. A failed resolution is not cached, so each later stage
that needs the client raises the same error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ANALYSIS_DEADLINE_SECONDS = 300.0
ANALYSIS_MAX_BATCH_SIZE = 8


@dataclass(eq=False)
class ModelRuntime:
    """The model profile selection and the client resolved from it."""

    profile: str | None
    profiles_file: str
    session: Any = None
    _resolved: tuple[Any, str | None] | None = field(
        default=None, init=False, repr=False
    )

    @classmethod
    def for_inputs(cls, inputs: Any, session: Any = None) -> ModelRuntime:
        """Return the runtime selected by a synthesis request.

        The client it resolves records and replays through *session*.
        """
        return cls(
            profile=inputs.profile,
            profiles_file=str(inputs.profiles_file),
            session=session,
        )

    def _resolve(self) -> tuple[Any, str | None]:
        if self._resolved is None:
            from asago_scenario_generator.stpa.pipeline import llm_config

            self._resolved = llm_config.resolve_llm_client(
                self.profile, self.profiles_file, self.session
            )
        return self._resolved

    @property
    def client(self) -> Any:
        """Return the run's LLM client."""
        return self._resolve()[0]

    @property
    def profile_name(self) -> str | None:
        """Return the resolved profile name, or None for an environment client."""
        return self._resolve()[1]

    def temperature(self) -> float:
        """Return the client's effective sampling temperature."""
        from asago_scenario_generator.stpa.infra.llm import effective_temperature

        return effective_temperature(self.client)

    def analysis_controls(self) -> Any:
        """Return the SP2 analysis controls for the run's client."""
        from asago_scenario_generator.stpa.obligation_aware.contracts import (
            AnalysisControls,
        )

        client, profile_name = self._resolve()
        return AnalysisControls(
            model_profile=profile_name or "environment",
            model_name=client.model,
            deadline_seconds=ANALYSIS_DEADLINE_SECONDS,
            temperature=self.temperature(),
            max_batch_size=ANALYSIS_MAX_BATCH_SIZE,
        )

    def obligation_adapter(self, output_dir: Path) -> Any:
        """Return an SP2 provider adapter over the run's client."""
        from asago_scenario_generator.stpa.obligation_aware.provider import (
            ObligationAwareLLMAdapter,
        )

        return ObligationAwareLLMAdapter(
            self.client,
            run_dir=Path(output_dir),
            controls=self.analysis_controls(),
        )


__all__ = [
    "ANALYSIS_DEADLINE_SECONDS",
    "ANALYSIS_MAX_BATCH_SIZE",
    "ModelRuntime",
]
