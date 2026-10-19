"""Stated flawed beliefs: the variable frame, the reply rules, and the variable.

The belief step asks, for every Stage 5 causal factor, what the controller
wrongly takes to be true and which process-model variable holds the belief. Code fills the variable where the structure fixes it: a process-model
factor's own source, and a feedback factor's updated variable when that
variable is on the selected path. The model chooses for every other factor,
from the path's variables under local handles, or ``none`` with a description
of the missing variable.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from pydantic import BaseModel

from asago_scenario_generator.stpa.models.causal_factor import (
    CausalFactorKind,
    ProcessModelVariable,
)
from asago_scenario_generator.stpa.models.control_structure import ControlStructure
from asago_scenario_generator.stpa.models.scenario_context import (
    ScenarioGenerationContext,
)

from .wire import _CausalSourceChoice


VARIABLE_NONE = "none"

_FEEDBACK_KINDS = frozenset(
    {CausalFactorKind.feedback_delay, CausalFactorKind.sensor_anomaly}
)

# Structural identifiers and request-local handles; neither belongs in a
# statement in domain words.
_STRUCTURAL_OR_HANDLE = re.compile(
    r"\b(?:PM|FB|CA|CM|CL|CP|RESP|H|L|SC|CF|SEM|REQ|OUTCOME|EXEC|SCN)-"
    r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*\b"
    r"|\b(?:cause|variable)_\d+\b"
)


@dataclass(frozen=True)
class VariableChoice:
    """One process-model variable of the selected path under a local handle."""

    handle: str
    pm_id: str
    description: str
    values: tuple[str, ...]


@dataclass(frozen=True)
class FlawedBeliefFrame:
    """The variables a request offers and the factors whose variable code fills.

    ``fixed`` maps a causal-source handle to the variable handle code assigns
    it; the model chooses the variable of every other source.
    """

    variables: tuple[VariableChoice, ...]
    fixed: tuple[tuple[str, str], ...]

    @property
    def variable_handles(self) -> tuple[str, ...]:
        return tuple(item.handle for item in self.variables)

    def fixed_variable(self, source_handle: str) -> VariableChoice | None:
        """Return the variable code assigns ``source_handle``, if any."""
        assigned = dict(self.fixed).get(source_handle)
        return None if assigned is None else self.variable(assigned)

    def variable(self, handle: str) -> VariableChoice:
        return next(item for item in self.variables if item.handle == handle)


def build_flawed_belief_frame(
    choices: Sequence[_CausalSourceChoice],
    context: ScenarioGenerationContext,
    control_structure: ControlStructure,
) -> FlawedBeliefFrame:
    """Number the path's variables and fix the variable of PM and FB sources."""
    parts = {
        part.pm_id: part
        for responsibility in control_structure.responsibilities
        for part in responsibility.process_model_parts
    }
    updates = {
        channel.fb_id: channel.updates
        for responsibility in control_structure.responsibilities
        for channel in responsibility.feedback_channels
    }
    path_parts = {
        item.element_id: item.description
        for item in context.target_control_path.process_model_parts
    }
    variables = tuple(
        VariableChoice(
            handle=f"variable_{index}",
            pm_id=pm_id,
            description=description,
            values=tuple(parts[pm_id].values) if pm_id in parts else (),
        )
        for index, (pm_id, description) in enumerate(path_parts.items(), start=1)
    )
    handle_of = {item.pm_id: item.handle for item in variables}
    fixed: list[tuple[str, str]] = []
    for choice in choices:
        if choice.kind is CausalFactorKind.process_model_flaw:
            pm_id: str | None = choice.source_id
        elif choice.kind in _FEEDBACK_KINDS:
            pm_id = updates.get(choice.source_id)
        else:
            pm_id = None
        if pm_id in handle_of:
            fixed.append((choice.handle, handle_of[pm_id]))
    return FlawedBeliefFrame(variables=variables, fixed=tuple(fixed))


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9']+", text.casefold()))


def flawed_belief_findings(
    factors: Sequence[BaseModel],
    frame: FlawedBeliefFrame,
    *,
    locate: Callable[[int, BaseModel], str] | None = None,
) -> list[str]:
    """Return one line per broken stated-belief rule, in factor order.

    Code checks structure only: whether a belief says what the controller
    wrongly takes to be true, rather than only naming a variable, is a
    judgement of meaning that the rules leave to the model.

    ``locate`` names a factor from its index and itself; by default it names
    the factor's place in a Stage 5 reply's ``causal_factors``.
    """
    findings: list[str] = []
    choosable = ", ".join((*frame.variable_handles, VARIABLE_NONE))
    for index, factor in enumerate(factors):
        where = (
            f"causal_factors[{index}] ({factor.source_handle})"
            if locate is None
            else locate(index, factor)
        )
        belief = (getattr(factor, "flawed_belief", None) or "").strip()
        variable = getattr(factor, "process_model_variable", None)
        missing = getattr(factor, "missing_variable", None)
        missing_text = (missing or "").strip()
        if not belief:
            findings.append(
                f"{where}: flawed_belief is blank; state what the controller "
                "wrongly takes to be true when it issues the unsafe action."
            )
        else:
            found = _STRUCTURAL_OR_HANDLE.search(belief)
            if found is not None:
                findings.append(
                    f"{where}: flawed_belief contains the identifier "
                    f"{found.group(0)}; state the belief in domain words."
                )
        fixed = frame.fixed_variable(factor.source_handle)
        if fixed is not None:
            # Repeating the handle code assigns, or a blank missing_variable,
            # agrees with code; only a conflicting value breaks the rule.
            if variable not in (None, fixed.handle) or missing_text:
                findings.append(
                    f"{where}: code fills this factor's variable; set "
                    "process_model_variable and missing_variable to null."
                )
            continue
        if variable is None:
            findings.append(
                f"{where}: process_model_variable is null; choose one of {choosable}."
            )
        elif variable == VARIABLE_NONE:
            if not missing_text:
                findings.append(
                    f"{where}: process_model_variable is none, so "
                    "missing_variable must describe the variable the "
                    "controller would need to hold the belief."
                )
            else:
                found = _STRUCTURAL_OR_HANDLE.search(missing_text)
                if found is not None:
                    findings.append(
                        f"{where}: missing_variable contains the identifier "
                        f"{found.group(0)}; describe the variable in domain "
                        "words."
                    )
                listed = next(
                    (
                        item
                        for item in frame.variables
                        if _words(item.description) == _words(missing_text)
                    ),
                    None,
                )
                if listed is not None:
                    findings.append(
                        f"{where}: missing_variable describes the listed "
                        f"variable {listed.handle}; choose {listed.handle} "
                        "instead of none."
                    )
        elif missing_text:
            findings.append(
                f"{where}: process_model_variable names a listed variable, so "
                "set missing_variable to null."
            )
    return findings


def resolve_process_model_variable(
    factor: BaseModel, frame: FlawedBeliefFrame
) -> ProcessModelVariable:
    """Return the variable a validated factor's belief concerns, or its gap."""
    fixed = frame.fixed_variable(factor.source_handle)
    if fixed is not None:
        return ProcessModelVariable(pm_id=fixed.pm_id, description=fixed.description)
    if factor.process_model_variable == VARIABLE_NONE:
        return ProcessModelVariable(
            pm_id=None, description=factor.missing_variable.strip()
        )
    chosen = frame.variable(factor.process_model_variable)
    return ProcessModelVariable(pm_id=chosen.pm_id, description=chosen.description)
