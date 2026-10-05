"""Deterministic acceptance handlers for the public synthesis composition root."""

from __future__ import annotations

import html
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from runtime_shared import World, _feature_state

from asago_scenario_generator.models.obligation_consideration import ObligationRoute
from asago_scenario_generator.pipeline.obligation_planner import (
    plan_taxonomy_obligations,
)
from asago_scenario_generator.pipeline.synthesis import (
    ACCOUNTING_FILENAME,
    CONSIDERATION_FILENAME,
    MANIFEST_FILENAME,
    PLAN_FILENAME,
    SCENARIO_REALIZATION_FILENAME,
    SynthesisAdapters,
    run_synthesis,
)
from asago_scenario_generator.stpa.obligation_aware.routing import RoutingRunResult

from tests.helpers.synthesis_fixture import (
    applicable_obligation_ids,
    baseline_control_structure,
    baseline_loss_analysis,
    obligation_id_for,
    obligation_routes,
    structural_revision,
    synthesis_capability_profile,
    synthesis_inputs,
    synthesis_taxonomy_inputs,
)

FEATURE_ID = "synthesis"


class _FakeSynthesis:
    def __init__(
        self,
        revision_status: str,
        *,
        route_disposition: str | None = None,
        provider_failure: bool = False,
        baseline_warning: bool = False,
    ) -> None:
        self.revision_status = revision_status
        self.route_disposition = route_disposition
        self.provider_failure = provider_failure
        self.baseline_warning = baseline_warning
        self.calls: list[str] = []
        self.recheck_sizes: list[int] = []
        self.considered_ids: tuple[str, ...] = ()
        self.scenario_failure = False
        self.revision_failed = False
        self.fill_structures: list[tuple[Any, Any]] = []
        self.routes: tuple[ObligationRoute, ...] = ()
        self.scenario_envelopes: tuple[Any, ...] = ("scenario-1",)
        self.candidate_outcomes: tuple[Any, ...] | None = None
        self.plan: Any = None
        self.loss_analysis = baseline_loss_analysis()
        self.control_structure = baseline_control_structure()

    def prepare_capability(self, **_: Any) -> Any:
        return synthesis_capability_profile()

    def build_taxonomy_inputs(self, **_: Any) -> Any:
        return synthesis_taxonomy_inputs()

    def plan_obligations(self, *, taxonomy_inputs: Any, **_: Any) -> Any:
        self.calls.append("plan")
        self.plan = plan_taxonomy_obligations(taxonomy_inputs)
        return self.plan

    def baseline(self, **_: Any) -> Any:
        self.calls.append("baseline")
        result = SimpleNamespace(
            loss_analysis=self.loss_analysis,
            control_structure=self.control_structure,
        )
        if self.baseline_warning:
            result.stage_warnings = ("baseline warning remains unresolved",)
        return result

    def consider(self, *, briefs: tuple[Any, ...], **_: Any) -> Any:
        self.calls.append("consider")
        briefs = tuple(briefs)
        self.considered_ids = tuple(item.obligation_id for item in briefs)
        if self.provider_failure:
            disposition = "unresolved"
        else:
            disposition = self.route_disposition or (
                "targeted" if self.revision_status == "not_required" else "upstream_gap"
            )
        self.routes = obligation_routes(briefs, disposition)
        diagnostics = (
            ("local provider response could not be validated",)
            if self.provider_failure
            else ()
        )
        return RoutingRunResult(
            briefs=briefs,
            routes=self.routes,
            requests=(),
            call_evidence=(),
            diagnostics=diagnostics,
        )

    def revise(
        self,
        *,
        gaps: tuple[Any, ...],
        loss_analysis: Any,
        control_structure: Any,
        **_: Any,
    ) -> Any:
        self.calls.append("revise")
        if self.revision_status == "invalid":
            self.revision_failed = True
            raise ValueError("invalid deterministic revision response")
        return structural_revision(
            gaps,
            loss_analysis=loss_analysis,
            control_structure=control_structure,
            outcome=self.revision_status,
        )

    def recheck(self, *, briefs: tuple[Any, ...], **_: Any) -> Any:
        self.calls.append("recheck")
        briefs = tuple(briefs)
        self.recheck_sizes.append(len(briefs))
        return RoutingRunResult(
            briefs=briefs,
            routes=obligation_routes(briefs, "targeted"),
            requests=(),
            call_evidence=(),
        )

    def fill_icas(self, **kwargs: Any) -> Any:
        self.calls.append("ica")
        self.fill_structures.append(
            (kwargs.get("loss_analysis"), kwargs.get("control_structure"))
        )
        return "ica-enumeration"

    def scenarios(self, **_: Any) -> Any:
        self.calls.append("scenarios")
        if self.scenario_failure:
            raise RuntimeError("deterministic SP3 failure")
        return SimpleNamespace(
            scenario_envelopes=self.scenario_envelopes,
            candidate_outcomes=self.candidate_outcomes,
        )

    def account(self, *, plan, **_: Any) -> Any:
        self.calls.append("account")
        rows = tuple(
            SimpleNamespace(
                obligation_id=item.obligation_id,
                disposition=(
                    "capability_excluded"
                    if item.scope_disposition == "capability_excluded"
                    else "governance_only"
                    if item.scope_disposition == "governance_only"
                    else "unresolved"
                ),
            )
            for item in plan.obligations
        )
        return SimpleNamespace(
            rows=rows,
            summary=SimpleNamespace(addressed=0, total=len(rows)),
            model_dump=lambda **__: {
                "schema_version": "stpa-obligation-accounting-v1",
                "rows": [],
            },
        )

    def realize(self, **_: Any) -> Any:
        self.calls.append("realize")
        return SimpleNamespace(
            schema_version="stpa-scenario-realization-v1",
            records=(),
            summary=SimpleNamespace(total=0, realized=0, unresolved=0, not_requested=0),
            model_dump=lambda **__: {
                "schema_version": "stpa-scenario-realization-v1",
                "records": [],
                "summary": {
                    "total": 0,
                    "realized": 0,
                    "unresolved": 0,
                    "not_requested": 0,
                },
            },
        )


def _state(world: World) -> dict[str, Any]:
    return _feature_state(world, "synthesis_state")


def _h_fixture(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    state["output_dir"] = Path(
        __import__("tempfile").mkdtemp(prefix="synthesis-acceptance-")
    )
    state["fake"] = None
    state["result"] = None
    return True, ""


def _h_revision_mode(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    lowered = text.lower()
    status = (
        "invalid"
        if "invalid" in lowered
        else "rejected"
        if "rejected" in lowered
        else "not_required"
        if "not required" in lowered
        else "applied"
    )
    _state(world)["fake"] = _FakeSynthesis(status)
    return True, ""


def _h_route_mode(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    disposition = text.rsplit('"', 2)[1]
    # Only the upstream-gap disposition reaches revision; a rejected revision
    # keeps the initial routes final so the scenario observes them unchanged.
    _state(world)["fake"] = _FakeSynthesis("rejected", route_disposition=disposition)
    return True, ""


def _h_provider_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    _state(world)["fake"] = _FakeSynthesis("not_required", provider_failure=True)
    return True, ""


def _h_baseline_warning(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    _state(world)["fake"] = _FakeSynthesis("not_required", baseline_warning=True)
    return True, ""


def _h_candidate_mode(world: World, text: str, examples: dict) -> tuple[bool, str]:
    """Select explicit candidate terminal records for yield-status acceptance."""
    del examples
    mode = text.rsplit('"', 2)[1]
    fake = _FakeSynthesis("not_required")
    if mode == "no_candidates":
        fake.scenario_envelopes = ()
        fake.candidate_outcomes = ()
    elif mode == "zero_yield":
        fake.scenario_envelopes = ()
        fake.candidate_outcomes = tuple(
            SimpleNamespace(
                scenario_id=f"SCN-{index:03d}",
                ica_slot_id=f"RESP-{index}:CA-{index}-1:INCORRECT",
                ica_id=f"ICA-{index}",
                status="generation_failed",
                diagnostics=("provider contract failure",),
            )
            for index in (1, 2)
        )
    elif mode == "partial":
        fake.scenario_envelopes = ("scenario-1",)
        fake.candidate_outcomes = (
            SimpleNamespace(
                scenario_id="SCN-001",
                ica_slot_id="RESP-1:CA-1-1:INCORRECT",
                ica_id="ICA-1",
                status="published",
                diagnostics=(),
            ),
            SimpleNamespace(
                scenario_id="SCN-002",
                ica_slot_id="RESP-2:CA-2-1:INCORRECT",
                ica_id="ICA-2",
                status="rendering_failed",
                diagnostics=("rendering failed",),
            ),
            SimpleNamespace(
                scenario_id="SCN-003",
                ica_slot_id="RESP-3:CA-3-1:INCORRECT",
                ica_id="ICA-3",
                status="skipped",
                diagnostics=("not attempted",),
            ),
        )
    else:
        return False, f"unknown candidate outcome mode: {mode}"
    _state(world)["fake"] = fake
    return True, ""


def _run_fake(world: World, fake: _FakeSynthesis | None = None) -> Any:
    """Run the public composition seam with a deterministic adapter."""
    state = _state(world)
    selected = fake or state.get("fake")
    if selected is None:
        raise ValueError("synthesis fixture was not selected")
    state["fake"] = selected
    inputs = synthesis_inputs(
        state["output_dir"], use_case="A deterministic acceptance system"
    )
    result = run_synthesis(inputs, SynthesisAdapters.from_object(selected))
    state["result"] = result
    return result


def _h_run(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    _run_fake(world)
    return True, ""


def _h_stage_order(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    calls = _state(world)["fake"].calls
    if calls[:2] != ["plan", "baseline"]:
        return False, f"expected Phase 1 plan before baseline, got {calls}"
    return True, ""


def _h_recheck_all(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fake = _state(world)["fake"]
    if fake.recheck_sizes != [2] or fake.calls.count("recheck") != 1:
        return (
            False,
            f"expected one recheck over two applicable briefs, got {fake.recheck_sizes}",
        )
    return True, ""


def _h_no_recheck(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fake = _state(world)["fake"]
    if fake.calls.count("recheck") != 0:
        return False, "rejected revision unexpectedly triggered a recheck"
    return True, ""


def _h_sidecars(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    result = _state(world).get("result")
    if result is None:
        return False, "synthesis did not produce a result before sidecar verification"
    output_dir = result.output_dir
    expected = {
        PLAN_FILENAME,
        CONSIDERATION_FILENAME,
        ACCOUNTING_FILENAME,
        SCENARIO_REALIZATION_FILENAME,
        MANIFEST_FILENAME,
    }
    actual = {path.name for path in output_dir.iterdir()}
    if not expected.issubset(actual):
        return False, f"missing synthesis sidecars: {sorted(expected - actual)}"
    if any(path.name.endswith(".tmp") for path in output_dir.iterdir()):
        return False, "temporary synthesis artifact remains"
    return True, ""


def _h_report(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    report = _state(world)["result"].report_path
    if report is None:
        return False, "synthesis report is missing"
    rendered = report.read_text(encoding="utf-8")
    status = _state(world)["result"].manifest["run_status"]
    expected = f"<tr><th>Scenario generation status</th><td>{status}</td></tr>"
    if expected not in rendered:
        return False, f"synthesis report does not state run status {status!r}"
    return True, ""


def _h_considered_and_accounted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    fake = state["fake"]
    result = state["result"]
    if result is None:
        return (
            False,
            "synthesis did not produce a result before accounting verification",
        )
    applicable = applicable_obligation_ids(fake.plan)
    if len(applicable) != 2 or fake.considered_ids != applicable:
        return (
            False,
            f"expected both applicable obligations to be considered, got {fake.considered_ids}",
        )
    by_id = {row.obligation_id: row.disposition for row in result.accounting.rows}
    if (
        by_id.get(obligation_id_for(fake.plan, "capability_excluded"))
        != "capability_excluded"
        or by_id.get(obligation_id_for(fake.plan, "governance_only"))
        != "governance_only"
    ):
        return False, f"excluded/governance obligations were not accounted: {by_id}"
    return True, ""


def _h_clean(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fake = _state(world)["fake"]
    if fake.calls.count("revise") or fake.calls.count("recheck"):
        return False, f"clean synthesis unexpectedly revised/rechecked: {fake.calls}"
    return True, ""


def _h_typed_route(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    expected = text.rsplit('"', 2)[1]
    routes = _state(world)["fake"].routes
    if not routes or any(
        not isinstance(route, ObligationRoute) or route.disposition != expected
        for route in routes
    ):
        return False, f"expected closed {expected} routes, got {routes!r}"
    return True, ""


def _h_route_not_coverage(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    routes = _state(world)["fake"].routes
    if not routes or any(not route.evidence for route in routes):
        return False, "route evidence was not retained"
    if any(hasattr(route, "coverage") for route in routes):
        return False, "STPA route evidence was conflated with taxonomy coverage"
    return True, ""


def _h_terminal_status(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    expected = text.rsplit('"', 2)[1]
    actual = _state(world)["result"].run_status
    return actual == expected, f"expected {expected}, got {actual}"


def _h_candidate_counts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del examples
    values = [int(value) for value in __import__("re").findall(r"\d+", text)]
    if len(values) != 5:
        return False, f"expected five candidate counts, got {values}"
    requested, attempted, published, failed, skipped = values
    counts = _state(world)["result"].manifest["scenario_counts"]
    actual = (
        counts.get("requested"),
        counts.get("attempted"),
        counts.get("generated"),
        counts.get("failed"),
        counts.get("skipped"),
    )
    expected = (requested, attempted, published, failed, skipped)
    return actual == expected, f"expected {expected}, got {actual}"


def _h_yield_artifacts(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    result = _state(world)["result"]
    expected = {
        PLAN_FILENAME,
        CONSIDERATION_FILENAME,
        ACCOUNTING_FILENAME,
        SCENARIO_REALIZATION_FILENAME,
        MANIFEST_FILENAME,
    }
    present = {path.name for path in result.output_dir.iterdir()}
    return expected.issubset(
        present
    ), f"missing artifacts: {sorted(expected - present)}"


def _h_baseline_retained(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fake = _state(world)["fake"]
    if len(fake.fill_structures) != 1 or any(
        seen is not baseline
        for seen, baseline in zip(
            fake.fill_structures[0], (fake.loss_analysis, fake.control_structure)
        )
    ):
        return (
            False,
            f"invalid revision changed baseline inputs: {fake.fill_structures}",
        )
    return True, ""


def _h_invalid_no_recheck(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fake = _state(world)["fake"]
    if fake.calls.count("recheck"):
        return False, "invalid revision unexpectedly triggered a recheck"
    return True, ""


def _h_revision_diagnostic(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    result = _state(world)["result"]
    revision_status = getattr(
        getattr(result.consideration, "revision", None), "status", None
    )
    if revision_status != "technical_failure" or not result.stage_errors:
        return False, "invalid revision was not retained as a technical diagnostic"
    return True, ""


def _h_provider_unresolved(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fake = _state(world)["fake"]
    if not fake.routes or any(
        route.disposition != "unresolved" for route in fake.routes
    ):
        return False, "provider failure did not remain as unresolved route evidence"
    return True, ""


def _h_baseline_warning_persisted(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    result = state.get("result")
    if result is None:
        return (
            False,
            "synthesis did not produce a result before diagnostics verification",
        )
    expected = "Baseline stage_warnings: baseline warning remains unresolved"
    manifest_path = result.output_dir / MANIFEST_FILENAME
    manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if expected not in (manifest or {}).get("stage_warnings", ()):
        return False, "baseline warning was not persisted in the synthesis manifest"
    report = result.report_path
    if report is None:
        return False, "synthesis report is missing"
    rendered = report.read_text(encoding="utf-8")
    if "Analysis diagnostics" not in rendered:
        return False, "analysis diagnostics section is missing from the report"
    if html.escape(expected) not in rendered:
        return False, "baseline warning is missing from the escaped report"
    return True, ""


def _h_baseline_warning_yield(
    world: World, text: str, examples: dict
) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    result = state.get("result")
    if result is None:
        return False, "synthesis did not produce a result before yield verification"
    published = len(result.scenario_envelopes)
    generated = (result.manifest or {}).get("scenario_counts", {}).get("generated")
    if published != 1 or generated != published:
        return (
            False,
            f"baseline diagnostics changed published yield: {published}/{generated}",
        )
    return True, ""


def _h_scenario_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    fake = state["fake"]
    fake.scenario_failure = True
    # Execute the same public run seam after toggling the deterministic SP3
    # failure.  ICA/accounting are still required to complete.
    _h_run(world, "the product run executes", {})
    result = state["result"]
    if not result.stage_errors or "account" not in fake.calls:
        return False, "scenario failure erased downstream accounting"
    return True, ""


def _h_product_surface(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del world, text, examples
    from asago_scenario_generator.cli import app

    # Typer leaves ``name`` unset for commands registered with the decorator's
    # default.  Resolve those through the callback so this public compatibility
    # check observes the same names users see at the command line.
    names = {
        command.name
        or getattr(command.callback, "__name__", "")
        .removesuffix("_cmd")
        .replace("_", "-")
        for command in app.registered_commands
    }
    required = {"generate"}
    retired = {"run", "resume", "synthesis-run", "report", "eval"}
    if not required.issubset(names):
        return False, f"STPA execution commands missing: {sorted(names)}"
    present_retired = retired.intersection(names)
    if present_retired:
        return False, f"retired commands remain registered: {sorted(present_retired)}"
    return True, ""


def register(api: Any) -> None:
    """Register synthesis feature steps."""
    api.set_feature(FEATURE_ID)
    api.register(r"a deterministic synthesis fixture is available", _h_fixture)
    api.register(
        r"a deterministic synthesis revision is (applied|rejected|not required|invalid)",
        _h_revision_mode,
    )
    api.register(
        r'a deterministic synthesis route disposition "(targeted|proposed_not_applicable|upstream_gap|unresolved)"',
        _h_route_mode,
    )
    api.register(
        r"a deterministic synthesis provider fails during consideration",
        _h_provider_failure,
    )
    api.register(
        r"a deterministic synthesis baseline has an unresolved warning",
        _h_baseline_warning,
    )
    api.register(
        r'a deterministic synthesis candidate outcome set "(no_candidates|zero_yield|partial)"',
        _h_candidate_mode,
    )
    api.register(r"the product run executes", _h_run)
    api.register(r"Phase 1 planning runs before baseline STPA", _h_stage_order)
    api.register(
        r"the synthesis recheck covers every applicable obligation exactly once",
        _h_recheck_all,
    )
    api.register(
        r"the synthesis performs no recheck after a rejected revision", _h_no_recheck
    )
    api.register(
        r"the synthesis writes the five normative sidecars atomically", _h_sidecars
    )
    api.register(
        r"the synthesis still writes accounting and manifest sidecars", _h_sidecars
    )
    api.register(
        r"the synthesis report states the scenario generation status",
        _h_report,
    )
    api.register(
        r"applicable and non-applicable obligations are accounted separately",
        _h_considered_and_accounted,
    )
    api.register(r"the clean synthesis has no revision or recheck", _h_clean)
    api.register(
        r'the synthesis returns a typed "(targeted|proposed_not_applicable|upstream_gap|unresolved)" route',
        _h_typed_route,
    )
    api.register(
        r"the route evidence remains separate from taxonomy coverage",
        _h_route_not_coverage,
    )
    api.register(
        r'the synthesis terminal status is "(completed|no_candidates|failed|degraded)"',
        _h_terminal_status,
    )
    api.register(
        r"synthesis candidate counts are requested (\d+) attempted (\d+) published (\d+) failed (\d+) skipped (\d+)",
        _h_candidate_counts,
    )
    api.register(
        r"the synthesis diagnostic and accounting artifacts remain available",
        _h_yield_artifacts,
    )
    api.register(
        r"the synthesis retains the baseline after the revision failure",
        _h_baseline_retained,
    )
    api.register(
        r"the synthesis performs no recheck after the invalid revision",
        _h_invalid_no_recheck,
    )
    api.register(
        r"the invalid revision remains a typed technical diagnostic",
        _h_revision_diagnostic,
    )
    api.register(
        r"the provider failure is retained as local unresolved evidence",
        _h_provider_unresolved,
    )
    api.register(
        r"the baseline warning survives the persisted manifest and report",
        _h_baseline_warning_persisted,
    )
    api.register(
        r"the published candidate count remains unchanged",
        _h_baseline_warning_yield,
    )
    api.register(r"scenario generation fails after ICA", _h_scenario_failure)
    api.register(
        r"generate is the normal command and retired generation commands are absent",
        _h_product_surface,
    )


__all__ = ["FEATURE_ID", "register"]
