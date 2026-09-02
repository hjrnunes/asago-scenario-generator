"""Deterministic acceptance handlers for the public synthesis composition root."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

from runtime_shared import World

from asago_scenario_generator.manifest import atomic_write_text

from asago_scenario_generator.models.obligation_consideration import (
    MissingStructuralConcept,
    ObligationRoute,
)

from asago_scenario_generator.pipeline.synthesis import (
    ACCOUNTING_FILENAME,
    CONSIDERATION_FILENAME,
    MANIFEST_FILENAME,
    PLAN_FILENAME,
    SCENARIO_REALIZATION_FILENAME,
    SynthesisAdapters,
    SynthesisInputs,
    run_synthesis,
)

FEATURE_ID = "synthesis"
_OBLIGATION_IDS = tuple(f"ob:v1:{digit * 64}" for digit in "1234")


def _plan() -> SimpleNamespace:
    obligations = (
        SimpleNamespace(
            obligation_id=_OBLIGATION_IDS[0],
            scope_disposition="applicable",
            qualification_disposition="missing_evidence",
        ),
        SimpleNamespace(
            obligation_id=_OBLIGATION_IDS[1],
            scope_disposition="applicable",
            qualification_disposition="ready",
        ),
        SimpleNamespace(
            obligation_id=_OBLIGATION_IDS[2],
            scope_disposition="capability_excluded",
            qualification_disposition="not_attempted",
        ),
        SimpleNamespace(
            obligation_id=_OBLIGATION_IDS[3],
            scope_disposition="governance_only",
            qualification_disposition="not_attempted",
        ),
    )
    return SimpleNamespace(
        obligations=obligations,
        semantic_digest="synthesis-acceptance-plan",
        model_dump=lambda **_: {
            "schema_version": "taxonomy-obligation-plan-v1",
            "obligations": [
                {
                    "obligation_id": row.obligation_id,
                    "scope_disposition": row.scope_disposition,
                    "qualification_disposition": row.qualification_disposition,
                }
                for row in obligations
            ],
        },
        assert_integrity=lambda: None,
    )


def _route(obligation_id: str, disposition: str) -> ObligationRoute:
    """Build one closed route for acceptance's deterministic fake adapter."""
    common = {
        "obligation_id": obligation_id,
        "evidence": (f"acceptance:{obligation_id}",),
    }
    if disposition == "targeted":
        common.update(
            slot_ids=(f"SLOT-{obligation_id}",),
            hazard_ids=(f"H-{obligation_id}",),
            constraint_ids=(f"C-{obligation_id}",),
        )
    elif disposition == "proposed_not_applicable":
        common.update(
            slot_ids=(f"SLOT-{obligation_id}",),
            rationale="The supplied structural inventory shows no applicable path.",
        )
    elif disposition == "upstream_gap":
        common.update(
            rationale="The baseline lacks a structural concept needed for analysis.",
            missing_concepts=(
                MissingStructuralConcept(
                    concept_type="hazard",
                    description="The hazard is not explicit in the baseline.",
                    evidence_refs=(f"acceptance:{obligation_id}:gap",),
                    obligation_id=obligation_id,
                ),
            ),
        )
    else:
        common["rationale"] = "The available structural evidence is insufficient."
    return ObligationRoute(disposition=disposition, **common)


class _FakeSynthesis:
    def __init__(
        self,
        revision_status: str,
        *,
        route_disposition: str | None = None,
        provider_failure: bool = False,
    ) -> None:
        self.revision_status = revision_status
        self.route_disposition = route_disposition
        self.provider_failure = provider_failure
        self.calls: list[str] = []
        self.recheck_sizes: list[int] = []
        self.considered_ids: tuple[str, ...] = ()
        self.scenario_failure = False
        self.revision_failed = False
        self.fill_structures: list[tuple[Any, Any]] = []
        self.routes: tuple[ObligationRoute, ...] = ()

    def plan(self, **_: Any) -> Any:
        self.calls.append("plan")
        return _plan()

    def baseline(self, **_: Any) -> Any:
        self.calls.append("baseline")
        return SimpleNamespace(
            loss_analysis="baseline-loss", control_structure="baseline-control"
        )

    def consider(self, *, briefs: tuple[Any, ...], **_: Any) -> Any:
        self.calls.append("consider")
        self.considered_ids = tuple(item.obligation_id for item in briefs)
        if self.provider_failure:
            disposition = "unresolved"
        else:
            disposition = self.route_disposition or (
                "targeted" if self.revision_status == "not_required" else "upstream_gap"
            )
        routes = tuple(_route(item.obligation_id, disposition) for item in briefs)
        self.routes = routes
        diagnostics = (
            ("local provider response could not be validated",)
            if self.provider_failure
            else ()
        )
        return SimpleNamespace(
            initial_routes=routes,
            final_routes=routes,
            diagnostics=diagnostics,
        )

    def revise(self, **_: Any) -> Any:
        self.calls.append("revise")
        if self.revision_status == "invalid":
            self.revision_failed = True
            raise ValueError("invalid deterministic revision response")
        return SimpleNamespace(
            status=self.revision_status,
            loss_analysis="revised-loss",
            control_structure="revised-control",
        )

    def recheck(self, *, briefs: tuple[Any, ...], **_: Any) -> Any:
        self.calls.append("recheck")
        self.recheck_sizes.append(len(briefs))
        return SimpleNamespace(
            final_routes=tuple(
                _route(item.obligation_id, "targeted") for item in briefs
            )
        )

    def fill_icas(self, **_: Any) -> Any:
        self.calls.append("ica")
        kwargs = _
        self.fill_structures.append(
            (kwargs.get("loss_analysis"), kwargs.get("control_structure"))
        )
        return "ica-enumeration"

    def scenarios(self, **_: Any) -> Any:
        self.calls.append("scenarios")
        if self.scenario_failure:
            raise RuntimeError("deterministic SP3 failure")
        return SimpleNamespace(scenario_envelopes=("scenario-1",))

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

    def verify_phase2(self, *, output_dir: Path, **_: Any) -> Any:
        self.calls.append("phase2")
        names = (
            "system-resource-map.yaml",
            "correspondence-proposals.yaml",
            "correspondence-reconciliation.yaml",
            "hybrid-coverage-assessment.yaml",
        )
        paths = {
            name: atomic_write_text(output_dir / name, "schema_version: acceptance\n")
            for name in names
        }
        return SimpleNamespace(
            status="awaiting_evidence",
            assessment=SimpleNamespace(
                diagnostics=SimpleNamespace(
                    accepted_relations=0,
                    taxonomy_unresolved=2,
                ),
                network_calls=0,
                model_calls=0,
            ),
            artifact_paths=paths,
        )


def _state(world: World) -> dict[str, Any]:
    value = getattr(world, "synthesis_state", None)
    if value is None:
        value = {}
        world.synthesis_state = value
    return value


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
    _state(world)["fake"] = _FakeSynthesis(
        "not_required", route_disposition=disposition
    )
    return True, ""


def _h_provider_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    _state(world)["fake"] = _FakeSynthesis("not_required", provider_failure=True)
    return True, ""


def _run_fake(world: World, fake: _FakeSynthesis | None = None) -> Any:
    """Run the public composition seam with a deterministic adapter."""
    state = _state(world)
    selected = fake or state.get("fake")
    if selected is None:
        raise ValueError("synthesis fixture was not selected")
    state["fake"] = selected
    inputs = SynthesisInputs(
        use_case="A deterministic acceptance system",
        risk_cards=({"risk_id": "risk-1"},),
        qualification_facts={"facts": []},
        output_dir=state["output_dir"],
        capability_profile="acceptance-profile",
        taxonomy_inputs="acceptance-taxonomy-inputs",
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
        "system-resource-map.yaml",
        "correspondence-proposals.yaml",
        "correspondence-reconciliation.yaml",
        "hybrid-coverage-assessment.yaml",
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
    if "Phase 2: taxonomy–STPA verification" not in rendered:
        return False, "Phase 2 synthesis report section is missing"
    if "awaiting_evidence" not in rendered:
        return False, "Phase 2 evidence status is missing"
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
    if fake.considered_ids != _OBLIGATION_IDS[:2]:
        return (
            False,
            f"expected both applicable obligations to be considered, got {fake.considered_ids}",
        )
    by_id = {row.obligation_id: row.disposition for row in result.accounting.rows}
    if (
        by_id.get(_OBLIGATION_IDS[2]) != "capability_excluded"
        or by_id.get(_OBLIGATION_IDS[3]) != "governance_only"
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


def _h_baseline_retained(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    fake = _state(world)["fake"]
    if fake.fill_structures != [("baseline-loss", "baseline-control")]:
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


def _h_scenario_failure(world: World, text: str, examples: dict) -> tuple[bool, str]:
    del text, examples
    state = _state(world)
    fake = state["fake"]
    fake.scenario_failure = True
    # Execute the same public run seam after toggling the deterministic SP3
    # failure.  ICA/accounting are still required to complete.
    _h_run(world, "synthesis-run executes", {})
    result = state["result"]
    if not result.stage_errors or "account" not in fake.calls:
        return False, "scenario failure erased downstream accounting"
    return True, ""


def _h_compatibility(world: World, text: str, examples: dict) -> tuple[bool, str]:
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
    if not {"generate", "stpa-run", "synthesis-run"}.issubset(names):
        return False, f"CLI compatibility commands missing: {sorted(names)}"
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
    api.register(r"synthesis-run executes", _h_run)
    api.register(r"Phase 1 planning runs before baseline STPA", _h_stage_order)
    api.register(
        r"the synthesis recheck covers every applicable obligation exactly once",
        _h_recheck_all,
    )
    api.register(
        r"the synthesis performs no recheck after a rejected revision", _h_no_recheck
    )
    api.register(
        r"the synthesis writes the nine normative sidecars atomically", _h_sidecars
    )
    api.register(
        r"the synthesis still writes accounting and manifest sidecars", _h_sidecars
    )
    api.register(
        r"the synthesis report includes non-blocking Phase 2 verification",
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
    api.register(r"scenario generation fails after ICA", _h_scenario_failure)
    api.register(r"existing generation commands remain compatible", _h_compatibility)


__all__ = ["FEATURE_ID", "register"]
