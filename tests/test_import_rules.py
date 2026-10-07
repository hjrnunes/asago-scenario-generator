"""Import rules of the producer package, as data.

Three tables drive the tests:

* ``RULES`` -- per-module rules: what a module or package may not import
  (``forbidden``), may import (``allowed``), or must import (``required``).
* ``LAYER_TABLES`` -- layer numbers per module; a module may import only
  modules on its own layer or below. Add a row when you add a module to a
  layered package; ``test_every_module_has_a_layer_row`` fails for a module
  without one.
* every module under ``asago_scenario_generator`` imports on its own.

Modules come from ``pkgutil.walk_packages``, so a new module joins its package's
rules without a list edit. Matching is by dotted name: ``a.b`` covers ``a.b`` and
everything under it unless the rule sets ``exact``.
"""

from __future__ import annotations

import ast
import importlib
import pkgutil
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path

import pytest

import asago_scenario_generator

PACKAGE = "asago_scenario_generator"
SRC_ROOT = Path(asago_scenario_generator.__file__).resolve().parent
FACADE = "__init__"

STPA = f"{PACKAGE}.stpa"
INFRA = f"{STPA}.infra"
MODELS = f"{STPA}.models"
SYSTEM_MODEL = f"{STPA}.system_model"
SCENARIO_PROD = f"{STPA}.scenario_prod"
STAGE5 = f"{SCENARIO_PROD}.stage5"
PUBLIC_MODELS = f"{PACKAGE}.models"
PIPELINE = f"{PACKAGE}.pipeline"
DATA = f"{PACKAGE}.data"


@dataclass(frozen=True)
class SourceModule:
    name: str
    path: Path
    is_package: bool


@cache
def source_modules() -> dict[str, SourceModule]:
    """Every module of the package, found by walking it."""
    found = {
        PACKAGE: SourceModule(PACKAGE, SRC_ROOT / "__init__.py", True),
    }
    for info in pkgutil.walk_packages([str(SRC_ROOT)], prefix=f"{PACKAGE}."):
        relative = Path(*info.name.split(".")[1:])
        path = (
            SRC_ROOT / relative / "__init__.py"
            if info.ispkg
            else SRC_ROOT / relative.with_suffix(".py")
        )
        found[info.name] = SourceModule(info.name, path, info.ispkg)
    return found


def _under(name: str, root: str) -> bool:
    return name == root or name.startswith(root + ".")


def _absolute_imports(module: SourceModule) -> set[str]:
    """Absolute names a module imports, with relative imports resolved.

    ``from pkg import name`` also counts ``pkg.name`` when that is a module, and
    counts ``pkg`` itself only when it imports something that is not a module.
    """
    known = source_modules()
    package = module.name if module.is_package else module.name.rpartition(".")[0]
    tree = ast.parse(module.path.read_text(encoding="utf-8"), filename=str(module.path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                parts = package.split(".")
                parts = parts[: len(parts) - (node.level - 1)]
                base = ".".join([*parts, *([node.module] if node.module else [])])
            else:
                base = node.module or ""
            submodules = {
                alias.name for alias in node.names if f"{base}.{alias.name}" in known
            }
            found.update(f"{base}.{name}" for name in submodules)
            if any(alias.name not in submodules for alias in node.names):
                found.add(base)
    return found


def _internal_imports(path: Path, prefix: str) -> set[str]:
    """First component below ``prefix`` of each import under it.

    Importing a name from ``prefix`` itself yields ``FACADE``.
    """
    module = next(m for m in source_modules().values() if m.path == path)
    result: set[str] = set()
    for name in _absolute_imports(module):
        if name == prefix:
            result.add(FACADE)
        elif name.startswith(prefix + "."):
            result.add(name[len(prefix) + 1 :].split(".")[0])
    return result


def _modules_in(scope: str) -> list[SourceModule]:
    return [m for m in source_modules().values() if _under(m.name, scope)]


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    """One import rule over a module, a package, or several of them.

    ``scope`` names modules; a package name covers every module under it.
    ``forbidden`` names modules (and everything under them) that may not be
    imported. ``allowed``, when set, lists the only imports permitted among the
    imports under ``within`` (all imports when ``within`` is unset); with
    ``exact`` an entry matches only itself. ``required`` modules must be
    imported by every module in scope.
    """

    name: str
    scope: str | tuple[str, ...]
    reason: str
    forbidden: tuple[str, ...] = ()
    allowed: tuple[str, ...] | None = None
    within: str | None = None
    exact: bool = False
    required: tuple[str, ...] = ()
    scopes: tuple[str, ...] = field(init=False, default=())

    def __post_init__(self) -> None:
        scope = (self.scope,) if isinstance(self.scope, str) else self.scope
        object.__setattr__(self, "scopes", scope)

    def modules(self) -> list[SourceModule]:
        return [m for scope in self.scopes for m in _modules_in(scope)]

    def violations(self, module: SourceModule) -> list[str]:
        imports = _absolute_imports(module)
        found: list[str] = []
        for name in sorted(imports - {"__future__"}):
            if any(_under(name, root) for root in self.forbidden):
                found.append(f"imports {name}: forbidden")
            if self.allowed is not None and (
                self.within is None or _under(name, self.within)
            ):
                permitted = (
                    name in self.allowed
                    if self.exact
                    else any(_under(name, root) for root in self.allowed)
                )
                if not permitted:
                    found.append(f"imports {name}: not in the allowed list")
        found.extend(
            f"does not import {name}" for name in self.required if name not in imports
        )
        return found


IO_NEAR = (
    f"{PACKAGE}.prompts",
    f"{PACKAGE}.manifest",
    f"{PACKAGE}.report",
    f"{PACKAGE}.cli",
    STPA,
)
LEGACY_PIPELINE = (
    f"{PIPELINE}",
    f"{PACKAGE}.prompts",
    DATA,
    f"{PACKAGE}.models.stage",
    f"{PACKAGE}.report",
    f"{PACKAGE}.cli",
    f"{PACKAGE}.config",
    f"{PACKAGE}.io",
)
STAGE_MODULES = tuple(
    f"{SYSTEM_MODEL}.{name}"
    for name in ("loss_analysis", "profile", "control_structure", "heuristics")
)
ATTACK_PATTERN_FACADE = f"{PUBLIC_MODELS}.attack_pattern"
PROJECTION_IMPLEMENTATIONS = tuple(
    f"{PIPELINE}.projection_{name}"
    for name in (
        "allocation",
        "allocator",
        "authoritative",
        "candidates",
        "qualification",
        "relations",
        "requirements",
        "resources",
    )
)
PROJECTION_CONTRACTS = f"{PIPELINE}.projection_contracts"
OBLIGATION_OUTPUT = f"{PUBLIC_MODELS}.obligation_plan"
OBLIGATION_INPUT = f"{PIPELINE}.obligation_contracts"
OBLIGATION_PLANNER = f"{PIPELINE}.obligation_planner"
OBLIGATION_PERSISTENCE = f"{PIPELINE}.obligation_persistence"

RULES: list[Rule] = [
    # stpa/infra: a clean copy, independent of the legacy pipeline
    Rule(
        "infra-clean-copy",
        INFRA,
        "the clean-copy decision: importing the legacy pipeline would re-couple "
        "the STPA pipeline to the manifest system and the hardcoded template loader",
        forbidden=(
            PIPELINE,
            f"{PACKAGE}.prompts",
            DATA,
            f"{PACKAGE}.models.capability_profile",
            f"{PACKAGE}.models.risk_card",
            f"{PACKAGE}.models.stage",
            f"{PACKAGE}.report",
            f"{PACKAGE}.cli",
            f"{PACKAGE}.config",
            f"{PACKAGE}.io",
        ),
    ),
    Rule(
        "infra-allowed-imports",
        INFRA,
        "infra modules import only stpa, the shared leaves, the standard "
        "library, and the model-client dependencies",
        allowed=(
            STPA,
            f"{PACKAGE}.strict_schema",
            f"{PACKAGE}.model_profiles",
            "openai",
            "httpx",  # the OpenAI SDK's transport: its exceptions carry httpx objects
            "pydantic",
            "yaml",
            "jinja2",
            "hashlib",
            "json",
            "os",
            "time",
            "datetime",
            "pathlib",
            "typing",
            "functools",
            "enum",
            "dataclasses",
            "abc",
            "collections",
            "io",
            "re",
            "copy",
            "math",
            "itertools",
            "contextlib",
            "contextvars",
            "argparse",
            "threading",
            "concurrent",
        ),
    ),
    Rule(
        "infra-below-id-normalization",
        INFRA,
        "tolerant LLM parsing stays in infra; ID policy is not pulled downward",
        forbidden=(f"{SYSTEM_MODEL}.id_normalization",),
    ),
    Rule(
        "stpa-model-profiles-reexports-shared-leaf",
        f"{INFRA}.model_profiles",
        "the historical STPA import path keeps its public name without owning "
        "the loader",
        required=(f"{PACKAGE}.model_profiles",),
    ),
    Rule(
        "shared-model-profiles-leaf",
        f"{PACKAGE}.model_profiles",
        "the YAML loader is a shared leaf, not a workflow implementation",
        forbidden=(PIPELINE, *IO_NEAR),
    ),
    # stpa/models: boundary schemas, the lowest layer
    Rule(
        "stpa-models-below-workflows",
        MODELS,
        "boundary models stay free of the pipeline that consumes them",
        forbidden=(SCENARIO_PROD, f"{STPA}.report", SYSTEM_MODEL),
    ),
    Rule(
        "validation-helper-imports-no-model",
        f"{MODELS}._validation",
        "_validation is the lowest shared helper and may be imported by any model",
        forbidden=(MODELS,),
    ),
    Rule(
        "enriched-threat-set-is-pure-data",
        f"{MODELS}.enriched_threat_set",
        "a pure data model with no stpa model imports",
        forbidden=(MODELS,),
    ),
    Rule(
        "loss-analysis-model-below-higher-models",
        f"{MODELS}.loss_analysis",
        "loss analysis precedes every later boundary model",
        forbidden=tuple(
            f"{MODELS}.{name}"
            for name in (
                "control_structure",
                "ica_enumeration",
                "enriched_threat_set",
                "scenario_spec",
                "scenario_envelope",
            )
        ),
    ),
    Rule(
        "control-structure-model-below-higher-models",
        f"{MODELS}.control_structure",
        "the control structure precedes ICA enumeration and later models",
        forbidden=tuple(
            f"{MODELS}.{name}"
            for name in (
                "ica_enumeration",
                "enriched_threat_set",
                "scenario_spec",
                "scenario_envelope",
            )
        ),
    ),
    # stpa/system_model
    Rule(
        "system-model-clean-copy",
        SYSTEM_MODEL,
        "the clean-copy decision: no coupling to the legacy pipeline",
        forbidden=LEGACY_PIPELINE,
    ),
    Rule(
        "system-model-pipeline-contract-types",
        SYSTEM_MODEL,
        "CapabilityProfile and RiskCard cross the STPA boundary by design; "
        "no other legacy model may",
        allowed=(
            f"{PUBLIC_MODELS}.capability_profile",
            f"{PUBLIC_MODELS}.risk_card",
        ),
        within=PUBLIC_MODELS,
        exact=True,
    ),
    Rule(
        "system-model-constants-leaf",
        f"{SYSTEM_MODEL}._constants",
        "constants import nothing but pathlib",
        allowed=("pathlib",),
        exact=True,
    ),
    Rule(
        "system-model-stages-stay-independent",
        STAGE_MODULES,
        "stage modules neither import each other nor the critic or orchestrator",
        forbidden=(*STAGE_MODULES, f"{SYSTEM_MODEL}.critic", f"{SYSTEM_MODEL}.run"),
    ),
    Rule(
        "system-model-heuristics-is-pure",
        f"{SYSTEM_MODEL}.heuristics",
        "a pure post-check imports no system_model module",
        forbidden=(SYSTEM_MODEL,),
    ),
    Rule(
        "system-model-critic-below-run",
        f"{SYSTEM_MODEL}.critic",
        "the critic stitches revisions, then delegates published IDs to the leaf "
        "normalizer, and stays below the orchestrator",
        forbidden=(f"{SYSTEM_MODEL}.run",),
        required=(f"{SYSTEM_MODEL}.id_normalization",),
    ),
    Rule(
        "system-model-id-normalization-is-a-leaf",
        f"{SYSTEM_MODEL}.id_normalization",
        "high-level ID policy has no sibling or IO-near imports",
        forbidden=(SYSTEM_MODEL, INFRA),
    ),
    Rule(
        "system-model-control-structure-uses-leaf-normalizer",
        f"{SYSTEM_MODEL}.control_structure",
        "stage 2 uses the leaf normalizer internally",
        required=(f"{SYSTEM_MODEL}.id_normalization",),
    ),
    # stpa/scenario_prod
    Rule(
        "scenario-prod-constants-leaf",
        f"{SCENARIO_PROD}._constants",
        "constants import nothing but pathlib",
        allowed=("pathlib",),
        exact=True,
    ),
    Rule(
        "scenario-prod-stages-below-reporting",
        (f"{SCENARIO_PROD}.assembly", f"{SCENARIO_PROD}.validators"),
        "stage modules stay below evaluation, coverage, and the orchestrator",
        forbidden=tuple(
            f"{SCENARIO_PROD}.{n}" for n in ("eval_metrics", "coverage", "run")
        ),
    ),
    Rule(
        "scenario-prod-eval-metrics-below-run",
        f"{SCENARIO_PROD}.eval_metrics",
        "evaluation metrics do not import the orchestrator",
        forbidden=(f"{SCENARIO_PROD}.run",),
    ),
    Rule(
        "scenario-prod-enrichment-is-a-model-layer-leaf",
        f"{SCENARIO_PROD}.enrichment",
        "enrichment computes deterministic blocks from models and the capability "
        "profile; it imports no scenario_prod module",
        allowed=(
            MODELS,
            f"{PUBLIC_MODELS}.capability_profile",
            "typing",
            "pydantic",
        ),
    ),
    Rule(
        "scenario-prod-stage5-below-run",
        STAGE5,
        "stage 5 prompt assembly stays below the orchestrator",
        forbidden=(f"{SCENARIO_PROD}.run",),
    ),
    # models, pipeline, data: the attack-pattern split
    Rule(
        "attack-pattern-leaves-stay-inward-and-offline",
        tuple(
            f"{PUBLIC_MODELS}.attack_pattern_{name}"
            for name in ("contracts", "digests", "chain", "projection", "validation")
        ),
        "responsibility modules stay free of the public facade and of IO",
        forbidden=(ATTACK_PATTERN_FACADE, PIPELINE, *IO_NEAR),
    ),
    Rule(
        "attack-pattern-consumers-skip-the-facade",
        (
            f"{DATA}.taxonomy_pins",
            *(
                f"{PIPELINE}.projection_{name}"
                for name in (
                    "allocation",
                    "allocator",
                    "candidates",
                    "qualification",
                    "relations",
                    "requirements",
                    "resources",
                )
            ),
        ),
        "adapters reach types through the responsibility leaves",
        forbidden=(ATTACK_PATTERN_FACADE,),
    ),
    Rule(
        "projection-contracts-are-a-leaf",
        PROJECTION_CONTRACTS,
        "the contract leaf imports no implementation module and no IO",
        forbidden=(*PROJECTION_IMPLEMENTATIONS, *IO_NEAR),
    ),
    Rule(
        "projection-adapters-import-the-contract-leaf",
        tuple(
            f"{PIPELINE}.projection_{name}"
            for name in (
                "resources",
                "requirements",
                "qualification",
                "candidates",
                "relations",
                "allocation",
                "allocator",
            )
        ),
        "adapters reach shared types through the contract leaf",
        required=(PROJECTION_CONTRACTS,),
    ),
    # threat scope
    Rule(
        "threat-scope-contract-stays-in-the-model-layer",
        f"{PUBLIC_MODELS}.threat_scope",
        "the contract imports only models and pydantic, never data or pipeline",
        allowed=(PUBLIC_MODELS, "pydantic", "typing"),
    ),
    Rule(
        "data-below-pipeline",
        DATA,
        "the taxonomy and gating layer never imports pipeline modules",
        forbidden=(PIPELINE,),
    ),
    Rule(
        "threat-gating-stays-offline",
        f"{DATA}.threat_gating",
        "gating logic stays free of IO and framework modules",
        forbidden=IO_NEAR,
    ),
    # obligation plan
    Rule(
        "obligation-plan-output-uses-shared-leaves",
        OBLIGATION_OUTPUT,
        "the persisted model depends only on shared contract leaves",
        allowed=(
            f"{PUBLIC_MODELS}.attack_pattern_contracts",
            f"{PUBLIC_MODELS}.attack_pattern_projection",
            f"{PUBLIC_MODELS}.canonical",
        ),
        within=PACKAGE,
        exact=True,
    ),
    Rule(
        "obligation-input-contract-stays-inward",
        OBLIGATION_INPUT,
        "input definitions do not reach the planner, persistence, or CLI adapters",
        forbidden=(OBLIGATION_PLANNER, OBLIGATION_PERSISTENCE, f"{PACKAGE}.cli"),
    ),
    Rule(
        "obligation-planner-uses-domain-and-projection-leaves",
        OBLIGATION_PLANNER,
        "the planner uses domain and projection contracts, never delivery code",
        allowed=(
            PIPELINE,
            OBLIGATION_OUTPUT,
            OBLIGATION_INPUT,
            f"{PUBLIC_MODELS}.attack_pattern_chain",
            f"{PUBLIC_MODELS}.attack_pattern_contracts",
            ATTACK_PATTERN_FACADE,
            f"{PUBLIC_MODELS}.canonical",
            f"{PIPELINE}.projection_authoritative",
            PROJECTION_CONTRACTS,
            f"{PIPELINE}.projection_qualification",
        ),
        within=PACKAGE,
        exact=True,
        required=(OBLIGATION_INPUT, OBLIGATION_OUTPUT),
    ),
    Rule(
        "obligation-persistence-depends-inward-on-core",
        OBLIGATION_PERSISTENCE,
        "the persistence adapter consumes the typed plan output and nothing "
        "of the input contract or the CLI",
        forbidden=(OBLIGATION_INPUT, f"{PACKAGE}.cli"),
        required=(OBLIGATION_OUTPUT,),
    ),
]


def _rule_cases() -> list:
    return [pytest.param(rule, id=rule.name) for rule in RULES]


@pytest.mark.parametrize("rule", _rule_cases())
def test_module_follows_import_rule(rule: Rule) -> None:
    modules = rule.modules()
    assert modules, f"rule scope {rule.scopes} matches no module"
    violations = [
        f"{module.name} {problem}"
        for module in modules
        for problem in rule.violations(module)
    ]
    assert not violations, f"{rule.reason}:\n" + "\n".join(violations)


# ---------------------------------------------------------------------------
# Layers
# ---------------------------------------------------------------------------

# Lower number = lower level. A module may import modules on its own layer or
# below. Add a row here when you add a module.
STPA_MODEL_LAYERS: dict[str, int] = {
    "_validation": 0,
    "semantic_conditions": 0,
    "execution_classification": 0,
    "causal_factor": 1,
    "loss_analysis": 1,
    "control_structure": 1,
    "enriched_threat_set": 1,
    "ica_enumeration": 2,
    "scenario_context": 2,
    "scenario_spec": 3,
    "omission_evidence": 3,
    "run_identity": 0,
    "scenario_envelope": 4,
    # A pure dataclass leaf over the standard library; only scenario_prod
    # modules import it.
    "target_subject_model": 0,
}

SYSTEM_MODEL_LAYERS: dict[str, int] = {
    "semantic_review": 0,
    "_constants": 0,
    "id_normalization": 0,
    "loss_analysis_repair": 0,
    "rule_span_repair": 0,
    "heuristics": 1,
    "loss_analysis": 1,
    "loss_analysis_gates": 2,
    "risk_coverage_review": 2,
    "profile": 1,
    "target_evidence": 0,
    "risk_actionability": 1,
    "stated_rule_coverage": 1,
    "control_structure": 1,
    "critic": 2,
    "reply_constraint_placement": 2,
    "run": 3,
}

SCENARIO_PROD_LAYERS: dict[str, int] = {
    "target_observations": 0,
    "outcome_grounding": 0,
    # Discriminating-condition resolution depends only on models and the
    # target-observation snapshot; its state index depends only on models.
    "condition_check": 0,
    "condition_index": 0,
    # Tool-call binding resolves fact operands through condition_check only.
    "tool_call_binding": 0,
    # Realized-operation lookup is a pure leaf over the realization model;
    # condition families derive hints from it, the state index, and the
    # observation snapshot.
    "realized_operation": 0,
    "condition_family": 0,
    "presentation": 1,
    "_constants": 0,
    "enrichment": 0,
    "context": 0,
    # Phase 3 content-surface facts: a pure leaf over the IO capability model.
    "content_surface": 0,
    # The v4 attack shape is a pure pydantic leaf; the handoff embeds it.
    "attack_shape": 0,
    "assembly": 1,
    "stage5": 1,
    "validators": 1,
    "execution_classification": 1,
    # The versioned scenario handoff is the normal publication seam: a pure
    # projection over the scenario envelope and its models.
    "handoff": 1,
    # Deterministic scenario identity is a pure projection over ScenarioSpec.
    "deduplication": 1,
    # Target-profile publication is an atomic IO writer over the profile model.
    "target_profile_publication": 2,
    "eval_metrics": 2,
    "coverage": 2,
    "run": 3,
}


@dataclass(frozen=True)
class LayerTable:
    """Layers for the modules directly in ``package``.

    Imports are judged by the first component below ``prefix``. A table with
    ``own`` fixes the layer of every scanned module (the stage5 package sits at
    one layer of its parent) and ignores imports of its own package.
    """

    name: str
    package: str
    layers: dict[str, int]
    prefix: str | None = None
    own: str | None = None

    def scanned(self) -> list[SourceModule]:
        return [
            m
            for m in source_modules().values()
            if m.name.rpartition(".")[0] == self.package
        ]


LAYER_TABLES = [
    LayerTable("stpa-models", MODELS, STPA_MODEL_LAYERS),
    LayerTable("system-model", SYSTEM_MODEL, SYSTEM_MODEL_LAYERS),
    LayerTable("scenario-prod", SCENARIO_PROD, SCENARIO_PROD_LAYERS),
    LayerTable(
        "scenario-prod-stage5",
        STAGE5,
        SCENARIO_PROD_LAYERS,
        prefix=SCENARIO_PROD,
        own="stage5",
    ),
]


@pytest.mark.parametrize("table", [pytest.param(t, id=t.name) for t in LAYER_TABLES])
def test_no_module_imports_a_higher_layer(table: LayerTable) -> None:
    prefix = table.prefix or table.package
    modules = table.scanned()
    assert modules, f"{table.package} has no modules"
    violations: list[str] = []
    for module in modules:
        short = module.name.rpartition(".")[2]
        own_layer = table.layers.get(table.own or short, 99)
        for imported in sorted(_internal_imports(module.path, prefix) - {FACADE}):
            if table.own and imported == table.own:
                continue
            target = table.layers.get(imported, 99)
            if target > own_layer:
                violations.append(
                    f"{short} (layer {own_layer}) imports {imported} (layer {target})"
                )
    assert not violations, "dependency direction violations:\n" + "\n".join(violations)


@pytest.mark.parametrize(
    "table",
    [pytest.param(t, id=t.name) for t in LAYER_TABLES if t.own is None],
)
def test_every_module_has_a_layer_row(table: LayerTable) -> None:
    unlisted = sorted(
        module.name.rpartition(".")[2]
        for module in table.scanned()
        if module.name.rpartition(".")[2] not in table.layers
    )
    assert not unlisted, f"modules of {table.package} without a layer row: {unlisted}"


@pytest.mark.parametrize("table", [pytest.param(t, id=t.name) for t in LAYER_TABLES])
def test_layer_rows_name_real_modules(table: LayerTable) -> None:
    prefix = table.prefix or table.package
    stale = sorted(
        name for name in table.layers if f"{prefix}.{name}" not in source_modules()
    )
    assert not stale, f"layer rows without a module: {stale}"


# ---------------------------------------------------------------------------
# Import cycles
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "module_name",
    [name for name in sorted(source_modules()) if not name.endswith(".__main__")],
)
def test_module_imports_cleanly(module_name: str) -> None:
    assert importlib.import_module(module_name) is not None
