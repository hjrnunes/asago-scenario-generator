# Legacy taxonomy generator cleanup inventory

Status: public execution retired  
Audit date: 2026-09-02

The former taxonomy-led scenario generator is not a supported workflow. Its
`generate`, `resume`, legacy `report`, and legacy `eval` commands have been
removed from the CLI. The obligation-aware STPA composition root and the
standalone STPA runner do not import the legacy runner or its generation
package.

This inventory records implementation that remains only so deletion can be
performed without accidentally removing inward taxonomy evidence used by the
product run.

## Retained legacy roots awaiting deletion

| Root | Why it remains in this cutover | Required action |
|---|---|---|
| `pipeline/runner.py`, `runner_run.py`, `runner_resume.py`, `runner_finalization.py` | Large legacy orchestration graph with dedicated unit and QA fixtures | Delete the runner graph and its runner-only tests after moving any generally useful manifest readers |
| `pipeline/generate/` | Legacy actor, narrative, attack-tree, behavior, and assembly implementation | Move any genuinely shared compiler primitive to a neutral inward module, then delete the package |
| `pipeline/finalization*.py` | Legacy candidate retry, admission, and persistence lifecycle | Delete with the runner; retain nothing merely for old resume compatibility |
| legacy `report/` sections and template, and legacy `eval/` adapters | Consume the retired manifest-v3 taxonomy scenario output | Delete after identifying report helpers used by Phase 2 or synthesis and moving those helpers inward |
| legacy manifest-v3 and persistence controllers | Read and write retired run directories | Retain only narrowly required read-only migration/audit models; delete execution and resume writers |
| taxonomy scenario-authoring prompt templates | Used only by the retired actor/narrative/tree/behavior calls | Delete with `pipeline/generate/` |
| taxonomy-generation acceptance features, QA scripts, and unit tests | Still protect internal legacy implementation while deletion is decomposed | Delete in the same slice as the source behavior they specify |

## Explicitly retained product inputs

These are not legacy scenario-generation code and must remain:

- reviewed risk loading and SSSOM/cross-taxonomy mapping;
- attack-pattern catalogs and semantic validation;
- capability profiles, capability-fact snapshots, and projection
  qualification;
- deterministic candidate projection needed to materialize obligation
  evidence;
- Phase 1 obligation models, planner, persistence, and CLI;
- STPA SP1, SP2, SP3, reporting, and execution projection;
- synthesis consideration, bounded revision, accounting, scenario
  realization, and Phase 2 verification; and
- offline Phase 2, Phase 3, and Phase 4 contracts.

## Reachability proof for the public cutover

Static import inspection found no import of the legacy
`asago_scenario_generator.pipeline.runner` or
`asago_scenario_generator.pipeline.generate` roots from:

- `pipeline.synthesis` and its adjacent synthesis modules;
- `cli.synthesis`;
- `cli.stpa_commands`; or
- the STPA implementation package.

The registered CLI therefore has no path to the legacy runner. Importing a
legacy source module manually is not a supported interface and must not be
used by new code.

## Deletion order

1. Remove legacy CLI and product compatibility assertions. **Done.**
2. Delete runner-only CLI tests and acceptance scenarios. **In progress.**
3. Delete legacy report/evaluation adapters and their acceptance surface.
4. Delete runner/resume/finalization orchestration and manifest writers.
5. Move any shared compiler leaves required outside the old stack.
6. Delete `pipeline/generate/`, its prompt templates, and its remaining tests.
7. Re-run static reachability and remove this inventory when no retained root
   remains.

No item in this inventory may regain a CLI command, be called by product
`run`, or become a dependency of STPA while deletion is pending.
