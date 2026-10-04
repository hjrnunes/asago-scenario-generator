# Legacy taxonomy generator cleanup inventory

Status: cleanup complete
Audit date: 2026-09-02

The former taxonomy-led scenario generator has been removed. The repository
has no registered command, orchestration path, prompt set, report, evaluation
adapter, or acceptance surface capable of authoring a non-STPA scenario.

## Deleted execution surface

- the legacy taxonomy runner, resume, and finalization controllers;
- `pipeline/generate/` and its actor, narrative, attack-tree, behavior, and
  assembly stages;
- taxonomy scenario-authoring prompt templates and the old capability-profile
  inference stage;
- legacy report sections/templates and the legacy evaluation package;
- persistence writers and adapters used only to create or resume legacy runs;
- legacy source-influence scenario assembly/qualification adapters; and
- the corresponding CLI, features, QA scripts, and implementation tests.

Neutral helpers still required by active projection were moved to inward
modules before their former package was removed:

- `pipeline.actor_access`;
- `pipeline.narrative_access`;
- `pipeline.leaf_budget`; and
- `models.scorecard`.

These helpers do not construct provider clients or author scenarios.

## Retained read-only historical seam

Explicit audits of old artifact directories still need to parse and verify the
manifest-v3 format. The following contracts and
readers therefore remain:

- manifest models, resolution, and completion validation;
- persistence record models and inventory validation;
- `generation_contracts`, `finalization_contracts`, and
  `finalization_gate_contracts` as schema dependencies of those readers; and
- legacy scenario-envelope models required to validate historical inventory.

This seam is intentionally read-only. It has no CLI command, provider
construction, runner, resume controller, finalization controller, or artifact
writer. It may validate historical inventory; it may not create, extend, resume, or relabel a historical taxonomy scenario.

## Product inputs that remain

The following are current inputs to the STPA-led product and are not legacy
generation code:

- reviewed risk loading and pinned taxonomy mappings;
- attack-pattern catalogs and semantic validation;
- capability profiles, capability-fact snapshots, and projection
  qualification;
- deterministic candidate projection used to materialize obligation evidence;
- Phase 1 obligations and obligation-aware STPA synthesis;
- STPA SP1, SP2, SP3, reporting, and execution projection; and
- offline Phase 2, Phase 3, and Phase 4 verification contracts.

## Reachability result

The registered CLI exposes `run` as the sole normal scenario-generation
command and `stpa-run` as an advanced baseline diagnostic. Static import and
acceptance checks confirm that neither path imports a retired taxonomy runner
or `pipeline.generate` namespace. All scenarios are authored by STPA.
