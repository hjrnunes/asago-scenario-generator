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
- `pipeline.leaf_budget`.

These helpers do not construct provider clients or author scenarios.

## Removed read-only historical seam

Decision 52 removed the manifest-v3 read-only seam that earlier audits retained
for catalog qualification and inspection of old artifact directories. The
repository no longer contains:

- the `qualify-catalog` and `validate-catalog-qualification` commands, with
  `catalog_qualification` and `pipeline.qualification_metrics`;
- manifest models, resolution, and completion validation (`manifest_models`,
  `manifest_resolver`, `manifest_errors`);
- persistence record models and inventory validation
  (`pipeline.persistence*`);
- `finalization_contracts`, `finalization_gate_contracts`, and
  `models.scorecard`; and
- the JSON schemas for the coverage plan, finalization inventory, planning
  checkpoint, quarantine bundle, and catalog-qualification contracts.

No code reads or validates a manifest-v3 run directory. `manifest.py` keeps
only `write_text_atomically` and `write_bytes_atomically`, which the product
writers use.

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
