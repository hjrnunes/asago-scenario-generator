# Orchestration entry point — generation → artifact design → execution

One reusable entry point runs the complete end-to-end path for one target with
no manual file operations between stages:

```bash
cd <PRODUCER>
uv run python scripts/qualification/run_end_to_end.py \
    --output-dir build/adaptive-e2e/<fresh-run-name>
```

The executable form is `scripts/qualification/run_end_to_end.py` (producer
repo). It chains the documented per-stage CLIs:

| Stage | Command (as invoked by the script) | Publishes |
| --- | --- | --- |
| generation | `uv run asago-scenario-generator run …` over the registered staged MiniKlarna inputs | scenario handoff artifacts under `generation/scenarios/`, run manifest, call evidence |
| artifact | `uv run asago-artifact-generator design --handoff … --target-profile … --runtime-context …` (consumer worktree) | executable artifact, detector + fidelity record, freeze record, design manifest |
| execution | `<garak-venv>/bin/python scripts/qualification/garak_case_runner.py --case … --plan …` | `execution/qualification.json`, `execution/garak-attempts.jsonl` |

`<PRODUCER>` = this worktree; `<garak-venv>` =
`<WT>/.mission-runtime/garak-venv`. The script bridges the model settings
(profile `gemma4-oc`) into the consumer and runner child environments
silently; it never prints or logs endpoint or key values.

## Options

- `--domain` — registered target configuration (default: `klarna`).
- `--output-dir` — required; a fresh directory the script creates. The script
  refuses to overwrite an existing directory, and every attempt is preserved.
- `--max-design-attempts` — how many selected handoffs artifact design may
  try (default 3). Each attempted design is preserved with its typed
  exclusion or its compiled manifest.
- `--generation-dir` — reuse an existing generation output directory (its
  published scenarios and run manifest) instead of running the producer. The
  generation status reports `source: reused` after verifying the artifacts
  exist. Use this for failure-injection demonstrations that must vary only
  one variable (the stopped stack) relative to a normal run.

## Handoff selection (deterministic)

Artifact design consumes adversarial scenario handoffs only, ordered by: (1)
handoffs whose `documented_operations` name the domain's dangerous operation
(`process_refund` for MiniKlarna) first, then (2) scenario id order. The first
design that compiles is selected for execution; every attempt stays recorded
in the status report.

## Independent stage statuses

The script writes `run-status.json` in the output directory and prints the
three statuses on stdout:

```json
{
  "schema_version": "orchestration-status-v1",
  "target_domain": "klarna",
  "preflight": { "stack_listening": { "safe_mcp": true, "ogx": true } },
  "stages": {
    "generation": { "status": "success", "run_id": "…", "scenarios_published": 33 },
    "artifact":   { "status": "success", "selected_design_id": "SCN-026:design-1" },
    "execution":  { "status": "success", "evidence_dir": "…/execution" }
  }
}
```

Statuses are per stage and independent: a failure in one stage never erases
or conflates another stage's outcome. A stage that cannot run because an
upstream stage failed reports `not_run`; a stage that ran and failed reports
`failed` while the upstream stages keep their `success` statuses and their
published artifacts stay intact. The exit code is 0 only when all three
stages succeeded.

## Failure injection (independence demonstration)

With the mini-agents stack stopped, generation and artifact design still
complete — both consume staged files and never touch the live target — and
only the execution status reports failed:

```bash
<WT>/.mission-runtime/garak-venv/bin/python \
    scripts/qualification/run_recipe.py stop      # injection: stack stopped
uv run python scripts/qualification/run_end_to_end.py \
    --output-dir build/adaptive-e2e/<fresh-injected-run-name> \
    --generation-dir <normal-run>/generation
# expect: generation: success (reused), artifact: success, execution: failed
```

The stack is an execution-stage prerequisite, not a script stage. Reset it
with `run_recipe.py reset` (documented in `run-recipe.md`) before a run whose
execution stage should succeed; the script records stack availability in the
preflight block but does not manage the stack itself.

## Evidence layout

```
<output-dir>/
  run-status.json          the three independent stage statuses
  generation.log           producer run stdout/stderr
  generation/              producer run artifacts (scenarios/, run-manifest.yaml, calls.jsonl)
  artifact-design-<SCN>.log  one log per attempted design
  artifact/<SCN>/          consumer design output (design-manifest.json, <SCN>:design-1/)
  execution.log            garak runner stdout/stderr
  execution/               qualification.json, garak-attempts.jsonl
```
