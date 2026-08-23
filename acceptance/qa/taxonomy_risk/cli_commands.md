# End-to-end QA: taxonomy/risk CLI command contracts

## Boundary

Drive only the public taxonomy-and-risk CLI commands:

```bash
uv run asago-scenario-generator generate \
  --use-case <text-or-@file> --risk-extraction <path> --sssom <path> ...
uv run asago-scenario-generator projection-preflight \
  --use-case <text-or-@file> --risk-extraction <path> --sssom <path> --profile <path>
uv run asago-scenario-generator report --output-dir <run-or-collection> [--output <path>]
uv run asago-scenario-generator eval --output-dir <run-or-collection> [--format yaml|json]
uv run asago-scenario-generator profile --use-case <text-or-@file> [--output <path>]
uv run asago-scenario-generator validate-catalog-qualification <artifact> --contract <matrix|campaign|report>
```

Do not import project modules and do not call `run_pipeline`, `run_profile_only`,
`run_projection_preflight`, `run_evaluation`, `generate_report`, or any other
project API. Capture stdout, stderr, and the exit status of every child
process, and keep every fixture in a fresh disposable workspace (one
`mktemp -d` per case). Keep the suite offline; never set
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`. The only network-adjacent surface is
the deterministic local OpenAI-compatible fixture endpoint used by the
`profile` case, and that endpoint must be loopback-only.

Scope pinning:

- `generate` is covered here only for its up-front input validation. Its
  run-outcome and exit-policy contract belongs to
  `features/taxonomy_cli_run_outcome.feature` and
  `acceptance/qa/taxonomy_risk/cli_run_outcome.md`; do not duplicate those
  examples.
- `stpa-report` and `validate-stpa-projection` stay consistent with the
  existing STPA QA suites (`acceptance/qa/stpa_report.py` and
  `acceptance/qa/stpa/execution_projection_production_wiring.py`); do not
  re-test them here.
- `report` and `eval` require an authoritative completed manifest-v3 run
  fixture; `eval` additionally requires the coverage-plan,
  finalization-inventory, and capability-profile manifest entries.

## Fixture records

- **Disposable workspace**: a temp directory with a `missing/` folder whose
  entries never exist, an output folder for written artifacts, and a
  use-case text file for `@file` references.
- **Offline input files**: a `risk-extraction.json` carrying at least one
  `ibm-risk-atlas` card, an SSSOM TSV mapping that card, and a reviewed
  `capability-profile.yaml` (the same input shapes the projection-readiness
  suites use; reading committed `data/taxonomies/` files as fixture sources
  is allowed, calling pipeline functions is not).
- **Qualification contracts**: `data/catalog-qualification-matrix-v1.yaml`
  is the committed reviewed matrix (a valid `matrix` contract); a corrupted
  copy (truncated bytes or a removed required key) is the invalid-input
  artifact.
- **Completed run fixture**: an authoritative completed manifest-v3 run
  directory as described in
  `acceptance/qa/taxonomy_risk/taxonomy_report_rendering.md` (hash-matching
  manifest inventories), extended with the coverage-plan and
  finalization-inventory artifacts `eval` requires.
- **Fixture endpoint**: a deterministic local OpenAI-compatible HTTP fixture
  that returns one valid capability profile for the `profile` stage, per the
  loopback pattern in `acceptance/qa/taxonomy_risk/cli_run_outcome.md`.

## Workflows

### QA-TCLC-01: generate rejects a missing risk-extraction file

1. Point `--risk-extraction` at a path inside `missing/`; keep the use case
   inline and every other input valid.
2. Run `generate`.

**Expected:** stderr contains `Error: risk-extraction file not found: <path>`.
The process exits `1`, no output collection directory is created, and no
pipeline work runs.

### QA-TCLC-02: generate rejects a missing SSSOM file

1. Point `--sssom` at a path inside `missing/`; keep the use case inline and
   every other input valid.
2. Run `generate`.

**Expected:** stderr contains `Error: SSSOM file not found: <path>`. The
process exits `1` and no output collection directory is created.

### QA-TCLC-03: generate rejects a missing @file use-case reference

1. Pass `--use-case @<missing>/use-case.txt`; keep every other input valid.
2. Run `generate`.

**Expected:** stderr contains `Error: use-case file not found: <path>`. The
process exits `1` before any pipeline work, so no output collection
directory is created. The error is the file-resolution error, not a pipeline
error.

### QA-TCLC-04: projection-preflight rejects each missing required input

For each of `--risk-extraction`, `--sssom`, and `--profile`:

1. Point that option at a path inside `missing/`; pass an inline use case and
   keep the other two inputs valid.
2. Run `projection-preflight`.

**Expected:** stderr contains `Error: <label> not found: <path>` where
`<label>` is `risk-extraction file`, `SSSOM file`, or
`capability profile file` respectively. The process exits `1` and stdout
carries no JSON report.

### QA-TCLC-05: validate-catalog-qualification rejects a missing artifact path

1. Run `validate-catalog-qualification <missing>/matrix.yaml --contract matrix`.
2. Run it again with `--contract campaign` and `--contract report`.

**Expected:** Every run prints an `Error:`-prefixed line to stderr and exits
`1`; no JSON is printed to stdout.

### QA-TCLC-06: validate-catalog-qualification rejects invalid artifact content

1. Copy `data/catalog-qualification-matrix-v1.yaml`, truncate its tail (or
   delete a required key), and save the copy in the workspace.
2. Run `validate-catalog-qualification <corrupted-copy> --contract matrix`.

**Expected:** The process exits `1`, stderr carries an `Error:`-prefixed
validation message, and stdout carries no JSON. A structurally unrelated
YAML file (e.g. the use-case text file renamed to `.yaml`) is rejected the
same way.

### QA-TCLC-07: validate-catalog-qualification rejects an invalid contract option

1. Run `validate-catalog-qualification <valid-matrix> --contract unknown`.

**Expected:** stderr contains `Error: contract must be matrix, campaign, or
report`. The process exits `1` and the valid artifact is not read.

### QA-TCLC-08: report and eval reject a missing run directory

For each of `report` and `eval`:

1. Pass `--output-dir <missing>/run`.
2. Run the command.

**Expected:** stderr contains `Error: directory not found: <path>`. The
process exits `1` and nothing is written.

### QA-TCLC-09: report rejects an output destination inside the run directory

1. Use the completed run fixture and pass `--output <run-dir>/injected.html`.
2. Run `report`.

**Expected:** The process exits `1`, stderr explains that the output path is
inside the immutable run directory, and the fixture run directory is left
byte-for-byte unchanged (no `injected.html` appears inside it).

### QA-TCLC-10: report writes the HTML artifact outside the run directory

1. Use the completed run fixture and pass
   `--output <workspace>/report.html`.
2. Run `report`.

**Expected:** The process exits `0`. stdout announces
`Report written to <workspace>/report.html`; the file exists, is non-empty,
and is an HTML document (contains an `<html` tag). The fixture run directory
is unchanged. Report content itself is covered by the rendering suite, not
re-verified here.

### QA-TCLC-11: eval prints the YAML scorecard from a completed fixture run

1. Run `eval --output-dir <completed-run-fixture>` with the default format.
2. Re-read the fixture's `run-manifest.yaml`.

**Expected:** The process exits `0`. stdout parses as one YAML mapping whose
`run_id` equals the run id recorded in the fixture manifest, whose
`schema_version` is `1`, and which contains the keys `manifest_version`,
`scenario_count`, `feature_file_count`, `presence_coverage`,
`validity_grounding`, `cross_artifact_agreement`,
`semantic_quality_diagnostics`, `release_qualification`, and
`qualification`. `scenario_count` matches the fixture's admitted scenario
count. Nothing is written into the run directory.

### QA-TCLC-12: eval prints the JSON scorecard with --format json

1. Run `eval --output-dir <completed-run-fixture> --format json`.
2. Re-read the fixture's `run-manifest.yaml`.

**Expected:** The process exits `0`. stdout parses as JSON with the same key
set and `run_id`/`scenario_count` reconciled against the fixture manifest as
in QA-TCLC-11.

### QA-TCLC-13: profile writes the capability profile YAML

1. Start the deterministic local OpenAI-compatible fixture endpoint with one
   valid capability profile response (a known `entry_points` list; other
   required fields copied from an authoritative profile).
2. Run `profile --use-case <inline-text> --output <workspace>/capability-profile.yaml`
   with the endpoint configured as the model base URL.
3. Run once more with `--use-case @<valid-use-case-file>` using the same
   endpoint and output path.

**Expected:** Both runs exit `0`, stdout announces
`Profile written to <workspace>/capability-profile.yaml`, and the file
exists, parses as YAML, and carries the `entry_points` list served by the
fixture. The token-summary line appears on stdout after the written path.

### QA-TCLC-14: projection-preflight prints the requirements report from fixture inputs

1. Run `projection-preflight --use-case <inline-text>` with the offline
   input files for risk extraction, SSSOM, and the reviewed capability
   profile, no qualification facts.
2. Run it again with `--facts-template <workspace>/facts-template.yaml`.
3. Run the second command a third time unchanged (target file now exists).

**Expected:** In runs 1 and 2 the process exits `0` and stdout parses as JSON
with the top-level keys `readiness`, `fact_states`, `facts_template`, and
`explicit_facts_source`. `readiness` is an object with the `ready` flag and,
in run 1, a non-empty `missing_facts` list whenever the reviewed profile
does not cover every required fact. In run 2,
`<workspace>/facts-template.yaml` is created, parses as YAML with
`schema_version: 1` and a `facts` list, and each fact's status is
`unknown`. In run 3 the process exits `1` with an `Error:`-prefixed stderr
line stating the facts template target already exists, and the existing
template file is unchanged. `explicit_facts_source` is `false` in all three
runs because no qualification facts file was supplied.

### QA-TCLC-15: deterministic repository gates and output hygiene

1. Confirm the live-model opt-in is unset and no external LLM endpoint is
   reachable (the profile fixture endpoint, if still running, is loopback).
2. Run the documented commands in order:

   ```bash
   ./scripts/quality.sh
   ./scripts/acceptance.sh
   uv run pytest tests/ -q
   ```

3. Run `git status --short --untracked-files=all`.

**Expected:** Quality, acceptance, and unit gates pass deterministically
offline, and no generated acceptance IR, coverage, mutation workspaces, or
temporary QA captures are newly tracked or staged.

## Notes and pinned interpretations

- Every command validates its input paths before doing work. Validation
  failures print a line starting with `Error:` to stderr and exit `1`; a
  validation failure never creates an output artifact or run directory.
- The `@file` use-case resolution applies to `generate`, `profile`, and
  `projection-preflight`; it fails before any pipeline or LLM work, so
  `@file` failures are distinguishable from pipeline failures by the
  absence of artifacts.
- `generate`'s success path and default outcome policy are pinned in
  `features/taxonomy_cli_run_outcome.feature`; this suite pins only the
  validation failure contract for `generate`.
- `report` requires an authoritative `completed` manifest (or
  `--allow-non-authoritative` for forensics) and refuses output destinations
  inside the finalized run directory because finalized runs are immutable.
  The announced path is the exact written path; with `--output`, the file is
  written as `<parent>/report.html` and renamed to the requested name, which
  is why the announcement must be re-parsed from stdout rather than assumed.
- `eval` never writes into the run directory; the scorecard is emitted to
  stdout only, as YAML by default and JSON with `--format json`.
- `profile` runs stage 1 only; its LLM contact is confined to the
  deterministic loopback fixture endpoint, and the use-case `@file`
  resolution error surfaces before that contact.
- `projection-preflight` is fully offline: it never constructs an LLM
  client. Its JSON report carries `readiness` (with a boolean `ready` and
  missing/required lists), `fact_states` (one entry per fact with status in
  `present`, `absent`, `unknown`, `stale`, `contradictory`),
  `facts_template`, and `explicit_facts_source` (true only when a
  qualification facts file is supplied). `--facts-template` writes exactly
  once and never overwrites.
- `validate-catalog-qualification` accepts only `--contract matrix`,
  `campaign`, or `report`, and validates the persisted contract with schema
  and semantic checks; missing paths and invalid content both fail on stderr
  with exit `1`.
- Exit-status convention is shared with the CLI run-outcome feature: `0`
  on success, `1` on every validation or execution failure, expressed
  through the same "the process exits with code N" vocabulary.
