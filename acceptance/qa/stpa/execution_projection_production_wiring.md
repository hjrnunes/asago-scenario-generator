# End-to-end QA: STPA execution projection production wiring

Drive the public STPA CLI only:
`uv run python scripts/run_sp3.py --enriched-threats <file> --control-structure
<file> --loss-analysis <file> --output-dir <dir>`.
Use the repository's deterministic local OpenAI-compatible stub endpoint for
the Stage 5 and Stage 6 responses. Do not import project modules, call
`run_sp3`, or inspect Pydantic objects directly. Use a fresh output directory
for every case.

## QA-STPA-PROJ-01: declared factors reach every artifact

1. Configure one structural threat for `RESP-1:CA-1-1:WRONG_TIMING`, with ICA
   ID `RESP-1:CA-1-1:WRONG_TIMING:1` and scenario ID `SCN-001`.
2. Configure the Stage 5 stub response with, in order, a process-model flaw
   for `PM-1-1` and a feedback delay for `FB-1-1`, including evidence text.
3. Run the CLI and inspect the Stage 5/6 request log, scenario directory, and
   run diagnostics.

**Expected:** The run succeeds. The scenario YAML contains the two causal
factors in declared order. The narrative, attack-tree, and Gherkin requests
contain byte-identical projection alignment tables with one row for each
factor and a final `CA-1-1` unsafe-control-action row. No request contains an
additional inferred factor, assertion, or step.

## QA-STPA-PROJ-02: invalid evidence is rejected before Stage 6

1. Repeat QA-STPA-PROJ-01 with a Stage 5 factor referencing `PM-99-1`.
2. Run the CLI and inspect its exit status, diagnostics, request log, and
   output directory.

**Expected:** The command reports a causal-factor reference validation error
and exits nonzero (or reports the scenario as rejected according to the
existing run contract). No Stage 6 request or projection artifact is
published for that scenario.

## QA-STPA-PROJ-03: explicit empty is not structural inference

1. Configure Stage 5 to return an explicit empty causal-factor list for a
   threat whose control structure still contains `PM-1-1`, `FB-1-1`, and
   `CA-1-1`.
2. Run the CLI and inspect the scenario YAML, canonical projection files,
   and Stage 6 request log.

**Expected:** The stored `causal_factors`, `assertions`, and `steps` values
are present empty lists. No temporal behavior or alignment row is invented
from structural presence. The legacy YAML and feature remain present, and no
Stage 6 prompt claims a causal factor that was not declared.

## QA-STPA-PROJ-04: canonical projection files are standalone and distinct
identities

1. Run QA-STPA-PROJ-01 again and locate the canonical JSON and YAML projection
   files beside the legacy scenario YAML and `.feature`.
2. Parse the files with command-line standard JSON/YAML readers or equivalent
   reader tools; do not load project code.
3. Inspect the top-level schema version, candidate ID, ICA ID, and scenario
   ID, then compare the JSON and YAML data.

**Expected:** Both files declare `stpa-execution-projection-v1`, have
equivalent plain data, and preserve factor/assertion/step order. The
structural candidate ID is
`EXEC:RESP-1:CA-1-1:WRONG_TIMING`; ICA ID
`RESP-1:CA-1-1:WRONG_TIMING:1` and scenario ID `SCN-001` are separate fields.
Changing either separate identity in a copied document does not rewrite the
candidate ID.

## QA-STPA-PROJ-05: fail-closed traceability and empty compatibility

1. Copy a canonical projection file and remove each of
   `causal_factors`, `assertions`, and `steps` in separate copies. Validate
   each copy through the supported projection-validation CLI affordance (or
   the project’s documented artifact validation command).
2. Create another copy with all three keys present as empty lists and validate
   it.
3. Mutate candidate identity, an assertion source, the final step source, and
   typed provenance in separate copies and validate each.

**Expected:** Each absent key fails closed with a typed violation naming the
   missing key; present-empty is valid. Forged identity, source, final-UCA,
   and provenance links fail with typed violations and identify the earliest
   affected element. No malformed document is treated as a valid empty
   projection.

## QA-STPA-PROJ-06: typed constraints do not become observations

1. Configure declared factors with ordering, delay, duration, window, and
   absence timing where timing is known, using both milliseconds and seconds.
2. Configure a second run where feedback timing is unknown, and configure the
   stub to return runtime observation values only in evaluation output.
3. Inspect the canonical projection and evaluation artifacts.

**Expected:** Known timing uses the named typed constraint variant, relevant
   fields only, and canonical `ms`/`s` units. Unknown timing has a null
   constraint and `requires_binding: true`; it does not receive a guessed
   timing. The temporal vector carries an explicit final UCA outcome mapping
   for `CA-1-1` and `WRONG_TIMING`. Runtime observations appear only in
   evaluation output and never in the canonical projection.
