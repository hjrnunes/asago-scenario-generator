# End-to-end QA: acceptance framework refactor

Run from the repository root. Exercise only the checked-in command-line
entrypoints and the mutation worker's documented JSON-lines interface. Do not
import project modules. Use fresh paths beneath `tmp/qa-acceptance-framework/`
and capture stdout, stderr, and exit status for each command.

## QA-AFR-01: deterministic generated-output rebuild

1. Set the acceptance IR, DRY, generated, and mutation directory environment
   variables to fresh directories beneath `tmp/qa-acceptance-framework/`.
2. Run `./scripts/acceptance.sh`.
3. Verify every source `.feature` beneath `features/` has one nested IR and DRY
   report, one flat `<stem>_acceptance_test.py`, and one metadata file.
4. Verify metadata source and IR paths are repo-relative and contain no
   checkout-specific absolute path.
5. Add stale files matching each generated artifact pattern plus an unrelated
   text file to the configured output trees, then rerun the command.
6. Verify mapped stale artifacts are removed, the unrelated file remains, and
   a third run produces the same generated file set and contents.

## QA-AFR-02: acceptance execution and compatibility

1. Unset `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE` in a child-process environment.
2. Run `./scripts/acceptance.sh --test` against the artifacts from QA-AFR-01.
3. Verify the quality gate runs before generated tests.
4. Verify framework-contract scenarios AFR-01 through AFR-09 are reported with
   their expected PASS results.
5. Verify deterministic scenarios execute.
6. Verify the JPKW canonical structured artifact and raw fallback scenarios
   retain their existing PASS results.
7. Verify the command's failures, if any, are exactly the repository's recorded
   acceptance baseline and contain no new framework-contract failure.

## QA-AFR-03: scenario and process isolation

1. Record the parent process environment.
2. Run the generated AFR-05 test by its pytest node ID in a child process.
3. Verify both the passing-first and failing-first example rows complete their
   observer checks.
4. Verify each second example reports a fresh world and the original child
   environment, while background and scenario steps in one example share state.
5. Verify the parent environment is byte-for-byte unchanged after the process
   exits.
6. Run the same node ID again and verify its output does not depend on the
   preceding run.

## QA-AFR-04: namespaced runtime from the user entrypoint

1. From the repository root, run the generated AFR-07 test by its pytest node
   ID without adding `acceptance/` to `PYTHONPATH`.
2. Verify AFR-07 is reported as passed, confirming the namespaced import,
   declared feature identities, manifest order, and exactly-once registration.
3. Run one generated acceptance test from a nested feature directory and
   verify it resolves its IR beneath the configured project-root IR directory.

## QA-AFR-05: mutation worker JSON-lines protocol

1. Start `acceptance/runner_adapter.py` as a persistent child process and
   verify `runner_adapter: ready` appears on stderr, not stdout.
2. Send a valid job referencing a passing temporary IR. Verify exactly one
   stdout JSON line echoes the ID, reports `test_success`, separates output
   from error, and contains a non-negative integer duration.
3. Send a valid job referencing an IR with an unsupported step. Verify exactly
   one response reports `test_failure`.
4. Send malformed JSON followed by another passing job on the same process.
   Verify the malformed line yields `infrastructure_error` with ID `unknown`
   and the subsequent job still receives its own response.
5. Close stdin and verify the worker exits with status `0`.

## QA-AFR-06: scope and repository hygiene

1. Run `git status --short`.
2. Verify generated IR, DRY, test, metadata, mutation, coverage, and temporary
   QA artifacts are not staged or newly tracked.
3. Verify `config/swarmforge.env` still keeps permanent CRAP, DRY, and
   language-mutation commands scoped to `src/`.
4. Verify `scripts/quality.sh` still checks and format-checks `src` and
   `acceptance`.
5. Verify no production file beneath `src/` changed for this refactor.
