# End-to-end QA: taxonomy candidate-filter seed quarantine

Drive only `uv run asago-scenario-generator generate` and inspect its console
output and published run directory. Use a fresh output collection and a
deterministic local OpenAI-compatible fixture endpoint; do not import project
modules or contact a live model.

Use valid use-case, risk-extraction, SSSOM, capability-profile, and
qualification-facts files. The fixture exposes two independent seeds and
returns valid downstream generation responses unless a case says otherwise.

## QA-TCFQ-01: corrected retry succeeds

1. Configure the first filter response for seed `AP-T1-01` to contain
   unsubmitted but well-formed ID
   `cand:v2:ffffffffffffffffffffffffffffffff`; configure its second response
   with exactly the submitted IDs. Configure `AP-T2-01` with a valid first
   response.
2. Run `generate` with `--profile`, `--qualification-facts`, and the fixture
   endpoint options.
3. Verify the call log contains two filter attempts for `AP-T1-01` and one for
   `AP-T2-01`.
4. Verify both seeds can contribute admitted scenario artifacts and no
   artifact contains `cand:v2:ffffffffffffffffffffffffffffffff`.

**Expected:** The bounded retry repairs the local protocol error. No seed is
quarantined because the final response reconciles.

## QA-TCFQ-02: irreconcilable seed is local

1. Configure both responses for `AP-T1-01` to contain unsubmitted ID
   `cand:v2:ffffffffffffffffffffffffffffffff`.
2. Configure `AP-T2-01` and all its downstream responses as valid.
3. Run the same CLI command and capture stdout, stderr, and exit status.
4. Inspect `calls.jsonl`, `run-manifest.yaml`, quarantine evidence, and
   admitted scenario YAML through their published paths.

**Expected:** `AP-T1-01` has exactly two filter attempts and is quarantined;
no candidate from it reaches projection. `AP-T2-01` reaches projection and
produces an admitted scenario. The run is not `failed`, but the degraded final
status produces the default nonzero exit. No unknown ID is admitted.

## QA-TCFQ-03: reconciliation evidence is exact

1. Have `AP-T1-01` submit `cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` and
   `cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`.
2. Return `cand:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa` and
   `cand:v2:ffffffffffffffffffffffffffffffff` on both attempts.
3. Run the CLI and inspect its final summary and published quarantine
   evidence.

**Expected:** Both surfaces identify `AP-T1-01` and record the sorted expected
IDs, received IDs, missing ID
`cand:v2:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb`, and unknown ID
`cand:v2:ffffffffffffffffffffffffffffffff`. The received metadata is evidence
only and cannot alter candidate metadata or create an admitted identity.
