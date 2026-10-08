# Replay gate

The replay gate proves that a code change leaves a recorded `generate` unchanged.
It replays the run's recorded provider calls through the current code, offline,
and compares every output file with the recording.

## Record once, replay after every change

1. Record: any live `generate` writes `provider-calls.jsonl` into its output
   directory. Orch `generate` stages keep the command line in the `stage.json`
   beside that directory, which the gate reads.
2. Replay after every change, from the checkout under test:

   ```bash
   ./scripts/replay-check.sh \
     ../asago-orch/runs/<run-id>/stages/generate/output [more output dirs ...]
   ```

   Or for one directory, with options:

   ```bash
   uv run python scripts/replay_gate.py check RECORDED_OUTPUT_DIR \
     [--stage-json FILE] [--work-dir DIR] [--show N] [-- generate ARGS...]
   ```

   Without a `stage.json`, give the recorded `generate ...` arguments after `--`.
   The gate deletes its temporary scratch directory when it finishes; to inspect
   the copied inputs, the replayed output, and `run.log`, pass `--work-dir DIR`,
   which the gate keeps.

A pass means the change preserved behaviour for those recordings: every request
the code sent matched a recorded one, and every output matched. A refactor that
must not change behaviour has to pass on all chosen recordings. A change that
alters any prompt, request control, or output fails, and the gate shows the
first difference in each file; re-record after an intended change.

## What the gate does

- Reruns `generate` with the recorded arguments. It copies each input file into a
  scratch directory, writes a fresh output directory there, and adds
  `--replay-calls` pointing at a copy of the record. It reads `--profiles-file`
  in place because the file holds endpoint credentials. The recorded run
  directory is never written.
- Removes `ASAGO_SCENARIO_GENERATOR_*`, `OPENAI_*`, `OPENROUTER_*`, and
  `*_API_KEY` variables from the environment, and refuses every outbound
  IPv4/IPv6 connection and DNS lookup in the replay process. Any refused attempt
  fails the gate, even if the code caught the error.
- Requires the replay exit code to equal the recorded one.
- Compares every file. A file passes if its bytes are equal after mapping
  scratch paths and the replay's run ids back to the recorded values; a JSON,
  JSONL, or YAML file that still differs is compared as parsed data, including
  key order, after removing only the allowed differences below.

Replay serves each request from the record by call identity (stage, step, slot,
scenario, attempt) and request digest, in recorded order, so identical requests
issued concurrently for different scenarios each get their own response. A
recorded provider error is raised again as the class the live call raised
(`openai.RateLimitError` with its status, `TimeoutError`, ...), so error
handling replays too.

The gate replays strictly and does not take the output of a replay-fill run as a
recording: that run's `provider-calls.jsonl` lines carry a `source` key and its
manifest a fill block, which a strict replay does not write. Check a fill run by
replaying its record with `--replay-calls` alone (see the README).

A transport error (HTTP 5xx or a non-timeout connection error) earns one retry,
which the record holds as a second line with `retry_of`. A replay retries only
when the record holds that line, so a recording made before the retry existed
replays its error as recorded, and a recording with a retry replays both
attempts without a pause. `retry_of` holds the error class and status, not a
sequence number, so concurrent runs compare equal.

## Allowed differences

| File | Fields | Reason |
| --- | --- | --- |
| every file | scratch paths, replay run id | the replay runs in another directory at another time; both are mapped back to the recorded strings |
| `provider-calls.jsonl` | `sequence`, `timestamp`, `duration_ms` | wall-clock time and arrival order of concurrent requests; records compare as a multiset ordered by identity, digest, and sequence |
| `calls.jsonl` | `timestamp`, `duration_ms` | wall-clock time of each call |
| `run-manifest.yaml` | `created_at` | wall-clock time of the run |
| `synthesis-manifest.yaml` | `created_at`, `prompt_call_evidence[].duration_ms`, `semantic_digest` | wall-clock times; the digest covers them, so the gate checks each side's digest against its own payload instead of comparing digests |

The list lives in `ALLOWED_DIFFERENCES` in
`scripts/replay_gate.py`. Add an entry only for a value
that legitimately varies between two executions of the same code on the same
responses; fix nondeterminism in the code instead of normalising it.

### Removed templates

A run records a hash for each prompt template it can load, for example under
`prompt_hashes` in `run-manifest.yaml`. Deleting an unused template removes its
entry from the replay. The gate accepts a recorded key ending in `.j2` that the
replay lacks only when no template of that name exists anywhere in the checkout,
and the report lists it under `removed templates`. Every other difference in the
same table still fails: a changed hash, a missing entry for a template that
still exists, or a new entry. A self-digested file checks each side's digest
over its full payload before the comparison drops any entry.

## Limits

- Replay needs the same inputs and model profile as the recording, because the
  profile's controls are part of each request digest.
- A run that sent a request the record lacks fails with
  `ReplayIncompleteError`; the report shows the run log tail and the cascade of
  output differences.
- Recordings made before identity-keyed replay replay unchanged: the record
  format did not change.
