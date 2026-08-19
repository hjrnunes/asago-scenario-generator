# STPA Reference and Stage 5 Robustness — End-to-End QA Suite

This suite verifies the grouped behavior for GitHub issues 9 and 7 through
the shipped `run_sp1.py` and `run_sp3.py` command lines. QA supplies local
OpenAI-compatible stub servers through `--profiles-file` and `--profile`,
then inspects command output and generated artifacts. It does not import or
call project internals.

All cases are deterministic and offline. Stub servers must capture each HTTP
request body so QA can verify call count, prompts, response schema, and token
ceilings from the same requests made by the command-line workflow.

## Shared setup

1. Create a temporary directory with sanitized use-case, risk-extraction,
   capability-profile, loss-analysis, control-structure, and enriched-threat
   fixtures containing one structural threat.
2. Start the applicable QA stub on an ephemeral localhost port.
3. Write a temporary profiles file selecting that endpoint.
4. Capture each command's stdout, stderr, exit status, stub request log, and
   output directory.
5. Stop the stub after each case.

## STPA tolerant reference normalization

### QA-STPA-REFERENCE-01: Observed Gemma shapes publish canonical references

Configure the SP1 stub's control-element response with:

- process model source ID `PM-9-7`;
- `FeedbackChannel.updates` equal to
  `{"type":"process_model_part","id":"PM-9-7"}`;
- one `ElementRef` with `{"type":"CP-9","id":"CP-9"}`;
- one `ElementRef` with `{"type":"RESP-9","id":"RESP-9"}`;
- source IDs whose final list positions produce canonical IDs `PM-1-1`,
  `CP-2`, and `RESP-2`.

Run:

```bash
uv run python scripts/run_sp1.py \
  --use-case <use-case.txt> \
  --risk-extraction <risk-extraction.json> \
  --capability-profile <capability-profile.yaml> \
  --output-dir <supported-output> \
  --profiles-file <profiles.yaml> \
  --profile qa
```

Verify:

1. The command completes and reports a produced control structure rather than
   degraded assembly.
2. `control-structure.yaml` contains scalar
   `feedback_channels[0].updates: PM-1-1`.
3. The two ID-shaped types are published as `controlled_process` with `CP-2`
   and `responsibility` with `RESP-2`.
4. Neither stdout nor stderr contains `PydanticSerializationUnexpectedValue`,
   `serializer warning`, or `unhashable type`.
5. `calls.jsonl` and `run-manifest.yaml` contain no Stage 2 error for these
   supported shapes.

### QA-STPA-REFERENCE-02: Ambiguous PM objects fail in a controlled way

Repeat the SP1 command with two process model parts in one responsibility that
share source ID `PM-LEGACY`, and an `updates` object identifying
`PM-LEGACY`.

Verify:

1. The command reaches the documented Stage 2 degraded/error result rather
   than terminating with an uncaught exception.
2. The visible Stage 2 diagnostic identifies the feedback channel's `updates`
   reference as ambiguous or unresolved.
3. Neither stdout nor stderr contains `unhashable type`, a Python traceback
   ending in `TypeError`, or a Pydantic serializer warning.
4. No published feedback channel contains a mapping in its scalar `updates`
   field.

### QA-STPA-REFERENCE-03: Unknown shapes fail in a controlled way

Repeat QA-STPA-REFERENCE-02 for each response:

| Case | Supplied shape | Required diagnostic |
| --- | --- | --- |
| unknown PM | `updates={"type":"process_model_part","id":"PM-UNKNOWN"}` | `updates` |
| wrong namespace | `updates={"type":"control_action","id":"CA-9-1"}` | `updates` |
| unknown element type | `target={"type":"NODE-9","id":"NODE-9"}` | `target` or `type` |

For every row, verify the same controlled behavior and absence of serializer
warnings and unhashable-value failures as QA-STPA-REFERENCE-02.

## SP3 Stage 5 completion-length retry

Run every case below through:

```bash
uv run python scripts/run_sp3.py \
  --enriched-threats <enriched-threats.yaml> \
  --control-structure <control-structure.yaml> \
  --loss-analysis <loss-analysis.yaml> \
  --output-dir <case-output> \
  --profiles-file <profiles.yaml> \
  --profile qa
```

The stub returns valid Stage 6 responses whenever Stage 5 succeeds.

### QA-SP3-STAGE5-RETRY-01: First-attempt success is unchanged

Configure the stub's first Stage 5 response as a valid structured BDI result.

Verify:

1. Exactly one captured request and one `calls.jsonl` entry are labeled
   `stage_5`.
2. The request does not contain a truncation-correction instruction.
3. One scenario YAML and one scenario feature are published.
4. The run summary and `run-manifest.yaml` contain no Stage 5 BDI error.

### QA-SP3-STAGE5-RETRY-02: One bounded corrective retry succeeds

Configure the stub to return `finish_reason: length` for the first structured
Stage 5 completion and a valid BDI result for the second.

Verify:

1. Exactly two captured requests and two `calls.jsonl` entries are labeled
   `stage_5`; the first is failed and the second is successful.
2. The second request uses the same structured BDI response schema.
3. The second request sets `max_completion_tokens` to a positive integer no
   greater than `2048`.
4. The second request says the prior response was truncated and requests only
   a concise response matching the schema.
5. One scenario YAML and one scenario feature are published from the retry
   result.
6. The run summary and `run-manifest.yaml` contain no Stage 5 BDI error.

### QA-SP3-STAGE5-RETRY-03: Retry exhaustion remains visible

Configure the stub to return `finish_reason: length` for both structured Stage
5 completions.

Verify:

1. Exactly two captured requests and two failed `stage_5` call-log entries
   exist; no third Stage 5 request occurs.
2. No scenario artifact is published for the threat.
3. The CLI run summary reports a Stage 5 error mentioning
   `LengthFinishReasonError` and retry exhaustion.
4. `run-manifest.yaml` records the same error in `stage_errors`.

### QA-SP3-STAGE5-RETRY-04: Other failures are not retried

Repeat the SP3 command with each first-attempt failure:

| Case | Stub behavior | Required visible error |
| --- | --- | --- |
| misleading text | non-length failure whose message contains `LengthFinishReasonError` | `RuntimeError` |
| endpoint failure | HTTP error from the model endpoint | endpoint failure type |
| invalid structure | successful HTTP response missing `attacker_bdi` | `ValidationError` |

For every row, verify exactly one captured Stage 5 request, no scenario
artifact, and a matching error in the CLI summary and manifest.
