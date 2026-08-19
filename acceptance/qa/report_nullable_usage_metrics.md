# End-to-end QA: nullable LLM usage reporting

## Boundary

Exercise only the public taxonomy-and-risk report command:

```bash
uv run asago-scenario-generator report \
  --output-dir <run-directory> \
  --output <temporary-directory>/report.html
```

Do not import project modules or call a project API. Keep the suite offline.
Use disposable copies of authoritative run fixtures whose manifest inventory
and hashes match their call logs.

## Fixture records

Provide one completed taxonomy-and-risk run fixture with:

- one reportable scenario and its normal generated artifacts;
- a failed pipeline call with `prompt_tokens`, `completion_tokens`, and
  `duration_ms` set to JSON `null`;
- one numeric pipeline call with values `11`, `13`, and `170`;
- a synthetic scenario call with all three metrics set to JSON `null`;
- one numeric scenario call with values `19`, `23`, and `290`.

Provide derivative fixtures, with matching manifests, for each single null
field, one fully numeric call, and each invalid value from NLM-04.

## Workflows

### QA-NLM-01 failed call with unavailable telemetry

1. Run the report command against the failed-call fixture.
2. Verify exit status `0` and that `report.html` exists.
3. Open the report in a browser.
4. Verify the failed pipeline call remains visible and is identified as
   failed.
5. Verify its three metrics read as unavailable rather than measured zero.
6. Verify aggregate prompt tokens, completion tokens, and duration are `0`.
7. Verify a visible warning identifies the call and unavailable metrics.
8. Verify neither command output nor report content contains
   `unsupported operand type`, `TypeError`, or a traceback.

### QA-NLM-02 mixed nullable and numeric telemetry

For each of `prompt_tokens`, `completion_tokens`, and `duration_ms`:

1. Run the report command against the corresponding single-null fixture.
2. Verify exit status `0`.
3. Open the report and verify both pipeline calls are present.
4. Verify the nullable field is displayed as unavailable.
5. Verify the totals are respectively `11/20/260`, `16/13/260`, and
   `16/20/170` for prompt tokens, completion tokens, and milliseconds.
6. Verify a visible warning names the unavailable field.

### QA-NLM-03 scenario preservation

1. Run the report command against the fixture with synthetic and numeric
   scenario calls.
2. Verify exit status `0`.
3. Open the report and verify both scenarios and both call entries remain
   visible.
4. Verify the synthetic call's three metrics are unavailable.
5. Verify the numeric call shows `19` prompt tokens, `23` completion tokens,
   and `290` milliseconds.
6. Verify a visible warning identifies the synthetic call's unavailable
   metrics.

### QA-NLM-04 invalid telemetry diagnostic

For `prompt_tokens="many"`, `completion_tokens={"count": 4}`, and
`duration_ms=[300]`:

1. Run the report command against the matching invalid fixture.
2. Verify the command exits nonzero and does not produce a successful report.
3. Verify the user-facing diagnostic identifies the field, offending value,
   and call.
4. Verify the diagnostic does not contain an arithmetic exception, an
   implementation traceback, or `unsupported operand type`.

### QA-NLM-05 fully available telemetry

1. Run the report command against a fixture containing one pipeline call with
   `31` prompt tokens, `17` completion tokens, and `410` milliseconds.
2. Verify exit status `0`.
3. Open the report and verify the same values in the call and aggregate totals.
4. Verify no unavailable-metrics warning is shown.
