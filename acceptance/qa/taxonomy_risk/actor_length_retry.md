# End-to-end QA: taxonomy actor profile length retry

Drive only `uv run asago-scenario-generator generate` and inspect the
published run directory and `calls.jsonl`. Use a deterministic local
OpenAI-compatible fixture endpoint, valid offline taxonomy inputs, and a fresh
output collection. Do not import project modules or contact a live model.

Configure the model profile with `max_completion_tokens: 16384`. The fixture
must raise `LengthFinishReasonError` for the first actor-profile response and
then return a valid structured actor profile.

## QA-TALR-01: actor profile retry is concise and bounded

1. Run `generate` against the fixture endpoint with the configured model
   profile, reviewed architecture profile, qualification facts, and valid
   taxonomy inputs.
2. Locate the actor-profile Call 0 entries in `calls.jsonl`.
3. Verify there are exactly two actor-profile attempts.
4. Verify the second request includes corrective feedback that says the prior
   response was truncated and requests only a concise schema-matching response.
5. Verify both actor-profile requests use `max_completion_tokens: 16384`.
6. Verify the run continues past actor-profile generation and publishes its
   normal downstream artifacts.

**Expected:** The first length failure causes exactly one corrective retry. The
retry does not reduce the operator-configured completion limit.

## QA-TALR-02: a second length failure stops after one retry

1. Configure the fixture to raise `LengthFinishReasonError` for both
   actor-profile attempts.
2. Run the same CLI command and capture stdout, stderr, exit status, and
   `calls.jsonl`.
3. Verify exactly two actor-profile attempts are present, both with
   `max_completion_tokens: 16384`.
4. Verify the failure remains visible in the run diagnostics and no third
   actor-profile request is issued.

**Expected:** Retry handling is bounded and the exhausted length failure is
reported rather than looping indefinitely.
