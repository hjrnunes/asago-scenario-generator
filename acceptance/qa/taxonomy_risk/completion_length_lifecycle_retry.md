# End-to-end QA: taxonomy completion-length lifecycle retry

Drive only `uv run asago-scenario-generator generate` and inspect console
output, the published run directory, and requests captured by a deterministic
local OpenAI-compatible fixture. Do not import project modules or contact a
live model. Use valid offline taxonomy inputs, a reviewed capability profile,
qualification facts, one qualified candidate with no fallback, a fresh output
collection per case, and `max_completion_tokens: 16384`.

The fixture must expose ordered response scripts independently for actor,
narrative, tree, and behavior requests. A scripted length response has
`finish_reason: "length"` and usage values `prompt_tokens: 31`,
`completion_tokens: 16`, and `total_tokens: 47`. All responses not named by a
case are valid and deterministic.

## QA-TCLLR-01: structured and unstructured normalization

1. For each structured stage (actor, narrative, and behavior), run the CLI
   with a first length response and a valid second response. For tree, do the
   same with the unstructured completion endpoint.
2. Verify the fixture receives exactly two requests for the targeted stage and
   each request uses `max_completion_tokens: 16384`.
3. Inspect `finalization-inventory.json` and `calls.jsonl`.
4. Verify the first targeted attempt is a typed completion-length failure with
   code `completion_length`, finish reason `length`, prompt tokens `31`, and
   completion tokens `16`; verify its failure does not depend on provider
   exception text.
5. Verify the second targeted attempt is successful and the lifecycle
   continues with the accepted artifact.

**Expected:** Structured SDK length failures and unstructured length finish
reasons have the same project-owned typed and durable representation.

## QA-TCLLR-02: all four stages retry once and succeed

1. Configure the fixture so the first response of each of actor, narrative,
   tree, and behavior ends for length, and each second response is valid.
2. Run the CLI once.
3. Verify the fixture receives exactly two requests per generated stage,
   eight generated-stage requests in total, and no stage helper emits two
   requests during one lifecycle invocation.
4. Verify all eight requests use `max_completion_tokens: 16384`.
5. Verify the run reaches admission and publishes its normal scenario
   artifacts from the four second responses.

**Expected:** Finalization, rather than a stage helper, owns one
length-specific retry for each generated stage.

## QA-TCLLR-03: a second length failure is terminal

1. Run four cases, targeting actor, narrative, tree, and behavior in turn.
   Return valid responses before the target and return length responses for
   both target attempts.
2. For each case, capture stdout, stderr, exit status, fixture requests,
   `finalization-inventory.json`, and `calls.jsonl`.
3. Verify exactly two target requests, no third target request, and no
   downstream request after the exhausted target.
4. Verify both target requests use `max_completion_tokens: 16384`.
5. Verify the candidate has terminal
   `generation_or_finalization_failed` evidence with code
   `completion_length`; no fallback is attempted.
6. Verify the stage's semantic owner-retry counter remains unchanged.

**Expected:** A second length failure is terminal for that candidate and cannot
loop or consume semantic retry budget.

## QA-TCLLR-04: non-length semantic retries retain their budget

1. Run four cases, targeting each generated stage. Return a response that
   reaches the target's semantic validation but fails it without
   `finish_reason: "length"`, then return a valid response.
2. Verify each target has two lifecycle invocations, one semantic owner retry,
   and no `completion_length` retry reason, failure code, or length suffix.
3. Repeat with three semantically invalid target responses.
4. Verify the target receives the initial attempt plus two semantic owner
   retries, then terminates under its existing semantic failure code.

**Expected:** Non-length failures never enter length routing, and the existing
semantic budget remains initial attempt plus two owner retries.

## QA-TCLLR-05: every provider request has durable attempt evidence

1. Use the successful four-stage length-retry run from QA-TCLLR-02.
2. Correlate fixture requests, stage attempts in
   `finalization-inventory.json`, and rows in `calls.jsonl` by stage and
   attempt identity.
3. Verify there is one distinct inventory record and one distinct call-log row
   for every provider request, including each failed first attempt.
4. Verify every failed first attempt stores a `StageAttemptFailure` with code
   `completion_length`, finish reason `length`, and the fixture usage values.
5. Verify every corresponding failed call-log row has stable code
   `completion_length`.

**Expected:** No internal retry can hide or collapse a provider request.

## QA-TCLLR-06: retry prompts append only stage-specific feedback

1. For each generated stage, compare the fixture's first and second request.
2. Verify the second system prompt is byte-for-byte equal to the first.
3. Verify the second user prompt starts with the complete first user prompt
   and appends exactly one short suffix:
   - actor and narrative: `Return only a schema-matching object with bounded
     lists and concise prose.`
   - tree: `Return only a complete schema-matching YAML document.`
   - behavior: `Return only the complete required Gherkin/assertion payload.`
4. Verify the retry directive reason is `completion_length`.
5. Verify the suffix occurs only after the original prompt and does not occur
   inside access-provenance, title, consistency, semantic, or other original
   feedback sections.

**Expected:** Length feedback preserves the original prompt and remains
separate from semantic feedback channels.

## QA-TCLLR-07: narrative and schema shapes are bounded

1. Run cases whose projected candidates select 1, 8, 14, and 16 canonical
   steps. Return valid narratives at their permitted limits.
2. Inspect each admitted scenario and verify all selected step IDs are covered.
3. Verify narrative step counts do not exceed 3, 10, 16, and 16 respectively.
4. Inspect `response_format.json_schema.schema` in captured actor, narrative,
   and behavior requests.
5. Recursively verify every generated array field declares a finite
   `maxItems` and every generated prose field declares a finite `maxLength`.

**Expected:** Call 1 covers every selected step, permits at most two connector
steps, never exceeds 16 steps, and all structured generated content has static
schema maxima.

## QA-TCLLR-08: deterministic default gates stay offline

1. Block outbound network access and leave all live-model opt-in variables
   unset.
2. Run the repository's deterministic unit and acceptance commands.
3. Run this QA suite only against its loopback fixture endpoint.

**Expected:** Deterministic tests never contact an external LLM endpoint; all
completion-length coverage is reproducible through the local fixture.
