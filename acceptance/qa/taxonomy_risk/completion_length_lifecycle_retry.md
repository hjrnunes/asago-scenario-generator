# End-to-end QA: taxonomy completion-length lifecycle retry

Drive only `uv run asago-scenario-generator generate` and inspect console
output, the published run directory, and requests captured by a deterministic
local OpenAI-compatible fixture. Do not import project modules or contact a
live model. Use valid offline taxonomy inputs, a reviewed capability profile,
qualification facts, one qualified candidate with no fallback, a fresh output
collection per case, and a transport cap of `max_completion_tokens: 16384`.
The generated stages apply operation caps of 4096 (actor), 8192 (narrative),
8192 (tree), and 4096 (behavior). Each length retry uses exactly one approved causal control,
which the fixture journals separately from the prompt suffix.

The fixture must expose ordered response scripts independently for actor,
narrative, tree, and behavior requests. A scripted length response has
`finish_reason: "length"` and usage values `prompt_tokens: 31`,
`completion_tokens: 16`, and `total_tokens: 47`, plus nested token-detail
fields. All responses not named by a case are valid and deterministic.

## QA-TCLLR-01: structured and unstructured normalization

1. For each structured stage (actor, narrative, and behavior), run the CLI
   with a first length response and a valid second response. For tree, do the
   same with the unstructured completion endpoint.
2. Verify the fixture receives exactly two requests for the targeted stage,
   the first uses its stage operation cap, and the retry follows the
   configured causal-control experiment without increasing the fixed request
   budget.
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
4. Verify the first requests use the stage operation caps and each retry
   changes only its selected approved causal control. Narrative changes from
   8192 to 4096; the transport cap remains 16384.
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
4. Verify each first target request uses its stage operation cap and each retry
   changes only its selected approved causal control.
5. Verify the candidate has terminal
   `generation_or_finalization_failed` evidence with code
   `semantic_draft_length_failed`; no fallback is attempted.
6. Verify the stage's semantic owner-retry counter remains unchanged.

**Expected:** A second length failure is terminal for that candidate and cannot
loop or consume semantic retry budget.

## QA-TCLLR-04: non-length semantic retries retain their budget

1. Run four cases, targeting each generated stage. Return a response that
   reaches the target's semantic validation but fails it without
   `finish_reason: "length"`, then return a valid response.
2. Verify each target has two lifecycle invocations, one semantic owner retry,
   and no `completion_length` retry reason, failure code, or length suffix.
3. Repeat with two semantically invalid target responses.
4. Verify the target receives the initial attempt plus one semantic owner
   retry, then terminates under its existing semantic failure code.

**Expected:** Non-length failures never enter length routing, and the existing
semantic budget remains initial attempt plus one owner retry.

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
5. Verify the request journal also records exactly one approved causal control
   change for the retry, independent of the suffix, and no other request
   control changes.
6. Verify the suffix occurs only after the original prompt and does not occur
   inside access-provenance, title, consistency, semantic, or other original
   feedback sections.

**Expected:** Length feedback preserves the original prompt and remains
separate from semantic feedback channels; it is not the sole retry
correction.

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

## QA-TCLLR-09: bounded partial length diagnostics preserve failure evidence

1. Start a deterministic local OpenAI-compatible HTTP fixture that returns a
   partial structured response for actor with `finish_reason: "length"` and
   then a second length response for the same candidate. Include a response
   ID, model identifier, prompt/completion/total usage, nested prompt-token
   details, nested completion-token details, and a partial content marker
   containing `SECRET=fixture-customer@example.invalid`.
2. Run the public `generate` CLI against the loopback fixture with one
   qualified candidate and no fallback.
3. Inspect `finalization-inventory.json`, `calls.jsonl`, and the output
   directory.
4. Verify the first failed stage attempt and its failed call record preserve
   finish reason `length`, every fixture usage/token-detail field, the
   response ID, model identifier, a non-null non-negative elapsed duration,
   partial character count, and the SHA-256 digest of the original partial
   content.
5. Verify the durable failure evidence contains bounded prefix and suffix
   previews, each no longer than 128 characters, with the secret marker
   redacted. Verify no full unbounded partial response is stored.
6. Repeat the case through the unstructured completion endpoint, where the
   returned choice has `finish_reason: "length"` rather than an SDK exception.
7. Verify both provider shapes use the same typed durable completion-length
   evidence contract.
8. Verify neither partial response is parsed, repaired, or admitted, and no
   published scenario artifact is created.

**Expected:** A length failure preserves enough bounded, redacted evidence to
diagnose the provider response without treating partial content as a product
artifact or leaking the fixture secret.

## QA-TCLLR-10: causal retry control is journaled within a fixed budget

1. For each of actor, narrative, tree, and behavior, run a fresh candidate
   case with a first length response and a valid second response.
2. Configure one approved causal control for the target case:
   candidate-specific compact response schema, stage-specific completion cap,
   or lower retry temperature. Do not configure more than one. Run the
   experiment only after provider-facing fields are schema-bounded; do not
   lower the transport cap merely to force an earlier failure.
3. Run the public `generate` CLI against the loopback fixture.
4. Inspect the ordered fixture request journal and the lifecycle inventory.
5. Verify the journal contains exactly two requests for the target candidate,
   one first attempt and one length retry, with no third request.
6. Verify the second request changes exactly the selected causal field and
   leaves all other causal request fields unchanged. The retry directive
   reason is `completion_length`, and the concise stage-specific suffix is
   appended to the original user prompt.
7. Verify the journal records the selected control, initial value, retry
   value, and fixed total request budget of two.
8. Verify the retry does not consume semantic owner-retry budget and does not
   increase the configured total-attempt bound.

**Expected:** The sole length retry is a controlled causal experiment rather
than a prose-only resample, while request count and lifecycle budgets remain
strictly bounded.

## QA-TCLLR-11: deterministic default gates stay offline

1. Block outbound network access and leave all live-model opt-in variables
   unset.
2. Run the repository's deterministic unit and acceptance commands.
3. Run this QA suite only against its loopback fixture endpoint.

**Expected:** Deterministic tests never contact an external LLM endpoint; all
completion-length coverage is reproducible through the local fixture.
