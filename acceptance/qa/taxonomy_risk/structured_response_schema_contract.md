# End-to-end QA: taxonomy structured-response schema contract closure

Drive only the public `uv run asago-scenario-generator generate` command,
the deterministic local OpenAI-compatible fixture, and the documented
repository test/quality commands. Do not import project modules or contact a
live model. Use valid offline taxonomy inputs, a reviewed projection context,
fresh output directories, and a fixture that records complete provider
request bodies, including each `response_format.json_schema.schema`.

## QA-TSSRC-01: recursive provider-schema audit

1. Run `generate` with deterministic valid Call 0, Call 1, and Call 3
   responses.
2. Collect the exact structured response schemas sent in the fixture request
   bodies, not a separately generated model schema.
3. Recursively traverse every reachable schema path, resolving `$ref`, every
   `anyOf` branch, array `items`, and nested model definitions.
4. Verify every reachable generated string has a finite `maxLength` and every
   reachable generated array has a finite `maxItems`.
5. Verify the audit reports no unbounded path for Call 0, Call 1, or Call 3.

**Expected:** The provider request contract, rather than only Python field
metadata, proves that generated strings and arrays are bounded.

## QA-TSSRC-02: Call 0 item boundaries are enforced

1. Run one fixture case for each Call 0 collection: `beliefs`, `desires`,
   `intentions`, and `resources`.
2. In the success case, return a valid response whose targeted item is
   exactly 200 characters.
3. In the failure case, return the same response with that item at 201
   characters.
4. Capture exit status, diagnostics, provider request count, and the run
   directory for every case.

**Expected:** Every 200-character item is accepted, every 201-character item
is rejected by the structured response validation path, and no over-limit
actor response is finalized.

## QA-TSSRC-03: Call 1, realization, and Call 3 ID boundaries are enforced

1. Run deterministic fixture cases with a 200-character Call 1 projected
   step ID and a 64-character Call 1 zone item, then repeat with 201 and
   65-character items respectively.
2. Exercise each nested realization ID-list field through the finalized
   artifact path: `resource_ref_ids`, `consumed_ref_ids`,
   `produced_ref_ids`, `produced_effect_ids`, `outcome_link_pc_ids`, and
   `postcondition_ids`. Test one item at its declared boundary and one item
   one character beyond it.
3. Run Call 3 cases with 200-character `source_step_ids` and
   `projected_postcondition_ids`, then repeat with 201-character values.
4. Inspect the resulting CLI status and diagnostics without treating
   truncation, clipping, or silent omission as success.

**Expected:** Boundary values pass and over-limit values fail closed through
   Pydantic validation for Call 1 and Call 3. Nested realization ID lists
   remain bounded wherever the domain DTO retains them.

## QA-TSSRC-04: Call 1 omits deterministic realizations from provider output

1. Configure a valid candidate whose immutable projection selects
   `step.1,step.2`.
2. Return a Call 1 response containing only model-owned step fields:
   number, zone, action, effect, control point, and projected step IDs.
3. Inspect the captured Call 1 request schema and verify the step definition
   has no `realizations` property.
4. Complete the run and inspect the published narrative artifact.
5. Verify it contains exactly one canonical realization per resolved
   projected step ID, with values matching the immutable projection context.
6. Repeat with an attempted provider realization payload if the fixture
   supports extra-field injection.

**Expected:** The provider is never asked to generate realizations. The
finalized narrative retains exact deterministic realizations, and any
provider-supplied realization data is not published.

## QA-TSSRC-05: narrative realization resolution fails closed

Run separate deterministic cases in which Call 1 has:

- an unknown projected step ID;
- two IDs that resolve to the same canonical step;
- an omitted selected projected step ID; and
- a projected step whose semantics are incompatible with the narrative
  mapping.

For each case:

1. Run `generate` with all otherwise valid fixture responses.
2. Capture stdout, stderr, exit status, request counts, and finalization
   evidence.
3. Verify the diagnostic names the resolution defect.
4. Verify no finalized narrative or admitted scenario is published.

**Expected:** Unknown, duplicate, omitted, and semantically incompatible IDs
remain terminal fail-closed validation errors. They are never repaired by
deduplication, fuzzy matching, or model-supplied realization semantics.

## QA-TSSRC-06: Call 1 sends candidate-specific step bounds

1. Run a fixture case with a candidate selecting five canonical projected
   steps.
2. Inspect the exact Call 1 request schema before the fixture responds.
3. Verify `steps.maxItems` is `7`.
4. Repeat with a candidate selecting 16 canonical projected steps and verify
   `steps.maxItems` is `16`.
5. Verify each bound is present in the provider request itself, not only in
   post-response finalization diagnostics.

**Expected:** The provider receives
`min(selected_step_count + 2, 16)` for the current candidate.

## QA-TSSRC-07: consistency grounding import regression is restored

1. Run the two targeted direct consistency tests by their public pytest node
   IDs:

   ```text
   tests/test_cmps9_typed_actions.py::TestToolExecutionZonePromptParity::test_consistency_accepts_integration_in_tool_execution
   tests/test_consistency_enforcement.py::TestDirectIntegrationInToolExecution::test_integration_interaction_grounding_no_violation
   tests/test_consistency_enforcement.py::TestDirectIntegrationInToolExecution::test_ai_action_in_tool_execution_still_flagged
   ```

2. Verify the tests import the grounding helper successfully from the
   established generation surface.
3. Verify integration interaction in `tool_execution` produces no
   `untyped-tool-execution` violation.
4. Verify an AI-system action in `tool_execution` still produces the expected
   `untyped-tool-execution` violation.

**Expected:** The stale import is repaired without weakening the consistency
matrix or changing the accepted and rejected action behavior.

## QA-TSSRC-08: deterministic repository gates and output hygiene

1. Ensure the live-model opt-in is unset and the fixture is loopback-only.
2. Run the documented commands in order:

   ```bash
   ./scripts/quality.sh
   ./scripts/acceptance.sh
   uv run pytest tests/ -q
   ```

3. Verify the targeted regression tests remain passing in the full unit
   result.
4. Run `git status --short --untracked-files=all`.
5. Verify generated acceptance IR, DRY reports, generated tests, coverage,
   mutation workspaces, and temporary QA captures are not newly tracked or
   staged.

**Expected:** Quality, acceptance, and unit gates pass deterministically
without an LLM endpoint, and generated acceptance artifacts remain outside
the repository diff.
