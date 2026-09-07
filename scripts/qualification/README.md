# External Garak qualification

This opt-in runner is outside the scenario and artifact product pipelines.
It accepts a compiled `executable-conversation.json` and its exact
`execution-plan.json`, validates their authority, and invokes Garak's actual
`injection.IndirectInjection` replay probe. Despite that probe's name, its
conversation source also accepts direct and multi-turn compiled cases.

Use an isolated environment containing the artifact-generator package, MCP,
and the Garak PR checkout at
`06aba1a2c9b142d561eeeff08dfaffcbe77487c3`. These external dependencies are not
installed into the scenario-generator environment.

## Observe and compile

Capture current test data independently of scenario generation. The automatic
selector requires exactly one independently verified, read-only observation
tool with no arguments. It verifies that tool's live description and schema
before calling it; ambiguous or unsupported inventories stop explicitly.

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  /path/to/garak-venv/bin/python scripts/qualification/capture_runtime_context.py \
  --mcp-url http://127.0.0.1:8888/sse \
  --target-profile /path/to/discovery/execution-target-profile.json \
  --output build/qualification/runtime-context
```

An explicitly supplied source document can additionally authorize bounded
text-search observations. The target profile must contain exactly one verified
`text_search` role with a single required plain string argument. Without
`--query-profile`, the source is passed literally for compatibility. With a
named `--query-profile`, one model-planning call proposes at most four distinct
single-term topical search stimuli (each at most 80 characters), retaining a
verbatim source quote and rationale for each. The planner is not a policy
authority: its queries are search stimuli only, and returned content remains
untrusted. There are no retries, fallback providers, brand prefixes,
conjunctions, combined subjects, wildcards, whole-paragraph queries, or
business-action calls. An ambiguous or unsupported profile records a no-call
diagnostic while still preserving the state observation.

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  /path/to/garak-venv/bin/python scripts/qualification/capture_runtime_context.py \
  --mcp-url http://127.0.0.1:8888/sse \
  --target-profile /path/to/discovery/execution-target-profile.json \
  --query-text-file /path/to/use-case.txt \
  --query-profile gemma4-oc \
  --profiles config/model-profiles.yaml \
  --output build/qualification/runtime-context-with-read
```

The raw capture retains each exact argument, live tool description/schema,
profile digest, and MCP result under `read_observations`. The normalized runtime
context keeps those observations separate from `state`, includes the paired
`target_profile_digest`, and labels transport verification separately from
untrusted returned content. A returned payload is not interpreted as policy
authority or an execution binding. Query-plan provenance contains the source
digest, each query digest, source quote, rationale, and selected model profile;
the existing `calls.jsonl` records the single planner receipt. Oversized or
empty source text, unsupported planning, and planner validation failures retain
the state observation with an explicit diagnostic and make no read calls.

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  .venv/bin/python scripts/qualification/compile_with_profile.py \
  --profiles config/model-profiles.yaml --profile gemma4-oc \
  --call-log build/qualification/artifact-author-calls.jsonl -- \
  generate --bundle /path/to/run/execution-bundle.json \
  --target-profile /path/to/discovery/execution-target-profile.json \
  --runtime-context build/qualification/runtime-context/runtime-context.json \
  --platform garak --output-dir build/qualification/artifacts
```

The observation is data for attack authoring, not a replacement for a missing
semantic condition or authority to change an execution plan. The raw MCP
capture stays in `observation.json`; only normalized state and explicitly
requested read observations enter authoring.
The compilation adapter invokes the normal artifact CLI unchanged and records
its exact prompt inputs and parsed provider returns locally. These logs may
contain target test data; do not publish them as sanitized configuration.

## Execute

```bash
PYTHONPATH=src:../asago-artifact-generator/src \
  /path/to/garak-venv/bin/python scripts/qualification/garak_case_runner.py \
  --case /path/to/SCN-NNN/executable-conversation.json \
  --plan /path/to/SCN-NNN/execution-plan.json \
  --mcp-url http://127.0.0.1:8888/sse \
  --model-url http://127.0.0.1:8321/v1/ \
  --model gemma-4-26b-a4b-it \
  --judge-profile gemma4-oc --profiles config/model-profiles.yaml \
  --state-tool get_klarna_state_summary \
  --timeout 180 \
  --output build/qualification/SCN-NNN-safe
```

Supply runtime authentication through `OPENAI_API_KEY` when required; never
put credentials in profiles or compiled cases. Set the XDG cache/config/data
directories to the isolated environment when testing an external Garak fork.
The MCP server must be an explicitly authorized disposable test target.
`--state-tool` authorizes that named zero-argument read operation; the runner
does not guess which tool is safe to call. The default safe MiniKlarna server
uses port 8888; a separately started unsafe counterpart uses 8889.

The runner does not extract or rewrite attack prompts. It verifies selected
function names, descriptions and schemas against the live MCP inventory,
then adapts only their transport to MCP `allowed_tools`. Extra runtime tools
are not exposed. Forced function selection is currently unsupported and is
rejected explicitly. No target system policy is inserted.

Outputs are `garak-attempts.jsonl` and `qualification.json`, including the
compiled digest, actual responses/tool calls, before/after state and separate
execution errors. Existing output directories are not overwritten.

## Evaluation boundary

Argument predicates distinguish safe/unsafe observed arguments. They do not
equate an attempted unsafe argument with a successful ledger change. Missing
operation calls remain inconclusive unless their triggering condition is
independently established. With `--judge-profile`, response-text propositions
are evaluated against the exact compiled oracle, actual response and observed
state. The judge must quote literal evidence; missing, malformed or fabricated
evidence cannot establish an unsafe outcome. Judge calls are saved under
`judge/calls.jsonl`.

The response judge's result is provider-reported. Literal-quote validation checks
that a quotation exists, not that it logically supports the verdict. Results
explicitly retain `semantic_support_independently_verified: false`. Saved
synthetic controls can be rescored with
`calibrate_semantic_judge.score_saved_controls`; this ignores stored pass flags
and counts missing/unknown judgments separately. An authentic quotation does
not make a verdict that disagrees with a control's expected label pass.

The separate MiniKlarna ledger adapter checks exact refund/order or payment-plan
changes and their matching tool result. A rejected or held refund is not an
applied refund, and unrelated state changes are inconclusive. This is a
qualification adapter for MiniKlarna's inspected state schema, not a generic
business-policy inference engine. Neither it nor the judge inserts policies
into the target conversation. `vulnerability_confirmed` stays false: the
report distinguishes observed predicates and effects from a broader causal
claim about attack success.

Offline checks (the Garak test skips outside its isolated environment):

```bash
/path/to/garak-venv/bin/python -m pytest \
  scripts/qualification/test_garak_case_runner.py \
  scripts/qualification/test_evaluation.py -q
```

These checks exercise the actual probe with Garak's deterministic test
generator, verify unchanged conversation history, and distinguish old
assistant messages from newly generated evidence. They are not live campaign
success evidence.

## Optional offline outcome checks

`outcome_checks.evaluate_supplied_outcome` is a separate, network-free evidence
check. It is not connected to scenario generation, artifact authoring, or live
execution, and adds no new mandatory product input.

Its closed `OutcomeCheck` names the exact artifact digest and references supplied
documents for: rule provenance, execution status, observation completeness,
applicability comparisons, and a violation comparison. Each operand is a
`FactRef(document=..., path=(...))`, not a fabricated literal. It supports only
scalar equality/inequality and numeric greater/less comparisons. It records
the check/document digests and the exact values or missing paths used.

- A recorded failed execution is `execution_error`.
- Missing rules, facts, completed execution, or complete observations remain
  `inconclusive`; unknown values are never replaced with defaults.
- A rule whose prerequisites are false is outside this check's scope, not proof
  of a safe target.
- Safe/unsafe means only that the explicitly supplied check was satisfied or
  violated. Rule prose is provenance, not proof that the expression correctly
  interprets it; `rule_interpretation_independently_verified` remains false.
- No rule is inferred from tool names, schemas, a state change, or a missing
  call. `vulnerability_confirmed` stays false.

The neutral tests contain illustrative rules for answers, refunds, payment
changes, and escalation. They are **not MiniKlarna policies** and are never
attached to saved cases automatically. In particular, an applied refund amount
is distinct from a requested amount, and absence of escalation requires both
applicability and a complete observation.

Run the offline controls without Garak, a target, or an LLM:

```bash
.venv/bin/pytest scripts/qualification/test_outcome_checks.py \
  scripts/qualification/test_calibration.py \
  scripts/qualification/test_evaluation.py -q
```
