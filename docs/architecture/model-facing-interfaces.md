# Model-facing interfaces

Model responses describe semantic choices. Deterministic adapters resolve those
choices against the exact request context before existing domain validation and
publication. A mechanically valid selection is not proof of authorization,
applicability, coverage, or test soundness.

## Ownership

| Model chooses | Code supplies |
| --- | --- |
| Which observed fact supports a claim or condition | Exact path, source bytes, typed value, deduplicated used-fact registry |
| Which available obligation/check combination expresses the test | Admissibility, canonical obligation reference, fixed target action, allowed operands |
| Which supplied number is the governing bound and why | The selected source's numeric value |
| Exact stimulus and semantically relevant earlier claims | Fixed user roles and source-reference assembly |
| Coverage verdict and which source excerpts support it | Verbatim selected quotations and their source identities |
| Which graph records need changing and their new meaning | Untouched records, identity allocation, reference resolution, complete-graph validation |
| What belief exists and which observation updates it | Nested association and process-model identifiers |
| Whether a structural relationship makes sense | Deterministic reference/completeness diagnostics |

## Request-local evidence and choices

Named model profiles optionally support OpenAI reasoning controls:
`reasoning_effort` and `service_tier` pass through as top-level request fields.
Because hidden reasoning counts against the completion cap, a profile that
sets `reasoning_effort` raises every smaller call-site cap to its own
`max_completion_tokens`; other profiles keep the call-site caps.
If a configured `service_tier` receives HTTP 429, the client retries that
request once with `service_tier_fallback` and records the tier change. A
separate retry, made once per request, follows an HTTP 5xx status or a
non-timeout connection error (`provider-calls.jsonl` records both attempts).
Set
`sampling_controls: false` to omit temperature, top-p, top-k, seed, and
chat-template thinking controls. Set `strict_json_schema: true` to normalize
Pydantic response schemas to OpenAI Structured Outputs form and restore
defaulted fields when the provider returns null. Set `json_schema_strict: false`
to send the original Pydantic schema with `"strict": false`; local Pydantic
validation remains authoritative, and this setting takes precedence over
`strict_json_schema` for the request schema. OpenRouter JSON-object and vLLM
guided decoding compatibility paths are unchanged.

The transport sends a strict call's JSON Schema as `response_format` whether
or not the profile sets `use_guided_decoding`. A guided vLLM endpoint decodes
against that schema, so for a client whose profile sets
`use_guided_decoding`, the call sites below send tightened request schemas
that close every vocabulary code later matches on. Every other client
receives the static schemas byte for byte, pinned by digest in
`tests/stpa/test_guided_schema_constraints.py`. For every client, a Stage 1b
draft that its promotion to `CapabilityProfile` would reject fails
validation and receives one correction.

Under guided decoding, Stage 1b requires `kc_subcodes` with at least one
known KC or KCX code and requires `tool_inventory` (it may be empty). The
Stage 1a risk-derivation schema
limits `source_risk_cards` to the supplied risk-card IDs and lists exactly
one disposition row per supplied card, in supplied order, with each row's
`risk_ref` fixed; the disposition repair schema does the same for the
selected cards. An enum plus a row count was not enough: `qwen38-oc`
repeated some cards and skipped others. The discovery interpretation schema
allows at most one `semantic_roles` entry from `text_search`,
`identifier_lookup`, `state_observation`, `state_change`, and
`command_execution`, and limits `tool_handle` and `observer_tool_handles` to
the batch handles; the verifier schema limits `tool_handle` the same way.
Only `text_search` is matched downstream. The other roles exist because a
guided decoder that means to write any role must pick an enum value: with
`text_search` as the only value, a qwen38-oc smoke tagged every tool
`text_search`. For the same reason `evidence_refs` stays open, since a
batch-wide enum let a row cite another tool's fields. These enums exist in
the request schema only; local validation keeps its existing checks and
feedback.

Handles identify explained entries in one request. The request includes enough
source context for the author to distinguish entries; a handle alone is not an
explanation. Index construction depends only on supplied inputs and has an
explicit size bound. Oversize or unresolved material produces an explicit
failure rather than truncation or guessed source selection.

Normal Stage 5 renders target-operation and target-observation sections only
when those facts are supplied. It asks for concrete record and observed-value
grounding only when both sources are available; operation-only requests retain
the operation schema without inventing a record, and target-blind requests
retain generic STPA grounding. The authored bounded
`semantic_proposition` is copied verbatim into the published handoff's
`semantic_failure_criterion`; deterministic code continues to own lineage
identities and relational joins.

When an observation contract and target operations or observations are
supplied, every executable Stage 5 scenario also returns
`unsafe_outcome.discriminating_condition`; analytical-only scenarios return
`null`, and target-blind requests do not see the field. The request lists
every citable fact as an absolute path with its type (`object`, `list`, or
`value`) and scalar value, including read-observation
`<ref>.arguments.<name>` facts, followed by one worked observed selection
with synthetic names. The condition holds a one-line `statement`, one to six
`comparisons`, and a `record_selection`:

- A value comparison relates two operands with `eq`, `ne`, `gt`, `ge`, `lt`,
  `le`, `in`, or `not_in`. An operand is an operation `argument`, a supplied
  fact `path`, or a `literal`; at least one operand is an argument or a fact.
- An order comparison states that `operation` runs without an earlier
  `requires_prior` call, optionally for the same argument value.
- A `not_called` comparison states that the unsafe behavior is the omission
  of `operation`.
- The record selection names the observed record the unsafe call acts on
  (the target of the violation) and, in `argument_values`, the arguments
  that select it with the fact paths that supply their values, or marks the
  record `unavailable` with a reason. An argument whose value the request
  chooses (for example a quantity compared with a record's limit) stays out
  of `argument_values` and is compared as an argument operand; a second
  worked example shows this bounded-value shape. The prompt asks for an
  observed record whenever a listed one meets the comparisons.
- When no supplied record of the subject type exists and a documented
  operation creates one, the record is `unavailable`, the reason names the
  creating operation, and the test creates the record in the same session.
  A record of a different resource type is never cited because it shares a
  word with the subject.
- `order` is for rules about call sequence. A rule about who may act on a
  record whose owner or party fields and session value are supplied is a
  value comparison, even when worded as a prior verification.
- A trigger that supplied facts or the request subject establish before the
  run is stated from those facts, not as the result of a run-time lookup.

The same request tells the model that a precondition is not an observation
requirement: a claim about what a reply states is observable through
`assistant_message` when the supplied facts establish the precondition and
the reference to judge it, even though returned results are not captured.

Reply content is not an operand. Code resolves every reference against the
request's operation inventory and fact paths, makes `argument_values` paths
written relative to `record_path` absolute, and evaluates each value
comparison against the selected values. Order and `not_called` comparisons
and arguments without a selected value are `not_checkable`.

Code also derives record kinds from the TARGET-STATE snapshot
(`condition_index.py`): collections follow the `RecordIndex` rule. Key
domains are those collections plus every top-level mapping whose values are
all lists (for example records keyed by a subject ID). A field links to a key
domain when every observed string value of the field is a key of that
domain. Two checks use this index:

- Two ID-shaped strings (letters, an optional `-` or `_`, then digits) with
  different prefixes and disjoint observed domains, at least one being a
  record key, are different kinds of value. Comparing them with `eq`, `ne`,
  `in`, or `not_in` is a reference error, because it holds or fails for
  every record alike. Values not found in the state are not flagged.
- With an observed selection, a fact inside a collection record must lie in
  the selected record or one link from it (a record whose key a field of the
  selected record holds, or a record whose linking field holds the selected
  key). Top-level scalars, collection paths, and read-observation facts are
  exempt.

A value comparison with no argument operand and no fact in or one link from
the selected record restates a precondition. Code reports it
`not_checkable` with the reason `precondition only; does not depend on the
unsafe call` and does not evaluate it, even when the snapshot would violate
it, since its result does not change with the record the unsafe call acts
on. The overall status still comes from the remaining comparisons. The
condition
check runs after every other Stage 5 check. An unresolved reference or a
violated comparison fails the result validator, so the existing validation
retry delivers the exact `discriminating_condition_check_failed:` text as the
one correction; that text asks for condition changes only and keeps the
observation fields unchanged. If the corrected response still fails only
because of its condition (missing, unresolved, violated, or structurally
invalid), code removes the condition and publishes the scenario with
`discriminating_condition: null`, `condition_check: null`, and a code-owned
`condition_omitted_reason` naming the failure code; the exact failure stays
in the call log. A `command_attempt` claim is scored by a tool-call condition,
so code does not publish that claim without one. When the omitted-condition
scenario's safe outcome is a `command_attempt` claim, code moves it, with no
new model request, to the `reply` claim if the response declares a reply
criterion the observation contract supports, and to analytical-only
otherwise (code never writes reply wording). The note says which; every
changed field, with the failure code in the reason
`condition_dropped_<route>:<code>`, goes to the Stage 5 normalization record. A
condition returned for an analytical-only scenario is
discarded with its own `condition_omitted_reason`. The condition never
causes a scenario to be dropped. The accepted condition and its
`condition_check` flow into `ScenarioSpec`, the deduplication key (as
canonical sorted comparisons), the Gherkin `Given` steps, and the handoff.

When a realized operation and TARGET-STATE are available, code derives
generic condition families per operation (`condition_family.py`) from the
operation schema and the state index only:

| Family | Derived when |
| --- | --- |
| `ownership` | A key argument's records carry the session subject in a field, directly or one forward link away, and some record holds another value; or a subject argument (a field name, or a key domain containing the session value) has other observed values. |
| `flag` | A boolean field of the bound records shows both `true` and `false`. |
| `bound` | A numeric argument and a numeric field of the bound records, or of records one forward link away. |
| `state` | A string field that every bound record has, with 2 or more distinct values but fewer than the records, and no value that has whitespace, is ID-shaped, is a record key, or is a top-level string of the state. |
| `prior_read` | A non-state-changing `read` or `observe` operation takes an argument bound to the same key domain. |

An argument binds to a key domain by field name (a field linking to exactly
one domain, or a string field of records that the argument names) or, failing
that, by inferred prefix (the argument without `_id` is prefix-compatible
with the sole shared ID prefix of exactly one domain). The binding label is
recorded with the family.

Each INCORRECT slot deals its operation's `ownership`, `flag`, `bound`, and
`state` families round-robin across the slot's ICAs in threat order. Each ICA
yields one Stage 5 candidate per assigned family, at most 4; an ICA with no
family keeps one plain candidate. A WRONG_TIMING ICA keeps one candidate with
its first `prior_read` family. Other slots are unchanged. Scenario IDs stay
contiguous, and synthesis contexts are keyed by scenario ID, so family
siblings share an ICA but not a context. Authored scenario bundles skip the
fan-out.

The Stage 5 user message shows one optional family hint before the condition
example: the family kind, operation, argument, field paths, and candidate
record paths grouped by value (4 per value, then a count). The hint allows
the model to decline; a declined family is written as a condition with
`record_selection.status: unavailable` and a reason. Code records each
candidate's family, binding label, capped-out families, and whether the
accepted condition honoured, declined, or ignored the family in
`condition-families.yaml` next to `testability.yaml`. The sidecar is a
diagnostic and does not affect acceptance.

Normal Stage 5 validation corrects three unambiguous slips in place instead
of spending the correction request on them:

- A `safe_observable_outcome.record_refs` entry that is a supplied record or
  collection path becomes its top-level `observation_ref`, and the path moves
  to `fact_refs`. Any other unsupplied reference still fails.
- The deterministic observation assessment decides `observable`. For an
  analytical-only scenario, code sets `observable: false` and clears the
  claim, operation, and references. For an executable scenario whose
  supported criteria are all `reply`/`assistant_message`, code sets
  `observable: true` with that pair. Any other contradiction still fails.
- An intention that cites at least one declared causal factor drops its
  undeclared handles; an intention with no declared handle still fails.

Each correction is recorded in
`<run_dir>/stage5-normalizations/<context_digest>.yaml` as
`{field, original, normalized, reason}` entries, so published values stay
distinguishable from the model's response. The handoff schema is unchanged.

Stage 5 renders plain-language capture guidance from the supplied observation
contract. It describes only capture kinds marked `available: true`: complete
assistant-message capture supports concrete reply-level claims, and complete
tool-call capture supports operation presence, decoded arguments, same-capture
call ordering, and operation omissions. Comparative reply claims still require
paired evidence. Model-to-model prompts, internal signals, unobserved state
effects, returned results without a supported result claim, missing replies,
and events outside the captured conversation remain unsupported. An executable
omission uses an observable `command_attempt` criterion naming the operation
that should have been called, plus a safe observable outcome using the expected
call when that call is the supported safe boundary. A `not_called`
discriminating condition describes omission in the same complete tool-call
capture; a temporal `absence` factor retains its `until_step_handle` boundary.

## Target discovery verification

Target discovery sends each batch of observed tools to an interpreter and then
to an independent verifier. The verifier returns one verdict per request-local
handle: `tool_handle`, a one-sentence `reason`, and `agreement` (`agree` or
`disagree`). Each interpretation keeps its own verdict, so a disputed tool
loses only its own verification; the other tools in the batch stay agreed. A
disagreement becomes a `verifier_disagreement` warning that names the tool and
quotes the reason.

When the model's verdicts do not cover every handle exactly once, the
verification call fails and every tool in the batch stays `unverified`. A
non-model adapter may still return one batch-level boolean or enum, which
applies to every tool in the batch.

## Target evidence, context tables, and security mechanisms

When discovery supplies a target profile or observations, `target_evidence.py`
projects them into one bounded, citable evidence block. A simulation-basis
profile contributes no operations. The block has four kinds of reference:

| Reference | Source |
| --- | --- |
| `operation:<name>`, `argument:<name>.<arg>` | Observed tool inventory and schemas |
| `session:<field>` | Top-level scalar state fields |
| `state:<collection>.<field>` | State collections, with up to 6 observed values per field |
| `policy:<observation_ref>` | Captured policy reads, quoted and bounded |

The block reaches these requests:

- Risk actionability (`risk-actionability.yaml`) runs before Stage 1a. The
  model marks each risk card `actionable`, `outside_boundary`, or
  `not_applicable`; only actionable cards reach Stage 1a. The model judges
  the card's description, threat, and consequence together: a card whose
  threat names an outside actor stays actionable when the system's own
  replies or tool calls can produce the described harm. A card the model
  does not classify after one retry stays actionable with `source: fallback`
  and a warning.
- Stage 1a hazard and constraint requests, Stage 2 calls 1, 2a, 2b, and 3,
  the completeness critic, and the revision request.

Stage 2 adds optional, backward-compatible context fields; empty values are
omitted from `control-structure.yaml`:

- A process-model part may list the distinct `values` that change a decision
  and the `evidence_refs` it tracks. Call 2a asks for a content-support
  variable (whether stated content has a source the controller may rely on)
  on every responsibility whose output states content to a recipient.
- A control action may name the observed `operation` it invokes and the
  `process_model_refs` of its own controller's variables. A reference to
  another controller's variable fails validation.
- A feedback channel may name its `source_kind`. `user_message`,
  `conversation_history`, and `retrieved_content` are untrusted.

After derivation and after revision, code drops an unsupported
`evidence_refs` entry or unobserved `operation` with a warning and reports
observed operations that no action names. A revision that restates a
responsibility keeps the context fields it omits.

Code derives each action's context table from the product of its referenced
variables' values, within a budget of 12 rows (`MAX_CONTEXT_ROWS_PER_ACTION`).
A product of at most 12 combinations is shown whole, in reference and value
order. A larger product is sampled without enumerating it: every value of
every variable appears in some row whenever no variable has more than 12
values, and the remaining rows cover value pairs that no earlier row holds.
The selection is deterministic and ignores the order of `process_model_refs`.
A row's ID is its 1-based position in the full product (`CA-1-1:ctx-14`), so
an ID always names the same combination. `synthesis-manifest.yaml` records,
under `context_tables`, the budget and, per action, the number of
combinations, the rows shown, and the values no row shows. The Stage 3
prompt does not say that a table is a sample.
Stage 3 receives the rows of its target's actions, and a finding may cite one
row of its own slot's action as its `context_row`; any other row fails and
spends the existing retry. The cited assignments become the ICA's
`process_model_context`. The table does not limit which deviations are
unsafe: a finding whose unsafe context no row expresses uses
`context_row: null`.

When a reply slot's findings for one constraint cite a variable that a
`retrieved_content` channel updates but leave some of its values without a
cited row, the adapter makes one supplement call for the target
(`synthesis_ica_context_system.j2`). The request lists each gap's
`gap_id`, slot, action, constraint, hazards, uncovered rows, feedback IDs,
and existing findings. The response holds one entry per `gap_id` with
`findings` (the ordinary finding fields; each must cite a listed row and only
the gap's constraint) and `rationale`. Code appends the findings to the slot;
a failed supplement keeps the slot as validated. The slot response still
reports one provider call; `calls.jsonl` records the supplement separately.

A Stage 5 causal factor may carry one STPA-Sec `mechanism`. Each source
choice lists its `feedback_source_kind`, its trust, and its
`compatible_mechanisms`:

| Mechanism | Factor kinds | Feedback sources |
| --- | --- | --- |
| `none` (default, omitted) | any | any |
| `accepted_untrusted_claim` | process-model flaw, sensor anomaly | user message, conversation history |
| `injected_instruction` | sensor anomaly | retrieved content |
| `backend_non_enforcement` | actuator anomaly | not applicable |

An incompatible mechanism fails with `mechanism_source_mismatch:` and spends
the existing validation retry. The scenario specification's causal factor
records the mechanism. The handoff contract does not carry the field.

Each Stage 5 draft check that rejects a response raises a typed
`ValidationIssueError` with one `IssueCode` (`stage5/issues.py`). The error
text stays `<code>: <detail>`. A schema failure on a field with its own
guidance (`temporal_condition`, the evidence-status fields,
`semantic_proposition`) carries that field's code. The correction request
lists repair guidance only for the codes the rejected response raised,
followed by the available causal handles. A failure without a code gets the
general instruction and the handles, with no code lines. The publication
note for a dropped discriminating condition names the code of the final
attempt's issue, not text found in its message.

## Target-realization extension

The bounded `extend_uncovered_operations` step returns exactly one outcome for
each uncovered observed operation. An accepted outcome proposes the minimum
additive action and cites observed and systemic evidence. A rejected outcome
must include a non-empty, one-sentence rationale grounded in the supplied
evidence. The provider validator names every rejected operation missing a
rationale in the existing one-attempt correction feedback. If the correction
still fails, salvage retains individually valid outcomes; it does not invent a
rationale, and compilation reports a blank rejection as `no rationale`.

Evidence selections are resolved before domain validation. Selecting a state
fact does not make an adversarial claim about it true. Literal operands remain
separate from source-bound operands; code cannot infer the governing policy
bound from a field name, equal number, or fact order.

Current provider response schemas describe source- and check-specific required
fields. The request-local authoring schema enumerates the exact displayed
1-based `applies_when` indexes for condition evidence. A rule with no
conditions exposes an empty `conditions_established` tuple rather than an
unbounded condition entry. Historical response decoding remains a separate
compatibility seam; old saved artifacts are not rewritten or silently
repaired. Provider-visible schema checks and local parsing must be tested
together through the actual request builder.

The authoring root selects one closed result: `result.kind: scenarios` carries
one to three drafts and no reason field; `result.kind: no_scenario` carries a
nonblank `reason` and no drafts. Code derives the durable empty collection or
null reason. The model does not synchronize a nullable reason with a scenario
list. Mixed results and the previous flat provider envelope fail closed; saved
flat responses may be examined by an explicitly recorded offline translation,
never a live-parser fallback or a rewrite of historical run evidence.

Current authoring keeps valid siblings when a structurally parsed draft selects
an unknown handle or fails adaptation. Malformed JSON or a missing required
structural field still fails parsing of the response as a whole; this change
does not claim row isolation before that boundary. Coverage review performs
its own row-level parsing and retains valid sibling rows.

## Authority and observation limits

Reviewed obligation/action connections control admission. A selected admissible
choice proves structural compatibility only. Proposed direction authority,
unknown realizations, unresolved relationships, and missing reviewed bindings
retain their existing distinctions. No model-controlled field grants reviewed
authority.

Omission evidence establishes source presence, not that the obligation applies.
Functional tests remain persisted specifications that are never prepared for
execution.
Attempt-level checks never establish completed state effects.

The semantic proposition limit remains 600 characters. In the structured
branch the authored proposition carries the trigger sentence only; exact
evidence, locators, meanings, attestations, and the unresolved applicability
stamp stay in the typed `OmissionEvidenceBasis` on the scenario
specification. Source values and evidence serialization stay code-owned;
representation retains exact selected evidence and the applicability caveat.
Evidence that cannot fit the basis bounds remains an explicit uncompiled hold
with the original evidence retained; nothing is truncated or removed to fit.

## Corrections and preservation

A graph revision edits selected records and adds explicitly local declarations.
Unselected records survive in code. A changed rule must not inherit stale
obligation interpretations accidentally. Existing accounting, density,
source-span, authority-restamping, and final graph checks still apply. Risk
classification/disposition and loss citation remain distinct semantic records.

An obligation `rule_span` must be a verbatim (case-insensitive) substring of
its constraint `rule`. Every prompt states this rule in the words of one
template partial, `_rule_span_requirement.j2` (contiguous substring, compared
case-insensitively), which the derivation, revision, and repair prompts include
and the Python-built correction texts render through `rule_span_requirement()`.
Before that check, the Stage 1a risk-derivation and
gap-analysis parsers and the graph-revision compiler map a non-verbatim span
to the rule text it denotes when exactly one mapping exists:

- `whitespace`: the span matches after collapsing whitespace and normalizing
  typographic quotes and dashes.
- `ellipsis`: every fragment between `...` or `…` markers occurs in the rule
  in order; the span becomes the rule text from the first fragment's start to
  the last fragment's end.

A match whose placements yield different rule text (for example, a repeated
fragment) is refused, not resolved by position. Each repair is a
`rule_span_repaired` entry in `loss-analysis-repair.yaml`, a
`stage_1a.rule_span_repairs` row in the run manifest, and a normalization
warning. The logged provider response is not rewritten, but the repaired body
is the one every later check reads, including the response a targeted repair
adapts after another defect; a risk-derivation or gap-analysis repair entry
therefore reads `applied`. (The graph-revision compiler still marks the
repairs of an attempt it did not accept `discarded`.)

A span that no mapping resolves goes to the targeted obligation repair as
before. When the corrected entry's `rule_span` still is not part of the rule
and nothing else in the entry broke the repair's scope, code drops that
obligation instead of stopping the run. A constraint left with no obligation is
dropped with it. Each drop is a `rule_span_dropped` entry (outcome `dropped`,
the span and the rule under `proposed`) in `loss-analysis-repair.yaml` and a
normalization warning; the dropped obligation has no `repair` entry. The drop
applies to `risk_derivation` and `gap_analysis`; the graph revision keeps its
own drop of slipping records.

The risk-derivation request asks for `risk_dispositions` rows in the
supplied risk order. When a response reaches its completion-token cap inside
that array and does not decode, code keeps the decoded graph and every
complete row, collapses duplicate rows that agree, and sends the risks still
missing to the existing incomplete-disposition repair. The recovery applies
only when the text before the array decodes; each use is a
`truncated_disposition_recovery` entry in `loss-analysis-repair.yaml`.

The Stage 1a density revision prompt follows each `hazard H-n has no
constraint` check with its repair: a constraint whose `related_hazards`
includes that hazard. Code resolves a hazard addition that restates an
existing hazard (same description, ignoring case and whitespace, and no loss
the existing hazard lacks) to that hazard's ID instead of adding a duplicate,
and records a normalization warning. A `rule_span` that is not in its
rule fails with the span and the rule quoted; on a constraint addition, the
error names the addition's handle, because the provider never sees the ID
code assigns to it.

The post-review density gate exempts a hazard or constraint that the
semantic review explicitly marks `unresolved`. The exemption becomes a
`post-review unresolved:` advisory check. A kept record left without its
partner still fails the gate and receives the scoped correction round.

Stated use-case rules (`stated_rule_coverage.py`) use two requests before
the density gate. Extraction sees only the use-case text and returns a
verbatim `quote`, a `restatement` ("The system must/may ..."), and a
`modality`; code keeps the exact source excerpt and rejects unmatched quotes,
other restatement forms, and duplicates. Mapping sees each constraint's
`rule` only (no `applies_when`) and returns a verdict, cited IDs, a
`constraint_quote`, `shared_terms`, and a reason. Code uses the quote to
locate the carrying constraint rules: a quote found in no rule makes the rule
a finding, and a quote found only under other IDs moves the judgment there
with a warning. `shared_terms` names 1 to 3 words of the stated rule's
specific limit that the carrying rule repeats. Code accepts a term only when
it occurs, as consecutive whole words with simple plural suffixes reduced
("agents" matches "agent", "policies" matches "policy") and `-ed`, `-d`, and
`-ing` endings matched to their base ("escalated" matches "escalate",
"blocked" matches "block"), in the stated rule's quote and in a carrying
rule, and has a word of at least four characters found in at most half of the
constraint rules; with no accepted term, the rule is a finding. Uncovered
rules never join the density revision, whose prompt and fail-closed rounds
are unchanged. Once the graph passes density, they get one non-fatal
revision round of their own, in a separately labelled section with the
exact quote. That round may only add hazards and constraints or extend an
existing `rule` word for word. Code discards the whole response, without a
correction call, when it changes any other part of an existing record or
edits an ID the graph does not have. Echoes are not changes: a condition
that differs from the original only by an echoed count heading
(`>= 1 condition:`), list number, or whitespace keeps the original, and an
`obligations` list that repeats every original entry unchanged may add
entries with new IDs. A re-mapping then judges the revised
graph, and code discards the revision when a rule the first mapping covered
loses its coverage. A covered rule whose cited constraints still repeat its
accepted shared terms keeps its first verdict, so re-mapping variance alone
cannot discard the round. `stated-rule-coverage.yaml` records the outcome.

Call 2a ignores an unknown field inside a responsibility when its value is
empty (`null`, `""`, `[]`, or `{}`). An unknown field with content still
fails, and the retry lists the fields a responsibility may contain. Any
alternate top-level collection still fails, even when empty.

Call 3 lists each constraint's obligation phrases. A `revise` decision must
keep every phrase verbatim in the new rule; otherwise the retry names the
dropped phrase and asks the model to keep it or preserve the constraint.

A call 3 coordination link may name a `shared_pm` only when one endpoint
responsibility owns that process-model part. A retry lists every link that
breaks this rule, the actual owner, and the endpoints' own parts.

A graph-revision response that fails parsing or validation receives one
correction call carrying the exact validation error and the prior response.
If the correction also fails, the stage fails with the correction's error;
`graph_revision_call_count` records both calls.

Coverage materialization preserves row-local failures and valid siblings. A
source handle prevents transcription errors; it does not rescue unsupported
coverage claims or manufacture an evidence selection.

## Presentation validation

Normal product execution uses deterministic hypothesis summaries. Stage 7
validates their narrative, tree, structured Gherkin, and feature text against
that exact scenario's deterministic summary. Shared factor-evidence and
loss/hazard-reference checks remain active. The explicitly selected
model-authored presentation mode retains its legacy root-label and PM-reference
format checks. The mode comes from the run configuration, never from guessing
whether an artifact looks deterministic.

The deterministic summary builds one connected account from the selected
semantic proposition, established context, supported actor evidence, defender
BDI, declared causal factors, and exact action/hazard/constraint/loss lineage.
Every claim remains a proposed hypothesis. Functional scenarios omit actor BDI
while retaining defender and structural causality. The causal tree records
`flat` relations unless typed conjunction or alternative evidence exists; a
factor list never implies `AND` or `OR`. The renderer does not add messages,
delivery, setup, detectors, or executable checks.

The product run requests the Stage 5 semantics-only wire, whose specs carry
no executable condition, and publishes the scenario handoff from it.

## Shape step

After Stage 5, the shape step makes one request per adversarial scenario
(`stage5_shape_system.j2`, `stage5_shape_user.j2`). The response model,
`ShapeProposal` in `stpa.scenario_prod.stage5.shape_step`, is closed: `channel`,
`turn_count`, `turn_plan` entries of `position`, `speaker` and `purpose`, and
an `indirect` block of `carrier_operation`, `content_kind`, `record_ref` and
`controller`. Enums, bounded integers and whitespace-free identifiers are its
only value types, and a test asserts that no string field accepts free text.
The system prompt explains each field with one example and lists every
vocabulary. The user prompt supplies the scenario account, the adversary kind,
the channels allowed for it, and the target operations with a flag for those
whose result carries attacker-influenced content. The system prompt opens the
`indirect` field with its requirement: required when `channel` is `indirect`,
`null` otherwise. When `indirect` is among the allowed channels, the user prompt
also states that choosing it requires the `indirect` object with
`carrier_operation` copied from an operation marked `outside content: yes`. The
forged-transcript
channel, its speakers and its purpose appear in the response model and the
prompts only when `ShapeStepConfig.allow_forged_transcript` is on.

Code validates the reply and never asks the model to correct it. A failed
request, an invalid reply or a rejected shape becomes the single-turn direct
default with a `downgrade_reason`; the table in `overview.md` lists the reasons.
`tests/stpa/shape_step_prompts/` pins the rendered request for each adversary
kind.

Deduplication runs after this step. A duplicate group keeps as canonical the
smallest scenario ID among the members with a validated shape, so a shape the
model proposed is not dropped in favor of a smaller ID that holds only the
default.

Neither summary validation nor successful publication establishes test soundness or executed
safety.

## Verification

Interface tests must exercise request construction, emitted schema, decoding,
resolution, domain validation, and production integration. Include unknown and
foreign handles, duplicate selections, missing source-specific fields, bound
source/value agreement, changed reviewed bindings, unchanged graph records,
invalid edits, exact quote materialization, and summary tampering. Preserve
historical input/output hashes and report future-run schema/prompt changes.
No offline test constructs a live provider or contacts a target.
