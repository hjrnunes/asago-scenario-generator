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
request once with `service_tier_fallback` and records the tier change. Set
`sampling_controls: false` to omit temperature, top-p, top-k, seed, and
chat-template thinking controls. Set `strict_json_schema: true` to normalize
Pydantic response schemas to OpenAI Structured Outputs form and restore
defaulted fields when the provider returns null.

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
  (the target of the violation) and the fact paths that supply the argument
  values the test passes for it, or marks the record `unavailable` with a
  reason. The prompt asks for an observed record whenever a listed one meets
  the comparisons.

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
in the call log. A condition returned for an analytical-only scenario is
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
Functional tests remain persisted specifications outside execution bundles.
Attempt-level checks never establish completed state effects.

The semantic proposition limit remains 600 characters. In the structured
branch the authored proposition carries the trigger sentence only; exact
evidence, locators, meanings, attestations, and the unresolved applicability
stamp ride in the closed `stpa-omission-evidence-v1` carrier completed from
the projection's source pins, delivered through the paired
`stpa-execution-projection-v3` / `stpa-execution-bundle-v2` contract that this
seam's earlier deferral required. Source values and evidence serialization
stay code-owned; representation retains exact selected evidence and the
applicability caveat. A direct-prompt carrier records the exact authored user
text (`prepared_user_text`) verbatim with its digest, and the consumer
delivers those bytes without generative rewriting. Evidence that cannot fit
the closed carrier bounds remains an explicit uncompiled hold with the
original evidence retained; nothing is truncated or removed to fit.

## Corrections and preservation

A graph revision edits selected records and adds explicitly local declarations.
Unselected records survive in code. A changed rule must not inherit stale
obligation interpretations accidentally. Existing accounting, density,
source-span, authority-restamping, and final graph checks still apply. Risk
classification/disposition and loss citation remain distinct semantic records.

An obligation `rule_span` must be a verbatim (case-insensitive) substring of
its constraint `rule`. Before that check, the Stage 1a risk-derivation and
gap-analysis parsers and the graph-revision compiler map a non-verbatim span
to the rule text it denotes when exactly one mapping exists:

- `whitespace`: the span matches after collapsing whitespace and normalizing
  typographic quotes and dashes.
- `ellipsis`: every fragment between `...` or `…` markers occurs in the rule
  in order; the span becomes the rule text from the first fragment's start to
  the last fragment's end.

A match whose placements yield different rule text (for example, a repeated
fragment) is refused, not resolved by position. Each repair is a
`rule_span_repaired` entry in `loss-analysis-repair.yaml` (`applied` or
`discarded`), a `stage_1a.rule_span_repairs` row in the run manifest, and a
normalization warning. The logged provider response is not rewritten.

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

Generative presentation is defined only against the historical execution wire.
`run_sp3(render_presentation=True)` combined with the normal
handoff-publishing path (`publish_execution_bundle=False`) fails closed: the
normal semantics-only specs carry no executable unsafe-outcome condition, so
`prepare_execution_projection` rejects the conditionless outcome and the run
drops every scenario with a typed Stage 6 error. The product run never
combines these options — normal publication always publishes the scenario
handoff, and generative presentation remains reachable only through callers
that keep the execution wire (bundle publication).

Execution projection and bundle validation are unchanged. Neither summary
validation nor successful publication establishes test soundness or executed
safety.

## Verification

Interface tests must exercise request construction, emitted schema, decoding,
resolution, domain validation, and production integration. Include unknown and
foreign handles, duplicate selections, missing source-specific fields, bound
source/value agreement, changed reviewed bindings, unchanged graph records,
invalid edits, exact quote materialization, and summary tampering. Preserve
historical input/output hashes and report future-run schema/prompt changes.
No offline test constructs a live provider or contacts a target.
