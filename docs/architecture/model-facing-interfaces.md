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

Handles identify explained entries in one request. The request includes enough
source context for the author to distinguish entries; a handle alone is not an
explanation. Index construction depends only on supplied inputs and has an
explicit size bound. Oversize or unresolved material produces an explicit
failure rather than truncation or guessed source selection.

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
