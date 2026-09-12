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
fields. Historical response decoding remains a separate compatibility seam;
old saved artifacts are not rewritten or silently repaired. Provider-visible
schema checks and local parsing must be tested together through the actual
request builder.

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

The current consumer proposition limit remains 600 characters. Source values
and evidence serialization are code-owned; representation must retain exact
selected evidence and the applicability caveat. Essential evidence that cannot
fit remains an explicit uncompiled hold. A separate structured evidence carrier
through the consumer would require a paired versioned contract change; this
interface update does not silently add one or remove evidence to fit.

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
