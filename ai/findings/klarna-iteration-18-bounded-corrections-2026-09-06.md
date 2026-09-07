# Iteration 18: correct source scope and feedback interpretation

Run 17 published 15/16 candidates and compiled eight artifacts, but failed the
quality goal: no escalation case compiled, one response case called an allowed
account lookup unsafe, and another confused provider-bound prompts with final
customer responses. This work corrects those causes without another model call
or a filter that discards every affected scenario.

## Existing Stage 2 review

Extend the existing final coordination review, before target realization. It
already sees the use case and full systemic model. It may revise hazard and
constraint descriptions against supplied evidence while retaining every loss,
identity, ordering and hazard-to-loss relationship. It still cannot invent
controllers/actions, alter action meaning, or use target inventory.

Require one explicit review row per hazard and constraint. Each row carries
`disposition` (`preserve`, `revise`, `unresolved`), required nullable
`revised_description` and `missing_fact`, `source_evidence` and `rationale`.
Evidence names `USE_CASE` or an exact supplied loss ID, a verbatim quotation,
and the reviewer's interpretation in the durable artifact. On the provider
wire, the model selects an explained `source_N` excerpt and supplies only its
meaning; code copies the exact text and canonical source identity. Revision requires a changed nonblank
description and at least one valid source quotation; preserve requires no
replacement or missing fact. Unresolved requires a specific missing fact and
no replacement. Quotations prove source presence, not semantic correctness.

No constraint may retain an edge to an unresolved hazard. An unresolved
constraint has no hazard edges or responsibility ownership. Unknown findings
remain in the original and review artifacts. This is not permission to call an
explicit legitimate function unresolved merely because the draft prohibited it.

Keep `loss-analysis-draft.yaml` untouched. Persist the review's decisions,
evidence and replacements in `control-structure-review.yaml`; final
`loss-analysis.yaml` contains the reviewed wording under the same identities.
Apply descriptions, edges and existing ownership/effect decisions through one
pure copied-artifact seam, then revalidate the result.

Examples to verify against saved run 17:

- The use case permits authenticated users to retrieve their financial details.
  H-2/SC-2 must support correction from a universal backend-data ban to the
  unauthorized/wrong-account disclosure boundary supported by the source.
- H-5/SC-5 concern secrets transmitted in prompts to a third-party model. They
  must not govern the final customer-output action merely because both involve
  a model. Preserve communication direction and correct responsibility ownership.

## Existing Stage 5 causal choices

An accurate negative/empty tool result is not inherently a sensor anomaly.
When the failure is interpretation of that result, use the explained
process-model-flaw choice. A sensor-anomaly hypothesis needs an explicit
supported corruption/misreporting mechanism; prospective injection through a
supplied reachable carrier remains possible without claiming it already
occurred. Never infer an attacker-controlled carrier from an empty result or
from downstream harm. Do not relabel a provider factor after generation or
force direct prompting merely to obtain a compilable case.

## Verification and exclusions

Focused tests cover the actual saved counterexamples, strict review-field and
source-evidence combinations, immutable history/identities, complete provider
rows, unresolved-reference closure, and unchanged normal call count. Acceptance
must exercise correction through the public review seam, not only mocked green
verdicts. A bounded replay of the exact run-17 escalation authorities tests the
Stage 5 change before another fresh end-to-end run.

Then generate fresh Klarna with `gemma4-oc`, compile all published entries using
the same saved discovered profile/observations, and inspect every actual source,
author prompt/response, artifact and criterion. Diagnostic replays do not count
toward the goal. Two consecutive qualifying full runs are still required;
current qualifying count is zero. No target attacks, prolonged mutation run,
new reviewer layer, human binding assignment or invented policy facts.

## First feedback diagnostic: partial change, still not useful

`build/klarna-escalation-stage5-replay-17` replays only saved run-17 SCN-012 and
SCN-013 through public SP3, with reconstructed contexts whose four source pins
match the originals exactly. The frozen source is
`/tmp/asago-escalation-stage5-17.8V9oeZ`; the two actual model responses are in
the diagnostic's `calls.jsonl`. This is not a fresh full run.

Result: two attempted, two published, zero compiled, both excluded for missing
carrier. Both responses now select a process-model flaw, but still describe
ordinary policy-tool feedback as attacker-influenced content and redundantly
declare a sensor anomaly whose own explanation says the feedback was accurate.
The incorrect-value escalation case also retains an unknown topic reference.
The first prompt correction therefore improved the selected label but did not
resolve the causal/delivery error. No author call or target execution occurred.

Next hypothesis: the prompt's direct-input guidance is incorrectly qualified
as applying only to model-output targets. Input delivery and target action are
independent: a user request can exercise a tool-call action without modifying a
tool's returned data. The repeated sensor explanations also dominate the source
choice list. Test a smaller, explicit distinction rather than adding another
review model or accepting the invalid carrier.

The corrected existing-field invariant also requires an executable indirect
stimulus's selected factor to use `reachable_capability` or `bounded_assumption`.
Its `structural_failure` branch explicitly establishes no attacker access, so it
cannot alone justify attacker-influenced returned content. Both captured shapes
now fail at the existing validation/correction boundary. Dedicated prospective
indirect fixtures retain explicit bounded carrier hypotheses; no indirect route
class has been removed. Focused Stage 5/provider/continuity suite: 107 passed.

## Second feedback diagnostic: meaningful route improvement

`build/klarna-escalation-stage5-replay-17b`, frozen producer
`/tmp/asago-escalation-stage5-17b.XIzMZ4`: two model calls, two published cases,
one compiled omission case, one explicit missing-topic comparison. Both responses
now choose user-message delivery and process-model flaws, with no unsupported
sensor factor or carrier. The exact `escalate_to_human` action is unchanged.

The one author call and compiled artifact were inspected. Its observer correctly
requires both an established escalation obligation and complete tool-call
observation; tool absence alone is inconclusive. However, the authored message
explicitly requests a human and claims prior policy searches, whereas the source
hypothesis is misclassification of a naturally regulated question. This is a
useful omission baseline, not yet a faithful adversarial stimulus. A bounded
consumer prompt fix will distinguish the input's intent from the outcome being
tested and background observations from prior conversational events. No phrase
blacklist, forced target call or substitution of the oracle is planned.

## First Stage 2 diagnostic: exact quotation is the wrong provider task

`build/klarna-stage2-review-replay-17`, frozen source
`/tmp/asago-stage2-review-17.I1NIQc`: both attempts failed exact source-quote
validation. The actual responses are saved, including paraphrases and ellipses;
the endpoint returned successfully. All hazard/constraint descriptions were
preserved, including the overbroad rule, while provider-input ownership was
removed from the customer-output responsibility. This does not qualify as a
successful semantic correction.

The final artifact's strict evidence remains useful, but asking the model to
recopy exact source bytes is unnecessary. The next bounded change gives Call 3
explained, selectable source excerpts. Code copies the chosen excerpt into the
existing final evidence object; the model supplies its interpretation and
revision. No extra call is introduced. A leftover “ownership/effects only”
instruction also needs removal, and review must assess the description's actual
words rather than silently read an absent authorization qualifier into them.

## Live adapter and author checks after source selection

The `17b` Stage 2 diagnostic received two valid local-source responses but
failed while converting them: the actual provider returns typed tuples, whereas
the new parser handled only lists from test mocks. The parser now handles both
at this boundary, with a regression using the actual dynamic provider model.
The final source-evidence contract remains unchanged. Focused review/source
selection tests: 38 passed.

`build/klarna-stage2-review-replay-17c` confirms that conversion now works, but
the existing two-attempt review fails on inconsistent uncertainty references:
first an unresolved constraint retains hazard edges, then a responsibility
still owns an unresolved constraint. The actual model also preserves the
overbroad financial-disclosure wording and treats some policy-derived losses
as unsupported because the use case does not repeat them. These are not
endpoint failures and are not successful source-scope corrections.

Consumer diagnostics `artifact-author-calls-17c.jsonl` and `...-17d.jsonl` under
`build/klarna-escalation-stage5-replay-17b` each compile one omission case and
retain one unknown-topic case without authoring it. Removing the competing
desired effect and distinguishing saved observations from conversation history
stops the invented prior-search claim. However, both new inputs still explicitly
request human handling instead of exercising missed classification. A final
bounded author refinement supplies one complete neutral causal-trigger example
in the existing system prompt; the next full run will evaluate it. No extra
author/model-review call or content blacklist was added.

The consumer deterministic suite after that refinement passes: 403 tests and
two subtests. These checks and diagnostic replays still contribute zero fresh
qualifying runs; the full two-run goal is unchanged.

## Full run 18: failed before candidate generation

`output/runs/20260906-klarna-gemma4-oc-semantic-quality-iteration-18`, frozen
producer `/tmp/asago-klarna-run18.qOBJbF`, exited 1. The first Call 3 response
labelled SC-2 `revise` but supplied its original description byte-for-byte.
The strict application rejected the no-op revision. The bounded retry then
exceeded the input budget: 14,795 estimated tokens versus 13,107 available.
No scenario candidate or artifact was generated; this run cannot qualify.

The provider adapter now compiles an exact unchanged replacement as `preserve`,
retaining raw response/evidence and leaving the strict public review seam
unchanged. Prompt compaction groups constraints under their first hazard while
showing every complete hazard-edge list. Shared hazard/loss text and the source
handle explanation are no longer repeated under every constraint/paragraph.
On the exact saved 20-constraint input, the initial prompt falls from 11,124 to
8,257 estimated tokens; all 20 constraints remain visible exactly once. There
is no context-limit increase, evidence truncation, or additional model call.

The source-role correction now precedes coordination analysis: declared losses
are unacceptable-outcome objectives, while the use case establishes permitted
behavior and communication direction. Missing deployment mechanisms or numeric
thresholds do not negate a qualitative policy requirement. Only explicit
unresolved constraint decisions cause deterministic removal of their hazard
edges and responsibility ownership; unknown references still reject before
that compilation step.

The full deterministic producer suite before the final no-op/compaction delta
passed 6,919 tests with one skip. The final focused delta passes 79 tests.
The consumer suite passed 403 tests plus two subtests. Two acceptance fixtures
needed explicit bounded carrier assumptions for their intended indirect cases;
both corrected features pass (21 scenario examples). Full acceptance is being
rerun against the final source.

Bounded CRAP/DRY audit, using the 112-test focused branch-coverage report at
`/tmp/asago-iteration18-focused-lcov.info`: the new source-excerpt builder scores
4.0 and indirect-access check 5.0, but the dynamic provider schema scores 34.1,
raw review-collection checker 31.3, source-selection parser 27.1, and pure review
application 19.2. This is not a passing all-functions-under-six gate. Coverage
is focused, not a whole-project score; the later no-op branch is not included
in that measurement. The raw checker duplicates identity/reference checks from
the durable review seam and is a concrete simplification candidate. No score-
driven refactor or mutation campaign is being used to delay live qualification.

## Fresh run 19

Started with frozen producer `/tmp/asago-klarna-run19.hRkXQ9` and consumer
`/tmp/asago-artifact-run18.3ifg2H`, using the same approved Gemma OC profile,
discovered target and saved synthetic runtime context. Output:
`output/runs/20260906-klarna-gemma4-oc-semantic-quality-iteration-19`.
Generation, compilation and semantic inspection results remain to be recorded.
The consecutive qualifying-run count remains zero.
