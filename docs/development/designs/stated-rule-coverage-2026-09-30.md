# Stated use-case rule coverage design (2026-09-30)

Status: implemented on branch `feat/stated-rule-coverage` (first slice). The
owner decided that an unresolved rule is a warning, never a stage failure, and
that the first slice includes a code-only Stage 2 citation check. No contract
change is part of this work.

Revised on branch `fix/stated-rule-isolation` after fresh gemma generations
showed a fatal combined revision (OcciAI rep1) and damaging edits (OcciAI
rep3): findings no longer join the density revision, and the rule round may
only add. The `combined` trigger no longer exists.

## Problem

Stage 1a sometimes drops a behavioral rule that the use case states outright,
and nothing notices. Every later stage builds on the constraints Stage 1a
keeps, so a rule missing there becomes a hazard class with no scenarios.

The MiniKlarna use case states under "Knowledge Grounding" that the chatbot
"does not go into details that are not on the approved information
whitelist". Three generations with the same inputs produced:

| Run (orch `runs/`) | Stage 1a constraint carrying the rule |
| --- | --- |
| `run-20260929T0920Z-klarna-g5` | SC-4: "only provide policy and fee information that is strictly contained within the approved knowledge-grounding whitelist" |
| `run-20260929T1800Z-klarna-g12` | SC-5: "only provide information found within the approved policy whitelist" |
| `run-20260929T1905Z-klarna-g13` | None. Only SC-3 (escalate when no snippet is returned) survives |

In g13 the Stage 2 reply responsibility then carries only "Maintain consistent
response quality and accuracy", and hazard H-2 yields six scenarios, all about
escalating when no snippet exists. No scenario tests a reply that contradicts
an approved snippet, such as a wrong return window. The orch scorer reports
that class as `not_generated` in every g13 run.

## Design as built

The step lives in `stpa/system_model/stated_rule_coverage.py` and runs in
`run_sp1` around the Stage 1a gates. Pinned loss analyses skip it.

1. **Extract stated rules (one call, before the gates).** The request carries
   only generic instructions and the use-case text, so the constraints cannot
   bias which rules are listed. The model returns `quote`, `restatement`, and
   `modality` (`requires`, `forbids`, `permits`), one entry per distinct rule.
   The prompt excludes deployment facts, history, figures, capabilities
   without a limit, and enforcement a backend performs on its own. It counts
   a sentence that limits what an answer may contain or which sources may
   support it as a rule about the system's reply, whatever its grammatical
   subject. Code rejects an entry when:
   - its quote does not occur in the use-case text (case-insensitive,
     whitespace- and typography-normalized, Markdown `*` and backticks
     ignored); the published quote is the exact source excerpt;
   - its restatement does not start with "The system must" or "The system
     may" (the requested form; this discards non-rules such as "The company
     launched ...");
   - it duplicates an earlier quote.
2. **Map rules to constraints (one call, before the gates).** The request
   shows each constraint's `rule` text only; `applies_when` conditions are
   omitted because a condition that mentions a subject does not state the
   behavior. Each row returns `verdict` (`carried`, `uncovered`,
   `out_of_scope`, `not_testable`), `constraint_ids`, `constraint_quote`,
   `shared_terms`, and `reason`. Code checks references only; a disposition
   needs a reason. A `carried` row passes two checks:
   - **Quote locator.** The `constraint_quote` locates the carrying
     constraints (those whose `rule` text contains it, normalized like
     extraction quotes). A quote in a cited rule keeps the cited IDs it
     matches; a quote found only in other rules moves the judgment to those
     rules with a warning; a blank quote or one found in no rule is a finding.
   - **Shared terms.** `shared_terms` lists 1 to 3 words that name the stated
     rule's specific limit. Code compares casefolded text with punctuation
     reduced to spaces, on word boundaries, after reducing each word's simple
     plural suffix (`-ies` to `-y`; `-ches`, `-shes`, `-sses`, `-xes`, `-zes`
     drop `-es`; another final `s` drops, except `-ss`), so "human agent"
     matches "human agents" and "policy" matches "policies". A word ending
     in `-ed` also matches the word without `-ed` or `-d`, and a word ending
     in `-ing` matches the word without `-ing` or with `-e` in its place, when
     at least four letters remain: "escalated" matches "escalate", "blocked"
     matches "block", and "escalating" matches "escalate". The term's words
     must occur consecutively, so "red-flag terms" does not match "red-flag
     clinical terms", and different noun and verb endings ("diagnosis",
     "diagnose") do not match. A term is accepted when it occurs
     in the stated rule's quote and in a carrying rule, and contains a word of
     at least four characters that occurs in at most half of the graph's
     constraint rules. Coverage keeps only the carrying rules that contain an
     accepted term. With no accepted term, the rule is a finding. Each row
     records `shared_terms` and `rejected_terms` (term and reason).

   The quote locator alone let a wrong ID pass when the model copied that
   rule's real words (MiniKlarna g13: the whitelist rule mapped to a
   session-data rule). The shared-terms check requires the constraint to
   repeat the limit's wording. It cannot reject a function word that happens
   to be rare in a small graph (for example "does not" in one of eight
   rules); the prompt asks for words that name the limit, and the graph
   frequency test is the only code filter, by owner decision (no word
   lists). An uncovered, invalid, or omitted row is a finding. At most five
   findings go to the revision.
3. **Revise.** `gate_loss_analysis` takes the findings as
   `stated_rule_findings`. They never reach the density revision:
   - Density fails: the density revision runs exactly as it does without
     findings, with a byte-identical density-only prompt and the same
     fail-closed rounds. If it fails, the stage fails and no rule revision
     runs.
   - Once the graph passes density, at once or after the density revision,
     one revision round runs for the findings alone (trigger
     `stated_rules`) on that graph. It is non-fatal: every rejection below
     keeps the graph that passed density and records a warning.
   The rule round may only add. It accepts hazard and constraint additions,
   and an edit that extends an existing constraint's `rule` so that it still
   contains the prior text after quote normalization (the prior text's
   closing punctuation may move) and still contains every prior obligation
   `rule_span`. Code rejects the whole revision, without a correction call,
   when the response:
   - edits a hazard or constraint ID the graph does not have (for example
     `SC-4_updated`);
   - rewrites an existing constraint's `rule`, or changes its
     `applies_when`, `related_hazards`, or obligations;
   - changes an existing hazard.
   Code also rejects a revision that fails validation after its correction,
   breaks a structural check, or loses a rule's coverage (step 4).
   The revision user message lists the findings in a separate "Stated Rules
   No Constraint Carries" section with the exact quote. The system prompt
   adds a matching section, rendered only when findings exist: the quote is
   supporting evidence, a structural repair does not resolve a finding, the
   revision may only add, and each rule gets its own constraint unless an
   existing rule can be extended word for word. For an extension, the
   section overrides the general edit rule that a changed `rule` needs an
   `obligations` list: the model omits the list so code carries the prior
   entries, and copies each `applies_when` condition as plain text rather
   than the numbered form the request displays.
4. **Re-map, check, and record.** An otherwise acceptable rule revision gets
   one more mapping call on the revised graph. A rule the first mapping
   covered keeps that verdict while its cited constraints still repeat every
   accepted shared term, whatever the new call says, because the round only
   adds. When the call fails, or a covered rule loses those terms and the
   new call does not cover it, code rejects the revision and the artifact
   keeps the first mapping. The
   artifact `stated-rule-coverage.yaml` (`stated-rule-coverage-v1`) records
   each row's quote, restatement, modality, status (`covered`,
   `dispositioned`, `unresolved`, `unavailable`), disposition, constraint IDs,
   `added_by_revision`, `sent_to_revision`, and reason, plus the digests of
   the use case, the mapped graph, and the final gated graph. Unresolved and
   unavailable rows become `stage_1a/stated_rule_coverage` stage warnings;
   the manifest summarizes counts under `stage_summary.stage_1a`.

No path through the step fails the stage: provider errors and invalid
responses produce `unavailable` status or rows.

**Stage 2 citation check (code only).** After Stage 2 revision, every
Stage 1a security constraint must be cited by at least one responsibility's
`security_constraint_refs`. Each uncited constraint becomes a
`stage_2/constraint_citation` stage warning and is listed under
`stage_summary.stage_2.uncited_security_constraints`.

## Cost and risk

- Two calls per generation, one revision round (plus its correction) when a
  rule is uncovered on a graph that passes density, and one re-mapping call
  after a revision that passes the code checks. Stage 1a call counts in the
  manifest include them.
- The first mapping judges the draft graph. When the density revision
  changed the graph, the findings and the "covered before" baseline of the
  coverage check still describe the draft, so a density edit that dropped a
  rule's coverage also rejects the later rule revision.
- Extraction and mapping quality bound the benefit. A missed rule is no worse
  than before. A spurious finding costs a revision round that adds a
  constraint; the five-finding cap bounds that change.
- The smoke checks (below) found both failure directions: a false `carried`
  verdict and a spurious finding on a partly covered rule.

## Validation

- Offline tests (`tests/stpa/test_stated_rule_coverage.py`) cover quote
  rejection, the restatement contract, covered and dispositioned rules,
  uncovered and invalid mappings, the finding cap, provider errors, the
  rule-only revision (applied, failed, and density-breaking), the density
  revision that ignores findings, the addition-only rejections, the
  coverage-loss rejection, the unchanged density-only prompt, `run_sp1`
  integration, and the Stage 2 warning.
- Live smokes ran extraction, mapping, and the rule-only revision on saved
  g12/g13 loss analyses (no generation). With shared terms:
  - MiniKlarna g13, `gemma4-oc`: the whitelist rule was a finding in 2 of 2
    runs. One rule-only revision added SC-9 (the use-case sentence as its
    rule, with a new hazard), passed the structural checks, and the
    re-mapping covered the rule with the accepted term "approved information
    whitelist".
  - MiniKlarna g13, `qwen38-oc-8k`: code rejected every extracted entry in
    2 of 2 runs (rewritten quotes, non-rule restatements), so the step
    produced no rules.
  - MiniAirbnb g13 and MiniOcciAI g12, both profiles: at most one false
    finding per run (0 to 1). The false findings came from a quote that
    refers back to an earlier clause ("such messages"), a term in a
    different word form ("diagnose" against "diagnosis"; "blocked" against
    "block"), and a term absent from the cited rule.
- Next: fresh generations, compared against the g13 baseline for constraint
  counts, scenario counts, and orch recovery.
- 2026-10-01 extraction probe, `gemma4-oc-65k`, 3 calls per use case. Before
  the grammatical-subject paragraph, gemma returned 1 or 2 MiniAirbnb rules
  (only trust-and-safety escalation) and never the policy-grounding rule,
  whose sentence has policy documents as its subject. After it, gemma
  returned 5 or 6 MiniAirbnb rules, including policy grounding in 3 of 3.
  MiniKlarna (2 rules) and MiniOcciAI (6 to 8 rules) did not change.
- 2026-10-01 control probe, same setup. Without the paragraph's example,
  MiniAirbnb fell back to 1 or 2 rules, so the example carries the effect.
  The first example ("only signed quotes set a price; a draft quote is not
  a price") shared its shape with the MiniAirbnb sentence. A domain-neutral
  example ("forecasts come from the national weather service") gave the
  same result: MiniAirbnb 5 or 6 rules with policy grounding in 3 of 3,
  MiniKlarna both rules in 5 of 6 calls, MiniOcciAI 7 or 8 rules. The prompt
  keeps the neutral example.
