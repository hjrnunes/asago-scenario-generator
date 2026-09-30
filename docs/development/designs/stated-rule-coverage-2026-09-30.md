# Stated use-case rule coverage design (2026-09-30)

Status: implemented on branch `feat/stated-rule-coverage` (first slice). The
owner decided that an unresolved rule is a warning, never a stage failure, and
that the first slice includes a code-only Stage 2 citation check. No contract
change is part of this work.

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
   without a limit, and enforcement a backend performs on its own. Code
   rejects an entry when:
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
   `stated_rule_findings`:
   - Density fails: the first revision round receives the findings next to
     the failing checks (trigger `combined`). Density keeps its fail-closed
     behavior; findings never add a failing check.
   - Density passes: one revision round runs for the findings alone (trigger
     `stated_rules`). It is non-fatal. A failed call, or a revision that
     breaks a structural check, keeps the unrevised graph.
   The revision user message lists the findings in a separate "Stated Rules
   No Constraint Carries" section with the exact quote. The system prompt
   adds a matching section, rendered only when findings exist: the quote is
   supporting evidence, a structural repair does not resolve a finding, and
   the model should prefer adding one constraint per rule over editing
   existing ones. A density-only revision prompt renders byte-identically to
   the previous one.
4. **Re-map and record.** When findings went to a revision that changed the
   graph, one more mapping call judges the rules on the final graph. The
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
  rule is uncovered on a passing graph, and one re-mapping call after an
  applied revision. Stage 1a call counts in the manifest include them.
- Extraction and mapping quality bound the benefit. A missed rule is no worse
  than before. A spurious finding costs a revision round that adds a
  constraint; the five-finding cap bounds that change.
- The smoke checks (below) found both failure directions: a false `carried`
  verdict and a spurious finding on a partly covered rule.

## Validation

- Offline tests (`tests/stpa/test_stated_rule_coverage.py`) cover quote
  rejection, the restatement contract, covered and dispositioned rules,
  uncovered and invalid mappings, the finding cap, provider errors, the
  rule-only revision (applied, failed, and density-breaking), the combined
  revision, the unchanged density-only prompt, `run_sp1` integration, and
  the Stage 2 warning.
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
