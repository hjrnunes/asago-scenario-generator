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
   `out_of_scope`, `not_testable`), `constraint_ids`, `constraint_quote`, and
   `reason`. Code checks references only: `carried` needs at least one
   existing ID; a disposition needs a reason. A `constraint_quote` that does
   not quote a cited rule is recorded as a warning, not a finding, because
   live responses cite the right ID but copy a neighbour's wording. An
   uncovered, invalid, or omitted row is a finding. At most five findings go
   to the revision.
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
- A live smoke of extraction and mapping only (12 calls, no generation) ran
  on saved g12/g13 loss analyses for MiniKlarna, MiniAirbnb, and MiniOcciAI
  on `gemma4-oc` and `qwen38-oc`. See the branch report for results.
- Next: fresh generations, compared against the g13 baseline for constraint
  counts, scenario counts, and orch recovery.
