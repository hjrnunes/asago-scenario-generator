# Stated use-case rule coverage design (2026-09-30)

Status: proposal for owner review. Nothing here is implemented. No provider
calls, target execution, or contract change is part of this note.

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

## Current state

- Stage 1a receives the use-case text as a prompt variable
  (`stpa/system_model/loss_analysis.py:1259-1268`, templates
  `stage1a_risk_user.j2` and `stage1a_gap_user.j2`). Stage 2 receives it in
  all four calls (`stpa/system_model/control_structure.py:2132-2331`).
- No step extracts the rules a use case states or checks that constraints
  cover them. The existing checks cover other things:
  - Stage 1a gates (`loss_analysis_gates.py`) check per-card risk accounting
    and hazard-graph density.
  - The risk-coverage review (`risk_coverage_review.py`) reviews taxonomy risk
    cards. It is advisory and never changes the graph.
  - `Obligation.rule_span` (`stpa/models/loss_analysis.py:52-67`) quotes the
    constraint's own rule. `_require_obligation_phrases`
    (`semantic_review.py:388`) protects that wording once it exists.
  - Run-level obligation accounting (`pipeline/obligation_planner.py:1039`)
    starts from taxonomy risk cards, not from the use case.

## Proposal

Add one bounded step after the Stage 1a gates (`stpa/system_model/run.py`,
after `_try_gate_loss_analysis` and before the risk-coverage review).

1. **Extract stated rules (one LLM call).** The model lists each explicit
   behavioral rule in the use-case text. Each entry carries a verbatim quote,
   a short restatement, and whether the rule permits, requires, or forbids
   behavior. Code rejects any quote that does not appear verbatim
   (case-insensitive, whitespace-normalized) in the use-case text. This is
   reference validation, the same kind `rule_span` already uses.
2. **Map rules to constraints (same call or a second one).** For each rule the
   model names the Stage 1a constraint IDs that carry it, or gives a
   disposition with a reason: `out_of_scope` (for example, a deployment fact
   with no agent behavior) or `not_testable`. Code checks that every rule has
   either existing constraint IDs or a disposition. The model makes the
   semantic judgment; code does no keyword matching between rule and
   constraint text.
3. **Repair uncovered rules through the existing loop.** An uncovered rule is
   a gate finding. It feeds the one bounded Stage 1a revision call that
   `_try_gate_loss_analysis` already makes, with the exact quote and the
   instruction to add or revise a constraint that carries it. If the revised
   graph still leaves a rule uncovered, the run records the rule as
   `unresolved` with the quote. It does not fail the run, so an extraction
   error cannot block generation.
4. **Record the result** in a new artifact,
   `stated-rule-coverage.yaml` (`stated-rule-coverage-v1`), pinned by digest
   like the risk-coverage review. Each row holds the quote, disposition,
   constraint IDs, and whether the revision call added them.

Stage 2 needs no new check in the first slice. Its responsibility
constraints already cite Stage 1a constraints, and the g13 loss happened at
Stage 1a. If a later run shows Stage 2 dropping a covered rule, extend the
same row with the carrying responsibility constraint.

## Cost and risk

- One or two extra LLM calls per generation, plus at most the existing single
  revision call when a rule is uncovered.
- Extraction quality bounds the benefit. A missed rule is no worse than
  today. A spurious rule costs one revision call or one disposition.
- Keeping the rule set small matters. The prompt asks only for rules the
  text states about agent behavior, not inferred good practice.
- Prompts contain only generic instructions and the use-case text. They
  contain no gold data or case-specific wording.

## Validation plan

1. Write offline tests with fixture responses for: a quote that does not
   match (rejected), an uncovered rule (triggers revision), a covered rule
   (passes), and a disposition with a reason (passes).
2. Replay extraction offline against the saved g13 loss analysis to confirm
   the whitelist rule is flagged as uncovered.
3. Run live generations under the standing approval: three MiniKlarna runs,
   and one each for MiniAirbnb and MiniOcciAI to check for spurious rules.
   Compare constraint counts, scenario counts, and the orch recovery report
   against the g13 baseline.

## Open questions for the owner

- Should an unresolved stated rule stay a warning, or become a stage error
  after the revision call?
- Should Stage 2 coverage be part of the first slice?
