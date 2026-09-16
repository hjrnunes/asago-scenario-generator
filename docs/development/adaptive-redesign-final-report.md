# Adaptive redesign final report

**Recorded:** 2026-09-16
**Branch:** `codex/adaptive-scenario-artifact-split`
**Validation assertion:** `VAL-REPORT-001`

## Outcome

The final reporting package is complete. It covers all F-01–F-04, S-01–S-05,
and P-01–P-03 requirements, preserves before/after scenario examples, records
usage by generation, authoring, review, and execution stage, and appends the
correction trail without rewriting earlier evidence.

The contract assertions passed through M2. M3 scrutiny also found three
material follow-ups: an unseen F-01 compound completed-effect verb, uncovered
F-02 synonym negation/deferment, and S-03 functional prompt framing in the
consumer. The report keeps those findings open.

## Requirement matrix

| Family | Corrected behavior | Evidence | Status |
|---|---|---|---|
| F-01 | Command observation does not establish a completed effect. | `evidence/M1/consumer-pytest-m1/VAL-FID-001-pytest.log`; Klarna qualification excerpt | Validated; one scrutiny follow-up |
| F-02 | Stimulus meaning requires affirmative operation, value, and record evidence. | `evidence/M1/consumer-pytest-m1/VAL-FID-002-artifact-design-pytest.log`; functional design excerpt | Validated; one scrutiny follow-up |
| F-03 | Design prerequisites are rechecked before dispatch. | `evidence/M1/consumer-pytest-m1/VAL-PREREQ-001-pytest.log`; OcciAI qualification | Validated |
| F-04 | Required target context reaches authoring and dispatch without guessed identities. | `evidence/M1/consumer-pytest-m1/VAL-CTX-001-pytest.log`; OcciAI qualification | Validated for the confirmed route |
| S-01 | Authored semantic propositions survive handoff publication. | `evidence/M1/producer-pytest-m1/VAL-SEM-001-SCN-034-criterion-excerpt.yaml`; functional handoff excerpt | Validated |
| S-02 | Defender beliefs, desires, and intentions cite their owned sources. | `evidence/M2/producer-pytest-m2/VAL-QUAL-001-bdi-grounding-notes.txt` | Validated |
| S-03 | Functional handoffs retain `kind: functional` and empty attacker BDI. | `evidence/M2/e2e-confirmations-m2/VAL-FUNC-001-handoff-excerpt.json` | Validated for producer; consumer prompt follow-up |
| S-04 | Gherkin names a concrete trigger and safe expected behavior. | `evidence/M2/producer-pytest-m2/VAL-QUAL-003-pytest.txt`; functional handoff excerpt | Validated; semantic boundary note |
| S-05 | Causal references distinguish identity, permission, eligibility, and review. | `evidence/M2/producer-pytest-m2/VAL-QUAL-004-pytest.txt` | Validated |
| P-01 | Stage 1a revision edits the named failing relation and rechecks the graph. | `evidence/M2/producer-pytest-m2/VAL-QUAL-005-revision-prompt-excerpts.txt` | Validated |
| P-02 | Stage 5 prompts include only supplied facts. | `evidence/M1/producer-pytest-m1/VAL-SEM-002-pytest.txt` | Validated |
| P-03 | Authoring evidence contains prompts, raw response, controls, and pins. | `evidence/M2/consumer-pytest-m2/VAL-QUAL-006-pytest.txt` | Validated; cleanup-history follow-up |

The mission companion matrix records the assertion IDs, source citations,
open scrutiny boundaries, and complete evidence paths. It is stored in the
mission durable library as `final-requirement-evidence-matrix.md` alongside
the other mission records.

## Before and after examples

The corrected representations preserve semantic ownership:

1. **Refund:** before, a refund command and completed payment were conflated;
   after, the `process_refund` command is observed separately and the
   qualification record says `target_effect: not_established`.
2. **Clinical draft:** before, dispatch could omit the draft-to-patient
   prerequisite or guess `UNKNOWN`; after, PAT-104, draft status, and session
   ownership remain checked through dispatch, which records an explicit
   human-review rejection.
3. **Functional handoff:** before, functional cases could acquire adversarial
   framing; after, `SCN-009` retains `kind: functional`, empty attacker BDI,
   an explicit refund-limit criterion, and a safe refusal step.
4. **Graph and authoring evidence:** before, a graph revision could leave the
   failing edge intact and raw provider output was not fully inspectable;
   after, the named edge is repaired and prompts, raw responses, controls, and
   transformations are pinned.

The complete scenario tables are in the mission companion
`before-after-scenarios.md`.

## Usage accounting

The preserved usage ledger separates the stages:

- Producer generation: 3,287 historical call records across 29 runs.
- Producer Stage 1a: pinned final confirmations use zero derived calls.
- Producer Stage 2/routing: 149 semantic-review and 117 routing records.
- Producer ICA/realization: 1,210 enumeration, 184 verification, 101
  correction, and 571 realization records.
- Producer Stage 5: 926 authoring records in the historical total.
- M3 extension: 635 producer generation, 6 live consumer authoring, 4
  single-attempt Garak executions, and 0 judge calls.

The registered caps, target rows, reserve rules, and exact run boundaries
remain in `library/budget-ledger.md`.

## Verification and claim boundary

- Producer quality, generated acceptance, and 7,852 producer tests passed.
- Consumer quality passed. Consumer pytest had 704 passed and 2 subtests
  passed, with only the documented nested-worktree path assertion failure.
- Independent scrutiny covered one unseen counterexample for all twelve
  requirement families.
- No report entry treats a command-level unsafe verdict as a completed
  backend effect.

The independent scrutiny report is the mission durable library record
`independent-scrutiny-report.md`.
The append-only correction trail is
`adaptive-redesign-revisions.md`.
