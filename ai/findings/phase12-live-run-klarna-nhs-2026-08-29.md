# Phase 1/2 live run: Klarna fs-isac v36 and OcciAI NHS on gemma4-oc

**Date:** 2026-08-29 → 2026-08-30
**Commits under test:** `aaca0bc` (typed taxonomy obligation planner, Phase 1) and `6be244a` (typed observational Phase 2 synthesis)
**Runtime:** `gemma-4-26b-a4b-it` served from the OpenShift endpoint; `gemma4-oc-taxonomy` (t=0.4) for taxonomy generation, `gemma4-oc` (t=1.0) for STPA; exhaustive mode; 2 workers for STPA
**Artifacts:** `output/runs/20260829-phase12-live/` (all paths below relative to it)

**Status:** Observational findings from live runs, corrected after semantic
review on 2026-08-30. No production contract changed during the original run;
the two assembly scripts are session tooling, not product code. The
all-confirmed result below is retained as a reconciliation transition test and
must not be interpreted as independently validated semantic coverage.

---

## 1. What was run, end to end

For each use case the full chain was executed live:

1. **Phase 1 obligation planning** (`plan-obligations` seam, driven by a local
   `build_phase1_inputs.py`): risk cards from policy-mapper RAG + reviewed
   capability profile + qualification facts + committed catalog/mappings →
   published `taxonomy-obligation-plan-v1`. Zero model calls.
2. **Taxonomy generation** (`generate`, live, exhaustive): risk→pattern
   candidates → LLM semantic generation → admitted scenarios + quarantine.
3. **STPA** (`stpa-run`, live): SP1 control structure / loss analysis → ICA
   enumeration → SP3 scenarios.
4. **Phase 2** (`build_phase2.py map/propose/assess`): operator resource map →
   validated `system-resource-map-v1` → deterministic correspondence proposals →
   explicit adjudication → `hybrid-coverage-assessment-v1` via the
   `reconcile_taxonomy_and_stpa` facade. Zero model calls.

## 2. Headline results

| Stage | Klarna fs-isac v36 | OcciAI NHS |
|---|---|---|
| Reviewed risks | 49 | 112 |
| Phase 1 obligations | 92 (43 ready, 9 missing_evidence, 40 governance_only) | 152 (36 ready, 16 missing_evidence, 100 governance_only) |
| Candidate records | 501 projectable, 42 projection_infeasible, 0 budget-deferred | 232 projectable, 68 projection_infeasible, 0 budget-deferred |
| Taxonomy generate | 115 candidates → **94 admitted (82%)**, 21 quarantined, 0 failed | 44 candidates → **27 admitted (61%)**, 17 quarantined (39%), including 10 hard failures |
| Complete provider semantics | 96/115 candidates | all 27 admitted |
| STPA | 16 scenarios, **20/20 slots** (5 per UCA type), 0 validation/stage errors | 18 scenarios, **24/24 slots**, 0 errors, 0 warnings |
| Phase 2 map | 11 links (6 authoritative), validated first pass | 9 links (6 authoritative) after 2 validation iterations |
| Shared-resource proposal candidates | 389 across 4 CAs / 12 slots | 108 across 1 CA / 3 slots |
| Assessment, confirm-none | 0 accepted; 43 unresolved_ambiguous | 0 accepted; 36 unresolved_ambiguous |
| Assessment, synthetic all-confirmed | **389/389 mechanically accepted, 43 obligations `satisfied`, 389 realization rows** | **108/108 mechanically accepted, 36 `satisfied`, 108 realization rows** |
| Network/model calls in Phase 2 | 0 | 0 |

Both Phase 1 ledgers and both Phase 2 assessment chains published atomically
with digest verification. The final all-confirmed assessments are the primary
`hybrid-coverage-assessment.yaml` / `hybrid-coverage-report.md` in each
`*-phase2/` directory; the confirm-none baselines are preserved as
`*-unadjudicated.*`, with both adjudication sets (`adjudications.yaml`,
`adjudications-none.yaml`) kept so either variant re-runs in seconds.

### 2.1 Human calibration and corrected offline rerun (2026-08-31)

The synthetic all-confirmed result was superseded for semantic calibration by
twenty one-at-a-time reviews: ten Klarna and ten NHS proposals. The reviewer
confirmed seven proposals only as shared-resource associations, rejected
thirteen, and confirmed zero coverage-bearing equivalences. The exact reviewed
proposal IDs, source digests, evidence, and decisions are retained in
`tests/fixtures/klarna-phase12-reviewed-adjudications.yaml` and
`tests/fixtures/nhs-phase12-reviewed-adjudications.yaml`. These are development
regressions, not a requirement to repeat the same manual review on every
pipeline run.

That calibration exposed two concrete defects. Phase 1 allowed resources to
fill roles they could not perform, and Phase 2 joined an obligation's pooled
resources without retaining the exact candidate that supplied the link. The
corrected implementation now:

- records reviewed `retrieve_data`, `transmit_data`, and `execute_code`
  support on tools and integrations;
- distinguishes unknown operation support from explicit incompatibility;
- requires distinct retrieval and delivery resources for AP-T2-02;
- requires a real code-interpreter capability for AP-T2-06;
- models AP-T6-03 as indirect external-content ingestion from a readable
  source into the agent's own goal state;
- retains and verifies one exact selected candidate and its own resource link
  in every correspondence proposal; and
- derives shared-resource proposals only as `related_but_not_coverage`.

The original risk cards and STPA outputs were then reused in a fully offline
rerun with reviewed operation metadata. No model or network calls were made.

| Corrected offline stage | Klarna | NHS |
|---|---:|---:|
| Obligations retained | 92 | 152 |
| Ready obligations | 38 | 20 |
| Contradictory evidence | 9 | 24 |
| Structurally infeasible | 0 | 8 |
| Governance only | 40 | 100 |
| Projectable candidates | 332 | 72 |
| Projection-infeasible candidates | 37 | 24 |
| Exact candidate/link association observations | 1,660 | 216 |
| Distinct obligation/ICA/link claims | 387 | 60 |
| Coverage-bearing proposals or accepted relations | **0** | **0** |

The large association-observation count is trace detail, not a coverage count:
several concrete candidates may witness the same obligation/ICA/link claim.
The corrected artifacts live in `klarna-phase1-corrected/`,
`klarna-phase2-corrected/`, `nhs-phase1-corrected/`, and
`nhs-phase2-corrected/`. Their assessments leave every association unresolved
and grant zero taxonomy satisfaction until independent mechanism evidence and
an explicit adjudication exist.

### 2.2 Real-scenario lineage validation (2026-08-31)

The admitted taxonomy envelopes (94 Klarna, 27 NHS) and STPA envelopes (16
Klarna, 18 NHS) were loaded as typed records and passed through the exact
candidate/slot/ICA adapters. Every taxonomy envelope's `cand:v2` ID recomputes
from its own typed projection, and every admitted candidate is present in its
generation coverage plan. The corrected Phase 1 inventories intentionally
have different candidate identities because the reviewed operation metadata
changed the capability snapshot, so no ID remapping was applied: corrected-plan
joins are 0/94 and 0/27. As a control, the pre-correction plans join 77/94
Klarna (316 obligation observations across 31 obligations) and 13/27 NHS (104
observations across 24 obligations).

Against the corrected inventories, the non-joins classify deterministically as
follows: Klarna has 77 `inconsistent_planning_input` records (exactly present in
the pre-correction projectable inventory but absent after correction) and 17
`expected_extra_candidate` records (AP-T10-01 ×7, AP-T15-02 ×5, AP-T9-01 ×5,
absent from both Phase 1 pattern inventories); NHS has 13 and 14 respectively
(all 14 extras are AP-T10-01). Both runs have 0 `identity_lineage_bug` records.
The complete scenario and candidate ID lists, per-record adapter errors, and
evidence are in `klarna-phase2-corrected-lineage/lineage-audit.json` and
`nhs-phase2-corrected-lineage/lineage-audit.json`.

STPA exact joins succeeded for all 16 Klarna and 18 NHS envelopes (20/24
structural slots, respectively), resolving each to its exact slot, ICA, and
canonical `EXEC:*` identity. Regenerated corrected assessments fail closed on
the taxonomy non-joins, retain zero taxonomy scenario observations and zero
coverage credit, and record 0 model/network calls:

- `klarna-phase2-corrected-lineage/hybrid-coverage-assessment.yaml`
- `klarna-phase2-corrected-lineage/hybrid-coverage-report.md`
- `nhs-phase2-corrected-lineage/hybrid-coverage-assessment.yaml`
- `nhs-phase2-corrected-lineage/hybrid-coverage-report.md`

The only session tooling added is the ignored
`output/runs/20260829-phase12-live/validate_lineage.py`; no production adapter
change was indicated.

## 3. Findings

### 3.1 The cheap path is real: Phase 1/2 do not need `generate`

The user asked whether only the risk→attack-pattern mapping part of the
taxonomy pipeline was needed. Answer, confirmed empirically: the full
taxonomy `generate` run is **optional** for Phases 1/2. Phase 1's inputs
(risk-extraction, reviewed profile, qualification facts, committed catalog and
mappings) are all offline, and the planner projects candidates itself; there
is no partial stage of `generate` to invoke. The only live dependency of
Phase 2 is `stpa-run` (~85 calls for NHS vs ~183 for taxonomy generate — the
Stage-6 semantic writing dominates). A minimal future run is:

```
risk-extraction (offline) → reviewed profile + facts (offline)
  → plan-obligations (offline) → stpa-run (live)
  → map → propose → adjudicate → assess (offline)
```

The full `generate` run still earns its cost for a different reason: it is the
only source of evidence for *which obligations produced admitted scenarios*.
Neither of tonight's assessments consumed generated scenarios
(`taxonomy_scenarios` empty), which is why every satisfied row rests purely on
the accepted-relation path.

### 3.2 Structured-output admission is domain-sensitive

Same model, same sampling profile, same pipeline: Klarna's financial-service
candidates admitted at 82% (94/115) while NHS's clinical-workflow candidates
admitted at 61% (27/44), with 17 quarantined and 10 hard failures within that
non-admitted population. Klarna's candidates carry
concrete tool bindings (refund, payment scheduling, order lookup), which give
the structured-output schema concrete anchors; NHS's scenarios lean on
workflow abstractions that the schema validates less cleanly. All admitted
scenarios on both runs have `complete_provider_semantics: true` — no
presentation fallbacks were needed anywhere — so the funnel is rejecting on
validity, not repairing into compliance. The 39% NHS non-admission rate is
still a substantial quality lever, but the original headline inverted the
admitted and non-admitted percentages.

### 3.3 STPA output quality varied more than generation quality

NHS's control structure came out clean (0 warnings). Klarna's needed
auto-repair: a feedback channel referencing another responsibility's process
model part, a coordination link referencing a non-existent process model, and
after revision, 4 hazards (H-1..H-4) not traced from any responsibility and
both controlled processes unreferenced by feedback/control edges. The pipeline
surfaced all of this as typed `stage_warnings` / `post_revision_warnings`
rather than silently absorbing it — the honesty mechanism works — but the
underlying LLM output for financial control structures is less coherent than
the clinical one. Notably this did not block Phase 2: the repair artifacts are
what the map pins, and the ICA enumeration itself was complete and consistent
on both runs.

### 3.4 The resource-map validator catches real authoring errors

First NHS draft: 9 violations (relation kinds outside the closed
compatibility table, `represents` one-to-one cardinality conflicts between
authoritative links to the same controlled process). All caught
deterministically before anything downstream ran; fixed by mapping relations
to the closed table and demoting 3 secondary entry-point links to `advisory`
(which can never be authority-bearing). The Klarna map, authored with the
table in hand, validated first pass. The `represents`-is-one-to-one rule and
the closed relation vocabulary are doing real work.

The Klarna map's authoritative set is also a good demonstration of
*semantic* linkage: the four `acts_on` links connect each tool to exactly the
control action whose ICA text names it (refund API → CA-1-1 "fails to verify
… before invoking the 'refund processing API'"), and the customer-input trust
boundary `crosses` CA-1-1 because that ICA's hazardous context is prompt
injection arriving through customer input.

### 3.5 Proposal authority is fail-closed, and two authoring bugs surfaced it

The first all-confirmed attempt accepted nothing: all 497 proposals failed
validation with `source_pin_mismatch` and `taxonomy_candidate_ids_mismatch`
before adjudication was even consulted (they had also been mislabeled
"rejected" rather than "unresolved" in earlier summaries for the same
reason — the validation happens before the decision is consulted). Two bugs
in the session's propose script, not in the product pipeline:

1. hardcoded `taxonomy_version`/`stpa_version` where
   `CorrespondenceAuthority.from_artifacts` derives `plan.schema_version` and
   `"stpa-foundation-v1"`;
2. attaching only the matched candidate's ID where the authority record
   carries the obligation's **full** `candidate_records` ID list.

Both are exactly the class of drift the exact-pin design exists to catch: the
proposals' claimed authority fingerprint had to match the recomputed one
bit-for-bit. After fixing the script, all 497 proposals passed the implemented
identity and authority checks and, once confirmed, became accepted
coverage-bearing relations. That demonstrated the exact-pin machinery, but
subsequent semantic review found that the proposal authoring rule was too
broad: it labelled every shared authoritative resource match as
`same_mechanism`. A resource link is necessary identity evidence, not
sufficient mechanism evidence. Lesson: proposal authoring tooling must derive
every pin from the same typed constructors the authority uses, never from
literals, and must not promote a resource join into a coverage-bearing
relation without independent reviewed mechanism evidence.

### 3.6 `structural_inventory_status` and capability `inferred_partial` are different axes

An earlier conflation: running assessment with
`structural_inventory_status=partial` (mirroring the capability profile's
`inferred_partial` completeness) fail-closes **all** confirmation via
`incomplete_authority_inventory` — "incomplete inventories cannot establish
confirmed correspondence." Reading the code and the seam contract: the flag
attests to the **structural denominator** (is the ICA enumeration the
complete slot universe?), not to the capability profile's entry-point/tool
inventory completeness. Both live STPA runs enumerated every slot with zero
unresolved, so `complete` is the accurate structural status. The capability
profiles remain `inferred_partial` (LLM-inferred profiles are forced to that
value by design), which gates exactly one thing: `structurally_inapplicable`
closure demands explicit other authoritative evidence. Neither flag leaked
into the other's semantics once separated. Both fixture profiles in the repo
(Klarna, Airbnb, OcciAI) are also `inferred_partial`, so this is the normal
operating state, not an anomaly.

### 3.7 The confirm-none vs all-confirmed contrast demonstrates bookkeeping, not semantic validity

With zero configuration change other than the adjudication set:

- confirm-none: 0 accepted relations, 0 realization rows, every proposal
  traceable as rejected/unresolved with its validation codes; taxonomy
  obligations that had proposals sit at `unresolved_*`;
- synthetic all-confirmed: 389/108 accepted relations, all labelled
  coverage-bearing by the session helper, taxonomy
  `satisfied` exactly equals each use case's ready-obligation count (43/36),
  realization matrix populated with one row per accepted relation, every row
  carrying source pins back through map link → proposal → obligation →
  ICA slot.

This contrast proves deterministic state transitions and trace retention. It
does **not** prove that the 497 proposed obligation/ICA pairs express the same
or enabling mechanisms. The NHS count is exactly 36 ready obligations × 3
slots, exposing the shared-resource Cartesian expansion. The accepted
relations and `satisfied` dispositions from this synthetic variant must not be
used as coverage ground truth.

The 9 (Klarna) / 16 (NHS) `unresolved_missing_resource_map` rows are correct
in both worlds: those obligations' candidate resources never received an
authoritative link, so no proposal could exist for them. Nothing was blended
into a composite score at any point; the three matrices stayed independent.

One expectation to set: realization rows currently read
`hybrid_admission_status: not_assessed` / `hybrid_generation_status:
not_attempted`. In the synthetic variant the accepted relations prove only
that reconciliation accepted the supplied decisions; semantic correspondence
still requires independent review. No *hybrid* scenarios have been generated
against them yet.

### 3.8 Operational notes for future live runs

- **Background longevity:** the first Klarna `generate` died when its parent
  shell exited (~365 calls in); `asago-scenario-generator resume <run_dir>`
  (positional run dir) recovered cleanly from the planning checkpoint and
  completed the run with no duplicated or lost work. Long runs should always
  be launched detached.
- **Wrong-flag friction:** `stpa-run` takes `--profile` (not
  `--model-profile`); `resume` takes the run dir positionally. The
  `use-case` path is not recorded in the generate run manifest (only its
  hash), so keep the original `--use-case` path alongside the run.
- **Assessment CLI seam:** `build_phase2.py assess` hits a harmless
  post-publication `AttributeError` (`assessment.summary` does not exist on
  the model); artifacts are already written when it fires. Either drop the
  summary print or use an existing field.
- **Report size:** the Klarna generate `report.html` is 107 MB for 94
  scenarios; anything that embeds it (or archives run dirs) should plan for
  that.

## 4. Artifact map

```
output/runs/20260829-phase12-live/
  build_phase1_inputs.py              # offline Phase 1 assembly (session tooling)
  build_phase2.py                     # map/propose/assess driver (session tooling)
  klarna-obligation-snapshot.yaml     # pinned capability snapshot + facts (Klarna)
  klarna-phase1/taxonomy-obligation-plan.yaml
  klarna-non-stpa/<run>/              # live generate: 94 admitted, run-manifest, report.html
  klarna-stpa/                        # live STPA: 16 scenarios, ica-enumeration
  klarna-phase2/
    klarna-resource-links.yaml -> system-resource-map.yaml
    correspondence-proposals.yaml    # 389
    adjudications.yaml / adjudications-none.yaml
    hybrid-coverage-assessment.yaml (+ -unadjudicated.yaml)
    hybrid-coverage-report.md        (+ -unadjudicated.md)
  nhs-…                               # same shape for NHS
```

## 5. Suggested next steps

1. **Semantically calibrate correspondence before hybrid generation.** Treat
   shared-resource-only pairs as `related_but_not_coverage`; review a
   stratified subset independently and retain confirmed, rejected, unresolved,
   contradictory, and noncoverage decisions. Measure confirmed/(confirmed +
   rejected) precision over resolved coverage-bearing proposals and reviewer
   agreement where two reviewers are available.
2. **Feed exact generated scenarios into the assessment.** The product adapters
   fail closed on unknown identities. Against these artifacts, exact candidate
   joins cover 77/94 Klarna taxonomy scenarios (316 obligation observations,
   31 distinct obligations) and 13/27 NHS scenarios (104 observations, 24
   obligations); the remaining 17/14 generated candidates are outside the
   Phase 1 candidate inventory and require an explicit lineage decision rather
   than fuzzy matching. Exact STPA joins cover all 16 Klarna and all 18 NHS
   scenarios.
3. **Exercise a small hybrid-generation pilot only after calibration** against
   5–10 genuinely reviewed coverage-bearing relations so realization rows can
   move past `not_attempted` without importing new correspondence inference.
4. **Audit Klarna's untraced hazards** (H-1..H-4) before relying on its
   hazard tracing; consider a regeneration with the revised-control-structure
   feedback loop tightened.
5. **Investigate NHS admission failures** (10 failed within 17 quarantined) —
   the corrected 39% non-admission rate remains an important quality lever;
   quarantine bundles
   carry per-candidate reasons.
6. If `structurally_inapplicable` closures are ever wanted, upgrade the
   relevant profile inventories to `operator_confirmed_complete` with
   evidence (this changes the profile digest and re-pins the offline chain —
   cheap, but everything re-pins).
