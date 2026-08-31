# End-to-end QA: taxonomy obligation planner

Drive the public `plan-obligations` file adapter with complete typed input.
The fixture contains full serialized `AttackPattern` and
`CapabilityFactSnapshot` records from the shared offline projection factory.
The planner derives candidate records from those authoritative records;
callers do not provide candidate expansions or candidate identities.

Inspect the published YAML with standard readers and the console/filesystem.
Do not call `generate` or `stpa-run`, import the planner directly, contact an
LLM endpoint, or set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`. Use a fresh output
directory for every case. The acceptance runtime separately checks persisted
plan tamper rejection through the closed model loader.

Bounded projection may emit `budget_deferred` only for candidate identities and
bindings actually derived and validated before the derivation-work limit.
Remaining overflow is reported as typed limitation evidence, not inferred
candidate rows. Projection and qualification evidence round-trips typed
condition and precondition evaluations. Absent or explicitly unknown required
qualification facts appear as `qualification_fact` readings with `result:
unknown` and the corresponding status. An explicitly contradictory required
fact remains `status: contradictory`, uses contradictory rationale, and
classifies the row as `contradictory_evidence`; contradictory takes precedence
over mixed absent/unknown readings, after capability exclusion.

## QA-TOP-01: shared authoritative pattern keeps risk-scoped obligations

1. Build typed input with reviewed risks `risk-a` and `risk-b`, both mapped to
   the full authoritative `AP-T1-01` record.
2. Publish the YAML plan.
3. Inspect rows, risk references, and obligation IDs.

Expected: two rows retain both risk identities and have distinct obligation
IDs. The same pattern does not collapse separate reviewed risks.

## QA-TOP-02: governance-only risk remains visible

1. Build typed input with only reviewed risk `risk-governance-only` and no
   pattern mapping.
2. Publish the YAML plan.

Expected: exactly one row remains, with the original `risk_ref`,
`governance_only` scope, `not_attempted` qualification and correspondence,
and no invented attack-pattern ID.

## QA-TOP-03: candidate rows come from authoritative projection

1. Build typed input with `risk-a`, the complete serialized `AP-T1-01`
   `AttackPattern`, the complete serialized capability snapshot, and the
   canonical catalog/mapping pins. The mapping-pin inventory contains the
   unchanged `sssom` taxonomy-context pin plus the
   `obligation_edges` pin at release `obligation-mapping-bundle-v1`, whose
   digest covers the supplied cross-taxonomy and SSSOM rows.
2. Publish the YAML plan.
3. Compare the candidate ID, canonical ingress, and every resource binding
   with the shared projection factory's derived candidate.

Expected: the row has exactly the closed v1 fields and one candidate record.
The candidate ID, ingress, and bindings match the authoritative projection;
no caller-supplied candidate data is accepted.

## QA-TOP-04: projection evidence is retained without leaking secrets

1. Add a deliberately recognizable secret as an additional typed, present
   string fact (with its canonical reference key) and recompute the
   domain-framed digest.
2. Publish the plan and inspect row evidence and raw YAML bytes.

Expected: authoritative projection evidence is retained, while the secret is
absent from persisted row evidence and the YAML artifact.

## QA-TOP-05: stale qualification digest fails closed

1. Replace the qualification facts `semantic_digest` with an all-zero digest.
2. Run the public adapter.

Expected: typed validation fails with a qualification/digest diagnostic and no
partial YAML plan is published. The digest is content integrity, not caller
identity.

## QA-TOP-06: unknown candidate input is rejected

1. Add the legacy `candidate_expansions` field to otherwise valid typed input.
2. Run the public adapter.

Expected: the closed typed contract rejects the unknown field before planning;
the diagnostic names `candidate_expansions`, and no partial plan is published.

## QA-TOP-07: every identity-bearing input changes the row identity

1. Produce a baseline plan.
2. Produce paired plans changing exactly one of risk identity, the complete
   authoritative pattern record, the complete capability snapshot, catalog
   pin release, or mapping pin release.
3. Compare obligation IDs and plan semantic digests.

Expected: each changed input produces a different obligation ID and semantic
digest. Pattern and capability variants remain full, self-consistent records;
an isolated pattern ID, pattern digest, or capability reference is not a
valid substitute.

## QA-TOP-08: public planning makes no external calls

1. Publish a valid typed plan with the environment's live-model opt-in
   removed.
2. Inspect the command summary and captured environment/request evidence.

Expected: the command reports `Network calls: 0` and `Model calls: 0`; no live
endpoint is contacted.

## QA-TOP-09: summary reconciles from emitted rows

1. Build input with two mapped risks and one reviewed risk with no mapping.
2. Publish the plan.
3. Recompute all summary counters from obligation rows and candidate records.

Expected: every summary value equals the recomputed value. The summary retains
only the closed v1 counters and does not add taxonomy-correspondence or
scenario-realization rates. All three reviewed risks remain represented.

## QA-TOP-10: invalid projection budget fails before publication

1. Set `projection_budget.max_candidates` to zero in otherwise valid typed
   input.
2. Run the public adapter.

Expected: validation fails before planning and no partial YAML artifact is
published.

## QA-TOP-11: normalized equivalent typed inputs are byte-equivalent

1. Build one typed input with a composed NFC risk identifier and one with the
   canonically equivalent decomposed spelling.
2. Plan both through the typed planner.
3. Compare canonical semantic bytes, semantic digests, obligation IDs, and
   derived candidate IDs.

Expected: both plans have byte-equivalent canonical content and retain the
same identities after input normalization.

## QA-TOP-12: ICA and scenario keyword prose is outside obligation planning

1. Place baseline ICA/scenario prose sidecars beside one typed input snapshot,
   without adding those fields to `TaxonomyObligationInputs`, and publish it.
2. Publish the same typed input with only those ambient sidecars changed.
3. Compare the canonical plan bytes, semantic digest, and obligation IDs.

Expected: changing either prose value has no effect on the obligation plan;
the planner receives only `TaxonomyObligationInputs`.

## QA-TOP-13: typed planning constructs no provider client and contacts no endpoint

1. Run the public adapter in a guarded child process where both project
   provider-client constructors and socket connection functions fail while
   recording any attempted activity.
2. Inspect the recorded construction and connection counts.

Expected: both counts are zero. The check is deterministic and does not
   require a reachable endpoint or live-model opt-in.

## QA-TOP-14: resource operation support distinguishes unknown from unsupported

1. Require `retrieve_data` on the canonical tool slot with operation support
   left unknown.
2. Publish the typed plan and inspect the row disposition and evidence.
3. Repeat with a reviewed tool that supports only `transmit_data`.

Expected: unknown operation support retains the obligation as
`missing_evidence` with `unknown_resource_operation` evidence and no candidate
record. A reviewed operation mismatch retains the obligation as
`structurally_infeasible` with `unsupported_resource_operation` evidence and a
typed projection-infeasible candidate record. This external check drives the
public file adapter for both cases; the committed acceptance scenario exercises
the same public typed planner seam.

## Completion evidence

The executable checks are in
`acceptance/qa/taxonomy_risk/obligation_planner.py`. A successful run prints
14 completed procedures and `Result: PASS`, and leaves only untracked
diagnostic evidence under `tmp/`.
