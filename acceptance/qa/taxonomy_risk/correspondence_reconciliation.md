# End-to-end QA: correspondence reconciliation

Drive a deterministic file-to-file correspondence reconciler: a valid
`SystemResourceMap` and a `ProposalSet` in, a published
`ReconciliationResult` YAML or JSON artifact out. That invocation is a
user-interface affordance; it is not `generate` or `stpa-run`, and it is
not required as a new public CLI subcommand. Inspect artifacts with
standard JSON/YAML readers, the console, and the filesystem. Do not
import project modules, call `reconcile_correspondence`, or contact an
LLM endpoint. Never set `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case. Reconciliation depends on
the `SystemResourceMap` domain contract, not a storage representation.
Adjudication input is explicit; do not infer confirmation from proposal
strength.

## QA-CR-01: confirmed, rejected, and unresolved outcomes are retained

1. Author proposal `P-1` with relation type `supports` and assign
   adjudication `confirmed`.
2. Author proposal `P-2` with relation type `addresses` and assign
   adjudication `rejected`.
3. Author proposal `P-3` with relation type `overlaps` and assign
   adjudication `unresolved`.
4. Reconcile and inspect the result.

**Expected:** The result retains `P-1`, `P-2`, and `P-3`. `P-1` is
`confirmed` with type `supports`. `P-2` is `rejected` with type
`addresses`. `P-3` is `unresolved` with type `overlaps`. Rejected and
unresolved proposals remain in the artifact.

## QA-CR-02: relation type stays separate from strength and adjudication

1. Reconcile `P-1` as type `supports`, strength `high`, adjudication
   `confirmed`.
2. Reconcile `P-4` as type `contradicts`, strength `high`, adjudication
   `rejected`.
3. Reconcile `P-3` as type `overlaps`, strength `weak`, adjudication
   `unresolved`.
4. Inspect each proposal.

**Expected:** Each proposal keeps its named type, strength, and
adjudication as separate fields. Relation type is not equal to
adjudication. Relation type is not equal to strength.

## QA-CR-03: conflicting proposals stay unresolved regardless of order

1. Author `P-1` proposing `supports` for `CA-1-1` and
   `ep:v1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa`.
2. Author `P-4` proposing `contradicts` for the same pair.
3. Present the pair as `P-1,P-4`, reconcile, and inspect.
4. Repeat with presentation order `P-4,P-1`.

**Expected:** Both proposals are retained. The pair has adjudication
`unresolved` and conflict reason `conflict`. Neither proposal is
confirmed by iteration order.

## QA-CR-04: dangling, stale, and evidence-free confirmation fail closed

1. Attempt to confirm proposal `P-9` with dangling left reference.
2. Attempt to confirm `P-9` with dangling right reference.
3. Attempt to confirm `P-9` with a stale source version.
4. Attempt to confirm `P-9` with no evidence or provenance.
5. Inspect each result.

**Expected:** Each attempt fails. Dangling-left and dangling-right
yield error code `dangling_reference` identifying `P-9`. Stale-version
yields `source_version_mismatch` identifying `P-9`. Evidence-free
yields `evidence_required` identifying `P-9`. No confirmed relation is
written for `P-9`.

## QA-CR-05: reconciliation is deterministic and idempotent

1. Reconcile proposals in order `P-1,P-2,P-3`.
2. Reconcile the same proposals in order `P-3,P-1,P-2`.
3. Reconcile the first result again.
4. Compare identities and adjudications.

**Expected:** Both results have identical proposal identities and
identical adjudications. Repeating reconciliation on the first result
does not change it.

## QA-CR-06: scenario wording infers no relation

1. Author scenario prose `the assistant supports prompt injection`.
2. Include no explicit proposal that cites that prose.
3. Reconcile and inspect the result.

**Expected:** The result contains 0 proposals. No relation is inferred
from scenario wording. No prose-only relation is stored.

## QA-CR-07: source STPA and taxonomy artifacts are unchanged

1. Capture bytes of source artifacts `control-structure.yaml` and
   `attack-patterns.sssom.tsv`.
2. Produce proposals and reconcile them.
3. Recapture those source artifact bytes.

**Expected:** `control-structure.yaml` is unchanged.
`attack-patterns.sssom.tsv` is unchanged.

## QA-CR-08: reconciliation records zero network and model calls

1. Use any valid resource map and proposal set covering confirmed,
   rejected, and unresolved outcomes.
2. Reconcile while capturing call logs, endpoint logs, and environment.
3. Confirm `ASAGO_SCENARIO_GENERATOR_QA_PIPELINE` is unset.

**Expected:** Reconciliation recorded 0 network calls and 0 model
calls. No LLM endpoint is contacted.
