# Phase 4 live semantic pilot runbook

**Status: required future qualification deliverable — not run.**

This document describes the controlled work needed before a live semantic
pilot can be started. Phase 4's readiness gate is offline and deterministic;
it does not create a provider, call a model, contact a network, regenerate
taxonomy scenarios, or write a run artifact. Completing this checklist is a
future qualification activity, not a prerequisite for ordinary `generate` or
`stpa-run` development.

## 1. Prepare the corrected inputs

Use the corrected, reviewed inputs for one named use case and one immutable
run. Do not repair or rename old scenario IDs.

1. Extract the corrected nested capability profile from the reviewed source
   profile. Preserve the source artifact identity and record its canonical
   semantic digest as `corrected_nested_capability_profile_digest`.
2. Extract qualification facts from that same corrected profile and the
   approved capability/fact source. Build the typed qualification-facts
   snapshot, retain its content digest as `qualification_facts_digest`, and
   ensure the Phase 1 obligation plan uses the same digest.
3. Pin the use case, risk extraction, SSSOM release, cross-taxonomy mapping,
   threats, catalog, mappings, settings, and model profile. Record each
   digest in the corresponding `PilotProvenanceBundle` field; do not use a
   file timestamp or a YAML byte hash as a substitute.
4. Validate the Phase 1 obligation plan and candidate materialization set,
   the successful Phase 2 resource-map validation, correspondence
   reconciliation, coverage assessment, and the pinned STPA projection
   authority. Their capability, obligation-plan, resource-map, loss,
   control-structure, ICA, execution-projection, assessment, and
   reconciliation pins must agree.

## 2. Create the run manifest and target list

Create a fresh run manifest before any semantic calls. Give it one immutable
`run_id` and retain its exact `ArtifactPin` as
`generate_run_manifest_pin`. The run ID, manifest pin, settings digest, model
profile digest, and all scenario artifact pins must be recorded together in
one `PilotProvenanceBundle`.

Select an explicit target list of `(relation_id, selected_candidate_id)`
pairs. The list is target-scoped: it is not a claim that the complete risk
corpus or every obligation is ready. For each target, record whether it is
expected, generated, admitted, or quarantined. Record exact counts and the
exact-join count; never replace them with a percentage or an aggregate score.

Before live work, run `assess_hybrid_pilot_readiness` on the complete typed
authority graph. It must recompute each fresh taxonomy envelope's `cand:v2`
identity and match the corrected Phase 1 candidate, full projection, ingress,
and resource bindings. It must also find an accepted, coverage-bearing
relation with a matching taxonomy row, realization row, exact STPA
slot/ICA/`EXEC:*` identity, and independent confirmed mechanism evidence.

The current audit is not ready. Preserve these blockers verbatim until the
underlying evidence changes:

- `old Klarna taxonomy envelopes: 0/94 corrected-plan joins`
- `old NHS taxonomy envelopes: 0/27 corrected-plan joins`
- `corrected assessments: zero accepted coverage-bearing relations for both`

## 3. Record model-call evidence

For every semantic call, record typed `ModelCallEvidence` tied to the same
run. It must include:

- the adapter kind and exact model/provider call counts;
- the settings and model-profile digests;
- the semantic digest of every generated scenario artifact; and
- the evidence and semantic digests for the evidence record itself.

Do not put prompts, secrets, provider payloads, or prose in place of these
typed pins. The readiness gate itself must still report zero model, provider,
and network calls.

## 4. Admit or quarantine candidates

Load each fresh result as a typed `ScenarioEnvelope`. For every expected
target, perform the checks in this order:

1. parse and revalidate the typed envelope;
2. recompute its `cand:v2` ID from the attack pattern and canonical
   projection;
3. require the envelope ID to equal that recomputed ID;
4. resolve the complete projectable Phase 1 candidate and separate
   materialization;
5. compare projection, canonical ingress, and resource bindings exactly;
6. reject duplicate, old, superseded, extra, or unrequested identities; and
7. only after all checks pass, pass the exact envelopes to the taxonomy
   coverage adapter.

An identity mismatch, tampered authority, or substituted digest is fatal. A
genuine missing candidate, missing materialization, missing review, or absent
coverage relation is recorded as a typed blocker or quarantine reason. Do not
fuzzy-match, remap old IDs, infer a relation from shared-resource evidence,
or turn a `related_but_not_coverage` association into coverage.

## 5. Human review and adjudication

For each admitted target, present the exact relation, risk, attack pattern,
candidate, selected resources, STPA slot/ICA/`EXEC:*` path, assessment rows,
and provenance to a reviewer. The reviewer must explicitly confirm, reject,
or leave unresolved the proposed relation.

To confirm coverage, retain all of the following as typed evidence:

- reviewer identity and the review-artifact pin/digest;
- the accepted relation and its exact proposal/reconciliation pins;
- an independent mechanism-evidence pin and record identity; and
- evidence that is not merely the bridge or shared-resource association.

A confirmed review without independent mechanism evidence does not admit a
semantic scenario. Rejected, unresolved, contradictory, and unreviewed
decisions remain separate diagnostics with their original evidence and
digests.

## 6. Finalize the pilot record

After review, rerun the offline readiness gate against the unchanged source
authorities and the final exact target lists. Store:

- the complete `PilotProvenanceBundle` and its semantic digest;
- expected/generated/admitted/quarantined/exact-join counts;
- each typed review decision and independent evidence pin;
- every quarantine or fatal validation reason; and
- the final readiness result and semantic digest.

Do not claim a successful pilot if any target used an old envelope, fuzzy
identity repair, synthetic all-confirmed bookkeeping, unreviewed coverage,
or provider/network activity on the offline path. A not-ready result is the
correct outcome when the evidence is genuinely absent.

## 7. Stop conditions

Stop and preserve the evidence if only superseded envelopes are available,
there is no independently reviewed coverage-bearing relation, an identity
requires repair, the run would need a default provider/network path, or
ordinary `generate`/`stpa-run` behavior changes. Resolve the source evidence
and start a new pinned run; never weaken the gate to make the old run pass.
