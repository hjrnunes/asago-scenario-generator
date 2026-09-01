# Phase 4 live semantic pilot record and retired runbook

**Status: historical target-scoped qualification attempt completed; the
combined-projection generation direction is retired.**

This document describes the controlled work needed before a live semantic
pilot can be started. Phase 4's readiness gate is offline and deterministic;
it does not create a provider, call a model, contact a network, regenerate
taxonomy scenarios, or write a run artifact. Completing this checklist is a
future qualification activity, not a prerequisite for ordinary `generate` or
`stpa-run` development. Following the 2026-09-01 product correction, this
runbook is retained as evidence of the rejected prescriptive approach. The
current implementation direction is
[obligation-aware STPA](stpa-taxonomy-obligation-aware-stpa-spec.md).

## Qualification attempt: Klarna

The first target-scoped attempt ran on 2026-08-31 UTC against the two
operator-confirmed Klarna relations in projection set
`7f32dac755fad94620f1fe6436cdafc1a9f9d307885522c47511b7a003a84793`.
It did not run the complete taxonomy corpus and did not change ordinary
`generate` or `stpa-run` behavior. Its evidence is retained under
`output/runs/20260831-phase4-klarna-pilot/klarna-targeted-hybrid-generation/`.

The outcome was **0 generated, 0 admitted, and 2 quarantined**:

- the AP-T3-02 privilege-escalation target failed the existing taxonomy
  attack-tree consistency checks after their bounded retries; and
- the AP-T2-01 parameter-pollution target failed the existing attack-tree
  schema because the generated root label exceeded its 120-character limit.

No scenario artifact was published for either target. The first adapter
revision also failed to count retry calls independently from final stage call
records, so that target's exact provider-call count is not qualified evidence.
This alone prevents a ready result even if its generated content had passed.

The attempt tested the wrong product interpretation. It treated each combined
projection as a scenario recipe and required one generated artifact to realize
both the exact taxonomy chain and the STPA outcome. The two reviewed combined
projections remain valid evidence, but they should not be sent to generation as
mandatory templates.

There is therefore no planned retry of this target-scoped combined-generation
path. The next live qualification should exercise `synthesis-run`: every
applicable taxonomy obligation is presented to STPA as a question, STPA derives
its own ICA and causal scenario, and a separate accounting artifact records
what happened. Phase 2 may later verify the claimed correspondence. Phase 4
projections may be used to explain selected accepted relations, but they do not
control scenario production.

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

The historical combined-projection pilot remains not ready. Preserve these
blockers as evidence about that approach rather than as prerequisites for
obligation-aware synthesis:

- `old Klarna taxonomy envelopes: 0/94 corrected-plan joins`
- `old NHS taxonomy envelopes: 0/27 corrected-plan joins`
- `reviewed Klarna targets: 2 accepted relations, 0/2 generated and admitted`

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
