# Phase 4 Task 1 hybrid projection QA

This check verifies the small offline seam that turns already-attested
taxonomy and STPA material into exact projection units. It does not run
scenario generation, contact a provider, or publish a later-phase artifact.

Run it from the repository root:

```text
uv run python acceptance/qa/taxonomy_risk/phase4_task1_hybrid_projection.py
```

The runner starts a clean child process and checks:

1. The returned resolution digest matches an independent canonical JSON
   recomputation.
2. One accepted relation retains the exact relation, obligation, candidate,
   ICA, and `EXEC:*` identities.
3. The resolution includes the wrapper pins for capability facts,
   materializations, correspondence, STPA authority, and confirmed review.
4. A confirmed `related_but_not_coverage` relation remains one typed
   `relation_not_coverage` exclusion, not a projection unit.
5. A ProposalSet paired with a different reconciliation fails with the exact
   proposal-content diagnostic.
6. A copied and re-digested attestation is rejected because it did not come
   from the verified factory boundary.
7. Provider constructors and socket construction are guarded; the expected
   result is zero attempted calls.

The child process has the live-model opt-in removed from its environment.
Successful output ends with `QA suite: 8 passed, 0 failed`.
