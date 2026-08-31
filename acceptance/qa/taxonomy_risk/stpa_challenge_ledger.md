# External QA: Phase 3 STPA challenge ledger

Run from the repository root:

```bash
uv run python acceptance/qa/taxonomy_risk/stpa_challenge_ledger.py
```

The driver imports no application package. It independently verifies the
representative ledger's version-framed semantic digest and challenge IDs,
exact Phase 2 assessment and upstream pins, explicit priority/budget ordering,
derived counts, unique obligation/STPA-slot targets, unchanged original STPA
decision fields and evidence, zero outcomes, zero correspondence/scenario
fields, and zero model/network calls.
