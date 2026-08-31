# External QA: Phase 3 STPA challenge analysis

Run from the repository root:

```bash
uv run python acceptance/qa/taxonomy_risk/stpa_challenge_analysis.py
```

The driver imports no application package. It independently checks the
representative result, request, response, and challenge identities; explicit
one-attempt/no-retry controls; unchanged original STPA decision; typed
unresolved reason; exact `EXEC:*` identity; fake-adapter call evidence; zero
correspondence or coverage changes; and unchanged hybrid generation status.
