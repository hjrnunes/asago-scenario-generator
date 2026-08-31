# External QA: bounded Phase 3 composition

Run from the repository root:

```bash
uv run python acceptance/qa/taxonomy_risk/closed_loop_stpa.py
```

The driver itself imports no application package. It invokes the typed public
composition seam in a subprocess with deterministic fake adapters, then
independently verifies the aggregate digest, priority order, explicit budget,
all three completed outcome types, exact idempotent resume, unchanged Phase 2
bytes, zero correspondence and coverage changes, and unchanged hybrid status.
It also verifies the exact Klarna/NHS lineage classifications and STPA joins
without turning the audit evidence into eligibility.
