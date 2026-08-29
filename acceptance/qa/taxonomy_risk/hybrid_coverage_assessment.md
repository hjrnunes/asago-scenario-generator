# External QA: hybrid coverage assessment

Run from the repository root:

```bash
uv run python acceptance/qa/taxonomy_risk/hybrid_coverage_assessment.py
```

The driver uses a standard YAML reader and an independent implementation of
the NFC, canonical-JSON, version-framed digest contract. It does not import the
application package. It verifies the committed complete assessment fixture,
the UCA-slot, obligation, and accepted-relation denominators from source spec
§8.11, exact row/cell source traces, independent diagnostics reconciliation,
the exact capability-snapshot digest and explicit artifact pin, exact
risk/pattern/taxonomy-candidate identity, accepted proposal support,
coverage-bearing relation kinds, observational legacy scenario status, absence
of the retired task-shorthand matrices or a blended score, and zero
provider/network calls.

The contract-visible generated acceptance suite separately verifies the
false-absence rule at the live seam: a complete structural inventory cannot
justify structural inapplicability for a candidate whose relevant capability
inventory remains `inferred_partial` unless the reviewed decision supplies
explicit other authoritative evidence.
