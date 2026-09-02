# Phase 4 hybrid projection-set QA

This is an independent reader for the committed Phase 4 bookkeeping fixture.
It uses PyYAML and the standard library only; it does not import the
application package or call a provider, model, network, or scenario runner.

Run it from the repository root:

```text
uv run python acceptance/qa/taxonomy_risk/hybrid_scenario_projection.py
```

The suite checks the exact artifact filename and closed fields, independently
recomputes the version-framed set, projection, causal, mechanism, bridge,
review, evidence, exclusion, and diagnostic digests/IDs, and verifies canonical
ordering, the five-part identity, the fixed bridge endpoint, the causal DAG,
source-pin inheritance, and independent review/mechanism evidence. It also
ensures the fixture is labelled `normative_bookkeeping_fixture`, contains no
score/readiness/execution claim, and is not presented as semantic pilot truth.
The independent source checks also verify the complete closed exclusion
vocabulary, the valid process-model and feedback bridge examples, and the
distinct ICA/shared-EXEC acceptance case.

The fixture is intentionally deterministic bookkeeping evidence. Passing this
QA does not establish real taxonomy/STPA correspondence or authorize a live
pilot.

Successful output for the committed complete fixture ends with
`QA suite: 37 passed, 0 failed`.
