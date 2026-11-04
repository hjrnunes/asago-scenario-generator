# asago-handoff

The scenario-handoff-v5 rules that the producer, the consumer and the orchestrator share.

`asago_handoff` holds the shared rules:

- `validate_handoff(doc)` returns a `Violation` for each rule a handoff breaks: the
  ownership walker's codes first, then the schema's and the rules the schema cannot
  state.
- `ownership_violations(doc)` runs the artifact-design walker alone.
- `run_conformance(contract_dir)` runs a handoff kit's `conformance-cases.json`.
- `evaluate_condition_v2(condition, calls, complete)` evaluates a
  `tool-call-condition-v2` condition, and `validate_condition(condition)` reports a
  structural problem first. `evaluate_condition` is the same function under the
  consumer's name, and `DETECTED`, `NOT_DETECTED` and `INCONCLUSIVE` name its
  outcomes. Each way the producer's and the consumer's former evaluators differed
  is a named case in `tests/test_condition_eval.py`; the producer's behaviour wins.

The package needs the standard library and `jsonschema` only. It carries the
`handoff-v5` schema and the ownership rules as package data; the producer's
`scripts/sync_handoff_package_data.py` copies them from
`data/contracts/scenario-handoff/`, and a producer test fails when the copies
differ.
