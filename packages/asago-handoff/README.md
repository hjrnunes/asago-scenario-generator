# asago-handoff

The scenario-handoff name that the producer, the consumer and the orchestrator
import. The rules moved to the shared
[`asago-contracts-core`](../asago-contracts-core/README.md) package, and this
package re-exports them, so `asago_handoff` keeps working without a second copy
of the code or the contract data.

- `validate_handoff(doc)` returns a `Violation` for each rule a handoff breaks.
- `ownership_violations(doc)` runs the artifact-design walker alone.
- `run_conformance(contract_dir)` runs a handoff kit's `conformance-cases.json`.
- `evaluate_condition(condition, calls, complete)` evaluates a
  `tool-call-condition-v1` condition.

The package needs the standard library, `jsonschema` and
`asago-contracts-core` only. The schema and ownership rules live in the core
package; the producer's `scripts/sync_handoff_package_data.py --check` copies
them from `data/contracts/scenario-handoff/` and fails when the copies differ.
