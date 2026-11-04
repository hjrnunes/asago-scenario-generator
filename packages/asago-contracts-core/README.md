# asago-contracts-core

The contracts machinery the producer, the consumer and the orchestrator share:
scenario-handoff validation, the artifact-design boundary walker, canonical
JSON and framed digests in both persisted encodings, and the conformance
runner that checks a contract kit's cases.

The package needs the standard library and `jsonschema` only. It imports
nothing from producer, consumer or orchestrator code, and every schema or data
file it reads lives inside the package directory. It is a workspace member of
`asago-scenario-generator` and is built to move to its own package and
repository without a code change.

## Rules

- `validate_handoff(doc)` returns a `Violation` for each rule a handoff breaks:
  the ownership walker's codes first, then the schema's and the rules the
  schema cannot state.
- `ownership_violations(doc)` and `iter_boundary_strings(doc)` run the
  artifact-design walker alone.
- `run_conformance(contract_dir)` runs a kit's `conformance-cases.json`. An
  invalid case passes only when a violation carries a code the rule names, so
  an unrelated violation does not hide a broken case.
- `evaluate_condition_v2(condition, calls, complete)` evaluates a
  `tool-call-condition-v2` condition, and `validate_condition(condition)`
  reports a structural problem first. `evaluate_condition` is the same
  function under the consumer's name, and `DETECTED`, `NOT_DETECTED` and
  `INCONCLUSIVE` name its outcomes.

## Canonical JSON and digests

`canonical_json`, `canonical_json_bytes` and `framed_digest` take a named
`Encoding`. Two policies are pinned by tests because they are persisted:

- `PRODUCER_ENCODING` (`canonical-json-nfc-v1`): NFC-normalize strings and
  mapping keys, refuse a key that collides after normalization, reject
  non-finite numbers.
- `CONSUMER_ENCODING` (`canonical-json-v1`): leave strings as written, accept
  non-finite numbers.

Both sort mapping keys, use `(",", ":")` separators and keep non-ASCII text as
UTF-8. `digest_record` returns a framed digest beside the encoding name that
produced it. `encoding_for(nfc=..., allow_nan=...)` names the two further
policy combinations the consumer uses for input digests.

## Data

`src/asago_contracts_core/data/` carries `handoff-v5/schema.json` and
`ownership-rules.json` for the code to read. `tests/data/` carries the handoff
kit and the tool-call-condition vectors the tests run against, so the package
tests pass after extraction. The producer's
`scripts/sync_handoff_package_data.py` copies both sets from `data/contracts/`,
and the producer's `tests/test_contracts_core_data.py` fails when the copies
differ.

## Test and build alone

```bash
cd packages/asago-contracts-core
uv run pytest -q
uv build
```
