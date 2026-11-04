# asago-contracts-core

The contracts machinery the producer, the consumer and the orchestrator share:
scenario-handoff validation, the self-identifying contract envelope, the
artifact-design boundary walker, canonical JSON and framed digests in both
persisted encodings, and the conformance runner that checks a contract kit's
cases.

The package needs the standard library and `jsonschema` only. It imports
nothing from producer, consumer or orchestrator code, and every schema or data
file it reads lives inside the package directory. It is a workspace member of
`asago-scenario-generator` and is built to move to its own package and
repository without a code change.

## The self-identifying envelope

A contract kit splits into its runtime spec, its cases and its docs:

```
contracts/<contract>/<version>/
  spec.json      the identity: contract, version, status, supports, extensions,
                 the schema's file name, its cases and docs, and spec_digest
  schema.json    the runtime schema
  cases/         the conformance cases (never part of the identity)
  README.md      the contract's docs
```

`spec_digest` covers `spec.json` without its `spec_digest` field and the bytes of
`schema.json`, under the producer encoding. Editing a case or a doc leaves it
alone, so a case can change without changing the contract's identity.

A new-version document carries the envelope:

```json
{
  "contract": {
    "id": "midojo-delivery",
    "version": "midojo-delivery-v1",
    "spec_digest": "sha256:...",
    "requires": ["feature-a"],
    "provenance": {
      "writer": "asago-orch.qualification.midojo_episode_runner",
      "writer_version": "0.1.0",
      "validator_version": "asago-contracts-core 0.1.0"
    }
  }
}
```

`envelope_schema()` is the JSON Schema of that block. `load_specs(contracts_dir)`
loads every installed spec under a contract root, and `SpecSet.read(document)`
selects the spec the document names and enforces four rules:

- an unsupported version fails, and the error lists the supported versions;
- a `requires` entry the spec does not support fails, so an old reader cannot
  silently ignore a new constraint;
- a top-level field outside the schema and the spec's `extensions` fails;
- a `spec_digest` that is not exactly the installed spec's fails, for a draft as
  for a published version.

A document without an envelope is a legacy document of the version its
`schema_version` names; a spec with `"envelope": "required"` refuses one.
`write_envelope(document, spec, writer=..., writer_version=..., requires=...)`
gives a document the envelope its spec's reader accepts.

## Rules

- `read_handoff(doc)` reads one handoff through the installed
  `scenario-handoff-v5` spec: an enveloped document is selected by its contract
  id and version, a legacy one by its `schema_version`. `installed_specs()`
  returns the spec set the package carries, and `load_contract(contract_dir)`
  pairs a selected spec's schema with the ownership rules.
- `validate_handoff(doc)` reads the document through the installed spec first
  and then returns a `Violation` for each rule a handoff breaks: the ownership
  walker's codes first, then the schema's and the rules the schema cannot state.
  A legacy document keeps the code the kit records for its break; an enveloped
  document gets the reader's own refusal, since that states a newer contract.
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

`src/asago_contracts_core/data/` is the spec root: it carries the producer's
whole `scenario-handoff/` contract directory (the `scenario-handoff-v5/` version
directory with `spec.json`, `schema.json`, `cases/` and `README.md`, plus
`ownership-rules.json` and `CONTRACT.lock`) and `envelope-v1.schema.json`, for
the code to read. `installed_specs()` loads the specs from that root.
`tests/data/` carries the same contract tree and the tool-call-condition
vectors the tests run against, so the package tests pass after extraction. The
producer's `scripts/sync_handoff_package_data.py` copies both trees from
`data/contracts/`, removes the files the authority no longer holds, and the
producer's `tests/test_contracts_core_data.py` fails when the copies differ.

## Test and build alone

```bash
cd packages/asago-contracts-core
uv run pytest -q
uv build
```
