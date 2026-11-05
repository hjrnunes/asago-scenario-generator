# asago-contracts-core

The contracts machinery the producer, the consumer and the orchestrator share:
scenario-handoff validation, the self-identifying contract envelope, semantic
version names, the schema-diff check, the support window, saved-artifact
upgrades, the artifact-design boundary walker, canonical JSON and framed digests
in both persisted encodings, and the conformance runner that checks a contract
kit's cases.

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

## Version names and semver

A version directory carries the version number in its name. The name is a prefix
and a semantic version, usually the contract name and `-v`: `<contract>-v<major>`,
`<contract>-v<major>.<minor>` or `<contract>-v<major>.<minor>.<patch>`. Some
installed kits keep a historical prefix (`artifact-runtime-contract-v2` belongs
to `runtime-contract`) or use the bare `<prefix>-<major>.<minor>.<patch>` form
(`attack-flow-2.0.0`). A missing minor or patch reads as 0, so
`scenario-handoff-v5` is 5.0.0 and `example-v1.1.0` is 1.1.0. `v1`, `1.`,
`1.2.3.4` and prereleases do not parse. The loader, the support window and the
upgrade hook accept any prefix; `parse_version_name(name, contract=...)` is
available when a caller wants to require the contract's own prefix.

`ContractSpec.semver` returns the version numbers of an installed spec, and
`SemVer` orders versions and renders them as `major.minor.patch`.

The directory name is the only place the number lives. Do not add a semver field
to `spec.json`: `spec_digest` covers the spec's bytes, and saved artifacts pin
that digest, so a new key would retire every artifact that names the spec. Add a
version by adding its directory and spec, and let the code derive the number.

## Schema changes

`diff_schemas(old, new)` compares two JSON Schemas and returns a `SchemaChange`
for each structural difference, with the `location` as a JSON Pointer, a `kind`
and a `breaking` flag. A change breaks an old reader when it can reject a
document the old schema accepted or read it differently: a removed property under
a closed object, a new required property, a narrowed type or bound, a removed
enum value, a changed constant, a removed alternative, and closing
`additionalProperties` on an object that accepted unknown properties. A change is
compatible when it adds an optional property, widens a type or bound, adds an
enum value or opens a closed object. An unknown keyword outside the `x-`
extensions counts as breaking, so a keyword the classifier does not know never
passes silently.

`check_roots(roots)` checks the installed kits under one or more contract roots.
It walks `<root>/<contract>/<version>/schema.json`, skips a directory whose name
does not parse as a version, groups the remaining versions by the name's prefix,
orders them by `SemVer` and compares each consecutive pair. A breaking change
without a new major version is a problem; compatible changes may share a major
version.

Run the check directly:

```bash
uv run python -m asago_contracts_core.schema_diff_cli data/contracts
```

The command exits 0 when no version changes its schema incompatibly without a
major bump, 1 when a problem exists, and 2 when a root or a schema cannot be
read. `tests/data/schema-diff/` holds a clean fixture and a breaking fixture the
tests use. The producer and consumer CI workflows run the same command.

## The support window

`SUPPORT_POLICY` records the rule the code enforces: support follows actual
readers and saved artifacts, not a calendar. The dcpl.2 retirement is the
precedent. The owner retired `artifact-package-v4` reading and
`tool-call-condition-v1` because nothing that must still load used them, and
re-locked every copy.

`support_window(contract, versions, read_by=..., retired=...)` returns the
support status of each installed version, oldest first:

- A version that a newer installed version still reads is supported.
- The newest installed major and the major before it are supported.
- A version the change names in `retired` is retired, even inside the major
  window; a retired version may not also have a reader.
- Every other installed version is retired.

`read_by` maps an installed version to the newer version that still reads it; the
reader may not be older than the version it reads. `retired` names only installed
versions, and never the newest. `check_support_window` raises
`UnsupportedVersionError` when the window retires a version, so a change that
drops support says so and updates the saved artifacts first.

## Upgrading a saved artifact

`Upgrade(contract, from_version, to_version, step)` declares one hop between
installed versions, and `register_upgrade` validates and records it in the
process-wide registry. `upgrade(document, specs=None, steps=None)` reads the
document through the installed specs, walks every hop from its version to the
newest installed version, and returns the upgraded document with a fresh
envelope. Each step receives the document body and returns a mapping that sets
`specs.version_key` to the hop's target version; the envelope keeps the
`requires` the source document declared. The call refuses a document already at
the newest version, a missing hop (and names the next version), a step that
leaves the document on another version, and a requirement the target spec does
not support.

The contract's owner registers its hops. The handoff package does this on import:

```python
from asago_handoff import HANDOFF_UPGRADE, installed_specs, upgrade

current = upgrade(saved_v5_handoff, installed_specs())
```

`HANDOFF_UPGRADE` renames `attack_shape.indirect.party_relation.controller` to
`controlling_party`, advances `schema_version` to `scenario-handoff-v6` and
recomputes `content_digest` under the v6 domain, so every v5 conformance case
upgrades to its v6 case.

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
  an unrelated violation does not hide a broken case. A rule code that ends in
  `:` names a family and matches every violation code that starts with it; any
  other code matches exactly.
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
