# End-to-end QA: system resource map artifact

Drive a deterministic file-to-file resource-map validator: a snapshot
fixture and a `SystemResourceMap` file in, published YAML and JSON map
artifacts out. That invocation is a user-interface affordance; it is
not `generate` or `stpa-run`, and it is not required as a new public
CLI subcommand. Inspect artifacts with standard JSON/YAML readers and
byte comparison. Do not import project modules, call
`validate_resource_map`, or contact an LLM endpoint. Never set
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`.

Use a fresh output directory for every case.

## QA-SRMA-01: pinned snapshot versions are copied into the map

1. Author a snapshot that pins schema version `1`, STPA version
   `stpa-v1`, and taxonomy version `atlas-2026.05`.
2. Produce a valid resource map.
3. Inspect the published map with a standard reader.

**Expected:** The map records schema version `1`, STPA version
`stpa-v1`, and taxonomy version `atlas-2026.05`.

## QA-SRMA-02: identifiers and order ignore presentation order

1. Author two maps with the same entities in opposite order:
   `SR-1,RESP-1,CA-1-1` versus `CA-1-1,RESP-1,SR-1`.
2. Validate and serialize each map.
3. Compare identifiers, canonical entity order, and serialized
   artifacts.

**Expected:** Both maps have identical identifiers and identical
canonical entity order. The serialized artifacts are canonically
equivalent.

## QA-SRMA-03: YAML and JSON round-trip without semantic loss

1. Produce a valid representative map that includes identifiers,
   cross-references, provenance, and unknown versus absent statuses.
2. Serialize it as YAML, deserialize it with a standard YAML reader,
   and re-inspect those fields.
3. Repeat with JSON.

**Expected:** Identifiers, cross-references, provenance, and
unknown/absent statuses are preserved in both formats.

## QA-SRMA-04: identical inputs are byte-stable

1. Serialize the same valid map twice as YAML.
2. Serialize the same valid map twice as JSON.
3. Compare the raw artifact bytes.

**Expected:** The two YAML artifacts are byte-identical. The two JSON
artifacts are byte-identical.

## QA-SRMA-05: consumers read the domain contract without persistence details

1. Serialize a valid representative map as YAML and as JSON.
2. Consume each artifact through the published domain contract, not
   through a persistence adapter.
3. Read entity families `control-action` from YAML and
   `trust-boundary` from JSON.

**Expected:** The consumer can access those families. The consumer
path does not import persistence adapters.
