# STPA Execution Bundle Producer Specification

Status: proposed implementation specification  
Date: 2026-09-02  
Repository: `asago-scenario-generator`  
Companion specification: `asago-artifact-generator/docs/specs/stpa-execution-bundle-consumer-spec.md`

## 1. Decision

The scenario generator shall publish a versioned, independently verifiable
execution bundle for every successfully generated STPA scenario.

The scenario generator owns the scenario's semantic and structural execution
intent. It does not own a target platform's prompt roles, tool schemas,
endpoints, clocks, state observers, detector implementation, or runtime
observations.

The cross-repository seam consists of two wire contracts:

1. `stpa-execution-projection-v2`, one closed execution-intent document per
   scenario; and
2. `stpa-execution-bundle-v1`, one run-level index that pairs each projection
   with its canonical scenario envelope through exact byte digests.

Canonical JSON is the machine interchange. YAML may be emitted as a
human-readable mirror but is not authoritative and is not hashed as the
semantic contract.

## 2. Context and motivation

The current `stpa-execution-projection-v1` is a useful internal projection but
is not a safe consumer contract:

- it accepts forged or malformed temporal payloads that retain valid
  traceability identifiers;
- it does not reject all unknown fields or runtime-observation contamination;
- its final UCA outcome records only the UCA label, not the condition that
  makes the action unsafe;
- Stage 6 renders the projection before invoking complete standalone
  validation;
- persistence accepts an arbitrary projection dictionary; and
- scenario and projection files are paired only through filename convention.

The current artifact generator consumes a retired taxonomy-era scenario shape
and cannot load current STPA envelopes. This specification does not add
artifact-platform logic to the scenario generator. It creates the narrow,
deep producer interface that a strict consumer can trust.

## 3. Domain language

The following terms are normative.

### 3.1 Semantic intent

What the scenario means independently of a platform: causal factors, their
order, the unsafe control action, the unsafe outcome, declared temporal
conditions, and unresolved semantic parameters.

### 3.2 Semantic binding

An explicit, human-reviewed value needed to complete semantic intent when
Stage 5 can declare the condition's type, subject and operator but source
evidence does not contain its concrete value. Examples include an
organization-specific forbidden amount or a timing threshold not present in
the use-case evidence.

The producer preserves the condition shape and inserts a typed binding
placeholder for the missing value. It never invents the value. A downstream
tool may fill that exact placeholder but must record the value as an
operator-supplied semantic binding, not as model inference or platform
configuration. A downstream tool may not replace the condition type, subject
or operator.

### 3.3 Runtime binding

A deployment-specific mapping from semantic intent to a concrete surface,
tool, schema, event, clock, state observer, or detector. Runtime bindings are
owned by the artifact generator.

### 3.4 Execution requirement

A platform-neutral capability needed to realize or observe a projection, such
as tool execution, multiple turns, persistent state, multiple agents, a real
clock, or state observation.

### 3.5 Validated projection

An immutable projection value that has passed complete model and cross-field
validation and carries its canonical bytes and digest. Stage 6 and persistence
may consume this value; they may not consume an arbitrary projection mapping.

### 3.6 Execution bundle

A run-level, content-addressed index written after all referenced canonical
files. Presence of a valid bundle index is the publication-completion marker.

## 4. Ownership

### 4.1 The scenario generator owns

- causal-factor selection, evidence and declared order;
- structural PM/FB/CA/CM/CL identities;
- controller, control action, ICA slot, ICA and candidate identities;
- UCA type and the semantic condition that makes the outcome unsafe;
- semantic temporal values supported by source evidence;
- explicit indication of missing semantic values;
- neutral execution requirements;
- complete projection validation;
- canonical serialization, content digests and atomic publication;
- contract schemas, conformance fixtures and violation semantics; and
- taxonomy obligations and technique mappings as traceable provenance only.

### 4.2 The scenario generator does not own

- Garak, PyRIT, AgentDojo or other platform payloads;
- concrete chat roles or injection locations;
- target tool names, APIs, arguments or credentials;
- deployment-specific threshold selection;
- clocks, event collectors, state observers or detector implementations;
- whether a platform supports a requirement;
- generated attack-message wording for a particular harness; or
- runtime observations and evaluation results.

## 5. Public producer interface

The implementation shall concentrate projection construction, validation and
canonicalization behind one deep module.

```python
def prepare_execution_projection(
    spec: ScenarioSpec,
    control_structure: ControlStructure,
    run_identity: ExecutionRunIdentity,
) -> ValidatedExecutionProjection:
    ...

def publish_execution_bundle(
    destination: Path,
    run_identity: ExecutionRunIdentity,
    entries: Sequence[ExecutionBundlePublication],
) -> ExecutionBundleIndex:
    ...
```

`ValidatedExecutionProjection` shall expose:

- the immutable typed `ExecutionProjectionV2` document;
- exact canonical JSON bytes;
- the framed semantic digest;
- the validator-derived Stage 6 alignment view;
- source and structural identities; and
- neutral execution requirements.

`ExecutionBundlePublication` shall contain only:

- a validated scenario envelope;
- a `ValidatedExecutionProjection`; and
- the final run-relative output names.

No public persistence function may accept `dict[str, Any]` as a projection.

## 6. `stpa-execution-projection-v2`

### 6.1 Top-level shape

The JSON document shall be closed: unknown fields are errors.

```yaml
schema_version: stpa-execution-projection-v2
run_id: synthesis-20260902T124500Z
scenario_id: SCN-001
candidate_id: EXEC:CL-1:CM-1:INCORRECT
ica_slot_id: CL-1:CM-1:INCORRECT
ica_id: CL-1:CM-1:INCORRECT:1
controller_id: CL-1
control_action_id: CM-1
uca_type: INCORRECT
causal_factors: []
steps: []
unsafe_outcome: {}
execution_requirements: {}
trace_refs: {}
semantic_digest: <64 lowercase hexadecimal characters>
```

Required top-level fields are exactly:

- `schema_version`;
- `run_id`;
- `scenario_id`;
- `candidate_id`;
- `ica_slot_id`;
- `ica_id`;
- `controller_id`;
- `control_action_id`;
- `uca_type`;
- `causal_factors`;
- `steps`;
- `unsafe_outcome`;
- `execution_requirements`;
- `trace_refs`; and
- `semantic_digest`.

Optional top-level fields are prohibited. Optionality belongs inside the
closed nested records where its semantics are explicit.

### 6.2 Identity rules

- `scenario_id` must equal the paired scenario envelope's ID.
- `candidate_id` retains the structural form
  `EXEC:<controller_id>:<control_action_id>:<uca_type>`.
- `ica_slot_id` must identify the same controller/control action/UCA tuple.
- `ica_id` must be a concrete ICA belonging to `ica_slot_id`.
- `run_id` must equal the enclosing bundle's `run_id`.
- Changing run, scenario, candidate, slot or ICA identity changes the semantic
  digest.
- IDs are opaque to consumers except for equality. Consumers must not infer
  platform behavior from ID prefixes.

### 6.3 Causal factors

Each factor shall be a closed record:

```yaml
factor_id: CF-1
order: 1
kind: PROCESS_MODEL_FLAW
structural_source_id: PM-3-1
description: The intent state diverges from the authorized transaction.
evidence_status: structural_failure
capability_refs: []
access_refs: []
bounded_assumption: null
temporal_condition: null
```

Rules:

- `factor_id` is deterministic and positional: `CF-1`, `CF-2`, ... .
- `order` is contiguous and one-based.
- `kind` uses the existing closed causal-factor registry.
- `structural_source_id` resolves against the exact control structure using
  the namespace required by `kind`.
- evidence fields preserve Stage 5 authority and existing evidence-shape
  validation.
- `temporal_condition` is either a valid temporal condition or `null`;
- `null` means that no separate temporal constraint was supported by evidence,
  not that the factor's causal meaning is absent or delegated downstream;
- a temporal condition may contain a typed value placeholder when its family,
  subject and operator are known but its numeric value is not;
- a condition may not contain runtime tool names, prompt roles, endpoints,
  observer configuration or observations.

The normal contextual product path requires at least one evidence-backed
causal factor. An inability to support any factor rejects that scenario before
Stage 6. V1 readers may continue to recognize historical present-empty
vectors, but v2 product publication does not use an empty factor list as a
successful executable scenario.

### 6.4 Semantic condition union

`SemanticCondition` is a closed discriminated union. Its value fields may
contain literal scalar values or typed `SemanticBindingPlaceholder` values
where this specification explicitly permits them.

```yaml
binding_ref: SEM-1
value_type: integer
description: Maximum acceptable feedback delay for this deployment.
minimum: 0
maximum: null
```

Binding references are unique within a projection. A placeholder is part of
the producer-owned semantic condition; filling it cannot change the
condition's discriminator, subject, semantic property or operator. Initial
condition variants are:

#### `ordering`

```yaml
type: ordering
reference_step_id: S-2
relation: before
```

#### `delay`

```yaml
type: delay
reference_ref: FB-1-1
delay_ms: 500
```

#### `duration`

```yaml
type: duration
reference_ref: CA-1-1
duration_ms:
  binding_ref: SEM-1
  value_type: integer
  description: Maximum safe action duration in this deployment.
  minimum: 0
  maximum: null
```

#### `window`

```yaml
type: window
reference_ref: PM-1-1
window_from_ms: 100
window_to_ms: 500
```

#### `absence`

```yaml
type: absence
reference_ref: FB-1-1
until_step_id: S-2
```

#### `action_presence`

```yaml
type: action_presence
control_action_id: CA-1-1
expected: not_provided
```

#### `action_value`

```yaml
type: action_value
control_action_id: CA-1-1
property: authorized_destination
operator: not_equals
expected: authorized_account_id
```

#### `state_value`

```yaml
type: state_value
subject_ref: PM-1-1
property: authorization_valid
operator: equals
expected: false
```

Closed operators for `action_value` and `state_value` are initially:

- `equals`;
- `not_equals`;
- `contains`;
- `not_contains`;
- `greater_than`;
- `greater_than_or_equal`;
- `less_than`; and
- `less_than_or_equal`.

The contract does not admit regular-expression source code, executable code,
arbitrary detector prompts or a generic `custom` variant. A new semantic
family requires a new compatible contract version or an explicitly compatible
schema revision governed by the version policy in section 13.

All literal time quantities use integer milliseconds and must be non-negative.
Typed integer placeholders must require a non-negative value. Literal window
bounds must be ordered; placeholder bounds are revalidated after binding.
`S-*` references must resolve to exported steps; structural references must
resolve to the source control structure. Semantic `property` names describe
meaning, not concrete runtime field paths; mapping them to a tool argument or
event field is a consumer-owned runtime binding.

### 6.5 Steps

Each step shall be a closed record:

```yaml
step_id: S-1
order: 1
kind: CAUSAL_FACTOR
factor_id: CF-1
structural_source_id: PM-3-1
```

The final step shall be:

```yaml
step_id: S-2
order: 2
kind: UNSAFE_CONTROL_ACTION
factor_id: null
structural_source_id: CM-1
```

Rules:

- step IDs and order are contiguous and one-based;
- every causal factor has exactly one corresponding causal-factor step;
- causal-factor step order equals causal-factor order;
- each causal-factor step references its exact `factor_id` and structural
  source;
- the final and only final step is `UNSAFE_CONTROL_ACTION`;
- its structural source equals `control_action_id`; and
- no step contains platform placement, generated message text or runtime
  observation data.

### 6.6 Unsafe outcome

The unsafe outcome is independent from individual causal-factor timing:

```yaml
outcome_id: OUTCOME-1
control_action_id: CM-1
uca_type: INCORRECT
condition:
  type: action_value
  control_action_id: CM-1
  property: synchronized_intent
  operator: not_equals
  expected:
    binding_ref: SEM-1
    value_type: string
    description: The authorized transaction intent for the test environment.
semantic_binding_required: true
hazard_refs: [H-3]
constraint_refs: [SC-3]
```

Rules:

- `control_action_id` and `uca_type` equal the projection identity;
- `condition` is always a valid semantic condition compatible with the UCA
  type; it is never `null` in a published v2 projection;
- `semantic_binding_required` is `true` exactly when the condition contains at
  least one `SemanticBindingPlaceholder`;
- `NOT_PROVIDED` accepts an `action_presence` condition with
  `expected: not_provided`;
- `INCORRECT` accepts `action_value` or `state_value`;
- `WRONG_TIMING` accepts `ordering`, `delay`, `window` or `absence`;
- `WRONG_DURATION` accepts `duration`;
- values within the compatible condition may be typed placeholders when the
  semantic shape is known but source evidence does not supply the value;
- referenced hazards and constraints resolve against the exact loss analysis;
  and
- prose alone is not an executable condition.

### 6.7 Execution requirements

```yaml
requires_multi_turn: true
requires_tool_execution: true
requires_persistent_state: false
requires_multi_agent: false
requires_real_clock: false
requires_state_observation: true
required_surface_categories: [external_input, tool_result]
```

The record is closed. Surface categories are neutral capabilities, not
platform roles. Initial categories are:

- `external_input`;
- `system_instruction`;
- `tool_result`;
- `tool_definition`;
- `persistent_data`;
- `agent_message`; and
- `environment_event`.

Remove `garak_testability` and `midojo_testability` from the authoritative v2
contract. Existing envelope hints may remain deprecated presentation metadata
but cannot authorize execution or readiness.

### 6.8 Trace references

`trace_refs` preserves provenance without turning upstream methodology into
execution instructions:

```yaml
obligation_ids: [OBL-...]
risk_ids: [RISK-...]
attack_pattern_ids: [AP-T2]
technique_ids: [AML.T0051]
loss_ids: [L-3]
hazard_ids: [H-3]
constraint_ids: [SC-3]
source_pins:
  control_structure: <digest>
  loss_analysis: <digest>
  ica_enumeration: <digest>
  scenario_context: <digest>
```

Taxonomy obligation, pattern and technique IDs are provenance only. A
consumer must not translate them into platform operations or use them to
override the projected sequence or outcome.

### 6.9 Digest

`semantic_digest` is computed with the repository's framed digest function:

- frame: `stpa-execution-projection-v2`;
- payload: the complete canonical JSON object excluding `semantic_digest`;
- JSON keys sorted lexicographically;
- UTF-8 encoding;
- no insignificant whitespace;
- no NaN or infinity;
- arrays retain semantic order; and
- lowercase hexadecimal SHA-256 output.

Parsing must recompute and compare the digest. Re-serializing YAML must not
change the semantic digest.

## 7. `stpa-execution-bundle-v1`

### 7.1 Layout

The recommended run layout is:

```text
<run>/
  execution-bundle.json
  execution-bundle.yaml
  scenarios/
    SCN-001.scenario.json
    SCN-001.yaml
    SCN-001.feature
    canonical/
      SCN-001.projection.json
      SCN-001.projection.yaml
```

The canonical scenario JSON and canonical projection JSON are the files
referenced by the bundle. YAML and Gherkin are human-facing companions.

### 7.2 Index shape

```yaml
schema_version: stpa-execution-bundle-v1
run_id: synthesis-20260902T124500Z
producer:
  name: asago-scenario-generator
  version: <package or commit version>
entries:
- scenario_id: SCN-001
  candidate_id: EXEC:CL-1:CM-1:INCORRECT
  ica_slot_id: CL-1:CM-1:INCORRECT
  ica_id: CL-1:CM-1:INCORRECT:1
  scenario:
    path: scenarios/SCN-001.scenario.json
    content_sha256: <digest>
  projection:
    path: scenarios/canonical/SCN-001.projection.json
    schema_version: stpa-execution-projection-v2
    content_sha256: <digest>
    semantic_digest: <digest>
  validation:
    status: valid
    validator_version: stpa-execution-projection-v2
bundle_digest: <digest>
```

### 7.3 Index rules

- The document and every nested record are closed.
- `entries` are sorted by `scenario_id`, then candidate and ICA identity.
- Every identity tuple is unique.
- Paths are normalized POSIX paths relative to the index directory.
- Absolute paths, empty components and `..` traversal are rejected.
- Symlink resolution may not escape the bundle directory.
- `content_sha256` hashes the exact persisted canonical JSON bytes.
- Projection semantic digest equals the digest inside the projection.
- Scenario and projection identity tuples must match their index entry.
- Every projection must have `validation.status: valid`.
- Rejected or unresolved scenarios are reported in run diagnostics but are not
  represented by fake or empty executable entries.
- `bundle_digest` uses frame `stpa-execution-bundle-v1` over the complete
  canonical index excluding `bundle_digest`.

### 7.4 Publication transaction

Publication order is normative:

1. Prepare and validate all `ValidatedExecutionProjection` values.
2. Serialize canonical scenario and projection JSON to temporary files in the
   destination filesystem.
3. Flush and atomically replace each final canonical file.
4. Write optional YAML and Gherkin companions.
5. Compute the final index from the exact persisted canonical bytes.
6. Write and atomically replace `execution-bundle.json` last.
7. Optionally write the YAML index mirror after JSON publication.

A missing index means the run is not a published execution bundle. An old
index must never reference newly replaced partial content. Resume must verify
every indexed byte digest before reusing an entry.

## 8. Complete standalone validation

Validation shall be model-first and cross-field complete. It must never rely
only on Pydantic construction of the original in-process objects.

The public standalone parser shall accept JSON-compatible data and return
either a valid immutable projection or typed violations. It shall not raise
incidental `AttributeError`, `KeyError` or `TypeError` for malformed input.

Validation covers:

- exact container types and required/unknown fields;
- schema version;
- all identity equalities and source-pin integrity;
- factor IDs, order, registry kinds, evidence shape and structural namespace;
- condition discriminator, exact fields, operators, values and references;
- condition/binding-state equivalence;
- factor-to-step one-to-one mapping and ordering;
- final UCA step and unsafe-outcome compatibility;
- hazard and constraint references;
- neutral requirement vocabulary;
- exclusion of runtime observations and platform fields;
- semantic digest; and
- bundle/index byte digests and pair identity.

Typed violation codes shall include at least:

- `schema_version_mismatch`;
- `required_field_missing`;
- `unexpected_field`;
- `container_type_mismatch`;
- `identity_mismatch`;
- `source_pin_mismatch`;
- `factor_reference_mismatch`;
- `factor_order_mismatch`;
- `condition_type_mismatch`;
- `condition_field_mismatch`;
- `condition_reference_mismatch`;
- `condition_value_invalid`;
- `semantic_binding_state_mismatch`;
- `step_mapping_mismatch`;
- `uca_condition_incompatible`;
- `runtime_observation_forbidden`;
- `semantic_digest_mismatch`;
- `bundle_path_invalid`;
- `content_digest_mismatch`; and
- `pair_identity_mismatch`.

Violations are deterministic and name the earliest affected JSON path.

## 9. Stage 5 and Stage 6 changes

### 9.1 Stage 5

- Replace free-form timing strings with the typed condition union at the
  provider response seam.
- Keep the provider-facing model closed and structured-output compatible.
- Require `causal_factors` in every successful response.
- Require each factor's explicit `temporal_condition` field, including `null`
  when no separate temporal constraint is supported.
- Require a non-null unsafe-outcome condition and a binding flag derived from
  the presence of typed value placeholders.
- State plainly in prompts that the model must not invent numeric values,
  tool names, platform surfaces or detector behavior.
- Use the existing bounded response retry for omitted/malformed fields.
- Reject the scenario after retry exhaustion.
- Keep exactly one explicit conversion seam if provider-local handles differ
  from structural IDs. Do not duplicate domain translation across orchestration.

### 9.2 Stage 6

- Call `prepare_execution_projection` before any Stage 6 model request.
- Reject invalid projections with typed diagnostics and make zero Stage 6
  calls for that scenario.
- Build every Stage 6 alignment prompt from the same validated projection
  value that will be persisted.
- Stage 6 narrative, attack-tree and Gherkin generation may clarify the
  projection but may not add, remove, reorder or reinterpret execution steps.
- Persist only the validated projection returned before Stage 6.
- Validate that generated presentation artifacts retain the source identities;
  they do not become projection authority.

## 10. Contract publication and conformance kit

The producer repository is the contract authority. Add a versioned tree such
as:

```text
data/contracts/stpa-execution/
  projection-v2/
    schema.json
    valid/
      fully-bound.json
      semantic-binding-required.json
      ordering.json
      delay.json
      duration.json
      window.json
      absence.json
    invalid/
      forged-reference.json
      negative-time.json
      reversed-window.json
      unknown-field.json
      binding-state-mismatch.json
      runtime-observation.json
    expected-violations.json
    canonical-digests.json
  bundle-v1/
    schema.json
    valid/minimal-run/
    invalid/hash-mismatch/
    invalid/pair-mismatch/
    expected-violations.json
  CONTRACT.lock
```

`CONTRACT.lock` records the schema and fixture digests. Fixtures are
deterministic and make no model calls. The consumer vendors the entire frozen
version and pins `CONTRACT.lock`; it does not import producer Python code or
read a sibling checkout during tests.

## 11. Suggested implementation modules

Names may vary, but responsibilities shall remain local:

- `stpa/models/execution_projection_v2.py`: closed inward models and digest
  integrity;
- `stpa/scenario_prod/execution_projection.py`: deep prepare/validate module;
- `stpa/scenario_prod/execution_bundle.py`: atomic publication and index
  verification;
- `stpa/scenario_prod/bdi_generation.py`: typed provider response and one
  conversion seam;
- `stpa/scenario_prod/run.py`: orchestration through the new interfaces only;
- `stpa/models/scenario_envelope.py`: neutral consumer requirements;
- `cli/stpa.py` or current command module: validation/reporting options; and
- `data/contracts/stpa-execution/`: schemas and fixtures.

Do not make inward models import CLI, provider clients, persistence modules or
artifact-generator concepts.

## 12. Acceptance specification

Feature scenarios shall prove:

1. A valid Stage 5 response produces one validated v2 projection before any
   Stage 6 call.
2. Omitted causal factors or unsafe outcome trigger bounded retry and then
   reject before Stage 6.
3. A contextual response with no evidence-backed factor is rejected, not
   published as an executable empty projection.
4. A supported typed condition round-trips without numeric or unit drift.
5. An unknown semantic value preserves its typed condition and produces a
   constrained binding placeholder with `semantic_binding_required: true`.
6. A condition containing only literal values produces
   `semantic_binding_required: false`.
7. Every condition family validates through standalone JSON parsing.
8. Negative quantities, reversed windows, unknown operators and cross-variant
   fields fail with typed violations.
9. A syntactically plausible but nonexistent PM/FB/CA/S reference fails.
10. Unknown fields and runtime observations fail.
11. The unsafe outcome is compatible with its UCA type.
12. Stage 6 prompts use the exact digest-bearing projection that is persisted.
13. Invalid projection preparation makes zero Stage 6 calls and writes no
    scenario/projection pair.
14. Successful publication writes matching canonical scenario and projection
    byte digests, then the index last.
15. Interrupted publication without an index is not a valid bundle.
16. Hash, path, schema or identity tampering makes bundle verification fail.
17. Reordered input collections produce byte-identical canonical output when
    their semantic order is unchanged.
18. Obligation and technique trace references survive but cannot change
    execution semantics.
19. Platform-specific hints do not authorize or alter the projection.
20. The committed conformance kit is consumable with standard JSON tooling and
    no project import.

Acceptance mutation testing belongs after the complete producer and consumer
path is operational. Initial implementation shall run Gherkin, focused tests,
DRY and CRAP gates without spending a long cycle hardening partially built
modules.

## 13. Versioning and compatibility

- V1 remains a historical read/validation format only.
- Normal product runs publish v2 after cutover.
- Do not silently add fields or widen unions in a way that changes canonical
  validation or digest semantics.
- Additive documentation clarifications do not change the contract version.
- A backward-compatible schema revision must retain old canonical bytes and
  meanings for all existing valid fixtures.
- Any incompatible field, identity, digest or semantic change creates a new
  projection or bundle version.
- Old bundle versions remain independently verifiable; they are never rewritten.
- The artifact generator explicitly declares supported versions. Unknown
  versions fail before model activity.

## 14. Implementation sequence

1. Add acceptance scenarios and deterministic conformance fixtures.
2. Add closed v2 models and complete standalone validation.
3. Replace Stage 5 timing strings and add the unsafe-outcome condition.
4. Implement `prepare_execution_projection` and route Stage 6 through it.
5. Add canonical scenario JSON and atomic bundle publication.
6. Publish schemas, fixtures and `CONTRACT.lock`.
7. Coordinate the first vendored contract update in the artifact generator.
8. Run a deterministic cross-repository fixture through consumer validation.
9. Update README, architecture documentation, context/domain documentation and
   CLI help.
10. After both sides work end to end, run focused mutation hardening.

## 15. Quality gates

Before producer completion:

- generated Gherkin acceptance passes;
- focused and full deterministic tests pass;
- DRY analysis finds no parallel projection validation or digest recipes;
- all changed functions have CRAP at or below the repository threshold;
- Ruff check and format pass;
- canonical fixture hashes are reproducible;
- deterministic tests make zero network/model calls;
- a normal live STPA synthesis run publishes a valid bundle; and
- the artifact generator consumes that bundle through its strict adapter.

## 16. Non-goals

- implementing a platform adapter in this repository;
- deciding that Garak or another harness supports a requirement;
- producing concrete tool schemas, attack prompts or detector rubrics;
- inventing missing semantic thresholds;
- writing runtime observations into scenarios or projections;
- making taxonomy obligations force scenario admission;
- converting historical taxonomy scenarios into STPA by relabeling fields; or
- preserving successful empty projections in the normal contextual product
  path.

## 17. Completion condition

The producer work is complete when every normal STPA product run either rejects
a scenario before Stage 6 with typed diagnostics or publishes an immutable,
fully validated v2 projection paired with its canonical scenario through a
valid hash-bearing bundle index, and when the artifact generator can verify the
published contract without importing scenario-generator implementation code.
