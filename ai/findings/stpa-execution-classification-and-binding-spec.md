# STPA Execution Classification and Binding Specification

Status: approved implementation specification  
Date: 2026-09-03  
Repositories: `asago-scenario-generator`, `asago-artifact-generator`

## 1. Decision

The scenario generator shall decide what an admitted STPA scenario means as an
execution case. It shall fix the adversarial delivery path, selected causal
factor, logical resources, required operations, unsafe action and observable
unsafe outcome before publication.

The artifact generator shall bind that fixed meaning to one exact target or
simulation environment and compile it for a supported test platform. It shall
not choose a different delivery path, causal factor, resource role, operation
or oracle.

Classification is deterministic. A model may select from request-local,
explained execution-route choices during Stage 5, but it does not label its own
output concrete, parameterized, simulated or executable.

`concrete` versus `parameterized` and `target-backed` versus `simulated` are
independent dimensions. A simulation with a complete mock contract is
concrete. A direct prompt requiring no domain tool may be concrete and
target-agnostic.

The existing pre-alpha `stpa-execution-projection-v2`,
`stpa-execution-bundle-v1` and consumer contract kit shall be revised in place.
Both repositories change together and the consumer repins the producer
contract. There is no compatibility obligation to preserve the incomplete
pre-change v2 shape.

## 2. Domain language

### 2.1 Semantic execution contract

The scenario-owned description of how its causal path is exercised and how
the unsafe outcome can be observed, independent of endpoints, credentials,
runtime locators and platform syntax.

### 2.2 Resource requirement

One exact logical need in a semantic execution contract. It identifies the
purpose, resource kind, semantic role, operation, source structural reference
and matching constraints. It may name an exact target resource when that fact
is authoritative, or remain a late-bound role.

### 2.3 Execution target profile

A reviewed, content-addressed description of semantic resources and
interfaces available in one target or deliberately simulated environment. It
contains no credentials, secret values or live endpoint configuration.

### 2.4 Binding completeness

Whether every semantic resource requirement is resolved:

- `concrete`: every required semantic resource has one exact binding, or the
  scenario needs no target-dependent semantic resource;
- `parameterized`: the path, roles, operations and oracle are complete, but at
  least one resource must be selected later; or
- `analytical_only`: required execution meaning is absent, so no honest test
  can be compiled.

Use American spelling `parameterized` in wire values and code.

### 2.5 Environment basis

The evidence basis for execution:

- `target_agnostic`: the semantic test needs no domain-specific resource;
- `target_profile`: bindings come from a reviewed real-target profile;
- `simulation_profile`: bindings come from an explicitly selected simulation
  profile; or
- `none`: no executable environment basis is established.

### 2.6 Profile fit

The result of comparing a scenario's requirements with one selected profile:
`not_required`, `matched`, `needs_binding`, `ambiguous`, `unsupported` or
`invalid`.

### 2.7 Bound execution case

One immutable combination of one verified scenario projection, one selected
target or simulation profile, and one exact semantic resource mapping. It
precedes runtime readiness and platform compilation.

### 2.8 Platform artifact

One Garak, PyRIT or other harness rendering of one bound execution case. It is
not a scenario and may not alter scenario meaning.

## 3. Ownership

### 3.1 Scenario generator owns

- STPA identities, causal factors and order;
- adversarial delivery class and selected factor;
- whether the unsafe action is model output, a tool call, a state change, an
  agent message or another declared action kind;
- logical resource roles, required semantic operations and matching
  constraints;
- exact resource IDs when supported by an authoritative supplied profile;
- explicit selection of real-target, simulation or target-agnostic basis;
- semantic unsafe condition and observation requirement;
- deterministic classification and its diagnostics;
- source/profile pins and canonical publication.

It does not own runtime URLs, authentication, credentials, secret values,
deployment locators, platform detector implementations or execution results.

### 3.2 Artifact generator owns

- independent verification of the bundle and target profile;
- exact semantic role-to-resource resolution for parameterized scenarios;
- the immutable bound execution case and its digest;
- runtime surfaces, endpoints, schemas, safe fixture values, secret handles,
  clocks and observers;
- platform capability checks, readiness, compilation and traceability;
- explicit separate cases when a caller requests more than one target,
  environment or platform;
- observation receipts and post-execution claim evidence.

It does not own delivery selection, causal-factor selection, logical role or
operation invention, simulation fallback, semantic thresholds, unsafe outcome
or oracle meaning.

## 4. Independent classification dimensions

The wire contract shall carry the independent dimensions, not one overloaded
three-way enum.

| Binding completeness | Environment basis | Plain-language result |
|---|---|---|
| `concrete` | `target_agnostic` | Concrete model-only case |
| `concrete` | `target_profile` | Concrete target-specific case |
| `parameterized` | `none` or `target_profile` | Complete semantic case awaiting resource binding |
| `concrete` | `simulation_profile` | Concrete simulated case |
| `parameterized` | `simulation_profile` | Complete mock intent with incomplete mock binding |
| `analytical_only` | `none` | Finding that cannot honestly be compiled |

The producer also records a pre-runtime `claim_scope`:

- `model_behavior_only`;
- `target_specific_intent`;
- `agent_behavior_with_simulated_tools`; or
- `no_execution_claim`.

`target_integration_ready` is a consumer readiness result, not a producer
claim. `target_observation_recorded` requires a later execution receipt.

## 5. Stage 5 execution-route decision

Stage 5 shall return one typed route disposition with the BDI result. The
prompt presents only local handles and plain explanations. The response is a
closed union:

- `executable_route`, which contains the complete route below; or
- `analytical_only`, which contains one or more typed semantic-gap codes,
  evidence and a concise reason.

An invalid or missing response field remains a provider validation failure; it
is never silently converted into an analytical finding. For an executable
route the provider selects:

- one `delivery_class`: `direct_prompt`, `indirect_content` or
  `conversation_context`;
- exactly one selected causal-factor handle;
- one `action_kind`: `model_output`, `tool_call`, `state_change`,
  `agent_message` or `environment_action`;
- request-local resource-role handles required by that route;
- for an indirect carrier, whether the supplied evidence establishes direct
  or indirect attacker influence over that carrier; and
- a concise reason tying the route to the selected causal factor.

Deterministic assembly resolves the handles to fixed structural references and
resource-requirement templates. The provider never emits profile resource IDs,
schemas, locators, classification labels or claim levels.

Rules:

- `direct_prompt` binds the adversarial stimulus to a user-input semantic
  surface and needs no carrier resource;
- `conversation_context` requires multi-turn execution and binds the stimulus
  to prior conversation context;
- `indirect_content` requires one carrier resource role with attacker
  influence and an operation that brings content into model context;
- `tool_call` and other external action kinds require a target-action resource
  role tied to the exact control action;
- every `tool_call`, `state_change` or `environment_action` contract therefore
  contains a `target_action` requirement whose `owner_ref` is the unsafe
  outcome's exact control-action ID; resolving only an indirect carrier is not
  sufficient;
- `agent_message` requires an `agent_channel` requirement;
- a state resource is required only when that particular store's identity or
  behaviour is part of the attack mechanism; merely observing a state-based
  outcome does not create a semantic resource requirement;
- state and event observation, clocks, chat surfaces, locators and credentials
  remain consumer runtime-readiness concerns expressed through the existing
  execution-requirements and runtime-binding contracts;
- the route's selected factor must be one of the published causal factors;
- absent or invalid route fields fail Stage 5 before Stage 6;
- an explicit analytical-only disposition is retained as a safety finding and
  excluded from downstream execution compilation; and
- ordinary narrative prose is never parsed to recover route fields.

One scenario has exactly one selected delivery route and one action path.
Materially different direct, indirect and conversation attacks receive
separate scenario IDs. The consumer may not turn one ambiguous stimulus into
several execution variants.

## 6. Producer wire records

### 6.1 `SemanticExecutionContract`

Add this closed value to `ExecutionProjectionV2`:

```yaml
execution_contract:
  disposition: executable_route
  requested_environment_basis: target_profile
  delivery:
    delivery_class: indirect_content
    factor_id: CF-1
    source_role: attacker_influenced_content
    carrier_requirement_id: REQ-1
  action_kind: tool_call
  resource_requirements:
    - requirement_id: REQ-1
      purpose: stimulus_carrier
      factor_id: CF-1
      owner_ref: PM-1-1
      acceptable_resource_kinds: [tool, integration]
      role_id: attacker_influenced_content_source
      operation: retrieve_content
      required_properties: [content_reaches_model_context]
      required_attacker_influence: indirect
      exact_resource_id: null
      late_bindable: true
      evidence_refs: [CF-1]
    - requirement_id: REQ-2
      purpose: target_action
      factor_id: null
      owner_ref: CA-1-1
      acceptable_resource_kinds: [tool, integration]
      role_id: target_control_action
      operation: CA-1-1
      required_surfaces: [tool_call]
      required_properties: []
      required_attacker_influence: none
      exact_resource_id: TOOL-123
      late_bindable: false
      evidence_refs: [CA-1-1, target-profile:TOOL-123]
```

Closed enums:

- purpose: `stimulus_carrier`, `target_action`, `state_resource`,
  `agent_channel`;
- acceptable resource kind: `surface`, `tool`, `integration`, `state_store`,
  `agent_channel`. The tuple is canonical, unique and non-empty. It may contain
  one kind when the path is exact or several explicitly acceptable kinds when
  a logical role can later be realized by, for example, either a tool or an
  integration.

`role_id`, `operation` and `required_properties` are canonical lower-snake-case
semantic identifiers. `required_surfaces` is a canonical non-empty tuple of
closed `ExecutionSurface` values. Matching is exact; every required surface
must be declared by the matched profile resource; no fuzzy comparison is
permitted.
Attacker influence is a closed fact: `none`, `direct`, `indirect` or `unknown`.
A requirement may demand one exact value; `unknown` never satisfies a demand
for direct or indirect attacker influence.

Every requirement must be referenced by the route, action or domain state
needed by the unsafe outcome. Unused requirements are invalid. Required IDs and ordering
are canonical and deterministic.

These are domain-semantic resources only. Chat surfaces, clocks, generic
detectors, event collectors, locators and credentials remain in the existing
neutral `ExecutionRequirements` and consumer runtime readiness. Their absence
does not make a semantic scenario parameterized. A state resource is included
only when the identity or behavior of that particular store is part of the
attack meaning, not merely because an observer reads state.

`factor_id` is trace identity and, when present, names the selected `CF-*`
record. `owner_ref` is the underlying PM/FB/CA/CM/CL structural identity used
for target matching. The producer resolves `factor_id` to its exact
`structural_source_id`; a profile never treats a `CF-*` identifier as a target
resource identity.

`requested_environment_basis` is `target_profile`, `simulation_profile` or
`target_agnostic`. It may be omitted only for the safe deterministic default:
no domain resource means `target_agnostic`; any domain resource means
`target_profile`. `target_agnostic` with domain-resource requirements is
invalid. Selecting simulation without a simulation profile remains explicitly
incomplete and never triggers automatic mock creation.

The analytical union member instead carries:

```yaml
execution_contract:
  disposition: analytical_only
  gaps:
    - code: operation_missing
      detail: The source evidence does not establish an executable operation.
      evidence_refs: [CF-1]
```

Closed gap codes are `delivery_path_missing`, `operation_missing`,
`resource_role_missing` and `observable_oracle_missing`. At least one gap and
one evidence reference are required. It carries no fabricated delivery,
action or resource binding.

### 6.2 `ExecutionClassification`

Add this closed value to `ExecutionProjectionV2`:

```yaml
execution_classification:
  binding_completeness: parameterized
  environment_basis: none
  profile_fit: needs_binding
  claim_scope: no_execution_claim
  resolved_bindings: []
  unresolved_requirement_ids: [REQ-1]
  ambiguous_matches: []
  unsupported_requirement_ids: []
  diagnostics:
    - code: target_profile_not_supplied
      requirement_id: REQ-1
      candidate_resource_ids: []
  target_profile_digest: null
  classification_digest: <digest>
```

Resolved bindings contain exact `(requirement_id, resource_id,
operation_id)` tuples. Ambiguities retain the exact sorted candidate resource
IDs. Diagnostics use a closed code registry:

- `target_profile_not_supplied`;
- `target_resource_unresolved`;
- `target_resource_ambiguous`;
- `operation_unsupported`;
- `profile_inventory_unknown`;
- `profile_inferred_only`;
- `simulation_contract_missing`;
- `oracle_missing`;
- `execution_route_missing`;
- `explicit_target_ref_dangling`;
- `target_profile_digest_mismatch`.

Classification and the enclosing projection are content-addressed.

### 6.3 Existing stimulus record

`AdversarialStimulusRequirement` shall cease delegating path selection to the
consumer. It shall name the exact delivery record and selected factor. Intent
and desired effect remain presentation-authoring inputs, not binding
authority. Executable projections contain the exact contract-bound stimulus;
analytical-only projections contain no executable stimulus.

## 7. Shared execution target profile

The producer owns and publishes the contract kit for
`execution-target-profile-v1`; the artifact generator vendors it.

```yaml
schema_version: execution-target-profile-v1
profile_id: klarna-test
environment_id: klarna-test
basis: target
authority: reviewed
inventory_completeness: reviewed_complete
evidence_refs: [architecture-review-2026-09]
resources:
  - resource_id: TOOL-payment-scheduler
    resource_kind: tool
    role_ids: [target_control_action]
    structural_refs: [CA-1-1]
    attacker_influence: none
    surfaces: [tool_call, tool_result]
    operations:
      - operation_id: schedule_payment
        semantic_operation: CA-1-1
        argument_names: [recipient, amount, execution_time]
        observable_properties: [tool_call, tool_arguments]
    interface_schema: {}
    evidence_refs: [tool-registry:schedule-payment]
    authority: reviewed
    simulation_behavior: null
semantic_digest: <digest>
```

Profile basis is `target` or `simulation`. Authority is `reviewed` or
`inferred`. Inventory completeness is `unknown`, `inferred_partial` or
`reviewed_complete`.

Only reviewed resource facts may support a concrete target-specific
classification. An inferred profile may help form a parameterized contract but
cannot establish a target claim. A role-based search additionally requires a
reviewed-complete inventory before its single visible match can be considered
unique. A producer-selected exact resource ID may be concrete in a partial
inventory when that exact resource itself has reviewed evidence, because no
resource selection is being inferred from inventory completeness.

A simulation resource additionally requires a complete closed
`simulation_behavior` describing deterministic inputs, outputs, emitted
events, state changes and observation points. Missing target information never
creates a simulation profile automatically. If both target and simulation
profiles are available, the caller explicitly selects one.

The profile excludes URLs, credentials and secret values. Those remain in the
artifact generator's runtime bindings.

## 8. Deterministic producer classification

Expose one pure seam:

```python
def classify_scenario_execution(
    contract: SemanticExecutionContract,
    unsafe_outcome: UnsafeOutcome,
    profile: ExecutionTargetProfile | None,
) -> ExecutionClassification:
    ...
```

The algorithm is:

1. Validate that delivery, selected factor, action, required operations and
   observable unsafe outcome are semantically complete.
2. If any indispensable semantic element is absent, return
   `analytical_only/none/no_execution_claim` with exact diagnostics.
3. If the contract requires no domain resource, return
   `concrete/target_agnostic/not_required/model_behavior_only`.
4. If no profile is selected, retain the exact logical requirements and return
   `parameterized/none/needs_binding/no_execution_claim`.
5. Verify the profile digest, authority, basis and internal integrity.
6. For each exact resource reference, require that exact resource and
   operation to satisfy every constraint. With no profile, retain the reference
   as unresolved. With a selected profile, a dangling or incompatible exact
   reference yields `analytical_only/none/invalid/no_execution_claim`; never
   substitute another resource.
7. For each role requirement, require the resource kind to be in the exact
   `acceptable_resource_kinds` set and match role, semantic operation, required
   properties, required surface, attacker influence and structural reference.
   Specifically, `requirement.operation` equals
   `profile.operation.semantic_operation`; the bound concrete operation is the
   profile operation's `operation_id`.
8. One role match resolves the requirement only under a reviewed-complete
   inventory. One visible match under an unknown or partial inventory remains
   `needs_binding`; zero matches under an unknown or partial inventory also
   remains `needs_binding`; zero matches under a reviewed-complete inventory is
   `unsupported`; multiple matches are `ambiguous`.
9. All requirements resolved under a reviewed target profile yields
   `concrete/target_profile/matched/target_specific_intent`.
10. All requirements resolved under a complete simulation profile yields
    `concrete/simulation_profile/matched/agent_behavior_with_simulated_tools`.
11. Otherwise retain a parameterized classification and every diagnostic.

Input ordering may not affect matches, identities or digests.

## 9. Artifact-generator binding

Add the pure consumer seam:

```python
def resolve_execution_case(
    intent: ExecutionIntent,
    profile: ExecutionTargetProfile | None,
) -> ExecutionCaseResolution:
    ...
```

The result contains either one `BoundExecutionCase` or one typed exclusion.
It never silently fans out.

`BoundExecutionCase` contains:

- source run/scenario/projection identities and digests;
- the producer classification and classification digest;
- selected profile ID, basis and digest when applicable;
- exact requirement-to-resource/operation mappings;
- the source classification and the concrete case-resolution result;
- claim scope;
- immutable case digest.

Exclusion codes are `analytical_only`, `needs_target_binding`, `ambiguous`,
`unsupported`, `invalid_profile` and `invalid_source_binding`.

Consumer behavior:

- verify a producer concrete binding against the exact pinned profile;
- resolve parameterized requirements using the same exact matching rules;
- never use resource names or scenario prose as matching evidence;
- never convert missing target information into a mock;
- require an explicit simulation profile for simulated claims;
- preserve zero/multiple-match diagnostics;
- do not call an author, compiler, provider or network for exclusions;
- permit several cases only when the caller explicitly supplies several
  profiles or asks for named alternatives; and
- pin the bound-case digest into readiness, plan, artifact trace and receipt.

A target-agnostic intent remains a target-agnostic bound case when the caller
also supplies a profile for other entries in the same bundle. The irrelevant
profile is neither rejected nor pinned to that case, and the claim remains
`model_behavior_only`.

The bound case records that every semantic resource is concrete even when the
source projection was published as parameterized. It retains the source
classification rather than rewriting it.

`bind_and_plan` shall consume a `BoundExecutionCase` plus an optional
`RuntimeBindingSet`; it shall not reinterpret an unbound `ExecutionIntent`.
Missing credentials, locators, safe values, clocks or observers produce normal
runtime-readiness diagnostics after a bound case exists. They are not
execution-case exclusions. Existing runtime readiness axes remain separate
from semantic binding completeness and profile fit.

## 10. Garak compilation consequences

- `direct_prompt` becomes a user message; it needs no domain tool profile.
- `conversation_context` becomes fixed prior turns followed by the adversarial
  user turn or other producer-selected context position.
- `indirect_content` becomes a call/result pair for the exact bound carrier
  resource.
- a tool-call unsafe action uses the exact bound target resource and operation.
- simulated resources are clearly labeled and their mock contract is emitted
  or referenced by the artifact.
- the detector/oracle derives from the producer unsafe outcome and consumer
  observer binding; it is never generated from narrative prose.
- artifact metadata exposes `claim_scope` and cannot label a simulated case as
  target-integrated.

## 11. CLI and persistence

Scenario generator product `run` gains an optional explicit target-profile
path and optional explicit basis selection. No profile remains a valid mode and
produces target-agnostic or parameterized scenarios as appropriate.

When a profile is supplied, the run copies its verified canonical content to
`execution-target-profile.json` before publishing the final bundle index. Each
projection classification pins that content digest. The artifact generator
still receives the profile path explicitly and verifies the pin; it never
searches neighboring files or guesses a profile by name.

The artifact-generator primary command gains an explicit target-profile input.
For each selected entry it writes either:

- `bound-execution-case.json` followed by normal readiness/plan/artifact files;
  or
- `execution-case-exclusion.json`, with no platform artifact.

Manifests retain exact totals for concrete, parameterized, simulated,
analytical-only, ready, unsupported, ambiguous and unresolved cases. These are
counts, not a blended score.

## 12. Acceptance matrix

Both repositories shall exercise the same canonical cases:

1. Direct prompt with no domain resource is concrete and target-agnostic.
2. Jailbreak/encoding stimulus with no domain resource is concrete and
   target-agnostic.
3. Indirect-content path with a precise carrier role and no profile is
   parameterized.
4. Exact reviewed target profile with one matching carrier and action is
   concrete and target-backed.
5. One unresolved requirement keeps the whole scenario parameterized.
6. Zero matches in an unknown/partial inventory is unresolved, not unsupported.
7. Zero matches in a reviewed-complete inventory is unsupported.
8. Multiple exact matches are ambiguous and none is chosen.
9. An explicit resource ID that is absent or incompatible is invalid; no
   fallback match occurs when a profile is supplied. Without a profile the
   exact reference remains unresolved and parameterized.
10. A tool name appearing only in prose is not target authority.
11. An inferred profile cannot produce a target-specific claim.
12. An explicit complete mock produces a concrete simulated case.
13. Missing target data never automatically produces a mock.
14. Target and simulation profiles without explicit basis selection are
    invalid.
15. Missing route, required operation or observable oracle is analytical-only.
16. Missing endpoints, auth, locators or test data affects consumer runtime
    readiness, not producer semantic classification.
17. Consumer resolution preserves delivery, factor, operation and oracle.
18. Analytical, ambiguous, unsupported and unresolved cases make zero author
    and compiler calls.
19. A simulated artifact carries only the simulated-agent claim.
20. Reordering profiles/resources/requirements leaves identities and results
    unchanged.
21. Profile, classification or case tampering changes a digest and is rejected.
22. One scenario creates multiple artifacts only through explicit separate
    bound cases.
23. A producer fixture is consumed byte-for-byte from the vendored contract
    kit without a sibling checkout or network.

## 13. Implementation sequence

1. Add this approved specification and domain terms.
2. Add producer acceptance for Stage 5 route selection and deterministic
   classification.
3. Add the target-profile, semantic execution-contract and classification
   models plus pure classifier.
4. Extend corrected Stage 5 prompt views and deterministic handle compiler.
5. Put the contract and classification in projection v2 and refresh schema,
   canonical fixtures and producer lock.
6. Wire optional target-profile input through product `run` and bundle
   publication.
7. Vendor the exact producer kit in the artifact generator and refresh its
   upstream lock.
8. Add consumer acceptance and the target-profile, bound-case and exclusion
   models.
9. Implement pure case resolution before runtime readiness.
10. Make planning, Garak compilation, trace, receipt and CLI consume and pin the
    bound case.
11. Run the coordinated fixture matrix and both repositories' deterministic
    gates.
12. Run DRY and CRAP checks after the entire path is operational. Defer source
    mutation unless a later hardening pass is explicitly requested.

## 14. Quality gates

- generated Gherkin acceptance passes in both repositories;
- deterministic unit and cross-repository fixture tests pass offline;
- no model/client construction occurs in either classifier or resolver;
- no author/compiler construction occurs for excluded cases;
- one digest recipe and one exact matching implementation exist per repository;
- changed production functions have CRAP at or below 6;
- DRY, Ruff, format and diff checks pass;
- producer contract hashes reproduce and consumer files match byte-for-byte;
- live model execution is not required for contract correctness;
- at least one target-agnostic, one parameterized, one target-bound and one
  simulated fixture completes through the appropriate endpoint.

## 15. Non-goals

- discovering deployment tools from prose;
- asking a model whether its own output is executable;
- treating taxonomy technique IDs as tool or operation instructions;
- automatically mocking missing target resources;
- embedding credentials or live endpoints in producer artifacts;
- choosing among ambiguous matches;
- claiming a real integration is vulnerable before execution evidence exists;
- changing the STPA causal path during artifact generation; or
- requiring complete target knowledge for model-only attacks.

## 16. Completion condition

The work is complete when every published scenario states a deterministic
semantic execution contract and honest classification; parameterized scenarios
retain enough information for exact later binding; simulations are explicit
and claim-limited; analytical findings cannot reach compilation; the artifact
generator creates a content-addressed bound execution case before readiness;
and every compiled artifact preserves the scenario's delivery, causal factor,
operation and oracle without invention.
