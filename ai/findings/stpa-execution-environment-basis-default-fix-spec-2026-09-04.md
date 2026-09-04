# STPA execution environment-basis default correction

Status: proposed for approval  
Date: 2026-09-04  
Repositories: `asago-scenario-generator`, `asago-artifact-generator`  
Evidence run: `output/runs/20260904-klarna-gemma4-oc-wire-contract-recovery-v2`

## 1. Objective

Stop treating an omitted environment choice as an implicit request to execute
against a real target. Preserve the distinction between:

- a scenario that needs no domain-specific environment;
- a complete semantic scenario that still needs a target or simulation
  resource to be selected;
- an explicit request to bind against a real target;
- an explicit request to bind against a simulation; and
- an analytical finding that has no executable meaning.

The correction must not turn internal messages, tool calls, state changes, or
external side effects into target-agnostic model conversations merely to make
them pass Garak readiness.

## 2. Plain-language decision

No option and no profile means **no environment has been chosen**.

- If the semantic scenario needs no domain resource, the producer may derive
  `target_agnostic`.
- If the semantic scenario needs a domain resource, the producer retains it as
  `parameterized` with environment basis `none`.
- Supplying a target profile explicitly chooses `target_profile`.
- Supplying a simulation profile explicitly chooses `simulation_profile`.
- An explicit `--basis` without a profile records the requested future basis,
  but does not pretend that the binding already exists.

## 3. Investigation findings

### 3.1 The implicit default is applied before classification

The CLI correctly accepts an optional `--requested-environment-basis`. When it
is omitted and no profile is supplied, `_resolve_requested_environment_basis`
correctly returns `None`.

That absence is later discarded in `stpa/scenario_prod/run.py`:

```python
requested_environment_basis or RequestedEnvironmentBasis.target_profile
```

`generate_bdi_for_context` also declares `target_profile` as its default. By
the time the semantic contract is materialized, code can no longer distinguish
an explicit real-target request from an omitted caller choice.

### 3.2 The classifier itself already has the right no-profile result

`classify_scenario_execution` already classifies a resource-bearing contract
without a supplied profile as:

```text
binding_completeness = parameterized
environment_basis = none
profile_fit = needs_binding
claim_scope = no_execution_claim
```

The defect is therefore primarily in contract construction and consumer
interpretation, not the central classification algorithm.

### 3.3 Ordinary chat and internal agent messages are different things

The current execution model correctly distinguishes:

- `model_output`: the tested model or agent's externally returned response;
- `agent_message`: a message between internal responsibilities, controllers,
  or separately addressable agents.

Garak can supply a normal user turn and observe model output without knowing a
domain-specific target resource. It cannot claim to have delivered or observed
an internal coordination message merely because it can run a chat completion.

Therefore:

- `model_output` uses neutral runtime surfaces and creates no semantic resource
  requirement;
- `agent_message` retains an `agent_channel` semantic resource requirement and
  needs a target or simulation profile.

The fix must not remove `agent_channel` requirements from genuine internal
messages.

### 3.4 The Klarna evidence does not contain 25 generic chat cases

The 25 published scenarios contain:

| Semantic requirements | Count |
| --- | ---: |
| internal `agent_channel` only | 10 |
| target action only | 13 |
| indirect-content carrier plus agent channel | 1 |
| indirect-content carrier plus target action | 1 |

The ten `agent_channel` cases concern internal context synchronization,
policy-to-rule alignment, risk interlocks, uncertainty reporting, rejection
messages, policy flags, and human notifications. Treating them as ordinary
Garak chat would overstate what was tested.

### 3.5 One upstream action-kind result is questionable

The generated control action `Provide grounded response to user` was classified
as `environment_action`. A response returned by the tested model should usually
be `model_output`; `environment_action` should describe a non-model external
side effect.

The Stage 2 prompt lists the five action kinds but does not define them tightly
enough. This is separate from the omitted-basis bug, but it directly affects
whether a scenario is correctly classified as target-agnostic. It must be
corrected at the typed control-structure seam, not by reinterpreting action
descriptions later in Stage 5 or in the artifact generator.

### 3.6 The artifact generator overstates the missing choice

When no profile is supplied, the artifact generator currently reports:

```text
target_profile_not_supplied
the execution contract requests a profile but none was supplied
```

That is correct only when the producer explicitly requested
`target_profile`. For an unspecified parameterized contract, the honest result
is that an environment binding is still needed and may be satisfied by either
an explicitly selected target or an explicitly selected simulation.

## 4. Domain rules

### 4.1 Domain resource requirements

These remain semantic requirements and prevent target-agnostic classification:

- an indirect-content carrier such as a RAG source or tool result;
- a concrete tool or integration action;
- session or persistent-state identity whose behavior is part of the scenario;
- an internal agent/controller message channel;
- an external environment action; and
- any exact domain resource named by the unsafe outcome.

### 4.2 Neutral runtime requirements

These do not create a semantic target-profile dependency:

- an ordinary user-turn surface;
- an externally returned model-output surface;
- a generic output-text observer;
- a content slot for authored adversarial text;
- endpoint locators and transport configuration;
- credentials or secret handles; and
- generic clocks or collectors unless the exact domain resource is part of the
  scenario's meaning.

Neutral runtime requirements remain in `ExecutionRequirements` and runtime
bindings. They do not belong in `SemanticExecutionContract.resource_requirements`.

### 4.3 Action-kind meanings

Stage 2 must use these exact meanings:

- `model_output`: text or structured output returned by the tested model or
  agent invocation;
- `tool_call`: a structured invocation emitted by the tested agent;
- `state_change`: a change to session or persistent state;
- `agent_message`: an internal message to another responsibility, controller,
  or separately addressable agent;
- `environment_action`: an external side effect that is not merely model
  output, a tool call, or a state mutation.

Target type alone does not turn a user-facing response into an environment
action. The existing rule that a responsibility target is an `agent_message`
remains valid.

## 5. Scenario-generator changes

### 5.1 Preserve the optional caller choice

Change the Stage 5 interface so `requested_environment_basis` remains optional
through contract materialization.

Remove both implicit real-target defaults:

- the fallback in `_stage5_bdi`; and
- the default argument on `generate_bdi_for_context`.

The normal product run passes exactly one of:

- the caller's explicit requested basis;
- the basis derived from a supplied, validated profile; or
- `None`.

### 5.2 Derive the contract basis after semantic requirements exist

Use one pure module interface:

```python
def resolve_contract_environment_request(
    requirements: tuple[ExecutionResourceRequirement, ...],
    requested: RequestedEnvironmentBasis | None,
) -> RequestedEnvironmentBasis | None:
    ...
```

Its complete behavior is:

| Domain requirements | Requested value | Contract value |
| --- | --- | --- |
| none | omitted | `target_agnostic` |
| none | `target_agnostic` | `target_agnostic` |
| none | target or simulation | `target_agnostic` |
| present | omitted | `null` |
| present | target | `target_profile` |
| present | simulation | `simulation_profile` |
| present | `target_agnostic` | reject |

A global profile may be supplied for a mixed bundle. Resource-free cases do
not consume or pin it.

### 5.3 Permit an unresolved environment request

`SemanticExecutionContract` must allow:

```yaml
requested_environment_basis: null
resource_requirements:
  - ...
```

This means that semantic execution is complete but the caller has not chosen
between a real target and a simulation. It does not mean target-agnostic.

`target_agnostic` with domain resource requirements remains invalid.

### 5.4 Keep classification dimensions independent

For a resource-bearing contract with no profile, classification remains:

```text
parameterized / none / needs_binding / no_execution_claim
```

Diagnostics depend on the contract request:

- omitted: `environment_profile_not_supplied`;
- explicit target: `target_profile_not_supplied`;
- explicit simulation: `simulation_contract_missing`.

Do not change this result to `concrete` merely because Garak can represent the
scenario as text.

### 5.5 Tighten Stage 2 action semantics

Update the Stage 2 control-action prompt to define every action kind using the
rules in section 4.3 and include domain-neutral contrasts:

- returning advice to a user is `model_output`;
- emitting a structured refund invocation is `tool_call`;
- updating a session record is `state_change`;
- sending a risk flag to another controller is `agent_message`;
- activating a physical alarm is `environment_action`.

The provider continues to return the typed `effect_kind`. Deterministic code
must not recover it from verbs in the description. Existing structural checks
remain responsible for rejecting a responsibility target with a non-message
effect.

The Stage 2 critic should be instructed to report an explicit gap when a
control action's described effect conflicts with its typed effect kind. The
bounded revision path may correct it; exhaustion retains the original typed
result and diagnostic rather than silently relabelling it.

## 6. Artifact-generator changes

### 6.1 Interpret an omitted request honestly

`resolve_execution_case` must distinguish:

- target-agnostic and resource-free: produce a `BoundExecutionCase` without a
  profile;
- resource-bearing with no requested basis and no profile: retain a typed
  `needs_environment_binding` exclusion;
- explicitly target-backed without a profile: `needs_target_binding`;
- explicitly simulation-backed without a profile: `needs_simulation_binding`.

These are pending binding results, not malformed source artifacts.

### 6.2 Let an explicitly supplied profile choose the pending basis

For a parameterized contract whose request is `null`, supplying a profile at
artifact-generation time is an explicit choice:

- a target profile attempts exact target binding;
- a simulation profile attempts exact simulation binding.

The consumer must still enforce profile integrity, authority, inventory
completeness, exact role and operation matching, attacker influence, surfaces,
and observable properties. No fuzzy or prose matching is added.

The resulting bound case records and pins the selected basis and profile. It
does not rewrite the source projection.

### 6.3 Preserve the Garak adapter's narrow defaults

Garak may continue to provide deterministic runtime mechanics for:

- user turns;
- multi-turn conversation history;
- ordinary model-output observation; and
- exact tool-call observation after a target operation is bound.

It may not default an internal agent channel, RAG carrier, target tool,
session store, environment action, or real clock.

## 7. Cross-repository contract update

Revise the current pre-alpha contract in place; do not add another projection
or bundle version solely for this correction.

Producer work:

1. update model semantics and schemas;
2. add canonical fixtures for unresolved environment choice;
3. regenerate canonical digests and `CONTRACT.lock`;
4. preserve an explicit target and explicit simulation fixture; and
5. publish one producer commit.

Consumer work:

1. vendor the producer contract kit byte-for-byte;
2. update the inward model and resolver semantics;
3. refresh `UPSTREAM.lock` to the producer commit; and
4. prove byte equality excluding `UPSTREAM.lock`.

Historical run artifacts need not be rewritten. They remain readable as the
meaning they actually published: an explicit target-profile request.

## 8. Acceptance contract

### Producer

1. Omitted basis and no profile reach Stage 5 as `None`.
2. A resource-free direct prompt with model output becomes
   `concrete/target_agnostic/not_required/model_behavior_only`.
3. A resource-free multi-turn conversation with model output has the same
   semantic classification; multi-turn support remains a runtime requirement.
4. An internal `agent_message` creates an `agent_channel` domain requirement.
5. An internal message with no selected profile becomes
   `parameterized/none/needs_binding/no_execution_claim`.
6. A tool call, state change, external environment action, or indirect carrier
   with no selected profile gets the same parameterized result.
7. An omitted basis on a resource-bearing contract remains `null`; it is not
   rewritten to `target_profile`.
8. Explicit target without a profile records `target_profile` and the exact
   missing-target diagnostic.
9. Explicit simulation without a profile records `simulation_profile` and the
   exact missing-simulation diagnostic.
10. Explicit target-agnostic with any domain requirement is rejected.
11. A supplied target or simulation profile determines the request basis and
    remains digest-pinned.
12. A global profile does not change a resource-free case's target-agnostic
    classification.
13. Stage 2 examples distinguish model output, tool calls, state changes,
    internal messages, and environment actions.
14. A typed action-kind conflict becomes an explicit critic gap and is never
    silently reclassified from prose.

### Consumer

15. A target-agnostic model-output case binds without a profile and reaches
    ordinary Garak runtime readiness.
16. An unspecified parameterized case without a profile reports
    `needs_environment_binding`.
17. The same case binds against an explicitly supplied matching target profile.
18. The same case binds against an explicitly supplied complete simulation
    profile.
19. An explicit target request cannot consume a simulation profile, and the
    inverse also fails closed.
20. Garak does not synthesize an internal agent channel or indirect-content
    carrier from its ordinary chat defaults.
21. Mixed bundles may contain target-agnostic, pending, target-bound, and
    simulated cases without applying one case's basis to another.

### Live qualification

22. Run Klarna without `--basis` and without a profile.
23. No resource-bearing contract may claim that a real target was explicitly
    requested.
24. Any genuine `model_output` case is target-agnostic and reaches the artifact
    generator's runtime-readiness step without a target profile.
25. Internal messages, tools, state changes, indirect carriers, and environment
    actions remain pending rather than being promoted to generic chat tests.
26. Report counts separately for target-agnostic, pending-unselected,
    target-requested, simulation-requested, and analytical-only cases.

The live run has no required scenario-count target. The gate concerns truthful
classification and readiness, not promotion of more cases.

## 9. Likely files

Scenario generator:

- `src/asago_scenario_generator/stpa/scenario_prod/run.py`
- `src/asago_scenario_generator/stpa/scenario_prod/bdi_generation.py`
- `src/asago_scenario_generator/stpa/scenario_prod/execution_classification.py`
- `src/asago_scenario_generator/stpa/models/execution_classification.py`
- `src/asago_scenario_generator/stpa/system_model/prompts/stage2_call2b_system.j2`
- `src/asago_scenario_generator/stpa/system_model/prompts/stage2_call2b_user.j2`
- `src/asago_scenario_generator/stpa/system_model/prompts/critic_system.j2`
- execution projection schemas, fixtures, acceptance, unit tests, and docs.

Artifact generator:

- `src/asago_artifact_generator/planning/resolve_case.py`
- `src/asago_artifact_generator/models/execution_case.py`
- `src/asago_artifact_generator/garak/default_bindings.py`
- CLI manifest aggregation, consumer contract fixtures, tests, and docs.

## 10. Non-goals

- inventing a Klarna target profile;
- treating all direct prompts as target-agnostic;
- turning internal messages into model output;
- deriving action kind from description keywords;
- adding endpoint URLs, credentials, or secret values to producer artifacts;
- making Garak responsible for scenario meaning;
- adding automatic simulations; or
- weakening exact resource matching.

## 11. Completion criteria

The work is complete when omission remains omission, target-agnostic cases are
derived only from genuinely resource-free model behavior, parameterized cases
can later bind to an explicitly selected target or simulation, and both
repositories report the distinction without inventing execution evidence.

