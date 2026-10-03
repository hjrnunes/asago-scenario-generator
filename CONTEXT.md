# STPA–Taxonomy Synthesis Domain

This context names the domain concepts used when taxonomy supplies systematic
obligations to an STPA-led analysis. It describes the meaning of the work, not
how the repository implements or stores it.

## Language

**Scenario**:
A description of how a use case can fail, including its causal conditions,
unsafe behavior, consequences and supporting evidence. It is not an executable
test or a prescribed sequence of messages.
_Avoid_: prompt, payload, test artifact

**STPA scenario representation**:
The narrative, attack tree and Gherkin that express one scenario's causal
meaning, accompanied by the metadata necessary to understand and trace it.
These describe a failure hypothesis, not harness instructions or an execution
result.
_Avoid_: prepared conversation, executable test script

**Test artifact**:
A concrete test of a scenario, including its stimulus, setup, delivery and
observation method for a selected environment.
_Avoid_: scenario, observed failure

**Artifact fidelity**:
Whether a concrete test exercises the scenario's causal mechanism and
distinguishes its unsafe behavior from its safe alternatives.
_Avoid_: successful compilation, content integrity, scenario coverage

**Semantic failure criterion**:
The behavior that would constitute the scenario's failure, independently of
the detector or harness chosen to observe it.
_Avoid_: detector expression, judge prompt, tool-call proxy

**Taxonomy obligation**:
A risk-specific requirement to account for one authoritative attack pattern
for one capability context.
_Avoid_: catalog item, coverage claim

**Mapping relation**:
A closed statement of how one taxonomy record relates to another at one edge;
it does not by itself establish the meaning of a complete risk-to-pattern path.
_Avoid_: mapping strength, correspondence claim

**Mapping path witness**:
The complete ordered provenance connecting one reviewed risk to one attack
pattern, retaining every mapping relation used to discover the pair.
_Avoid_: strongest edge, taxonomy chain label

**Crosswalk disposition**:
The evidence-bounded conclusion about one exact reviewed-risk and attack-pattern
pair: direct support, category hypothesis, association only, reviewed mismatch,
or unresolved.
_Avoid_: STPA applicability, scenario coverage

**Reviewed crosswalk assertion**:
A human decision supporting, rejecting, or leaving unresolved one exact
reviewed-risk and attack-pattern pair, bound to the reviewed source content.
_Avoid_: model alignment verdict, category-wide override

**Crosswalk resolution**:
The complete deterministic account of every discovered reviewed-risk and
attack-pattern pair, its full mapping provenance, and its crosswalk disposition.
_Avoid_: obligation plan, scenario classification

**Neutral obligation brief**:
The non-prescriptive form of a taxonomy obligation presented to STPA as an
analysis question, with exact provenance but no required attack sequence.
_Avoid_: taxonomy scenario, execution template

**Obligation consideration**:
STPA's explicit examination of one taxonomy obligation against its own losses,
hazards, constraints, and control structure.
_Avoid_: mechanism implementation, automatic coverage

**Upstream STPA gap**:
A missing loss, hazard, constraint, or control-structure concept that prevents
STPA from meaningfully analysing an otherwise applicable obligation.
_Avoid_: uncovered attack, failed scenario

**Bounded structural revision**:
The single additive opportunity to address upstream STPA gaps while preserving
the original analysis as history.
_Avoid_: regeneration loop, taxonomy override

**Obligation accounting**:
The provisional record of what STPA did with every taxonomy obligation,
separate from scenario realization.
_Avoid_: coverage score

**Synthesis run**:
The STPA-led workflow in which Phase 1 obligations are always considered and
accounted for before ordinary STPA scenario production completes.
_Avoid_: hybrid scenario generator, combined-projection run

**Product run**:
The normal end-to-end scenario-generation workflow: taxonomy supplies
obligations and STPA alone produces scenarios.
_Avoid_: taxonomy generation run, choice of peer generators

**Semantic execution contract**:
The scenario-owned description of its delivery path, selected causal factor,
logical resource needs, operations and observable unsafe outcome.
_Avoid_: runtime binding, generated transcript, platform plan

**Environment basis**:
Whether execution meaning is target-agnostic, backed by a reviewed target
profile, backed by an explicit simulation profile, or has no execution basis.
An omitted request is the last case when domain resources are required: it is
an unresolved choice, not an implicit real-target request. A resource-free
model-output route may derive `target_agnostic`; a resource-bearing route
remains `parameterized` with basis `none` until a target or simulation is
selected explicitly.
_Avoid_: deployment readiness

**Execution target profile**:
A content-addressed description of the semantic resources and interfaces
available in one real or deliberately simulated environment. Its observed
inventory authority remains distinct from inferred or reviewed semantic
authority, so automatic discovery does not pretend to be human review.
Supplying one is the consumer's explicit choice for a pending parameterized
contract; it does not rewrite the producer's route or turn an omitted request
into a default target.
_Avoid_: capability inference, credential file, runtime receipt

**Target discovery**:
An independent, read-only observation of a target interface followed by a
separately identified semantic interpretation. For MCP, discovery lists tool
schemas without calling the tools and publishes an execution target profile;
connection details and credentials never enter the artifact.
_Avoid_: product-run introspection, active probing, trusted semantic truth

**Target realization**:
The additive post-baseline step that relates exact observed target operations
to the completed systemic STPA model. It may select one exact operation for a
baseline control action or add a narrowly verified target-derived action and
ICA, but it never rewrites or removes baseline losses, hazards, constraints,
control actions, or ICAs.
_Avoid_: target-aware baseline, generic resource binding, scenario generation

**Model output**:
The externally returned text or structured value from the tested model or
agent invocation. It uses neutral runtime surfaces and does not imply a
domain-specific environment resource.
_Avoid_: internal coordination message, target operation

**Comparison value grounding**:
The distinction between a literal present in supplied rule/action evidence and
a reference value that is still unknown. Source presence does not independently
verify that the proposed comparison correctly interprets the rule.
_Avoid_: JSON type compatibility, inferred business policy, confirmed violation

**Agent message**:
An internal message sent between responsibilities, controllers, or separately
addressable agents. It requires an `agent_channel` semantic resource and must
not be represented as ordinary user/model chat merely because a chat adapter
can send text.
_Avoid_: model output, generic conversation history

**Analytical-only scenario**:
An admitted safety finding whose delivery path, operation or observable oracle
is too incomplete to compile into an honest executable test.
_Avoid_: unsupported platform case, missing credentials, failed test

**Standalone STPA analysis**:
A diagnostic baseline STPA analysis that omits taxonomy-obligation
completeness. It supports isolation and comparison but is not the normal
product workflow.
_Avoid_: equivalent product run, taxonomy-complete analysis

**Scenario-generation authority**:
The methodology permitted to create and admit scenarios. In this domain that
authority is STPA alone; taxonomy discovers and supplies obligations but does
not author scenarios.
_Avoid_: peer generation approach, taxonomy-authored scenario

**Structural consideration**:
The STPA account of each UCA slot as an ICA, justified N/A, or unresolved,
independent of taxonomy correspondence.
_Avoid_: taxonomy coverage

**Prompt view**:
The small, closed, stage-specific explanation of the exact concepts and choices
a model needs for one decision. Opaque handles are accompanied by their local
meaning; digests, paths, scores, raw mappings, and unrelated global records are
excluded.
_Avoid_: serialized artifact, context dump

**Prompt preflight**:
The deterministic check of a fully rendered prompt's contract, references,
size, model context window, reserved output, and safety margin before any
provider request is allowed.
_Avoid_: provider error, silent truncation

**Scenario generation context**:
The immutable, target-scoped authority behind Stage 5 and every Stage 6
renderer: the selected loss, hazard, governing constraint, unsafe action,
obligation concern, and causal evidence. Stage 5 receives only its actionable
semantic projection; Stage 6 retains the complete content-addressed artifact.
Contextual Stage 5 declares each causal statement once. Its exact PM source
also supplies the defender-belief annotation; an undeclared belief is simply
not selected in this scenario, not proven safe.
_Avoid_: global STPA dump, unrelated constraints

**Test stimulus**:
The provider-described way adversarial input reaches one selected causal path,
using a closed request-local category. Deterministic compilation derives the
resource roles required by that category and the fixed target action; an
unsupported upload or traffic/load stimulus remains analytical.
_Avoid_: runtime binding, inferred resource set, delivery label chosen from prose

**Scenario candidate outcome**:
The single terminal generation/publication result for one exact
scenario/ICA-slot/ICA identity. Its diagnostic messages are retained
separately and do not increase the candidate count.
_Avoid_: error-message count, provider-call success flag

**Synthesis terminal status**:
The product-level yield outcome derived from exact candidate records:
`completed`, `no_candidates`, `failed` after attempted zero yield, or
`degraded` for partial/unattempted yield.
_Avoid_: provider transport status, diagnostic-message count, coverage status

**Scenario realization**:
The separate account of whether a generated scenario retained an exact ICA and
its obligation concern. It does not alter the structural obligation accounting
decision.
_Avoid_: correspondence coverage, ICA disposition

**Obligation-linked scenario**:
A completed STPA scenario whose generation context identifies one or more
taxonomy obligations that influenced its analysis. The link does not mean the
scenario implements an obligation's attack mechanism.
_Avoid_: taxonomy-generated scenario, obligation implementation
