# Scenario Design and Generation: Scope and Findings

Exploratory analysis of the problem of LLM-driven red-teaming scenario design and generation for LLM and Agentic AI
systems.

**Status**: Draft — several key design decisions resolved (§9 updated), remaining open questions are non-blocking.

**Context**: This document is unconstrained by existing fg-gen work. The only fixed inputs are risk cards (from the
policy-mapper) and a free-form use case description.

**References**:

- [MAESTRO Methodology Analysis](maestro-methodology-analysis.md)
- [Threat Modeling Agentic AI — Schneider](threat-modeling-agentic-ai-schneider.md)
- OWASP Agentic AI Threats and Mitigations v1.1 (Dec 2025)
- OWASP Top 10 for LLM Applications 2025
- NIST AI 100-2 Adversarial ML Taxonomy
- [GenAI Security Crosswalk](https://github.com/emmanuelgjr/GenAI-Security-Crosswalk) (LLM Top 10 × MITRE ATLAS
  mappings)

---

## 1. Design philosophy: LLM as degenerate agent

Rather than treating LLM red-teaming and agentic red-teaming as separate concerns, we treat a plain LLM application as
an agent with minimal capabilities — "an agent that can only talk."

Schneider's five-zone model maps directly to a capability spectrum:

| Active zones                      | System type                       |
|-----------------------------------|-----------------------------------|
| 1 (Input) + 2 (Reasoning)         | Pure LLM — text-in, text-out      |
| 1–3 (+ Tool Execution)            | LLM with tools / function calling |
| 1–4 (+ Memory/State)              | Stateful agent                    |
| 1–5 (+ Inter-Agent Communication) | Multi-agent system                |

The OWASP Agentic Threats decision tree (Steps 1–6) degrades the same way. For a pure LLM, Steps 2–6 mostly answer "no,"
and you're left with T6 (goal manipulation via prompt injection), T7 (misaligned behavior), T8 (untraceability), and the
LLM Top 10 proper. As capabilities are "turned on" — memory, tools, auth delegation, multi-agent communication —
additional threat families activate.

**Consequence**: The scenario generator needs one pipeline with capability flags that expand the threat surface, not two
separate pipelines for LLM vs. agentic systems.

---

## 2. Inputs

### 2.1 Risk cards

Produced by the policy-mapper. Each risk card contains:

- **Risk identity**: `risk_id` (IBM Risk Atlas taxonomy, e.g. `atlas-hallucination`), `risk_name`, `risk_description`
- **Confidence**: cross-encoder score, grounding confidence, acceptance method
- **Evidence**: source text, document, page, section, chunk/sentence indices
- **Causal chain**: `threat`, `threat_source`, `vulnerability`, `consequence`, `impact`
- **Mitigations**: action IDs from multiple sources (NIST AI RMF, OWASP LLM 2.0, MIT AI Risk Repository, Credo UCF,
  AIUC1)
- **Scores**: BM25 rank, embedding distance, cross-encoder score, RRF score

Risk cards are policy/governance-level artifacts. They describe *what could go wrong* but not *how an attacker makes it
happen*. The causal chain provides raw material for attack scenario construction but is written from an organizational
perspective, not an adversarial one.

Risk cards contain no system architecture information — no zones, layers, components, or trust boundaries.

### 2.2 Use case description

Free-form text describing the AI system under assessment. No control over format or content — may range from a
one-paragraph idea to a structured questionnaire response.

The system may provide guidance on what an ideal description contains, but cannot enforce requirements. Must work to
some extent for any input.

---

## 3. Taxonomy chain

### 3.1 The risk-to-attack gap

The risk cards are grounded in the **IBM Risk Atlas** — a governance-level risk taxonomy. For scenario generation, we
need to reach attack-level taxonomies:

- **OWASP Agentic AI Threats (T1–T17)**: attack-level threat enumeration with sub-scenarios
- **MITRE ATLAS techniques**: specific attack methods with maturity levels (Feasible / Demonstrated / Realized)

The existing SSSOM mappings in the policy-mapper bridge IBM Risk Atlas → OWASP LLM Top 10 and → NIST AI RMF categories.
No existing mappings reach the Agentic Threats or MITRE ATLAS techniques.

### 3.2 The three-hop chain

```
IBM Risk Atlas  ──[existing SSSOM]──▶  OWASP LLM Top 10
                                           │
                                     [new SSSOM, this component owns]
                                           │
                               ┌───────────┴───────────┐
                               ▼                       ▼
                    OWASP Agentic Threats       MITRE ATLAS techniques
                         (T1–T17)               (agent-focused subset)
```

### 3.3 Mapping feasibility

The LLM Top 10 → Agentic Threats and → ATLAS techniques mappings are **finite and curated**:

- ~80% of the mapping is deterministic (e.g. LLM03 → T17, LLM10 → T4, LLM04 → T1)
- ~20% depends on architectural preconditions — whether the target system has multi-agent topology, cascading execution
  paths, or human-in-the-loop dynamics
- These preconditions are binary flags, not fuzzy interpretation — they can be encoded as conditional rows in the
  mapping table

For MITRE ATLAS, ~25–30 techniques are relevant to LLM/agentic scenarios. Each LLM Top 10 entry maps to 2–4 ATLAS
techniques. The [GenAI Security Crosswalk](https://github.com/emmanuelgjr/GenAI-Security-Crosswalk) provides a
ready-made starting point, needing extension with the Oct 2025+ agent-focused techniques (~18 new techniques: context
poisoning, tool abuse, agent configuration modification, escape-to-host, etc.).

ATLAS is the more volatile axis (~18 techniques in 5 months), requiring periodic refresh, but the mapping remains a
curated lookup table, not a runtime inference problem.

### 3.4 Governance risk filtering

Many IBM Risk Atlas entries don't map to any ATLAS technique or agentic threat (e.g.
`atlas-generated-content-ownership`, `atlas-legal-accountability`). These are natural dead-ends in the mapping chain.
The scenario generator does not need upstream classification of risks as "governance vs. technical" — if a risk card
reaches the generator and the SSSOM chain produces no applicable agentic threats or ATLAS techniques, it is reported
as "governance-only, no red-teaming scenarios applicable" and skipped.

### 3.5 Ownership

This component owns the new SSSOM mappings (LLM Top 10 → Agentic Threats, LLM Top 10 → ATLAS techniques). The existing
mapping (IBM Risk Atlas → LLM Top 10) remains with the policy-mapper.

---

## 4. Capability profile

### 4.1 Purpose

The capability profile captures the structural properties of the system under assessment that determine which threat
families are in scope. It is derived from the use case description and is a **reviewable, editable artifact** — not
hidden inference.

### 4.2 Two-stage inference

**Stage 1 — Deterministic flags (always runs):**

Extract capability flags and entry points via lightweight NLP/LLM pass. Example output:

```yaml
capability_profile:
  zones_active: [ 1, 2, 3 ]        # Input, Reasoning, Tool Execution
  has_persistent_memory: false
  multi_agent: false
  hitl: true
  entry_points:
    - user prompts (zone 1)
    - RAG-retrieved documents (zone 1)
    - database query results (zone 3)
  confidence: medium              # how much the use case text supported these inferences
```

This alone is enough to filter the SSSOM chain and determine which threats are in scope.

**Stage 2 — LLM-inferred enrichment (configurable depth):**

Enriches the profile with tool types, data flows, trust boundaries, memory mechanisms — whatever the use case text
supports. Depth options:

| Depth        | Behavior                                                                                                |
|--------------|---------------------------------------------------------------------------------------------------------|
| **Minimal**  | Only extract what's explicitly stated in the text                                                       |
| **Moderate** | Infer likely components from domain context ("a customer service agent probably has CRM access")        |
| **Thorough** | Generate a Schneider-style zone map with hypothesized trust boundaries, data flows, and attack surfaces |

### 4.3 Design rationale

- Stage 1 output determines **scope** (which threats to generate scenarios for)
- Stage 2 output determines **specificity** (how concrete those scenarios are)
- A one-paragraph input produces correct scope with generic scenarios
- A detailed spec produces correct scope with highly specific scenarios
- Both stages produce reviewable artifacts — a human can correct inferences before scenario generation proceeds

---

## 5. Pipeline

```
┌──────────────┐     ┌────────────────────┐
│  Risk Cards  │     │  Use Case          │
│  (policy-    │     │  Description       │
│   mapper)    │     │  (free-form text)  │
└──────┬───────┘     └────────┬───────────┘
       │                      │
       │                      ▼
       │             ┌────────────────────┐
       │             │ 1. Capability      │
       │             │    Profile         │──▶ reviewable artifact
       │             │    Inference       │
       │             └────────┬───────────┘
       │                      │
       ▼                      ▼
┌─────────────────────────────────────────┐
│ 2. Threat Surface Determination         │
│    Risk Atlas ──[SSSOM]──▶ LLM Top 10   │
│    LLM Top 10 ──[SSSOM]──▶ Agentic T's  │
│    LLM Top 10 ──[SSSOM]──▶ ATLAS techs  │
│    filtered by capability profile       │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│ 3. Scenario Seed Expansion              │
│    For each in-scope threat:            │
│    enumerate sub-scenario templates     │
│    from taxonomy, filter by             │
│    capability profile                   │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│ 4. Scenario Generation                  │
│    For each seed: LLM follows           │
│    Schneider methodology to produce     │
│    multi-layered representation         │
│    (narrative + attack tree +           │
│     behavior spec + faceting metadata)  │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│ 5. Coverage Validation                  │
│    MAESTRO layers, ATLAS technique      │
│    coverage, threat family coverage     │
│    → gaps reported explicitly           │
└────────────────────┬────────────────────┘
                     │
                     ▼
            Faceted Scenario Collection
```

### 5.1 Stage 1: Capability Profile Inference

See §4. Produces a reviewable capability profile from the use case description.

### 5.2 Stage 2: Threat Surface Determination

Deterministic SSSOM chain walk. Walks the three-hop mapping (§3.2), applying capability profile flags as filters on
conditional mappings.

Output: a scoped list of (risk_card, owasp_llm_ids, agentic_threat_ids, atlas_technique_ids) tuples with full
provenance.

Risk cards that produce no downstream agentic threats or ATLAS techniques are classified as governance-only and excluded
from scenario generation.

### 5.3 Stage 3: Scenario Seed Expansion

For each in-scope threat, enumerates sub-scenario templates from the OWASP Agentic Threats taxonomy. The OWASP document
provides 3–6 sub-scenarios per threat (e.g. T2 Tool Misuse has 6: parameter pollution, tool chain manipulation,
automated abuse, hijacking via memory poisoning, hijacking via vector DB, hijacking via prompt injection).

Each sub-scenario template is filtered by the capability profile — e.g. "Agent Hijacking via Vector Database" only
applies if the system has a vector database.

All sub-scenarios that pass the filter are generated. No depth-based filtering at this stage — completeness is the goal.

### 5.4 Stage 4: Scenario Generation

The LLM's creative contribution: **contextualizing taxonomy-provided scenario templates for the specific use case**,
guided by Schneider's methodology.

The LLM does NOT invent attack categories from scratch. It grounds in existing taxonomy scenarios and:

1. Rewrites the generic OWASP scenario into a use-case-specific attack narrative
2. Walks the attack path through the inferred architecture (Schneider zones)
3. Generates the attack tree structure (AND/OR decomposition with control points)
4. Produces tool-neutral behavior specifications
5. Identifies control points and what-if alternatives
6. Computes structural exposure signals (single point of failure, convergence point, probabilistic control)

Schneider's 7-step methodology provides the discipline:

| Step                                   | Role in generation                      |
|----------------------------------------|-----------------------------------------|
| 1. Map architecture to zones           | Already done in capability profile (§4) |
| 2. Identify entry points per zone      | Already done in capability profile (§4) |
| 3. Walk attack scenarios through zones | Produces the **narrative layer**        |
| 4. Formalize into attack trees         | Produces the **attack tree layer**      |
| 5. Challenge controls with what-if     | Enriches tree with alternative paths    |
| 6. Validate coverage against MAESTRO   | Input to coverage validation (§5.5)     |
| 7. Validate against 4 agentic factors  | Agentic-specific quality check          |

**Decomposition into three LLM calls per scenario seed** (decided — see §9.6):

| Call | Input | Output | Schneider steps |
|------|-------|--------|-----------------|
| **Call 1: Narrative** | OWASP sub-scenario seed + capability profile + reframed causal chain | Zone-annotated attack prose | Step 3 |
| **Call 2: Attack tree** | Narrative + threat/technique IDs | AND/OR tree (YAML, structured output) | Step 4 |
| **Call 3: What-if + behavior spec** | Tree + capability profile | Enriched tree + behavior specs with multi-level success criteria | Step 5 |

The pipeline is **fully automated** — no human review gate between stages. Validation is structural (schema
conformance, valid taxonomy IDs, expected zones present), not judgmental. Failure modes become metadata
(`confidence: low`, generation notes) rather than exceptions. The causal chain from the risk card is reframed from
policy-voice to adversarial-voice within the Call 1 prompt instructions, not as a separate pipeline stage.

### 5.5 Stage 5: Coverage Validation

After all scenarios are generated, validate coverage across three dimensions:

- **MAESTRO layers**: Did we produce scenarios targeting risks at every architectural layer present in the system?
- **ATLAS technique coverage**: Which ATLAS techniques are exercised by at least one scenario? Which are in scope but
  uncovered?
- **Threat family coverage**: Which of the in-scope OWASP Agentic Threats have scenarios? Which were filtered at the
  sub-scenario level and why?

Gaps are reported explicitly, not silently ignored.

---

## 6. Scenario representation

### 6.1 Multi-layered structure

Each scenario is a multi-layered document serving different consumers:

| Layer                      | Format                                                                                      | Consumer                                 |
|----------------------------|---------------------------------------------------------------------------------------------|------------------------------------------|
| **Narrative**              | Schneider-style prose — human-readable attack path through zones                            | Human reviewers                          |
| **Attack tree**            | AND/OR decomposition with zone annotations, control points, OWASP/ATLAS references per node | Analysts, coverage tools                 |
| **Behavior specification** | Tool-neutral structured test specs (Gherkin or similar)                                     | Downstream tool adapters                 |
| **Faceting metadata**      | Structured fields for querying/filtering                                                    | Navigation, dashboards, coverage reports |

### 6.2 Tool-neutral design

The behavior specification layer is in a tool-neutral format. Translation to tool-specific formats (PyRIT attack
strategies, Garak probe configs, promptfoo test suites) is the responsibility of **adapters** outside this component.
The neutral format must be expressive enough to capture what all target tools need, without being specific to any one.

**Decided**: The behavior spec describes attack **shape**, not prompt text. It specifies structure ("a two-turn
escalation where turn 1 establishes a benign persona and turn 2 exploits the established trust to request a privileged
action") — the actual prompt text is crafted downstream by the execution tool or adapter, which knows the target
system's API, tone, and domain vocabulary. This makes specs more durable: prompt text ages fast as models are patched,
but attack shapes are stable patterns.

**Success criteria** are multi-level, with confidence signals:

| Level | Example | When it applies |
|-------|---------|-----------------|
| **Category** | `violation: unauthorized_tool_use` | Abstract scenarios, zone 1–2 only |
| **Behavioral** | "The agent invokes a tool not in the user's authorized set" | Zone 3 active |
| **Observable** | "The transfer_money tool is called with a destination account not matching the user's request" | Use case describes specific tools/data |
| **Stateful** | "The target account balance increases" | Zone 4 in scope, state model described |

The specificity level is a function of use case detail — Stage 1 capability profile supports category-level, Stage 2
enrichment enables observable/stateful when the text supports it. Each scenario carries success criteria at multiple
levels with confidence per level. The adapter picks the most specific level it can operationalize. Example:

```yaml
success_criteria:
  - level: category
    violation: unauthorized_tool_use
  - level: observable
    description: "The agent invokes transfer_money with a destination account not specified by the user"
    confidence: medium
  - level: stateful
    description: "The destination account balance increases"
    confidence: low
```

### 6.3 Faceting metadata

Each scenario carries structured metadata enabling queries across the collection:

**From the risk card:**

- `risk_id`, `risk_name`, `taxonomy` (IBM Risk Atlas)
- `confidence`, `grounding_confidence`

**From the taxonomy chain:**

- `owasp_llm_ids` (e.g. LLM01, LLM06)
- `agentic_threat_ids` (e.g. T2, T6)
- `atlas_technique_ids` (e.g. AML.T0051, AML.T0085)
- `scenario_seed` — which OWASP sub-scenario template seeded this scenario

**From the capability profile:**

- `zones_traversed` — ordered list encoding the attack propagation path through Schneider zones (e.g. `[1, 2, 3, 5]`)
- `architecture_match` — whether the scenario matches explicit or inferred capabilities
- `entry_point` — which entry point the attack uses

**From MAESTRO:**

- `maestro_layers` — which architectural layers are targeted

**Computed after generation:**

- Priority signals (see §7)

### 6.4 Queryability

The faceting model supports queries such as:

- "All scenarios traversing Zone 3 (Tool Execution)"
- "All scenarios for T2 (Tool Misuse)"
- "All scenarios targeting MAESTRO Layer 2 (Data Operations)"
- "Coverage: which threats have scenarios, which were filtered and why"
- "Highest-priority scenarios" (composite score sort)
- "Scenarios with Realized ATLAS techniques only"
- "All scenarios originating from risk card `atlas-hallucination`" (provenance tracing)
- "All scenarios executable by PyRIT" (requires adapter metadata)

---

## 7. Scenario prioritization

All relevant sub-scenarios are always generated (completeness). Prioritization is for human navigation, not filtering.

### 7.1 Priority signals

| Signal                  | Source                                                    | What it indicates                                                               |
|-------------------------|-----------------------------------------------------------|---------------------------------------------------------------------------------|
| **Technique maturity**  | MITRE ATLAS                                               | Feasible / Demonstrated / Realized — has this attack been observed in the wild? |
| **Risk impact**         | Risk card causal chain (`impact` field)                   | Severity of consequence if the attack succeeds                                  |
| **Risk likelihood**     | Risk card causal chain (`threat_source`, `vulnerability`) | How feasible and motivated is the attack                                        |
| **Attack complexity**   | Generated attack tree                                     | Number of steps, zones traversed, preconditions required                        |
| **Architecture match**  | Capability profile                                        | Explicit (stated in use case) vs. inferred (hypothesized by enrichment)         |
| **Structural exposure** | Generated attack tree                                     | Single point of failure, convergence point, probabilistic control               |

### 7.2 Composite score

A composite priority score enables default sort order. Individual signals are preserved as facets for custom filtering.

```yaml
priority:
  composite: 0.82
  signals:
    technique_maturity: realized
    risk_impact: high
    risk_likelihood: medium
    attack_complexity: low
    architecture_match: explicit
    structural_exposure: convergence_point
```

### 7.3 Structural exposure types

Derived from Schneider's node selection criteria (Part 2: micro simulations):

| Type                        | Definition                                                     | Why it matters                                                               |
|-----------------------------|----------------------------------------------------------------|------------------------------------------------------------------------------|
| **Single point of failure** | Only one control blocks the entire attack path                 | If that control fails, there's no backup                                     |
| **Convergence point**       | Multiple attack paths flow through one control                 | One test covers multiple attack vectors                                      |
| **Probabilistic control**   | Relies on an LLM guardrail or classifier, not binary pass/fail | Needs repeated probing to establish bypass rates                             |
| **Defense-in-depth claim**  | Multiple controls ostensibly back each other up                | Must verify the backup catches what the primary *misses*, not the same class |

---

## 8. What this system does NOT do

- **Execute scenarios**: Downstream tooling (PyRIT, Garak, promptfoo) executes. This system produces the specifications.
- **Classify risks as governance vs. technical**: The mapping chain handles this implicitly — no downstream mapping = no
  scenarios.
- **Require structured architecture input**: Works with free-text, degrades gracefully.
- **Invent attack categories**: Grounds all scenarios in taxonomy-provided seeds. Every generated scenario traces to a
  specific OWASP sub-scenario template.
- **Filter scenarios by depth**: All relevant sub-scenarios are generated. Prioritization is for navigation, not
  exclusion.
- **Generate scenarios where a correct control action fails to take effect**: A controller that issues the right
  action, which is then not carried out or does not prevent the harm, is a failure downstream of the controller, not an
  unsafe control action. The ICA hazard verifier reports such a finding's action state as `performed_without_effect`;
  code rejects it as `contradictory` with the rejection reason `correct_action_without_effect`, gives it no correction
  round, and the finding stops at `ica_hazard_correct_action_without_effect`. It is never accepted as
  `performed_unsafe`.

---

## 9. Design decisions and open questions

### Resolved

#### 9.1 Attack tree format — RESOLVED

- **Format**: Pure AND/OR tree in YAML. Nodes carry zone annotation, threat/technique IDs, MAESTRO layer, control
  point, and structural exposure type as metadata. Evidence level (assumed / design-reviewed / lab-validated /
  end-to-end validated / regression-tested) included per node — for generated scenarios most will be "assumed" until
  execution.
- **Granularity**: 3–5 levels per Schneider's examples. Deeper structure is emergent from what-if enrichment (Call 3).
- **Cross-zone propagation**: Encoded as an ordered `zones_traversed` list on the scenario, not in the tree structure.
  The tree stays a pure logical decomposition (AND/OR gates); the path captures temporal/spatial structure separately.

#### 9.2 Cross-zone attack chains — RESOLVED (falls out of §9.1)

A multi-zone attack chain is an attack tree whose nodes span multiple zones, with the propagation path recorded
separately as `zones_traversed: [1, 2, 3, 5]` (ordered). No dedicated chain-of-scenarios model needed. Cross-zone
chains emerge naturally from Schneider's zone-walking step (Call 1), not from explicit combination of single-zone
scenarios.

#### 9.4 Behavior specification format — RESOLVED

- **Shape, not content**: Specs describe attack structure ("two-turn escalation where turn 1 establishes trust, turn 2
  exploits it"), not prompt text. Prompt crafting is the adapter's / execution tool's responsibility.
- **Multi-level success criteria** with confidence signals per level (category → behavioral → observable → stateful).
  Specificity determined by use case detail. Adapter picks the most specific level it can operationalize.
- See §6.2 for full detail and examples.

#### 9.6 Scenario generation methodology — RESOLVED

- **Three decomposed LLM calls** per scenario seed: Call 1 (narrative), Call 2 (attack tree), Call 3 (what-if +
  behavior spec). See §5.4 for detail.
- **Fully automated pipeline** — no human review gate. Validation is structural (schema conformance, valid taxonomy
  IDs, expected zones). Failures become metadata, not exceptions.
- **Causal chain reframing** from policy-voice to adversarial-voice handled via prompt instructions in Call 1, not a
  separate pipeline stage.
- **Methodology compliance** validated structurally: Call 1 must annotate with zones, Call 2 must produce a tree with
  valid threat/technique IDs per node, Call 3 must produce behavior specs conforming to the schema. Non-compliance is
  structurally detectable. Whether scenarios are *meaningful* (not just valid) is surfaced via the what-if enrichment
  and priority signals, not as a pipeline gate.

### Open (non-blocking)

#### 9.3 Versioning and diffing

If policies change and risk cards are re-extracted, the scenario collection should support diff:

- **Stable scenario identifiers**: What makes a scenario the "same" across regeneration runs? The (risk_id, threat_id,
  sub-scenario_seed) tuple? This would survive regeneration if the taxonomy chain is stable, but the generated content
  would differ.
- **Structural diff**: New scenarios, removed scenarios, scenarios whose priority signals changed.
- **Provenance chain**: Can we trace from a changed policy clause → changed risk card → changed scenario?

#### 9.5 SSSOM mapping maintenance

The new SSSOM mappings (LLM Top 10 → Agentic Threats, LLM Top 10 → ATLAS techniques) need a maintenance model:

- ATLAS is volatile (~18 techniques in 5 months). How often should mappings be refreshed?
- Who validates mapping correctness? Is there a process for incorporating new OWASP or ATLAS releases?
- Should the mapping include the conditional/architectural flags directly in SSSOM format, or as a separate overlay?

#### 9.7 Scale and cost

For a typical policy extraction producing 20–30 risk cards:

- How many scenarios does the pipeline produce? (Rough estimate: 20 risks × 3 applicable threats × 4 sub-scenarios × 0.6
  capability filter = ~144 scenarios)
- What is the LLM cost per scenario (now 3 calls per seed, not 1)?
- Batch generation is feasible — capability profile inference runs once, not per scenario. No interactive review gate.
