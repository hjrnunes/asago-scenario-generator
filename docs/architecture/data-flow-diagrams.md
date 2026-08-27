# Asago Scenario Generator Data Flow Diagrams

## 1. End-to-End Pipeline Overview

```mermaid
flowchart LR
    subgraph Inputs["INPUTS"]
        direction TB
        useCase["use-case.txt<br>(plain text)"]
        riskExtraction["risk-extraction.json<br>(from policy-mapper)"]
        sssomTsv["*.sssom.tsv<br>(taxonomy mappings)"]
        crossTaxonomy["cross-taxonomy-mappings.yaml"]
        refData["OWASP / ATLAS / NIST<br>(reference data)"]
        kcMapping["kc-threat-mapping.yaml"]
        attackGoalsFile["attack-goals.json +<br>threat-goal-affinity.yaml"]
    end

    subgraph Pipeline["PIPELINE"]
        direction TB
        stage1["Stage 1: Capability Profiling<br>(1 LLM call)<br>infer_capability_profile()"]
        stage2["Stage 2: Threat Surface<br>(deterministic, no LLM)<br>3-hop taxonomy chain"]
        stage3["Stage 3: Scenario Seeds<br>(deterministic, no LLM)<br>Expand attack patterns"]
        stage35["Stage 3.5: Candidate Filtering<br>(1 LLM call per seed)<br>expand + filter candidates"]
        goalSelect["Attack Goal Selection<br>(deterministic, per seed)"]
        stage4["Stage 4: Scenario Generation<br>(4 LLM calls per seed)"]
        postPipeline["Post: Coverage & Eval<br>(deterministic)"]
        done(["DONE"])
        stage1 -->|CapabilityProfile| stage2
        stage2 -->|ThreatSurface| stage3
        stage3 -->|ScenarioSeeds| stage35
        stage35 -->|FilteredSeeds| goalSelect
        goalSelect --> stage4
        stage4 -->|ScenarioEnvelopes| postPipeline
        postPipeline --> done
    end

    subgraph Outputs["OUTPUTS"]
        direction TB
        capProfile["capability-profile.yaml"]
        threatSurface["threat-surface.yaml"]
        seedsList["in-memory seeds list"]
        filteredSeeds["in-memory filtered seeds"]
        scenarioFiles["scenarios/*.yaml + *.feature<br>run-manifest.yaml"]
        postOutputs["coverage-gaps.json<br>eval-scorecard.yaml<br>report.html"]
    end

    useCase --> stage1
    riskExtraction --> stage2
    sssomTsv --> stage3
    crossTaxonomy --> stage3
    refData --> stage35
    kcMapping --> stage4
    attackGoalsFile --> goalSelect

    stage1 --> capProfile
    stage2 --> threatSurface
    stage3 --> seedsList
    stage35 --> filteredSeeds
    stage4 --> scenarioFiles
    postPipeline --> postOutputs
```

**Output details per stage:**

| Stage | Output File | Key Fields |
|-------|-------------|------------|
| Stage 1 | `capability-profile.yaml` | `zones_active: [input, reasoning]`, `has_persistent_memory: false`, `multi_agent: false`, `kc_subcodes: [KC1.1, KC3.3]`, `entry_points: [...]` |
| Stage 2 | `threat-surface.yaml` | `entries:` each with `risk_card`, `owasp_llm_ids: [LLM09]`, `agentic_threat_ids: [T7]`, `attack_pattern_ids: [AP-T7-01]` |
| Stage 3 | (in-memory) | `[ScenarioSeed(AP-T7-01), ScenarioSeed(AP-T15-01), ...]` |
| Stage 3.5 | (in-memory) | `[FilteredSeed(AP-T7-01, entry_point=..., technique_ids=...), ...]` |
| Stage 4 | `scenarios/AP-T7-01-f088b5.yaml` + `.feature` | One YAML + Gherkin pair per seed; `run-manifest.yaml` for pipeline metadata |
| Post | `coverage-gaps.json`, `eval-scorecard.yaml`, `report.html` | Coverage analysis, quality scores, HTML report |

---

## 2. Input Data Sources

| Source | Format | Example Content |
|--------|--------|-----------------|
| **use-case.txt** (user-provided) | `.txt` | `"A stateless LLM-powered customer service chatbot for an eBay-like marketplace. No memory, no tool access, no state."` |
| **risk-extraction** (from policy-mapper tool) | `.json` | `[{"risk_id": "atlas-hallucination", "risk_name": "Hallucination", "confidence": 0.809, "threat": "AI may generate inaccurate...", "vulnerability": "Lack of groundedness...", "consequence": "Untruthful content...", "impact": "Negative impacts on..."}]` |
| **SSSOM mappings** `data/taxonomies/attack-patterns/*.sssom.tsv` | `.tsv` | `AP-T1-01  asago-scenario-generator  skos:exactMatch  T1-S1  owasp-agentic` / `AP-T1-01  asago-scenario-generator  skos:relatedMatch  AML.T0020  mitre-atlas` |
| **Cross-taxonomy mappings** `data/taxonomies/mappings/` | `.yaml` | `t_to_asi:` `- source: T1, target: ASI06, predicate: exact_match, confidence: 1.0` |
| **OWASP LLM Top 10** `data/taxonomies/owasp-llm-top10/LLM{01-10}.json` | `.json` | `{"id": "LLM01", "name": "Prompt Injection", "severity": "Critical", "mappings": [{framework: "MITRE ATLAS", control_id: "AML.T0051.000"}...]}` |
| **OWASP Agentic Threats v1.1** `data/taxonomies/owasp-agentic-threats/` | `.yaml` | `threats:` `T7: {name: "Misaligned & Deceptive Behavior", attack_patterns: [AP-T7-01, AP-T7-02, ...]}` |
| **Attack Patterns** `data/taxonomies/attack-patterns/attack-patterns.yaml` | `.yaml` | `patterns:` `AP-T7-01: {threat_id: T7, name: "Constraint bypass via goal-priority conflict", prerequisite_capabilities: {min_zones: [input, reasoning], kc_requires: {any: [KC1.1, KC1.2, KC1.3, KC1.4]}}}` |
| **MITRE ATLAS** `data/taxonomies/atlas/` | `.yaml` | `techniques:` `AML.T0051: {name: "LLM Prompt Injection", tactic: "Initial Access"}` |
| **NIST AI 100-2** `data/taxonomies/nist-ai-100-2/` | `.yaml` | `classification_dimensions:` `- dimension: attacker_goal, values: [integrity, availability, confidentiality, abuse]` |
| **KC Threat Mapping** `data/taxonomies/mappings/kc-threat-mapping.yaml` | `.yaml` | `kc_to_threats: {KC1.1: [T5, T6, T7, T15], KC2.1: [T6, T8], KC4.3: [T1, T5, T6, T8], KC6.1.2: [T2, T3, T4, T9]}` / `threat_to_kc_subcodes: {T1: [KC4.3, KC4.4, KC4.5, ...]}` / `hitl: {threat_ids: [T10]}` |
| **Attack Goals** `data/taxonomies/attack-goals/attack-goals.json` | `.json` | `categories:` `- {id: "availability", name: "Availability Disruption", sub_goals: [{id: "AV-1", name: "Service Denial"}, ...]}` |
| **Threat-Goal Affinity Map** `data/taxonomies/attack-goals/threat-goal-affinity.yaml` | `.yaml` | `affinities: {T1: {primary: [integrity], secondary: [privacy, abuse], excluded: [availability]}}` |

---

## 3. Stage 2: Three-Hop Taxonomy Chain (Deterministic)

```mermaid
flowchart TD
    subgraph InputSources["Input Sources"]
        riskJson["risk-extraction.json<br>risk_id: atlas-halluc..."]
        sssomFiles["SSSOM .tsv files<br>AP-T7-01 --> T7-S1<br>AP-T1-01 --> AML.T0020"]
        crossTaxonomy["cross-taxonomy-mappings.yaml<br>T1 --> ASI06, T7 --> ASI07<br>LLM01 --> AML.T0051"]
        kcMapping["kc-threat-mapping.yaml<br>KC1.1 --> T5,T6,...<br>KC4.3 --> T1,T5,..."]
    end

    subgraph HopChain["Three-Hop Chain"]
        hop1["HOP 1: Risk Atlas ID --> OWASP LLM Top 10 IDs<br>e.g. atlas-hallucination --> LLM09, LLM02<br>(via SSSOM + risk_card mappings)"]
        hop2["HOP 2: OWASP LLM IDs --> OWASP Agentic Threat IDs<br>e.g. LLM09, LLM02 --> T15, T7, T8<br>(via cross-taxonomy-mappings.yaml)"]
        hop3["HOP 3: Agentic Threats --> Filtered by KC sub-codes<br>e.g. T15, T7, T8 --> T15, T7, T8 ✓<br>(via threat_gating.py + kc-threat-mapping.yaml)"]
        directPath["DIRECT PATH: agentic-only threats T7-T10, T14-T16<br>bypasses LLM hop, KC sub-code filter only"]
        hop1 --> hop2
        hop2 --> hop3
    end

    subgraph Resolution["Pattern & Technique Resolution"]
        inScope["In-scope T-threats"]
        apResolve["ATTACK PATTERNS: T-threats --> AP-* IDs<br>per-AP kc_requires gate checked<br>against profile.kc_subcodes"]
        atlasResolve["ATLAS TECHNIQUES: T-threats --> ATLAS IDs<br>via t_to_atlas in cross-taxonomy<br>zone-3-gated if tool_execution not active"]
        inScope --> apResolve
        inScope --> atlasResolve
    end

    riskJson --> hop1
    sssomFiles --> hop1
    crossTaxonomy --> hop2
    kcMapping --> hop3
    hop3 --> inScope
    directPath --> inScope

    apResolve --> threatSurfaceOut
    atlasResolve --> threatSurfaceOut

    threatSurfaceOut["threat-surface.yaml<br>entries: risk_card, owasp_llm_ids,<br>agentic_threat_ids, attack_pattern_ids,<br>atlas_technique_ids"]
```

**Notes on the hop chain:**

- A threat is in scope if ANY of the profile's `kc_subcodes` maps to it in `kc_to_threats`
- HITL (T10) is cross-cutting, enabled by `profile.hitl`
- `min_zones` is still present in data but no longer checked in code -- `kc_requires` subsumes it
- Per-AP `kc_requires` gate: `{any: [...], all: [...]}` checked against `profile.kc_subcodes`

---

## 3b. Stage 3.5: Candidate Expansion + Filtering

```mermaid
flowchart TD
    subgraph CandidateInputs["Inputs"]
        scenarioSeeds["ScenarioSeeds (from Stage 3)<br>ScenarioSeed(AP-T7-01),<br>ScenarioSeed(AP-T15-01), ..."]
        capProfile["CapabilityProfile (from Stage 1)<br>entry_points, zones_active,<br>kc_subcodes"]
    end

    subgraph Processing["Candidate Pipeline"]
        step1["Step 1: expand_candidates() — deterministic<br>Cross-product: seed x entry_point x ATLAS_technique_combo<br>e.g. 5 seeds x 4 entry_points x 2 techniques = 40 CandidateTriples<br>(max_techniques controls combo size: 1=singles, 2=pairs too)"]
        step2["Step 2: filter_candidates() — 1 LLM call per seed, parallelized<br>Renders filter_system.j2 + filter_user.j2 per seed<br>Prompt includes: use_case, profile, attack_pattern, candidate list<br>LLM returns: BatchFilterResponse with per-candidate accept/reject + rationale"]
        step3["Step 3: Build FilteredSeed objects from accepted verdicts<br>Each carries pinned_entry_point, pinned_technique_ids,<br>pinned_technique_names, rejection_rationales (provenance)"]
        step1 --> step2
        step2 --> step3
    end

    scenarioSeeds --> step1
    capProfile --> step1

    step3 --> filteredOutput

    filteredOutput["FilteredSeed output<br>seed_id: AP-T7-01<br>pinned_entry_point: user chat input<br>pinned_technique_ids: (AML.T0051,)<br>pinned_technique_names: (LLM Prompt Injection,)<br>rejection_rationales: ..."]

    filteredOutput -.->|"Hard constraints<br>for Stage 4"| stage4["Stage 4 Generation"]
```

---

## 4. Attack Goal Selection (Deterministic, per Seed)

```mermaid
flowchart TD
    subgraph GoalInputs["Inputs"]
        attackGoals["attack-goals.json<br>categories: availability, integrity,<br>privacy, abuse<br>sub_goals: AV-1, AV-2, IN-1, ..."]
        affinityMap["threat-goal-affinity.yaml<br>T1: primary=[integrity],<br>  secondary=[privacy, abuse],<br>  excluded=[availability]<br>T7: primary=[integrity, abuse], ..."]
    end

    subgraph Selection["Selection Process"]
        loadGoals["Step 1: get_all_sub_goals(taxonomy)<br>Flatten categories --> sub-goals<br>Augment with category_id, category_name,<br>category_description"]
        filterZones["Step 2: filter_sub_goals_by_zones()<br>Zone-gated goals removed:<br>AV-5 needs inter_agent<br>IN-5 needs persistent memory<br>PR-5 needs persistent memory<br>AB-7 needs multi_agent<br>...etc (see _GOAL_ZONE_REQUIREMENTS)"]
        perSeed["Step 3: Per-seed selection<br>select_attack_goal(available_goals,<br>usage_counts, total_seeds, threat_id)"]
        affinityPath["Step 3a: Affinity-aware path<br>(when threat_id in affinity map)<br>Load affinity: primary_cats, excluded_cats<br>Remove excluded-category goals<br>Partition into primary_pool / secondary_pool<br>Fair-share ceiling = ceil(total_seeds / n_primary)<br>Pick least-used from primary_pool<br>Fallback to secondary then full pool"]
        fallbackPath["Step 3b: Affinity-unaware fallback<br>_fair_share_pick(sub_goals, usage_counts)<br>Pick least-used sub-goal,<br>ties broken randomly"]

        loadGoals --> filterZones
        filterZones --> perSeed
        perSeed --> affinityPath
        perSeed --> fallbackPath
    end

    attackGoals --> loadGoals
    affinityMap --> affinityPath

    affinityPath --> selectedGoal
    fallbackPath --> selectedGoal

    selectedGoal["Selected sub-goal<br>id: IN-3<br>name: Decision Corruption<br>category_id: integrity<br>category_name: Integrity Violation<br>--> Passed to generate_scenario()"]
```

---

## 5. Stage 4: Per-Seed LLM Generation (4 Calls)

```mermaid
flowchart TD
    subgraph GenInputs["Inputs"]
        seed["ScenarioSeed<br>seed_id: AP-T7-01, threat_id: T7<br>attack_pattern_name, risk_card_ref,<br>owasp_llm_ids, agentic_threat_ids,<br>atlas_technique_ids, owasp_origin,<br>laaf_technique_ids, atlas_provenance_ids"]
        attackGoal["Selected Attack Goal<br>id: IN-3<br>name: Decision Corruption<br>category_id: integrity"]
    end

    subgraph Call0["CALL 0: Actor Profile"]
        call0Prompt["System: red-team persona generator<br>User: seed context + threat + use-case<br>+ profile.zones_active + kc_subcodes<br>+ entry_points + attack_goal context<br>+ actor type diversity hints<br>+ ATLAS technique context<br>Structured output (Pydantic)"]
        call0Out["ActorProfile<br>actor_type: nation-state<br>capability_level: intermediate<br>beliefs, desires, intentions<br>resources, goal_category: IN-3<br>goal_category_name, goal_category_parent"]
        call0Prompt --> call0Out
    end

    subgraph Call1["CALL 1: Narrative"]
        call1Prompt["System: red-team scenario writer<br>User: actor_profile + seed context<br>+ zones_active + kc_subcodes<br>+ entry point diversity hints<br>+ pattern exclusions<br>+ ATLAS technique context<br>Structured output (Pydantic)"]
        call1Out["NarrativeLayer<br>title: Subverting Class...<br>entry_point: user prompts...<br>zone_sequence: input, reasoning<br>steps with zone + action +<br>control_point annotations"]
        call1Prompt --> call1Out
    end

    subgraph Call2["CALL 2: Attack Tree"]
        call2Prompt["System: Produce a YAML attack tree<br>User: narrative steps + threat IDs<br>+ technique IDs + actor_profile<br>Unstructured text output<br>(parsed as YAML post-hoc)"]
        call2Out["AttackTree<br>goal: Generate deceptive...<br>root: id=n1, gate=AND<br>  children: id=n1.1, gate=OR<br>    children: LEAF nodes"]
        call2Prompt --> call2Out
    end

    subgraph Call3["CALL 3: Behavior Spec"]
        call3Prompt["System: Write a Gherkin feature file<br>User: narrative + attack_tree summary<br>+ use-case<br>Unstructured text output"]
        call3Out["Raw Gherkin text<br>@id:AP-T7-01-f088b5<br>Feature: Subverting Class...<br>  Background: Given access to Zone 1<br>  Scenario: When attacker submits..."]
        call3Prompt --> call3Out
    end

    seed --> call0Prompt
    attackGoal --> call0Prompt
    call0Out --> call1Prompt
    call1Out --> call2Prompt
    call2Out --> call3Prompt

    call3Out --> envelope

    envelope["ScenarioEnvelope (assembled)<br>scenario_id: AP-T7-01-f088b5<br>actor_profile, narrative, attack_tree, behavior_spec<br>scenario_seed_metadata, faceting, priority, generation<br>--> Written to: scenarios/AP-T7-01-f088b5.yaml<br>--> Written to: scenarios/AP-T7-01-f088b5.feature"]
```

**Generation metadata per call:**

| Call | Function | Typical Tokens (in/out) |
|------|----------|------------------------|
| Call 0 | `_call_actor_profile()` | ~950 / ~320 |
| Call 1 | `_call_narrative()` | ~2000 / ~640 |
| Call 2 | `_call_attack_tree()` | ~1140 / ~675 |
| Call 3 | `_call_behavior_spec()` | ~1490 / ~390 |

---

## 6. Complete Data Lineage (File-Level)

```mermaid
flowchart TD
    subgraph UserFiles["USER-PROVIDED FILES"]
        useCaseFile["use-case.txt"]
        riskFile["risk-extraction.json"]
        sssomFile["*.sssom.tsv"]
    end

    subgraph BundledData["BUNDLED REFERENCE DATA"]
        agenticThreats["owasp-agentic-threats/*-v1.1.yaml"]
        llmTop10["owasp-llm-top10/LLM01-10.json"]
        agenticTop10["owasp-agentic-top10/ASI01-10.json"]
        atlas["atlas/ATLAS-2026.05.yaml"]
        nist["nist-ai-100-2/nist-ai-100-2e2023.yaml"]
        attackPatterns["attack-patterns/attack-patterns.yaml + *.sssom.tsv"]
        attackGoalsData["attack-goals/attack-goals.json + threat-goal-affinity.yaml"]
        mappings["mappings/cross-taxonomy-mappings.yaml + kc-threat-mapping.yaml"]
    end

    loaders["loaders.py<br>(data loading)"]
    runner["runner.py<br>(pipeline orchestrator)"]

    agenticThreats --> loaders
    llmTop10 --> loaders
    agenticTop10 --> loaders
    atlas --> loaders
    nist --> loaders
    attackPatterns --> loaders
    attackGoalsData --> loaders
    mappings --> loaders

    useCaseFile --> runner
    riskFile --> runner
    sssomFile --> runner
    loaders --> runner

    subgraph PipelineStages["PIPELINE STAGES"]
        manifest_start["Run Manifest (start)<br>write run-manifest.yaml"]
        stg1["Stage 1 (profile.py)<br>1 LLM call"]
        stg2["Stage 2 (threats.py)<br>deterministic"]
        stg3["Stage 3 (seeds.py)<br>deterministic, in-memory"]
        stg35["Stage 3.5 (candidates.py)<br>1 LLM call per seed<br>expand + filter candidates"]
        goalSel["Attack Goal Selection<br>deterministic, per seed, in-memory"]
        stg4["Stage 4 (generate.py)<br>4 LLM calls x N seeds"]
        postStage["Post-pipeline"]
        manifest_start --> stg1
        stg1 --> stg2
        stg2 --> stg3
        stg3 --> stg35
        stg35 --> goalSel
        goalSel --> stg4
        stg4 --> postStage
    end

    runner --> manifest_start

    subgraph PostSteps["Post-pipeline Steps"]
        coverage["coverage.py (deterministic)"]
        evalRunner["eval/runner.py (deterministic)"]
        reportGen["report/generator.py (deterministic)"]
        manifestUpdate["Run Manifest update<br>(end timestamp, counts)"]
    end

    postStage --> coverage
    postStage --> evalRunner
    postStage --> reportGen
    postStage --> manifestUpdate
```

**Output directory structure:**

```
output/{name}/
├── run-manifest.yaml       (input hashes, model config, prompt template hashes)
├── use-case.txt
├── capability-profile.yaml
├── threat-surface.yaml
├── scenarios/
│   ├── AP-T7-01-f088b5.yaml
│   ├── AP-T7-01-f088b5.feature
│   ├── AP-T15-01-16cf51.yaml
│   ├── AP-T15-01-16cf51.feature
│   ├── calls.jsonl
│   └── ... (one pair per seed)
├── coverage-gaps.json
├── eval-scorecard.yaml
└── report.html
```

---

## 7. Diversity Enforcement (Batch-Level)

The runner tracks 6 diversity dimensions across the batch via Counters:

| Dimension | Counter | Strategy |
|-----------|---------|----------|
| **Entry Points** | `entry_point_usage` | `assign_entry_point()`: affinity score (keyword-to-zone Jaccard overlap) minus overuse penalty. `get_overused_entry_points()` builds exclude list. |
| **Attack Patterns** | `pattern_usage` | `extract_narrative_keywords()`: NLP keyword extraction from narrative. `get_overused_patterns()` builds exclude list to avoid repetitive attack techniques. |
| **Structural Patterns** | `structural_usage` | `extract_structural_pattern()`: phase-sequence hash (e.g. "inject->hallucinate->persist->bypass"). `get_overused_structural_patterns()` builds excludes. |
| **Actor Types** | `actor_type_usage` | Fair-share ceiling = `ceil(total_seeds / num_types)`. Least-used type preferred, overused types excluded. |
| **Capability Levels** | `capability_level_usage` | Least-used level preferred (hint, not enforced). 4 levels: novice, intermediate, advanced, expert. |
| **Attack Goals** | `goal_usage` | `select_attack_goal()`: affinity-aware fair-share. Primary affinity preferred, secondary fallback, excluded categories removed. See Section 4 above. |

All diversity hints are injected into LLM prompts as guidance. The LLM may deviate; actual generated values are tracked for subsequent seeds.

---

## 8. LLM Call Summary

| Stage | Function | Output Format | Typical Tokens (in/out) |
|-------|----------|---------------|------------------------|
| Stage 1 | `infer_capability_profile()` | Structured (Stage1Profile) | ~500 / ~100 |
| Stage 3.5 | `filter_candidates()` (1 call per seed) | Structured (BatchFilterResponse) | varies per seed (depends on candidate count) |
| Stage 4, Call 0 | `_call_actor_profile()` | Structured (ActorProfile) | ~950 / ~320 |
| Stage 4, Call 1 | `_call_narrative()` | Structured (NarrativeLayer) | ~2000 / ~640 |
| Stage 4, Call 2 | `_call_attack_tree()` | Unstructured (raw YAML text) | ~1140 / ~675 |
| Stage 4, Call 3 | `_call_behavior_spec()` | Unstructured (raw Gherkin text) | ~1490 / ~390 |
| **TOTAL** | 1 + N_seeds(filter) + 4 x N_filtered_seeds | | ~6k in + ~2k out per seed + filter + profiling calls |

**LLM Client Config:**

| Setting | Environment Variable | Default |
|---------|---------------------|---------|
| Base URL | `ASAGO_SCENARIO_GENERATOR_MODEL_BASE_URL` | (OpenAI-compatible endpoint) |
| API Key | `ASAGO_SCENARIO_GENERATOR_API_KEY` | — |
| Model | `ASAGO_SCENARIO_GENERATOR_MODEL_NAME` | `gemma-3n-e4b-it` |
| Max Tokens | `ASAGO_SCENARIO_GENERATOR_MAX_COMPLETION_TOKENS` | (optional) |
| Temperature | `ASAGO_SCENARIO_GENERATOR_TEMPERATURE` | `0.4` |
| Top P | `ASAGO_SCENARIO_GENERATOR_TOP_P` | (optional) |
| Top K | `ASAGO_SCENARIO_GENERATOR_TOP_K` | (optional) |
| Guided decoding | `ASAGO_SCENARIO_GENERATOR_USE_GUIDED_DECODING` | `false` |
| Request timeout | `ASAGO_SCENARIO_GENERATOR_TIMEOUT` | `300` seconds |

- **Structured calls:** `openai.beta.chat.completions.parse(response_format=PydanticModel)`
- **Unstructured calls:** `openai.chat.completions.create()` returning raw text
- **Transport retries:** disabled; pipeline-owned retries are explicit and logged

---

## 9. Schneider 5-Zone Model (Referenced Throughout)

```mermaid
flowchart TD
    subgraph ZoneModel["AI SYSTEM ZONES"]
        zone1["Zone 1: INPUT<br>User prompts, API inputs, data uploads"]
        zone2["Zone 2: REASONING<br>LLM planning, inference, decisions"]
        zone3["Zone 3: TOOL EXECUTION<br>External API calls, tool invocations"]
        zone4["Zone 4: MEMORY<br>Session state, persistent storage, KBs"]
        zone5["Zone 5: INTER-AGENT<br>Multi-agent communication, coordination"]
        zone1 --> zone2
        zone2 --> zone3
        zone3 --> zone4
        zone4 --> zone5
    end
```

The capability profile determines which zones are active (e.g. a stateless chatbot only has zones `[input, reasoning]`). Stage 4 narratives and attack trees annotate every step/node with its zone. The eval scorecard checks zone alignment across all layers.

**KC Sub-Codes:** 27 granular capabilities (KC1.1-KC6.7) decompose what the system can do WITHIN each zone. They are inferred by Stage 1, stored in the capability profile as `kc_subcodes`, and used by:

- **threat_gating.py:** KC sub-codes determine which threats are in scope (via kc-threat-mapping.yaml: KC --> T-threats)
- **_evaluate_prerequisite_capabilities():** per-AP `kc_requires` gate checks `{any: [...], all: [...]}` against profile
- **LLM prompts (Calls 0-1):** passed as "System capabilities (KC sub-codes)" so the LLM constrains scenarios to actual system capabilities
- **filter_system.j2:** candidate filter prompt includes KC sub-codes for plausibility judgment

---

## 10. Run Manifest

Written at pipeline start; updated at pipeline end.

```yaml
# run-manifest.yaml (runner.py)
version: "0.1.0"                      # asago-scenario-generator package ver
timestamp_start: "2026-07-06T..."     # pipeline start time
timestamp_end: "2026-07-06T..."       # pipeline end time (added)

inputs:
  use_case_hash: "sha256:..."         # SHA-256 of use-case.txt
  risk_extraction_hash: "sha256:..."  # SHA-256 of risk-extraction
  sssom_hash: "sha256:..."            # SHA-256 of SSSOM TSV

config:
  model: "gemma-3n-e4b-it"            # LLM model name
  temperature: 0.7                    # sampling temperature
  max_completion_tokens: null         # token limit (or null)
  prompt_template_hashes:             # SHA-256 per template file
    profile_system.j2: "sha256:..."
    profile_user.j2: "sha256:..."
    filter_system.j2: "sha256:..."
    filter_user.j2: "sha256:..."
    call0_system.j2: "sha256:..."
    call0_user.j2: "sha256:..."
    call1_system.j2: "sha256:..."
    call1_user.j2: "sha256:..."
    # ...

seeds_generated: 12                   # total seeds expanded
candidates_expanded: 48               # total candidates generated
candidates_accepted: 10               # candidates passing filter
candidates_rejected: 38               # candidates rejected
scenarios_generated: 10               # successful scenario count
scenarios_failed: 2                   # failed generation count
```

Purpose: Reproducibility and provenance. Enables diffing runs by comparing input hashes and model configuration.

---

## 11. Post-Pipeline Data Flows

```mermaid
flowchart LR
    subgraph ScenarioInputs["Scenario Artifacts"]
        scenarioYamls["All scenario YAMLs<br>in output/*/scenarios/"]
        capProfile["capability-profile.yaml"]
    end

    coveragePy["coverage.py<br>(gap analysis)"]

    scenarioYamls --> coveragePy
    capProfile --> coveragePy

    coveragePy --> coverageGaps

    coverageGaps["coverage-gaps.json<br>uncovered_entry_points, uncovered_zones<br>attacker_diversity:<br>  model_counts, dominant_fraction"]
```

**Coverage Remediation Pass (runner.py):** If `uncovered_entry_points` exist after initial generation, `_remediate_coverage_gaps()` runs additional seeds to fill gaps.

```mermaid
flowchart LR
    subgraph EvalInputs["Eval Inputs"]
        scenarioYamls2["All scenario YAMLs<br>(narratives, attack_trees,<br>zone_sequences)"]
        featureFiles["All .feature files"]
        capProfile2["capability-profile.yaml"]
    end

    evalRunner["eval/runner.py"]

    scenarioYamls2 --> evalRunner
    featureFiles --> evalRunner
    capProfile2 --> evalRunner

    evalRunner --> scorecard

    scorecard["eval-scorecard.yaml<br>scenario_count, consistency mean,<br>gherkin parse_success"]

    subgraph EvalModules["Eval Modules"]
        consistency["consistency.py<br>(zone alignment, step-node match)"]
        diversity["diversity.py<br>(attacker type spread)"]
        gherkin["gherkin.py<br>(parse validation)"]
        grounding["grounding.py<br>(taxonomy grounding)"]
        plausibility["plausibility.py<br>(structural plausibility)"]
    end

    evalRunner --> consistency
    evalRunner --> diversity
    evalRunner --> gherkin
    evalRunner --> grounding
    evalRunner --> plausibility
```

---

## 12. Report Generation Data Flow

`report/generator.py: generate_report(output_dir)`

```mermaid
flowchart TD
    subgraph ReportInputs["Artifacts Read from Disk"]
        rpCapProfile["capability-profile.yaml"]
        rpThreatSurface["threat-surface.yaml"]
        rpScenarioYaml["scenarios/*.yaml"]
        rpFeatureFiles["scenarios/*.feature"]
        rpCallsJsonl["scenarios/calls.jsonl"]
        rpCoverageGaps["coverage-gaps.json"]
        rpEvalScorecard["eval-scorecard.yaml"]
        rpUseCase["use-case.txt"]
    end

    generator["generator.py<br>(loads all, sorts by priority)"]

    rpCapProfile --> generator
    rpThreatSurface --> generator
    rpScenarioYaml --> generator
    rpFeatureFiles --> generator
    rpCallsJsonl --> generator
    rpCoverageGaps --> generator
    rpEvalScorecard --> generator
    rpUseCase --> generator

    generator --> buildPage["build_full_page()<br>assembles single-page HTML"]

    buildPage --> report["report.html"]
```

**Section builders** (template.py):

| Builder Function | Input |
|-----------------|-------|
| `build_use_case_section(use_case_text)` | Use case text |
| `build_capability_profile_section(profile_data)` | Profile data |
| `build_threat_surface_section(ts_data)` | Threat surface data |
| `build_coverage_section(coverage_data)` | Coverage data |
| `build_threat_technique_section(scenarios)` | Scenarios |
| `build_attacker_diversity_section(scenarios)` | Scenarios |
| `build_scenarios_section(scenarios, feature_files, call_logs, threat_surface=ts_data, capability_profile=profile_data)` | Scenarios + provenance chain data |
| `build_scorecard_section(scorecard_data)` | Scorecard data |
| `build_raw_data_section(raw_files)` | Raw files |
| `build_glossary_section()` | — |

**Report structure** (build_full_page):

```mermaid
flowchart TD
    sidebar["Sidebar navigation<br>(auto-hides empty sections)"]

    sidebar --> sec1["1. Use Case description"]
    sidebar --> sec2["2. Capability Profile"]
    sidebar --> sec3["3. Threat Surface (Sankey diagram)"]
    sidebar --> sec4["4. Coverage Analysis"]
    sidebar --> sec5["5. Threat-Technique Matrix"]
    sidebar --> sec6["6. Actor Profiles (diversity chart)"]
    sidebar --> sec7["7. Scenarios (main section)"]
    sidebar --> sec8["8. Eval Scorecard"]
    sidebar --> sec9["9. Raw Data (YAML/JSON browser)"]
    sidebar --> sec10["10. Glossary"]
```

**Scenarios section detail** (build_scenarios_section):

```mermaid
flowchart TD
    dashboard["DASHBOARD HEADER<br>Priority donut chart (HIGH/MEDIUM/LOW)<br>Total scenarios breakdown"]
    heatmap["COVERAGE HEATMAP<br>Threat (rows) x Zone (columns) matrix<br>Cell color intensity = scenario count<br>Coverage gap percentage"]
    chipFilters["CHIP FILTERS<br>Threat ID, Zone, Priority chips<br>(toggle to filter scenario cards)"]
    cards["SCENARIO CARDS (one per scenario, collapsible)"]

    dashboard --> heatmap --> chipFilters --> cards

    subgraph CardTabs["Scenario Card: 9 Tabs (CSS-only radio buttons)"]
        tab1["1. Provenance<br>(8-step derivation chain)"]
        tab2["2. Generation Inputs<br>(per-call grouped sub-tables)"]
        tab3["3. Actor Profile<br>(BDI: beliefs/desires/intentions)"]
        tab4["4. ATLAS Techniques<br>(Gherkin-grounded technique cards)"]
        tab5["5. Narrative<br>(summary + entry point + zone breadcrumb)"]
        tab6["6. Attack Tree<br>(recursive AND/OR tree rendering)"]
        tab7["7. Behavior Spec<br>(syntax-highlighted Gherkin)"]
        tab8["8. Priority Signals<br>(composite score breakdown)"]
        tab9["9. LLM Calls<br>(expandable prompt/response log)"]
    end

    cards --> CardTabs
```

---

## 13. Provenance Chain (8-Step Derivation)

`_build_provenance_chain(scenario, threat_surface, capability_profile)`

Displayed as Tab 1 in each scenario card. Shows how deterministic pipeline inputs flowed into this specific scenario.

```mermaid
flowchart TD
    step1["Step 1: Risk Card<br>Risk ID: atlas-hallucination<br>Risk Name: Hallucination<br>Taxonomy: IBM Risk Atlas<br>Confidence: 0.81"]
    step2["Step 2: OWASP LLM IDs (SSSOM Mapping)<br>LLM09, LLM02<br>(badges with tooltip names)"]
    step3["Step 3: Agentic Threats (surviving)<br>T7 - Misaligned & Deceptive Behavior<br>T15 - ...<br>(badges with tooltip descriptions)"]
    step4["Step 4: Attack Pattern<br>Seed ID: AP-T7-01<br>Name: Constraint bypass via<br>goal-priority conflict<br>Threat: T7"]
    step5["Step 5: Attack Goal<br>Goal: IN-3 Decision Corruption<br>Category: Integrity Violation<br>T7 affinity: primary=[integrity, abuse]<br>secondary=[privacy, availability]<br>Sub-goal grid with tier highlights"]
    step6["Step 6: ATLAS Techniques<br>AML.T0051 - LLM Prompt Injection<br>AML.T0053 - AI Agent Tool Invocation<br>(badges with tooltip descriptions)"]
    step7["Step 7: Entry Point<br>User chat input<br>(from narrative.entry_point)"]
    step8["Step 8: Zone Sequence<br>input --> reasoning<br>(color-coded zone breadcrumb)"]

    step1 --> step2
    step2 --> step3
    step3 --> step4
    step4 --> step5
    step5 --> step6
    step6 --> step7
    step7 --> step8
```

**Data sources for each step:**

| Steps | Data Source |
|-------|------------|
| Steps 1-3 | `faceting.risk_card`, `faceting.taxonomy_chain` |
| Step 4 | `scenario_seed_metadata` (seed_id, attack_pattern_name, etc.) |
| Step 5 | `actor_profile` (goal_category, goal_category_name, goal_category_parent) + live taxonomy/affinity data |
| Step 6 | `faceting.taxonomy_chain.atlas_technique_ids` |
| Step 7 | `narrative.entry_point` |
| Step 8 | `faceting.capability_profile.zones_traversed` |
