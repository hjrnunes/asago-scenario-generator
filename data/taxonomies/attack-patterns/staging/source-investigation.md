# Source Investigation: Future Pattern Sources

## Summary

- **7 additional sources** identified in staging analysis files (ASI, CSA, Microsoft, LAAF, NIST, OWASP GenAI Top 10, plus more ATLAS case studies)
- **46 ATLAS case studies not yet referenced** (of 57 total in ATLAS-2026.05.yaml)
- **Primary extraction target**: ATLAS case studies CS0040-CS0056 (agentic focus, 17 case studies)
- **Priority ranking**: ATLAS agentic > Microsoft Copilot research > ASI > CSA > LAAF > GenAI Top 10

## ATLAS Case Studies Not Yet Referenced

The current 10 attack patterns reference these case studies:
- **Referenced (8)**: CS0040, CS0041, CS0048, CS0049, CS0051, CS0052, CS0053, CS0055
  - NOTE: CS0059 and CS0062 were previously listed here but DO NOT EXIST in ATLAS-2026.05.yaml (valid range: CS0000-CS0056)

ATLAS-2026.05.yaml contains **57 total case studies** (CS0000-CS0056). The agentic case studies (CS0040-CS0056, 17 total) are the most relevant.

### Agentic Case Studies Not Yet Referenced (9 of 17)

> **WARNING**: Earlier versions of this document listed CS0057-CS0062 as real case studies. These DO NOT EXIST in ATLAS-2026.05.yaml. The valid range is CS0000-CS0056 only. Lines below referencing CS0057+ have been removed.

| Case Study | Name | Type | Target | Agentic | Tactic Sequence Available | Priority |
|------------|------|------|--------|---------|---------------------------|----------|
| AML.CS0042 | SesameOp: AI API for C2 | Incident | OpenAI Assistants API | Yes | Minimal (1-step; C2 only) | P2 |
| AML.CS0043 | Malware with embedded prompt injection | Incident | LLM malware detectors | Yes | Yes (8 steps) | P3 |
| AML.CS0044 | LAMEHUG: AI-generated polymorphic commands | Incident | APT28 malware | Yes | Yes (8 steps) | P3 |
| AML.CS0045 | MCP data exfiltration (Cursor) | Exercise | Cursor | Yes | **Yes (11 steps, 7 tactics)** | **P1** |
| AML.CS0046 | Claude Computer Use data destruction | Exercise | Claude Computer Use | Yes | **Yes (7 steps)** | **P1** |
| AML.CS0047 | Amazon Q destructive agent deployment | Incident | Amazon Q VS Code | Yes | **Yes (7 steps)** | **P1** |
| AML.CS0050 | OpenClaw 1-click RCE | Exercise | OpenClaw | Yes | **Yes (9 steps)** | **P1** |
| AML.CS0054 | MCP tool docstring injection | Exercise | MCP | Yes | **Yes (9 steps)** | **P1** |
| AML.CS0056 | Model distillation campaigns | Incident | Anthropic Claude | No | Yes (6 steps) | P3 (out of scope) |

**Key observations:**
- **P1 (5 cases)**: Direct agentic exploitation with full tactic sequences — CS0045, CS0046, CS0047, CS0050, CS0054
- **P2 (1 case)**: AI-as-infrastructure patterns — CS0042
- **P3 (1 case)**: Out of scope (model theft) — CS0056
- **P3 (2 cases)**: AI-augmented malware (target is not an agent) — CS0043, CS0044

### Non-Agentic Case Studies (CS0000-CS0039, 40 total)

These focus on traditional ML, early LLM attacks, and pre-agentic systems. **Low priority** for pattern extraction because:
- Target traditional ML models (image classifiers, malware detectors, recommender systems)
- Predate agentic AI capabilities (tool use, memory, computer use, multi-agent)
- Most attacks are model evasion, poisoning, or extraction — not agent misuse

**Notable exceptions:**
- **CS0024** (Morris II Worm): RAG-based email assistant worm — already studied in staging analysis
- **CS0026** (M365 Copilot transaction hijacking): RAG poisoning + tool misuse — likely covered by existing AP-T1-* and AP-T2-* patterns
- **CS0035** (Slack AI data exfiltration): Agent memory + tool abuse — likely covered
- **CS0037** (Copilot Studio data exfiltration): Agent tool chain exploitation — likely covered

**Recommendation**: Review CS0024, CS0026, CS0035, CS0037 for kill chain enrichment opportunities on existing patterns, but prioritize CS0040-CS0062 for new pattern extraction.

## Staging Analysis Files Review

### 1. ATLAS case-study analysis, CS0040-CS0051

**Coverage**: Exhaustive analysis of CS0040-CS0051 (12 case studies)

**Content**:
- Full metadata, attack chain tables, mechanism summaries, technique inventories
- Detailed procedural steps with tactic/technique mappings
- Novel pattern identification (memory poisoning, supply chain, C2 channels, agent infrastructure)

**Tactic sequence quality**: **High** — every case study has a complete step-by-step kill chain with `leads-to` ordering

**Pattern yield**: The document explicitly identifies 13 new patterns and 3 enrichment candidates

**Status**: Already analyzed; ready for extraction

---

### 2. ATLAS case-study analysis, CS0052-CS0056

**Coverage**: Exhaustive analysis of CS0052-CS0056 (5 case studies; earlier version claimed CS0052-CS0062 but CS0057+ do not exist)

**Content**:
- Same structure as part1: full metadata, attack chains, mechanism summaries, technique inventories
- Cross-case-study technique frequency analysis
- Attack pattern category clustering (prompt-to-code, supply chain poisoning, RAG poisoning, LLM as XSS generator, AI service as infrastructure, model/IP theft, jailbreak services)

**Tactic sequence quality**: **High** — complete kill chains for all cases

**Pattern yield**: Identifies attack pattern categories across CS0052-CS0056 (earlier claim of CS0052-CS0062 was based on hallucinated case studies)

**Status**: Already analyzed; ready for extraction

---

### 3. ATLAS data model analysis

**Coverage**: ATLAS v6 YAML format structural analysis

**Content**:
- Top-level schema (tactics, techniques, mitigations, case-studies, relationships)
- Object field inventories, ID naming conventions, relationship types
- Kill chain model details (`employs` relationships with `step-id`, `leads-to`, `tactic`, `technique`)
- Python code analysis (Pydantic schemas, SQLAlchemy models, enums)

**Tactic sequence quality**: **N/A** (structural documentation, not attack analysis)

**Pattern yield**: **N/A** (this is infrastructure documentation)

**Relevance**: Critical for understanding how to extract and transform ATLAS case studies into asago-scenario-generator patterns

**Status**: Reference document for extraction tooling

---

### 4. ATLAS actor analysis

**Coverage**: Kill chain step actor classification across 14 case studies

**Content**:
- Per-step actor classification (Attacker, System/Agent, Victim/Environment)
- Actor transition patterns (attacker-first → system-second progression)
- Statistical breakdown: 55% attacker steps, 40% system steps, 6% victim steps
- Identifies the "fire and forget" inflection point in agentic cases where attacker hands off to autonomous agent behavior

**Tactic sequence quality**: **High** — demonstrates that ATLAS kill chains explicitly model the attacker-to-agent handoff

**Pattern yield**: Conceptual insight (not direct pattern source)

**Relevance**: Informs how to frame kill chain steps in asago-scenario-generator patterns (who acts: attacker, agent, or both?)

**Status**: Methodological reference

---

### 5. Case-study abstraction strategy

**Coverage**: Methodology for transforming ATLAS concrete case studies into abstract asago-scenario-generator patterns

**Content**:
- 4-operation abstraction method: Strip (domain-specific details) → Keep (attack mechanism) → Abstract (generalize descriptions) → Add (asago-scenario-generator fields)
- Kill chain abstraction rules
- Full transformation examples (CS0040 → AP-T1-05, CS0045 → AP-T2-07, CS0055 → AP-T11-05)
- Coverage analysis: 13 new patterns, 3 variants, 5 enrichments, 3 out-of-scope, 2 AI-as-infrastructure
- Extraction candidate clusters (MCP ecosystem, computer-use agent, AI as C2, AI-augmented malware, agent infrastructure, AI output weaponization)
- Concrete extraction plan with priority ordering (P1: 5 patterns, P2: 4 patterns, P3: 4 patterns)

**Tactic sequence quality**: **High** — demonstrates how to map ATLAS `employs` relationships to abstract kill chain templates

**Pattern yield**: **13 new patterns + 5 enrichments** — the master extraction plan

**Status**: Extraction blueprint; ready to execute

---

### 6. format-comparison-and-synthesis.md

**Coverage**: Structural comparison of ATLAS v6 and asago-scenario-generator attack pattern formats

**Content**:
- Abstraction level analysis (ATLAS Level 4 concrete → asago-scenario-generator Level 3.5 abstract)
- Field-by-field inventory of what each format captures
- Strengths/weaknesses of each format for scenario generation
- Three synthesis options: A (minimal adaptation), B (hybrid model with kill chains), C (ATLAS-native)
- Recommendation: Option B (add structured kill chain templates to asago-scenario-generator patterns)

**Tactic sequence quality**: **N/A** (structural comparison)

**Pattern yield**: **N/A** (design document)

**Relevance**: Informs how to integrate ATLAS kill chain structure into asago-scenario-generator without abandoning the prerequisite model

**Status**: Architecture decision document; Option B recommended, with Phase 1 (minimal) as immediate next step

---

### 7. pattern-actor-analysis.md

**Coverage**: Kill chain step actor classification across 27 asago-scenario-generator attack patterns

**Content**:
- Per-step actor classification (Attacker, Agent, Ambiguous)
- Aggregate distribution: 46.4% ATK, 25.8% AGT, 27.8% AMB
- Framing archetype identification: Pure attacker playbook, Pure agent behavior trace, Attacker-to-agent handoff
- Description vs. kill chain perspective alignment analysis
- Comparison with ATLAS framing (uniformly attacker-perspective vs. asago-scenario-generator handoff model)

**Tactic sequence quality**: **High** — existing asago-scenario-generator patterns already have kill chain scaffolds

**Pattern yield**: **N/A** (quality analysis of existing patterns)

**Relevance**: Identifies that asago-scenario-generator patterns model the attacker-to-agent handoff, which differs from ATLAS's consistent attacker-perspective framing

**Status**: Quality audit; informs how to frame new kill chains consistently

---

### 8. Asago scenario generator format analysis

**Coverage**: Exhaustive analysis of asago-scenario-generator attack pattern data model and pipeline consumption

**Content**:
- Field-by-field inventory with consumption points in pipeline code
- Hard constraints for format adoption (MUST have: id, threat_id, name, description)
- Fields that are unused by pipeline (nist_classification, min_zones)
- SSSOM provenance flow through pipeline stages
- Design constraints and naming conventions

**Tactic sequence quality**: **N/A** (data model documentation)

**Pattern yield**: **N/A** (infrastructure analysis)

**Relevance**: Critical for understanding which fields are required/optional when creating new patterns from ATLAS case studies

**Status**: Reference document for pattern authoring

---

## Source Quality Assessment

### Source 1: MITRE ATLAS Case Studies CS0040-CS0056

**Procedural depth**: **Explicit steps** — every case study has a numbered, ordered kill chain with `leads-to` pointers

**Estimated pattern yield**: Revised down from earlier estimate — original "13 new patterns + 5 enrichments" count included hallucinated CS0057-CS0062

**Tactic sequence quality**: **High** — 5-18 steps per case study, spans 4-8 distinct ATLAS tactics, explicit tactic assignment per step

**Notes**:
- 17 agentic case studies total (CS0040-CS0056)
- 8 already referenced in existing patterns
- 9 unreferenced, of which 5 are P1 priority
- Each case study includes: actor, target, date, type (Incident/Exercise), references, step descriptions, technique mappings, leads-to relationships
- Format: ATLAS v6 YAML with `relationships.employs` section encoding the kill chain
- **Actionable**: Ready for extraction; staging analysis provides complete transformation methodology

---

### Source 2: Microsoft Copilot Security Research

**Procedural depth**: **Implicit steps** — research papers describe attack mechanisms but not always in step-by-step format

**Estimated pattern yield**: 2-4 patterns (RAG poisoning, agent memory exploitation, connected app attacks)

**Tactic sequence quality**: **Medium** — procedural details exist but need extraction and abstraction

**Notes**:
- Sources: Microsoft Security blog posts, M365 Copilot security research, Azure OpenAI security advisories
- NOTE: CS0059 ("EchoLeak") was previously referenced here but does not exist in ATLAS
- Example: M365 Copilot transaction hijacking (CS0026) — RAG + tool misuse
- **Status**: Many covered by ATLAS case studies; review for kill chain enrichment opportunities

---

### Source 3: AI Safety Institute (ASI) Taxonomy

**Procedural depth**: **Description only** — high-level threat descriptions, no procedural steps

**Estimated pattern yield**: 0 new patterns (already mapped via cross-taxonomy-mappings.yaml)

**Tactic sequence quality**: **None** — ASI provides threat categories (ASI01-ASI10), not attack procedures

**Notes**:
- ASI01: Goal Hijacking, ASI02: Tool Misuse, ASI03: Identity/Privilege Abuse, ASI04: Compromise Supply Chain, ASI05: Unexpected Code Attacks, ASI06: Persistent Agent Compromise, ASI07: Insecure Inter-Agent Protocols, ASI08: Audit Trail Evasion, ASI09: Human Manipulation, ASI10: Scaling Violations
- All asago-scenario-generator patterns already map to ASI IDs via `t_to_asi` in cross-taxonomy-mappings.yaml
- **Value**: Validation that asago-scenario-generator threat coverage aligns with industry taxonomy, not a pattern source

---

### Source 4: Cloud Security Alliance (CSA) AI Security Framework

**Procedural depth**: **Description only** — control objectives and risk areas, not attack procedures

**Estimated pattern yield**: 0 new patterns

**Tactic sequence quality**: **None** — CSA provides defense recommendations, not adversary TTPs

**Notes**:
- CSA framework focuses on secure AI development lifecycle, governance, and control frameworks
- Does not describe specific attack mechanisms or kill chains
- **Value**: Could inform mitigation mappings, not useful for attack pattern extraction

---

### Source 5: LAAF (OWASP Language Model Abuse Framework)

**Procedural depth**: **Implicit steps** — technique descriptions include some procedural detail

**Estimated pattern yield**: 0 new patterns (already mapped via SSSOM)

**Tactic sequence quality**: **Low** — LAAF techniques describe injection/delivery methods but not complete kill chains

**Notes**:
- LAAF provides 20+ LLM abuse techniques (S1-S20+, M1-M20+, etc.)
- All asago-scenario-generator patterns already map to LAAF technique IDs via SSSOM provenance files
- Example: S1 (Direct Prompt Injection), S2 (Indirect Prompt Injection), M3 (Multi-Turn Manipulation)
- **Value**: Already integrated; no new patterns to extract

---

### Source 6: NIST AI 100-2e2023

**Procedural depth**: **Description only** — attack taxonomy and lifecycle model, not procedural TTPs

**Estimated pattern yield**: 0 new patterns (already used for classification)

**Tactic sequence quality**: **None** — NIST provides abstract attack classes, not kill chains

**Notes**:
- NIST taxonomy used for `nist_classification.attack_class` field in asago-scenario-generator patterns
- Example: `genai.indirect_prompt_injection.abuse_violations`, `poisoning.targeted_poisoning`
- Provides attacker_goal/knowledge/learning_stage classification scheme
- **Value**: Already integrated via pattern metadata; not a procedural attack source

---

### Source 7: OWASP GenAI Top 10

**Procedural depth**: **Description only** — threat categories with example scenarios, not step-by-step procedures

**Estimated pattern yield**: 0 new patterns (conceptually covered by existing T1-T17)

**Tactic sequence quality**: **Low** — GenAI Top 10 describes threat types but not operational kill chains

**Notes**:
- LLM01: Prompt Injection, LLM02: Insecure Output Handling, LLM03: Training Data Poisoning, LLM04: Model Denial of Service, LLM05: Supply Chain Vulnerabilities, LLM06: Sensitive Information Disclosure, LLM07: Insecure Plugin Design, LLM08: Excessive Agency, LLM09: Overreliance, LLM10: Model Theft
- Asago Scenario Generator's T1-T17 taxonomy already subsumes these concepts
- **Value**: Validation of threat coverage; no new procedural content

---

## Recommendations

### Priority 1: Extract from ATLAS CS0040-CS0056 (agentic case studies)

**Why**: Complete kill chains, explicit tactic sequences, agentic focus, already analyzed in staging

**Which case studies**:
1. **CS0045** (MCP data exfiltration via Cursor) → AP-T2-07
2. **CS0046** (Claude Computer Use data destruction) → AP-T2-08
3. **CS0047** (Amazon Q destructive agent deployment) → already used for AP-T11-02
4. **CS0050** (OpenClaw 1-click RCE) → AP-T3-05
5. **CS0054** (MCP tool docstring injection) → AP-T16-04

**Method**: Follow the transformation rules of the case-study abstraction strategy (section 5 above):
- Strip domain-specific anchors (named actors, specific targets, CVEs)
- Keep tactical progression and technique IDs
- Abstract action descriptions to be domain-agnostic
- Add asago-scenario-generator prerequisite_capabilities and NIST classification
- Create SSSOM provenance entries mapping to ATLAS technique IDs

**Effort**: Medium (2-3 weeks for 6 P1 patterns + SSSOM + validation)

---

### Priority 2: Review CS0042 for AI-as-Infrastructure Patterns

**Why**: Represents a genuinely new category (AI service as C2 relay) not currently modeled

**Caveat**: This is an attack USING AI services, not an attack ON AI agents. The AI is infrastructure, not target. May warrant a separate threat category (proposed T18) or annotation on existing T11 patterns. CS0061, previously listed alongside CS0042, does not exist.

**Method**: Determine if this fits the asago-scenario-generator threat model (agentic system threats) or if it is out of scope (traditional malware using AI APIs)

**Effort**: Low (1 week for analysis + 1 pattern if in scope)

---

### Priority 3: Enrich Existing Patterns with Kill Chains from ATLAS

**Why**: Many existing patterns were derived from ATLAS case studies but lack explicit kill chain scaffolds

**Which patterns**:
- AP-T1-01 ← CS0040 (ChatGPT memory poisoning)
- AP-T17-01/AP-T17-02 ← CS0041, CS0049 (rules file backdoor, skill supply chain)
- AP-T11-01 ← CS0052 (prompt-to-RCE frameworks); AP-T11-02 now mapped to CS0047 (CS0062 does not exist)

**Method**: Add `kill_chain` section to existing patterns using format-comparison-and-synthesis.md Option B (hybrid model)

**Effort**: Low-medium (1-2 weeks for 5 patterns)

---

### Priority 4: Cross-Check Non-Agentic Case Studies for Enrichment

**Why**: CS0024, CS0026, CS0035, CS0037 may provide kill chain details for existing memory/tool patterns

**Method**: Review case studies for tactic sequences that enrich AP-T1-*, AP-T2-* patterns

**Effort**: Low (1 week for review + documentation updates)

---

## Methodology Gaps

Based on the staging analysis, the following gaps exist in the current extraction workflow:

### Gap 1: No Automated ATLAS-to-Asago Scenario Generator Transformer

**Issue**: The case-study abstraction strategy (section 5 above) provides manual transformation rules, but there is no tooling to automate the extraction

**Recommendation**: Build a script that:
1. Parses ATLAS v6 YAML `relationships.employs` section
2. Extracts kill chain steps with tactic/technique/description
3. Generates asago-scenario-generator `kill_chain` scaffold
4. Prompts for manual abstraction (strip domain details, add prerequisite_capabilities)
5. Outputs YAML pattern stub + SSSOM entries

**Effort**: 1-2 weeks for tooling development

---

### Gap 2: Kill Chain Scaffold Format Not Finalized

**Issue**: format-comparison-and-synthesis.md proposes Option B (hybrid model with kill chain templates), but the schema is not implemented in the codebase

**Recommendation**: Finalize kill chain schema before extracting new patterns:
- Define `KillChainStep` data model (step name, tactic, techniques[], abstract_action)
- Update pattern loader to parse optional `kill_chain` section
- Update templates to consume kill chain scaffolds (if present)

**Effort**: 1 week for schema design + 1 week for pipeline integration

---

### Gap 3: SSSOM Provenance Generation Is Manual

**Issue**: Each new pattern needs manual SSSOM entries mapping to ATLAS/LAAF technique IDs

**Recommendation**: Generate SSSOM entries from kill chain technique IDs automatically:
- Extract unique ATLAS technique IDs from `kill_chain[].techniques`
- Generate SSSOM rows with `skos:relatedMatch` predicate
- Include confidence=1.0, mapping_justification=ManualMappingCuration

**Effort**: 1-2 days for script

---

### Gap 4: No Validation of Kill Chain Consistency

**Issue**: If kill chains are added to patterns, the pipeline needs to validate that:
- Tactic ordering follows ATLAS matrix sequence
- Technique IDs are valid ATLAS techniques
- At least one technique from the kill chain appears in generated attack trees

**Recommendation**: Add kill chain validation checks to `validation.py`:
- `check_kill_chain_tactic_ordering()` — warn if tactics are out of ATLAS sequence
- `check_kill_chain_technique_validity()` — verify all technique IDs exist in ATLAS
- Extend `check_leaf_technique_provenance()` to check kill chain techniques

**Effort**: 1 week for validation logic

---

## Appendix: ATLAS Tactic Reference

For kill chain extraction, ATLAS tactics (ordered by matrix position):

| Position | ID | Name |
|----------|-----|------|
| 1 | AML.TA0002 | Reconnaissance |
| 2 | AML.TA0003 | Resource Development |
| 3 | AML.TA0004 | Initial Access |
| 4 | AML.TA0000 | AI Model Access |
| 5 | AML.TA0005 | Execution |
| 6 | AML.TA0006 | Persistence |
| 7 | AML.TA0012 | Privilege Escalation |
| 8 | AML.TA0007 | Defense Evasion |
| 9 | AML.TA0013 | Credential Access |
| 10 | AML.TA0008 | Discovery |
| 11 | AML.TA0015 | Lateral Movement |
| 12 | AML.TA0009 | Collection |
| 13 | AML.TA0001 | AI Attack Staging |
| 14 | AML.TA0014 | Command and Control |
| 15 | AML.TA0010 | Exfiltration |
| 16 | AML.TA0011 | Impact |

**Notes**:
- AML.TA0000 (AI Model Access) and AML.TA0001 (AI Attack Staging) are AI-specific tactics with no ATT&CK equivalent
- Most agentic kill chains span 4-8 tactics (typically: Resource Development → Initial Access → Execution → Persistence/Evasion → Collection/Exfiltration → Impact)
