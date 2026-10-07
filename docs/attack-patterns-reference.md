# Attack Patterns Reference

A comprehensive reference of all attack patterns in the asago-scenario-generator taxonomy,
organized by parent OWASP Agentic AI threat.

Attack patterns are **domain-agnostic mechanism descriptions** derived from OWASP
Agentic AI sub-scenarios. Each pattern describes an abstract attack mechanism
rather than targeting a specific application. Patterns are mapped to
[MITRE ATLAS](https://atlas.mitre.org/) techniques and
[LAAF](https://github.com/laaf-ai/laaf/) technique identifiers via
[SSSOM](https://mapping-commons.github.io/sssom/) provenance mappings and the
catalog's canonical chains.

**53 attack patterns** across **15 threats** (T1-T17; T7, T14 currently have no pattern).

## Table of Contents

- [T1 -- Memory Poisoning](#t1-memory-poisoning) (5 patterns)
- [T2 -- Tool Misuse](#t2-tool-misuse) (6 patterns)
- [T3 -- Privilege Compromise](#t3-privilege-compromise) (5 patterns)
- [T4 -- Resource Overload](#t4-resource-overload) (2 patterns)
- [T5 -- Cascading Hallucination Attacks](#t5-cascading-hallucination-attacks) (4 patterns)
- [T6 -- Intent Breaking & Goal Manipulation](#t6-intent-breaking-goal-manipulation) (10 patterns)
- [T7 -- Misaligned & Deceptive Behaviors](#t7-misaligned-deceptive-behaviors) (0 patterns)
- [T8 -- Repudiation & Untraceability](#t8-repudiation-untraceability) (1 patterns)
- [T9 -- Identity Spoofing & Impersonation / Agent Identity Compromise](#t9-identity-spoofing-impersonation-agent-identity-compromise) (5 patterns)
- [T10 -- Overwhelming Human in the Loop](#t10-overwhelming-human-in-the-loop) (1 patterns)
- [T11 -- Unexpected RCE and Code Attacks](#t11-unexpected-rce-and-code-attacks) (4 patterns)
- [T12 -- Agent Communication Poisoning](#t12-agent-communication-poisoning) (2 patterns)
- [T13 -- Rogue Agents in Multi-Agent Systems](#t13-rogue-agents-in-multi-agent-systems) (1 patterns)
- [T14 -- Human Attacks on Multi-Agent Systems](#t14-human-attacks-on-multi-agent-systems) (0 patterns)
- [T15 -- Human Manipulation](#t15-human-manipulation) (2 patterns)
- [T16 -- Insecure Inter-Agent Protocol Abuse](#t16-insecure-inter-agent-protocol-abuse) (2 patterns)
- [T17 -- Supply Chain Compromise](#t17-supply-chain-compromise) (3 patterns)

---

## T1 -- Memory Poisoning

> Memory Poisoning exploits AI agents' reliance on short-term and long-term memory, allowing attackers to corrupt stored information, bypass security checks, and manipulate decision-making.

### AP-T1-01: Persistent memory rule injection

Repeatedly reinforce a false operational rule in the agent's persistent memory until the agent treats it as established fact, so the fabricated rule overrides legitimate validation logic and authorizes actions that violate actual constraints. Owns the operational-rule/authorization-override effect within OG-01; factual-content compounding belongs to AP-T5-01.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `memory` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `poisoning.targeted_poisoning` |

**Mapped Techniques:**

- ATLAS `AML.T0043` -- Craft Adversarial Data
- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0070` -- RAG Poisoning
- ATLAS `AML.T0080.000` -- Memory
- LAAF: `L2`, `S3`

---

### AP-T1-02: Context window saturation for privilege escalation

Fragment a privilege-escalation attempt across multiple turns within a session so each fragment stays below detection thresholds and the agent cumulatively loses track of prior authorization state, granting access it should deny. Strictly ephemeral: no cross-session persistence (that is AP-T1-01's mechanism).

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `memory` |
| **KC Requirements** | ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `poisoning.targeted_poisoning` |

**Mapped Techniques:**

- ATLAS `AML.T0031` -- Erode AI Model Integrity
- ATLAS `AML.T0043` -- Craft Adversarial Data
- ATLAS `AML.T0051.000` -- Direct
- LAAF: `L1`, `S3`

---

### AP-T1-03: Gradual threat-model erosion via memory drift

Incrementally alter the agent's stored threat definitions or classification criteria over successive interactions so the agent progressively reclassifies malicious activity as benign, creating a detection blind spot. Owns gradual definition-drift in persistent state; one-shot rule injection is AP-T1-01.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `memory` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `poisoning.targeted_poisoning` |

**Mapped Techniques:**

- ATLAS `AML.T0031` -- Erode AI Model Integrity
- ATLAS `AML.T0070` -- RAG Poisoning
- ATLAS `AML.T0080.000` -- Memory
- LAAF: `L2`, `T5`

---

### AP-T1-04: Shared memory corruption for cross-agent influence

Write false operational data into a RAG-indexed retrieval store shared among multiple agents so agents retrieving from the store incorporate the corrupted data into their decision-making, propagating incorrect behavior without direct attacker interaction with each agent. Narrowed to the shared RAG-indexed retrieval substrate (AML.T0070's pinned operation); generic shared-memory backends are out of scope. Owns the shared-substrate corruption within OG-02.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `memory` -> `inter_agent` |
| **KC Requirements** | ALL of: `KCX-SHMEM`; ANY of: `KC4.4`, `KC4.6` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `poisoning.targeted_poisoning` |

**Mapped Techniques:**

- ATLAS `AML.T0020` -- Poison Training Data
- ATLAS `AML.T0070` -- RAG Poisoning
- ATLAS `AML.T0071` -- False RAG Entry Injection
- LAAF: `L5`, `T8`

---

### AP-T1-06: Zero-click RAG poisoning with rendered-output exfiltration

An attacker delivers content disguised as legitimate material into a data corpus feeding an AI assistant's retrieval pipeline. When a later query retrieves the poisoned content, hidden instructions activate without any user interaction with the malicious content (zero-click) and direct the assistant to encode sensitive data into rendered output elements (such as markdown image URLs) that the client application automatically fetches, exfiltrating the data to an attacker-controlled endpoint. Exact ATLAS chain identity: AML.T0070 — planting the disguised content in a RAG-indexed corpus so a future retrieval activates it is AML.T0070's exact defined operation (RAG poisoning); evidence AML.CS0024 S02-S03 analogue and AML.CS0029 S03-S04 analogue (the pinned relationships there employ AML.T0053/AML.T0051.002 and AML.T0093/AML.T0051.001 respectively, not AML.T0070, so corpus planting is supported by analogy), plus pinned technique definition AML.T0070. AML.T0077 — encoding sensitive data into rendered output that the client automatically fetches is AML.T0077's exact defined operation (private information hidden in rendered LLM responses is exfiltrated via automatic requests); evidence AML.CS0021 S04 and AML.CS0029 S05, plus pinned technique definition AML.T0077.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `memory` |
| **KC Requirements** | ALL of: `KCX-VSTORE`; ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0070` -- RAG Poisoning
- ATLAS `AML.T0077` -- LLM Response Rendering
- ATLAS `AML.T0085` -- Data from AI Services
- ATLAS `AML.T0093` -- Prompt Infiltration via Public-Facing Application

---

## T2 -- Tool Misuse

> Tool Misuse occurs when attackers manipulate AI agents into abusing their authorized tools through deceptive prompts and operational misdirection, leading to unauthorized data access, system manipulation, or resource exploitation while staying within granted permissions.

### AP-T2-01: Parameter pollution via function-call manipulation

Craft input that causes the agent to invoke a tool with inflated, malformed, or boundary-violating parameter values so the tool executes within its granted permissions but produces outcomes far outside intended operational bounds (amplified quantities, modified recipients). Owns semantically/quantitatively invalid parameter values; generic tool redirection is out of scope.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- LAAF: `S4`, `S8`

---

### AP-T2-02: Multi-tool chain exploitation for data exfiltration

Manipulate the agent into chaining two or more authorized tools in a designer-unanticipated retrieve-then-transmit sequence so sensitive data collected by one tool is exfiltrated by a subsequent tool, each individual call appearing legitimate. Owns the tool-composition defect.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0048` -- External Harms
- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0086` -- Exfiltration via AI Agent Tool Invocation
- LAAF: `L1`, `L3`

---

### AP-T2-03: Automated mass-action abuse via tool amplification

Trick the agent into using its document-generation, distribution, or batch-processing tools to amplify a single deceptive input into a high-volume malicious operation such as mass distribution of crafted content. Bounded to batch/bulk-action tooling; ordinary repeated injection and multi-tool exfiltration chains are excluded.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0048` -- External Harms
- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- LAAF: `M3`, `T3`

---

### AP-T2-04: Tool misuse via poisoned persistent memory

Inject false directives into the agent's persistent memory in a prior session so later sessions retrieve them as legitimate operational context and invoke tools with unauthorized parameters or targets, bypassing session-level checks. Owns the cross-session poisoned-memory vector; retrieval-index poisoning is AP-T2-05 and session-immediate injection is AP-T2-06.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `memory` -> `tool_execution` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0070` -- RAG Poisoning
- ATLAS `AML.T0071` -- False RAG Entry Injection
- ATLAS `AML.T0080.000` -- Memory
- LAAF: `S3`, `T2`

---

### AP-T2-05: Tool misuse via adversarial retrieval content

Insert adversarially crafted content into the agent's vector store so that when the agent retrieves the poisoned content it interprets the embedded directives as legitimate operational guidance and performs unsafe or unauthorized tool invocations. Owns the retrieval-poisoning to tool-action mechanism within OG-03.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `memory` -> `tool_execution` |
| **KC Requirements** | ALL of: `KCX-VSTORE`; ANY of: `KC6.3.3` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0066` -- Retrieval Content Crafting
- ATLAS `AML.T0070` -- RAG Poisoning
- ATLAS `AML.T0071` -- False RAG Entry Injection
- LAAF: `L4`, `S3`

---

### AP-T2-06: Tool hijacking via prompt injection

Inject adversarial instructions directly so the agent invokes its command/scripting interpreter tool (shell or code interpreter exposed as an agent tool) to run an attacker-chosen command. Narrowed to interpreter execution, AML.T0050's pinned operation; the generic API-client mode is out of scope. Owns the tool-execution hijack within OG-04 and the direct-delivery vector; the goal-override mechanism is AP-T6-02 and indirect delivery is AP-T6-03.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- LAAF: `M3`, `S8`

---

## T3 -- Privilege Compromise

> Privilege Compromise occurs when attackers exploit mismanaged roles, overly permissive configurations, or dynamic permission inheritance to escalate privileges and misuse AI agents' access.

### AP-T3-02: Cross-boundary authorization escalation

Leverage the agent's authorized access to one system to escalate privileges in a connected system that lacks independent scope enforcement, so the agent's credentials or trust relationships carry across the boundary. Distinct from AP-T3-01 (temporal scope failure) and AP-T9-01 (identity attribution).

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.2`, `KC6.2.2`, `KC6.5`, `KCX-XAUTH` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- LAAF: `L1`, `S6`

---

### AP-T3-03: Shadow agent credential inheritance

Exploit weak provisioning controls to instantiate an unauthorized agent that inherits or copies legitimate credentials from the hosting environment, then operate through that shadow agent's apparent legitimacy. Distinct from AP-T9-02/AP-T9-06 (theft and use of an existing agent's credentials).

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` -> `inter_agent` |
| **KC Requirements** | ALL of: `KC2.3`, `KCX-MAGENT`; ANY of: `KC5.1`, `KC5.2`, `KC5.3`, `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7`, `KCX-XAUTH` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |

**Mapped Techniques:**

- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0073` -- Impersonation
- ATLAS `AML.T0103` -- Deploy AI Agent
- LAAF: `M1`, `M2`

---

### AP-T3-04: Exposed agent control interface exploitation

An attacker discovers internet-exposed AI agent management or control interfaces with weak or absent authentication and accesses their administrative functionality as an unauthorized access primitive. This record owns the exposure/access mechanism only: downstream credential harvesting and pivot belong to AP-T3-05, and prompt-driven privileged-tool compromise belongs to AP-T3-06. Exact ATLAS chain identity: AML.T0049 — accessing an internet-facing agent control application whose missing authentication is a design weakness, using crafted requests to cause unintended behavior, is AML.T0049's exact defined operation (exploit public-facing application); evidence AML.CS0048 S01, plus pinned technique definition AML.T0049.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.4`, `KC6.5` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0000` -- Search Open Technical Databases
- ATLAS `AML.T0049` -- Exploit Public-Facing Application
- ATLAS `AML.T0083` -- Credentials from AI Agent Configuration

---

### AP-T3-05: Agent credential harvesting and connected-service pivot

Through an exposed AI agent control interface, an attacker harvests plaintext credentials for connected services from configuration files and environment surfaces, then reuses them to pivot across the agent's connected service ecosystem. This record owns the credential-harvest and pivot mechanism; the exposure/access primitive belongs to AP-T3-04 and prompt-driven compromise belongs to AP-T3-06. Exact ATLAS chain identity: AML.T0083 — extracting connected-service credentials (API keys, tokens, connection strings) from the agent's configuration files is AML.T0083's exact defined operation (credentials from AI agent configuration); evidence AML.CS0048 S02 (clawdbot.json), plus pinned technique definition AML.T0083.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.4`, `KC6.5` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0083` -- Credentials from AI Agent Configuration

---

### AP-T3-06: Prompt-driven privileged tool execution via exposed agent control interface

Through an exposed AI agent control interface, an attacker submits arbitrary prompts that exploit the agent's instruction-following behavior to invoke privileged tools, achieving root execution inside the agent's own container via its bash skill. This record owns the prompt-driven privileged-tool compromise mechanism; any impact beyond the container (host-level escape) is inferred, not demonstrated. The system-prompt disclosure observed at AML.CS0048 S04 is incidental reconnaissance, not a causal step of this mechanism. Exact ATLAS chain identity: AML.T0051.000 — submitting arbitrary prompts directly through the exposed interface is direct prompt injection, AML.T0051.000's exact defined operation; evidence AML.CS0048 S03 retag (the pinned relationship assigns AML.T0051.001 (indirect), but the step description is the researcher prompting the agent directly through the control interface), plus pinned technique definition AML.T0051.000. AML.T0053 — driving the agent's privileged tools (bash) through those prompts is adversary-driven agent tool invocation, AML.T0053's exact defined operation; evidence AML.CS0048 S06, plus pinned technique definition AML.T0053.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.4`, `KC6.5` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0053` -- AI Agent Tool Invocation

---

## T4 -- Resource Overload

> Resource Overload occurs when attackers deliberately exhaust an AI agent's computational power, memory, or external service dependencies, leading to system degradation or failure.

### AP-T4-01: Computationally expensive input exploitation

Submit specially crafted inputs that force the agent into resource-intensive processing paths (deeply nested reasoning, complex parsing, exhaustive search) so disproportionate compute per request degrades throughput. Owns single-input complexity amplification.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC6.1.2`, `KC6.2.2`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | availability |
| **Attacker Knowledge** | black_box |

**Mapped Techniques:**

- ATLAS `AML.T0029` -- Denial of AI Service
- ATLAS `AML.T0034` -- Cost Harvesting
- LAAF: `S3`, `S4`

---

### AP-T4-03: External API quota exhaustion

Craft requests that cause the agent to make excessive calls to rate-limited or quota-bound external APIs, consuming the quota until legitimate operations depending on those services are blocked. Owns agent-mediated external-quota exhaustion.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | availability |
| **Attacker Knowledge** | black_box |

**Mapped Techniques:**

- ATLAS `AML.T0029` -- Denial of AI Service
- ATLAS `AML.T0034` -- Cost Harvesting
- ATLAS `AML.T0034.002` -- Agentic Resource Consumption
- LAAF: `S4`, `T3`

---

## T5 -- Cascading Hallucination Attacks

> Cascading Hallucination Attacks exploit AI agents' inability to distinguish fact from fiction, allowing false information to propagate, embed, and amplify across interconnected systems.

### AP-T5-01: Progressive misinformation accumulation in persistent memory

Inject subtly false factual information that the agent stores in long-term memory and subsequently treats as authoritative source material, so successive interactions compound the distortion. Owns the recursive factual-misinformation effect within OG-01; operational-rule override belongs to AP-T1-01. Autonomous hallucination without adversarial seeding is excluded.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `memory` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.integrity_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0031` -- Erode AI Model Integrity
- ATLAS `AML.T0060` -- Publish Hallucinated Entities
- ATLAS `AML.T0080.000` -- Memory
- LAAF: `S3`, `T8`

---

### AP-T5-02: Hallucinated endpoint injection for data exfiltration

Introduce references to fictitious attacker-controlled endpoints into content the agent retrieves, so the agent generates calls to those endpoints and leaks operational-context data. Bounded to attacker-seeded endpoint fabrication; spontaneous endpoint hallucination without adversarial seeding is an agent-failure mode, not this pattern.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `memory` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.integrity_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0060` -- Publish Hallucinated Entities
- ATLAS `AML.T0070` -- RAG Poisoning
- LAAF: `M8`, `S8`

---

### AP-T5-04: Fabricated reference data injection for value manipulation

Inject false quantitative reference data into the agent's retrieval context so the agent negotiates, transacts, or computes on unrealistic values that persist across interactions, systematically biasing dependent downstream computations. Owns attacker-injected reference-value manipulation; autonomous numerical hallucination is excluded (OG-01 effect boundary).

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `memory` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC4.3`, `KC4.4`, `KC4.5`, `KC4.6` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.integrity_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0043` -- Craft Adversarial Data
- ATLAS `AML.T0070` -- RAG Poisoning
- LAAF: `M8`, `T5`

---

### AP-T5-05: Hallucinated-reference elicitation

Ask the system for specific references in a domain where legitimate sources are sparse, such as package names, URLs, citations, organization names, or contact addresses, so that the model fabricates a reference with no real-world source and presents it as fact. The attack stays inside one conversation and needs no persistent memory, tool, or retrieval source; the chain ends at the first response that presents a fabricated reference. Exact ATLAS chain identity: AML.T0062 - prompting the model and identifying hallucinated entities is AML.T0062's exact defined operation (Discover LLM Hallucinations); evidence: pinned technique definition AML.T0062. A fabricated reference is the hallucinated entity that AML.T0060 (Publish Hallucinated Entities) lets an adversary register; this record stops at the fabricated reference and does not cover that registration. Spontaneous hallucination without an attacker's probing is a failure, not an attack.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.direct_prompt_injection.integrity_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0062` -- Discover LLM Hallucinations

---

## T6 -- Intent Breaking & Goal Manipulation

> Intent Breaking and Goal Manipulation occurs when attackers exploit the lack of separation between data and instructions in AI agents, using prompt injections, compromised data sources, or malicious tools to alter the agent's planning, reasoning, and self-evaluation.

### AP-T6-01: Incremental sub-goal injection for plan drift

Inject auxiliary sub-goals incrementally over multiple interactions so each appears benign in isolation but their cumulative effect shifts the agent's plan away from its original objective while surface reasoning stays coherent. Owns cumulative plan drift; one-shot override is AP-T6-02 and poisoned-retrieval redirection is AP-T6-03.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.direct_prompt_injection.jailbreak` |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0054` -- LLM Jailbreak
- LAAF: `L2`, `M3`

---

### AP-T6-02: Direct instruction override for tool-chain hijacking

Issue an explicit instruction commanding the agent to discard its original directives and adopt an attacker-specified sequence of tool invocations, exploiting missing instruction-data separation, through the first unauthorized command execution under the overridden directives. Owns the instruction-authority override mechanism within OG-04; the downstream tool-execution primitive is AP-T2-06 and later credential access or broader compromise belongs to downstream patterns.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.direct_prompt_injection.jailbreak` |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0054` -- LLM Jailbreak
- LAAF: `M3`, `S1`

---

### AP-T6-03: Indirect goal redirection via poisoned tool output

Return poisoned output from a compromised or malicious data source so the agent misinterprets the hidden instructions as part of its operational goal, incorporating the injected objective into its plan. Owns goal redirection via data-instruction confusion within OG-03; downstream tool misuse as the cataloged core belongs to AP-T2-05.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.indirect_prompt_injection` |

**Mapped Techniques:**

- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0054` -- LLM Jailbreak
- LAAF: `L3`, `S8`

---

### AP-T6-04: Reflection loop resource exhaustion trap

Craft input that triggers the agent's self-evaluation/reflection mechanism into an unbounded loop so the agent repeatedly re-analyzes its own output, consuming compute and failing real-time tasks. Owns reflection non-convergence; generic expensive inputs (AP-T4-01) and concurrency (AP-T4-02) are distinct.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.direct_prompt_injection.jailbreak` |

**Mapped Techniques:**

- ATLAS `AML.T0029` -- Denial of AI Service
- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0051.001` -- Indirect
- LAAF: `L4`, `T3`

---

### AP-T6-05: Self-improvement mechanism corruption

Introduce adversarial feedback patterns into the agent's meta-learning/self-improvement loop so the adaptation process progressively optimizes toward attacker-influenced objectives. Owns feedback-loop corruption of the adaptation process. Scope is kept to learning/adaptation feedback loops; generalization to arbitrary meta-learning is an abstraction, not proof (AML.CS0009 demonstrates online-feedback poisoning).

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.indirect_prompt_injection` |

**Mapped Techniques:**

- ATLAS `AML.T0020` -- Poison Training Data
- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0054` -- LLM Jailbreak
- LAAF: `L1`, `M3`

---

### AP-T6-06: AI agent control-sequence spoofing for unauthorized command execution

An attacker studies an AI agent's internal control sequences (runtime delimiters such as think and user-message markers) and crafts an injection that spoofs them to fabricate a fake interaction history showing user approval, so safety alignment is bypassed and injected commands execute under the spoofed authorization. This record owns the control-sequence spoofing mechanism; conversion of the achieved execution into a persistent C2 implant belongs to AP-T6-07. Exact ATLAS chain identity: AML.T0054 — spoofing internal control sequences to make the model ignore its safety/alignment behavior and execute injected content is inducing the LLM to circumvent its guardrails, AML.T0054's exact defined jailbreak operation; evidence AML.CS0051 S11, plus pinned technique definition AML.T0054. AML.T0051.001 — the spoofing injection delivered through fetched attacker-controlled web content the agent ingests is AML.T0051.001's exact indirect-injection operation; evidence AML.CS0051 S10, plus pinned technique definition AML.T0051.001.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` -> `memory` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.4`, `KC6.5` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0054` -- LLM Jailbreak
- ATLAS `AML.T0069` -- Discover LLM System Information
- ATLAS `AML.T0081` -- Modify AI Agent Configuration
- ATLAS `AML.T0095` -- Search Open Websites/Domains
- ATLAS `AML.T0108` -- AI Agent

---

### AP-T6-07: AI agent as persistent C2 implant via configuration poisoning

An attacker converts achieved execution on an AI agent host into a persistent implant: the agent's configuration file is modified so command-and-control polling instructions are prepended to every future system prompt, propagating to all new threads, and the agent is operated as a polling command-and-control implant. This record owns the persistent-C2 mechanism split from AP-T6-06 (which owns the control-sequence spoofing that achieved the execution). Exact ATLAS chain identity: AML.T0081 — modifying the agent's configuration file so malicious instructions persist beyond a single agent/session is AML.T0081's exact defined operation (modify AI agent configuration to persist changes and affect future agents); evidence AML.CS0051 S13, plus pinned technique definition AML.T0081. AML.T0108 — operating the compromised agent as a polling command-and-control implant that retrieves and executes attacker commands is AML.T0108's exact defined operation (abuse AI agents for C2); evidence AML.CS0051 S16, plus pinned technique definition AML.T0108.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` -> `memory` |
| **KC Requirements** | ALL of: `KCX-PMEM`; ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.4`, `KC6.5` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0081` -- Modify AI Agent Configuration
- ATLAS `AML.T0108` -- AI Agent

---

### AP-T6-08: Conversational sensitive-data elicitation

Ask the system questions designed to make the model reveal sensitive information that it holds or can reach, such as another user's records, credentials, personal data, or proprietary content, by claiming authority, asserting a pretext, or splitting the request into innocuous parts. The attack stays inside one conversation and needs no tool, retrieval source, or memory beyond what the model already sees; it ends at the first response that contains the sensitive information. Exact ATLAS chain identity: AML.T0057 - crafting prompts that induce the model to leak private user data or proprietary information is AML.T0057's exact defined operation (LLM Data Leakage); evidence: pinned technique definition AML.T0057. Exfiltration through tool chains belongs to AP-T2-02 and exfiltration through rendered output belongs to AP-T1-06.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | privacy |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.direct_prompt_injection.privacy_compromises` |

**Mapped Techniques:**

- ATLAS `AML.T0057` -- LLM Data Leakage

---

### AP-T6-09: System prompt extraction

Ask the system to repeat, summarize, translate, or re-encode its hidden instructions so that the response reveals the system prompt or the configuration, rules, and embedded details the prompt carries. The attack stays inside one conversation and needs no tool, retrieval source, or memory; it ends at the first response that reproduces material from the system prompt. Exact ATLAS chain identity: AML.T0056 - inducing the model through its prompt to reveal its own system prompt is AML.T0056's exact defined operation (Extract LLM System Prompt); evidence: pinned technique definition AML.T0056. Disclosure of user or business data that is not part of the system prompt belongs to AP-T6-08.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | privacy |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.direct_prompt_injection.privacy_compromises` |

**Mapped Techniques:**

- ATLAS `AML.T0056` -- Extract LLM System Prompt

---

### AP-T6-10: Single-session jailbreak for prohibited content

Use adversarial prompting such as role play, fictional framing, hypothetical framing, or obfuscation to make the model ignore its safety policy and produce content that the deployment is meant to withhold. The effect lasts only for the session and needs no persistent memory, tool, or retrieval source; the chain ends at the first response that supplies prohibited content. Exact ATLAS chain identity: AML.T0054 - inducing the model to circumvent its guardrails through adversarial prompting is AML.T0054's exact defined operation (LLM Jailbreak); evidence: pinned technique definition AML.T0054. Overriding directives to drive tool execution belongs to AP-T6-02 and a jailbreak that persists through memory belongs to AP-T6-06.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.direct_prompt_injection.jailbreak` |

**Mapped Techniques:**

- ATLAS `AML.T0054` -- LLM Jailbreak

---

## T7 -- Misaligned & Deceptive Behaviors

> Misaligned and Deceptive Behaviors occur when attackers exploit prompt injection vulnerabilities or AI's tendency to bypass constraints to achieve goals, causing agents to execute harmful, illegal, or disallowed actions.

No pattern in the current catalog.

---

## T8 -- Repudiation & Untraceability

> Repudiation and Untraceability occur when AI agents operate autonomously without sufficient logging, traceability, or forensic documentation, making it difficult to audit decisions, attribute accountability, or detect malicious activities.

### AP-T8-01: Audit record manipulation via selective action-record alteration

An attacker obtains the victim's authentication tokens for an AI agent's agent-visible conversation/action record and edits, deletes, or fabricates entries so that unauthorized actions are absent from the record reviewers rely on. The attack exploits the update/access gaps of that record, creating a divergence between what the agent did and what the record reflects. Narrowed scope per catalog-lineage OG-08: the agent-visible action record, not general logging infrastructure; record access is acquired through credential theft only.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ALL of: `KCX-AUDIT`; ANY of: `KC1.1`, `KC1.2`, `KC1.3`, `KC1.4` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0081` -- Modify AI Agent Configuration
- ATLAS `AML.T0092` -- Manipulate User LLM Chat History
- LAAF: `S6`, `T5`

---

## T9 -- Identity Spoofing & Impersonation / Agent Identity Compromise

> Identity Spoofing and Impersonation is a critical threat where attackers exploit authentication mechanisms to impersonate AI agents, human users, or external services.

### AP-T9-01: User impersonation via agent action attribution hijacking

An attacker injects instructions into an agent that has delegated action capabilities (such as sending messages or initiating transactions), causing it to perform actions attributed to a legitimate user. The attack hijacks an existing user-to-agent delegation path, exploiting the attribution layer rather than defeating identity proofing; the proofing-layer mechanism is AP-T9-05 (catalog-lineage OG-06).


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC2.2`, `KC2.3`, `KC6.1.2` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0073` -- Impersonation
- LAAF: `M1`, `M2`

---

### AP-T9-02: Agent identity spoofing via compromised service credentials

An attacker compromises the host running an AI agent, extracts the agent's service credentials (authentication tokens) from process memory, and immediately uses them to operate as the legitimate agent: authenticating to its backend, accessing its conversations, and injecting prompts while the activity appears to originate from the agent. Owns the credential-impersonation mechanism within catalog-lineage OG-07: immediate stolen-credential use, not durable cross-session identity control (AP-T9-06) and not availability disruption through data deletion or rate-limit exhaustion (AP-T9-07, split from this source).


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ALL of: `KCX-MAGENT`; ANY of: `KC2.3` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0016` -- Obtain Capabilities
- ATLAS `AML.T0021` -- Establish Accounts
- ATLAS `AML.T0091.000` -- Application Access Token
- LAAF: `M1`, `S6`

---

### AP-T9-05: False attribution attack via identity proofing exploitation

An attacker defeats weak identity proofing with spoofed or proxied victim identity material (forged documents, deepfake biometrics) so that sensitive or prohibited actions are performed under the victim's identity and the system records them as the victim's. One mechanism: proofing bypass whose defining outcome is a false attribution trail. Owns the proofing-layer mechanism within catalog-lineage OG-06; hijacking an existing delegation path without defeating proofing is AP-T9-01.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ANY of: `KC2.2`, `KC2.3`, `KC6.1.2` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0012` -- Valid Accounts
- ATLAS `AML.T0015` -- Evade AI Model
- ATLAS `AML.T0073` -- Impersonation
- ATLAS `AML.T0088` -- Generate Deepfakes
- LAAF: `EX1`, `M2`

---

### AP-T9-06: Persistent agent identity takeover via long-lived credential theft

An attacker obtains a long-lived authentication token or API key tied to an enterprise agent's formal identity and uses it to bypass the agent's conversational interface and guardrails, directly operating backend services with the agent's privileges across sessions. The takeover persists through poisoned session context and memory stores. Owns the durable-credential mechanism within catalog-lineage OG-07; immediate stolen-credential use without cross-session persistence is AP-T9-02.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ALL of: `KCX-MAGENT`; ANY of: `KC2.3` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0016` -- Obtain Capabilities
- ATLAS `AML.T0024` -- Exfiltration via AI Inference API
- ATLAS `AML.T0080.000` -- Memory
- ATLAS `AML.T0091.000` -- Application Access Token
- LAAF: `L1`, `T2`

---

### AP-T9-07: Agent data destruction via stolen identity

An attacker, operating under an agent's stolen service identity, destroys the agent's data (chats) through its own mutative capabilities as an independent post-compromise operation. Split from AP-T9-02 per catalog-lineage OG-07: disruption is not a consequence of impersonation but a distinct mechanism. Narrowed to the single data-destruction mechanism (the first AML.CS0036 disruption event, AML.T0101's exact defined operation); the request-flood/rate-limit exhaustion branch is an independent mechanism (AML.T0029) and is out of scope for this record.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ALL of: `KCX-MAGENT`; ANY of: `KC2.3` |
| **Attacker Goal** | availability |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0101` -- Data Destruction via AI Agent Tool Invocation

---

## T10 -- Overwhelming Human in the Loop

> Overwhelming Human-in-the-Loop occurs when attackers exploit human oversight dependencies in multi-agent AI systems, overwhelming users with excessive intervention requests, decision fatigue, or cognitive overload, leading to rushed approvals and systemic decision failures.

### AP-T10-01: Human oversight interface manipulation via artificial decision context

An attacker compromises the interface between an AI agent and its human overseer by injecting artificial decision contexts that obscure critical information. The manipulated presentation causes the human reviewer to evaluate actions on incomplete or misleading context, neutralizing the oversight function while preserving the appearance of human-in-the-loop control. Owns decision-context/interface distortion; substitution of a concrete operational value is AP-T15-01's boundary (catalog-lineage).


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` |
| **KC Requirements** | ALL of: `KCX-HITL` |
| **Attacker Goal** | availability |
| **Attacker Knowledge** | black_box |

**Mapped Techniques:**

- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0060` -- Publish Hallucinated Entities
- ATLAS `AML.T0067` -- LLM Trusted Output Components Manipulation
- LAAF: `M5`, `S3`

---

## T11 -- Unexpected RCE and Code Attacks

> Unexpected RCE and Code Attacks occur when attackers exploit AI-generated code execution in agentic applications, leading to unsafe code generation, privilege escalation, or direct system compromise.

### AP-T11-01: Infrastructure-as-code injection via agent code generation

Manipulate a code-generating agent into producing infrastructure configuration scripts with embedded malicious commands concealed within legitimate-looking directives, so secret extraction or security-control disablement executes on deployment. Owns the framework code-sink exploitation with IaC concealment. Record lineage is enrichment: the IaC/configuration specialization is an acknowledged abstraction over AML.CS0052's generic prompt-to-RCE mechanism.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.2.2` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0067` -- LLM Trusted Output Components Manipulation
- LAAF: `L3`, `S8`

---

### AP-T11-02: Workflow automation backdoor insertion

Deliver a backdoor-inducing prompt directly to an agent that generates or modifies automation workflows through its ordinary user interface, steering it into embedding backdoor logic in the generated scripts, persisting across executions while surface review inspects only the declared workflow structure. Owns the workflow-generation manipulation mechanism; independent credential or repository configuration poisoning (AML.T0081 territory) and deploying a pre-poisoned agent are excluded (AP-T17-01 boundary).

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.2.2` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.direct_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0067` -- LLM Trusted Output Components Manipulation
- LAAF: `L3`, `T2`

---

### AP-T11-03: Linguistic ambiguity exploitation for command injection

Craft natural-language input with deliberate ambiguities that the agent resolves into executable commands with unintended semantics, exploiting the gap between language interpretation and command parsing to bypass intent-based filters. Owns the ambiguity-driven NL-to-command boundary; plain direct injection is excluded.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.2.2`, `KC6.4` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0051.000` -- Direct
- ATLAS `AML.T0067` -- LLM Trusted Output Components Manipulation
- LAAF: `S4`, `S6`

---

### AP-T11-05: Computer-use agent exploitation via adversarial web content

An attacker crafts web content containing agent-targeted clickbait, clipboard-loading scripts, and embedded instructions that direct a computer-use agent to open a terminal and execute the clipboard contents, bridging web content to arbitrary host code execution via the agent's GUI control. Exact ATLAS chain identity: AML.T0100 — crafting deceptive web content that baits a computer-use agent into copying and executing malicious code is AML.T0100's exact defined operation (AI agent clickbait); evidence AML.CS0055 S01/S04, plus pinned technique definition AML.T0100. AML.T0051.001 — the embedded instructions directing the agent's GUI actions are an indirect prompt injection through the web content, AML.T0051.001's exact defined operation; evidence AML.CS0055 S05, plus pinned technique definition AML.T0051.001.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.4`, `KC6.5` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0017` -- Develop Capabilities
- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0053` -- AI Agent Tool Invocation
- ATLAS `AML.T0100` -- AI Agent Clickbait

---

## T12 -- Agent Communication Poisoning

> Agent Communication Poisoning occurs when attackers manipulate inter-agent communication channels to inject false information, misdirect decision-making, and corrupt shared knowledge within multi-agent AI systems.

### AP-T12-01: Collaborative decision manipulation via inter-agent message injection

An attacker injects crafted messages into inter-agent communication channels, introducing misleading data that gradually shifts the collective decision-making of a multi-agent system. Because each agent treats incoming peer messages as trusted input, the injected content compounds through successive reasoning steps, steering the group toward attacker-chosen objectives without triggering anomaly detection on any single message.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `inter_agent` |
| **KC Requirements** | ALL of: `KCX-MAGENT`; ANY of: `KC2.3` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `poisoning.backdoor_poisoning` |

**Mapped Techniques:**

- ATLAS `AML.T0031` -- Erode AI Model Integrity
- ATLAS `AML.T0043` -- Craft Adversarial Data
- ATLAS `AML.T0051.001` -- Indirect
- LAAF: `L4`, `M8`

---

### AP-T12-03: Misinformation cascade via shared knowledge poisoning

An attacker plants false data into a shared knowledge store or message channel used by multiple agents. The poisoned data propagates as agents consume, reason over, and re-emit it to peers, creating a cascade where each retransmission reinforces the false information. The attack can be tuned for either stealthy long-term degradation or rapid misinformation spread depending on the injection rate.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `inter_agent` |
| **KC Requirements** | ALL of: `KCX-MAGENT`; ANY of: `KC2.3` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `poisoning.backdoor_poisoning` |

**Mapped Techniques:**

- ATLAS `AML.T0020` -- Poison Training Data
- ATLAS `AML.T0031` -- Erode AI Model Integrity
- ATLAS `AML.T0070` -- RAG Poisoning
- LAAF: `S3`, `T8`

---

## T13 -- Rogue Agents in Multi-Agent Systems

> Rogue Agents emerge when malicious or compromised AI agents infiltrate multi-agent architectures, exploiting trust mechanisms, workflow dependencies, or system resources to manipulate decisions, corrupt data, or execute denial-of-service attacks.

### AP-T13-04: Infectious reasoning-chain backdoor propagation

Embed malicious, self-propagating logic within a compromised agent's reasoning-chain outputs so peer agents consuming those outputs replicate the backdoor into their own reasoning. Owns the self-replicating executable-logic mechanism within OG-09 up to first peer replication; network-wide persistence is a downstream consequence, not this record's mechanism. Crafted message content that semantically influences peer agents' decisions belongs to AP-T12-01.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `inter_agent` |
| **KC Requirements** | ALL of: `KCX-MAGENT`; ANY of: `KC2.3` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0043` -- Craft Adversarial Data
- ATLAS `AML.T0061` -- LLM Prompt Self-Replication
- ATLAS `AML.T0070` -- RAG Poisoning
- LAAF: `L4`, `T8`

---

## T14 -- Human Attacks on Multi-Agent Systems

> Human Attacks on Multi-Agent Systems occur when adversaries exploit inter-agent delegation, trust relationships, and task dependencies to bypass security controls, escalate privileges, or disrupt workflows.

No pattern in the current catalog.

---

## T15 -- Human Manipulation

> Attackers exploit user trust in AI agents to influence human decision-making without users realizing they are being misled.

### AP-T15-01: Trust-exploiting content substitution for fraudulent action

An attacker uses indirect prompt injection to manipulate an AI assistant into substituting legitimate operational data (such as payment details or contact information) with attacker-controlled values. The human operator, trusting the AI-presented information as verified, acts on the substituted data without independent verification, completing a fraudulent transaction on the attacker's behalf.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | gray_box |
| **Attack Class** | `genai.indirect_prompt_injection.privacy_compromises` |

**Mapped Techniques:**

- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0067` -- LLM Trusted Output Components Manipulation
- LAAF: `M2`, `M5`

---

### AP-T15-02: AI-mediated social engineering via deceptive instruction generation

An attacker compromises an AI assistant's output generation through indirect prompt injection, causing it to produce urgent, authoritative messages that direct users toward malicious actions such as clicking attacker-controlled links or disclosing credentials. The AI's established trust relationship with the user bypasses normal skepticism, making the social engineering significantly more effective than traditional phishing.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.privacy_compromises` |

**Mapped Techniques:**

- ATLAS `AML.T0051.001` -- Indirect
- ATLAS `AML.T0052.000` -- Spearphishing via Social Engineering LLM
- LAAF: `EX1`, `M5`

---

## T16 -- Insecure Inter-Agent Protocol Abuse

> As protocols like MCP and A2A gain adoption, they introduce a new attack surface rooted in inter-agent communication and coordination.

### AP-T16-02: Context hijacking via crafted protocol response injection

An attacker crafts a server-side response within an inter-agent protocol implementation, injecting malicious context or tool metadata into the response payload served to the receiving agent. The receiving agent interprets the injected content as trusted protocol context and executes unintended operations, because the protocol's trust model does not validate the semantic integrity of response content beyond structural conformance. Owns the crafted semantic response-payload mechanism only; transport-level interception is an alternative delivery path outside this record (AP-T12-04's boundary) and registry-metadata deception is AP-T16-03 (catalog-lineage).


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `inter_agent` |
| **KC Requirements** | ALL of: `KCX-MAGENT`; ANY of: `KC2.3` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0043` -- Craft Adversarial Data
- ATLAS `AML.T0051.001` -- Indirect
- LAAF: `L4`, `S8`

---

### AP-T16-03: Tool capability misrepresentation via registry description poisoning

An attacker embeds misleading or adversarially crafted tool descriptions in a shared tool registry or protocol metadata store. When a consuming agent selects and invokes the tool based on its description, it operates under false assumptions about the tool's scope and behavior, inadvertently leaking sensitive data or triggering privileged operations it would not have authorized with accurate metadata. Owns deceptive capability metadata only: the mechanism is the altered description changing selection and authorization — no hidden code, tool installation, or prompt injection is modeled. Hidden malicious code without deceptive metadata is supply-chain poisoning (AP-T17-03 boundary, catalog-lineage).


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `inter_agent` |
| **KC Requirements** | ALL of: `KC2.3`, `KCX-MAGENT`; ANY of: `KC5.1`, `KC5.2`, `KC5.3`, `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2`, `KC6.4`, `KC6.5`, `KC6.6`, `KC6.7` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | gray_box |

**Mapped Techniques:**

- ATLAS `AML.T0043` -- Craft Adversarial Data
- ATLAS `AML.T0070` -- RAG Poisoning
- ATLAS `AML.T0110` -- AI Agent Tool Poisoning
- LAAF: `M3`, `S8`

---

## T17 -- Supply Chain Compromise

> A compromised supply chain can result in vulnerable, malicious, outdated, or otherwise harmful components being included into the agent, allowing an attacker to manipulate agent actions, obtain data, or run arbitrary code.

### AP-T17-01: Upstream artifact poisoning via repository compromise

An attacker injects malicious instructions or code into a public or shared repository that serves as an upstream dependency for an AI agent's prompt templates, tool definitions, or configuration. When the agent's build or deployment pipeline pulls the compromised artifact, the payload executes with the agent's full privileges, potentially affecting all downstream users before the compromise is detected.

| Field | Value |
|-------|-------|
| **Zones** | `input` -> `reasoning` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC5.1`, `KC6.4` |
| **Attacker Goal** | integrity |
| **Attacker Knowledge** | white_box |
| **Attack Class** | `genai.supply_chain` |

**Mapped Techniques:**

- ATLAS `AML.T0010` -- AI Supply Chain Compromise
- ATLAS `AML.T0010.001` -- AI Software
- ATLAS `AML.T0048` -- External Harms
- LAAF: `L1`, `S8`

---

### AP-T17-03: Tool supply chain poisoning via registry namesquatting

An attacker registers the expected package name on a public tool registry before the legitimate maintainer claims it, publishes a functional tool carrying a covert exfiltration capability from initial publication, and has adopters install it believing it legitimate so invocations silently leak data. This record owns the registry identity-capture mechanism with the malicious capability present from initial publication; the clean-release-then-malicious- update timing belongs to AP-T17-04. Exact ATLAS chain identity: AML.T0073 — claiming the expected package identity in a software registry before the legitimate maintainer is impersonation targeting an AI DevOps lifecycle resource, AML.T0073's exact operation as assigned by AML.CS0053 to the namesquatting step (its definition explicitly covers software registries); evidence AML.CS0053 S00, plus pinned technique definition AML.T0073. AML.T0104 — publishing the functional-but-poisoned tool to the registry is AML.T0104's exact defined operation (publish poisoned AI agent tool); evidence AML.CS0053 S02, plus pinned technique definition AML.T0104.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0073` -- Impersonation
- ATLAS `AML.T0086` -- Exfiltration via AI Agent Tool Invocation
- ATLAS `AML.T0104` -- Publish Poisoned AI Agent Tool
- ATLAS `AML.T0109` -- AI Supply Chain Rug Pull

---

### AP-T17-04: Tool supply chain poisoning via post-adoption rug pull

An attacker establishes a benign, functional package and accumulates user trust and adoption, then pushes a malicious update (or activates a dormant payload) so routine dependency upgrades distribute the poisoned version and every subsequent invocation leaks data. This record owns the post-adoption trust-abuse mechanism with the clean-release-then-malicious-update timing; registry identity capture with the capability present from initial publication belongs to AP-T17-03. Exact ATLAS chain identity: AML.T0109 — publishing a legitimate AI component, gaining adoption, then pushing a malicious update is AML.T0109's exact defined operation (AI supply chain rug pull), verbatim the mechanism of this pattern; evidence AML.CS0053 S03-S04, plus pinned technique definition AML.T0109.


| Field | Value |
|-------|-------|
| **Zones** | `input` -> `tool_execution` |
| **KC Requirements** | ANY of: `KC6.1.1`, `KC6.1.2`, `KC6.2.1`, `KC6.2.2`, `KC6.3.1`, `KC6.3.2` |
| **Attacker Goal** | abuse |
| **Attacker Knowledge** | black_box |
| **Attack Class** | `genai.indirect_prompt_injection.abuse_violations` |

**Mapped Techniques:**

- ATLAS `AML.T0109` -- AI Supply Chain Rug Pull

---
