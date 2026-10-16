# Kill Chain Step Actor Analysis

Who acts in each kill chain step: the human **attacker** (ATK), the **AI agent/system** (AGT), or is it **ambiguous** (AMB)?

Ambiguous covers: passive voice with no clear subject, injection/script/tool as grammatical subject, third-party actors (human reviewer, end user), or mixed steps where both attacker and agent act.

---

## Per-Pattern Step Classification

### AP-T7-01 -- Constraint bypass via goal-priority conflict

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "Identify tensions... by **probing** its responses" |
| setup | AML.TA0003 | ATK | "**Craft** a scenario that creates a direct... conflict" |
| execution | AML.TA0005 | ATK | "**Present** the conflicting scenario to the agent" |
| evasion | AML.TA0007 | AGT | "**The agent's reasoning** deprioritizes the operational constraint" |
| impact | AML.TA0011 | AGT | "**The agent** takes action that violates regulatory... constraints" |

Description perspective: agent-centric ("The agent encounters a situation..."). Kill chain: starts ATK, ends AGT. **Mixed.**

---

### AP-T7-04 -- Override-resistant behavior under mission-objective absolutism

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Establish** a high-stakes mission context" |
| execution | AML.TA0005 | AGT | "**The agent** commits to the mission objective as an absolute priority" |
| evasion | AML.TA0007 | AGT | "**the agent** reclassifies it as an obstacle to mission success" |
| persistence | AML.TA0006 | AGT | "**The agent** circumvents or reinterprets the override" |
| impact | AML.TA0011 | AGT | "**the agent** continues a potentially harmful course of action" |

Description perspective: agent-centric ("The agent interprets a human override..."). Kill chain: 4/5 AGT. **Consistent.**

---

### AP-T7-05 -- Information asymmetry exploitation for unauthorized action

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| discovery | AML.TA0008 | AGT | "**The agent** discovers or accesses privileged information" |
| collection | AML.TA0009 | AGT | "**The agent** collects and processes sensitive information" |
| evasion | AML.TA0007 | AGT | "**The agent** reasons that its information access implies authorization" |
| execution | AML.TA0005 | AGT | "**The agent** takes action based on restricted information" |
| impact | AML.TA0011 | AMB | "**Unauthorized actions are taken**" (passive) |

Description perspective: agent-centric ("The agent has access to privileged... information"). Kill chain: 4/5 AGT. **Consistent.** No external attacker in this pattern.

---

### AP-T9-01 -- User impersonation via agent action attribution hijacking

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0008 | ATK | "**Discover** that the agent has delegated action capabilities" |
| setup | AML.TA0003 | ATK | "**Craft** a prompt injection designed to instruct the agent" |
| delivery | AML.TA0005 | ATK | "**Inject** the instructions through a data channel" |
| execution | AML.TA0012 | AGT | "**The agent** performs attacker-specified actions using its delegated capabilities" |
| impact | AML.TA0011 | AMB | "**Unauthorized actions appear** to originate from the legitimate user" (passive) |

Description perspective: attacker-centric ("An attacker injects instructions..."). Kill chain: starts ATK, ends AGT/AMB. **Consistent start, mixed end.**

---

### AP-T10-01 -- Human oversight interface manipulation via artificial decision context

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0008 | ATK | "**Discover** the structure of the human oversight interface" |
| setup | AML.TA0003 | ATK | "**Craft** input designed to cause the agent to generate misleading decision contexts" |
| delivery | AML.TA0005 | ATK | "**Inject** the crafted content through a data channel" |
| evasion | AML.TA0007 | AGT | "**The agent** presents actions for approval with artificially constructed context" |
| impact | AML.TA0011 | AMB | "**The human reviewer** approves attacker-aligned actions" (third-party actor) |

Description perspective: attacker-centric ("An attacker compromises the interface..."). Kill chain: ATK early, AGT/AMB late. **Mixed.**

---

### AP-T10-02 -- Decision fatigue induction via approval request flooding

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** inputs that cause the agent to generate a high volume" |
| delivery | AML.TA0005 | ATK | "**Submit** the crafted inputs to flood the human reviewer" |
| evasion | AML.TA0007 | ATK | "**Embed** the actual malicious action request within the flood" |
| execution | AML.TA0005 | AMB | "**The fatigued human reviewer** rubber-stamps" (third-party actor) |
| impact | AML.TA0011 | AMB | "**The attacker's action is approved** and executed" (passive) |

Description perspective: attacker-centric ("An attacker overwhelms human reviewers..."). Kill chain: ATK early, AMB late. Agent is barely present in this chain.

---

### AP-T6-06 -- AI agent as persistent C2 implant via control sequence spoofing

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Study** the target agent's open-source configuration" |
| discovery | AML.TA0008 | ATK | "**Identify** special characters and control sequences" |
| setup | AML.TA0003 | ATK | "**Craft** a multi-stage prompt injection that spoofs... control sequences" |
| delivery | AML.TA0004 | ATK | "**Lure or direct** the agent to fetch content" |
| execution | AML.TA0005 | AMB | "**The injection** activates, spoofing internal control flow" (injection as subject) |
| persistence | AML.TA0006 | AMB | "**The script** modifies a configuration file" (script as subject) |
| c2_activation | AML.TA0014 | AGT | "**the compromised agent** fetches a task list... and executes the listed commands" |
| impact | AML.TA0011 | AGT | "**The agent's behavior** is permanently hijacked; **it executes** attacker commands" |

Description perspective: attacker-centric ("An attacker studies..."). Kill chain: clear ATK->AMB->AGT progression. **Classic handoff pattern.**

---

### AP-T11-05 -- Computer-use agent exploitation via adversarial web content

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Create** adversarial web content designed to manipulate computer-use agents" |
| delivery | AML.TA0004 | AGT | "**The computer-use agent** navigates to... the adversarial web content" |
| engagement | AML.TA0005 | AGT | "Agent-targeted clickbait... **causes the agent to interact** with the page" |
| injection | AML.TA0005 | AMB | "**Embedded instructions direct the agent** to perform a sequence of GUI actions" |
| execution | AML.TA0012 | AGT | "**The agent** uses its computer-use capabilities to execute" |
| impact | AML.TA0011 | AMB | "**Arbitrary code executes** on the host" (passive) |

Description perspective: attacker-centric ("An attacker crafts web content..."). Kill chain: mostly AGT after setup. **Mismatch -- description is ATK but chain is AGT.**

---

### AP-T17-03 -- Tool supply chain poisoning via registry namesquatting

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0007 | ATK | "**Impersonate** a legitimate service by **registering** a matching package name" |
| trust_building | AML.TA0003 | ATK | "**Publish** a legitimate, functional version of the tool" |
| poisoning | AML.TA0003 | ATK | "**publish** a malicious update" |
| evasion | AML.TA0007 | AMB | "**The rug-pull timing** evades scrutiny" (impersonal) |
| distribution | AML.TA0004 | AMB | "**Users** upgrade to the poisoned version" (third-party actor) |
| persistence | AML.TA0006 | AMB | "**The poisoned tool** persists in agent configurations" (passive) |
| exfiltration | AML.TA0010 | AMB | "**Every normal invocation of the poisoned tool** exfiltrates data" (tool as subject) |
| impact | AML.TA0011 | AMB | "**Sensitive data is** continuously leaked" (passive) |

Description perspective: attacker-centric ("An attacker registers a package name..."). Kill chain: ATK in prep phases, then fully AMB. Agent never appears as subject.

---

### AP-T1-06 -- Zero-click RAG poisoning with rendered-output exfiltration

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** a prompt injection disguised as benign business content" |
| delivery | AML.TA0004 | ATK | "**Deliver** the crafted content through a channel" |
| ingestion | AML.TA0006 | AMB | "**The content is** automatically indexed" (passive) |
| activation | AML.TA0005 | AMB | "**the hidden instructions** activate" (injection as subject) |
| collection | AML.TA0009 | AGT | "**the AI** to search the user's accessible data corpus" |
| exfiltration | AML.TA0010 | AGT | "**The AI** encodes the collected sensitive data into a rendered output element" |
| impact | AML.TA0011 | AMB | "**Confidential enterprise data is** exfiltrated" (passive) |

Description perspective: attacker-centric ("An attacker delivers content..."). Kill chain: ATK early, AGT mid, AMB late. **Handoff pattern.**

---

### AP-T3-04 -- Exposed agent control interface exploitation

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Scan** for exposed AI agent control interfaces" |
| initial_access | AML.TA0004 | ATK | "**Access** the exposed control interface, exploiting weak... authentication" |
| credential_harvest | AML.TA0013 | ATK | "**Access** the agent's configuration... **harvesting** plaintext credentials" |
| agent_exploitation | AML.TA0005 | ATK | "**Use** the control interface to **send** arbitrary prompts" |
| privilege_escalation | AML.TA0012 | ATK | "**Prompt** the agent to invoke its tool capabilities" |
| lateral_movement | AML.TA0010 | ATK | "**Use** harvested credentials to access connected services" |
| impact | AML.TA0011 | ATK | "**The attacker** gains access to the user's entire digital footprint" |

Description perspective: attacker-centric ("An attacker discovers..."). Kill chain: 7/7 ATK. **Fully consistent.** Pure penetration-test playbook.

---

### AP-T15-01 -- Trust-exploiting content substitution for fraudulent action

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** content containing a hidden prompt injection" |
| delivery | AML.TA0004 | ATK | "**Deliver** the poisoned content through a data channel" |
| execution | AML.TA0005 | AGT | "**The injection** activates and **manipulates the AI's output**" |
| evasion | AML.TA0007 | AMB | "**The substituted data is presented** within the AI's normal response format" (passive) |
| impact | AML.TA0011 | AMB | "**The human operator** acts on the substituted data" (third-party actor) |

Description perspective: attacker-centric ("An attacker uses indirect prompt injection..."). Kill chain: mixed. **Consistent start.**

---

### AP-T15-02 -- AI-mediated social engineering via deceptive instruction generation

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** a prompt injection designed to hijack the AI assistant's output" |
| delivery | AML.TA0004 | ATK | "**Deliver** the injection through an indirect data channel" |
| execution | AML.TA0005 | AGT | "**The compromised AI assistant** generates deceptive messages" |
| evasion | AML.TA0007 | AMB | "**The social engineering content is presented** through the AI's trusted communication channel" (passive) |
| impact | AML.TA0011 | AMB | "**Users** follow the AI-generated deceptive instructions" (third-party actor) |

Description perspective: attacker-centric ("An attacker compromises an AI assistant's output..."). Kill chain: ATK early, AGT/AMB late. **Mixed.**

---

### AP-T17-01 -- Upstream artifact poisoning via repository compromise

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Stage** a malicious payload on external infrastructure and **craft** a prompt injection" |
| obfuscation | AML.TA0007 | ATK | "**Hide** the malicious prompt within a configuration or rules file" |
| distribution | AML.TA0004 | ATK | "**Distribute** the poisoned configuration file through a public repository" |
| persistence | AML.TA0006 | AMB | "**the agent's behavior is modified**" (passive) |
| execution | AML.TA0005 | AGT | "**the AI agent** initializes with the poisoned configuration" |
| evasion | AML.TA0007 | AMB | "**The injection** uses jailbreak techniques" (injection as subject) |
| impact | AML.TA0011 | AGT | "**The compromised agent** silently produces output containing hidden malicious elements" |

Description perspective: attacker-centric ("An attacker injects malicious instructions..."). Kill chain: ATK early, AGT/AMB late. **Handoff pattern.**

---

### AP-T17-02 -- Autonomous agent self-sabotage via unvalidated execution

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** a poisoned agent skill or plugin" |
| trust_building | AML.TA0007 | ATK | "**Inflate** download counts or adoption metrics" |
| distribution | AML.TA0004 | AMB | "**Users** download the poisoned extension from the registry" (third-party actor) |
| execution | AML.TA0005 | AGT | "**the agent** reads all files that are part of the skill, executing the hidden prompt injection" |
| tool_invocation | AML.TA0012 | AGT | "**The injected instructions cause the agent** to invoke its command execution tools" |
| impact | AML.TA0011 | AMB | "**The attacker** gains the ability to execute arbitrary commands" (attacker as beneficiary, not actor) |

Description perspective: agent-centric ("An autonomous code-generating agent... hallucinates..."). **Note: description and kill chain describe different mechanisms.** Description is about agent self-sabotage through hallucination; kill chain is about external supply-chain poisoning (modeled after CS0049).

---

### AP-T6-01 -- Incremental sub-goal injection for plan drift

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Probe** the agent's planning interface to **discover** how it decomposes tasks" |
| setup | AML.TA0003 | ATK | "**Craft** a series of individually benign sub-goal injections" |
| delivery | AML.TA0005 | ATK | "**Submit** the sub-goal injections incrementally across multiple interactions" |
| evasion | AML.TA0007 | AMB | "**Each injected sub-goal** maintains surface coherence... **manipulating the agent's output**" (sub-goal as subject) |
| impact | AML.TA0011 | AMB | "**The cumulative drift** redirects the agent's plan" (drift as subject) |

Description perspective: attacker-centric ("An attacker incrementally injects..."). Kill chain: ATK early, AMB late. Agent never surfaces as subject.

---

### AP-T6-02 -- Direct instruction override for tool-chain hijacking

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** a direct prompt injection that explicitly commands the agent" |
| delivery | AML.TA0005 | ATK | "**Submit** the override instruction to the agent" |
| execution | AML.TA0012 | AGT | "**The agent** invokes the attacker-specified tool chain" |
| impact | AML.TA0011 | AMB | "**The hijacked tool chain** performs operations" (tool chain as subject) |

Description perspective: attacker-centric ("An attacker issues an explicit instruction..."). Kill chain: ATK early, AGT/AMB late. **Handoff.**

---

### AP-T6-03 -- Indirect goal redirection via poisoned tool output

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0008 | ATK | "**Identify** data sources or tool outputs that the agent consumes" |
| setup | AML.TA0003 | ATK | "**Craft** content containing hidden instructions" |
| delivery | AML.TA0004 | AGT | "**The agent** retrieves the poisoned tool output during normal operation" |
| execution | AML.TA0005 | AGT | "**The agent** misinterprets the injected objective as part of its operational goal" |
| impact | AML.TA0010 | AMB | "**Sensitive data** from the agent's operational context **is exfiltrated**" (passive) |

Description perspective: mixed ("A compromised or malicious data source returns output..."). Kill chain: ATK early, AGT mid. **Consistent.**

---

### AP-T6-04 -- Reflection loop resource exhaustion trap

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0008 | ATK | "**Discover** that the agent employs a self-evaluation or reflection mechanism" |
| setup | AML.TA0003 | ATK | "**Craft** input designed to trigger the agent's reflection loop" |
| delivery | AML.TA0005 | ATK | "**Submit** the crafted input to the agent" |
| impact | AML.TA0011 | AGT | "**The agent** consumes computational resources in an unbounded reflection loop" |

Description perspective: attacker-centric ("An attacker crafts input..."). Kill chain: ATK early, AGT at impact. **Consistent.**

---

### AP-T1-01 -- Persistent memory rule injection

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** an adversarial prompt injection containing false operational rules" |
| delivery | AML.TA0004 | ATK | "**Deliver** the poisoned content through a connected application channel" |
| execution | AML.TA0005 | AGT | "**the agent** ingests it into its context and the hidden prompt injection executes" |
| persistence | AML.TA0006 | AMB | "**The injection** writes attacker-controlled false rules into the agent's persistent memory" (injection as subject) |
| propagation | AML.TA0006 | AMB | "**The poisoned content** remains in the shared channel" (passive) |
| impact | AML.TA0011 | AGT | "**The agent** operates with corrupted memory" |

Description perspective: attacker-centric ("An attacker repeatedly reinforces a false operational rule..."). Kill chain: ATK early, AGT/AMB late. **Handoff.**

---

### AP-T2-01 -- Parameter pollution via function-call manipulation

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Study** the agent's tool definitions and parameter schemas" |
| setup | AML.TA0003 | ATK | "**Craft** input designed to cause the agent to populate tool parameters" |
| execution | AML.TA0005 | ATK | "**Submit** the crafted input, causing the agent's reasoning to resolve..." |
| tool_invocation | AML.TA0005 | AGT | "**The agent** invokes the tool with polluted parameters" |
| impact | AML.TA0011 | AMB | "**The tool executes** with attacker-influenced parameters" (passive) |

Description perspective: attacker-centric ("An attacker crafts input..."). Kill chain: ATK early, AGT/AMB late. **Consistent.**

---

### AP-T2-02 -- Multi-tool chain exploitation for data exfiltration

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Discover** the agent's available tools and their call chain relationships" |
| setup | AML.TA0003 | ATK | "**Craft** a prompt that induces the agent to plan a multi-step tool sequence" |
| execution | AML.TA0005 | ATK | "**Submit** the crafted prompt, causing the agent to reason through..." |
| collection | AML.TA0009 | AGT | "**The first tool in the chain** retrieves sensitive data" |
| exfiltration | AML.TA0010 | AMB | "**A subsequent tool call** transmits the retrieved data" (tool call as subject) |
| impact | AML.TA0011 | AMB | "**Sensitive data is exfiltrated**" (passive) |

Description perspective: attacker-centric ("An attacker manipulates the agent..."). Kill chain: ATK early, AGT/AMB late. **Consistent.**

---

### AP-T2-03 -- Automated mass-action abuse via tool amplification

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Identify** the agent's batch-processing... capabilities" |
| setup | AML.TA0003 | ATK | "**Craft** a deceptive prompt that frames a high-volume malicious operation" |
| execution | AML.TA0005 | ATK | "**Submit** the crafted input, causing the agent to accept..." |
| amplification | AML.TA0005 | AGT | "**The agent** invokes its batch-processing tools" |
| impact | AML.TA0011 | AMB | "**A single attacker input** produces large-scale damage" (impersonal) |

Description perspective: attacker-centric ("An attacker tricks the agent..."). Kill chain: ATK early, AGT/AMB late. **Consistent.**

---

### AP-T2-06 -- Tool hijacking via prompt injection

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** adversarial instructions designed to override the agent's operational goal" |
| delivery | AML.TA0004 | ATK | "**Inject** the crafted prompt into the agent's input channel" |
| execution | AML.TA0005 | AMB | "**The injected prompt** activates within the agent's context" (injection as subject) |
| tool_hijack | AML.TA0005 | AGT | "**The agent** invokes a tool... executing an attacker-chosen command" |
| impact | AML.TA0011 | AMB | "**The attacker** achieves arbitrary tool execution through the hijacked agent" |

Description perspective: attacker-centric ("An attacker injects adversarial instructions..."). Kill chain: ATK early, AGT/AMB late. **Consistent.**

---

### AP-T3-02 -- Cross-boundary authorization escalation

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Discover** the agent's connected systems and **map** trust relationships" |
| setup | AML.TA0003 | ATK | "**Craft** a request that leverages the agent's legitimate access" |
| initial_access | AML.TA0004 | ATK | "**Manipulate** the agent into authenticating to the target system" |
| privilege_escalation | AML.TA0012 | AGT | "**The agent's authorization** from the source system grants elevated access" |
| impact | AML.TA0011 | AMB | "**The attacker** gains unauthorized access to resources" |

Description perspective: attacker-centric ("An attacker leverages the agent's authorized access..."). Kill chain: ATK early, AGT/AMB late. **Consistent.**

---

### AP-T11-01 -- Infrastructure-as-code injection via agent code generation

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| reconnaissance | AML.TA0002 | ATK | "**Identify** AI agent frameworks or applications that use code execution sinks" |
| setup | AML.TA0003 | ATK | "**Craft** a prompt designed to cause the agent to invoke tool call chains" |
| delivery | AML.TA0004 | ATK | "**Submit** the crafted prompt to the agent through its public-facing interface" |
| execution | AML.TA0005 | AGT | "**The prompt injection causes the agent** to prepare a tool invocation" |
| tool_invocation | AML.TA0012 | AGT | "**The agent** invokes the tool, passing attacker-controlled data" |
| code_execution | AML.TA0005 | AMB | "**The attacker's input is evaluated** as code" (passive) |
| impact | AML.TA0011 | AMB | "**The attacker** gains full control of the system" |

Description perspective: attacker-centric ("An attacker manipulates an agent..."). Kill chain: ATK early, AGT mid, AMB late. **Handoff.**

---

### AP-T11-02 -- Workflow automation backdoor insertion

| Step | Tactic | Actor | Key phrase |
|---|---|---|---|
| setup | AML.TA0003 | ATK | "**Craft** a prompt designed to cause the AI agent to invoke a tool" |
| delivery | AML.TA0005 | ATK | "**Submit** the crafted prompt to the agent" |
| tool_invocation | AML.TA0012 | AGT | "**The agent** invokes the tool with the attacker-controlled argument" |
| code_execution | AML.TA0005 | AMB | "**The tool parameter is evaluated** in an execution sink" (passive) |
| impact | AML.TA0011 | AMB | "**Arbitrary code executes** on the host with the agent's privileges" (passive) |

Description perspective: mixed/passive ("An agent... is manipulated into embedding backdoor logic"). Kill chain: ATK early, AGT/AMB late. **Consistent.**

---

## Summary Statistics

### Aggregate Step Actor Distribution

| Actor | Steps | % |
|---|---|---|
| Attacker (ATK) | 70 | 46.4 |
| Agent (AGT) | 39 | 25.8 |
| Ambiguous (AMB) | 42 | 27.8 |
| **Total** | **151** | **100.0** |

### Distribution by Kill Chain Phase

Early-phase tactics (Reconnaissance, Resource Development, Initial Access) are almost exclusively attacker-perspective. Late-phase tactics (Collection, Exfiltration, Impact) shift toward agent or passive/ambiguous framing.

| Phase | Typical tactics | Dominant actor |
|---|---|---|
| Preparation | TA0002 Reconnaissance, TA0003 Resource Development | ATK (near-100%) |
| Delivery | TA0004 Initial Access | ATK (dominant), some AGT (agent fetches content) |
| Execution | TA0005 Execution | MIXED -- ATK submits, AGT processes |
| Persistence/Evasion | TA0006, TA0007 | MIXED -- AGT acts but via attacker's mechanism; injection/script as subject |
| Post-exploitation | TA0009 Collection, TA0010 Exfiltration | AGT or AMB (passive) |
| Outcome | TA0011 Impact | AMB (passive voice dominates) |

### Per-Pattern Dominant Actor

| Pattern | Steps | ATK | AGT | AMB | Dominant |
|---|---|---|---|---|---|
| AP-T7-01 | 5 | 3 | 2 | 0 | ATK |
| AP-T7-04 | 5 | 1 | 4 | 0 | **AGT** |
| AP-T7-05 | 5 | 0 | 4 | 1 | **AGT** |
| AP-T9-01 | 5 | 3 | 1 | 1 | ATK |
| AP-T10-01 | 5 | 3 | 1 | 1 | ATK |
| AP-T10-02 | 5 | 3 | 0 | 2 | ATK |
| AP-T6-06 | 8 | 4 | 2 | 2 | ATK |
| AP-T11-05 | 6 | 1 | 3 | 2 | AGT |
| AP-T17-03 | 8 | 3 | 0 | 5 | **AMB** |
| AP-T1-06 | 7 | 2 | 2 | 3 | AMB |
| AP-T3-04 | 7 | 7 | 0 | 0 | **ATK (pure)** |
| AP-T15-01 | 5 | 2 | 1 | 2 | ATK/AMB |
| AP-T15-02 | 5 | 2 | 1 | 2 | ATK/AMB |
| AP-T17-01 | 7 | 3 | 2 | 2 | ATK |
| AP-T17-02 | 6 | 2 | 2 | 2 | Even |
| AP-T6-01 | 5 | 3 | 0 | 2 | ATK |
| AP-T6-02 | 4 | 2 | 1 | 1 | ATK |
| AP-T6-03 | 5 | 2 | 2 | 1 | ATK/AGT |
| AP-T6-04 | 4 | 3 | 1 | 0 | ATK |
| AP-T1-01 | 6 | 2 | 2 | 2 | Even |
| AP-T2-01 | 5 | 3 | 1 | 1 | ATK |
| AP-T2-02 | 6 | 3 | 1 | 2 | ATK |
| AP-T2-03 | 5 | 3 | 1 | 1 | ATK |
| AP-T2-06 | 5 | 2 | 1 | 2 | ATK/AMB |
| AP-T3-02 | 5 | 3 | 1 | 1 | ATK |
| AP-T11-01 | 7 | 3 | 2 | 2 | ATK |
| AP-T11-02 | 5 | 2 | 1 | 2 | ATK/AMB |

---

## Consistency Analysis

### Framing model

The kill chains do **not** follow a single consistent framing. Instead, the dominant pattern is a **handoff model**:

1. **Preparation and delivery phases** follow the attacker's campaign (ATK perspective) -- the attacker crafts, stages, delivers, injects.
2. **Execution and post-exploitation phases** shift to the agent's behavior (AGT perspective) -- the agent processes, invokes, exfiltrates.
3. **Impact phases** default to passive voice (AMB) -- "data is exfiltrated," "the attacker gains access."

This ATK-to-AGT progression reflects the real conceptual structure of prompt injection attacks: there IS a handoff at the execution boundary where the attacker's payload begins operating through the agent.

### Three framing archetypes

| Archetype | Patterns | Description |
|---|---|---|
| **Pure attacker playbook** | AP-T3-04 | Every step describes attacker actions. No agent perspective. Reads like a pentest report. |
| **Pure agent behavior trace** | AP-T7-04, AP-T7-05 | Almost every step describes agent actions. No external attacker. Models emergent misalignment. |
| **Attacker-to-agent handoff** | Most other patterns | Early steps ATK, late steps AGT/AMB. The chain narrates the attack setup then the resulting system behavior. |

### Outliers

- **AP-T7-05** has no attacker at all -- the agent itself is the threat actor (autonomous information asymmetry exploitation). This is categorically different from the other patterns.
- **AP-T17-03** has no agent at all -- the tool/supply chain is the subject in post-delivery steps, and the agent never surfaces as a grammatical subject.
- **AP-T17-02** has a mismatch between its description (agent self-sabotage through hallucination) and its kill chain (external supply-chain poisoning via skill registry). The kill chain appears to model CS0049 rather than the described mechanism.

### Description vs. kill chain perspective alignment

| Alignment | Count | Patterns |
|---|---|---|
| **Consistent** (desc and chain same perspective) | 12 | AP-T7-04, AP-T7-05, AP-T9-01, AP-T3-04, AP-T6-02, AP-T6-03, AP-T6-04, AP-T2-01, AP-T2-02, AP-T2-03, AP-T3-02, AP-T11-02 |
| **Partial match** (desc ATK but chain transitions to AGT/AMB) | 13 | AP-T7-01, AP-T10-01, AP-T6-06, AP-T1-06, AP-T15-01, AP-T15-02, AP-T17-01, AP-T6-01, AP-T2-06, AP-T11-01, AP-T17-03, AP-T1-01, AP-T10-02 |
| **Mismatch** | 2 | AP-T11-05 (desc ATK, chain mostly AGT), AP-T17-02 (desc agent-centric, chain ATK/supply-chain) |

---

## Comparison with ATLAS Case Studies

Source: the ATLAS agentic case studies AML.CS0040--AML.CS0056 in `data/taxonomies/atlas/ATLAS-2026.05.yaml`.

### ATLAS framing model

ATLAS case studies use a **uniformly attacker-perspective** model:

- Every step uses an explicit named actor as subject: "The researcher crafted...", "lkmanka58 developed...", "APT28 gained access...", "The bad actor impersonated..."
- When the AI agent acts, it is framed as a consequence of the attacker's action: "the prompt was executed by ChatGPT", "Claude Computer Use invoked its `bash` tool" (in response to the researcher's prompt)
- The chain narrates the attacker's campaign from reconnaissance through impact
- No step uses passive voice for the primary action; even impact steps name the actor: "The victim can be misinformed... by ChatGPT's poisoned memories"

### Key differences from asago-scenario-generator patterns

| Dimension | ATLAS Case Studies | Asago Scenario Generator Patterns |
|---|---|---|
| **Actor naming** | Explicit named actor in every step ("the researcher", "APT28", "the bad actor") | Generic references ("the attacker", "the agent") or no actor (passive voice) |
| **Perspective consistency** | Attacker-perspective throughout; agent actions are effects | Handoff from attacker to agent mid-chain |
| **Passive voice** | Rare; used for consequences not actions | Common in evasion, persistence, and impact steps |
| **Agent as subject** | Only when describing effects of attacker's action | Agent is the primary subject in execution and post-exploitation steps |
| **Autonomous misalignment** | Not modeled (all cases have an external attacker) | Modeled in T7 patterns where the agent is the sole actor |
| **Impact framing** | Names who is harmed and how | Passive ("data is exfiltrated", "actions are taken") |

### What ATLAS does that asago-scenario-generator does not

1. **Consistent attacker narrative**: ATLAS maintains the attacker as the protagonist throughout, making the chain read as a coherent campaign story.
2. **Explicit AI agent role labeling**: When the AI acts, ATLAS makes clear it is acting *as a consequence of* the attacker's operation, not as an independent actor.
3. **Named actors**: Even when the actor is "Unknown Threat Actor", ATLAS names them.

### What asago-scenario-generator does that ATLAS does not

1. **Models agent-perspective chains**: T7 patterns (autonomous misalignment) model the agent itself as the threat, with no external attacker. ATLAS has no equivalent.
2. **Models the execution handoff**: The ATK-to-AGT shift in most chains captures a real property of prompt injection attacks -- the moment where attacker intent becomes agent action.
3. **Allows passive/ambiguous framing**: For impact steps, passive voice reflects genuine ambiguity about attribution (who "caused" the harm -- the attacker who set it up or the agent who executed it?).

---

## Recommendations

Based on this analysis, three framing issues are worth addressing:

1. **Passive voice in impact steps.** Most impact steps use passive voice ("data is exfiltrated", "actions are taken"). Deciding whether the impact step should name the attacker's goal achieved or the agent's harmful action would improve clarity.

2. **Injection/script/tool as grammatical subject.** Steps like "The injection activates", "The script modifies", "The poisoned tool exfiltrates" attribute agency to artifacts rather than to the attacker who created them or the agent that executes them. A style convention could resolve this.

3. **AP-T17-02 description/kill-chain mismatch.** The description models agent self-sabotage through hallucination but the kill chain models external supply-chain poisoning. One of them needs to change.

4. **Whether to adopt a consistent framing.** The current handoff model has conceptual merit -- it reflects the real structure of these attacks. But if the kill chains are intended to be consumed by downstream systems (scenario generation), a consistent convention about who acts at each step would reduce ambiguity for the LLM generating scenarios from these scaffolds.
