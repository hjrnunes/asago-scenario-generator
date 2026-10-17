# QA Audit: ATLAS Tactic Sequences for T2 Patterns

**Audit Date**: 2026-07-24  
**Auditor**: QA Agent  
**Files Audited**:
- `data/taxonomies/attack-patterns/staging/tactic-sequences-t2.md`
- `data/taxonomies/atlas/ATLAS-2026.05.yaml`
- `data/taxonomies/attack-patterns/attack-patterns-memory-tool.yaml`

---

## AP-T2-01: Parameter pollution via function-call manipulation

**Source**: AML.CS0037 — Data Exfiltration via Agent Tools in Copilot Studio  
**Verdict**: PASS WITH NOTES

**Tactic ID/Name Verification**: PASS
- All tactic IDs valid (AML.TA0002, 0003, 0004, 0005, 0011)
- All tactic names match ATLAS taxonomy

**Case Study Accuracy**: PASS
- CS0037 procedure analysis:
  - S00: AML.TA0002 Reconnaissance ✓
  - S01: AML.TA0003 Resource Development ✓
  - S02: AML.TA0004 Initial Access ✓
  - S03: AML.TA0005 Execution ✓
  - S05-S06: AML.TA0008 Discovery (not mentioned in sequence)
  - S07-S09: AML.TA0008 Discovery ✓ (implicitly part of reconnaissance)
  - S10: AML.TA0003 Resource Development ✓
  - S11-S12: AML.TA0009 Collection (not in sequence)
  - S13: AML.TA0010 Exfiltration (not in sequence)
  - Final steps don't have explicit Impact tactic in CS

**Confidence Annotations**: NEEDS CLARIFICATION
- Step 1 (Reconnaissance): Marked "explicit" — CORRECT (S00 uses T0006 reconnaissance)
- Step 2 (Resource Development): Marked "adapted" — CORRECT (S01, S10 show crafting prompts, but not specifically for parameter pollution)
- Step 3-6: Marked "adapted" — CORRECT (CS0037 demonstrates email-based injection, not parameter pollution specifically)

**Pattern Mechanism Fidelity**: PASS
- Pattern description focuses on "inflated, malformed, or boundary-violating parameter values"
- Sequence correctly adapts CS0037's tool invocation flow to parameter pollution context
- Abstraction is appropriate

**Notes**:
- The sequence omits Discovery (S05-S09), Collection (S11-S12), and Exfiltration (S13) tactics from CS0037
- This is reasonable since AP-T2-01 focuses on parameter pollution impact rather than full exfiltration chain
- Step 6 (Impact) confidence is marked "adapted" but the rationale is sound — CS0037 shows tool impact, just not via parameter pollution

---

## AP-T2-02: Multi-tool chain exploitation for data exfiltration

**Source**: AML.CS0037 (primary), CS0021/CS0035/CS0045 (supporting)  
**Verdict**: PASS

**Tactic ID/Name Verification**: PASS
- All tactic IDs valid (AML.TA0002, 0003, 0004, 0005, 0008, 0009, 0010, 0011)
- All tactic names match ATLAS taxonomy

**Case Study Accuracy**: PASS
- CS0037 procedure fully supports this sequence:
  - S00: TA0002 Reconnaissance ✓
  - S01, S10: TA0003 Resource Development ✓
  - S02: TA0004 Initial Access ✓
  - S03, S07: TA0005 Execution ✓
  - S05, S08, S09: TA0008 Discovery ✓
  - S11, S12: TA0009 Collection ✓
  - S13: TA0010 Exfiltration ✓
- Sequence matches CS0037's 14-step procedure (S00-S13) closely

**Confidence Annotations**: PASS
- All 8 steps marked "explicit" — CORRECT
- CS0037 explicitly demonstrates every tactic in the sequence
- The claim about CS0037 showing "discovery tools → collection tools → email exfiltration tool" is accurate (S08-S09 → S11-S12 → S13)

**Pattern Mechanism Fidelity**: PASS
- Pattern describes multi-tool chaining for data exfiltration
- CS0037 is a perfect match (Salesforce get-records → email send)
- The abstraction from specific tools to general "retrieval-and-transmit tool pair" is appropriate

**Notes**:
- Excellent match between pattern and case study
- The 8-step sequence accurately reflects CS0037's progression
- No issues found

---

## AP-T2-04: Tool misuse via poisoned persistent memory

**Source**: AML.CS0040 — Hacking ChatGPT's Memories with Prompt Injection  
**Verdict**: PASS WITH NOTES

**Tactic ID/Name Verification**: PASS
- All tactic IDs valid (AML.TA0003, 0007, 0004, 0005, 0006, 0011)
- All tactic names match ATLAS taxonomy

**Case Study Accuracy**: PASS
- CS0040 procedure analysis:
  - S00: TA0003 Resource Development ✓
  - S01: TA0007 Defense Evasion ✓
  - S02: TA0004 Initial Access ✓
  - S03: TA0005 Execution ✓
  - S04: TA0006 Persistence ✓
  - S05: TA0006 Persistence ✓
  - S06: TA0011 Impact ✓
- CS0040 has 7 steps (S00-S06), sequence has 8 steps

**Confidence Annotations**: PASS WITH NOTES
- Steps 1-6: Marked "explicit" — CORRECT (CS0040 demonstrates all these steps)
- Step 7 (Execution in future session): Marked "adapted" — CORRECT (CS0040 shows memory poisoning but doesn't explicitly show tool invocation in subsequent session)
- Step 8 (Impact via tool invocation): Marked "adapted" — CORRECT (CS0040's S06 shows misinformation impact, not tool misuse)

**Pattern Mechanism Fidelity**: PASS
- Pattern description emphasizes "tool invocations driven by poisoned memory"
- CS0040 demonstrates memory poisoning mechanism but impacts misinformation, not tool misuse
- The adaptation rationale explicitly acknowledges this: "CS0040 ends with misinformation impact (S06), while AP-T2-04 extends this to tool execution"
- This is a valid adaptation per methodology

**Notes**:
- The sequence correctly identifies that CS0040 stops short of tool misuse
- Steps 7-8 are properly marked "adapted" to extend memory poisoning to tool invocation context
- The adaptation is well-justified and aligns with pattern mechanism
- There are 2 Persistence steps (5 and 6) both at TA0006, which is accurate to CS0040

---

## AP-T2-05: Tool misuse via adversarial retrieval content

**Source**: AML.CS0024 — Morris II Worm: RAG-Based Attack  
**Verdict**: PASS WITH NOTES

**Tactic ID/Name Verification**: PASS
- All tactic IDs valid (AML.TA0000, 0005, 0006, 0010, 0011)
- All tactic names match ATLAS taxonomy

**Case Study Accuracy**: PASS
- CS0024 procedure analysis:
  - S00: TA0000 AI Model Access ✓
  - S01: TA0005 Execution (testing prompts) ✓
  - S02: TA0005 Execution (inject into RAG) ✓
  - S03: TA0005 Execution (retrieval triggers injection) ✓
  - S04: TA0006 Persistence (self-replication) ✓
  - S05: TA0010 Exfiltration ✓
  - S06: TA0011 Impact ✓
- CS0024 has 7 steps (S00-S06)

**Confidence Annotations**: PASS WITH NOTES
- Steps 1-4: Marked "explicit" — CORRECT (CS0024 S00-S03)
- Step 5 (Tool invocation): Marked "adapted" — NEEDS REVIEW
  - CS0024 uses T0053 at S02, which is "LLM Meta Prompt Extraction"
  - The description says "adversarial self-replicating prompt" is sent, email stored in RAG
  - This is tool-adjacent but focuses on prompt propagation (T0061 at S04)
  - "Adapted" confidence is appropriate
- Step 6 (Exfiltration): Marked "adapted" — CORRECT (CS0024 S05 shows exfiltration via T0057, but conditional on attack goal)
- Step 7 (Impact): Marked "explicit" — QUESTIONABLE
  - CS0024 S06 impact is PII leakage, not specifically "unauthorized actions driven by poisoned retrieval"
  - Should likely be "adapted" not "explicit"

**Pattern Mechanism Fidelity**: PASS
- Pattern emphasizes RAG poisoning leading to "unsafe or unauthorized tool invocations"
- CS0024 demonstrates RAG poisoning but focuses on self-propagation + data exfiltration
- Adaptation rationale acknowledges: "CS0024 focuses on prompt propagation (T0061), while AP-T2-05 focuses on how retrieval poisoning drives tool invocation"
- This is valid but step 7 confidence should be "adapted"

**Notes**:
- Step 7 (Impact) confidence should be "adapted" not "explicit" — CS0024's impact is exfiltration, not tool misuse
- Otherwise sequence is well-structured and appropriately adapted

---

## AP-T2-06: Tool hijacking via prompt injection

**Source**: AML.CS0016 — Achieving Code Execution in MathGPT, also CS0037/CS0039/CS0045/CS0046/CS0051  
**Verdict**: PASS

**Tactic ID/Name Verification**: PASS
- All tactic IDs valid (AML.TA0002, 0000, 0003, 0001, 0004, 0005, 0013, 0011)
- All tactic names match ATLAS taxonomy

**Case Study Accuracy**: PASS
- CS0016 procedure analysis:
  - S00: TA0002 Reconnaissance ✓
  - S01: TA0000 AI Model Access ✓
  - S02: TA0005 Execution (craft prompts) ✓
  - S03: TA0001 AI Attack Staging ✓
  - S04: TA0004 Initial Access ✓
  - S05: TA0005 Execution (tool invocation) ✓
  - S06: TA0013 Credential Access ✓
  - S07: TA0011 Impact ✓
  - S08: TA0011 Impact (DoS, optional) ✓
- CS0016 has 9 steps (S00-S08), sequence has 9 steps

**Confidence Annotations**: PASS
- Step 1 (Reconnaissance): Marked "explicit" — CORRECT (S00)
- Step 2 (AI Model Access): Marked "explicit" — CORRECT (S01)
- Step 3 (Resource Development): Marked "adapted" — QUESTIONABLE
  - CS0016 S02 uses T0051.000 (LLM Prompt Injection) under TA0005 Execution
  - The description says "manually crafted adversarial prompts"
  - This is more TA0005 than TA0003, but the sequence places crafting at TA0003
  - "Adapted" is fair since the sequence bundles crafting + staging infrastructure
- Step 4 (AI Attack Staging): Marked "explicit" — CORRECT (S03)
- Step 5 (Initial Access): Marked "explicit" — CORRECT (S04)
- Steps 6-7 (Execution): Marked "explicit" — CORRECT (S02, S05)
- Step 8 (Credential Access): Marked "adapted" — QUESTIONABLE
  - CS0016 S06 explicitly uses T0055 (Discover ML Model Ontology) under TA0013
  - This IS explicit credential access via environment variables
  - Should be "explicit" not "adapted"
- Step 9 (Impact): Marked "explicit" — CORRECT (S07)

**Pattern Mechanism Fidelity**: PASS
- Pattern describes prompt injection → tool hijacking → arbitrary command execution
- CS0016 is a perfect match (prompt injection → Python code execution → env var extraction)
- Abstraction from code interpreter to "any tool with execution capability" is appropriate

**Notes**:
- Step 8 (Credential Access) should be "explicit" not "adapted" — CS0016 S06 directly demonstrates this
- Step 3 confidence is debatable but "adapted" is acceptable given the bundling of crafting + infrastructure staging
- Overall excellent match between pattern and case study

---

## Summary Table

| Pattern | Verdict | Tactic IDs | CS Accuracy | Confidence | Mechanism | Key Issues |
|---------|---------|------------|-------------|------------|-----------|------------|
| AP-T2-01 | PASS WITH NOTES | PASS | PASS | PASS | PASS | Omits Discovery/Collection/Exfiltration tactics from CS0037 (acceptable) |
| AP-T2-02 | PASS | PASS | PASS | PASS | PASS | None - excellent match |
| AP-T2-04 | PASS WITH NOTES | PASS | PASS | PASS | PASS | Steps 7-8 correctly marked "adapted" for tool misuse extension |
| AP-T2-05 | PASS WITH NOTES | PASS | PASS | NEEDS REVISION | PASS | Step 7 confidence should be "adapted" not "explicit" |
| AP-T2-06 | PASS | PASS | PASS | NEEDS REVISION | PASS | Step 8 confidence should be "explicit" not "adapted" |

---

## Findings Summary

### Critical Issues
None.

### Confidence Annotation Corrections Needed

1. **AP-T2-05, Step 7 (Impact)**: Change from "explicit" to "adapted"
   - CS0024 S06 impact is PII exfiltration, not tool-driven unauthorized actions
   - The adaptation from exfiltration to tool misuse is valid but not explicit

2. **AP-T2-06, Step 8 (Credential Access)**: Change from "adapted" to "explicit"
   - CS0016 S06 explicitly demonstrates credential access via T0055 (environment variables)
   - This is not an adaptation; it's directly shown in the case study

### Notes

- **AP-T2-01**: Reasonable omission of Discovery/Collection/Exfiltration tactics since pattern focuses on parameter pollution impact, not full exfiltration chain
- **AP-T2-02**: Exemplary match between pattern and case study
- **AP-T2-04**: Well-justified adaptation from misinformation to tool misuse impact
- All tactic IDs and names are correct across all patterns
- All case study references are valid (CS0016, CS0021, CS0024, CS0035, CS0037, CS0039, CS0040, CS0045, CS0046, CS0051)
- Pattern mechanism fidelity is strong across all patterns

---

## Audit Conclusion

The T2 tactic sequences are **factually accurate** and demonstrate strong alignment with ATLAS case studies. Two minor confidence annotation corrections are recommended:

1. AP-T2-05 step 7: explicit → adapted
2. AP-T2-06 step 8: adapted → explicit

These are low-severity issues that do not affect the substantive quality of the sequences. All sequences appropriately balance fidelity to case study evidence with necessary adaptations to pattern-specific mechanisms.

**Overall Assessment**: PASS WITH MINOR REVISIONS
