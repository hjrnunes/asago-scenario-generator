# STPA-led product data flow

Asago has one normal scenario-generation workflow. Taxonomy supplies reviewed
risks, mappings, qualification evidence, and obligations; STPA owns all
scenario authoring.

## End-to-end `generate`

```mermaid
flowchart LR
    UC[Use case] --> PREP[Deterministic preparation]
    RISKS[Reviewed risks] --> PREP
    MAPS[Pinned taxonomy mappings] --> PREP
    FACTS[Qualification facts] --> PREP
    CATALOG[Attack-pattern catalog] --> PREP

    PREP --> OBL[Phase 1 obligation plan]
    UC --> SP1[STPA SP1 baseline]
    OBL --> CONSIDER[Consider every obligation]
    SP1 --> CONSIDER
    CONSIDER --> REVISION{Upstream STPA gap?}
    REVISION -->|eligible| BOUNDED[At most one additive revision]
    REVISION -->|no| FINAL[Final STPA analysis]
    BOUNDED --> RECHECK[One complete recheck]
    RECHECK --> FINAL

    FINAL --> SP2[STPA SP2 unsafe control actions]
    SP2 --> ICA[STPA ICA and causal analysis]
    ICA --> SP3[STPA SP3 scenario production]
    SP3 --> SCENARIOS[Generated scenarios]

    OBL --> ACCOUNT[Obligation accounting]
    ICA --> ACCOUNT
    SCENARIOS --> REALIZE[Scenario realization]
    ACCOUNT --> REALIZE

    REALIZE --> REPORT[STPA synthesis report]
```

An obligation is a question STPA must consider. It does not prescribe an
attack sequence or force scenario creation.

## Main inputs and outputs

| Boundary | Inputs | Outputs |
|---|---|---|
| Preparation | use case, reviewed risks, taxonomy mappings, capability profile/facts, attack-pattern catalog | typed projection evidence and pins |
| Phase 1 | prepared taxonomy evidence | `taxonomy-obligation-plan.yaml` |
| STPA baseline and consideration | use case, capability profile, obligation briefs | loss analysis, control structure, obligation consideration |
| Bounded revision | explicit upstream gaps | preserved baseline plus at most one additive revision and final recheck |
| STPA scenario production | final loss/control/ICA authority | STPA scenario artifacts and scenario handoff |
| Accounting | every obligation and final ICA evidence | `obligation-accounting.yaml`, `scenario-realization.yaml` |

## Command boundary

```mermaid
flowchart TB
    CLI[asago-scenario-generator]
    CLI --> RUN[run: normal product workflow]

    RUN --> SYN[pipeline.synthesis]
    SYN --> STPA[STPA SP1 / SP2 / SP3]
    SYN --> PHASES[obligations, accounting, realization]

    OLD[Retired taxonomy generator]
    OLD -. no CLI or import path .-> CLI
```

`generate` is the only scenario-generation command. The retired
taxonomy generator cannot be invoked through the CLI and has no remaining
scenario-authoring implementation.

## Historical artifact audit

Old manifest-v3 taxonomy runs may be parsed for explicit audit. That boundary
is read-only:

```mermaid
flowchart LR
    OLD[Historical run directory] --> READ[Manifest and inventory readers]
    READ --> VALIDATE[Integrity checks]
    VALIDATE --> RESULT[Audit result]
    READ -. cannot write, resume, or generate .-> OLD
```
