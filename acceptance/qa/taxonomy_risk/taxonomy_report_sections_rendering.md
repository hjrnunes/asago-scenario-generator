# End-to-end QA: taxonomy/risk HTML report section rendering

## Boundary

Exercise only the public taxonomy-and-risk report command:

```bash
uv run asago-scenario-generator report \
  --output-dir <completed-run-directory> \
  --output <temporary-directory>/report.html
```

Do not import project modules and do not call `generate_report`,
`build_threat_surface_section`, or any other project API. Keep the suite
offline; no LLM endpoint is involved. Use disposable copies of
authoritative completed run fixtures whose manifest inventories and
hashes match their artifacts. `--output` must be outside the run
directory.

Inspect the command's stdout, stderr, exit status, and the published
`report.html`. Verify visible text in a browser; verify CSS-class-level
claims (status badges, active/inactive chips, highlight markers,
placeholder styling) and document order directly in `report.html`
source. The report file is the user-visible output, not a project API.

## Fixture records

Provide one completed taxonomy-and-risk run fixture per workflow (or
per variant inside a workflow) containing exactly the artifacts the
case needs, each listed in a `completed` manifest with matching hashes:

- `capability-profile.yaml` — zones, flags, confidence, entry points,
  tool inventory, external integrations, completeness levels,
  evidence lists, `kc_subcodes` as needed;
- `threat-surface.yaml` — `entries` and `governance_only` lists as
  needed, each entry carrying `risk_card`, `owasp_llm_ids`,
  `agentic_threat_ids`, `attack_pattern_ids`;
- one or more `scenarios/*.yaml` — each must carry the typed
  `validation.semantic.corpus_claim_applicability` records the report
  generator requires (copy them from an authoritative fixture); plus
  `faceting.taxonomy_chain`, `faceting.capability_profile`,
  `actor_profile`, `priority`, `narrative`, `attack_tree`,
  `attack_complexity_assessment`, `scenario_seed_metadata`,
  `candidate_filter`, and `technique_scope_evidence` as each case
  needs;
- `scenarios/*.feature` files beside scenario YAMLs for the behavior
  spec and ATLAS-techniques cases;
- `coverage-gaps.json` (with `coverage_gaps`, `coverage_universe`,
  `coverage_summary`, `coverage_plan`) for the coverage cases;
- `run-manifest.yaml` (with `seeds_generated`, `funnel`,
  `scenarios_generated`, `scenarios_failed`, `config`,
  `timestamp_start`, `timestamp_end`) for the run-summary cases, and
  absent for the omission case;
- `calls.jsonl` (pipeline-level calls with `semantic_evidence`) for
  the pipeline-calls case;
- `scenarios/calls.jsonl` (per-scenario call log; each line carries a
  `scenario_id` plus `call`, usage metrics, prompts, and `success` /
  `error`) for the per-scenario LLM-calls case;
- `coverage-gaps.json` may also carry `coverage_summary` (with
  `covered_feasible`, `policy_exclusions`, `selection_limitations`,
  and the other category lists) and `coverage_plan` (with
  `schema_version` and `targets`) for the categorized-summary case;
- raw copies of a `.yaml` and a `.feature` file for the highlighting
  case (the report loads raw files from the manifest inventory the
  same way it loads every other artifact);
- `eval-scorecard.yaml` only where a case needs scorecard data; the
  scorecard cases already covered by the taxonomy-report-rendering
  suite are not repeated here.

Note that scenario-minimal cases (only a scenario ID) still need the
typed validation records: corpus-claim reconciliation is report-gate
plumbing, not optional report content.

Zone fields in fixture YAML use canonical names (`input`, `reasoning`,
`tool_execution`, `memory`, `inter_agent`) or legacy integer zone IDs
1–5; the report renders display names. The threat surface entries for
the outcomes case must list the same `agentic_threat_ids` as the
scenarios they should count.

## Workflows

### QA-TRSR-01: capability profile composites render

1. Fixture: capability-profile.yaml with active zones
   `[input, tool_execution]`, `has_persistent_memory: true`,
   `multi_agent: false`, `hitl: true`, `confidence: high`,
   entry points `[{name: ze-query, direction: input},
   {name: ze-rag, direction: bidirectional}]`, tool inventory
   `[{name: Web search, tool_id: tool-web}]`, external integrations
   `[{name: OAuth IdP, integration_id: int-oidc}]`,
   `entry_point_completeness: confirmed`,
   `entry_point_evidence: [use-case.md]`,
   `tool_inventory_completeness: partial`,
   `kc_subcodes: [KC6.1.1]`. No scenarios needed beyond corpus-claim
   plumbing.
2. Run `report` and open `report.html`.

**Expected:** Exit `0`. The `Capability Profile` section carries the
badge `Schneider 5-Zone`; `Input Surfaces` renders with the
`zone-chip active` class and `Planning & Reasoning` with
`zone-chip inactive`; the flags render `Memory` with `flag-dot on`,
`Multi-Agent` with `flag-dot off`, and `Confidence: High`; entry
points show name with the `ep-direction` arrows `←` (title `input`)
and `↔` (title `bidirectional`); the tool row shows `Web search` and
`tool-web`; the integration row shows `OAuth IdP` and `int-oidc`;
completeness rows show `Confirmed` with evidence `use-case.md` and
`Partial`; the KC sub-code badge `KC6.1.1` renders.

### QA-TRSR-02: empty profile inventories degrade honestly

1. Fixture: capability-profile.yaml with only
   `zones_active: [input]`; no entry points, tool inventory,
   integrations, evidence, or completeness values.
2. Run `report`.

**Expected:** Exit `0`. The profile shows `No tools inventoried`,
`No external integrations inventoried`, and `No evidence sources
recorded`; no `Entry Points` row renders.

### QA-TRSR-03: actionable and governance-only entries are distinct

1. Fixture: threat-surface.yaml with one actionable entry for
   `atlas-phishing` (`Spear phishing`, confidence `0.85`, LLM IDs
   `[LLM01]`, threats `[T6]`, patterns `[AP-T6-01]`) and one
   governance-only entry for `atlas-copyright` (`Copyright
   compliance`, no mappings).
2. Run `report`.

**Expected:** The `Threat Surface` badge shows `1 actionable / 1
governance`; the `atlas-phishing` row shows the `ACT` badge and the
values `Spear phishing`, `0.85`, `LLM01`, `T6`, `AP-T6-01`; the
`atlas-copyright` row shows the `GOV` badge; the governance row
renders `-` for the LLM IDs, agentic threats, and attack patterns
cells.

### QA-TRSR-04: empty threat surface renders placeholders

1. Fixture: threat-surface.yaml with empty `entries` and
   `governance_only`.
2. Run `report`.

**Expected:** The `Threat Surface` badge shows `0 actionable / 0
governance`; the flow diagram panel shows `No actionable entries to
visualize.` (Sankey placeholder).

### QA-TRSR-05: outcomes column counts scenarios by priority

1. Fixture: one scenario `scn-a` with threats `[T6]` and priority
   composite `0.85`; threat surface entry for `atlas-phishing` with
   agentic threats `[T6]`.
2. Run `report`.

**Expected:** The threat surface table has an `Outcomes` column; the
`atlas-phishing` row shows `1 scenarios` with the high chip `1 high`.

### QA-TRSR-06: full coverage renders every card covered

1. Fixture: coverage-gaps.json with empty `coverage_gaps` and
   `coverage_universe.completeness: confirmed_complete`,
   `coverage_universe.evidence_refs: [operator-confirmation.md]`.
2. Run `report`.

**Expected:** The `Coverage Analysis` badge is `Full Coverage`; all
four cards (`Entry Points`, `Active Zones`, `In-Scope Threats`,
`Attack Patterns`) show the `Covered` status; the section shows the
four empty-state messages (`All confirmed entry points have scenario
coverage.`, `All active zones are traversed by scenarios.`, `All
in-scope threats have scenario coverage.`, `All in-scope attack
patterns have scenario coverage.`); the universe card shows
`Confirmed Complete` with evidence `operator-confirmation.md`; the
sidebar links to `Coverage Analysis`.

### QA-TRSR-07: coverage gaps render counts, tiers, attributions

1. Fixture: coverage-gaps.json with 3 uncovered entry points (each a
   `{name, entry_point_id}` dict, one of them `ze-query` attributed
   `deterministic_rule_rejection`), 1 uncovered zone, 2 uncovered
   threats, no uncovered attack patterns; `coverage_universe` with 2
   feasible targets and 1 excluded target.
2. Run `report`.

**Expected:** The `Coverage Analysis` badge is `6 gaps`; the Entry
Points card shows `3 gaps` and lists `ze-query` with the attribution
`rejected by deterministic rules`; Active Zones shows `1 gap`; In-Scope
Threats shows `2 gaps`; the universe grid shows the `Feasible Targets
(2)` and `Excluded Targets (1)` cards.

### QA-TRSR-08: threat-technique matrix and roster render

1. Fixture: two scenarios `scn-a` (threat `[T6]`, seed
   `AP-T6-01`, techniques `[AML.T0015]`, pinned `AML.T0015`/`Phishing`,
   actor `cybercriminal`/`advanced`) and `scn-b` (threat `[T11]`,
   seed `AP-T11-01`, techniques `[AML.T0015, AML.T0040]`, pinned
   `AML.T0040`/`LLM Data Leakage`, actor `nation-state`/`expert`).
2. Run `report`.

**Expected:** The `Threat–Technique Matrix` badge shows `2/17
threats`, `2 techniques`, `2 scenarios`; the matrix cell for threat
`T6` × technique `AML.T0015` shows count `1` linking to
`#scenario-scn-a`; the cell for `T11` × `AML.T0040` shows count `1`
linking to `#scenario-scn-b`; the roster row `scn-a` shows threat
`T6`, attack pattern `AP-T6-01`, technique `AML.T0015`, actor type
`Cybercriminal`, capability `Advanced`; the roster row `scn-b` shows
the mirrored values with `Nation State` and `Expert`.

### QA-TRSR-09: matrix degrades when techniques are absent

1. Fixture: one scenario `scn-a` with threat `[T6]`, seed
   `AP-T6-01`, no ATLAS techniques, no pinned technique.
2. Run `report`.

**Expected:** The matrix badge shows `1/17 threats`, `0 techniques`,
`1 scenarios`; no technique column headers render; the roster row
`scn-a` shows attack pattern `AP-T6-01` with an empty technique cell.

### QA-TRSR-10: actor diversity, monotone warning, goals

1. Fixture: three scenarios, each `actor_profile.actor_type:
   cybercriminal`, `capability_level: advanced`,
   `goal_category_parent: integrity`.
2. Run `report`.

**Expected:** The `Actor Profile Distribution` badge is `1 type`; the
`Cybercriminal` bar shows count `3` and `100%`; the warning banner
reads `Low actor diversity: 100% of scenarios use the Cybercriminal
actor type.`; the `Goal Category Distribution` block shows
`Integrity` with count `3` and badge `1 category`.

### QA-TRSR-11: priority signals grid renders six values

1. Fixture: one scenario with priority composite `0.72` and signals
   `{technique_maturity: realized, risk_impact: critical,
   risk_likelihood: high, attack_complexity: medium,
   architecture_match: explicit, structural_exposure: elevated}`.
2. Run `report`.

**Expected:** The card shows a `signals-grid` with the six labels
`Technique Maturity`, `Risk Impact`, `Risk Likelihood`, `Attack
Complexity`, `Architecture Match`, `Structural Exposure`; the values
render title-cased (`Realized`, `Critical`, `High`, `Medium`,
`Explicit`, `Elevated`).

### QA-TRSR-12: signals grid omitted when absent

1. Fixture: one scenario with no `priority.signals`.
2. Run `report`.

**Expected:** The card renders no `signals-grid` (`Priority Signals`
tab remains and is empty).

### QA-TRSR-13: actor profile block with BDI and access

1. Fixture: one scenario with `actor_profile` of type
   `malicious-insider`, capability `advanced`, goal `Sell stolen
   data`, beliefs/desires/intentions/resources lists, and `access`
   with `ingress_mode: network`, `initial_entry_point_id:
   ze-query`, `influence_source: helpdesk`.
2. Run `report`.

**Expected:** The Actor Profile tab shows chips `Malicious Insider`,
`Advanced`, `Sell Stolen Data`; the block shows the four BDI items
verbatim; the `ACCESS PROVENANCE:` block shows ingress `network` and
entry point `ze-query`.

### QA-TRSR-14: actor profile block omitted when absent

1. Fixture: one scenario without `actor_profile`.
2. Run `report`.

**Expected:** The Actor Profile tab renders no actor-profile content
(no `BELIEFS:` marker, no type chip).

### QA-TRSR-15: attack tree node shapes

For each variant below, build the fixture, run `report`, and inspect
the Attack Tree tab:

1. OR root `Gain access` with two leaf children carrying techniques
   `AML.T0015` and `AML.T0040`.
2. AND root `Open safe` with two leaf children carrying techniques
   `AML.T0015` and `AML.T0040`.
3. A single leaf node `Exfiltrate data` with no children and no
   technique.
4. No `attack_tree.root`.

**Expected:** In 1, an OR gate summary (`gate-or`) contains exactly
two `tree-leaf` nodes and both technique badges appear in
`tree-meta` spans. In 2, an AND gate summary (`gate-and`) wraps the
same two-leaf shape inside a `<details open>` gate node and both
technique badges appear. In 3, exactly one leaf node renders and no
gate summary (`gate-and`/`gate-or`) appears. In 4, no tree node
markup (no `tree-leaf`, no nested `<details open>`) renders; only
the `Goal:` line remains.

### QA-TRSR-16: unresolved tree resource IDs render honestly

1. Fixture: one scenario whose attack tree has a leaf node with
   `action.kind: tool_invocation`, `action.tool_id: tool-code`, and
   another leaf node with `action.kind: initial_ingress`,
   `action.entry_point_id: ze-gone`, `zone: input`. The capability
   profile is empty.
2. Run `report`.

**Expected:** The Attack Tree tab shows the leaf meta `Tool:
Unresolved` with code `tool-code` and `Entry Point: Unresolved` with
code `ze-gone`.

Note: resolved resource names require canonical computed IDs (derived
from name/direction/controllability via the domain), which the CLI-only
boundary of this suite cannot author without importing project
modules. The resolved-name path is therefore not pinned here; see the
open questions.

### QA-TRSR-17: scenarios dashboard and cards

1. Fixture: `scn-a` (composite `0.85`, title `Phishing the support
   desk`) and `scn-b` (composite `0.35`, title `Exfiltrate via
   RAG`).
2. Run `report`.

**Expected:** The dashboard shows `2 In Report`, `1 High Priority`,
`0 Medium Priority`, `1 Low Priority`, `0 Coverage Gaps`; both
cards render with their IDs and titles; cards sort high first.

### QA-TRSR-18: minimal scenario card keeps every tab

1. Fixture: one scenario providing only its scenario ID (plus the
   required validation records).
2. Run `report`.

**Expected:** The card renders with priority badge `LOW` and score
`0.00`; all nine tab labels render (`Provenance`, `Generation
Inputs`, `Actor Profile`, `ATLAS Techniques`, `Narrative`, `Attack
Tree`, `Behavior Spec`, `Priority Signals`, `LLM Calls`); no zone
crumbs render.

### QA-TRSR-19: empty scenarios placeholder

1. Fixture: a completed run with no scenario artifacts.
2. Run `report`.

**Expected:** The Scenarios section shows `No scenarios generated.`;
the report contains no `Threat–Technique Matrix` section
(`<h2>Threat&ndash;Technique Matrix</h2>` absent) and no `Actor
Profile Distribution` section (its `sec-diversity` heading and
sidebar link are absent).

### QA-TRSR-20: run summary funnel, stats, config

1. Fixture: one scenario; run-manifest.yaml with
   `seeds_generated: 12`, `funnel: {expanded_instances: 10,
   filter_submitted: 6, filter_accepted: 3}`,
   `scenarios_generated: 4`, `scenarios_failed: 1`,
   `config: {model: gemma-3-27b, temperature: 0.7}`,
   `timestamp_start: 2026-08-24T10:00:00`,
   `timestamp_end: 2026-08-24T10:05:30`.
2. Run `report`.

**Expected:** The Run Summary funnel shows `12 Seeds Generated`, `10
Candidates Expanded`, `3 Candidates Accepted`, `4 Scenarios
Generated`, `1 In Report`; the stats show `1 Failed`, `3 Rejected`,
rejection rate `30.0%`, duration `5m 30s`; the config block shows
`gemma-3-27b`, `0.7`, `2026-08-24T10:00:00`, and
`2026-08-24T10:05:30`.

### QA-TRSR-21: run summary omitted without manifest

1. Fixture: no run-manifest artifact (and no other artifact
   requiring it).
2. Run `report`.

**Expected:** No `Run Summary` section renders and the sidebar shows
no Run Summary link.

### QA-TRSR-22: run summary honest absence values

1. Fixture: run-manifest.yaml with no funnel, no config, and no
   timestamps.
2. Run `report`.

**Expected:** The section renders with rejection rate `N/A`, model
`unknown`, temperature `N/A`, start `N/A`, end `N/A`.

### QA-TRSR-23: raw data YAML and Gherkin highlighting

1. Fixture: a raw `.yaml` file containing a comment line, a key
   with a quoted string value, a number, a boolean, and a null; a
   raw `.feature` file containing a comment, a `@smoke` tag, a
   `Feature:` line, and a `Given` step.
2. Run `report`.

**Expected:** The `Raw Data` badge is `2 files`; the YAML panel
shows `yaml-comment`, `yaml-key` (`completeness`), `yaml-number`
(`3`), `yaml-bool` (`true`), and `yaml-null` (`null`) spans, and the
quoted value `"confirmed"` renders with no highlight class (quote
characters are entity-escaped before the value classifier runs, so
quoted strings never receive a `yaml-string` class); the Gherkin
panel shows `gherkin-comment`, `gherkin-tag` (`@smoke`), and
`gherkin-keyword` spans for `Feature:` and `Given`.

### QA-TRSR-24: generation inputs block

1. Fixture: one scenario with seed metadata (attack pattern name
   `Prompt injection`, threat `T6` / `Social engineering`), taxonomy
   chain ATLAS techniques `[AML.T0015]`, narrative title `Phish the
   desk`, no narrative summary.
2. Run `report`.

**Expected:** The Generation Inputs tab shows call headers `Call 0:
Actor Profile` and `Call 3: Behavior Spec`; the `Attack pattern` row
shows `Prompt injection`; the `Threat` row shows `T6 —
Social engineering`; the `ATLAS techniques` row shows `AML.T0015`;
the `Narrative summary` row shows the em dash `—`.

### QA-TRSR-25: behavior spec rendering and degradation

1. Fixture: scenario `scn-a` with a feature file containing `Given a
   precondition`, `When the event occurs`, `Then the outcome holds`;
   scenario `scn-b` with no feature file.
2. Run `report`.

**Expected:** The Behavior Spec tab of `scn-a` renders the three
step keywords with their texts; the tab of `scn-b` shows `No
behavior specification available.`

### QA-TRSR-26: ATLAS techniques block and none placeholder

1. Fixture: one scenario with taxonomy-chain ATLAS techniques
   `[AML.T0015]` and `technique_scope_evidence` with
   `scenario_classification_ids: [AML.T0015]` and no
   `projected_step_mapping_ids`.
2. Run `report`.

**Expected:** The ATLAS Techniques tab shows the heading `Scenario
classifications` with a badge containing `AML.T0015`, and the
heading `Projected-step mappings` with the muted `none` placeholder.

### QA-TRSR-27: attack complexity assessment

1. Fixture: one scenario with `attack_complexity_assessment` at
   `rule_version: 3`, `candidate_lower_bound.required_level:
   advanced`, `final.required_level: expert`, and one reason with
   `rule_id: R-7`, detail `requires chaining three tools`, evidence
   `[{kind: projection, ref_id: R7}]`.
2. Run `report`.

**Expected:** The Actor Profile tab shows `ATTACK COMPLEXITY (RULE
V3):`; the block shows `Candidate lower bound` as `Advanced` and
`Final required level` as `Expert`; the reason line reads `R-7 →
expert: requires chaining three tools [projection:R7]` (reason
levels render as recorded, not title-cased).

### QA-TRSR-28: attack complexity omitted when absent

1. Fixture: one scenario with no `attack_complexity_assessment`.
2. Run `report`.

**Expected:** The Actor Profile tab shows no `ATTACK COMPLEXITY`
block.

### QA-TRSR-29: pipeline call logs and semantic status

1. Fixture: `calls.jsonl` with an accepted `candidate_filter` call
   (100 prompt tokens) whose `semantic_evidence` records
   `accepted_draft_digest` and a final attempt result `accepted`;
   and a `capability_profile` call (50 prompt tokens) whose
   `semantic_evidence` records a final attempt result `invalid`.
2. Run `report`.

**Expected:** The `Pipeline LLM Calls` section shows `2 call(s)`,
`150 prompt tokens`, `60 completion tokens`, `40ms total`; the
accepted entry shows `Candidate Filter semantic draft: Accepted
provider semantics`; the rejected entry shows `Capability Profile
semantic draft: Rejected: invalid`.

### QA-TRSR-30: deterministic repository gates and output hygiene

1. Confirm the live-model opt-in is unset and no LLM endpoint is
   reachable.
2. Run the documented commands in order:

   ```bash
   ./scripts/quality.sh
   ./scripts/acceptance.sh
   uv run pytest tests/ -q
   ```

3. Run `git status --short --untracked-files=all`.

**Expected:** Quality, acceptance, and unit gates pass deterministically
offline, and no generated acceptance IR, coverage, mutation workspaces,
or temporary QA captures are newly tracked or staged.

### QA-TRSR-31: behavior spec headers, tags, docstrings, And steps, zone
badges

1. Fixture: one scenario `scn-a` whose feature file carries a
   `@smoke` tag, a `Scenario: Phish the desk` header, a
   `Given access through (Zone input)` step, an `And escalate
   privileges` step, and a triple-quoted docstring `requires a
   compromised credential`.
2. Run `report`.

**Expected:** The Behavior Spec tab of `scn-a` renders the
`Scenario:` keyword header with `Phish the desk`; the `And` step
keyword with `escalate privileges`; the `Given` step text `access
through (Zone input)` with a `zone-badge` for `Input Surfaces`
(canonical zone `input`); a `step-docstring` div containing
`requires a compromised credential`; and no `@smoke` tag text
anywhere in the tab (tag lines are skipped).

### QA-TRSR-32: per-scenario LLM call entries

1. Fixture: one scenario `scn-a`; `scenarios/calls.jsonl` with two
   entries tagged `scenario_id: scn-a`: `actor_profile` (100 prompt,
   40 completion, 250ms, success) and `behavior_spec` (30 prompt, 10
   completion, 80ms, `success: false`, `error: timeout`), each with
   system and user prompts.
2. Run `report`.

**Expected:** The LLM Calls tab of `scn-a` shows the summaries
`Call 0: Actor Profile (100 prompt / 40 completion tokens, 250ms)`
and `Call 1: Behavior Spec (30 prompt / 10 completion tokens, 80ms)
FAILED: timeout`; the system and user prompts render in
`call-log-pre` blocks.

### QA-TRSR-33: categorized coverage summary, plan, not-confirmed
universe

1. Fixture: coverage-gaps.json with empty gap lists, a
   `coverage_universe` whose `completeness` is absent (or
   `not_applicable`) and with no `evidence_refs`; `coverage_summary`
   with `covered_feasible: [AP-T6-01]`, one `selection_limitations`
   item (`ze-query`, reason `selection_limitation`, detail
   `candidate queue saturated`, candidate_ids `[cand-42]`), one
   `policy_exclusions` item (`ze-license`, reason `out_of_scope`);
   `coverage_plan` with `schema_version: 1` and one target
   (`ze-query`, primary candidate `cand-42`, state `planned`,
   ordered choices `cand-42`, `cand-7`).
2. Run `report`.

**Expected:** The `Coverage Analysis` badge is `Known Targets
Covered`; the Entry Points card shows the not-confirmed empty
message (`All identified feasible entry points have scenario
coverage; inventory completeness is not confirmed.`) alongside the
three standard covered messages; the summary renders a `Covered
Feasible Targets` card containing `AP-T6-01`; a `Selection
Limitations` card with entry `ze-query`, reason span `cap overflow
(coverage preserved)`, detail span `candidate queue saturated`, and
candidate code `cand-42`; a `Policy Exclusions` card with entry
`ze-license` and reason span `out of scope`; a `Coverage Plan (schema
v1)` table row for `ze-query` with primary candidate `cand-42` and
state `planned`; the universe card shows inventory completeness
`Not Applicable (Inferred Partial)` and the message `No
operator-confirmed evidence`.

### QA-TRSR-34: run summary outcome summary and coverage gaps card

1. Fixture: two scenarios with composites `0.85` and `0.35`; a
   run manifest with the QA-TRSR-20 funnel; coverage-gaps.json with
   1 uncovered entry point, 1 uncovered zone, 2 uncovered threats,
   and no uncovered attack patterns.
2. Run `report`.

**Expected:** The Run Summary `Outcome Summary` card shows `1 High
Priority`, `0 Medium Priority`, `1 Low Priority`; the coverage-gaps
card inside the summary shows `4 Coverage Gaps` (entry points +
zones + threats; attack patterns are excluded by the generator).

### QA-TRSR-35: scenarios-section sub-charts and filters

1. Fixture: `scn-a` (threat `[T6]`, zones traversed
   `[input, tool_execution]`, narrative entry point `ze-query`,
   composite `0.72` with all six signals) and `scn-b` (threat
   `[T6]`, zones traversed `[input]`, narrative entry point
   `ze-rag`, composite `0.35` with all six signals); a run manifest
   with `scenarios_generated: 4`.
2. Run `report`.

**Expected:** The `Priority Signal Decomposition` chart shows a
segment tooltip `Risk Impact: critical` (recorded-case values, not
title-cased); the `Threat x Zone Coverage` matrix shows the zone
headers `Input Surfaces` and `Tool Execution` and a `T6 x Input
Surfaces` cell counting `2`; the `Entry Point Distribution` lists
`ze-query` (1) and `ze-rag` (1); the filter bar shows a Threats chip
containing `T6`, Zones chips `Input Surfaces` and `Tool Execution`,
and Priority chips `High`, `Medium`, `Low`; the Scenarios dashboard
`In Report` stat carries the sublabel `of 4 generated`; the `scn-a`
card's Narrative tab shows the zone crumbs `input` and
`tool_execution` joined by an arrow.

### QA-TRSR-36: conflicting corpus claims refuse the report command

1. Fixture: a completed run with two scenarios whose
   `validation.semantic.corpus_claim_applicability` records conflict
   (same category, differing `status` or `evidence`).
2. Run `report` and capture exit status and stderr; confirm no
   `report.html` is written.

**Expected:** Exit non-zero, `report.html` absent, and stderr names
the conflicting corpus-claim category. This failure path cannot be
driven through the acceptance harness (its When step raises instead
of asserting), so the pin is CLI-level only, mirroring
QA-TRSR-21's refusal boundary.

## Notes and pinned interpretations

- Fixture zone codes are canonical (`input`, `reasoning`,
  `tool_execution`, `memory`, `inter_agent`); the report renders
  display names (`Input Surfaces`, `Planning & Reasoning`, `Tool
  Execution`, `Memory & State`, `Inter-Agent Communication`).
  Legacy integer zone IDs 1–5 normalize to the same names.
- Case-sensitive display: the report title-cases enum and signal
  values (`confirmed` → `Confirmed`, `realized` → `Realized`,
  `malicious-insider` → `Malicious Insider`) while preserving
  fixture-provided prose (titles, goals, beliefs) mostly verbatim
  except goal chips and actor types, which are also title-cased.
  Attack-complexity reason lines render the recorded `required_level`
  verbatim (lowercase when stored lowercase), unlike the summary
  badges next to them, which are title-cased.
- Assertions on visible text must account for HTML entities the
  report emits: `&middot;` (matrix badge separators), `&ndash;`
  (Threat–Technique heading), `&rarr;` (reason lines and zone
  crumbs), `&mdash;` (em dash placeholder), `&amp;` (ampersands),
  `&and;`/`&or;`/`&bull;` (gate symbols).
- "Run Summary" as a phrase also appears in the Methodology section
  ("shown as *Candidates* in the Run Summary funnel"), so section
  presence/absence assertions must target the section header
  (`<h2>Run Summary</h2>`) and the sidebar link
  (`<a href="#sec-run-summary">`), never the bare words.
- YAML highlighting classifies values after entity escaping:
  numbers, booleans, and nulls/`~` receive `yaml-number`,
  `yaml-bool`, `yaml-null`; quoted strings (single or double)
  never match the string rule and render unhighlighted. Assert
  class presence for number/bool/null and plain rendering for
  quoted strings.
- Attack-tree resource IDs that do not resolve against the
  capability profile render as `Tool: Unresolved (id)` /
  `Integration: Unresolved (id)` / `Entry Point: Unresolved (id)`.
  Resolved names require canonical computed identities; see the
  open questions for the resolved-path pin.
- Coverage badge totals sum entry-point, zone, threat, and attack
  pattern gaps (`3 + 1 + 2 + 0 = 6`); status tiers are green at
  zero (`Covered`), amber at 1–2 gaps (`1 gap`/`2 gaps`), red at 3+
  (`3 gaps`).
- Run summary funnel reads `seeds_generated`, funnel
  `expanded_instances`/`filter_submitted`/`filter_accepted`, and
  `scenarios_generated`/`scenarios_failed`; rejected is
  `rule_rejected + (filter_submitted - filter_accepted)` floored at
  zero; the rejection rate renders with one decimal (`30.0%`) or
  `N/A` when nothing was expanded.
- The Run Summary section and its sidebar link appear only when a
  run manifest is present. The threat-technique matrix and Actor
  Profile Distribution sections are omitted entirely when the
  fixture has no scenarios, while the Scenarios section renders a
  `No scenarios generated.` placeholder — do not normalize these
  behaviors in assertions; they are the pinned contract.
- The scenario-minimal case still carries the typed
  corpus-claim validation records; those are fixture plumbing the
  generator requires, not report content.
- Raw Data panels are found by the file-name tab button, not by
  index, so insertion order in the fixture is not asserted.
- The Scenarios dashboard `In Report` stat shows `of N generated`
  only when the manifest's `scenarios_generated` differs from the
  rendered count; the Run Summary funnel `In Report` always equals
  the rendered count.
- The Run Summary coverage-gaps card counts entry-point + zone +
  threat gaps only (the generator drops attack-pattern gaps), while
  the Coverage Analysis badge sums all four lists and the Scenarios
  dashboard `Coverage Gaps` stat counts un-covered threat×zone
  combinations — three different numbers that must not be
  normalized against each other in assertions.
- Coverage gap attribution codes render through a human-readable
  map: `selection_limitation` → `cap overflow (coverage preserved)`,
  `out_of_scope` → `out of scope`. Reason and detail spans both use
  the `coverage-reason` class; candidate IDs render as `candidate-id`
  code chips. Summary-category cards render only when their list is
  non-empty.
- Priority Signal Decomposition segment tooltips render the recorded
  signal values verbatim (not title-cased): `Risk Impact: critical`.
- Behavior-spec rendering skips `@` tag lines, renders
  `Feature:`/`Scenario:` header lines, renders triple-quoted lines as
  `step-docstring` divs, and turns parenthesized `(Zone <name>)` step
  text into a `zone-badge` using canonical zone-name resolution
  (`(Zone input)` → `Input Surfaces`); `And`/`But`/`*` steps use
  their own keyword classes.
- Per-scenario call-log summaries follow the same
  `N prompt / M completion tokens, Xms` layout as pipeline calls;
  failed calls append ` FAILED: <error>`.
- Residual unpinned surfaces (unit-tested only, not e2e-asserted):
  hover-only tooltips (Sankey node tips, threat/attack-pattern/
  technique tooltips), per-scenario call anomaly badges
  (`⚠ slow` / `⚠ high tokens`, which require 3+ calls with an
  outlier), raw Gherkin highlighting keyword variants beyond
  `Feature:`/`Given`, the pipeline-call `semantic_evidence.warnings`
  list, and `build_full_page`'s unconditional sidebar links. A later
  slice may pin these.

## Open questions (report contract ambiguities)

- **Empty threat surface:** the section currently renders with `0
  actionable / 0 governance` and a Sankey placeholder instead of
  being omitted. Decide whether omission is preferred when no
  surface was derived, or whether the placeholder is the intended
  honest-absence signal.
- **No scenarios:** the Scenarios section renders `No scenarios
  generated.` while the threat-technique matrix and Actor Profile
  Distribution sections are omitted entirely. Pick one empty-section
  policy (placeholder vs omission) across all scenario-derived
  sections.
- **Absent run manifest:** the Run Summary section and its sidebar
  link are omitted with no explanatory note. Decide whether a
  "run summary unavailable" placeholder is required.
- **Absent attack tree:** the Attack Tree tab shows only the goal
  line with no tree markup and no "(no attack tree)" note. Decide
  whether an explicit placeholder should render.
- **Empty optional tabs:** scenarios without actor profile, attack
  complexity assessment, or priority signals leave those tabs
  visually empty (labels remain). Decide whether muted
  "none/not generated" placeholders should render inside the tabs.
- **Resolved attack-tree resource names:** tool, integration, and
  entry-point IDs are canonical computed identities, so a CLI-only
  fixture cannot reference one without the domain computation, and
  the resolved-name path (`Tool: Code interpreter (id)`) is not
  pinnable under the no-project-API QA boundary. Decide whether to
  provide a committed canonical fixture pair (profile entry + tree
  reference) in `data/` for QA reuse, or accept the unresolved-path
  pin as sufficient for this slice.
- **Run Summary coverage card gap basis:** the card counts entry
  point, zone, and threat gaps but silently drops attack-pattern
  gaps, while the Coverage Analysis badge sums all four lists.
  Decide whether the card should include attack-pattern gaps (or
  document why it excludes them).

## Module layout note (architect)

After extraction, the sections pinned here moved out of the
monolithic `src/asago_scenario_generator/report/template.py` into
focused modules (e.g. capability profile, threat surface, coverage,
threat-technique matrix, attacker diversity, scenario card blocks,
run summary, and a syntax-highlighting helper). The QA suite asserts
only the published `report.html`, so the extraction must not change
any user-visible text, markup class, or document order pinned above.
