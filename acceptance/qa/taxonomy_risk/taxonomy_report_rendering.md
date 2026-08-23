# End-to-end QA: taxonomy/risk HTML report rendering

## Boundary

Exercise only the public taxonomy-and-risk report command:

```bash
uv run asago-scenario-generator report \
  --output-dir <completed-run-directory> \
  --output <temporary-directory>/report.html
```

Do not import project modules and do not call `generate_report`,
`build_scorecard_section`, or any other project API. Keep the suite
offline; no LLM endpoint is involved. Use disposable copies of
authoritative completed run fixtures whose manifest inventories and
hashes match their artifacts. `--output` must be outside the run
directory.

Inspect the command's stdout, stderr, exit status, and the published
`report.html`. Verify visible text in a browser; verify CSS-class-level
claims (badge colors, highlight markers, placeholder styling) and
document order directly in `report.html` source. The report file is the
user-visible output, not a project API.

## Fixture records

Provide one completed taxonomy-and-risk run fixture with:

- a capability-profile.yaml whose `entry_points` list is known;
- a threat-surface.yaml with one actionable entry for each risk card
  used by the provenance cases (attack-pattern and ATLAS lists as
  needed);
- one or more scenario YAMLs, each carrying the typed
  `validation.semantic.corpus_claim_applicability` records the report
  generator requires (copy them from an authoritative fixture), plus
  `faceting.risk_card`, `faceting.taxonomy_chain`,
  `scenario_seed_metadata`, `actor_profile`, and
  `faceting.capability_profile` as each case needs;
- an eval-scorecard.yaml whose schema matches the case (legacy
  `evaluation` block or `schema_version: 1`), and no scorecard at all
  for the omission case;
- a manifest that lists every artifact with matching hashes.

Derivative fixtures: risk card absent; each ID list empty; no seed
metadata; the two description lengths; scorecards per badge-threshold,
outlier, and versioned case.

## Workflows

### QA-TRPT-01: the full provenance chain renders

1. Build the fixture from scenario `scn-01` in Features: risk card
   `atlas-phishing` (name `Spear phishing`, taxonomy `ibm-risk-atlas`,
   confidence `0.85`), OWASP LLM IDs `[LLM01, LLM06]`, agentic threats
   `[T6, T11]`, seed metadata (seed `AP-T6-01`, attack pattern name,
   short description, threat `T6` with name, origin `LLM01`), a
   threat-surface entry for `atlas-phishing` listing attack patterns
   `[AP-T11-01, AP-T6-01]` and ATLAS techniques
   `[AML.T0015, AML.T0053]`, entry points `[ze-query, ze-rag]` with
   `ze-rag` selected, and zones `[Z1, Z2]`.
2. Run `report` and open `report.html`.

**Expected:** Exit `0`. The scenario card `scn-01` has a Provenance tab.
Its chain shows the step labels Risk Card, OWASP LLM IDs, Agentic
Threats, Attack Pattern, Attack Goal, Scenario classifications, Entry
Point, and Zone Sequence in order. The risk card step shows
`atlas-phishing`, `Spear phishing`, and `0.85`; steps 2–3 show badges
`LLM01, LLM06` and `T6, T11` in order; `AP-T6-01` is highlighted as the
selected seed while `AP-T11-01` appears unselected; `AML.T0015` and
`AML.T0053` appear as unpinned candidates; `ze-rag` is highlighted among
the entry points; zone crumbs `Z1` and `Z2` appear in order.

### QA-TRPT-02: missing risk card degrades honestly

1. Use the fixture whose scenario carries no `faceting.risk_card`
   (OWASP `[LLM01]`, threats `[T6]`).
2. Run `report` and open `report.html`.

**Expected:** Exit `0`. The card still has a Provenance tab; the risk
card step shows an empty risk ID and risk name with confidence `0.00`,
and no taxonomy badge.

### QA-TRPT-03: empty ID lists show a placeholder

For each of OWASP LLM IDs and agentic threats:

1. Use the matching fixture (one list empty, the other populated).
2. Run `report` and check the provenance chain.

**Expected:** The emptied step shows the muted placeholder `none` and no
ID badge; the other step still shows its badge (`T6` or `LLM01`).

### QA-TRPT-04: provenance renders without seed metadata

1. Use the fixture whose scenario has no `scenario_seed_metadata` but
   does have an attack goal and one zone.
2. Run `report` and open `report.html`.

**Expected:** Exit `0`. The card still has a Provenance tab; the attack
pattern step shows an empty seed ID, name, and threat with no
description; the Attack Goal, Entry Point, and Zone Sequence steps still
render.

### QA-TRPT-05: long attack pattern descriptions truncate at 300

1. Fixture A: seed description is a 400-character run-on string with no
   sentence break inside the first 300 characters.
2. Fixture B: seed description is a 120-character description with a
   terminal period.

Run `report` for each and inspect the provenance section.

**Expected:** In A, the provenance shows the description cut at 300
characters followed by `...` (the trailing characters appear only
outside the provenance, e.g. in Generation Inputs, never within it). In
B, the description appears in full inside the provenance.

### QA-TRPT-06: complete scorecard renders every metric group

1. Use the fixture whose legacy `evaluation` block has consistency,
   gherkin, grounding, technique agreement, diversity, and plausibility
   metrics (scenario count 3, feature file count 2).
2. Run `report` and inspect the scorecard.

**Expected:** The `Eval Scorecard` section exists with summary
statistics `3` Scenarios and `2` Feature Files; the groups Consistency,
Gherkin Quality, Grounding, Projected-step Mapping Agreement, Diversity,
and Plausibility all render; the badge `Mean Technique Agreement: 0.92`
is present.

### QA-TRPT-07: in-range metrics show the clean outliers panel

1. Use the fixture whose consistency, agreement, diversity, and
   plausibility metrics are all in range.
2. Run `report` and inspect the scorecard.

**Expected:** The scorecard shows the text `All scenarios pass quality
checks` and no `Quality Outliers` panel.

### QA-TRPT-08: outliers list red tier before yellow tier

1. Use the fixture where scenario `scn-a` has zone alignment `0.65`
   (red tier), scenario `scn-b` has zone alignment `0.80` (yellow
   tier), and 2 capability-complexity violations are recorded.
2. Run `report` and inspect the outliers panel.

**Expected:** A `Quality Outliers` panel lists the aggregate row
`(aggregate) / Capability Violations / 2`, then `scn-a / Zone Alignment
/ 0.65`, then `scn-b / Zone Alignment / 0.80`, in that first-column
order.

### QA-TRPT-09: badge colors follow the 90/70 thresholds

For each of consistency mean `0.95`, `0.75`, `0.55`, and `1.0`:

1. Use the matching scorecard fixture (only the mean present).
2. Run `report` and verify the `Mean` badge.

**Expected:** The badge value renders as `0.95`, `0.75`, `0.55`, `1`
respectively, with green at `≥ 0.9`, yellow at `0.7–0.9`, and red below
`0.7`. Verdicts: green, yellow, red, green.

### QA-TRPT-10: inverted count badges color zero green and above red

For `0` and `2` capability-complexity violations:

1. Use the matching scorecard fixture (only the plausibility count
   present).
2. Run `report` and verify the `Capability Violations` badge.

**Expected:** Values render as `0` and `2`; `0` is green and any count
above zero is red.

### QA-TRPT-11: schema v1 scorecard renders status badges

For each of status `pass`, `fail`, and `not_applicable`:

1. Use the fixture with a `schema_version: 1` scorecard holding one
   metric of that status in the corresponding group (Presence /
   Coverage; Validity / Grounding; Release Qualification).
2. Run `report` and inspect the scorecard.

**Expected:** The `Versioned Eval Scorecard` section renders with the
schema badge `Schema v1`; the metric's status badge is green for `pass`,
red for `fail`, and yellow for `not_applicable`.

### QA-TRPT-12: Scenario Seed block only for complete seed metadata

For each of: no `scenario_seed_metadata`; metadata with attack pattern
name and seed ID; metadata with neither name nor seed ID:

1. Build the fixture, run `report`, and search `report.html` for a
   `Scenario Seed` section.

**Expected:** The section renders only in the second case. See the
wiring note below before treating the third case's absence as a defect.

### QA-TRPT-13: Scenario Seed block shows the seed fields

1. Use the fixture with full seed metadata (seed `AP-T6-01`, attack
   pattern name `Prompt injection with hidden intent`, short
   description, threat `T6` with name `Social engineering`, origin
   `LLM01`).
2. Run `report` and inspect the `Scenario Seed` section.

**Expected:** The section shows the attack pattern name, the
description, threat `T6` with its name, origin `LLM01`, and seed
`AP-T6-01`.

### QA-TRPT-14: no scorecard omits the section and sidebar link

1. Use the fixture whose manifest lists no eval scorecard.
2. Run `report` and open `report.html`.

**Expected:** Exit `0`. `report.html` contains no `Eval Scorecard`
section and no scorecard entry in the sidebar navigation.

### QA-TRPT-15: deterministic repository gates and output hygiene

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

## Notes and pinned interpretations

- The provenance chain reads OWASP LLM IDs and agentic threats from the
  scenario's `faceting.taxonomy_chain`; attack-pattern candidates come
  from threat-surface entries whose `agentic_threat_ids` contain the
  seed's threat, and ATLAS candidates from the entry whose `risk_card`
  matches the scenario's risk ID. Empty ID lists render the muted
  placeholder `none`.
- The seed description truncation rule is 300 characters with a
  sentence-boundary preference; Generation Inputs shows the full
  description, so truncation checks must be scoped to the provenance
  section.
- Legacy scorecard badges are green at `≥ 0.9`, yellow at `0.7–0.9`,
  and red below `0.7`; inverted count badges are green at exactly `0`
  and red above. Outliers are sorted red tier first, then yellow, each
  alphabetical by scenario ID (aggregate rows sort under
  `(aggregate)`).
- Schema v1 scorecards map status to badge color directly: `pass` green,
  `fail` red, `not_applicable` yellow, `error` red. The legacy
  `Eval Scorecard` (Tier 1) and `Versioned Eval Scorecard` (Schema v)
  sections are both published formats depending on the scorecard
  artifact; do not collapse them in QA assertions.
- The provenance Attack Goal step renders data-file-driven affinity
  explanations from committed taxonomy data. QA assertions avoid that
  text; the selected goal and the step labels are fixture-driven and
  stable.
- Scenario YAML fixtures must satisfy the report generator's strict
  corpus-claim reconciliation (typed
  `validation.semantic.corpus_claim_applicability` records); missing
  records make report generation fail loudly regardless of the
  provenance or scorecard case under test.
- The report command requires an authoritative completed manifest
  unless `--allow-non-authoritative` is passed; the suites use
  completed fixtures only.

## Module layout note (architect)

After the provenance + scorecard extraction, the scenario-seed and
provenance renderers no longer live in the monolithic
`src/asago_scenario_generator/report/template.py`:

- `_build_seed_metadata_block` (the `Scenario Seed` section),
  `_build_provenance_block` (the `SSSOM Provenance` section), and
  `_build_provenance_chain` now live in
  `src/asago_scenario_generator/report/provenance.py`, together with
  the taxonomy-derived display lookups those sections use.
- The scorecard renderers (`build_scorecard_section` and its helpers)
  now live in `src/asago_scenario_generator/report/scorecard.py`.
- `report/template.py` imports the provenance-chain and seed-block
  builders back into the scenario card; `report/generator.py` imports
  `build_scorecard_section` from the scorecard module.

The `Scenario Seed` block is wired into the scenario card's Provenance
tab (alongside the provenance chain), and renders only when seed
metadata is present and complete, so QA-TRPT-12/13 are observable
end-to-end on published reports.
