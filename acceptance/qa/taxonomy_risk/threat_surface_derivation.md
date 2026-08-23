# End-to-end QA: taxonomy threat-surface derivation

Drive only `uv run asago-scenario-generator generate` with a deterministic
local OpenAI-compatible fixture endpoint that returns valid responses for
every later generation stage. Use a fresh output collection per case and
valid offline inputs: a reviewed capability-profile YAML, a
risk-extraction.json containing exactly the named `ibm-risk-atlas` cards,
an SSSOM TSV, and a cross-taxonomy-mappings.yaml. Never set
`ASAGO_SCENARIO_GENERATOR_QA_PIPELINE`; the fixture endpoint must be
loopback-only.

Inspect CLI stdout, stderr, exit status, and the published
`threat-surface.yaml` in the run directory. Do not import project modules
and do not call `determine_threat_surface` directly. To build each fixture,
derive the expected in-scope T-threat and attack-pattern IDs from the
committed input data (`data/taxonomies/mappings/kc-threat-mapping.yaml`,
`data/taxonomies/owasp-agentic-threats/owasp-agentic-threats-v1.1.yaml`,
`data/taxonomies/attack-patterns/`); reading committed data files as
fixture sources is allowed, calling pipeline functions is not. Give every
risk card the identity fields (risk_id, risk_name) so the published
`risk_card` references can be checked.

## QA-TSDS-01: the three-hop chain publishes an actionable entry

1. Add one `ibm-risk-atlas` card `atlas-prompt-injection`. Author the
   SSSOM TSV to link it to `LLM01` and `LLM06`; author
   cross-taxonomy-mappings.yaml to link `LLM01` to T-threats `T6,T11` and
   `LLM06` to T-threats `T2,T13`, with an empty `t_to_atlas` section.
2. Choose capability-profile KC sub-codes that gate `T2,T6,T11,T13` in
   scope (e.g. `KC1.1,KC6.4,KC2.3`). The same codes also gate other
   threats, but with no `t_to_atlas` links the card's ATLAS set stays
   empty, so no additional threat can join; the fixture's SSSOM and
   cross-taxonomy links reach no other gated threat.
3. Run `generate` and inspect `threat-surface.yaml`.

**Expected:** The process exits `0`. The surface has one entry and an
empty `governance_only` list. The entry references risk card
`atlas-prompt-injection`, has `governance_only: false`, lists OWASP LLM
IDs exactly `[LLM01, LLM06]`, lists T-threats exactly
`[T6, T11, T2, T13]` (each Hop-1 ID before its Hop-2 IDs, in first-seen
order), and lists no ATLAS techniques.

4. Repeat with KC sub-codes gating `T6,T11` in scope (e.g.
   `KC1.1,KC6.4`, which also gate `T2,T3,T5,T7,T15,T17`; the fixture
   reaches none of them).

**Expected:** The entry remains actionable with OWASP LLM IDs
`[LLM01, LLM06]` unchanged and T-threats exactly `[T6, T11]`; the
out-of-scope reachable threats `T2,T13` are dropped. No direct-path
T-threat joins.

## QA-TSDS-02: a card without an LLM mapping stays governance-only

1. Make `atlas-orphan-risk` (risk name `Orphaned risk signal`) the only
   `ibm-risk-atlas` card, populated with causal-chain `threat`,
   `vulnerability`, `consequence`, and `impact` text. Provide an SSSOM
   TSV with no rows for it.
2. Run `generate` and inspect `threat-surface.yaml`.

**Expected:** `entries` is empty and `governance_only` has one entry. The
governance-only entry references the card by `risk_id` and `risk_name`
and retains its causal-chain text; `owasp_llm_ids`,
`agentic_threat_ids`, `attack_pattern_ids`, `atlas_technique_ids`, and
`owasp_asi_ids` are all empty; `governance_only` is `true`.

## QA-TSDS-03: only out-of-scope LLM mappings stay governance-only with their LLM IDs

1. Add card `atlas-prompt-injection`, linked by SSSOM to `LLM01` only.
   Author cross-taxonomy-mappings.yaml so `LLM01` maps to `T11` (a threat
   the chosen profile does not gate).
2. Choose KC sub-codes that gate the direct-path threats `T7,T9,T10` in
   scope without gating `T11` (e.g. `KC1.1,KC2.2`, which also gate
   `T5,T6,T8,T15`; the fixture's SSSOM/cross-taxonomy links reach none of
   them).
3. Run `generate` and inspect `threat-surface.yaml`.

**Expected:** `entries` is empty and `governance_only` has one entry for
`atlas-prompt-injection`. The entry retains OWASP LLM IDs `[LLM01]` and
has empty T-threat, attack-pattern, ATLAS, and ASI lists. No direct-path
T-threat is joined even though `T7,T9,T10` are in scope, because the card
has no scoped three-hop threats.

## QA-TSDS-04: direct-path T-threats join only on a shared ATLAS technique

For each of the two fixture variants below, run `generate` and inspect
`threat-surface.yaml`. Both variants use card `atlas-prompt-injection`
linked to `LLM06`, with `LLM06` mapping to `T2`, `T2` mapped to ATLAS
techniques `AML.T0015,AML.T0053`, and `AML.T0015`/`AML.T0053` absent from
every unrelated direct-path threat's technique set.

1. Variant A: link direct-path `T7` to ATLAS techniques
   `AML.T0054,AML.T0015,AML.T0053` and direct-path `T8` to
   `AML.T0056,AML.T0057`; choose KC sub-codes gating `T2,T7,T8` in scope
   (e.g. `KC5.1`, which also gates `T6,T17`; the fixture reaches neither).
2. Variant B: same mappings, but gate only `T2,T8` in scope (e.g.
   `KC6.1.1,KC4.3`, which also gate `T1,T5,T6`; the fixture reaches none
   of them, and `T7` stays out of scope).

**Expected (A):** One actionable entry; T-threats exactly
`[T2, T7]` — `T7` joins because `AML.T0015` and `AML.T0053` overlap the
card's three-hop ATLAS set, while in-scope `T8` stays absent because its
techniques do not overlap. ATLAS techniques exactly
`[AML.T0015, AML.T0053, AML.T0054]` in first-seen order.

**Expected (B):** T-threats exactly `[T2]` and ATLAS techniques exactly
`[AML.T0015, AML.T0053]`; the non-overlapping `T8` never joins.

## QA-TSDS-05: attack-pattern, ATLAS, and ASI IDs are unioned without duplicates

1. Add card `atlas-memory-poisoning`, linked by SSSOM to `LLM04` and
   `LLM08`. Author cross-taxonomy-mappings.yaml so `LLM04` maps to
   `T1,T12`, `LLM08` maps to `T1,T2`, both `T1` and `T12` map to ATLAS
   techniques `AML.T0043,AML.T0031,AML.T0020`, `T1` maps to ASI `ASI06`,
   and `T12` maps to ASI `ASI07`. Give the threat scope attack patterns
   `AP-T1-01,AP-T1-02` for `T1` and `AP-T12-01,AP-T1-01` for `T12`.
2. Choose KC sub-codes gating `T1,T12` in scope without gating any
   direct-path threat (e.g. `KC4.2,KC6.3.3`, which also gate `T5,T6`;
   the fixture reaches neither).
3. Run `generate` and inspect `threat-surface.yaml`.

**Expected:** One actionable entry; OWASP LLM IDs `[LLM04, LLM08]`;
T-threats `[T1, T12]` — `T1` appears once despite being reachable via
both LLM hops, and out-of-scope `T2` is dropped; attack patterns
`[AP-T1-01, AP-T1-02, AP-T12-01]` — the shared `AP-T1-01` appears once;
ATLAS techniques `[AML.T0043, AML.T0031, AML.T0020]` once each; ASI
entries `[ASI06, ASI07]`. Every list is de-duplicated and
order-preserving.

## QA-TSDS-06: KC6-gated ATLAS techniques follow the profile KC6 sub-code

Two runs, both with card `atlas-prompt-injection` linked to `LLM01`, with
`LLM01` mapping to `T6` and `T6` mapped to ATLAS techniques
`AML.T0054,AML.T0053`. Give direct-path `T7,T15` the disjoint technique
`AML.T0050` so they cannot join.

1. Run with a profile gating `T6` in scope via `KC1.1` only.
2. Run with `KC1.1,KC6.4`.

**Expected (1):** One actionable entry with ATLAS techniques exactly
`[AML.T0054]`; the KC6-gated `AML.T0053` is dropped.

**Expected (2):** The same entry with ATLAS techniques exactly
`[AML.T0054, AML.T0053]`; the gated technique remains. The gate concerns
`atlas_technique_ids` only — no attack pattern or ASI ID is added or
removed by it.

The full gated set is `AML.T0053, AML.T0070, AML.T0066, AML.T0071,
AML.T0025`; each is dropped without any profile KC6 sub-code (any of
`KC6.1.1`–`KC6.7`) and retained when one is present. Spot-check at least
one additional gated technique alongside `AML.T0053`.

## QA-TSDS-07: empty risk cards yield empty surfaces

1. Provide a risk-extraction.json containing zero entries (and, as a
   second run, an input whose entries all carry a taxonomy other than
   `ibm-risk-atlas`).
2. Run `generate` and inspect `threat-surface.yaml`.

**Expected:** Both runs publish a surface with `entries: []` and
`governance_only: []`, and exit `0`.

## QA-TSDS-08: deterministic repository gates and output hygiene

1. Confirm the live-model opt-in is unset and the fixture is loopback-only.
2. Run the documented commands in order:

   ```bash
   ./scripts/quality.sh
   ./scripts/acceptance.sh
   uv run pytest tests/ -q
   ```

3. Run `git status --short --untracked-files=all`.

**Expected:** Quality, acceptance, and unit gates pass deterministically
without an LLM endpoint, and no generated acceptance IR, DRY reports,
coverage, mutation workspaces, or temporary QA captures are newly tracked
or staged.

## Notes and pinned interpretations

- The direct-path overlap set is the ATLAS-technique union of the card's
  scoped three-hop T-threats only. Threats already reached via the
  three-hop path are never re-appended, and a threat joined via the
  direct path does not extend the overlap set for later direct threats.
  Direct-path threats are appended to `agentic_threat_ids` in
  lexicographic ID order after the three-hop threats.
- A card with no scoped three-hop threats never joins direct-path
  threats, however many direct threats are in scope; it is
  `governance_only` with its OWASP LLM IDs retained (see QA-TSDS-03).
- The KC6-gated technique set and the KC6 sub-code set are hard-coded in
  `pipeline/threats.py`; if either is ever moved into data files, this
  suite's expected values must be revisited.
- In-scope gating and attack-pattern retention are data-driven from the
  committed KC→threat mapping, OWASP agentic threats catalog, and attack
  patterns. Choose profile KC sub-codes so the fixture reaches no
  accidentally gated threat; the KC sets suggested per case are guides,
  not requirements.
- Duplicate SSSOM rows for the same risk→LLM pair collapse to one OWASP
  LLM ID in the entry.
- The risk-card loader keeps only `ibm-risk-atlas` entries, which is why
  a file containing only other taxonomies behaves like an empty card set.
