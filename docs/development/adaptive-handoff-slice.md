# M1 handoff note: minimal handoff slice

This note is the resolution index for the M1 (`m1-handoff-slice`) deliverables. Where a
validation assertion refers to "the fixture", "the mapping", "the interpretation", "the
recipe", or "the budget registration", resolve the exact path from the table below.

The milestone delivers hand-edited development material plus the reproducible run
recipe. It does not deliver a producer generation run, a consumer-authored artifact, or
a Garak execution; those belong to M2.

## Delivered paths

| Deliverable | Path | Owner / status |
| --- | --- | --- |
| SCN-007 design fixture (narrative + attack tree + Gherkin + metadata, with change record) | `docs/development/adaptive-redesign/scn-007-design-fixture.yaml` | producer — delivered in this feature |
| Field-ownership mapping (every fixture field attributed; semantic-criterion location explicit) | `docs/development/adaptive-redesign/scn-007-field-ownership.md` | producer — delivered in this feature |
| Consumer interpretation (decisions a–d) plus unknowns and limits | `docs/development/adaptive-redesign/scn-007-consumer-interpretation.md` | producer — delivered in this feature |
| Reproducible run recipe (startup, reset, seeded-state verification, evidence locations) | delivered by the companion feature `m1-run-recipe` | producer — record the exact path in this row when it lands |
| Budget registration (five stage estimates, no hard cap, discipline rules) | delivered by the companion feature `m1-run-recipe` | producer — record the exact path in this row when it lands |
| Revision record (starting commits; append-only) | `docs/development/adaptive-redesign-revisions.md` | producer — started in this feature |

## Notes for the inspector

- The fixture lives outside `build/adaptive-redesign-inputs/historical/`. Every file
  under `build/adaptive-redesign-inputs/` is unchanged; its digests match
  `build/adaptive-redesign-inputs/manifest.json` and the M1-start digests.
- The fixture is hand-edited development material. It settles the producer-to-consumer
  interface only. It is not fresh generation, not benchmark recovery, and not the
  versioned scenario-handoff contract kit (that kit is published in a later milestone).
- The historical source is
  `output/runs/20260908-phase4-grounded-authoring-live-v14/scenarios/SCN-007.yaml`, with
  its pinned copy at `build/adaptive-redesign-inputs/historical/scenario.yaml`
  (sha256 `1f93171c4783c64a09eab707a4dc7f959cbc686f292f218ade1c28889b328cd9`).
- Keep this note append-only for M1: the recipe feature fills the two recipe/budget rows
  without changing the rows above.

## How to update this note

Append or fill only the recipe and budget rows (above) and any newly delivered M1 paths.
Do not rewrite the fixture, mapping or interpretation rows.
