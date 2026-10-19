# policy-coverage-v2

`generate/output/policy-coverage.json` states which policy risks the producer's
generate stage turned into scenarios and where it dropped the others, and which
hazards lead to each harm. The producer owns the contract; the orchestrator
mirrors this directory byte for byte, and the run reports of the consumer and
the orchestrator read the file instead of re-deriving the mapping.

Version 2 adds hazards. Version 1 stays in this directory beside it, unchanged:
its schema sets `additionalProperties: false`, so a hazard needed a new schema
version, not an extra field. A reader that must also open older runs accepts
both versions and treats a version 1 document as one without hazards.

- `schema.json` is the schema. `valid/minimal.json` is a document that passes it.
- A risk reaches scenarios only through its harms. A harm is a loss; its
  `risk_ids` are the merged risks the loss cites, and its `scenario_ids` list
  every scenario written for it. A risk carries `loss_ids`, not scenarios.
- `hazards` lists every hazard in the run's loss analysis, including hazards no
  scenario reaches, in natural order of `hazard_id` (`H-2` before `H-10`). Each
  hazard has:
  - `hazard_id` and `description`, as written in loss analysis;
  - `loss_ids`: the losses the hazard can lead to, in natural order, taken from
    the hazard's `related_losses` in loss analysis;
  - `scenario_ids`: the published scenarios whose lineage `hazard_ids` name the
    hazard, in natural order. A hazard no scenario names has an empty list.
- Each harm has `hazard_ids`: the hazards whose `loss_ids` contain the harm's
  `loss_id`, in natural order. A harm no hazard leads to has an empty list. The
  two links agree: a harm lists a hazard exactly when the hazard lists the harm.
- Hazard losses come from loss analysis, never from scenario lineage. A
  scenario's lineage can cite every loss of the run at once, so reading a
  hazard's losses from it would link the hazard to harms it cannot cause. A
  scenario lineage id that names no hazard of loss analysis is ignored.
- A scenario sits under the hazards whose `scenario_ids` list it, and so under
  those hazards' harms. A scenario that names several hazards appears under each.
- `coverage` is `scenarios`, `not_reached` (a loss cites the risk but no
  scenario carries the loss), `not_applicable`, or `outside_boundary`. Every
  value except `scenarios` carries `reason`, whose `text` is the producer's
  plain-language sentence and whose `step` names where the risk dropped.
- The producer derives `coverage` in this order: a loss that cites the risk
  decides; otherwise a loss-analysis `not_applicable` disposition; otherwise
  the boundary decision.
- Entries that several taxonomies list under one normalized name merge into
  one risk that keeps every id (`merged_ids`) and source (`sources`).
- `rule` names the risk-to-scenario rule. Versions 1 and 2 have one value,
  `loss-source-risk-cards`.
