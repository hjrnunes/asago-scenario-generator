# policy-coverage-v1

`generate/output/policy-coverage.json` states which policy risks the producer's
generate stage turned into scenarios and where it dropped the others. The
producer owns the contract; orch mirrors this directory byte for byte, and
the consumer's and orch's run reports read the file instead of re-deriving
the mapping.

- `schema.json` is the schema. `valid/minimal.json` is a document that passes it.
- A risk reaches scenarios only through its harms. A harm is a loss; its
  `risk_ids` are the merged risks the loss cites, and its `scenario_ids` list
  every scenario written for it. A risk carries `loss_ids`, not scenarios.
- `coverage` is `scenarios`, `not_reached` (a loss cites the risk but no
  scenario carries the loss), `not_applicable`, or `outside_boundary`. Every
  value except `scenarios` carries `reason`, whose `text` is the producer's
  plain-language sentence and whose `step` names where the risk dropped.
- The producer derives `coverage` in this order: a loss that cites the risk
  decides; otherwise a loss-analysis `not_applicable` disposition; otherwise
  the boundary decision.
- Entries that several taxonomies list under one normalized name merge into
  one risk that keeps every id (`merged_ids`) and source (`sources`).
- `rule` names the risk-to-scenario rule. Version 1 has one value,
  `loss-source-risk-cards`.
