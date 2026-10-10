# Generate report fixture

`klarna-r1/` is a trimmed copy of a recorded klarna generate run (output of the
`pp-s7` replay). It holds eight scenarios (both kinds, a duplicate with the
scenario it duplicates, an analytical-only one, and one without a
discriminating condition), the typed sidecars whole, a manifest and obligation
plan reduced to the fields the report reads, and a `calls.jsonl` without prompt
or response text. `policy-coverage.json` is the output of
`publish_policy_coverage` over that directory. It holds no gold data.
