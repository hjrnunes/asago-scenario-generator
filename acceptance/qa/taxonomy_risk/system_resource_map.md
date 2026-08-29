# External QA: normative system resource map

`system_resource_map.py` is an external, deterministic QA driver. It imports
no project modules and invokes the optional typed file adapter with the
committed capability snapshot, STPA control-structure, and
`system-resource-map-v1` fixtures. It never enables live-model QA.

The valid case must publish `system-resource-map.yaml` atomically, retain the
exact `links[]` fields and source digest pins, report `is_valid: true`, and
attest the exact entry-point and tool inventory completeness values from the
validated capability snapshot while recording zero network and model calls.
Tampering each semantic, capability, and control-structure digest must fail
closed.

Run it with:

```text
uv run python acceptance/qa/taxonomy_risk/system_resource_map.py
```

Expected result: `4/4 passed`.
