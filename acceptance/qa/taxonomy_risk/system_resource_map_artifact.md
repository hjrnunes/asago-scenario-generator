# External QA: system resource map artifact

`system_resource_map_artifact.py` drives the typed file adapter without
importing project implementation modules. It checks that YAML and JSON
diagnostics are non-empty, the persisted sidecar is named
`system-resource-map.yaml`, and the artifact has schema version
`system-resource-map-v1`.

Run it with:

```text
uv run python acceptance/qa/taxonomy_risk/system_resource_map_artifact.py
```

Expected result: `3/3 passed`.
