# External QA: system resource map compatibility

The compatibility driver is intentionally external and offline. It runs the
existing `generate` and `stpa-run` commands as real subprocesses before and
after valid Phase 2 sidecars are placed beside their inputs. It compares exit
status, normalized scenario artifacts, exact public counts, and prompt
contracts. Only documented run-local IDs, timestamps, and duration telemetry
are normalized. The sidecar is an independent Phase 2 surface and is not
added to default workflow outputs.

Run it with:

```text
uv run python acceptance/qa/taxonomy_risk/system_resource_map_compatibility.py
```

Expected result: `12/12 passed`.
