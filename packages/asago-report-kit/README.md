# asago-report-kit

The producer's report kit: the helpers, stylesheet, script, catalog and
stage-summary schema that the producer's and the consumer's report writers
render with. It is a workspace member of the producer, installed as
`asago_report_kit`, and both the consumer and the orchestrator depend on it by
name with an editable path.

The module imports only the standard library (Python 3.12 or later). Every
file it reads lives inside `src/asago_report_kit/`, so the wheel carries
`kit.css`, `kit.js`, `catalog.html` and `stage-summary-v1.schema.json` without
a build hook.

## Commands

```bash
uv run pytest packages/asago-report-kit/tests -q
cd packages/asago-report-kit && uv build
```

## Layout

- `src/asago_report_kit/__init__.py` holds every helper and declares its
  public surface in `__all__`.
- `src/asago_report_kit/kit.css`, `kit.js` and `catalog.html` are the kit's
  data: `stylesheet()`, `script()` and `render_catalog()` read or produce them,
  and `write_catalog()` regenerates the catalog.
- `src/asago_report_kit/stage-summary-v1.schema.json` is the schema a report
  writer validates its `stage-summary.json` against;
  `stage_summary_schema()` returns its path.
- `tests/` checks the member's declaration, the catalog golden and the
  stdlib-only import boundary.

The producer's old path, `asago_scenario_generator.report_kit`, re-exports this
member for one cycle. New code imports `asago_report_kit`.
