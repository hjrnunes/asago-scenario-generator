# Acceptance snapshot contract

`features/` is the only committed source root for the acceptance snapshot.
IR, generated tests, metadata, and DRY reports are ignored build output.

## Mapping

```text
features/<rel>.feature
  → build/acceptance/ir/<rel>.json
  → build/acceptance/generated/<stem>_acceptance_test.py
  → build/acceptance/generated/metadata/<slug>.json
  → build/acceptance/dry/<rel>.txt
```

`<rel>` keeps subdirectories. Generated tests stay flat; duplicate stems are
an error.

Override the output directories with:

```text
SWARMFORGE_ACCEPTANCE_FEATURES_DIR=features
SWARMFORGE_ACCEPTANCE_IR_DIR=build/acceptance/ir
SWARMFORGE_ACCEPTANCE_DRY_DIR=build/acceptance/dry
SWARMFORGE_ACCEPTANCE_GENERATED_DIR=build/acceptance/generated
SWARMFORGE_ACCEPTANCE_MUTATION_DIR=build/acceptance-mutation
```

Metadata stores repository-relative paths only:

```json
{
  "schema_version": 1,
  "feature_path": "features/sp1_revision.feature",
  "ir_path": "build/acceptance/ir/sp1_revision.json",
  "feature_hash": "sha256:...",
  "implementation_hash": "sha256:...",
  "hash_scope": "generated_files",
  "generated_files": ["sp1_revision_acceptance_test.py"]
}
```

Generated tests resolve the project root via `pyproject.toml` and import the
runtime from `acceptance/`. They must not embed `/Users/`, `/private/`, or
`file://` paths.

## Membership

A `.feature` file is in the snapshot if and only if it lives under
`features/`. Leftover Gherkin under `acceptance/features/` is not
generated until someone moves it here.

Step data tables are not APS-native. Snapshot features use named fixture
steps or Scenario Outline Examples instead.

Refresh with:

```bash
uv run python acceptance/refresh_snapshot.py
uv run python acceptance/refresh_snapshot.py --run
```

Then run `uv run pytest build/acceptance/generated/`.

Acceptance code must pass both hygiene checks:

```bash
uv run ruff check acceptance
uv run ruff format --check acceptance
```

The gate is enforced before generated tests by
`./scripts/acceptance.sh --test`.

A throwaway worktree check lives at `scripts/verify_acceptance_fresh.sh`.
