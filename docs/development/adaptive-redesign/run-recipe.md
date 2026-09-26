# Qualification runbook pointer

The qualification runtime no longer lives in the producer repository. The
`asago-orch` checkout owns live setup, runtime-context capture, package
execution, detector probing, evidence, and cleanup.

Read `asago-orch/docs/qualification.md` for the current runbook and command
templates. The implementation lives under
`asago-orch/src/asago_orch/qualification/`, including `run_recipe.py`,
`capture_runtime_context.py`, `run_fresh_package_live.py`, and
`probe_detector.py`.

The producer still owns scenario meaning, target scanning, and its model
profile file. The orch pipeline invokes those producer-owned interfaces and
keeps qualification records in the orch run directory.
