# Correspondence artifact QA

Run:

    uv run python acceptance/qa/taxonomy_risk/correspondence_artifact.py

The driver verifies the canonical correspondence-proposals.yaml and correspondence-reconciliation.yaml artifacts, their semantic digests, YAML round-trip shape, and atomic publication cleanup. No application imports are used.
