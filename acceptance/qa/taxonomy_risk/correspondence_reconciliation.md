# Correspondence reconciliation QA

Run:

    uv run python acceptance/qa/taxonomy_risk/correspondence_reconciliation.py

The external driver first obtains a proposal artifact, then invokes the public reconcile-correspondence command with and without a typed adjudication. It checks unresolved and confirmed outcomes, stable relation identity, complete provenance, and zero network/model calls. It never calls the pipeline directly.
