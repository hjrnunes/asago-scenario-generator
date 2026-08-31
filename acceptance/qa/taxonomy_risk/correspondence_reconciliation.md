# Correspondence reconciliation QA

Run:

    uv run python acceptance/qa/taxonomy_risk/correspondence_reconciliation.py

The external driver first obtains a proposal artifact, then invokes the public reconcile-correspondence command with and without a typed adjudication. It checks unresolved and confirmed outcomes, stable relation identity, complete provenance, and zero network/model calls. It never calls the pipeline directly.

The committed acceptance feature also exercises two typed candidate witnesses:
the selected `candidate:v2` identity must survive proposal and reconciliation,
and a resource-map link that belongs to another candidate must fail closed with
`resource_link_not_on_selected_candidate` rather than becoming an accepted
relation.
