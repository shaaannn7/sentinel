# Deterministic analysis system

Phase 2 runs once on the parsed `ParsedEmail` representation and never reparses
the raw artifact or invokes the AI layer:

`authentication -> headers -> URLs -> domains -> IPs -> attachments -> content -> scoring -> timeline`

Each analyzer returns `AnalyzerResult` with evidence, findings, warnings, and
errors. A stage failure is isolated and persisted in `analysis_stages`; the
remaining stages still run. Evidence IDs are deterministic hashes, which makes
reruns traceable and idempotent.

Findings cannot be persisted without at least one evidence reference. The score
is bounded by category caps and includes its `score_breakdown` in the
investigation row. Verdicts are conservative: unusual indicators are described
as observations or potential signals, not proof of maliciousness.
