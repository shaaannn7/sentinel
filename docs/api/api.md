# Analysis API

`POST /api/v1/investigations` stores and deterministically analyzes an `.eml`
artifact. The response includes `findings`, `evidence`, `timeline`,
`analysis_stages`, authentication results, indicators, and `score_breakdown`.

`POST /api/v1/investigations/{id}/analyze` reruns the deterministic pipeline
against the stored artifact. It is safe for retries; prior deterministic
evidence, findings, timeline events, and stage records are replaced.

The current MVP executes analysis synchronously. A worker/queue can use the
same orchestrator contract later without changing analyzer behavior.
