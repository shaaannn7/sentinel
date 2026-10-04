# SENTINEL architecture

SENTINEL is a modular monolith with a Next.js analyst UI and FastAPI API. The API owns validation, deterministic parsing, persistence, and bounded AI orchestration. PostgreSQL is the source of truth; local artifact storage is an implementation of the `ArtifactStorage` boundary and can be replaced by object storage.

## Trust boundaries

1. Browser upload and metadata are untrusted.
2. Parsed email headers, bodies, URLs, and attachment names remain untrusted evidence.
3. AI receives an allowlisted structured evidence projection, never shell/browser/network tools or raw MIME bytes.
4. Provider output is untrusted until JSON parsing, schema validation, and evidence-reference validation succeed.

The deterministic parser is authoritative for extracted facts. AI output is advisory and is recorded in `ai_audits` with agent, model, prompt version, evidence references, attempt count, and validation state.

## Request flow

`multipart upload -> bounded read -> extension/size validation -> hashed safe storage -> RFC 822 parse -> structured evidence -> relational persistence -> investigation detail API`

AI is an explicit follow-up operation. If no API key is configured, the API returns deterministic results and records AI enrichment as unavailable rather than inventing a verdict.

## Service boundaries

- `email_parser`: pure deterministic MIME and indicator extraction.
- `artifact_storage`: filesystem/object-storage abstraction.
- `ai_investigation`: evidence projection, prompt construction, schema validation, retries, and audit persistence.
- `llm_provider`: provider transport only; no tools or arbitrary execution.
- SQLAlchemy models: durable investigation/evidence relationships.
