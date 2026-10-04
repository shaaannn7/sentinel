# SENTINEL security review and threat model

## Findings fixed

- Phase 2 findings are evidence-first: every persisted finding references one or more deterministic evidence records.
- URL, domain, IP, attachment, header, authentication, and content analyzers do not fetch, execute, decompress, or interpret email data as instructions.
- External lookup eligibility is centralized in `is_safe_for_external_lookup` and only returns true for public IPs.

- Uploads are bounded while reading, validated as `.eml`, hashed, and stored under a traversal-safe directory.
- Attachment content is never executed; only metadata, magic bytes, and hashes are retained.
- HTML is sanitized with an allowlist; scripts, forms, frames, event handlers, unsafe URL schemes, and active attributes are removed.
- Private, loopback, reserved, and link-local IPs are marked in structured evidence and must not be sent to enrichment providers.
- AI prompts explicitly delimit email-derived values as untrusted data and expose no shell, browser, HTTP, code execution, or provider tools.
- AI output is schema-validated, retried, rejected when it references unknown evidence, and recorded in an audit trail.
- API responses include restrictive CORS defaults and security headers.
- Upload rate and size limits reduce unauthenticated resource abuse.

## Residual risks

- Authentication and authorization are not implemented; deploy behind an authenticated gateway before handling multi-user or sensitive data.
- Local artifact storage needs an object-storage implementation and retention/deletion policy for production.
- Database schema creation currently occurs at startup for the MVP; add and run Alembic migrations before rolling deployments.
- The synchronous AI endpoint should move to a bounded worker with per-investigation token/time budgets.
- HTTPS, secret rotation, backups, dependency scanning, and centralized immutable logs belong in the deployment environment.

## STRIDE summary

| Threat | Control |
|---|---|
| Tampering | SHA-256 artifact identity, relational persistence, evidence-only AI inputs |
| Information disclosure | No secrets in prompts/logs; restrictive CORS; sanitized HTML |
| Denial of service | bounded upload reads, body limits, timeout, upload rate limit |
| Elevation of privilege | no agent tools; authentication remains a deployment prerequisite |
| Repudiation | AI audit records include prompt version, model, attempts, and validation state |
| Spoofing | email authentication results are reported as evidence, not trusted identity |
