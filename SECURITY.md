# Security policy

## Supported versions

Security fixes are applied to the latest commit on the `main` branch. Older
commits and unofficial forks may not receive security updates.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue. Report them
privately through GitHub's **Report a vulnerability** flow for this repository
when available. If private vulnerability reporting is unavailable, open a
minimal issue requesting a private contact channel without including exploit
details or sensitive artifacts.

Please include:

- A concise description and affected component or file
- Reproduction steps or a minimal proof of concept
- Impact assessment and any required configuration
- A suggested mitigation, if known

Never attach real email messages, credentials, API keys, private IP inventories,
or other sensitive investigation data.

## Response expectations

We will acknowledge a valid report within 7 days, triage its severity, and
coordinate a fix and disclosure timeline with the reporter. Please allow time
for a patch before public disclosure.

## Deployment note

SENTINEL is an analyst aid for authorized defensive investigations. Before
production use, set strong database, Redis, and API credentials; enable
`AUTH_ENFORCE`; restrict `CORS_ORIGINS`; and review the threat model in
`docs/security/threat-model.md`.
