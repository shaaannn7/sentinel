<div align="center">

# SENTINEL

### Evidence-first email threat detection for modern SOC investigations

<p>
  <a href="https://github.com/shaaannn7/sentinel"><img src="https://img.shields.io/github/stars/shaaannn7/sentinel?style=flat-square&logo=github&label=Stars" alt="GitHub stars"></a>
  <a href="https://github.com/shaaannn7/sentinel/issues"><img src="https://img.shields.io/github/issues/shaaannn7/sentinel?style=flat-square&logo=github" alt="Open issues"></a>
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=flat-square&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/FastAPI-0.135-009688?style=flat-square&logo=fastapi&logoColor=white" alt="FastAPI">
  <img src="https://img.shields.io/badge/Docker-ready-2496ED?style=flat-square&logo=docker&logoColor=white" alt="Docker ready">
</p>

<p>
  <img src="https://readme-typing-svg.demolab.com?font=JetBrains+Mono&size=16&duration=2600&pause=900&color=22D3EE&center=true&vCenter=true&width=760&lines=Upload+an+%2Eeml+%E2%86%92+Extract+evidence+%E2%86%92+Score+threats;Trace+delivery+%E2%86%92+Enrich+indicators+%E2%86%92+Explain+the+verdict;A+defensive+analyst+workbench+for+email+investigations" alt="SENTINEL workflow animation">
</p>

<p><strong>Turn suspicious email into a structured, explainable investigation.</strong></p>

<p>
  <a href="#quick-start">Quick start</a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="#api-at-a-glance">API</a> ·
  <a href="#security-model">Security</a> ·
  <a href="#contributing">Contributing</a>
</p>

</div>

---

## What is SENTINEL?

SENTINEL is an open-source SOC investigation platform for analyzing suspicious
email messages. It accepts raw RFC 822/`.eml` files and turns them into a
defensible investigation containing parsed evidence, authentication results,
threat findings, delivery timelines, indicator enrichment, relationship graphs,
and an explainable threat score.

The platform is deliberately **deterministic first**: parsing and security
scoring remain the source of truth, while AI and machine learning provide
optional enrichment and explanations. That makes the result useful for analyst
triage without treating an opaque model prediction as a security decision.

> **Defensive-use notice:** Use SENTINEL only with email artifacts you are
> authorized to investigate. It is an analyst aid, not an autonomous incident
> response system.

## Why it is useful

| Capability | What it provides |
| --- | --- |
| **Email forensics** | Headers, MIME parts, body text, attachments, URLs, domains, IPs, and authentication results |
| **Evidence-first scoring** | Modular analyzers, bounded scoring, conservative verdicts, and a visible score breakdown |
| **Authentication analysis** | SPF, DKIM, DMARC results and alignment signals |
| **Threat intelligence** | Pluggable IP, domain, URL, and hash enrichment; mock providers work out of the box |
| **AI-assisted reasoning** | Structured header, URL, content, and correlation analysis with schema-validated evidence references |
| **Investigation graph** | Interactive relationships between senders, infrastructure, URLs, and extracted indicators |
| **Forensic timeline** | Reconstructed delivery hops plus analysis events |
| **Terminal command center** | Rich dashboards, themes, live progress, JSON output, inbox workflows, and folder watching |
| **Demo mode** | Explore the platform locally without external API keys |

## Quick start

### Option 1: Terminal command center (recommended)

**Prerequisites:** Python 3.11+ and the dependencies in
`apps/api/requirements.txt`.

```bash
git clone https://github.com/shaaannn7/sentinel.git
cd sentinel
python3 -m venv .venv
source .venv/bin/activate
pip install -r apps/api/requirements.txt
./sentinel status --animate
```

Run an investigation:

```bash
./sentinel analyze path/to/message.eml --ai
./sentinel view INV-XXXXXXXX
```

For the guided command shell:

```bash
./sentinel interactive
```

### Option 2: Docker Compose backend

Use Docker when you want PostgreSQL, Redis, and the FastAPI service instead of
the default local SQLite store. The released user experience remains the
terminal CLI.

```bash
cp .env.example .env
docker compose up --build
```

The API and OpenAPI docs are available at
[http://localhost:8000](http://localhost:8000) and
[http://localhost:8000/docs](http://localhost:8000/docs). Stop the stack with:

```bash
docker compose down
# Add -v when you intentionally want to remove PostgreSQL and upload volumes.
```

Running the launcher without a command opens the interactive terminal shell:

```bash
./sentinel
```

The same commands are available through the explicit `cli` alias:

```bash
./sentinel cli status
./sentinel cli analyze path/to/message.eml
```

SENTINEL is released as a terminal-first tool. The Rich command center provides
themes, animated progress, threat posture dashboards, forensic reports, JSON
output, inbox workflows, folder watching, and model status without requiring a
browser.

## How it works

```mermaid
flowchart LR
    A[Authorized .eml upload] --> B[Bounded validation]
    B --> C[RFC 822 / MIME parsing]
    C --> D[Structured evidence]
    D --> E[Deterministic analyzers]
    E --> F[Threat score + verdict]
    D --> G[Optional AI enrichment]
    D --> H[Optional threat intelligence]
    F --> I[Timeline, graph, report]
    G --> I
    H --> I
    I --> J[Terminal command center]
```

The core request path is:

1. Validate the file type and size, then safely store the artifact.
2. Parse the message into structured headers, body parts, attachments, and indicators.
3. Run deterministic analyzers for headers, authentication, content, URLs, domains,
   IPs, attachments, and delivery timeline.
4. Persist the investigation and evidence in the configured database.
5. Optionally enrich the result with threat intelligence and schema-validated AI
   reasoning.
6. Present an explainable result through the terminal command center and API.

AI is an explicit enrichment step. If no provider key is configured, SENTINEL
returns deterministic results and records AI enrichment as unavailable instead
of inventing a verdict.

## Architecture

SENTINEL is released as a terminal-first security tool with a FastAPI service
behind the scenes. PostgreSQL is the durable source of truth; Redis is available
for service health and future queue/worker workflows.

```text
sentinel/
├── apps/
│   ├── api/                    # FastAPI service and investigation engine
│   │   ├── app/api/routes/     # Health, investigations, and brain endpoints
│   │   ├── app/services/       # Parser, analyzers, scoring, timeline, storage
│   │   ├── app/brain/          # ML, memory, explainability, orchestration
│   │   ├── app/models/         # SQLAlchemy persistence models
│   │   └── app/tests/          # Backend tests and email fixtures
│   ├── desktop/                # Optional Electron launcher configuration
│   └── web/                    # Optional internal web assets
├── packages/                   # Shared types and UI building blocks
├── infrastructure/k8s/         # Helm chart for Kubernetes deployment
├── docs/                       # API, architecture, deployment, and security docs
├── docker-compose.yml          # Local API, PostgreSQL, and Redis stack
└── sentinel                    # Terminal launcher
```

For deeper design details, see:

- [System architecture](docs/architecture/system.md)
- [Data flow](docs/architecture/data-flow.md)
- [API guide](docs/api/api.md)
- [Security threat model](docs/security/threat-model.md)
- [Kubernetes Helm chart](infrastructure/k8s/helm-chart/)

## Configuration

Copy `.env.example` to `.env` for local configuration. Demo mode requires no
external credentials.

| Variable | Purpose | Local default |
| --- | --- | --- |
| `DATABASE_URL` | SQLAlchemy database connection | SQLite in direct local runs; PostgreSQL in Docker |
| `POSTGRES_PASSWORD` | Docker/Kubernetes database password | set a strong secret |
| `REDIS_PASSWORD` | Redis password used by Docker Compose | set a strong secret |
| `REDIS_URL` | Redis connection | authenticated URL in Docker |
| `LLM_PROVIDER` | `openai`, `anthropic`, or `mock` | `mock` |
| `LLM_API_KEY` | Provider credential | empty |
| `LLM_MODEL` | Model name passed to the provider | `gpt-4o-mini` |
| `THREAT_INTEL_PROVIDER` | Threat intelligence adapter | `mock` |
| `THREAT_INTEL_API_KEY` | Threat intelligence credential | empty |
| `GEOLOCATION_PROVIDER` | Geolocation adapter | `mock` |
| `MAX_UPLOAD_SIZE` | Maximum upload size in bytes | `10485760` |
| `DEMO_MODE` | Enable synthetic/demo behavior | `true` |
| `STORE_RAW_EMAIL` | Retain the uploaded artifact | `true` |
| `UPLOAD_DIR` | Local artifact directory | `/tmp/sentinel/uploads` |
| `CORS_ORIGINS` | Comma-separated allowed browser origins | `http://localhost:3000` |
| `AUTH_ENFORCE` | Require an API key on protected routes | `false` for demo, `true` for production |
| `ADMIN_API_KEY` / `ANALYST_API_KEY` / `VIEWER_API_KEY` | Role-based API credentials | empty in demo mode |

Never commit `.env` or provider credentials. Use a secret manager for shared
or production deployments.

## Development

### Backend

```bash
cd apps/api
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pytest
```

Run the API directly from the repository root:

```bash
PYTHONPATH=apps/api python -m uvicorn app.main:app --reload --port 8000
```

### Optional web-package checks

In a second terminal:

```bash
cd apps/web
npm install
npm run dev
```

```bash
npm run type-check
npm run lint
npm test
npm run build
```

The web package is retained for contributors and internal deployments; it is
not part of the released terminal workflow.

The terminal tool can run directly against SQLite for local use. Use
`./sentinel serve` only when another local service needs the FastAPI boundary.

## API at a glance

The complete, interactive contract is available at `/docs` while the API is
running. The most useful routes are:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Service health check |
| `POST` | `/api/v1/investigations` | Upload and analyze an `.eml` artifact |
| `GET` | `/api/v1/investigations` | List investigations |
| `GET` | `/api/v1/investigations/{id}` | Retrieve investigation details |
| `POST` | `/api/v1/investigations/{id}/analyze` | Rerun deterministic analysis |
| `GET` | `/api/v1/investigations/{id}/report` | Retrieve the explainable report |
| `GET` | `/api/v1/brain/status` | View model and memory status |
| `GET` | `/api/v1/brain/explain/{id}` | Explain the investigation verdict |
| `POST` | `/api/v1/brain/retrain` | Trigger model retraining |

Example upload with `curl`:

```bash
curl -X POST http://localhost:8000/api/v1/investigations \
  -H "accept: application/json" \
  -F "file=@path/to/message.eml;type=message/rfc822"
```

## Retraining the detection model

The ML brain is an enrichment layer; deterministic evidence and scoring remain
the safety authority. Retraining metadata records the dataset source, feature
schema, seed, metrics, and model hash.

```bash
cd apps/api
python -m app.brain.train --samples 3000 --evaluate --verbose
```

To mix generated threat samples with a cached public ham/spam corpus:

```bash
python -m app.brain.train \
  --download --real --real-limit 5000 \
  --samples 5000 --evaluate --verbose
```

Downloaded corpus files are local training inputs and are intentionally ignored
by Git. Review validation metrics before using a retrained model in production.

## Security model

SENTINEL is designed for untrusted email evidence:

- Uploads are bounded by size, extension, and MIME validation.
- HTML email is sanitized before it is rendered.
- Attachments are analyzed as data and are never executed.
- Private and reserved IPs are not sent to external intelligence providers.
- Extracted URLs are not automatically fetched.
- AI receives an allowlisted structured evidence projection, not raw MIME bytes
  or shell/browser/network tools.
- Provider responses are parsed, schema-validated, and checked against evidence
  references before persistence.
- Deterministic analysis remains authoritative when optional providers fail.

Read the [threat model](docs/security/threat-model.md) before deploying with
real mail or external providers.

## Contributing

Contributions are welcome. A typical workflow is:

```bash
git checkout -b feat/your-change
# make and test your change
git add .
git commit -m "Describe the change"
git push origin feat/your-change
```

Before opening a pull request:

1. Keep changes focused and document behavior that affects operators or users.
2. Add or update tests for changed backend and terminal behavior.
3. Run the relevant checks listed above.
4. Do not include credentials, `.env` files, databases, build output, or downloaded
   training corpora.
5. Explain security and compatibility implications in the pull request.

## Project status

The main investigation flow is implemented, including parsing, deterministic
analysis, persistence, timeline generation, threat scoring, optional AI
enrichment, terminal dashboards, CLI access, and Docker/Kubernetes deployment
artifacts. See [implementation progress](docs/implementation-progress.md) for
the current feature checklist.

## License

SENTINEL is distributed under the [MIT License](LICENSE). See
[SECURITY.md](SECURITY.md) for the vulnerability disclosure process.

---

<div align="center">
  Built for authorized defensive email investigations.
</div>
