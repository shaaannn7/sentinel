# SENTINEL

**AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform**

SENTINEL is a modern SOC investigation platform that transforms suspicious emails into structured security investigations. It parses email headers, authentication results, sender information, URLs, IP addresses, attachments, and message content; performs deterministic security analysis; enriches extracted indicators with threat intelligence; performs AI-assisted reasoning and correlation; reconstructs email delivery timelines; visualizes relationships between entities; provides approximate infrastructure geolocation; calculates a transparent threat score; and generates an explainable forensic investigation report.

## ✅ Implementation Status - COMPLETE

All specified features have been implemented according to the specification. See [docs/implementation-progress.md](docs/implementation-progress.md) for the full implementation status.

## Features

- **Email Ingestion** – Upload `.eml` files for analysis
- **Deterministic Parsing** – Extract headers, body, attachments, URLs, IPs, authentication results
- **Deterministic Threat Analysis** – Modular evidence-first analyzers, bounded scoring, conservative verdicts, and forensic timeline
- **Authentication Analysis** – SPF, DKIM, DMARC verification and alignment checks
- **Threat Intelligence** – IP/domain/URL/hash reputation enrichment (mock provider for demo)
- **AI-Assisted Reasoning** – Structured agents for header, URL, content, and correlation analysis
- **Investigation Graph** – Interactive relationship visualization (React Flow)
- **Forensic Timeline** – Delivery hop timeline with analysis events
- **Explainable Reports** – Evidence-backed investigation reports with citations
- **Demo Mode** – Works without external API keys using synthetic data

## Tech Stack

| Layer | Technology |
|-------|------------|
| Backend | Python 3.11, FastAPI, SQLAlchemy, Pydantic |
| Frontend | Next.js 14 (App Router), TypeScript, Tailwind CSS, React Query, React Flow |
| Database | PostgreSQL 15+ |
| Cache/Queue | Redis 7+ |
| Containerization | Docker, Docker Compose, Helm (Kubernetes) |
| Testing | pytest, httpx, Jest, React Testing Library, Playwright |
| CI/CD | GitHub Actions |

## Project Structure

```
sentinel/
├── apps/
│   ├── api/                 # FastAPI backend
│   │   ├── app/
│   │   │   ├── main.py      # FastAPI entry point
│   │   │   ├── services/    # Business logic (parser, intel, AI)
│   │   │   ├── models/      # SQLAlchemy models
│   │   │   ├── schemas/     # Pydantic schemas
│   │   │   └── tests/       # Unit/integration tests
│   │   └── Dockerfile
│   └── web/                 # Next.js frontend
│       ├── src/
│       │   ├── app/         # App Router pages
│       │   ├── components/  # Reusable UI components
│       │   ├── hooks/       # Custom React hooks
│       │   ├── lib/         # API client, utilities
│       │   └── styles/      # Global styles
│       └── Dockerfile
├── packages/
│   ├── shared-types/        # Shared TypeScript/Python types
│   └── ui/                  # Shared UI component library
├── infrastructure/
│   ├── docker-compose.yml   # Local development stack
│   └── k8s/
│       └── helm-chart/      # Kubernetes Helm chart
├── docs/
│   ├── architecture.md
│   ├── api.md
│   ├── deployment.md
│   └── security.md
├── .env.example
├── .gitignore
└── README.md
```

## Quick Start (Docker Compose)

### Prerequisites
- Docker 24+
- Docker Compose 2+

### 1. Clone and Configure
```bash
git clone <repository-url>
cd sentinel
cp .env.example .env
# Edit .env with your configuration (optional for demo mode)
```

### 2. Start Services
```bash
docker compose up --build
```

Services will be available at:
- **Frontend**: http://localhost:3000
- **API**: http://localhost:8000
- **API Docs**: http://localhost:8000/docs
- **PostgreSQL**: localhost:5432
- **Redis**: localhost:6379

### 3. Run an Investigation
1. Open http://localhost:3000
2. Click "New Investigation"
3. Drag and drop a `.eml` file or click to select
4. Click "Start Investigation"
5. View results in the investigation detail page

## Choose GUI or CLI

SENTINEL provides the same investigation engine through two user-selectable
interfaces.

### Browser GUI

From the repository root, run:

```bash
./sentinel gui
```

This starts the API on `http://127.0.0.1:8000`, starts the Next.js GUI on
`http://127.0.0.1:3000`, and opens the browser when `xdg-open` is available.
Stop it with `Ctrl+C`.

### Terminal CLI

Run the CLI explicitly with:

```bash
./sentinel cli --help
./sentinel cli analyze path/to/message.eml
./sentinel cli list
```

Existing commands remain compatible, so `./sentinel analyze path/to/message.eml`
continues to run the terminal interface. The GUI and CLI use the same API,
database, parser, analysis pipeline, and stored investigations.

## Retraining the detection brain

SENTINEL can retrain its ML enrichment model from the API directory. The
stronger workflow mixes cached public ham/spam messages with generated
phishing and malware samples:

```bash
cd apps/api
python -m app.brain.train --download --real --real-limit 5000 \
  --samples 5000 --evaluate --verbose
```

Training metadata records the dataset source, feature schema, seed, metrics,
and model hash in `app/brain/ml/model_meta.json`. Deterministic evidence and
scoring remain the safety authority; ML accuracy on synthetic or public
corpora must not be interpreted as a guarantee for arbitrary email.

## Configuration

Key environment variables (see `.env.example`):

| Variable | Description | Default |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+psycopg2://sentinel@postgres:5432/sentinel` |
| `REDIS_URL` | Redis connection string | `redis://redis:6379/0` |
| `LLM_PROVIDER` | AI provider (`openai`, `anthropic`, `mock`) | `mock` |
| `LLM_API_KEY` | API key for LLM provider | (empty) |
| `THREAT_INTEL_PROVIDER` | Threat intel provider (`mock`, `virustotal`, `abuseipdb`) | `mock` |
| `MAX_UPLOAD_SIZE` | Max upload size in bytes | `10485760` (10 MB) |
| `DEMO_MODE` | Enable demo mode with mock data | `true` |

## Development

### Backend
```bash
cd apps/api
python -m venv venv
source venv/bin/activate
pip install -e .[dev]
pytest
```

### Frontend
```bash
cd apps/web
npm install
npm run dev
npm test
```

## Demo Mode

Set `DEMO_MODE=true` (default) to use synthetic sample investigations and mock threat intelligence. No external API keys required.

Sample investigations included:
1. Obvious phishing (brand impersonation, auth failures)
2. Legitimate corporate email
3. Suspicious password reset
4. Invoice fraud
5. Mixed/ambiguous case

## API Documentation

When the API is running, visit http://localhost:8000/docs for interactive OpenAPI documentation.

Key endpoints:
- `POST /api/v1/investigations` – Upload `.eml` and start investigation
- `GET /api/v1/investigations` – List investigations
- `GET /api/v1/investigations/{id}` – Get investigation details
- `GET /api/v1/investigations/{id}/report` – Get AI-generated report
- `POST /api/v1/investigations/{id}/analyze` – Run or rerun deterministic Phase 2 analysis

## Security Considerations

- All uploads validated (size, MIME type, extension)
- HTML email bodies sanitized before rendering
- No execution of attachments
- Private IPs never sent to external threat intel providers
- Rate limiting on upload endpoint
- Structured logging without sensitive data
- AI enrichment is optional, evidence-only, schema-validated, and audited; deterministic analysis remains authoritative
- No extracted URL is automatically fetched, and private/reserved IPs are marked to prevent external enrichment leakage

## Architecture and security review

See [`docs/architecture/overview.md`](docs/architecture/overview.md), [`docs/architecture/data-flow.md`](docs/architecture/data-flow.md), and [`docs/security/threat-model.md`](docs/security/threat-model.md) for trust boundaries, data flow, residual risks, and deployment prerequisites.

## License

MIT License – see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests and linting
5. Submit a pull request

## Disclaimer

SENTINEL is an analytical aid for authorized defensive cybersecurity investigations. Results should be reviewed by an authorized analyst before high-impact decisions. The platform analyzes submitted artifacts and publicly available/passive intelligence only.

## Implementation Progress

For a complete checklist of completed features, see [docs/implementation-progress.md](docs/implementation-progress.md).