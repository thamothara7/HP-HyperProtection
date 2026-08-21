# InsiderGuard

InsiderGuard is a Windows-focused, privacy-conscious insider-threat and compromised-account detection platform. It evaluates **identity × session × device context** after authentication, then contains only the risky application session when evidence warrants it.

It does not claim to prove the physical person behind a session. It detects behavioral inconsistency using security metadata.

## Current capabilities

- SOC console: overview, sessions, identities, incidents, telemetry, baselines, decoys, policy, and simulation views
- Typed FastAPI API with SQLite + SQLAlchemy storage and Alembic migration entry point
- Normalized event contract and session correlation primitives
- Trusted baseline primitives, peer comparison, robust statistics, poisoning safeguards, rolling features, within-session drift, explainable rules, sequence memory, intent assessment, risk composition, and Isolation Forest wrapper
- Controlled corporate-resource gateway that routes only eligible application requests to synthetic decoys
- Session-only containment and audited response action records

## Privacy and safety

InsiderGuard does **not** collect keystrokes, passwords, screen/video recordings, webcams, microphones, chat messages, or document contents. Analytics use pseudonymous identities and security-relevant metadata.

High anomaly is not a maliciousness verdict. Deception requires high session risk, a deception-eligible intent, sufficient intent confidence, and no verified legitimate override. The controlled gateway cannot redirect arbitrary Windows traffic.

## Local setup

Requirements: Python 3.12+, Node.js 20+, npm.

```bash
git clone https://github.com/thamothara7/HP-HyperProtection.git
cd HP-HyperProtection/backend
python3 -m pip install -e '.[dev]'
python3 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In a second terminal:

```bash
cd HP-HyperProtection/frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal (normally `http://localhost:5173`).

## Verify

```bash
cd backend && python3 -m pytest -q
cd frontend && npm run build
```

## API quick reference

| Area | Endpoint |
| --- | --- |
| Overview | `GET /api/v1/overview` |
| Sessions | `GET /api/v1/sessions`, `GET /api/v1/sessions/{id}` |
| Session decision data | `GET /api/v1/sessions/{id}/risk`, `/features`, `/timeline` |
| Session containment | `POST /api/v1/sessions/{id}/contain` |
| Telemetry | `GET /api/v1/events` |
| Identities | `GET /api/v1/identities`, `/api/v1/identities/{id}/sessions` |
| Deception evidence | `GET /api/v1/deception/interactions` |
| Simulation | `GET /api/v1/simulation/scenarios`, `POST /api/v1/simulation/reset` |

## Repository layout

```text
backend/app/     API, persistence, detection, policy, decoy modules
backend/tests/   API, policy, detection, baseline and sequence tests
frontend/        React/Vite SOC console and InsiderGuard brand assets
docs/            Architecture and UI research notes
```

## Next backend work

Connect normalized event ingestion to durable session correlation and the feature/risk pipeline, add WebSocket streams, then implement the local pywin32 Security Event Log reader. WEF/WEC follows that local reader; Sysmon remains optional enrichment and is not agentless telemetry.
