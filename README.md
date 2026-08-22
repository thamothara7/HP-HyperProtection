# HyperProtection

HyperProtection is a Windows-focused, privacy-conscious SOC platform for detecting compromised accounts and insider-threat behavior after authentication.

It evaluates:

```text
Identity × Session × Device × Resource × Sequence
```

The system detects behavioral inconsistency; it does not claim perfect physical-human attribution or permanently label an employee as malicious.

## System design

```text
Windows endpoints
  └─ Security logs / ETW / optional Sysmon
       └─ local collector or WEF/WEC ForwardedEvents
            └─ HTTPS normalized events + collector token
                 └─ FastAPI control plane
                      ├─ privacy + session correlation
                      ├─ rolling features + personal/peer baselines
                      ├─ rules + Isolation Forest + sequence memory
                      ├─ intent + risk composition
                      ├─ SQLAlchemy SQLite/PostgreSQL persistence
                      └─ WebSocket events/risk/incidents
                           └─ React SOC console

Protected corporate request
  └─ policy gateway
       ├─ real resource
       └─ synthetic decoy (only risk + intent + confidence + no override)
```

### Detection flow

```text
AUTH_SUCCESS → session/device correlation → rolling features
→ personal baseline + peer baseline → rules/ML/sequence/drift
→ explainable risk + intent confidence → monitor or respond
→ decoy evidence → incident → application-session-only containment
```

High anomaly alone never activates deception. Approved bulk operations, maintenance windows, SOC exceptions, and strong reauthentication can suppress deception while monitoring continues.

## Capabilities

- Windows Security and ForwardedEvents ingestion with typed normalized events
- Pseudonymous identity analysis and privacy boundary enforcement
- Personal/peer baselines with robust statistics and poisoning safeguards
- Rolling features, within-session drift, sequence memory, explainable rules, intent, and Isolation Forest scoring
- Controlled corporate routes: `/dashboard`, `/reports`, `/admin`, `/files`, `/export`
- Synthetic decoys, honey-credential evidence, incident creation, and session-only containment
- SQLite development persistence, PostgreSQL/Alembic deployment path
- WebSocket live streams: `/ws/events`, `/ws/risk`, `/ws/incidents`
- Live device and traffic metadata APIs: `/api/v1/devices`, `/api/v1/traffic`

## Privacy boundary

HyperProtection does not collect keystrokes, passwords, screenshots, screen recordings, webcam/microphone data, personal chats, or document contents. It collects security metadata such as authentication events, devices, sessions, resource categories, target systems, privilege activity, access frequency, source IP metadata, and event sequences.

The policy gateway is the enforcement point. Arbitrary Windows traffic cannot be transparently redirected, and decoys never contain real corporate data.

## Local setup

Requirements: Python 3.12+, Node.js 20+, npm.

```bash
git clone https://github.com/thamothara7/HP-HyperProtection.git
cd HP-HyperProtection/backend
python3 -m pip install -e '.[dev]'
python3 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

In another terminal:

```bash
cd HP-HyperProtection/frontend
npm install
npm run dev
```

Open `http://localhost:5173`. SQLite is created automatically for development. PostgreSQL setup is documented in [docs/production-database.md](docs/production-database.md).

## Verification

```bash
cd backend
python3 -m pytest -q
python3 -m compileall -q app
cd ../frontend
npm run build
```

## Private-network testing

Run the backend on an authorized private interface:

```bash
python3 -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Find the control-plane address:

```bash
# macOS
ipconfig getifaddr en0

# Windows
ipconfig
```

From an authorized endpoint:

```powershell
Test-NetConnection CONTROL_PLANE_IP -Port 8000
Invoke-WebRequest http://CONTROL_PLANE_IP:8000/health
```

Do not expose port 8000 to the public internet. Use a private LAN/VPN and configure `HYPERPROTECTION_COLLECTOR_TOKEN` on both backend and collector when authentication is enabled.

## Windows collector

Endpoint collection is Windows-only because it uses Windows Security Event Logs, WEF/WEC ForwardedEvents, and optional pywin32/Sysmon enrichment. The backend, database, simulation, and frontend can run on Windows, macOS, or Linux.

```powershell
cd backend
$env:HYPERPROTECTION_API_URL="http://CONTROL_PLANE_IP:8000"
$env:HYPERPROTECTION_COLLECTOR_TOKEN="replace-with-a-random-secret"
python -m app.collector.service --source security --endpoint http://CONTROL_PLANE_IP:8000 --collector-id MGR-PC --interval 5
```

For WEC:

```powershell
python -m app.collector.service --source forwarded --endpoint http://CONTROL_PLANE_IP:8000 --collector-id WEC-01 --interval 5
```

Collector liveness: `GET /api/v1/collectors`.

## API quick reference

| Area | Endpoints |
| --- | --- |
| Health | `GET /health`, `GET /api/v1/collectors` |
| Overview | `GET /api/v1/overview` |
| Sessions | `GET /api/v1/sessions`, `GET /api/v1/sessions/{id}`, `/risk`, `/features`, `/timeline` |
| Containment | `POST /api/v1/sessions/{id}/contain` |
| Events | `GET/POST /api/v1/events` |
| Devices/traffic | `GET /api/v1/devices`, `GET /api/v1/traffic` |
| Identities/baselines | `/api/v1/identities`, `/api/v1/identities/{id}/baseline` |
| Incidents | `/api/v1/incidents`, `/api/v1/incidents/{id}` |
| Deception | `/api/v1/deception/resources`, `/sessions`, `/interactions` |
| Corporate app | `/dashboard`, `/reports`, `/admin`, `/files/...`, `/export` with `X-HyperProtection-Session` |
| Simulation | `/api/v1/simulation/scenarios`, `POST /run`, `POST /reset` |
| WebSockets | `/ws/events`, `/ws/risk`, `/ws/incidents` |

## Repository layout

```text
backend/app/collector       Windows Security/WEF readers and service
backend/app/normalization   Typed normalized event contract
backend/app/privacy         Pseudonymization and sanitization
backend/app/sessions        Correlation and within-session drift
backend/app/features        Rolling feature extraction
backend/app/baseline        Personal/peer baselines and poisoning guard
backend/app/detection       Rules, sequence memory, intent
backend/app/risk             Risk composition and thresholds
backend/app/policy           Override and deception gates
backend/app/deception        Synthetic resources and evidence
backend/app/corporate        Controlled application enforcement
backend/app/db               SQLAlchemy models and repositories
backend/app/simulation       End-to-end demo scenarios
backend/tests                API, detection, baseline, policy, collector tests
frontend/src                 React/Vite SOC console
docs                         Architecture, Windows, database, UI notes
```

## Limitations

- Endpoint telemetry is Windows-only.
- An IP address alone cannot identify the physical person using a session.
- Website visibility requires an authorized proxy, DNS, or browser-security integration.
- Arbitrary file-copy/download visibility requires endpoint or application-specific telemetry.
- Decoys work only for routes protected by the controlled corporate-app gateway.
- This is a hackathon prototype, not an EDR or SIEM replacement.
