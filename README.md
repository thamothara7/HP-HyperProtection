# HP-HyperProtection

HP-HyperProtection is a Windows-focused, privacy-conscious prototype for detecting risky authenticated behaviour at the **identity × session × device-context** level.

This first vertical slice establishes the contract between the SOC console and the detection pipeline. It uses safe synthetic scenarios while the telemetry, database, baseline, and model layers are built incrementally.

## What is working now

- FastAPI API with typed session, intent, evidence timeline, and overview contracts
- Simulated concurrent Alice sessions: `MGR-PC` remains normal while `EMP-PC-22` is contained
- Explainable investigation console with risk activity, evidence, intent, comparison, and containment state
- An approved bulk-operation scenario that stays high-risk but is not a deception candidate
- Session-only containment API; no identity-wide account disablement

## Run locally

Use two terminals.

```bash
cd backend
python3 -m pip install -e '.[dev]'
python3 -m uvicorn app.main:app --reload --port 8000
```

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`.

## Safety boundary

This is not an attribution system: it detects behavioural inconsistency in an authenticated context. It collects neither keystrokes, passwords, screenshots, recordings, personal content, nor biometric signals. The forthcoming controlled deception feature will apply only to resources behind the corporate application's policy gateway; it cannot redirect arbitrary Windows traffic.

## Next implementation stage

Stage 2 replaces the in-memory simulation state with normalized events, session correlation, SQLite persistence, and a live WebSocket stream. Windows Event Log ingestion begins only after that path is testable end-to-end.
