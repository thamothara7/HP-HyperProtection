from datetime import UTC, datetime

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.schemas import ContainmentResponse, OverviewResponse, Scenario, SessionDetail, SessionStatus
from app.simulation import store

app = FastAPI(title="HP-HyperProtection API", version="0.1.0")
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def get_session(session_id: str) -> SessionDetail:
    session = store.sessions.get(session_id)
    if session is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return session


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/overview", response_model=OverviewResponse)
def overview() -> OverviewResponse:
    all_sessions = list(store.sessions.values())
    attention = sorted((s for s in all_sessions if s.risk_score >= 51), key=lambda s: s.risk_score, reverse=True)
    return OverviewResponse(active_sessions=126, elevated_sessions=8, critical_sessions=2, risk_activity=[12, 15, 18, 17, 22, 31, 28, 35, 42, 39, 46, 55, 49, 61, 59, 68, 74, 71, 88, 96, 87, 91, 82, 97], attention_sessions=attention, generated_at=datetime.now(UTC))


@app.get("/api/v1/sessions", response_model=list[SessionDetail])
def list_sessions() -> list[SessionDetail]:
    return sorted(store.sessions.values(), key=lambda session: session.risk_score, reverse=True)


@app.get("/api/v1/sessions/{session_id}", response_model=SessionDetail)
def session_detail(session_id: str) -> SessionDetail:
    return get_session(session_id)


@app.get("/api/v1/sessions/{session_id}/timeline")
def session_timeline(session_id: str):
    return get_session(session_id).timeline


@app.post("/api/v1/sessions/{session_id}/contain", response_model=ContainmentResponse)
def contain_session(session_id: str) -> ContainmentResponse:
    session = get_session(session_id)
    session.is_contained = True
    session.status = SessionStatus.CONTAINED
    return ContainmentResponse(session=session, action="REVOKE_APPLICATION_SESSION", message="The suspicious application session was contained. The identity remains active on other contexts.")


@app.get("/api/v1/simulation/scenarios", response_model=list[Scenario])
def scenarios() -> list[Scenario]:
    return store.SCENARIOS


@app.post("/api/v1/simulation/reset")
def reset_simulation() -> dict[str, str]:
    store.reset()
    return {"status": "reset"}
