from contextlib import asynccontextmanager
from datetime import UTC, datetime

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.db.bootstrap import create_schema, seed_demo_if_empty
from app.db.models import DecoyInteractionRecord, EventRecord, IdentityRecord, IncidentRecord, SessionRecord
from app.db.repository import contain, list_session_details, session_detail, session_summary
from app.db.session import SessionLocal
from app.schemas import ContainmentResponse, OverviewResponse, Scenario, SessionDetail
from app.simulation.store import SCENARIOS
from app.deception.decoy_data import DECOYS, decoy_payload
from app.policy.engine import deception_allowed
from app.ingestion import ingest_event
from app.normalization.event import NormalizedEvent
from app.realtime import hub


@asynccontextmanager
async def lifespan(_: FastAPI):
    create_schema()
    with SessionLocal() as db:
        seed_demo_if_empty(db)
    yield


app = FastAPI(title="HP-HyperProtection API", version="0.2.0", lifespan=lifespan)
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:5173"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])


def get_session_or_404(db: Session, session_id: str) -> SessionDetail:
    detail = session_detail(db, session_id)
    if detail is None:
        raise HTTPException(status_code=404, detail="Session not found")
    return detail


def get_ready_db():
    """Keeps scripts and test clients usable even when their lifespan is not entered."""
    create_schema()
    db = SessionLocal()
    try:
        seed_demo_if_empty(db)
        yield db
    finally:
        db.close()


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/v1/overview", response_model=OverviewResponse)
def overview(db: Session = Depends(get_ready_db)) -> OverviewResponse:
    details = list_session_details(db)
    attention = [detail for detail in details if detail.risk_score >= 51]
    active = db.scalar(select(func.count()).select_from(SessionRecord).where(SessionRecord.closed_at.is_(None))) or 0
    elevated = sum(31 <= detail.risk_score <= 74 for detail in details)
    critical = sum(detail.risk_score >= 75 for detail in details)
    activity = [12, 15, 18, 17, 22, 31, 28, 35, 42, 39, 46, 55, 49, 61, 59, 68, 74, 71, 88, 96, 87, 91, 82, 97]
    return OverviewResponse(active_sessions=active, elevated_sessions=elevated, critical_sessions=critical, risk_activity=activity, attention_sessions=[session_summary(db.get(SessionRecord, detail.id)) for detail in attention], generated_at=datetime.now(UTC))


@app.get("/api/v1/sessions", response_model=list[SessionDetail])
def list_sessions(db: Session = Depends(get_ready_db)) -> list[SessionDetail]:
    return list_session_details(db)


@app.get("/api/v1/sessions/{session_id}", response_model=SessionDetail)
def get_session(session_id: str, db: Session = Depends(get_ready_db)) -> SessionDetail:
    return get_session_or_404(db, session_id)


@app.get("/api/v1/sessions/{session_id}/timeline")
def session_timeline(session_id: str, db: Session = Depends(get_ready_db)):
    return get_session_or_404(db, session_id).timeline


@app.get("/api/v1/sessions/{session_id}/risk")
def session_risk(session_id: str, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    detail = get_session_or_404(db, session_id)
    return {"session_id": session_id, "risk_score": detail.risk_score, "anomaly_score": detail.anomaly_score, "sequence_score": detail.sequence_score, "explanation": detail.reason_codes}


@app.get("/api/v1/sessions/{session_id}/features")
def session_features(session_id: str, db: Session = Depends(get_ready_db)) -> dict[str, object]:
    detail = get_session_or_404(db, session_id)
    return {"session_id": session_id, "new_hosts": detail.new_hosts, "remote_access_ratio": detail.remote_access_ratio, "privilege_attempts": detail.privilege_attempts, "baseline_comparison": detail.baseline_comparison}


@app.post("/api/v1/sessions/{session_id}/contain", response_model=ContainmentResponse)
async def contain_session(session_id: str, db: Session = Depends(get_ready_db)) -> ContainmentResponse:
    summary = contain(db, session_id)
    if summary is None:
        raise HTTPException(status_code=404, detail="Session not found")
    response = ContainmentResponse(session=summary, action="REVOKE_APPLICATION_SESSION", message="The suspicious application session was contained. The identity remains active on other contexts.")
    await hub.publish("incidents", {"type": "SESSION_CONTAINED", "session_id": summary.id, "identity_id": summary.identity_id, "risk_score": summary.risk_score})
    return response


@app.get("/api/v1/events")
def events(limit: int = 100, db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    records = db.scalars(select(EventRecord).order_by(EventRecord.timestamp.desc()).limit(min(max(limit, 1), 500))).all()
    return [{"event_id": record.id, "timestamp": record.timestamp, "identity_id": record.identity_id, "session_id": record.session_id, "device_id": record.device_id, "event_type": record.event_type, "source": record.source, "target": record.target, "action": record.action, "result": record.result} for record in records]


@app.post("/api/v1/events", response_model=SessionDetail, status_code=201)
async def ingest_normalized_event(event: NormalizedEvent, db: Session = Depends(get_ready_db)) -> SessionDetail:
    """Ingestion boundary for real normalized Windows metadata and approved collectors."""
    try:
        session = ingest_event(db, event)
    except ValueError as error:
        raise HTTPException(status_code=409, detail=str(error)) from error
    detail = session_detail(db, session.id)
    if detail is None:
        raise HTTPException(status_code=500, detail="Session was not available after ingestion")
    await hub.publish("events", {"type": "NORMALIZED_EVENT", "event_id": event.event_id, "timestamp": event.timestamp.isoformat(), "identity_id": event.identity_id, "session_id": detail.id, "device_id": event.device_id, "event_type": event.event_type.value, "target": event.target, "result": event.result})
    await hub.publish("risk", {"type": "SESSION_RISK_UPDATED", "session_id": detail.id, "identity_id": detail.identity_id, "risk_score": detail.risk_score, "anomaly_score": detail.anomaly_score, "sequence_score": detail.sequence_score, "intent": detail.intent.value, "status": detail.status.value})
    return detail


async def websocket_topic(websocket: WebSocket, topic: str) -> None:
    await hub.connect(topic, websocket)
    try:
        while True:
            # The stream is server-driven; receive keeps the connection alive.
            await websocket.receive_text()
    except WebSocketDisconnect:
        await hub.disconnect(topic, websocket)


@app.websocket("/ws/events")
async def events_stream(websocket: WebSocket) -> None:
    await websocket_topic(websocket, "events")


@app.websocket("/ws/risk")
async def risk_stream(websocket: WebSocket) -> None:
    await websocket_topic(websocket, "risk")


@app.websocket("/ws/incidents")
async def incident_stream(websocket: WebSocket) -> None:
    await websocket_topic(websocket, "incidents")


@app.get("/api/v1/identities")
def identities(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    records = db.scalars(select(IdentityRecord).order_by(IdentityRecord.id)).all()
    return [{"id": record.id, "department": record.department, "role": record.role, "sessions": [session_summary(item).model_dump() for item in db.scalars(select(SessionRecord).where(SessionRecord.identity_id == record.id)).all()]} for record in records]


@app.get("/api/v1/identities/{identity_id}/sessions")
def identity_sessions(identity_id: str, db: Session = Depends(get_ready_db)) -> list[SessionDetail]:
    if db.get(IdentityRecord, identity_id) is None:
        raise HTTPException(status_code=404, detail="Identity not found")
    return [detail for detail in list_session_details(db) if detail.identity_id == identity_id]


@app.get("/api/v1/incidents")
def incidents(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    return [{"id": item.id, "session_id": item.session_id, "title": item.title, "severity": item.severity, "status": item.status, "summary": item.summary, "created_at": item.created_at} for item in db.scalars(select(IncidentRecord).order_by(IncidentRecord.created_at.desc())).all()]


@app.get("/api/v1/deception/interactions")
def decoy_interactions(db: Session = Depends(get_ready_db)) -> list[dict[str, object]]:
    return [{"session_id": item.session_id, "resource": item.resource, "action": item.action, "confidence_delta": item.confidence_delta, "observed_at": item.observed_at} for item in db.scalars(select(DecoyInteractionRecord).order_by(DecoyInteractionRecord.observed_at.desc())).all()]


@app.get("/corp/{path:path}")
def corporate_resource(path: str, x_insiderguard_session: str = Header(), db: Session = Depends(get_ready_db)) -> dict[str, object]:
    """Policy enforcement point for the controlled demo application only."""
    detail = get_session_or_404(db, x_insiderguard_session)
    decision = deception_allowed(risk_score=detail.risk_score, intent=detail.intent.value, intent_confidence=detail.intent_confidence, strong_legitimate_override=detail.approved_override)
    resource_path = f"/{path}"
    if decision.allow_decoy and resource_path in DECOYS:
        resource = DECOYS[resource_path]
        db.add(DecoyInteractionRecord(session_id=detail.id, resource=resource.path, action="ACCESSED", confidence_delta=12))
        db.commit()
        return {"route": "DECOY", "policy_reason": decision.reason, "payload": decoy_payload(resource)}
    return {"route": "REAL", "policy_reason": decision.reason, "resource": resource_path, "content": "Controlled corporate application response."}


@app.get("/api/v1/simulation/scenarios", response_model=list[Scenario])
def scenarios() -> list[Scenario]:
    return SCENARIOS


@app.post("/api/v1/simulation/reset")
def reset_simulation(db: Session = Depends(get_ready_db)) -> dict[str, str]:
    db.query(EventRecord).where(EventRecord.id.like("EVT-SES-%")).delete(synchronize_session=False)
    db.query(SessionRecord).where(SessionRecord.id.like("SES-%")).delete(synchronize_session=False)
    db.commit()
    seed_demo_if_empty(db)
    return {"status": "reset"}
