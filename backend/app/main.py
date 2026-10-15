import asyncio
import contextlib
import logging
import time

from fastapi import Depends, FastAPI, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import Counter, Gauge, generate_latest
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api import (
    audit,
    auth,
    dashboard,
    devices,
    events,
    incidents,
    ml,
    network,
    oauth,
    reports,
    search,
    servers,
    trust,
    users,
)
from app.database.connection import Base, SessionLocal, engine, get_db
from app.models import (
    AuditLog,
    Device,
    Incident,
    Role,
    SecurityEvent,
    Server,
    TrustScore,
    User,
)
from app.security.audit import write_audit_log
from app.security.auth import decode_access_token
from app.security.dependencies import get_client_ip, get_client_user_agent
from app.services import alerts
from app.services.scheduler import traffic_loop, trust_loop, warmup
from app.services.websocket import manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("zerotrust")

# ---------------------------------------------------------------- metrics
REQUESTS = Counter("http_requests_total", "HTTP requests", ["method", "path", "status"])
WS_CONNECTIONS = Gauge("ws_connections", "Active WebSocket connections")


@contextlib.asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    alerts.bind_main_loop(asyncio.get_running_loop())
    Base.metadata.create_all(bind=engine)
    try:
        await warmup()
    except Exception as exc:
        logger.warning("Warmup failed (continuing): %s", exc)

    tasks = [
        asyncio.create_task(traffic_loop()),
        asyncio.create_task(trust_loop()),
    ]
    logger.info("Zero-Trust Platform started")
    yield
    # Shutdown
    for task in tasks:
        task.cancel()
    logger.info("Zero-Trust Platform stopped")


app = FastAPI(
    title="Zero-Trust Security Platform",
    description=(
        "AI-powered Data-Center Cybersecurity Monitoring Platform. "
        "Zero-trust access control, network monitoring, ML anomaly detection, "
        "suspicious-login alerts, device/server trust scores, incident "
        "investigation, audit logs and reports."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------- routers
app.include_router(auth.router)
app.include_router(oauth.router)
app.include_router(users.router)
app.include_router(dashboard.router)
app.include_router(devices.router)
app.include_router(servers.router)
app.include_router(network.router)
app.include_router(events.router)
app.include_router(incidents.router)
app.include_router(trust.router)
app.include_router(audit.router)
app.include_router(reports.router)
app.include_router(search.router)
app.include_router(ml.router)


# ------------------------------------------------------- audit middleware
@app.middleware("http")
async def audit_and_metrics(request: Request, call_next):
    start = time.time()
    response = await call_next(request)

    # Metrics
    REQUESTS.labels(
        method=request.method,
        path=request.url.path,
        status=response.status_code,
    ).inc()

    # Audit: skip static/non-API paths and already-logged auth actions
    path = request.url.path
    if path.startswith(("/auth", "/oauth", "/ws", "/metrics", "/health", "/")):
        return response

    try:
        auth_header = request.headers.get("authorization", "")
        if auth_header.startswith("Bearer "):
            payload = decode_access_token(auth_header[7:])
            if payload and payload.get("sub"):
                db: Session = SessionLocal()
                try:
                    user = db.query(User).filter(
                        User.id == int(payload["sub"])
                    ).first()
                    if user:
                        write_audit_log(
                            db,
                            user_id=user.id,
                            username=user.username,
                            action=f"{request.method.lower()}.{path.strip('/').split('/')[0]}",
                            resource_type=path.strip("/").split("/")[0],
                            ip_address=get_client_ip(request),
                            user_agent=get_client_user_agent(request),
                            details={
                                "path": path,
                                "duration_ms": round((time.time() - start) * 1000, 1),
                                "status": response.status_code,
                            },
                        )
                finally:
                    db.close()
    except Exception as exc:
        logger.debug("Audit middleware skipped: %s", exc)

    return response


# ------------------------------------------------------------------ root
@app.get("/")
def root():
    return {
        "message": "Zero-Trust Security Platform API",
        "status": "running",
        "docs": "/docs",
        "realtime": "/ws/alerts",
        "metrics": "/metrics",
    }


@app.get("/health")
def health():
    return {"status": "healthy"}


@app.get("/health/database")
def database_health(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        return {"status": "healthy", "database": "connected"}
    except Exception as e:
        return {"status": "unhealthy", "database": "disconnected", "error": str(e)}


@app.get("/metrics")
def metrics():
    return Response(
        content=generate_latest(),
        media_type="text/plain",
    )


# ------------------------------------------------------------ WebSockets
@app.websocket("/ws/alerts")
async def websocket_alerts(websocket: WebSocket):
    """Real-time alert stream. Authenticate with ?token=<access_token>."""
    token = websocket.query_params.get("token", "")
    payload = decode_access_token(token)
    if not payload or not payload.get("sub"):
        await websocket.close(code=4401)
        return

    await manager.connect(websocket)
    WS_CONNECTIONS.set(len(manager.active_connections))
    try:
        await websocket.send_json({
            "type": "connected",
            "detail": "Real-time security alert stream ready",
        })
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
        WS_CONNECTIONS.set(len(manager.active_connections))
    except Exception:
        manager.disconnect(websocket)
        WS_CONNECTIONS.set(len(manager.active_connections))