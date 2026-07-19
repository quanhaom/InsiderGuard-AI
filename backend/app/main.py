from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.modules.ueba.router import router as ueba_router
from app.modules.behavior_twin.router import (
    router as behavior_twin_router,
)
from app.modules.entities.router import (
    router as entities_router,
)
from app.modules.threat_hunting.router import (
    router as threat_hunting_router
)
from app.modules.windows_events.router import (
    router as windows_event_router
)
from app.modules.events.router import (
    router as events_router,
)
from app.modules.incidents.router import (
    router as incidents_router,
)
from app.modules.evidence.router import (
    router as evidence_router,
)
from app.modules.blockchain.router import (
    router as blockchain_router,
)
from app.modules.investigator.router import (
    router as investigator_router,
)
from app.modules.collector.router import (
    router as collector_router,
)
from app.modules.dashboard.router import (
    router as dashboard_router,
)
from app.api.dashboard import router as dashboard_router
from app.modules.event_explorer.router import (
    router as event_explorer_router,
)
from app.modules.case_explorer.router import (
    router as case_explorer_router,
)
from app.modules.behavior_profile.router import (
    router as behavior_profile_router,
)
app = FastAPI(
    title="InsiderGuard AI",
    version="1.0.0"
)
app.add_middleware(

    CORSMiddleware,

    allow_origins=[
        "http://localhost:5173"
    ],

    allow_credentials=True,

    allow_methods=[
        "*"
    ],

    allow_headers=[
        "*"
    ]
)

app.include_router(
    entities_router,
    prefix="/api/v1",
)

app.include_router(
    threat_hunting_router,
    prefix="/api/v1"
)

app.include_router(
    event_explorer_router,
    prefix="/api/v1",
)

app.include_router(
    case_explorer_router,
    prefix="/api/v1",
)
app.include_router(
    dashboard_router,
    prefix="/api/v1"
)
app.include_router(
    dashboard_router,
    prefix="/api/v1",
)
app.include_router(
    windows_event_router,
    prefix="/api/v1"
)

# Existing modules
app.include_router(
    ueba_router,
    prefix="/api/v1"
)

app.include_router(
    events_router,
    prefix="/api/v1"
)

app.include_router(
    collector_router,
    prefix="/api/v1"
)

app.include_router(
    investigator_router,
    prefix="/api/v1"
)

app.include_router(
    blockchain_router,
    prefix="/api/v1"
)

app.include_router(
    behavior_twin_router,
    prefix="/api/v1"
)

app.include_router(
    incidents_router,
    prefix="/api/v1"
)
app.include_router(
    behavior_profile_router,
    prefix="/api/v1",
)

app.include_router(
    evidence_router,
    prefix="/api/v1"
)


@app.get("/")
def root():
    return {
        "project": "InsiderGuard AI",
        "status": "running"
    }