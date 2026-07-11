from fastapi import FastAPI
from app.modules.ueba.router import router as ueba_router
from app.modules.behavior_twin.router import (
    router as behavior_twin_router,
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

app = FastAPI(
    title="InsiderGuard AI",
    version="1.0.0"
)

app.include_router(
    ueba_router,
    prefix="/api/v1"
)

app.include_router(
    events_router,
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
    evidence_router,
    prefix="/api/v1"
)

@app.get("/")
def root():
    return {
        "project": "InsiderGuard AI",
        "status": "running"
    }