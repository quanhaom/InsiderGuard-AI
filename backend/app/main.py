from fastapi import FastAPI

from app.modules.behavior_twin.router import (
    router as behavior_twin_router,
)
from app.modules.events.router import (
    router as events_router,
)


app = FastAPI(
    title="InsiderGuard AI",
    version="1.0.0"
)


app.include_router(
    events_router,
    prefix="/api/v1"
)

app.include_router(
    behavior_twin_router,
    prefix="/api/v1"
)


@app.get("/")
def root():
    return {
        "project": "InsiderGuard AI",
        "status": "running"
    }