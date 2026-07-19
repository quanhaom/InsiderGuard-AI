from fastapi import APIRouter
from sqlalchemy.orm import Session

from app.db.session import get_db
from fastapi import Depends

from app.models.normalized_windows_event import (
    NormalizedWindowsEvent,
)

router = APIRouter(
    prefix="/threat-hunting",
    tags=["Threat Hunting"],
)


@router.get("/events")
def get_events(
    limit: int = 100,
    db: Session = Depends(get_db),
):

    events = (
        db.query(
            NormalizedWindowsEvent
        )
        .order_by(
            NormalizedWindowsEvent.created_at.desc()
        )
        .limit(limit)
        .all()
    )

    return events