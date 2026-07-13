from datetime import datetime

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    status,
)
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.event_explorer.service import (
    EventExplorerService,
)


router = APIRouter(
    prefix="/event-explorer",
    tags=["Event Explorer"],
)


@router.get("/events")
def list_raw_events(
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=25,
        ge=1,
        le=100,
    ),
    event_id: int | None = Query(
        default=None
    ),
    record_id: int | None = Query(
        default=None
    ),
    computer: str | None = Query(
        default=None
    ),
    provider: str | None = Query(
        default=None
    ),
    start_time: datetime | None = Query(
        default=None
    ),
    end_time: datetime | None = Query(
        default=None
    ),
    db: Session = Depends(get_db),
):
    return EventExplorerService.list_events(
        db=db,
        page=page,
        page_size=page_size,
        event_id=event_id,
        record_id=record_id,
        computer=computer,
        provider=provider,
        start_time=start_time,
        end_time=end_time,
    )


@router.get("/events/{raw_event_id}")
def get_raw_event(
    raw_event_id: int,
    db: Session = Depends(get_db),
):
    event = EventExplorerService.get_event(
        db=db,
        raw_event_id=raw_event_id,
    )

    if event is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Raw Windows event not found",
        )

    return event