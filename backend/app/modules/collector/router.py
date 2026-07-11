from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.db.dependencies import get_db
from app.modules.collector.service import CollectorService
from app.schemas.collector import (
    CollectorEvent,
    CollectorEventResponse,
)


router = APIRouter(
    prefix="/collector",
    tags=["Collector"]
)


@router.post(
    "/events",
    response_model=CollectorEventResponse
)
def ingest_collector_event(
    event: CollectorEvent,
    db: Session = Depends(get_db)
):
    try:
        return CollectorService.ingest(
            db=db,
            event=event
        )

    except ValueError as error:
        raise HTTPException(
            status_code=400,
            detail=str(error)
        ) from error