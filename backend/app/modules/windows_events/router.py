from fastapi import (
    APIRouter,
    Depends,
)

from sqlalchemy.orm import Session

from app.db.dependencies import (
    get_db,
)

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.schemas.raw_windows_event import (
    RawWindowsEventCreate,
)

from app.modules.windows_events.service import (
    WindowsEventService,
)


router = APIRouter(
    prefix="/windows-events",
    tags=["Windows Events"]
)


@router.post("")
def ingest_event(
    payload: RawWindowsEventCreate,
    db: Session = Depends(get_db)
):

    raw_event = RawWindowsEvent(

        record_id=payload.record_id,

        event_id=payload.event_id,

        computer=payload.computer,

        provider=payload.provider,

        xml=payload.xml,

    )


    db.add(raw_event)

    db.commit()

    db.refresh(raw_event)


    processed_result = (
        WindowsEventService.process_event(
            db=db,
            event=raw_event,
        )
    )


    return {
        "status": "processed",
        "raw_event_id": raw_event.id,
        "event_id": raw_event.event_id,
        "result": processed_result,
    }