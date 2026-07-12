from sqlalchemy.orm import Session

from app.models.raw_windows_event import RawWindowsEvent
from app.repositories.raw_windows_event_repository import (
    RawWindowsEventRepository,
)
from app.schemas.raw_windows_event import (
    RawWindowsEventCreate,
)


class RawEventService:

    @staticmethod
    def save(
        db: Session,
        payload: RawWindowsEventCreate
    ) -> RawWindowsEvent:

        event = RawWindowsEvent(

            record_id=payload.record_id,

            event_id=payload.event_id,

            computer=payload.computer,

            provider=payload.provider,

            xml=payload.xml
        )

        return RawWindowsEventRepository.create(
            db=db,
            event=event
        )