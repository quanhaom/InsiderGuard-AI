from sqlalchemy.orm import Session

from app.modules.collector.dispatcher import EventDispatcher
from app.schemas.collector import CollectorEvent


class CollectorService:

    @staticmethod
    def ingest(
        db: Session,
        event: CollectorEvent
    ) -> dict:
        return EventDispatcher.dispatch(
            db=db,
            event=event
        )