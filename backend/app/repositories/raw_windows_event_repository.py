from sqlalchemy.orm import Session

from app.models.raw_windows_event import RawWindowsEvent


class RawWindowsEventRepository:

    @staticmethod
    def create(
        db: Session,
        event: RawWindowsEvent
    ) -> RawWindowsEvent:

        db.add(event)

        db.commit()

        db.refresh(event)

        return event

    @staticmethod
    def get_latest(
        db: Session,
        limit: int = 100
    ) -> list[RawWindowsEvent]:

        return (
            db.query(RawWindowsEvent)
            .order_by(
                RawWindowsEvent.received_at.desc()
            )
            .limit(limit)
            .all()
        )