from datetime import datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.raw_windows_event import RawWindowsEvent
from app.modules.parsers.xml_utils import get_event_data


class EventExplorerService:

    @staticmethod
    def _serialize_summary(
        event: RawWindowsEvent
    ) -> dict[str, Any]:
        return {
            "id": event.id,
            "record_id": event.record_id,
            "event_id": event.event_id,
            "computer": event.computer,
            "provider": event.provider,
            "received_at": event.received_at,
        }

    @staticmethod
    def _serialize_detail(
        event: RawWindowsEvent
    ) -> dict[str, Any]:
        try:
            normalized_data = get_event_data(
                event.xml
            )
        except Exception:
            normalized_data = {}

        return {
            "id": event.id,
            "record_id": event.record_id,
            "event_id": event.event_id,
            "computer": event.computer,
            "provider": event.provider,
            "received_at": event.received_at,
            "normalized_data": normalized_data,
            "xml": event.xml,
        }

    @classmethod
    def list_events(
        cls,
        db: Session,
        *,
        page: int = 1,
        page_size: int = 25,
        event_id: int | None = None,
        record_id: int | None = None,
        computer: str | None = None,
        provider: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> dict[str, Any]:
        query = db.query(
            RawWindowsEvent
        )

        if event_id is not None:
            query = query.filter(
                RawWindowsEvent.event_id == event_id
            )

        if record_id is not None:
            query = query.filter(
                RawWindowsEvent.record_id == record_id
            )

        if computer:
            query = query.filter(
                RawWindowsEvent.computer.ilike(
                    f"%{computer.strip()}%"
                )
            )

        if provider:
            query = query.filter(
                RawWindowsEvent.provider.ilike(
                    f"%{provider.strip()}%"
                )
            )

        if start_time is not None:
            query = query.filter(
                RawWindowsEvent.received_at >= start_time
            )

        if end_time is not None:
            query = query.filter(
                RawWindowsEvent.received_at <= end_time
            )

        total = query.count()

        events = (
            query
            .order_by(
                RawWindowsEvent.received_at.desc(),
                RawWindowsEvent.id.desc(),
            )
            .offset(
                (page - 1) * page_size
            )
            .limit(page_size)
            .all()
        )

        total_pages = (
            (total + page_size - 1)
            // page_size
        )

        return {
            "items": [
                cls._serialize_summary(event)
                for event in events
            ],
            "page": page,
            "page_size": page_size,
            "total": total,
            "total_pages": total_pages,
        }

    @classmethod
    def get_event(
        cls,
        db: Session,
        raw_event_id: int,
    ) -> dict[str, Any] | None:
        event = (
            db.query(RawWindowsEvent)
            .filter(
                RawWindowsEvent.id == raw_event_id
            )
            .first()
        )

        if event is None:
            return None

        return cls._serialize_detail(
            event
        )