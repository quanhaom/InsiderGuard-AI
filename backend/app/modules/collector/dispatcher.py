from sqlalchemy.orm import Session

from app.modules.collector.windows_mapper import (
    WindowsEventMapper,
)
from app.modules.events.service import EventService
from app.schemas.collector import CollectorEvent


class EventDispatcher:

    @staticmethod
    def dispatch(
        db: Session,
        event: CollectorEvent
    ) -> dict:
        if event.source == "windows-security":
            return EventDispatcher._dispatch_windows_security(
                db=db,
                event=event
            )

        return {
            "status": "ignored",
            "event_id": event.event_id,
            "handler": "none",
            "message": (
                f"Unsupported collector source: {event.source}"
            )
        }

    @staticmethod
    def _dispatch_windows_security(
        db: Session,
        event: CollectorEvent
    ) -> dict:
        if event.event_id == 4624:
            payload = WindowsEventMapper.map_login_event(
                event
            )

            saved_event = EventService.create_login_event(
                db=db,
                payload=payload
            )

            return {
                "status": "accepted",
                "event_id": event.event_id,
                "handler": "windows_login_success",
                "message": (
                    f"Login event saved with ID "
                    f"{saved_event.id}"
                )
            }

        return {
            "status": "ignored",
            "event_id": event.event_id,
            "handler": "none",
            "message": (
                f"No handler registered for Windows "
                f"Event ID {event.event_id}"
            )
        }