from sqlalchemy.orm import Session

from app.modules.events.service import EventService
from app.modules.parsers.bootstrap import (
    register_default_parsers,
)
from app.modules.parsers.registry import ParserRegistry
from app.modules.collector.raw_event_service import (
    RawEventService,
)
from app.schemas.collector import CollectorEvent
from app.schemas.raw_windows_event import (
    RawWindowsEventCreate,
)


register_default_parsers()


class EventDispatcher:

    @staticmethod
    def dispatch(
        db: Session,
        event: CollectorEvent
    ) -> dict:
        raw_payload = RawWindowsEventCreate(
            record_id=event.record_id,
            event_id=event.event_id,
            computer=event.computer,
            provider=event.provider,
            xml=event.xml
        )

        raw_event = RawEventService.save(
            db=db,
            payload=raw_payload
        )

        parser = ParserRegistry.get(
            event.event_id
        )

        if parser is None:
            return {
                "status": "stored",
                "raw_event_id": raw_event.id,
                "event_id": event.event_id,
                "handler": "none",
                "message": (
                    "Raw event stored, but no parser is registered"
                )
            }

        normalized_event = parser.parse(
            db=db,
            event=raw_event
        )

        if event.event_id == 4624:
            login_event = EventService.create_login_event(
                db=db,
                payload=normalized_event
            )

            return {
                "status": "accepted",
                "raw_event_id": raw_event.id,
                "event_id": event.event_id,
                "handler": "windows_login_success",
                "message": (
                    f"Raw event stored and login event "
                    f"created with ID {login_event.id}"
                )
            }

        return {
            "status": "stored",
            "raw_event_id": raw_event.id,
            "event_id": event.event_id,
            "handler": "parser_only",
            "message": "Raw event stored and parsed"
        }