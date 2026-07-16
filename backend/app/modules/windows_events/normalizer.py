from sqlalchemy.orm import Session

from app.models.normalized_windows_event import (
    NormalizedWindowsEvent
)



class WindowsNormalizer:


    @staticmethod
    def save(
        db: Session,
        raw_event,
        parsed: dict
    ):


        event = NormalizedWindowsEvent(

            raw_event_id=raw_event.id,

            event_id=raw_event.event_id,

            username=parsed.get(
                "username"
            ),

            source_ip=parsed.get(
                "source_ip"
            ),

            computer=raw_event.computer,

            action=parsed.get(
                "action"
            ),

            severity=parsed.get(
                "severity",
                "LOW"
            ),

            details=parsed

        )


        db.add(event)

        db.commit()

        db.refresh(event)


        return event