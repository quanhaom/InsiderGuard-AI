from datetime import (
    datetime,
    timedelta,
    timezone,
)

from sqlalchemy.orm import Session

from app.models.usb_event import (
    UsbEvent,
)

from app.schemas.usb_event import (
    UsbEventCreate,
)


class UsbService:

    ALLOWED_EVENT_TYPES = {
        "USB_DEVICE_CONNECTED",
        "USB_DEVICE_DISCONNECTED",
    }

    @classmethod
    def create_event(
        cls,
        db: Session,
        payload: UsbEventCreate,
    ) -> UsbEvent:

        if (
            payload.event_type
            not in cls.ALLOWED_EVENT_TYPES
        ):
            raise ValueError(
                "Unsupported USB event type"
            )

        event = UsbEvent(
            computer=payload.computer,

            username=payload.username,

            event_type=(
                payload.event_type
            ),

            device_id=(
                payload.device_id
            ),

            drive_letter=(
                payload.drive_letter
            ),

            volume_label=(
                payload.volume_label
            ),

            serial_number=(
                payload.serial_number
            ),

            filesystem=(
                payload.filesystem
            ),
        )

        db.add(
            event
        )

        db.commit()

        db.refresh(
            event
        )

        return event

    @staticmethod
    def get_events(
        db: Session,
        *,
        computer: str | None = None,
        event_type: str | None = None,
        limit: int = 100,
    ) -> list[UsbEvent]:

        query = db.query(
            UsbEvent
        )

        if computer:
            query = query.filter(
                UsbEvent.computer
                == computer
            )

        if event_type:
            query = query.filter(
                UsbEvent.event_type
                == event_type
            )

        return (
            query
            .order_by(
                UsbEvent.created_at.desc()
            )
            .limit(limit)
            .all()
        )

    @staticmethod
    def get_recent_events(
        db: Session,
        *,
        computer: str | None = None,
        window_minutes: int = 60,
    ) -> list[UsbEvent]:

        cutoff = (
            datetime.now(
                timezone.utc
            )
            - timedelta(
                minutes=window_minutes
            )
        )

        query = (
            db.query(
                UsbEvent
            )
            .filter(
                UsbEvent.created_at
                >= cutoff
            )
        )

        if computer:
            query = query.filter(
                UsbEvent.computer
                == computer
            )

        return (
            query
            .order_by(
                UsbEvent.created_at.asc()
            )
            .all()
        )