from sqlalchemy.orm import Session

from app.models.failed_login_event import (
    FailedLoginEvent,
)
from app.schemas.failed_login_event import (
    FailedLoginEventCreate,
)


class FailedLoginEventService:

    @staticmethod
    def create(
        db: Session,
        payload: FailedLoginEventCreate,
    ) -> FailedLoginEvent:
        event = FailedLoginEvent(
            username=payload.username,
            source_ip=payload.source_ip,
            failure_reason=(
                payload.failure_reason
            ),
            status=payload.status,
            sub_status=payload.sub_status,
            failed_time=payload.failed_time,
        )

        db.add(event)
        db.commit()
        db.refresh(event)

        return event