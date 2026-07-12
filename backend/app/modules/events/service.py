from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent
from app.schemas.login_event import LoginEventCreate


class EventService:
    @staticmethod
    def create_login_event(
        db: Session,
        payload: LoginEventCreate
    ) -> LoginEvent:
        login_event = LoginEvent(
            username=payload.username,
            source_ip=payload.source_ip,
            login_time=payload.login_time
        )

        db.add(login_event)
        db.commit()
        db.refresh(login_event)

        return login_event