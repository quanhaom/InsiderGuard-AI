from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent


class LoginEventRepository:

    @staticmethod
    def create(
        db: Session,
        username: str,
        source_ip: str,
        login_time
    ):

        event = LoginEvent(
            username=username,
            source_ip=source_ip,
            login_time=login_time
        )

        db.add(event)

        db.commit()

        db.refresh(event)

        return event