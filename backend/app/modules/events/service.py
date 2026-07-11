from app.repositories.login_event_repository import (
    LoginEventRepository
)


class EventService:

    @staticmethod
    def create_login_event(
        db,
        payload
    ):

        return LoginEventRepository.create(
            db=db,
            username=payload.username,
            source_ip=payload.source_ip,
            login_time=payload.login_time
        )