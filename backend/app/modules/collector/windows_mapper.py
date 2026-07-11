from app.schemas.collector import CollectorEvent
from app.schemas.login_event import LoginEventCreate


class WindowsEventMapper:

    @staticmethod
    def map_login_event(
        event: CollectorEvent
    ) -> LoginEventCreate:
        username = str(
            event.payload.get("username", "")
        ).strip()

        source_ip = str(
            event.payload.get("source_ip", "")
        ).strip()

        if not username:
            raise ValueError(
                "Windows event payload is missing username"
            )

        if not source_ip or source_ip == "-":
            source_ip = "127.0.0.1"

        return LoginEventCreate(
            username=username,
            source_ip=source_ip,
            login_time=event.timestamp
        )