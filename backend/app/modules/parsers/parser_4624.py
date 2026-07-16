from sqlalchemy.orm import Session

from app.models.raw_windows_event import RawWindowsEvent

from app.modules.parsers.base import BaseParser
from app.modules.parsers.xml_utils import get_event_data

from app.schemas.login_event import LoginEventCreate
from app.schemas.collector import CollectorEvent


class Parser4624(BaseParser):

    @staticmethod
    def event_id() -> int:
        return 4624


    def parse(
        self,
        db: Session,
        event: RawWindowsEvent
    ) -> LoginEventCreate:

        data = get_event_data(
            event.xml
        )


        username = data.get(
            "TargetUserName",
            ""
        )


        source_ip = data.get(
            "IpAddress",
            ""
        )


        if not username:
            available_fields = ", ".join(
                sorted(data.keys())
            )

            raise ValueError(
                "Missing TargetUserName in "
                "Windows Event 4624. "
                f"Available fields: "
                f"{available_fields or 'none'}"
            )


        if source_ip in [
            "",
            "-",
            "::1"
        ]:
            source_ip = "127.0.0.1"


        return LoginEventCreate(
            username=username,
            source_ip=source_ip,
            login_time=event.received_at
        )