from sqlalchemy.orm import Session

from app.models.raw_windows_event import RawWindowsEvent
from app.modules.parsers.base import BaseParser
from app.modules.parsers.xml_utils import get_event_data

from app.schemas.failed_login_event import FailedLoginEventCreate


class Parser4625(BaseParser):

    @staticmethod
    def event_id() -> int:
        return 4625


    def parse(
        self,
        db: Session,
        event: RawWindowsEvent
    ) -> FailedLoginEventCreate:

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


        if source_ip in [
            "",
            "-",
            "::1"
        ]:
            source_ip = "127.0.0.1"


        return FailedLoginEventCreate(

            username=username,

            source_ip=source_ip,

            failure_reason=data.get(
                "FailureReason",
                ""
            ),

            status=data.get(
                "Status",
                ""
            ),

            sub_status=data.get(
                "SubStatus",
                ""
            ),

            failed_time=event.received_at
        )