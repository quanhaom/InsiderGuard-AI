from app.models import (
    CollectorEvent,
    RawWindowsEvent,
)

from app.parsers.base import BaseParser
from app.parsers.registry import ParserRegistry
from app.xml_utils import get_event_data


class Parser4624(BaseParser):

    def parse(
        self,
        event: RawWindowsEvent
    ) -> CollectorEvent:

        data = get_event_data(
            event.xml
        )

        payload = {

            "username": data.get(
                "TargetUserName",
                ""
            ),

            "source_ip": data.get(
                "IpAddress",
                ""
            ),

            "logon_type": int(
                data.get(
                    "LogonType",
                    0
                )
            )

        }

        return CollectorEvent(

            source="windows-security",

            event_id=4624,

            computer=event.computer,

            timestamp=event.timestamp,

            payload=payload

        )


ParserRegistry.register(
    4624,
    Parser4624()
)