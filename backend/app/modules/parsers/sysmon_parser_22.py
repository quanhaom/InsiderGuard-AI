from datetime import datetime
from typing import Any
from xml.etree import ElementTree

from sqlalchemy.orm import Session

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.schemas.sysmon_dns_event import (
    SysmonDnsEventData,
)


class SysmonParser22:

    EVENT_ID = 22

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int | None:

        if value is None:
            return None

        try:
            return int(
                str(value).strip()
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @staticmethod
    def _safe_datetime(
        value: Any,
    ) -> datetime | None:

        if not value:
            return None

        normalized = (
            str(value)
            .strip()
            .replace(
                "Z",
                "+00:00",
            )
        )

        try:
            return datetime.fromisoformat(
                normalized
            )

        except ValueError:
            return None

    @staticmethod
    def _extract_event_data(
        xml_content: str,
    ) -> dict[str, str]:

        try:
            root = ElementTree.fromstring(
                xml_content
            )

        except ElementTree.ParseError as error:
            raise ValueError(
                "Invalid Sysmon Event 22 XML"
            ) from error

        values: dict[str, str] = {}

        for element in root.iter():

            tag_name = (
                element.tag.split("}")[-1]
            )

            if tag_name != "Data":
                continue

            field_name = (
                element.attrib.get("Name")
            )

            if not field_name:
                continue

            values[field_name] = (
                element.text or ""
            ).strip()

        return values

    @classmethod
    def parse(
        cls,
        db: Session,
        event: RawWindowsEvent,
    ) -> SysmonDnsEventData:

        del db

        if event.event_id != cls.EVENT_ID:
            raise ValueError(
                "SysmonParser22 received "
                f"Event ID {event.event_id}"
            )

        data = cls._extract_event_data(
            event.xml
        )

        return SysmonDnsEventData(

            utc_time=cls._safe_datetime(
                data.get("UtcTime")
            ),

            process_guid=data.get(
                "ProcessGuid"
            ),

            process_id=cls._safe_int(
                data.get("ProcessId")
            ),

            query_name=data.get(
                "QueryName"
            ),

            query_status=cls._safe_int(
                data.get("QueryStatus")
            ),

            query_results=data.get(
                "QueryResults"
            ),

            image=data.get(
                "Image"
            ),

            user=data.get(
                "User"
            ),

            computer=event.computer,
        )