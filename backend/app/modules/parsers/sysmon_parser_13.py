from datetime import datetime
from typing import Any
from xml.etree import ElementTree

from sqlalchemy.orm import Session

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.schemas.sysmon_registry_event import (
    SysmonRegistryEventData,
)


class SysmonParser13:

    EVENT_ID = 13

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
                "Invalid Sysmon Event 13 XML"
            ) from error

        values: dict[str, str] = {}

        for element in root.iter():

            tag_name = (
                element.tag.split("}")[-1]
            )

            if tag_name != "Data":
                continue

            field_name = (
                element.attrib.get(
                    "Name"
                )
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
    ) -> SysmonRegistryEventData:

        del db

        if event.event_id != cls.EVENT_ID:
            raise ValueError(
                "SysmonParser13 received "
                f"Event ID {event.event_id}"
            )

        event_data = (
            cls._extract_event_data(
                event.xml
            )
        )

        return SysmonRegistryEventData(

            utc_time=cls._safe_datetime(
                event_data.get(
                    "UtcTime"
                )
            ),

            process_guid=(
                event_data.get(
                    "ProcessGuid"
                )
            ),

            process_id=cls._safe_int(
                event_data.get(
                    "ProcessId"
                )
            ),

            image=event_data.get(
                "Image"
            ),

            event_type=event_data.get(
                "EventType"
            ),

            target_object=(
                event_data.get(
                    "TargetObject"
                )
            ),

            details=event_data.get(
                "Details"
            ),

            user=event_data.get(
                "User"
            ),

            computer=event.computer,
        )