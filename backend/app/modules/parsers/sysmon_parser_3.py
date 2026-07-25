from datetime import datetime
from typing import Any
from xml.etree import ElementTree

from sqlalchemy.orm import Session

from app.models.raw_windows_event import (
    RawWindowsEvent,
)
from app.schemas.sysmon_network_event import (
    SysmonNetworkEventData,
)


class SysmonParser3:

    EVENT_ID = 3

    @staticmethod
    def _safe_int(
        value: Any,
    ) -> int | None:
        if value is None:
            return None

        try:
            return int(str(value).strip())
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _safe_bool(
        value: Any,
    ) -> bool | None:
        if value is None:
            return None

        normalized = str(value).strip().lower()

        if normalized in {
            "true",
            "1",
            "yes",
        }:
            return True

        if normalized in {
            "false",
            "0",
            "no",
        }:
            return False

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
            .replace("Z", "+00:00")
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
        root = ElementTree.fromstring(
            xml_content
        )

        values: dict[str, str] = {}

        for element in root.iter():
            tag_name = element.tag.split(
                "}"
            )[-1]

            if tag_name != "Data":
                continue

            field_name = element.attrib.get(
                "Name"
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
    ) -> SysmonNetworkEventData:
        del db

        if event.event_id != cls.EVENT_ID:
            raise ValueError(
                "SysmonParser3 received "
                f"Event ID {event.event_id}"
            )

        event_data = cls._extract_event_data(
            event.xml
        )

        return SysmonNetworkEventData(
            utc_time=cls._safe_datetime(
                event_data.get("UtcTime")
            ),
            process_guid=event_data.get(
                "ProcessGuid"
            ),
            process_id=cls._safe_int(
                event_data.get("ProcessId")
            ),
            image=event_data.get("Image"),
            user=event_data.get("User"),
            protocol=event_data.get(
                "Protocol"
            ),
            initiated=cls._safe_bool(
                event_data.get("Initiated")
            ),
            source_is_ipv6=cls._safe_bool(
                event_data.get(
                    "SourceIsIpv6"
                )
            ),
            source_ip=event_data.get(
                "SourceIp"
            ),
            source_hostname=event_data.get(
                "SourceHostname"
            ),
            source_port=cls._safe_int(
                event_data.get("SourcePort")
            ),
            source_port_name=event_data.get(
                "SourcePortName"
            ),
            destination_is_ipv6=(
                cls._safe_bool(
                    event_data.get(
                        "DestinationIsIpv6"
                    )
                )
            ),
            destination_ip=event_data.get(
                "DestinationIp"
            ),
            destination_hostname=(
                event_data.get(
                    "DestinationHostname"
                )
            ),
            destination_port=cls._safe_int(
                event_data.get(
                    "DestinationPort"
                )
            ),
            destination_port_name=(
                event_data.get(
                    "DestinationPortName"
                )
            ),
            computer=event.computer,
        )