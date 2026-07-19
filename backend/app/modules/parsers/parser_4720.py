from datetime import datetime, timezone
from xml.etree import ElementTree

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.schemas.account_event import (
    AccountCreatedEventCreate,
)


class Parser4720:

    @staticmethod
    def _strip_namespace(
        tag: str,
    ) -> str:
        if "}" in tag:
            return tag.split(
                "}",
                1,
            )[1]

        return tag

    @classmethod
    def parse(
        cls,
        db,
        event: RawWindowsEvent,
    ) -> AccountCreatedEventCreate:
        del db

        try:
            root = ElementTree.fromstring(
                event.xml
            )

        except ElementTree.ParseError as error:
            raise ValueError(
                "Invalid XML for Event 4720"
            ) from error

        values: dict[str, str] = {}

        for element in root.iter():
            if (
                cls._strip_namespace(
                    element.tag
                )
                != "Data"
            ):
                continue

            name = element.attrib.get(
                "Name"
            )

            if not name:
                continue

            values[name] = (
                element.text or ""
            ).strip()

        actor_username = (
            values.get(
                "SubjectUserName"
            )
            or "unknown"
        )

        target_username = (
            values.get(
                "TargetUserName"
            )
            or "unknown"
        )

        target_domain = (
            values.get(
                "TargetDomainName"
            )
        )

        target_sid = (
            values.get(
                "TargetSid"
            )
        )

        source_ip = (
            values.get(
                "IpAddress"
            )
            or event.source_ip
        )

        return AccountCreatedEventCreate(
            actor_username=actor_username,

            target_username=target_username,

            target_domain=target_domain,

            target_sid=target_sid,

            source_ip=source_ip,

            computer=event.computer,

            event_time=datetime.now(
                timezone.utc
            ),
        )