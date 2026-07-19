from datetime import datetime, timezone
from xml.etree import ElementTree

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.schemas.group_membership_event import (
    GroupMembershipEventCreate,
)


class Parser4728:

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

    @staticmethod
    def _clean_member_name(
        value: str | None,
    ) -> str:
        if not value:
            return "unknown"

        cleaned = value.strip()

        # Windows đôi khi trả:
        # CN=bob,CN=Users,DC=example,DC=local
        if cleaned.upper().startswith("CN="):
            first_part = cleaned.split(
                ",",
                1,
            )[0]

            return first_part.split(
                "=",
                1,
            )[-1]

        return cleaned

    @classmethod
    def parse(
        cls,
        db,
        event: RawWindowsEvent,
    ) -> GroupMembershipEventCreate:
        del db

        try:
            root = ElementTree.fromstring(
                event.xml
            )

        except ElementTree.ParseError as error:
            raise ValueError(
                "Invalid XML for Windows Event 4728"
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

        member_username = (
            cls._clean_member_name(
                values.get(
                    "MemberName"
                )
            )
        )

        member_sid = (
            values.get(
                "MemberId"
            )
            or values.get(
                "MemberSid"
            )
        )

        group_name = (
            values.get(
                "TargetUserName"
            )
            or values.get(
                "GroupName"
            )
            or "unknown"
        )

        group_domain = (
            values.get(
                "TargetDomainName"
            )
            or values.get(
                "GroupDomainName"
            )
        )

        group_sid = (
            values.get(
                "TargetSid"
            )
            or values.get(
                "GroupSid"
            )
        )

        source_ip = (
            values.get(
                "IpAddress"
            )
            or event.source_ip
        )

        return GroupMembershipEventCreate(
            actor_username=actor_username,

            member_username=(
                member_username
            ),

            member_sid=member_sid,

            group_name=group_name,

            group_domain=group_domain,

            group_sid=group_sid,

            source_ip=source_ip,

            computer=event.computer,

            event_time=datetime.now(
                timezone.utc
            ),
        )