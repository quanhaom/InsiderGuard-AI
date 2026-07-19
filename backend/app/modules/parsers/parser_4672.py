from datetime import datetime

from xml.etree import ElementTree

from app.schemas.privilege_event import (
    PrivilegeEventCreate,
)


class Parser4672:

    @staticmethod
    def parse(
        db,
        event,
    ):

        del db

        root = ElementTree.fromstring(
            event.xml
        )

        values = {}

        for data in root.findall(".//Data"):

            name = data.attrib.get(
                "Name"
            )

            values[name] = (
                data.text or ""
            ).strip()

        privilege_text = (
            values.get(
                "PrivilegeList",
                "",
            )
        )

        privileges = (
            privilege_text.split()
        )

        return PrivilegeEventCreate(

            username=values.get(
                "SubjectUserName",
                "unknown",
            ),

            source_ip=values.get(
                "IpAddress"
            ),

            computer=event.computer,

            privileges=privileges,

            event_time=datetime.utcnow(),

        )