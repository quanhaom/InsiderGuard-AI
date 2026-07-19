from datetime import datetime, timezone
from pathlib import PureWindowsPath
from xml.etree import ElementTree

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.schemas.process_event import (
    ProcessEventCreate,
)


class Parser4688:

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
    def _extract_filename(
        path: str | None,
    ) -> str:
        if not path:
            return "unknown"

        try:
            return PureWindowsPath(
                path
            ).name.lower()

        except Exception:
            return path.lower()

    @classmethod
    def parse(
        cls,
        db,
        event: RawWindowsEvent,
    ) -> ProcessEventCreate:
        del db

        try:
            root = ElementTree.fromstring(
                event.xml
            )

        except ElementTree.ParseError as error:
            raise ValueError(
                "Invalid XML for Event 4688"
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

        username = (
            values.get(
                "SubjectUserName"
            )
            or values.get(
                "TargetUserName"
            )
            or "unknown"
        )

        process_path = (
            values.get(
                "NewProcessName"
            )
            or values.get(
                "ProcessName"
            )
        )

        parent_process_path = (
            values.get(
                "ParentProcessName"
            )
            or values.get(
                "CreatorProcessName"
            )
        )

        command_line = (
            values.get(
                "CommandLine"
            )
            or values.get(
                "ProcessCommandLine"
            )
        )

        source_ip = (
            values.get(
                "IpAddress"
            )
            or event.source_ip
        )

        return ProcessEventCreate(
            username=username,

            source_ip=source_ip,

            computer=event.computer,

            process_name=(
                cls._extract_filename(
                    process_path
                )
            ),

            process_path=process_path,

            command_line=command_line,

            parent_process_name=(
                cls._extract_filename(
                    parent_process_path
                )
                if parent_process_path
                else None
            ),

            parent_process_path=(
                parent_process_path
            ),

            process_id=values.get(
                "NewProcessId"
            ),

            parent_process_id=(
                values.get(
                    "ProcessId"
                )
                or values.get(
                    "CreatorProcessId"
                )
            ),

            event_time=datetime.now(
                timezone.utc
            ),
        )