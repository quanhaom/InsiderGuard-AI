from datetime import datetime, timezone
from pathlib import PureWindowsPath
from xml.etree import ElementTree

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.schemas.sysmon_process_event import (
    SysmonProcessEventCreate,
)


class SysmonParser1:

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
    def _filename(
        path: str | None,
    ) -> str | None:
        if not path:
            return None

        return PureWindowsPath(
            path
        ).name.lower()

    @staticmethod
    def _parse_hashes(
        value: str | None,
    ) -> dict[str, str]:
        if not value:
            return {}

        result: dict[str, str] = {}

        for item in value.split(","):
            if "=" not in item:
                continue

            algorithm, hash_value = (
                item.split(
                    "=",
                    1,
                )
            )

            result[
                algorithm.strip().upper()
            ] = hash_value.strip()

        return result

    @classmethod
    def parse(
        cls,
        db,
        event: RawWindowsEvent,
    ) -> SysmonProcessEventCreate:
        del db

        try:
            root = ElementTree.fromstring(
                event.xml
            )

        except ElementTree.ParseError as error:
            raise ValueError(
                "Invalid Sysmon Event 1 XML"
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

        image = (
            values.get("Image")
            or "unknown"
        )

        parent_image = (
            values.get(
                "ParentImage"
            )
        )

        return SysmonProcessEventCreate(
            username=(
                values.get("User")
                or "unknown"
            ),

            computer=event.computer,

            process_guid=values.get(
                "ProcessGuid"
            ),

            process_id=values.get(
                "ProcessId"
            ),

            image=image,

            process_name=(
                cls._filename(image)
                or "unknown"
            ),

            command_line=values.get(
                "CommandLine"
            ),

            current_directory=values.get(
                "CurrentDirectory"
            ),

            parent_process_guid=(
                values.get(
                    "ParentProcessGuid"
                )
            ),

            parent_process_id=(
                values.get(
                    "ParentProcessId"
                )
            ),

            parent_image=parent_image,

            parent_process_name=(
                cls._filename(
                    parent_image
                )
            ),

            parent_command_line=(
                values.get(
                    "ParentCommandLine"
                )
            ),

            hashes=cls._parse_hashes(
                values.get("Hashes")
            ),

            integrity_level=values.get(
                "IntegrityLevel"
            ),

            logon_guid=values.get(
                "LogonGuid"
            ),

            logon_id=values.get(
                "LogonId"
            ),

            terminal_session_id=(
                values.get(
                    "TerminalSessionId"
                )
            ),

            event_time=datetime.now(
                timezone.utc
            ),
        )