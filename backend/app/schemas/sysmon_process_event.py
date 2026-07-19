from datetime import datetime

from pydantic import BaseModel


class SysmonProcessEventCreate(BaseModel):
    username: str

    computer: str

    process_guid: str | None = None

    process_id: str | None = None

    image: str

    process_name: str

    command_line: str | None = None

    current_directory: str | None = None

    parent_process_guid: str | None = None

    parent_process_id: str | None = None

    parent_image: str | None = None

    parent_process_name: str | None = None

    parent_command_line: str | None = None

    hashes: dict[str, str]

    integrity_level: str | None = None

    logon_guid: str | None = None

    logon_id: str | None = None

    terminal_session_id: str | None = None

    event_time: datetime