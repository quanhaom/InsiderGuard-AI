from datetime import datetime

from pydantic import BaseModel


class ProcessEventCreate(BaseModel):
    username: str

    source_ip: str | None = None

    computer: str

    process_name: str

    process_path: str | None = None

    command_line: str | None = None

    parent_process_name: str | None = None

    parent_process_path: str | None = None

    process_id: str | None = None

    parent_process_id: str | None = None

    event_time: datetime