from datetime import datetime

from pydantic import BaseModel


class PrivilegeEventCreate(BaseModel):

    username: str

    source_ip: str | None = None

    computer: str

    privileges: list[str]

    event_time: datetime