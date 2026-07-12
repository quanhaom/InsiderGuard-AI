from datetime import datetime

from pydantic import BaseModel


class FailedLoginEventCreate(BaseModel):

    username: str

    source_ip: str

    failure_reason: str | None = None

    status: str | None = None

    sub_status: str | None = None

    failed_time: datetime