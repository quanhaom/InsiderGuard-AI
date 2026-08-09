from datetime import datetime

from pydantic import BaseModel


class SysmonFileEventData(BaseModel):

    utc_time: datetime | None = None

    process_guid: str | None = None

    process_id: int | None = None

    image: str | None = None

    target_filename: str | None = None

    creation_utc_time: datetime | None = None

    user: str | None = None

    computer: str | None = None