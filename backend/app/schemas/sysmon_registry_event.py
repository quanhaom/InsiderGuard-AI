from datetime import datetime

from pydantic import BaseModel


class SysmonRegistryEventData(BaseModel):

    utc_time: datetime | None = None

    process_guid: str | None = None

    process_id: int | None = None

    image: str | None = None

    event_type: str | None = None

    target_object: str | None = None

    details: str | None = None

    user: str | None = None

    computer: str | None = None