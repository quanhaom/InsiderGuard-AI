from datetime import datetime

from pydantic import BaseModel


class SysmonDnsEventData(BaseModel):

    utc_time: datetime | None = None

    process_guid: str | None = None

    process_id: int | None = None

    query_name: str | None = None

    query_status: int | None = None

    query_results: str | None = None

    image: str | None = None

    user: str | None = None

    computer: str | None = None