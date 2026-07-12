from datetime import datetime

from pydantic import BaseModel


class RawWindowsEventCreate(BaseModel):

    record_id: int

    event_id: int

    computer: str

    provider: str

    xml: str


class RawWindowsEventResponse(BaseModel):

    id: int

    record_id: int

    event_id: int

    computer: str

    provider: str

    received_at: datetime

    class Config:
        from_attributes = True