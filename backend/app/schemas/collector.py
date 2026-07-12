from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class CollectorEvent(BaseModel):
    source: str = Field(
        examples=["windows-security"]
    )

    event_id: int = Field(
        examples=[4624]
    )

    record_id: int = Field(
        examples=[5516]
    )

    computer: str = Field(
        examples=["DESKTOP-01"]
    )

    provider: str = Field(
        default="Microsoft-Windows-Security-Auditing"
    )

    timestamp: datetime

    xml: str

    payload: dict[str, Any] = Field(
        default_factory=dict
    )


class CollectorEventResponse(BaseModel):
    status: str
    raw_event_id: int
    event_id: int
    handler: str
    message: str