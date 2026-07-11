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

    computer: str = Field(
        examples=["DESKTOP-01"]
    )

    timestamp: datetime

    payload: dict[str, Any]