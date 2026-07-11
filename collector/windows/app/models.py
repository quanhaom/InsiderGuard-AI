from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
class RawWindowsEvent:
    record_id: int
    event_id: int
    computer: str
    timestamp: datetime
    xml: str


@dataclass(slots=True)
class CollectorEvent:
    source: str
    event_id: int
    computer: str
    timestamp: datetime
    payload: dict[str, Any]