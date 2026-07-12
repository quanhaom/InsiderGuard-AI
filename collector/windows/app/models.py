from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(slots=True)
@dataclass
class RawWindowsEvent:

    record_id: int

    event_id: int

    computer: str

    provider: str

    timestamp: datetime

    xml: str

@dataclass
class CollectorEvent:

    source: str

    event_id: int

    record_id: int

    computer: str

    provider: str

    timestamp: datetime

    xml: str

    payload: dict