from dataclasses import dataclass, field
from typing import Any


@dataclass(slots=True)
class CorrelationResult:

    detected: bool

    score: int

    severity: str

    username: str | None = None

    computer: str | None = None

    process_guid: str | None = None

    process_id: int | None = None

    process_image: str | None = None

    event_ids: list[int] = field(
        default_factory=list
    )

    reasons: list[str] = field(
        default_factory=list
    )

    events: list[dict[str, Any]] = field(
        default_factory=list
    )

    mitre_techniques: list[str] = field(
        default_factory=list
    )