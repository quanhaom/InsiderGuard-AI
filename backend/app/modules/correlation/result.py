from dataclasses import (
    dataclass,
    field,
)

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

    parent_process_guid: str | None = None

    parent_process_id: int | None = None

    parent_image: str | None = None

    event_ids: list[int] = field(
        default_factory=list
    )

    process_chain: list[
        dict[str, Any]
    ] = field(
        default_factory=list
    )

    related_process_guids: list[
        str
    ] = field(
        default_factory=list
    )

    usb_events: list[
        dict[str, Any]
    ] = field(
        default_factory=list
    )

    usb_file_transfers: list[
        dict[str, Any]
    ] = field(
        default_factory=list
    )

    reasons: list[str] = field(
        default_factory=list
    )

    events: list[
        dict[str, Any]
    ] = field(
        default_factory=list
    )

    mitre_techniques: list[
        str
    ] = field(
        default_factory=list
    )