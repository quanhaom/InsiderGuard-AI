from datetime import date, datetime
from enum import Enum
from uuid import UUID

from sqlalchemy.orm import Session

from app.models.normalized_windows_event import (
    NormalizedWindowsEvent,
)


class WindowsNormalizer:

    @staticmethod
    def _to_dict(parsed) -> dict:
        if hasattr(parsed, "model_dump"):
            return parsed.model_dump()

        if isinstance(parsed, dict):
            return parsed

        if hasattr(parsed, "__dict__"):
            return {
                key: value
                for key, value in vars(parsed).items()
                if not key.startswith("_")
            }

        raise TypeError(
            "Parsed event must be a Pydantic model, "
            "dictionary, or object with attributes."
        )

    @staticmethod
    def _make_json_serializable(value):
        if isinstance(value, datetime):
            return value.isoformat()

        if isinstance(value, date):
            return value.isoformat()

        if isinstance(value, Enum):
            return value.value

        if isinstance(value, UUID):
            return str(value)

        if isinstance(value, dict):
            return {
                str(key): (
                    WindowsNormalizer
                    ._make_json_serializable(item)
                )
                for key, item in value.items()
            }

        if isinstance(value, (list, tuple, set)):
            return [
                WindowsNormalizer
                ._make_json_serializable(item)
                for item in value
            ]

        return value

    @staticmethod
    def save(
        db: Session,
        raw_event,
        parsed,
    ) -> NormalizedWindowsEvent:

        data = WindowsNormalizer._to_dict(
            parsed
        )

        details = (
            WindowsNormalizer
            ._make_json_serializable(data)
        )

        action_map = {
            4624: "LOGIN_SUCCESS",
            4625: "FAILED_LOGIN",
            4672: (
                "SPECIAL_PRIVILEGES_ASSIGNED"
            ),
            4688: "PROCESS_CREATED",
        }

        severity_map = {
            4624: "LOW",
            4625: "MEDIUM",
            4672: "HIGH",
            4688: "MEDIUM",
        }

        normalized_event = (
            NormalizedWindowsEvent(
                raw_event_id=raw_event.id,
                event_id=raw_event.event_id,
                username=data.get(
                    "username"
                ),
                source_ip=data.get(
                    "source_ip"
                ),
                computer=raw_event.computer,
                action=(
                    data.get("action")
                    or action_map.get(
                        raw_event.event_id,
                        "UNKNOWN",
                    )
                ),
                severity=(
                    data.get("severity")
                    or severity_map.get(
                        raw_event.event_id,
                        "LOW",
                    )
                ),
                details=details,
            )
        )

        db.add(normalized_event)
        db.commit()
        db.refresh(normalized_event)

        raw_event.source_ip = data.get(
            "source_ip"
        )

        raw_event.parsed_status = "PARSED"

        db.commit()
        db.refresh(raw_event)

        return normalized_event