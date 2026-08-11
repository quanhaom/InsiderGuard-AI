import json

from datetime import (
    datetime,
    timedelta,
    timezone,
)

from typing import Any

from sqlalchemy.orm import Session

from app.models.normalized_windows_event import (
    NormalizedWindowsEvent,
)

from app.modules.correlation.engine import (
    CorrelationEngine,
)

from app.modules.correlation.result import (
    CorrelationResult,
)


class CorrelationService:

    DEFAULT_WINDOW_MINUTES = 10

    SUPPORTED_EVENT_IDS = {
        1,
        3,
        11,
        13,
        22,
    }

    @staticmethod
    def _details_to_dict(
        details,
    ) -> dict[str, Any]:

        if details is None:
            return {}

        if isinstance(
            details,
            dict,
        ):
            return details

        if isinstance(
            details,
            str,
        ):

            try:
                result = json.loads(
                    details
                )

                if isinstance(
                    result,
                    dict,
                ):
                    return result

            except (
                json.JSONDecodeError,
                TypeError,
            ):
                pass

        return {}

    @classmethod
    def _serialize_event(
        cls,
        event: NormalizedWindowsEvent,
    ) -> dict[str, Any]:

        details = (
            cls._details_to_dict(
                event.details
            )
        )

        process_guid = (
            details.get(
                "process_guid"
            )
            or details.get(
                "ProcessGuid"
            )
        )

        process_id = (
            details.get(
                "process_id"
            )
            or details.get(
                "ProcessId"
            )
        )

        image = (
            details.get(
                "image"
            )
            or details.get(
                "Image"
            )
        )

        return {
            "id":
                event.id,

            "event_id":
                event.event_id,

            "username":
                event.username,

            "computer":
                event.computer,

            "action":
                event.action,

            "severity":
                event.severity,

            "process_guid":
                process_guid,

            "process_id":
                process_id,

            "image":
                image,

            "details":
                details,

            "created_at":
                getattr(
                    event,
                    "created_at",
                    None,
                ),
        }

    @staticmethod
    def _normalize_pid(
        value,
    ) -> int | None:

        if value is None:
            return None

        try:
            return int(
                str(value)
            )

        except (
            ValueError,
            TypeError,
        ):
            return None

    @classmethod
    def _process_key(
        cls,
        event: dict[
            str,
            Any,
        ],
    ) -> tuple:

        process_guid = (
            event.get(
                "process_guid"
            )
        )

        if process_guid:
            return (
                "guid",
                str(
                    process_guid
                ).lower(),
            )

        process_id = (
            cls._normalize_pid(
                event.get(
                    "process_id"
                )
            )
        )

        computer = (
            event.get(
                "computer"
            )
            or "unknown"
        )

        return (
            "pid",
            str(
                computer
            ).lower(),
            process_id,
        )

    @classmethod
    def get_recent_events(
        cls,
        db: Session,
        *,
        computer: str | None = None,
        window_minutes: int | None = None,
    ) -> list[
        dict[str, Any]
    ]:

        window = (
            window_minutes
            or cls.DEFAULT_WINDOW_MINUTES
        )

        cutoff = (
            datetime.now(
                timezone.utc
            )
            - timedelta(
                minutes=window
            )
        )

        query = (
            db.query(
                NormalizedWindowsEvent
            )
            .filter(
                NormalizedWindowsEvent
                .event_id
                .in_(
                    cls.SUPPORTED_EVENT_IDS
                )
            )
        )

        if computer:

            query = query.filter(
                NormalizedWindowsEvent
                .computer
                == computer
            )

        if hasattr(
            NormalizedWindowsEvent,
            "created_at",
        ):

            query = query.filter(
                NormalizedWindowsEvent
                .created_at
                >= cutoff
            )

        rows = (
            query
            .order_by(
                NormalizedWindowsEvent
                .id
                .asc()
            )
            .all()
        )

        return [
            cls._serialize_event(
                row
            )
            for row
            in rows
        ]

    @classmethod
    def analyze_processes(
        cls,
        db: Session,
        *,
        computer: str | None = None,
        window_minutes: int | None = None,
    ) -> list[
        CorrelationResult
    ]:

        events = (
            cls.get_recent_events(
                db=db,
                computer=computer,
                window_minutes=(
                    window_minutes
                ),
            )
        )

        grouped: dict[
            tuple,
            list[
                dict[str, Any]
            ],
        ] = {}

        for event in events:

            key = (
                cls._process_key(
                    event
                )
            )

            grouped.setdefault(
                key,
                [],
            ).append(
                event
            )

        results: list[
            CorrelationResult
        ] = []

        for (
            key,
            process_events,
        ) in grouped.items():

            if not process_events:
                continue

            first = (
                process_events[0]
            )

            process_guid = (
                first.get(
                    "process_guid"
                )
            )

            process_id = (
                cls._normalize_pid(
                    first.get(
                        "process_id"
                    )
                )
            )

            process_image = (
                first.get(
                    "image"
                )
            )

            username = (
                first.get(
                    "username"
                )
            )

            computer_name = (
                first.get(
                    "computer"
                )
            )

            result = (
                CorrelationEngine
                .analyze(
                    events=(
                        process_events
                    ),
                    username=(
                        username
                    ),
                    computer=(
                        computer_name
                    ),
                    process_guid=(
                        process_guid
                    ),
                    process_id=(
                        process_id
                    ),
                    process_image=(
                        process_image
                    ),
                )
            )

            results.append(
                result
            )

        results.sort(
            key=lambda item:
                item.score,
            reverse=True,
        )

        return results