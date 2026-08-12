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

    # =========================
    # DETAILS PARSER
    # =========================

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
                parsed = json.loads(
                    details
                )

                if isinstance(
                    parsed,
                    dict,
                ):
                    return parsed

            except (
                json.JSONDecodeError,
                TypeError,
            ):
                pass

        return {}

    # =========================
    # PID NORMALIZATION
    # =========================

    @staticmethod
    def _normalize_pid(
        value,
    ) -> int | None:

        if value is None:
            return None

        try:
            return int(
                str(value).strip()
            )

        except (
            ValueError,
            TypeError,
        ):
            return None

    # =========================
    # EVENT SERIALIZATION
    # =========================

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
                cls._normalize_pid(
                    process_id
                ),

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

    # =========================
    # PROCESS KEY
    # =========================

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
                )
                .strip()
                .lower(),
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
            )
            .strip()
            .lower(),
            process_id,
        )

    # =========================
    # RECENT EVENTS
    # =========================

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

    # =========================
    # MATCH PROCESS
    # =========================

    @classmethod
    def _matches_process(
        cls,
        event: dict[
            str,
            Any,
        ],
        *,
        computer: str | None,
        process_guid: str | None,
        process_id: int | None,
    ) -> bool:

        event_computer = (
            event.get(
                "computer"
            )
        )

        if (
            computer
            and event_computer
            and str(
                event_computer
            ).lower()
            != str(
                computer
            ).lower()
        ):
            return False

        event_guid = (
            event.get(
                "process_guid"
            )
        )

        # ProcessGuid has highest priority.
        if process_guid:

            if not event_guid:
                return False

            return (
                str(
                    event_guid
                )
                .strip()
                .lower()
                ==
                str(
                    process_guid
                )
                .strip()
                .lower()
            )

        normalized_pid = (
            cls._normalize_pid(
                process_id
            )
        )

        event_pid = (
            cls._normalize_pid(
                event.get(
                    "process_id"
                )
            )
        )

        if (
            normalized_pid is None
            or event_pid is None
        ):
            return False

        return (
            normalized_pid
            == event_pid
        )

    # =========================
    # ANALYZE SINGLE PROCESS
    # =========================

    @classmethod
    def analyze_process(
        cls,
        db: Session,
        *,
        computer: str | None,
        process_guid: str | None = None,
        process_id: int | None = None,
        process_image: str | None = None,
        username: str | None = None,
        window_minutes: int | None = None,
    ) -> CorrelationResult | None:

        if (
            not process_guid
            and process_id is None
        ):
            return None

        recent_events = (
            cls.get_recent_events(
                db=db,
                computer=computer,
                window_minutes=(
                    window_minutes
                ),
            )
        )

        process_events = [
            event
            for event
            in recent_events
            if cls._matches_process(
                event,
                computer=computer,
                process_guid=(
                    process_guid
                ),
                process_id=(
                    process_id
                ),
            )
        ]

        if not process_events:
            return None

        first = (
            process_events[0]
        )

        final_username = (
            username
            or first.get(
                "username"
            )
        )

        final_image = (
            process_image
            or first.get(
                "image"
            )
        )

        final_guid = (
            process_guid
            or first.get(
                "process_guid"
            )
        )

        final_pid = (
            cls._normalize_pid(
                process_id
            )
            or cls._normalize_pid(
                first.get(
                    "process_id"
                )
            )
        )

        return (
            CorrelationEngine
            .analyze(
                events=process_events,
                username=(
                    final_username
                ),
                computer=computer,
                process_guid=(
                    final_guid
                ),
                process_id=(
                    final_pid
                ),
                process_image=(
                    final_image
                ),
            )
        )

    # =========================
    # PERSIST SINGLE PROCESS
    # =========================

    @classmethod
    def process_detection(
        cls,
        db: Session,
        *,
        computer: str | None,
        process_guid: str | None = None,
        process_id: int | None = None,
        process_image: str | None = None,
        username: str | None = None,
        window_minutes: int | None = None,
    ):

        result = (
            cls.analyze_process(
                db=db,
                computer=computer,
                process_guid=(
                    process_guid
                ),
                process_id=(
                    process_id
                ),
                process_image=(
                    process_image
                ),
                username=username,
                window_minutes=(
                    window_minutes
                ),
            )
        )

        if result is None:
            return None

        if not result.detected:
            return None

        # Lazy import prevents
        # circular dependency.
        from app.modules.alert.service import (
            AlertService,
        )

        return (
            AlertService
            .create_from_correlation(
                db=db,
                result=result,
            )
        )

    # =========================
    # ANALYZE ALL PROCESSES
    # USED BY GET API / UI
    # =========================

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

            # Avoid grouping all events
            # with missing ProcessGuid/PID.
            if (
                key[0] == "pid"
                and key[-1] is None
            ):
                continue

            grouped.setdefault(
                key,
                [],
            ).append(
                event
            )

        results: list[
            CorrelationResult
        ] = []

        for process_events in (
            grouped.values()
        ):

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
                    username=username,
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

    # =========================
    # MANUAL BATCH PROCESSING
    # KEEP FOR POST ENDPOINT
    # =========================

    @classmethod
    def process_detections(
        cls,
        db: Session,
        *,
        computer: str | None = None,
        window_minutes: int | None = None,
    ):

        from app.modules.alert.service import (
            AlertService,
        )

        results = (
            cls.analyze_processes(
                db=db,
                computer=computer,
                window_minutes=(
                    window_minutes
                ),
            )
        )

        alerts = []

        for result in results:

            if not result.detected:
                continue

            alert = (
                AlertService
                .create_from_correlation(
                    db=db,
                    result=result,
                )
            )

            if alert:
                alerts.append(
                    alert
                )

        return alerts