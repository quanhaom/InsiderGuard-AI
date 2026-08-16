import json

from datetime import (
    datetime,
    timedelta,
    timezone,
)

from typing import Any

from sqlalchemy.orm import (
    Session,
)

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

    @staticmethod
    def _normalize_pid(
        value,
    ) -> int | None:

        if value is None:
            return None

        try:

            return int(
                str(
                    value
                ).strip()
            )

        except (
            ValueError,
            TypeError,
        ):
            return None

    @staticmethod
    def _normalize_guid(
        value,
    ) -> str | None:

        if value is None:
            return None

        normalized = (
            str(
                value
            )
            .strip()
            .lower()
        )

        if not normalized:
            return None

        return normalized

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

        parent_process_guid = (
            details.get(
                "parent_process_guid"
            )
            or details.get(
                "ParentProcessGuid"
            )
        )

        parent_process_id = (
            details.get(
                "parent_process_id"
            )
            or details.get(
                "ParentProcessId"
            )
        )

        parent_image = (
            details.get(
                "parent_image"
            )
            or details.get(
                "ParentImage"
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
                cls._normalize_guid(
                    process_guid
                ),

            "process_id":
                cls._normalize_pid(
                    process_id
                ),

            "image":
                image,

            "parent_process_guid":
                cls._normalize_guid(
                    parent_process_guid
                ),

            "parent_process_id":
                cls._normalize_pid(
                    parent_process_id
                ),

            "parent_image":
                parent_image,

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
    def _serialize_usb_event(
        event,
    ) -> dict[str, Any]:

        return {
            "id":
                event.id,

            "computer":
                event.computer,

            "username":
                event.username,

            "event_type":
                event.event_type,

            "device_id":
                event.device_id,

            "drive_letter":
                event.drive_letter,

            "volume_label":
                event.volume_label,

            "serial_number":
                event.serial_number,

            "filesystem":
                event.filesystem,

            "created_at":
                event.created_at,
        }

    @staticmethod
    def _serialize_usb_transfer(
        transfer,
    ) -> dict[str, Any]:

        return {
            "id":
                transfer.id,

            "computer":
                transfer.computer,

            "username":
                transfer.username,

            "device_id":
                transfer.device_id,

            "drive_letter":
                transfer.drive_letter,

            "file_path":
                transfer.file_path,

            "file_name":
                transfer.file_name,

            "extension":
                transfer.extension,

            "file_size":
                transfer.file_size,

            "sha256_hash":
                transfer.sha256_hash,

            "risk_score":
                transfer.risk_score,

            "severity":
                transfer.severity,

            "created_at":
                transfer.created_at,
        }

    @classmethod
    def get_usb_context(
        cls,
        db: Session,
        *,
        computer: str | None,
        username: str | None,
        window_minutes: int,
    ) -> tuple[
        list[dict[str, Any]],
        list[dict[str, Any]],
    ]:

        from app.modules.usb.service import (
            UsbService,
        )

        from app.modules.usb.file_transfer_service import (
            UsbFileTransferService,
        )

        usb_events_raw = (
            UsbService
            .get_recent_events(
                db=db,
                computer=computer,
                window_minutes=(
                    window_minutes
                ),
            )
        )

        usb_transfers_raw = (
            UsbFileTransferService
            .get_recent(
                db=db,
                computer=computer,
                limit=500,
            )
        )

        normalized_username = (
            str(
                username
                or ""
            )
            .strip()
            .lower()
        )

        usb_events = []

        for event in usb_events_raw:

            if normalized_username:

                event_username = (
                    str(
                        event.username
                        or ""
                    )
                    .strip()
                    .lower()
                )

                if (
                    event_username
                    and event_username
                    != normalized_username
                ):
                    continue

            usb_events.append(
                cls._serialize_usb_event(
                    event
                )
            )

        cutoff = (
            datetime.now(
                timezone.utc
            )
            - timedelta(
                minutes=(
                    window_minutes
                )
            )
        )

        usb_file_transfers = []

        for transfer in usb_transfers_raw:

            created_at = (
                transfer.created_at
            )

            if (
                created_at
                is not None
            ):

                if (
                    created_at.tzinfo
                    is None
                ):
                    created_at = (
                        created_at
                        .replace(
                            tzinfo=(
                                timezone.utc
                            )
                        )
                    )

                if (
                    created_at
                    < cutoff
                ):
                    continue

            if normalized_username:

                transfer_username = (
                    str(
                        transfer.username
                        or ""
                    )
                    .strip()
                    .lower()
                )

                if (
                    transfer_username
                    and transfer_username
                    != normalized_username
                ):
                    continue

            usb_file_transfers.append(
                cls._serialize_usb_transfer(
                    transfer
                )
            )

        return (
            usb_events,
            usb_file_transfers,
        )

    @classmethod
    def _process_key(
        cls,
        event: dict[
            str,
            Any,
        ],
    ) -> tuple:

        process_guid = (
            cls._normalize_guid(
                event.get(
                    "process_guid"
                )
            )
        )

        if process_guid:

            return (
                "guid",
                process_guid,
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

        normalized_guid = (
            cls._normalize_guid(
                process_guid
            )
        )

        event_guid = (
            cls._normalize_guid(
                event.get(
                    "process_guid"
                )
            )
        )

        if normalized_guid:

            return (
                event_guid
                == normalized_guid
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
            cls._normalize_guid(
                process_guid
            )
            or first.get(
                "process_guid"
            )
        )

        final_pid = (
            cls._normalize_pid(
                process_id
            )
        )

        if final_pid is None:

            final_pid = (
                cls._normalize_pid(
                    first.get(
                        "process_id"
                    )
                )
            )

        return (
            CorrelationEngine
            .analyze(
                events=(
                    process_events
                ),

                username=(
                    final_username
                ),

                computer=(
                    computer
                ),

                process_guid=(
                    final_guid
                ),

                process_id=(
                    final_pid
                ),

                process_image=(
                    final_image
                ),

                parent_process_guid=(
                    first.get(
                        "parent_process_guid"
                    )
                ),

                parent_process_id=(
                    first.get(
                        "parent_process_id"
                    )
                ),

                parent_image=(
                    first.get(
                        "parent_image"
                    )
                ),
            )
        )

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

                computer=(
                    computer
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

                username=(
                    username
                ),

                window_minutes=(
                    window_minutes
                ),
            )
        )

        if (
            result is None
            or not result.detected
        ):
            return None

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

    @classmethod
    def _build_process_tree(
        cls,
        events: list[
            dict[str, Any]
        ],
    ) -> dict[
        str,
        dict[str, Any],
    ]:

        nodes = {}

        for event in events:

            process_guid = (
                cls._normalize_guid(
                    event.get(
                        "process_guid"
                    )
                )
            )

            if not process_guid:
                continue

            node = nodes.setdefault(
                process_guid,
                {
                    "process_guid":
                        process_guid,

                    "process_id":
                        None,

                    "image":
                        None,

                    "username":
                        None,

                    "computer":
                        event.get(
                            "computer"
                        ),

                    "parent_process_guid":
                        None,

                    "parent_process_id":
                        None,

                    "parent_image":
                        None,

                    "events":
                        [],

                    "children":
                        [],
                },
            )

            node[
                "events"
            ].append(
                event
            )

            if (
                event.get(
                    "process_id"
                )
                is not None
            ):

                node[
                    "process_id"
                ] = event.get(
                    "process_id"
                )

            if event.get(
                "image"
            ):

                node[
                    "image"
                ] = event.get(
                    "image"
                )

            if event.get(
                "username"
            ):

                node[
                    "username"
                ] = event.get(
                    "username"
                )

            if (
                event.get(
                    "event_id"
                )
                == 1
            ):

                parent_guid = (
                    cls._normalize_guid(
                        event.get(
                            "parent_process_guid"
                        )
                    )
                )

                if parent_guid:

                    node[
                        "parent_process_guid"
                    ] = parent_guid

                if (
                    event.get(
                        "parent_process_id"
                    )
                    is not None
                ):

                    node[
                        "parent_process_id"
                    ] = event.get(
                        "parent_process_id"
                    )

                if event.get(
                    "parent_image"
                ):

                    node[
                        "parent_image"
                    ] = event.get(
                        "parent_image"
                    )

        for (
            guid,
            node,
        ) in nodes.items():

            parent_guid = (
                node.get(
                    "parent_process_guid"
                )
            )

            if not parent_guid:
                continue

            parent = nodes.get(
                parent_guid
            )

            if parent is None:
                continue

            if (
                guid
                not in parent[
                    "children"
                ]
            ):

                parent[
                    "children"
                ].append(
                    guid
                )

        return nodes

    @classmethod
    def _collect_descendants(
        cls,
        process_guid: str,
        nodes: dict,
    ) -> list[str]:

        root_guid = (
            cls._normalize_guid(
                process_guid
            )
        )

        if (
            not root_guid
            or root_guid
            not in nodes
        ):
            return []

        result = []

        visited = set()

        stack = [
            root_guid
        ]

        while stack:

            current_guid = (
                stack.pop()
            )

            if (
                current_guid
                in visited
            ):
                continue

            visited.add(
                current_guid
            )

            node = nodes.get(
                current_guid
            )

            if node is None:
                continue

            for child_guid in (
                node.get(
                    "children",
                    [],
                )
            ):

                if (
                    child_guid
                    in visited
                ):
                    continue

                result.append(
                    child_guid
                )

                stack.append(
                    child_guid
                )

        return result

    @classmethod
    def _collect_ancestors(
        cls,
        process_guid: str,
        nodes: dict,
    ) -> list[str]:

        current_guid = (
            cls._normalize_guid(
                process_guid
            )
        )

        if not current_guid:
            return []

        ancestors = []

        visited = set()

        while current_guid:

            if (
                current_guid
                in visited
            ):
                break

            visited.add(
                current_guid
            )

            node = nodes.get(
                current_guid
            )

            if node is None:
                break

            parent_guid = (
                cls._normalize_guid(
                    node.get(
                        "parent_process_guid"
                    )
                )
            )

            if (
                not parent_guid
                or parent_guid
                not in nodes
            ):
                break

            ancestors.append(
                parent_guid
            )

            current_guid = (
                parent_guid
            )

        ancestors.reverse()

        return ancestors

    @classmethod
    def get_process_tree(
        cls,
        db: Session,
        *,
        computer: str | None = None,
        window_minutes: int | None = None,
    ):

        events = (
            cls.get_recent_events(
                db=db,

                computer=(
                    computer
                ),

                window_minutes=(
                    window_minutes
                ),
            )
        )

        nodes = (
            cls._build_process_tree(
                events
            )
        )

        results = []

        for (
            guid,
            node,
        ) in nodes.items():

            event_ids = sorted({
                event.get(
                    "event_id"
                )
                for event
                in node.get(
                    "events",
                    [],
                )
                if event.get(
                    "event_id"
                )
                is not None
            })

            results.append(
                {
                    "process_guid":
                        guid,

                    "process_id":
                        node.get(
                            "process_id"
                        ),

                    "image":
                        node.get(
                            "image"
                        ),

                    "username":
                        node.get(
                            "username"
                        ),

                    "computer":
                        node.get(
                            "computer"
                        ),

                    "parent_process_guid":
                        node.get(
                            "parent_process_guid"
                        ),

                    "parent_process_id":
                        node.get(
                            "parent_process_id"
                        ),

                    "parent_image":
                        node.get(
                            "parent_image"
                        ),

                    "children":
                        node.get(
                            "children",
                            [],
                        ),

                    "ancestors":
                        cls._collect_ancestors(
                            guid,
                            nodes,
                        ),

                    "descendants":
                        cls._collect_descendants(
                            guid,
                            nodes,
                        ),

                    "event_ids":
                        event_ids,

                    "event_count":
                        len(
                            node.get(
                                "events",
                                [],
                            )
                        ),
                }
            )

        return results

    @classmethod
    def analyze_process_tree(
        cls,
        db: Session,
        *,
        process_guid: str,
        computer: str | None = None,
        window_minutes: int | None = None,
    ) -> CorrelationResult | None:

        effective_window = (
            window_minutes
            or cls.DEFAULT_WINDOW_MINUTES
        )

        events = (
            cls.get_recent_events(
                db=db,

                computer=(
                    computer
                ),

                window_minutes=(
                    effective_window
                ),
            )
        )

        nodes = (
            cls._build_process_tree(
                events
            )
        )

        root_guid = (
            cls._normalize_guid(
                process_guid
            )
        )

        if not root_guid:
            return None

        root = nodes.get(
            root_guid
        )

        if root is None:
            return None

        ancestors = (
            cls._collect_ancestors(
                root_guid,
                nodes,
            )
        )

        descendants = (
            cls._collect_descendants(
                root_guid,
                nodes,
            )
        )

        related_guids = []

        for guid in (
            ancestors
            + [
                root_guid
            ]
            + descendants
        ):

            if (
                guid
                not in related_guids
            ):

                related_guids.append(
                    guid
                )

        related_set = set(
            related_guids
        )

        tree_events = [
            event
            for event
            in events
            if (
                cls._normalize_guid(
                    event.get(
                        "process_guid"
                    )
                )
                in related_set
            )
        ]

        if not tree_events:
            return None

        process_chain = []

        for guid in (
            related_guids
        ):

            node = nodes.get(
                guid
            )

            if not node:
                continue

            process_chain.append(
                {
                    "process_guid":
                        guid,

                    "process_id":
                        node.get(
                            "process_id"
                        ),

                    "image":
                        node.get(
                            "image"
                        ),

                    "parent_process_guid":
                        node.get(
                            "parent_process_guid"
                        ),

                    "parent_process_id":
                        node.get(
                            "parent_process_id"
                        ),

                    "parent_image":
                        node.get(
                            "parent_image"
                        ),
                }
            )

        (
            usb_events,
            usb_file_transfers,
        ) = cls.get_usb_context(
            db=db,

            computer=(
                root.get(
                    "computer"
                )
            ),

            username=(
                root.get(
                    "username"
                )
            ),

            window_minutes=(
                effective_window
            ),
        )

        return (
            CorrelationEngine
            .analyze(
                events=(
                    tree_events
                ),

                username=(
                    root.get(
                        "username"
                    )
                ),

                computer=(
                    root.get(
                        "computer"
                    )
                ),

                process_guid=(
                    root.get(
                        "process_guid"
                    )
                ),

                process_id=(
                    root.get(
                        "process_id"
                    )
                ),

                process_image=(
                    root.get(
                        "image"
                    )
                ),

                parent_process_guid=(
                    root.get(
                        "parent_process_guid"
                    )
                ),

                parent_process_id=(
                    root.get(
                        "parent_process_id"
                    )
                ),

                parent_image=(
                    root.get(
                        "parent_image"
                    )
                ),

                process_chain=(
                    process_chain
                ),

                usb_events=(
                    usb_events
                ),

                usb_file_transfers=(
                    usb_file_transfers
                ),
            )
        )

    @classmethod
    def process_tree_detection(
        cls,
        db: Session,
        *,
        process_guid: str,
        computer: str | None = None,
        window_minutes: int | None = None,
    ):

        result = (
            cls.analyze_process_tree(
                db=db,

                process_guid=(
                    process_guid
                ),

                computer=(
                    computer
                ),

                window_minutes=(
                    window_minutes
                ),
            )
        )

        if (
            result is None
            or not result.detected
        ):
            return None

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

    @classmethod
    def create_incident_from_tree(
        cls,
        db: Session,
        *,
        process_guid: str,
        computer: str | None = None,
        window_minutes: int | None = None,
    ):

        result = (
            cls.analyze_process_tree(
                db=db,

                process_guid=(
                    process_guid
                ),

                computer=(
                    computer
                ),

                window_minutes=(
                    window_minutes
                ),
            )
        )

        if (
            result is None
            or not result.detected
        ):
            return None

        from app.modules.alert.service import (
            AlertService,
        )

        alert = (
            AlertService
            .create_from_correlation(
                db=db,
                result=result,
            )
        )

        if alert is None:
            return None

        from app.modules.incidents.service import (
            IncidentService,
        )

        incident = (
            IncidentService
            .create_from_alert(
                db=db,
                alert=alert,
            )
        )

        correlation_evidence = None

        if incident is not None:

            from app.modules.evidence.service import (
                EvidenceService,
            )

            correlation_evidence = (
                EvidenceService
                .create_correlation_snapshot(
                    db=db,

                    incident_id=(
                        incident.id
                    ),

                    username=(
                        result.username
                        or incident.username
                        or "UNKNOWN"
                    ),

                    correlation=(
                        result
                    ),
                )
            )

        return {
            "result":
                result,

            "alert":
                alert,

            "incident":
                incident,

            "correlation_evidence":
                correlation_evidence,
        }

    @classmethod
    def analyze_process_trees(
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

                computer=(
                    computer
                ),

                window_minutes=(
                    window_minutes
                ),
            )
        )

        nodes = (
            cls._build_process_tree(
                events
            )
        )

        if not nodes:
            return []

        root_guids = []

        for (
            guid,
            node,
        ) in nodes.items():

            parent_guid = (
                cls._normalize_guid(
                    node.get(
                        "parent_process_guid"
                    )
                )
            )

            if (
                not parent_guid
                or parent_guid
                not in nodes
            ):

                root_guids.append(
                    guid
                )

        if not root_guids:

            root_guids = list(
                nodes.keys()
            )

        results = []

        processed_guids = set()

        for root_guid in (
            root_guids
        ):

            if (
                root_guid
                in processed_guids
            ):
                continue

            descendants = (
                cls._collect_descendants(
                    root_guid,
                    nodes,
                )
            )

            processed_guids.add(
                root_guid
            )

            processed_guids.update(
                descendants
            )

            result = (
                cls.analyze_process_tree(
                    db=db,

                    process_guid=(
                        root_guid
                    ),

                    computer=(
                        computer
                    ),

                    window_minutes=(
                        window_minutes
                    ),
                )
            )

            if result is not None:

                results.append(
                    result
                )

        results.sort(
            key=lambda item: (
                item.score,

                len(
                    item.process_chain
                ),

                len(
                    set(
                        item.event_ids
                    )
                ),

                len(
                    item.usb_file_transfers
                ),
            ),
            reverse=True,
        )

        return results

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

                computer=(
                    computer
                ),

                window_minutes=(
                    window_minutes
                ),
            )
        )

        grouped = {}

        for event in events:

            key = (
                cls._process_key(
                    event
                )
            )

            if (
                key[0]
                == "pid"
                and key[-1]
                is None
            ):
                continue

            grouped.setdefault(
                key,
                [],
            ).append(
                event
            )

        results = []

        for process_events in (
            grouped.values()
        ):

            if not process_events:
                continue

            first = (
                process_events[0]
            )

            result = (
                CorrelationEngine
                .analyze(
                    events=(
                        process_events
                    ),

                    username=(
                        first.get(
                            "username"
                        )
                    ),

                    computer=(
                        first.get(
                            "computer"
                        )
                    ),

                    process_guid=(
                        first.get(
                            "process_guid"
                        )
                    ),

                    process_id=(
                        first.get(
                            "process_id"
                        )
                    ),

                    process_image=(
                        first.get(
                            "image"
                        )
                    ),

                    parent_process_guid=(
                        first.get(
                            "parent_process_guid"
                        )
                    ),

                    parent_process_id=(
                        first.get(
                            "parent_process_id"
                        )
                    ),

                    parent_image=(
                        first.get(
                            "parent_image"
                        )
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

                computer=(
                    computer
                ),

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