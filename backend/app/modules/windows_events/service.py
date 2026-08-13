from typing import Any

from sqlalchemy.orm import Session

from app.models.raw_windows_event import (
    RawWindowsEvent,
)

from app.modules.windows_events.pipeline_executor import (
    WindowsPipelineExecutor,
)

from app.modules.windows_events.normalizer import (
    WindowsNormalizer,
)

from app.modules.events.service import (
    EventService,
)

from app.modules.behavior_profile.service import (
    BehaviorProfileService,
)

from app.modules.ueba.failed_login_detector import (
    FailedLoginDetector,
)

from app.modules.ueba.privilege_detector import (
    PrivilegeDetector,
)

from app.modules.ueba.process_detector import (
    SuspiciousProcessDetector,
)

from app.modules.ueba.account_creation_detector import (
    AccountCreationDetector,
)

from app.modules.ueba.group_membership_detector import (
    GroupMembershipDetector,
)

from app.modules.ueba.sysmon_process_detector import (
    SysmonProcessDetector,
)

from app.modules.ueba.sysmon_network_detector import (
    SysmonNetworkDetector,
)

from app.modules.ueba.sysmon_file_detector import (
    SysmonFileDetector,
)

from app.modules.ueba.sysmon_registry_detector import (
    SysmonRegistryDetector,
)

from app.modules.ueba.sysmon_dns_detector import (
    SysmonDnsDetector,
)

from app.modules.ueba.download_file_detector import (
    DownloadFileDetector,
)

from app.modules.correlation.service import (
    CorrelationService,
)


SECURITY_PROVIDER = (
    "microsoft-windows-security-auditing"
)

SYSMON_PROVIDER = (
    "microsoft-windows-sysmon"
)


class WindowsEventService:

    CORRELATION_EVENT_IDS = {
        1,
        3,
        11,
        13,
        22,
    }

    @staticmethod
    def _parsed_value(
        parsed,
        *names: str,
    ):
        for name in names:

            if isinstance(
                parsed,
                dict,
            ):
                value = parsed.get(
                    name
                )

            else:
                value = getattr(
                    parsed,
                    name,
                    None,
                )

            if value not in {
                None,
                "",
            }:
                return value

        return None

    @classmethod
    def _process_id(
        cls,
        parsed,
    ) -> int | None:

        value = (
            cls._parsed_value(
                parsed,
                "process_id",
                "ProcessId",
            )
        )

        if value is None:
            return None

        try:
            return int(
                str(value).strip()
            )

        except (
            TypeError,
            ValueError,
        ):
            return None

    @classmethod
    def _run_correlation(
        cls,
        db: Session,
        *,
        event: RawWindowsEvent,
        provider_key: str,
        parsed,
    ):
        if provider_key != SYSMON_PROVIDER:
            return None

        if (
            event.event_id
            not in cls.CORRELATION_EVENT_IDS
        ):
            return None

        process_guid = (
            cls._parsed_value(
                parsed,
                "process_guid",
                "ProcessGuid",
            )
        )

        process_id = (
            cls._process_id(
                parsed
            )
        )

        process_image = (
            cls._parsed_value(
                parsed,
                "image",
                "Image",
            )
        )

        username = (
            cls._parsed_value(
                parsed,
                "user",
                "username",
                "User",
            )
        )

        # =========================
        # TREE-AWARE CORRELATION
        # =========================

        if process_guid:

            tree_alert = (
                CorrelationService
                .process_tree_detection(
                    db=db,
                    process_guid=(
                        process_guid
                    ),
                    computer=(
                        event.computer
                    ),
                    window_minutes=10,
                )
            )

            if tree_alert is not None:
                return tree_alert

        # =========================
        # FALLBACK:
        # SAME PROCESS / PID
        # =========================

        if (
            not process_guid
            and process_id is None
        ):
            return None

        return (
            CorrelationService
            .process_detection(
                db=db,
                computer=(
                    event.computer
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
                window_minutes=10,
            )
        )

    @staticmethod
    def _correlation_payload(
        alert,
    ):

        if alert is None:
            return None

        return {
            "alert_id":
                alert.id,

            "alert_type":
                alert.alert_type,

            "severity":
                alert.severity,

            "risk_score":
                alert.risk_score,
        }

    @classmethod
    def process_event(
        cls,
        db: Session,
        event: RawWindowsEvent,
    ) -> dict[str, Any]:

        provider_key = (
            event.provider
            or ""
        ).strip().lower()

        # =========================
        # PARSE
        # =========================

        parsed = (
            WindowsPipelineExecutor
            .parse(
                db=db,
                event=event,
            )
        )

        if parsed is None:

            return {
                "status":
                    "stored",

                "raw_event_id":
                    event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "message":
                    (
                        "No parser registered "
                        "for this event"
                    ),
            }

        # =========================
        # NORMALIZE
        # =========================

        normalized_event = (
            WindowsNormalizer
            .save(
                db=db,
                raw_event=event,
                parsed=parsed,
            )
        )

        db.flush()

        # =========================
        # CORRELATION
        # =========================

        correlation_alert = (
            cls._run_correlation(
                db=db,
                event=event,
                provider_key=provider_key,
                parsed=parsed,
            )
        )

        correlation_data = (
            cls._correlation_payload(
                correlation_alert
            )
        )

        # =========================
        # SECURITY 4624
        # =========================

        if (
            provider_key
            == SECURITY_PROVIDER
            and event.event_id == 4624
        ):

            login_event = (
                EventService
                .create_login_event(
                    db=db,
                    payload=parsed,
                )
            )

            BehaviorProfileService.build_profile(
                db=db,
                username=parsed.username,
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "login_event_id":
                    login_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,
            }

        # =========================
        # SECURITY 4625
        # =========================

        if (
            provider_key
            == SECURITY_PROVIDER
            and event.event_id == 4625
        ):

            from app.modules.failed_login_events.service import (
                FailedLoginEventService,
            )

            failed_event = (
                FailedLoginEventService
                .create(
                    db=db,
                    payload=parsed,
                )
            )

            detection_result = (
                FailedLoginDetector
                .evaluate(
                    db=db,
                    event=failed_event,
                )
            )

            BehaviorProfileService.build_profile(
                db=db,
                username=parsed.username,
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "failed_login_event_id":
                    failed_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,
            }

        # =========================
        # SECURITY 4672
        # =========================

        if (
            provider_key
            == SECURITY_PROVIDER
            and event.event_id == 4672
        ):

            detection_result = (
                PrivilegeDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,
            }

        # =========================
        # SECURITY 4688
        # =========================

        if (
            provider_key
            == SECURITY_PROVIDER
            and event.event_id == 4688
        ):

            detection_result = (
                SuspiciousProcessDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,
            }

        # =========================
        # SECURITY 4720
        # =========================

        if (
            provider_key
            == SECURITY_PROVIDER
            and event.event_id == 4720
        ):

            detection_result = (
                AccountCreationDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,
            }

        # =========================
        # SECURITY 4728
        # =========================

        if (
            provider_key
            == SECURITY_PROVIDER
            and event.event_id == 4728
        ):

            detection_result = (
                GroupMembershipDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,
            }

        # =========================
        # SYSMON 1
        # =========================

        if (
            provider_key
            == SYSMON_PROVIDER
            and event.event_id == 1
        ):

            detection_result = (
                SysmonProcessDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,

                "correlation":
                    correlation_data,
            }

        # =========================
        # SYSMON 3
        # =========================

        if (
            provider_key
            == SYSMON_PROVIDER
            and event.event_id == 3
        ):

            detection_result = (
                SysmonNetworkDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,

                "correlation":
                    correlation_data,
            }

        # =========================
        # SYSMON 11
        # FILE + DOWNLOAD
        # =========================

        if (
            provider_key
            == SYSMON_PROVIDER
            and event.event_id == 11
        ):

            file_detection = (
                SysmonFileDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            download_detection = (
                DownloadFileDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection": {
                    "file":
                        file_detection,

                    "download":
                        download_detection,
                },

                "correlation":
                    correlation_data,
            }

        # =========================
        # SYSMON 13
        # =========================

        if (
            provider_key
            == SYSMON_PROVIDER
            and event.event_id == 13
        ):

            detection_result = (
                SysmonRegistryDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,

                "correlation":
                    correlation_data,
            }

        # =========================
        # SYSMON 22
        # =========================

        if (
            provider_key
            == SYSMON_PROVIDER
            and event.event_id == 22
        ):

            detection_result = (
                SysmonDnsDetector
                .evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status":
                    "processed",

                "raw_event_id":
                    event.id,

                "normalized_event_id":
                    normalized_event.id,

                "event_id":
                    event.event_id,

                "provider":
                    event.provider,

                "detection":
                    detection_result,

                "correlation":
                    correlation_data,
            }

        # =========================
        # DEFAULT
        # =========================

        return {
            "status":
                "normalized",

            "raw_event_id":
                event.id,

            "normalized_event_id":
                normalized_event.id,

            "event_id":
                event.event_id,

            "provider":
                event.provider,

            "detection":
                None,

            "correlation":
                correlation_data,
        }