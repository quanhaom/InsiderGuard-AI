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


SECURITY_PROVIDER = (
    "microsoft-windows-security-auditing"
)

SYSMON_PROVIDER = (
    "microsoft-windows-sysmon"
)


class WindowsEventService:

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
        # PARSE EVENT
        # =========================

        parsed = (
            WindowsPipelineExecutor.parse(
                db=db,
                event=event,
            )
        )

        if parsed is None:
            return {
                "status": "stored",
                "raw_event_id": event.id,
                "event_id": event.event_id,
                "provider": event.provider,
                "message": (
                    "No parser registered "
                    "for this event"
                ),
            }

        # =========================
        # NORMALIZE EVENT
        # =========================

        normalized_event = (
            WindowsNormalizer.save(
                db=db,
                raw_event=event,
                parsed=parsed,
            )
        )

        # =========================
        # SECURITY EVENT 4624
        # SUCCESSFUL LOGIN
        # =========================

        if (
            provider_key == SECURITY_PROVIDER
            and event.event_id == 4624
        ):
            login_event = (
                EventService.create_login_event(
                    db=db,
                    payload=parsed,
                )
            )

            BehaviorProfileService.build_profile(
                db=db,
                username=parsed.username,
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "login_event_id": (
                    login_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
            }

        # =========================
        # SECURITY EVENT 4625
        # FAILED LOGIN
        # =========================

        if (
            provider_key == SECURITY_PROVIDER
            and event.event_id == 4625
        ):
            from app.modules.failed_login_events.service import (
                FailedLoginEventService,
            )

            failed_event = (
                FailedLoginEventService.create(
                    db=db,
                    payload=parsed,
                )
            )

            detection_result = (
                FailedLoginDetector.evaluate(
                    db=db,
                    event=failed_event,
                )
            )

            BehaviorProfileService.build_profile(
                db=db,
                username=parsed.username,
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "failed_login_event_id": (
                    failed_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
                "detection": detection_result,
            }

        # =========================
        # SECURITY EVENT 4672
        # SPECIAL PRIVILEGES
        # =========================

        if (
            provider_key == SECURITY_PROVIDER
            and event.event_id == 4672
        ):
            detection_result = (
                PrivilegeDetector.evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
                "detection": detection_result,
            }

        # =========================
        # SECURITY EVENT 4688
        # PROCESS CREATION
        # =========================

        if (
            provider_key == SECURITY_PROVIDER
            and event.event_id == 4688
        ):
            detection_result = (
                SuspiciousProcessDetector.evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
                "detection": detection_result,
            }

        # =========================
        # SECURITY EVENT 4720
        # USER ACCOUNT CREATED
        # =========================

        if (
            provider_key == SECURITY_PROVIDER
            and event.event_id == 4720
        ):
            detection_result = (
                AccountCreationDetector.evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
                "detection": detection_result,
            }

        # =========================
        # SECURITY EVENT 4728
        # GROUP MEMBERSHIP
        # =========================

        if (
            provider_key == SECURITY_PROVIDER
            and event.event_id == 4728
        ):
            detection_result = (
                GroupMembershipDetector.evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
                "detection": detection_result,
            }

        # =========================
        # SYSMON EVENT 1
        # PROCESS CREATION
        # =========================

        if (
            provider_key == SYSMON_PROVIDER
            and event.event_id == 1
        ):
            detection_result = (
                SysmonProcessDetector.evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
                "detection": detection_result,
            }

        # =========================
        # SYSMON EVENT 3
        # NETWORK CONNECTION
        # =========================

        if (
            provider_key == SYSMON_PROVIDER
            and event.event_id == 3
        ):
            detection_result = (
                SysmonNetworkDetector.evaluate(
                    db=db,
                    parsed=parsed,
                )
            )

            return {
                "status": "processed",
                "raw_event_id": event.id,
                "normalized_event_id": (
                    normalized_event.id
                ),
                "event_id": event.event_id,
                "provider": event.provider,
                "detection": detection_result,
            }

        # =========================
        # DEFAULT RESULT
        # =========================
        # Event đã có parser và đã được normalize,
        # nhưng chưa có detector hoặc nghiệp vụ riêng.

        return {
            "status": "normalized",
            "raw_event_id": event.id,
            "normalized_event_id": (
                normalized_event.id
            ),
            "event_id": event.event_id,
            "provider": event.provider,
            "detection": None,
        }