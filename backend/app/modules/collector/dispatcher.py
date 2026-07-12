from sqlalchemy.orm import Session

from app.modules.behavior.service import (
    BehaviorProfileService,
)
from app.modules.collector.raw_event_service import (
    RawEventService,
)
from app.modules.events.service import EventService
from app.modules.parsers.bootstrap import (
    register_default_parsers,
)
from app.modules.parsers.registry import ParserRegistry
from app.modules.risk.analyzer import RiskAnalyzer
from app.modules.risk.service import RiskEngine
from app.schemas.collector import CollectorEvent
from app.schemas.raw_windows_event import (
    RawWindowsEventCreate,
)


# Đăng ký parser khi module được load.
register_default_parsers()


class EventDispatcher:
    @staticmethod
    def dispatch(
        db: Session,
        event: CollectorEvent
    ) -> dict:
        raw_payload = RawWindowsEventCreate(
            record_id=event.record_id,
            event_id=event.event_id,
            computer=event.computer,
            provider=event.provider,
            xml=event.xml
        )

        raw_event = RawEventService.save(
            db=db,
            payload=raw_payload
        )

        parser = ParserRegistry.get(
            event.event_id
        )

        if parser is None:
            return {
                "status": "stored",
                "raw_event_id": raw_event.id,
                "event_id": event.event_id,
                "handler": "none",
                "message": (
                    "Raw event stored, but no parser "
                    "is registered"
                )
            }

        normalized_event = parser.parse(
            db=db,
            event=raw_event
        )

        if event.event_id == 4624:
            return EventDispatcher._handle_4624(
                db=db,
                raw_event_id=raw_event.id,
                normalized_event=normalized_event
            )

        if event.event_id == 4625:
            return EventDispatcher._handle_4625(
                db=db,
                raw_event_id=raw_event.id,
                normalized_event=normalized_event
            )

        return {
            "status": "stored",
            "raw_event_id": raw_event.id,
            "event_id": event.event_id,
            "handler": "parser_only",
            "message": "Raw event stored and parsed"
        }

    @staticmethod
    def _handle_4624(
        db: Session,
        raw_event_id: int,
        normalized_event
    ) -> dict:
        # Phân tích trước khi profile bị cập nhật bằng IP mới.
        reasons = RiskAnalyzer.analyze_login(
            db=db,
            username=normalized_event.username,
            source_ip=normalized_event.source_ip,
            login_time=normalized_event.login_time
        )

        login_event = EventService.create_login_event(
            db=db,
            payload=normalized_event
        )

        BehaviorProfileService.update_profile(
            db=db,
            login=login_event
        )

        # Luôn tạo RiskAssessment, kể cả score = 0.
        assessment = RiskEngine.calculate_risk(
            db=db,
            username=login_event.username,
            reasons=reasons
        )

        return {
            "status": "accepted",
            "raw_event_id": raw_event_id,
            "event_id": 4624,
            "handler": "windows_login_success",
            "message": (
                f"Login event ID={login_event.id}; "
                f"risk assessment ID={assessment.id}; "
                f"risk score={assessment.risk_score}; "
                f"severity={assessment.severity}"
            )
        }

    @staticmethod
    def _handle_4625(
        db: Session,
        raw_event_id: int,
        normalized_event
    ) -> dict:
        # Nếu bạn đã có FailedLoginService thì thay phần này
        # bằng service hiện tại của dự án.
        from app.models.failed_login_event import (
            FailedLoginEvent,
        )

        failed_event = FailedLoginEvent(
            username=normalized_event.username,
            source_ip=normalized_event.source_ip,
            failure_reason=(
                normalized_event.failure_reason
            ),
            status=normalized_event.status,
            sub_status=normalized_event.sub_status,
            failed_time=normalized_event.failed_time
        )

        db.add(failed_event)
        db.commit()
        db.refresh(failed_event)

        return {
            "status": "accepted",
            "raw_event_id": raw_event_id,
            "event_id": 4625,
            "handler": "windows_login_failure",
            "message": (
                f"Failed login event created "
                f"with ID={failed_event.id}"
            )
        }