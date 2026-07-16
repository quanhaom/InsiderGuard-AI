from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.failed_login_event import (
    FailedLoginEvent,
)
from app.models.risk_assessment import (
    RiskAssessment,
)
from app.modules.incidents.service import (
    IncidentService,
)


class FailedLoginDetector:
    WINDOW_MINUTES = 10
    FAILURE_THRESHOLD = 5
    ALERT_COOLDOWN_MINUTES = 10

    RISK_SCORE = 85
    SEVERITY = "CRITICAL"

    @staticmethod
    def _utc_now_naive() -> datetime:
        return datetime.now(UTC).replace(
            tzinfo=None
        )

    @classmethod
    def evaluate(
        cls,
        db: Session,
        event: FailedLoginEvent,
    ) -> dict:
        window_start = (
            event.failed_time
            - timedelta(
                minutes=cls.WINDOW_MINUTES
            )
        )

        failed_events = (
            db.query(FailedLoginEvent)
            .filter(
                FailedLoginEvent.username
                == event.username,
                FailedLoginEvent.failed_time
                >= window_start,
                FailedLoginEvent.failed_time
                <= event.failed_time,
            )
            .order_by(
                FailedLoginEvent.failed_time.asc()
            )
            .all()
        )

        failure_count = len(failed_events)

        if (
            failure_count
            < cls.FAILURE_THRESHOLD
        ):
            return {
                "detected": False,
                "failure_count": failure_count,
                "threshold": (
                    cls.FAILURE_THRESHOLD
                ),
            }

        source_ips = sorted(
            {
                item.source_ip
                for item in failed_events
                if item.source_ip
            }
        )

        reason = (
            f"{failure_count} failed login "
            f"attempts detected within "
            f"{cls.WINDOW_MINUTES} minutes. "
            f"Source IPs: "
            f"{', '.join(source_ips) or 'unknown'}"
        )

        existing_alert = (
            db.query(Alert)
            .filter(
                Alert.username
                == event.username,
                Alert.alert_type
                == "FAILED_LOGIN_BURST",
                Alert.created_at
                >= (
                    event.failed_time
                    - timedelta(
                        minutes=(
                            cls
                            .ALERT_COOLDOWN_MINUTES
                        )
                    )
                ),
            )
            .order_by(
                Alert.created_at.desc()
            )
            .first()
        )

        if existing_alert is not None:
            return {
                "detected": True,
                "failure_count": failure_count,
                "alert_id": existing_alert.id,
                "incident_created": False,
                "duplicate_suppressed": True,
            }

        assessment = RiskAssessment(
            username=event.username,
            risk_score=cls.RISK_SCORE,
            severity=cls.SEVERITY,
            reason=reason,
        )

        db.add(assessment)
        db.flush()

        alert = Alert(
            username=event.username,
            alert_type=(
                "FAILED_LOGIN_BURST"
            ),
            severity=cls.SEVERITY,
            risk_score=cls.RISK_SCORE,
            reason=reason,
        )

        db.add(alert)
        db.flush()

        incident = (
            IncidentService.create_from_alert(
                db=db,
                alert=alert,
            )
        )

        return {
            "detected": True,
            "failure_count": failure_count,
            "risk_score": cls.RISK_SCORE,
            "severity": cls.SEVERITY,
            "alert_id": alert.id,
            "incident_id": (
                incident.id
                if incident
                else None
            ),
            "incident_created": (
                incident is not None
            ),
            "duplicate_suppressed": False,
        }