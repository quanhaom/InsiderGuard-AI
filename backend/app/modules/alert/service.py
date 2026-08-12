from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.risk_assessment import (
    RiskAssessment,
)

from app.modules.incidents.service import (
    IncidentService,
)

from app.modules.correlation.result import (
    CorrelationResult,
)


class AlertService:

    # =========================
    # RISK -> ALERT
    # =========================

    @staticmethod
    def create_from_risk(
        db: Session,
        assessment: RiskAssessment,
    ):

        if assessment.risk_score < 50:
            return None

        severity = "MEDIUM"

        if assessment.risk_score >= 80:
            severity = "HIGH"

        alert = Alert(
            username=assessment.username,
            alert_type="RISK_THRESHOLD",
            severity=severity,
            risk_score=(
                assessment.risk_score
            ),
            reason=assessment.reason,
        )

        db.add(
            alert
        )

        db.commit()

        db.refresh(
            alert
        )

        IncidentService.create_from_alert(
            db=db,
            alert=alert,
        )

        return alert

    # =========================
    # CORRELATION KEY
    # =========================

    @staticmethod
    def _correlation_key(
        result: CorrelationResult,
    ) -> str:

        computer = (
            result.computer
            or "UNKNOWN"
        )

        if result.process_guid:

            identity = (
                "GUID:"
                f"{result.process_guid}"
            )

        elif (
            result.process_id
            is not None
        ):

            identity = (
                "PID:"
                f"{result.process_id}"
            )

        else:

            identity = (
                "UNKNOWN_PROCESS"
            )

        return (
            "[CORRELATION:"
            f"{computer}|"
            f"{identity}"
            "]"
        )

    # =========================
    # CORRELATION REASON
    # =========================

    @staticmethod
    def _build_correlation_reason(
        *,
        result: CorrelationResult,
        fingerprint: str,
    ) -> str:

        reasons = (
            "; ".join(
                result.reasons
            )
        )

        event_ids = (
            ",".join(
                str(
                    event_id
                )
                for event_id
                in sorted(
                    set(
                        result.event_ids
                    )
                )
            )
        )

        mitre = (
            ",".join(
                result.mitre_techniques
            )
        )

        return (
            f"{fingerprint} "
            "Process correlation detected. "
            f"Computer={result.computer}; "
            f"ProcessGuid={result.process_guid}; "
            f"ProcessId={result.process_id}; "
            f"Image={result.process_image}; "
            f"Events=[{event_ids}]; "
            f"MITRE=[{mitre}]; "
            f"Reasons={reasons}"
        )

    # =========================
    # CORRELATION -> ALERT
    # =========================

    @classmethod
    def create_from_correlation(
        cls,
        db: Session,
        result: CorrelationResult,
    ):

        if not result.detected:
            return None

        if result.severity == "LOW":
            return None

        username = (
            result.username
            or "UNKNOWN"
        )

        fingerprint = (
            cls._correlation_key(
                result
            )
        )

        reason = (
            cls._build_correlation_reason(
                result=result,
                fingerprint=(
                    fingerprint
                ),
            )
        )

        existing = (
            db.query(
                Alert
            )
            .filter(
                Alert.alert_type
                == "PROCESS_CORRELATION"
            )
            .filter(
                Alert.reason.contains(
                    fingerprint
                )
            )
            .order_by(
                Alert.id.desc()
            )
            .first()
        )

        severity_order = {
            "LOW": 0,
            "MEDIUM": 1,
            "HIGH": 2,
            "CRITICAL": 3,
        }

        # =========================
        # UPDATE EXISTING
        # =========================

        if existing:

            changed = False

            if (
                result.score
                > existing.risk_score
            ):

                existing.risk_score = (
                    result.score
                )

                changed = True

            if (
                severity_order.get(
                    result.severity,
                    0,
                )
                >
                severity_order.get(
                    existing.severity,
                    0,
                )
            ):

                existing.severity = (
                    result.severity
                )

                changed = True

            if (
                existing.reason
                != reason
            ):

                existing.reason = reason

                changed = True

            if changed:

                db.commit()

                db.refresh(
                    existing
                )

            # Retry-safe.
            # IncidentService already
            # deduplicates by alert_id.
            if existing.severity in {
                "HIGH",
                "CRITICAL",
            }:

                IncidentService.create_from_alert(
                    db=db,
                    alert=existing,
                )

            return existing

        # =========================
        # CREATE NEW ALERT
        # =========================

        alert = Alert(
            username=username,

            alert_type=(
                "PROCESS_CORRELATION"
            ),

            severity=(
                result.severity
            ),

            risk_score=(
                result.score
            ),

            reason=reason,
        )

        db.add(
            alert
        )

        db.commit()

        db.refresh(
            alert
        )

        if alert.severity in {
            "HIGH",
            "CRITICAL",
        }:

            IncidentService.create_from_alert(
                db=db,
                alert=alert,
            )

        return alert