from sqlalchemy.orm import Session

from app.models.alert import Alert

from app.modules.incidents.service import (
    IncidentService,
)

from app.modules.incidents.timeline_service import (
    IncidentTimelineService,
)


class AccountCreationDetector:

    SUSPICIOUS_ACCOUNT_NAMES = {
        "admin",
        "administrator",
        "backup",
        "support",
        "service",
        "svc",
        "system",
        "root",
        "helpdesk",
        "tempadmin",
    }

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed,
    ) -> dict:
        actor_username = (
            parsed.actor_username
            or "unknown"
        )

        target_username = (
            parsed.target_username
            or "unknown"
        )

        normalized_target = (
            target_username
            .strip()
            .lower()
        )

        reasons: list[str] = []

        risk_score = 50

        reasons.append(
            "A new Windows user account "
            f"was created: {target_username}"
        )

        if (
            normalized_target
            in cls.SUSPICIOUS_ACCOUNT_NAMES
        ):
            risk_score += 30

            reasons.append(
                "The new account uses a "
                "high-risk administrative "
                "or service-style name"
            )

        if normalized_target.startswith(
            "svc_"
        ):
            risk_score += 15

            reasons.append(
                "The new account resembles "
                "a service account"
            )

        if actor_username.lower() in {
            "unknown",
            "anonymous logon",
        }:
            risk_score += 15

            reasons.append(
                "The account creator could "
                "not be reliably identified"
            )

        risk_score = min(
            risk_score,
            100,
        )

        if risk_score >= 85:
            severity = "CRITICAL"

        elif risk_score >= 65:
            severity = "HIGH"

        else:
            severity = "MEDIUM"

        reason = "; ".join(
            reasons
        )

        alert = Alert(
            username=actor_username,

            alert_type=(
                "USER_ACCOUNT_CREATED"
            ),

            severity=severity,

            risk_score=risk_score,

            reason=reason,
        )

        db.add(alert)
        db.commit()
        db.refresh(alert)

        incident = (
            IncidentService
            .create_from_alert(
                db=db,
                alert=alert,
            )
        )

        if incident is not None:
            IncidentTimelineService.create_event(
                db=db,

                incident_id=incident.id,

                event_type=(
                    "USER_ACCOUNT_CREATED"
                ),

                actor_type="SYSTEM",

                description=(
                    "Windows Event 4720 "
                    "detected creation of "
                    "a new user account"
                ),

                event_metadata={
                    "actor_username": (
                        actor_username
                    ),

                    "target_username": (
                        target_username
                    ),

                    "target_domain": (
                        parsed.target_domain
                    ),

                    "target_sid": (
                        parsed.target_sid
                    ),

                    "source_ip": (
                        parsed.source_ip
                    ),

                    "computer": (
                        parsed.computer
                    ),

                    "risk_score": (
                        risk_score
                    ),
                },
            )

        return {
            "detected": True,

            "risk_score": risk_score,

            "severity": severity,

            "actor_username": (
                actor_username
            ),

            "target_username": (
                target_username
            ),

            "alert_id": alert.id,

            "incident_id": (
                incident.id
                if incident is not None
                else None
            ),

            "incident_created": (
                incident is not None
            ),
        }