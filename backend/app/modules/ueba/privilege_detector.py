from sqlalchemy.orm import Session

from app.models.alert import Alert

from app.modules.incidents.service import (
    IncidentService,
)


class PrivilegeDetector:

    HIGH_RISK = {

        "SeDebugPrivilege",

        "SeImpersonatePrivilege",

        "SeTcbPrivilege",

        "SeLoadDriverPrivilege",

        "SeTakeOwnershipPrivilege",

    }

    @classmethod
    def evaluate(
        cls,
        db: Session,
        parsed,
    ):

        dangerous = list(

            set(parsed.privileges)

            & cls.HIGH_RISK

        )

        if not dangerous:

            return {

                "detected": False

            }

        risk_score = min(
            70 + len(dangerous) * 5,
            95,
        )

        severity = (
            "CRITICAL"
            if risk_score >= 85
            else "HIGH"
        )

        alert = Alert(

            username=parsed.username,

            alert_type=(
                "PRIVILEGE_ESCALATION"
            ),

            severity=severity,

            risk_score=risk_score,

            reason=(
                "High-risk privileges assigned: "
                + ", ".join(dangerous)
            ),

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

        return {

            "detected": True,

            "severity": severity,

            "risk_score": risk_score,

            "alert_id": alert.id,

            "incident_id": (
                incident.id
                if incident
                else None
            ),

            "dangerous_privileges":
                dangerous,

        }