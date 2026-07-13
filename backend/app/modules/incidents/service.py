from sqlalchemy.orm import Session
from app.modules.evidence.service import EvidenceService
from app.models.alert import Alert
from app.models.incident import Incident


class IncidentService:


    @staticmethod
    def create_from_alert(
        db: Session,
        alert: Alert
    ):

        # Chỉ HIGH alert tạo incident

        if alert.severity != "HIGH":
            return None


        incident = Incident(

            alert_id=alert.id,

            username=alert.username,

            title=(
                "Suspicious user behavior detected"
            ),

            severity=alert.severity,

            status="OPEN",

            description=alert.reason
        )


        db.add(
            incident
        )

        db.commit()

        db.refresh(
            incident
        )
        snapshot = {

            "incident_id": incident.id,

            "username": incident.username,

            "alert_id": alert.id,

            "severity": alert.severity,

            "risk_score": alert.risk_score,

            "reason": alert.reason

        }


        EvidenceService.create_snapshot(

            db=db,

            incident_id=incident.id,

            username=incident.username,

            snapshot=snapshot
        )

        return incident