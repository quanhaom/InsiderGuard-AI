from sqlalchemy.orm import Session
from app.modules.incidents.service import IncidentService
from app.models.alert import Alert
from app.models.risk_assessment import RiskAssessment


class AlertService:


    @staticmethod
    def create_from_risk(
        db: Session,
        assessment: RiskAssessment
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

            risk_score=assessment.risk_score,

            reason=assessment.reason
        )


        db.add(alert)

        db.commit()

        db.refresh(alert)

        IncidentService.create_from_alert(
            db=db,
            alert=alert
)


        return alert