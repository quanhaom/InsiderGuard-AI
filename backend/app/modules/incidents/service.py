from datetime import datetime

from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.risk_assessment import RiskAssessment
from app.repositories.incident_repository import IncidentRepository


class IncidentService:

    INCIDENT_THRESHOLD = 61

    @classmethod
    def create_from_risk_assessment(
        cls,
        db: Session,
        assessment: RiskAssessment
    ) -> Incident | None:
        if assessment.risk_score < cls.INCIDENT_THRESHOLD:
            return None

        incident = Incident(
            username=assessment.username,
            risk_assessment_id=assessment.id,
            title=f"Potential insider threat detected for {assessment.username}",
            severity=assessment.risk_level,
            description=(
                f"UEBA generated risk score "
                f"{assessment.risk_score}. "
                f"Indicators: {assessment.reasons}"
            ),
            status="OPEN"
        )

        return IncidentRepository.create(
            db=db,
            incident=incident
        )

    @staticmethod
    def get_incident(
        db: Session,
        incident_id: int
    ) -> Incident | None:
        return IncidentRepository.get_by_id(
            db=db,
            incident_id=incident_id
        )

    @staticmethod
    def get_all_incidents(
        db: Session
    ) -> list[Incident]:
        return IncidentRepository.get_all(db=db)

    @staticmethod
    def get_user_incidents(
        db: Session,
        username: str
    ) -> list[Incident]:
        return IncidentRepository.get_by_username(
            db=db,
            username=username
        )

    @staticmethod
    def update_status(
        db: Session,
        incident: Incident,
        new_status: str
    ) -> Incident:
        allowed_statuses = {
            "OPEN",
            "INVESTIGATING",
            "RESOLVED",
            "FALSE_POSITIVE"
        }

        normalized_status = new_status.upper()

        if normalized_status not in allowed_statuses:
            raise ValueError(
                "Invalid incident status. Allowed values: "
                "OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE"
            )

        incident.status = normalized_status

        if normalized_status in {
            "RESOLVED",
            "FALSE_POSITIVE"
        }:
            incident.resolved_at = datetime.utcnow()
        else:
            incident.resolved_at = None

        return IncidentRepository.update(
            db=db,
            incident=incident
        )