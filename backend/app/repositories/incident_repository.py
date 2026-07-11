from sqlalchemy.orm import Session

from app.models.incident import Incident


class IncidentRepository:

    @staticmethod
    def create(
        db: Session,
        incident: Incident
    ) -> Incident:
        db.add(incident)
        db.commit()
        db.refresh(incident)

        return incident

    @staticmethod
    def get_by_id(
        db: Session,
        incident_id: int
    ) -> Incident | None:
        return (
            db.query(Incident)
            .filter(Incident.id == incident_id)
            .first()
        )

    @staticmethod
    def get_all(
        db: Session
    ) -> list[Incident]:
        return (
            db.query(Incident)
            .order_by(Incident.detected_at.desc())
            .all()
        )

    @staticmethod
    def get_by_username(
        db: Session,
        username: str
    ) -> list[Incident]:
        return (
            db.query(Incident)
            .filter(Incident.username == username)
            .order_by(Incident.detected_at.desc())
            .all()
        )

    @staticmethod
    def update(
        db: Session,
        incident: Incident
    ) -> Incident:
        db.commit()
        db.refresh(incident)

        return incident