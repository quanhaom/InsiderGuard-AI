from sqlalchemy.orm import Session

from app.models.evidence import Evidence


class EvidenceRepository:

    @staticmethod
    def create(
        db: Session,
        evidence: Evidence
    ) -> Evidence:
        db.add(evidence)
        db.commit()
        db.refresh(evidence)

        return evidence

    @staticmethod
    def get_by_id(
        db: Session,
        evidence_id: int
    ) -> Evidence | None:
        return (
            db.query(Evidence)
            .filter(Evidence.id == evidence_id)
            .first()
        )

    @staticmethod
    def get_by_incident_id(
        db: Session,
        incident_id: int
    ) -> list[Evidence]:
        return (
            db.query(Evidence)
            .filter(Evidence.incident_id == incident_id)
            .order_by(Evidence.created_at.asc())
            .all()
        )

    @staticmethod
    def exists_for_incident(
        db: Session,
        incident_id: int,
        evidence_type: str
    ) -> bool:
        evidence = (
            db.query(Evidence)
            .filter(
                Evidence.incident_id == incident_id,
                Evidence.evidence_type == evidence_type
            )
            .first()
        )

        return evidence is not None