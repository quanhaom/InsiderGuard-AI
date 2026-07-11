from sqlalchemy.orm import Session

from app.models.risk_assessment import RiskAssessment


class RiskRepository:

    @staticmethod
    def create(
        db: Session,
        assessment: RiskAssessment
    ) -> RiskAssessment:
        db.add(assessment)
        db.commit()
        db.refresh(assessment)

        return assessment

    @staticmethod
    def get_latest_by_username(
        db: Session,
        username: str
    ) -> RiskAssessment | None:
        return (
            db.query(RiskAssessment)
            .filter(RiskAssessment.username == username)
            .order_by(RiskAssessment.created_at.desc())
            .first()
        )

    @staticmethod
    def get_history(
        db: Session,
        username: str
    ) -> list[RiskAssessment]:
        return (
            db.query(RiskAssessment)
            .filter(RiskAssessment.username == username)
            .order_by(RiskAssessment.created_at.desc())
            .all()
        )