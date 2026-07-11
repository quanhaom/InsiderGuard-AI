from sqlalchemy.orm import Session

from app.models.investigation_report import InvestigationReport


class InvestigationRepository:

    @staticmethod
    def create(
        db: Session,
        report: InvestigationReport
    ) -> InvestigationReport:
        db.add(report)
        db.commit()
        db.refresh(report)

        return report

    @staticmethod
    def get_by_id(
        db: Session,
        report_id: int
    ) -> InvestigationReport | None:
        return (
            db.query(InvestigationReport)
            .filter(InvestigationReport.id == report_id)
            .first()
        )

    @staticmethod
    def get_by_incident_id(
        db: Session,
        incident_id: int
    ) -> InvestigationReport | None:
        return (
            db.query(InvestigationReport)
            .filter(
                InvestigationReport.incident_id == incident_id
            )
            .first()
        )

    @staticmethod
    def delete(
        db: Session,
        report: InvestigationReport
    ) -> None:
        db.delete(report)
        db.commit()