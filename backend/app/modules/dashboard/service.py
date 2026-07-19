from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alert import Alert
from app.models.device import Device
from app.models.incident import Incident
from app.models.risk_assessment import (
    RiskAssessment,
)
from app.models.user import User


class DashboardService:

    @staticmethod
    def get_overview(
        db: Session,
    ):
        open_incidents = (
            db.query(Incident)
            .filter(
                Incident.status != "CLOSED"
            )
            .count()
        )

        critical_alerts = (
            db.query(Alert)
            .filter(
                Alert.severity == "CRITICAL"
            )
            .count()
        )

        high_risk_users = (
            db.query(
                RiskAssessment.username
            )
            .filter(
                RiskAssessment.risk_score
                >= 60
            )
            .distinct()
            .count()
        )

        online_devices = (
            db.query(Device)
            .filter(
                Device.status == "ONLINE"
            )
            .count()
        )

        total_users = (
            db.query(User)
            .count()
        )

        return {
            "open_incidents": (
                open_incidents
            ),
            "critical_alerts": (
                critical_alerts
            ),
            "high_risk_users": (
                high_risk_users
            ),
            "online_devices": (
                online_devices
            ),
            "total_users": (
                total_users
            ),
        }

    @staticmethod
    def get_incident_statistics(
        db: Session,
    ):
        rows = (
            db.query(
                Incident.status,
                func.count(
                    Incident.id
                ),
            )
            .group_by(
                Incident.status
            )
            .all()
        )

        statistics = {
            "OPEN": 0,
            "INVESTIGATING": 0,
            "RESOLVED": 0,
            "CLOSED": 0,
        }

        for status, count in rows:
            statistics[status] = count

        return statistics

    @staticmethod
    def get_top_risk_users(
        db: Session,
        limit: int = 5,
    ):
        rows = (
            db.query(
                RiskAssessment.username,
                func.max(
                    RiskAssessment.risk_score
                ).label("risk_score"),
            )
            .group_by(
                RiskAssessment.username
            )
            .order_by(
                func.max(
                    RiskAssessment.risk_score
                ).desc()
            )
            .limit(limit)
            .all()
        )

        return [
            {
                "username": (
                    row.username
                ),
                "risk_score": (
                    row.risk_score
                ),
                "severity": (
                    DashboardService
                    .get_risk_severity(
                        row.risk_score
                    )
                ),
            }
            for row in rows
        ]

    @staticmethod
    def get_risk_severity(
        risk_score: int,
    ) -> str:
        if risk_score >= 81:
            return "CRITICAL"

        if risk_score >= 61:
            return "HIGH"

        if risk_score >= 31:
            return "MEDIUM"

        return "LOW"