from sqlalchemy.orm import Session

from app.models.risk_assessment import RiskAssessment


class RiskEngine:
    RISK_WEIGHTS = {
        "NEW_IP": 25,
        "OFF_HOUR_LOGIN": 20,
        "FAILED_LOGIN_BEFORE": 35,
    }

    @classmethod
    def calculate_risk(
        cls,
        db: Session,
        username: str,
        reasons: list[str]
    ) -> RiskAssessment:
        score = sum(
            cls.RISK_WEIGHTS.get(reason, 0)
            for reason in reasons
        )

        # Không để điểm vượt quá 100.
        score = min(score, 100)

        if score >= 80:
            severity = "HIGH"

        elif score >= 50:
            severity = "MEDIUM"

        else:
            severity = "LOW"

        assessment = RiskAssessment(
            username=username,
            risk_score=score,
            reason=", ".join(reasons),
            severity=severity
        )

        db.add(assessment)
        db.commit()
        db.refresh(assessment)
        from app.modules.alert.service import AlertService
        AlertService.create_from_risk(
            db=db,
            assessment=assessment
        )

        return assessment