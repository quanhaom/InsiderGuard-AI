import json

from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment
from app.modules.ueba.risk_engine import RiskEngine
from app.repositories.behavior_profile_repository import (
    BehaviorProfileRepository,
)
from app.repositories.risk_repository import RiskRepository
from app.schemas.risk import LoginRiskEvaluationRequest


class UebaService:

    @staticmethod
    def evaluate_login(
        db: Session,
        username: str,
        payload: LoginRiskEvaluationRequest
    ) -> RiskAssessment:
        profile = BehaviorProfileRepository.get_by_username(
            db=db,
            username=username
        )

        if profile is None:
            raise ValueError(
                f"Behavior profile for '{username}' not found"
            )

        event = LoginEvent(
            username=username,
            source_ip=payload.source_ip,
            login_time=payload.login_time
        )

        result = RiskEngine.evaluate_login(
            event=event,
            profile=profile
        )

        assessment = RiskAssessment(
            username=username,
            risk_score=result.score,
            risk_level=result.level,
            reasons=json.dumps(
                result.reasons,
                ensure_ascii=False
            )
        )

        return RiskRepository.create(
            db=db,
            assessment=assessment
        )

    @staticmethod
    def get_latest(
        db: Session,
        username: str
    ) -> RiskAssessment | None:
        return RiskRepository.get_latest_by_username(
            db=db,
            username=username
        )

    @staticmethod
    def get_history(
        db: Session,
        username: str
    ) -> list[RiskAssessment]:
        return RiskRepository.get_history(
            db=db,
            username=username
        )