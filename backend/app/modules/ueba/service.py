import json

from sqlalchemy.orm import Session

from app.models.login_event import LoginEvent
from app.models.risk_assessment import (
    RiskAssessment,
)
from app.modules.behavior_profile.service import (
    BehaviorProfileService,
)
from app.modules.incidents.service import (
    IncidentService,
)
from app.modules.ueba.risk_engine import (
    RiskEngine,
)
from app.repositories.behavior_profile_repository import (
    BehaviorProfileRepository,
)
from app.repositories.risk_repository import (
    RiskRepository,
)
from app.schemas.risk import (
    LoginRiskEvaluationRequest,
)


class UebaService:

    @staticmethod
    def evaluate_login(
        db: Session,
        username: str,
        payload: LoginRiskEvaluationRequest,
    ) -> RiskAssessment:
        normalized_username = (
            username.strip()
        )

        if not normalized_username:
            raise ValueError(
                "Username cannot be empty"
            )

        profile = (
            BehaviorProfileRepository
            .get_by_username(
                db=db,
                username=normalized_username,
            )
        )

        if profile is None:
            raise ValueError(
                "Behavior profile for "
                f"'{normalized_username}' "
                "not found. Build the profile "
                "before evaluating activity."
            )

        # Đánh giá dựa trên profile cũ,
        # trước khi sự kiện mới được đưa
        # vào baseline.
        event = LoginEvent(
            username=normalized_username,
            source_ip=payload.source_ip,
            login_time=payload.login_time,
        )

        result = RiskEngine.evaluate_login(
            event=event,
            profile=profile,
        )

        # Lưu login event sau khi đã đánh giá.
        db.add(event)
        db.flush()

        assessment = RiskAssessment(
            username=normalized_username,
            risk_score=result.score,
            severity=result.level,
            reason=json.dumps(
                result.reasons,
                ensure_ascii=False,
            ),
        )

        saved_assessment = (
            RiskRepository.create(
                db=db,
                assessment=assessment,
            )
        )

        # IncidentService nên tự quyết định
        # chỉ tạo incident khi risk đủ cao.
        IncidentService.create_from_risk_assessment(
            db=db,
            assessment=saved_assessment,
        )

        # Sau khi đánh giá xong mới cập nhật
        # baseline bằng login vừa nhận.
        BehaviorProfileService.build_profile(
            db=db,
            username=normalized_username,
        )

        return saved_assessment

    @staticmethod
    def get_latest(
        db: Session,
        username: str,
    ) -> RiskAssessment | None:
        return (
            RiskRepository
            .get_latest_by_username(
                db=db,
                username=username.strip(),
            )
        )

    @staticmethod
    def get_history(
        db: Session,
        username: str,
    ) -> list[RiskAssessment]:
        return (
            RiskRepository.get_history(
                db=db,
                username=username.strip(),
            )
        )