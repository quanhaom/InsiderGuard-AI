from datetime import timedelta

from sqlalchemy.orm import Session

from app.models.behavior_profile import BehaviorProfile
from app.models.failed_login_event import FailedLoginEvent


class RiskAnalyzer:
    @staticmethod
    def analyze_login(
        db: Session,
        username: str,
        source_ip: str,
        login_time
    ) -> list[str]:
        reasons: list[str] = []

        profile = (
            db.query(BehaviorProfile)
            .filter(
                BehaviorProfile.username == username
            )
            .first()
        )

        # Nếu chưa có profile thì IP hiện tại được xem là IP mới.
        if profile is None:
            reasons.append("NEW_IP")

        elif (
            profile.common_ip
            and profile.common_ip != source_ip
        ):
            reasons.append("NEW_IP")

        # Login ngoài khung 06:00 - 22:00.
        login_hour = login_time.hour

        if login_hour < 6 or login_hour >= 22:
            reasons.append("OFF_HOUR_LOGIN")

        # Chỉ đếm failed login gần đây, không đếm toàn bộ lịch sử.
        failed_window_start = (
            login_time - timedelta(minutes=5)
        )

        failed_count = (
            db.query(FailedLoginEvent)
            .filter(
                FailedLoginEvent.username == username,
                FailedLoginEvent.failed_time
                >= failed_window_start,
                FailedLoginEvent.failed_time
                <= login_time
            )
            .count()
        )

        if failed_count >= 5:
            reasons.append("FAILED_LOGIN_BEFORE")

        return reasons