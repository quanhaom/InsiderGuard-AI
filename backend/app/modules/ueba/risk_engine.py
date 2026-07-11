from dataclasses import dataclass
from datetime import datetime

from app.models.behavior_profile import BehaviorProfile
from app.models.login_event import LoginEvent


@dataclass
class RiskResult:
    score: int
    level: str
    reasons: list[str]


class RiskEngine:
    NIGHT_LOGIN_SCORE = 20
    WEEKEND_LOGIN_SCORE = 15
    NEW_IP_SCORE = 15
    ABNORMAL_LOGIN_TIME_SCORE = 25

    NIGHT_START_HOUR = 22
    NIGHT_END_HOUR = 6
    MAX_LOGIN_TIME_DEVIATION = 3

    @classmethod
    def evaluate_login(
        cls,
        event: LoginEvent,
        profile: BehaviorProfile
    ) -> RiskResult:
        score = 0
        reasons: list[str] = []

        if cls._is_night_login(event.login_time):
            score += cls.NIGHT_LOGIN_SCORE
            reasons.append("Night Login")

        if cls._is_weekend_login(event.login_time):
            score += cls.WEEKEND_LOGIN_SCORE
            reasons.append("Weekend Login")

        if cls._is_new_ip(
            current_ip=event.source_ip,
            common_ip=profile.common_source_ip
        ):
            score += cls.NEW_IP_SCORE
            reasons.append("New IP Address")

        if cls._is_abnormal_login_time(
            current_login_time=event.login_time,
            average_login_hour=profile.avg_login_hour
        ):
            score += cls.ABNORMAL_LOGIN_TIME_SCORE
            reasons.append("Abnormal Login Time")

        score = min(score, 100)

        return RiskResult(
            score=score,
            level=cls.get_risk_level(score),
            reasons=reasons
        )

    @classmethod
    def _is_night_login(
        cls,
        login_time: datetime
    ) -> bool:
        hour = login_time.hour

        return (
            hour >= cls.NIGHT_START_HOUR
            or hour < cls.NIGHT_END_HOUR
        )

    @staticmethod
    def _is_weekend_login(
        login_time: datetime
    ) -> bool:
        return login_time.weekday() >= 5

    @staticmethod
    def _is_new_ip(
        current_ip: str,
        common_ip: str | None
    ) -> bool:
        if common_ip is None:
            return False

        return current_ip != common_ip

    @classmethod
    def _is_abnormal_login_time(
        cls,
        current_login_time: datetime,
        average_login_hour: float
    ) -> bool:
        current_hour = (
            current_login_time.hour
            + current_login_time.minute / 60
        )

        deviation = abs(
            current_hour - average_login_hour
        )

        circular_deviation = min(
            deviation,
            24 - deviation
        )

        return circular_deviation > cls.MAX_LOGIN_TIME_DEVIATION

    @staticmethod
    def get_risk_level(score: int) -> str:
        if score <= 20:
            return "LOW"

        if score <= 40:
            return "MEDIUM"

        if score <= 60:
            return "HIGH"

        return "CRITICAL"