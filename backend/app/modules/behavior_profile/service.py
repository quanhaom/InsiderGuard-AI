import math
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.behavior_profile import BehaviorProfile
from app.models.device import Device
from app.models.failed_login_event import FailedLoginEvent
from app.models.login_event import LoginEvent
from app.models.risk_assessment import RiskAssessment


class BehaviorProfileService:

    @staticmethod
    def _utc_now_naive() -> datetime:
        return datetime.now(UTC).replace(
            tzinfo=None
        )

    @staticmethod
    def _get_common_value(
        values: list[str],
    ) -> str:
        cleaned_values = [
            value.strip()
            for value in values
            if value and value.strip()
        ]

        if not cleaned_values:
            return ""

        return Counter(
            cleaned_values
        ).most_common(1)[0][0]

    @staticmethod
    def _unique_values(
        values: list[str],
    ) -> list[str]:
        return sorted(
            {
                value.strip()
                for value in values
                if value and value.strip()
            }
        )

    @staticmethod
    def _calculate_average_login_hour(
        login_times: list[datetime],
    ) -> float:
        """
        Tính thời gian đăng nhập trung bình theo vòng tròn 24 giờ.

        Ví dụ:
        23:30 và 00:30 sẽ cho kết quả gần 00:00,
        thay vì 12:00 như trung bình số học thông thường.
        """
        if not login_times:
            return 0.0

        angles = [
            (
                (
                    login_time.hour
                    + login_time.minute / 60
                    + login_time.second / 3600
                )
                / 24
            )
            * 2
            * math.pi
            for login_time in login_times
        ]

        average_sin = (
            sum(
                math.sin(angle)
                for angle in angles
            )
            / len(angles)
        )

        average_cos = (
            sum(
                math.cos(angle)
                for angle in angles
            )
            / len(angles)
        )

        average_angle = math.atan2(
            average_sin,
            average_cos,
        )

        if average_angle < 0:
            average_angle += (
                2 * math.pi
            )

        average_hour = (
            average_angle
            * 24
            / (2 * math.pi)
        )

        return round(
            average_hour,
            2,
        )

    @staticmethod
    def _calculate_active_days(
        activity_times: list[datetime],
    ) -> int:
        valid_times = [
            activity_time
            for activity_time
            in activity_times
            if activity_time
        ]

        if not valid_times:
            return 1

        earliest_time = min(
            valid_times
        )

        latest_time = max(
            valid_times
        )

        return max(
            1,
            (
                latest_time.date()
                - earliest_time.date()
            ).days
            + 1,
        )

    @staticmethod
    def _calculate_risk_baseline(
        risk_assessments: list[
            RiskAssessment
        ],
    ) -> float:
        if not risk_assessments:
            return 0.0

        valid_scores = [
            float(
                risk.risk_score
            )
            for risk in risk_assessments
            if risk.risk_score
            is not None
        ]

        if not valid_scores:
            return 0.0

        return round(
            sum(valid_scores)
            / len(valid_scores),
            2,
        )

    @classmethod
    def build_profile(
        cls,
        db: Session,
        username: str,
    ) -> BehaviorProfile:
        normalized_username = (
            username.strip()
        )

        if not normalized_username:
            raise ValueError(
                "Username cannot be empty"
            )

        logins = (
            db.query(LoginEvent)
            .filter(
                LoginEvent.username
                == normalized_username
            )
            .order_by(
                LoginEvent.login_time.asc()
            )
            .all()
        )

        failed_logins = (
            db.query(FailedLoginEvent)
            .filter(
                FailedLoginEvent.username
                == normalized_username
            )
            .order_by(
                FailedLoginEvent
                .failed_time
                .asc()
            )
            .all()
        )

        devices = (
            db.query(Device)
            .filter(
                Device.owner_username
                == normalized_username
            )
            .order_by(
                Device.last_seen.desc()
            )
            .all()
        )

        risk_assessments = (
            db.query(RiskAssessment)
            .filter(
                RiskAssessment.username
                == normalized_username
            )
            .order_by(
                RiskAssessment
                .created_at
                .asc()
            )
            .all()
        )

        login_times = [
            login.login_time
            for login in logins
            if login.login_time
        ]

        failed_login_times = [
            failed_login.failed_time
            for failed_login
            in failed_logins
            if failed_login.failed_time
        ]

        successful_login_ips = [
            login.source_ip
            for login in logins
            if login.source_ip
        ]

        failed_login_ips = [
            failed_login.source_ip
            for failed_login
            in failed_logins
            if failed_login.source_ip
        ]

        ip_values = [
            *successful_login_ips,
            *failed_login_ips,
        ]

        host_values = [
            device.hostname
            for device in devices
            if device.hostname
        ]

        known_ips = (
            cls._unique_values(
                ip_values
            )
        )

        known_devices = (
            cls._unique_values(
                host_values
            )
        )

        common_ip = (
            cls._get_common_value(
                ip_values
            )
        )

        common_host = (
            cls._get_common_value(
                host_values
            )
        )

        avg_login_hour = (
            cls
            ._calculate_average_login_hour(
                login_times
            )
        )

        activity_times = [
            *login_times,
            *failed_login_times,
        ]

        active_days = (
            cls._calculate_active_days(
                activity_times
            )
        )

        avg_failed_logins_per_day = (
            round(
                len(failed_logins)
                / active_days,
                2,
            )
        )

        risk_baseline = (
            cls._calculate_risk_baseline(
                risk_assessments
            )
        )

        now = cls._utc_now_naive()

        first_seen = (
            min(activity_times)
            if activity_times
            else now
        )

        last_login = (
            login_times[-1]
            if login_times
            else now
        )

        profile = (
            db.query(
                BehaviorProfile
            )
            .filter(
                BehaviorProfile.username
                == normalized_username
            )
            .first()
        )

        if profile is None:
            profile = BehaviorProfile(
                username=(
                    normalized_username
                ),
                login_count=len(logins),
                common_ip=common_ip,
                common_host=common_host,
                avg_login_hour=(
                    avg_login_hour
                ),
                avg_failed_logins_per_day=(
                    avg_failed_logins_per_day
                ),
                known_ips=known_ips,
                known_devices=(
                    known_devices
                ),
                risk_baseline=(
                    risk_baseline
                ),
                first_seen=first_seen,
                last_seen=now,
                last_login=last_login,
                updated_at=now,
            )

            db.add(profile)

        else:
            profile.login_count = (
                len(logins)
            )

            profile.common_ip = (
                common_ip
            )

            profile.common_host = (
                common_host
            )

            profile.avg_login_hour = (
                avg_login_hour
            )

            (
                profile
                .avg_failed_logins_per_day
            ) = (
                avg_failed_logins_per_day
            )

            profile.known_ips = (
                known_ips
            )

            profile.known_devices = (
                known_devices
            )

            profile.risk_baseline = (
                risk_baseline
            )

            profile.first_seen = (
                first_seen
            )

            profile.last_seen = now

            profile.last_login = (
                last_login
            )

            profile.updated_at = now

        db.commit()
        db.refresh(profile)

        return profile

    @staticmethod
    def get_profile(
        db: Session,
        username: str,
    ) -> BehaviorProfile | None:
        normalized_username = (
            username.strip()
        )

        if not normalized_username:
            return None

        return (
            db.query(
                BehaviorProfile
            )
            .filter(
                BehaviorProfile.username
                == normalized_username
            )
            .first()
        )

    @staticmethod
    def serialize(
        profile: BehaviorProfile,
    ) -> dict[str, Any]:
        return {
            "id": profile.id,
            "username": (
                profile.username
            ),
            "login_count": (
                profile.login_count
            ),
            "common_ip": (
                profile.common_ip
            ),
            "common_host": (
                profile.common_host
            ),
            "avg_login_hour": (
                profile.avg_login_hour
            ),
            "avg_failed_logins_per_day": (
                profile
                .avg_failed_logins_per_day
            ),
            "known_ips": (
                profile.known_ips
                or []
            ),
            "known_devices": (
                profile.known_devices
                or []
            ),
            "risk_baseline": (
                profile.risk_baseline
            ),
            "first_seen": (
                profile.first_seen
            ),
            "last_seen": (
                profile.last_seen
            ),
            "last_login": (
                profile.last_login
            ),
            "updated_at": (
                profile.updated_at
            ),
        }