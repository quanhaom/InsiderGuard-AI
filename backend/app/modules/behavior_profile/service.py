from collections import Counter
from datetime import UTC, datetime
from typing import Any

from sqlalchemy.orm import Session

from app.models.behavior_profile import BehaviorProfile
from app.models.device import Device
from app.models.login_event import LoginEvent


class BehaviorProfileService:

    @staticmethod
    def _utc_now_naive() -> datetime:
        """
        Database hiện dùng TIMESTAMP WITHOUT TIME ZONE.

        Hàm này tạo thời gian UTC rồi loại bỏ
        timezone để tương thích với PostgreSQL.
        """
        return datetime.now(UTC).replace(
            tzinfo=None
        )

    @staticmethod
    def _get_common_value(
        values: list[str],
    ) -> str:
        cleaned_values = [
            value
            for value in values
            if value
        ]

        if not cleaned_values:
            return ""

        return Counter(
            cleaned_values
        ).most_common(1)[0][0]

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

        ip_values = [
            login.ip_address
            for login in logins
            if login.ip_address
        ]

        host_values = [
            device.hostname
            for device in devices
            if device.hostname
        ]

        common_ip = cls._get_common_value(
            ip_values
        )

        common_host = cls._get_common_value(
            host_values
        )

        now = cls._utc_now_naive()

        first_seen = (
            logins[0].login_time
            if logins
            else now
        )

        last_login = (
            logins[-1].login_time
            if logins
            else now
        )

        profile = (
            db.query(BehaviorProfile)
            .filter(
                BehaviorProfile.username
                == normalized_username
            )
            .first()
        )

        if profile is None:
            profile = BehaviorProfile(
                username=normalized_username,
                login_count=len(logins),
                common_ip=common_ip,
                common_host=common_host,
                first_seen=first_seen,
                last_seen=now,
                last_login=last_login,
            )

            db.add(profile)

        else:
            profile.login_count = len(logins)
            profile.common_ip = common_ip
            profile.common_host = common_host
            profile.last_seen = now
            profile.last_login = last_login

            if logins:
                profile.first_seen = (
                    first_seen
                )

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

        return (
            db.query(BehaviorProfile)
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
            "username": profile.username,
            "login_count": profile.login_count,
            "common_ip": profile.common_ip,
            "common_host": profile.common_host,
            "first_seen": profile.first_seen,
            "last_seen": profile.last_seen,
            "last_login": profile.last_login,
        }