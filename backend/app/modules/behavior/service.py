from sqlalchemy.orm import Session

from app.models.behavior_profile import BehaviorProfile
from app.models.login_event import LoginEvent


class BehaviorProfileService:
    @staticmethod
    def update_profile(
        db: Session,
        login: LoginEvent
    ) -> BehaviorProfile:
        profile = (
            db.query(BehaviorProfile)
            .filter(
                BehaviorProfile.username == login.username
            )
            .first()
        )

        if profile is None:
            profile = BehaviorProfile(
                username=login.username,
                login_count=1,
                common_ip=login.source_ip,
                common_host="",
                first_seen=login.login_time,
                last_seen=login.login_time,
                last_login=login.login_time
            )

            db.add(profile)

        else:
            profile.login_count += 1
            profile.last_seen = login.login_time
            profile.last_login = login.login_time
            profile.common_ip = login.source_ip

        db.commit()
        db.refresh(profile)

        return profile